package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Account is the subset of Silo's admin account projection the plugin reads
// (GET /api/v2/admin/users and /api/v2/admin/users/{id}).
type Account struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Enabled  bool   `json:"enabled"`
	// LibraryIDs is the account's own override: nil inherits (the access
	// group's list, or every library), an empty slice allows none.
	LibraryIDs    *[]string `json:"library_ids"`
	AccessGroupID *string   `json:"access_group_id"`
	IsOwner       bool      `json:"is_owner"`
	Effective     struct {
		LibraryIDs      *[]string `json:"library_ids"`
		DownloadAllowed bool      `json:"download_allowed"`
		RequestsAllowed bool      `json:"requests_allowed"`
	} `json:"effective_policy"`
	CreatedAt    string  `json:"created_at"`
	LastActiveAt *string `json:"last_active_at"`
}

func (a Account) isAdmin() bool { return a.Role == "admin" || a.IsOwner }

// AccessGroup is the subset of an access group the plugin reads.
type AccessGroup struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	LibraryIDs *[]string `json:"library_ids"`
}

// NewAccount is the body of POST /api/v2/admin/users.
type NewAccount struct {
	Username              string `json:"username"`
	Email                 string `json:"email"`
	Password              string `json:"password"`
	RequirePasswordChange bool   `json:"require_password_change,omitempty"`
	Role                  string `json:"role"`
	CreateDefaultProfile  bool   `json:"create_default_profile"`
	DefaultProfileName    string `json:"default_profile_name,omitempty"`
	// AllowDownloads and AllowRequests are sent as explicit account
	// overrides. Silo's no-group default allows both, and offline downloads
	// have no expiry: they keep playing after the account is disabled.
	AllowDownloads bool `json:"-"`
	AllowRequests  bool `json:"-"`
	// Access is merged into the body: library_ids and access_group_id are
	// only sent when set, because Silo tells null (inherit) from absent.
	Access Access `json:"-"`
}

// Access is a library assignment. Libraries nil with AllLibraries true sends
// library_ids: null (inherit: every library, or the access group's list).
type Access struct {
	Set          bool     `json:"-"`
	AllLibraries bool     `json:"all_libraries"`
	LibraryIDs   []string `json:"library_ids"`
	// GroupSet distinguishes "leave the group alone" from a change; an empty
	// GroupID with GroupSet removes the account from its group.
	GroupSet bool   `json:"group_set"`
	GroupID  string `json:"access_group_id"`
}

func (a Access) apply(body map[string]any) {
	if a.Set {
		if a.AllLibraries {
			body["library_ids"] = nil
		} else {
			ids := a.LibraryIDs
			if ids == nil {
				ids = []string{}
			}
			body["library_ids"] = ids
		}
	}
	if a.GroupSet {
		if a.GroupID == "" {
			body["access_group_id"] = nil
		} else {
			body["access_group_id"] = a.GroupID
		}
	}
}

type apiError struct {
	Status int
	Detail string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("silo api returned %d: %s", e.Status, e.Detail)
}

func statusOf(err error) int {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

type SiloClient struct {
	base string
	key  string
	http *http.Client
}

func newSiloClient(base, key string) *SiloClient {
	return &SiloClient{
		base: strings.TrimRight(base, "/"),
		key:  key,
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// pacer spaces requests: an API key shares its owner's rate allowance (20 a
// second on the standard tier) with their own sessions.
var pacer = struct {
	sync.Mutex
	next time.Time
}{}

const requestGap = 100 * time.Millisecond

func pace(ctx context.Context) error {
	pacer.Lock()
	now := time.Now()
	at := pacer.next
	if at.Before(now) {
		at = now
	}
	pacer.next = at.Add(requestGap)
	pacer.Unlock()
	return sleepCtx(ctx, time.Until(at))
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// do sends one request, retrying on 429, and returns the body and headers of
// a 2xx answer or an *apiError.
func (c *SiloClient) do(ctx context.Context, method, path string, headers map[string]string, body any) ([]byte, http.Header, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return nil, nil, err
		}
	}
	for attempt := 0; ; attempt++ {
		if err := pace(ctx); err != nil {
			return nil, nil, err
		}
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.key)
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, nil, err
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			return nil, nil, err
		}
		if resp.StatusCode == http.StatusTooManyRequests && attempt < 3 {
			wait := 2 * time.Second
			if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
				wait = min(time.Duration(s)*time.Second, 30*time.Second)
			}
			if err := sleepCtx(ctx, wait); err != nil {
				return nil, nil, err
			}
			continue
		}
		if resp.StatusCode >= 300 {
			return nil, resp.Header, &apiError{Status: resp.StatusCode, Detail: problemDetail(raw)}
		}
		return raw, resp.Header, nil
	}
}

// problemDetail turns a Problem Details body (or any body) into one line.
func problemDetail(raw []byte) string {
	var p struct {
		Title  string `json:"title"`
		Detail string `json:"detail"`
		Errors []struct {
			Location string `json:"location"`
			Message  string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(raw, &p) == nil && (p.Title != "" || p.Detail != "") {
		parts := []string{}
		if p.Detail != "" {
			parts = append(parts, p.Detail)
		} else {
			parts = append(parts, p.Title)
		}
		for _, e := range p.Errors {
			if e.Location != "" {
				parts = append(parts, e.Location+": "+e.Message)
			} else if e.Message != "" {
				parts = append(parts, e.Message)
			}
		}
		return strings.Join(parts, " — ")
	}
	s := strings.TrimSpace(string(raw))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// ListAccounts reads every account, 200 at a time.
func (c *SiloClient) ListAccounts(ctx context.Context) ([]Account, error) {
	var out []Account
	cursor := ""
	for page := 0; page < 100; page++ {
		q := url.Values{"limit": {"200"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		raw, _, err := c.do(ctx, http.MethodGet, "/api/v2/admin/users?"+q.Encode(), nil, nil)
		if err != nil {
			return nil, err
		}
		var resp struct {
			Items []Account `json:"items"`
			Page  *struct {
				NextCursor string `json:"next_cursor"`
				HasMore    bool   `json:"has_more"`
			} `json:"page"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("decode account list: %w", err)
		}
		out = append(out, resp.Items...)
		if resp.Page == nil || !resp.Page.HasMore || resp.Page.NextCursor == "" {
			return out, nil
		}
		cursor = resp.Page.NextCursor
	}
	return out, nil
}

// GetAccount returns one account and the ETag its update must carry.
func (c *SiloClient) GetAccount(ctx context.Context, id string) (Account, string, error) {
	raw, h, err := c.do(ctx, http.MethodGet, "/api/v2/admin/users/"+url.PathEscape(id), nil, nil)
	if err != nil {
		return Account{}, "", err
	}
	var acct Account
	if err := json.Unmarshal(raw, &acct); err != nil {
		return Account{}, "", fmt.Errorf("decode account: %w", err)
	}
	return acct, h.Get("ETag"), nil
}

// UpdateAccount applies a partial update. Silo guards the write with the
// account's ETag, so it reads the account first and tries once more if
// another writer got in between (412).
func (c *SiloClient) UpdateAccount(ctx context.Context, id string, body map[string]any, check func(Account) error) (Account, error) {
	for attempt := 0; ; attempt++ {
		acct, etag, err := c.GetAccount(ctx, id)
		if err != nil {
			return Account{}, err
		}
		if check != nil {
			if err := check(acct); err != nil {
				return acct, err
			}
		}
		if etag == "" {
			etag = "*"
		}
		_, _, err = c.do(ctx, http.MethodPut, "/api/v2/admin/users/"+url.PathEscape(id), map[string]string{"If-Match": etag}, body)
		if statusOf(err) == http.StatusPreconditionFailed && attempt < 2 {
			continue
		}
		return acct, err
	}
}

// CreateAccount creates an account and returns its id.
func (c *SiloClient) CreateAccount(ctx context.Context, in NewAccount) (string, error) {
	body := map[string]any{
		"username":               in.Username,
		"email":                  in.Email,
		"password":               in.Password,
		"role":                   "user",
		"create_default_profile": in.CreateDefaultProfile,
		"download_allowed":       in.AllowDownloads,
		"requests_allowed":       in.AllowRequests,
	}
	if in.RequirePasswordChange {
		body["require_password_change"] = true
	}
	if in.CreateDefaultProfile && in.DefaultProfileName != "" {
		body["default_profile_name"] = in.DefaultProfileName
	}
	in.Access.apply(body)
	raw, h, err := c.do(ctx, http.MethodPost, "/api/v2/admin/users", nil, body)
	if err != nil {
		return "", err
	}
	var resp struct {
		ID json.RawMessage `json:"id"`
	}
	_ = json.Unmarshal(raw, &resp)
	id := strings.Trim(string(resp.ID), `"`)
	if id == "" || id == "null" {
		loc := h.Get("Location")
		id = loc[strings.LastIndex(loc, "/")+1:]
	}
	if id == "" {
		return "", errors.New("silo created the account but did not return its id")
	}
	return id, nil
}

// DeleteAccount deletes an account, guarded like an update.
func (c *SiloClient) DeleteAccount(ctx context.Context, id string, check func(Account) error) error {
	for attempt := 0; ; attempt++ {
		acct, etag, err := c.GetAccount(ctx, id)
		if err != nil {
			return err
		}
		if check != nil {
			if err := check(acct); err != nil {
				return err
			}
		}
		if etag == "" {
			etag = "*"
		}
		_, _, err = c.do(ctx, http.MethodDelete, "/api/v2/admin/users/"+url.PathEscape(id), map[string]string{"If-Match": etag}, nil)
		if statusOf(err) == http.StatusPreconditionFailed && attempt < 2 {
			continue
		}
		return err
	}
}

// ListAccessGroups lists access groups. A key without the
// admin:access-groups:read scope gets 403, which callers treat as "no groups".
func (c *SiloClient) ListAccessGroups(ctx context.Context) ([]AccessGroup, error) {
	raw, _, err := c.do(ctx, http.MethodGet, "/api/v2/admin/access-groups?limit=200", nil, nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Items []AccessGroup `json:"items"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decode access groups: %w", err)
	}
	return resp.Items, nil
}
