package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

//go:embed web/admin.html
var adminTemplate []byte

// adminPage is the served page, with its Content-Security-Policy filled in.
var adminPage = withCSP(adminTemplate)

// The page shares Silo's origin and can change accounts, so a script
// injected into it would run as a signed-in admin. Its Content-Security-Policy
// allows only the page's own script (by hash, so injected <script> tags and
// inline handlers don't run) and requests to its own origin. The policy goes
// in a <meta> tag because Silo passes only a few response headers through
// from plugins.
func withCSP(tmpl []byte) []byte {
	html := string(tmpl)
	start := strings.Index(html, "<script>")
	end := strings.Index(html, "</script>")
	if start < 0 || end < start || strings.Count(html, "<script") != 1 || !strings.Contains(html, "__CSP__") {
		panic("admin.html must hold one <script> block and a __CSP__ placeholder")
	}
	sum := sha256.Sum256([]byte(html[start+len("<script>") : end]))
	csp := "default-src 'none'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; " +
		"style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'"
	return []byte(strings.Replace(html, "__CSP__", csp, 1))
}

type routeServer struct {
	pluginv1.UnimplementedHttpRoutesServer
	app *App
}

type request struct {
	method  string
	path    string
	headers map[string]string
	body    []byte
}

func (r request) header(name string) string {
	for k, v := range r.headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// actor names the admin making a change, for the activity log.
func (r request) actor() string {
	if n := r.header("X-Silo-User-Name"); n != "" {
		return n
	}
	if id := r.header("X-Silo-User-Id"); id != "" {
		return "user " + id
	}
	return "admin"
}

func (s *routeServer) Handle(ctx context.Context, in *pluginv1.HandleHTTPRequest) (*pluginv1.HandleHTTPResponse, error) {
	s.app.ensureLoop()
	req := request{method: in.GetMethod(), path: in.GetPath(), headers: in.GetHeaders(), body: in.GetBody()}
	switch {
	case req.path == "/admin/" || req.path == "/admin":
		return page(adminPage), nil
	case strings.HasPrefix(req.path, "/api/admin/"):
		// Silo only routes admins here (the route's access is "admin"), but
		// a role header that says otherwise is refused all the same.
		if role := req.header("X-Silo-User-Role"); role != "" && role != "admin" {
			return jsonError(403, "admin only"), nil
		}
		// CSRF defence in depth. Silo's plugin cookie is SameSite=Lax, which
		// still rides along on a form POST from another subdomain of the same
		// site. A form can't send application/json, and a cross-origin fetch
		// that sets it needs a CORS preflight Silo doesn't grant.
		if req.method != http.MethodGet && req.method != http.MethodHead && !isJSON(req.header("Content-Type")) {
			return jsonError(415, "send Content-Type: application/json"), nil
		}
		return s.app.adminAPI(ctx, req, strings.TrimPrefix(req.path, "/api/admin/")), nil
	}
	return jsonError(404, "not found"), nil
}

func isJSON(contentType string) bool {
	mt, _, _ := strings.Cut(contentType, ";")
	return strings.EqualFold(strings.TrimSpace(mt), "application/json")
}

// clip trims user text to n runes.
func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

func page(body []byte) *pluginv1.HandleHTTPResponse {
	return &pluginv1.HandleHTTPResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type":  "text/html; charset=utf-8",
			"Cache-Control": "no-store",
		},
		Body: body,
	}
}

func jsonResp(status int, v any) *pluginv1.HandleHTTPResponse {
	body, err := json.Marshal(v)
	if err != nil {
		return jsonError(500, err.Error())
	}
	return &pluginv1.HandleHTTPResponse{
		StatusCode: int32(status),
		Headers:    map[string]string{"Content-Type": "application/json", "Cache-Control": "no-store"},
		Body:       body,
	}
}

func jsonError(status int, msg string) *pluginv1.HandleHTTPResponse {
	return jsonResp(status, map[string]string{"error": msg})
}

// siloError maps a failed Silo call to a response for the admin page.
func siloError(err error) *pluginv1.HandleHTTPResponse {
	switch {
	case errors.Is(err, errNoKey):
		return jsonError(409, "Add a Silo API key in the plugin's settings first.")
	case errors.Is(err, errIsAdmin):
		return jsonError(403, "Administrator accounts are managed in Silo, not by this plugin.")
	}
	status := statusOf(err)
	if status == 0 || status >= 500 {
		status = 502
	}
	return jsonError(status, describeErr(err))
}

func decode(req request, v any) error {
	if len(req.body) == 0 {
		return errors.New("request body is empty")
	}
	return json.Unmarshal(req.body, v)
}

func notAdmin(acct Account) error {
	if acct.isAdmin() {
		return errIsAdmin
	}
	return nil
}

type libraryView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	MediaType string `json:"media_type"`
}

type accountView struct {
	Account
	Manageable bool   `json:"manageable"`
	Grant      *Grant `json:"grant,omitempty"`
}

func (a *App) adminAPI(ctx context.Context, req request, sub string) *pluginv1.HandleHTTPResponse {
	parts := strings.Split(strings.Trim(sub, "/"), "/")
	switch {
	case sub == "state" && req.method == http.MethodGet:
		return a.adminState(ctx)

	case sub == "run" && req.method == http.MethodPost:
		report := a.runExpiry(ctx, "manual run by "+req.actor())
		return jsonResp(200, report)

	case sub == "settings" && req.method == http.MethodPut:
		var s Settings
		if err := decode(req, &s); err != nil {
			return jsonError(400, err.Error())
		}
		if err := a.store.SaveSettings(ctx, s); err != nil {
			return jsonError(500, err.Error())
		}
		s.normalize()
		return jsonResp(200, s)

	case sub == "presets" && req.method == http.MethodPut:
		var list []Preset
		if err := decode(req, &list); err != nil {
			return jsonError(400, err.Error())
		}
		clean, err := cleanPresets(list)
		if err != nil {
			return jsonError(422, err.Error())
		}
		if err := a.store.SavePresets(ctx, clean); err != nil {
			return jsonError(500, err.Error())
		}
		return jsonResp(200, clean)

	case sub == "users" && req.method == http.MethodPost:
		return a.createGuest(ctx, req)

	case len(parts) == 3 && parts[0] == "users" && parts[2] == "expiry":
		id := parts[1]
		if !validID(id) {
			return jsonError(400, "bad account id")
		}
		switch req.method {
		case http.MethodPut:
			return a.setExpiry(ctx, req, id)
		case http.MethodDelete:
			return a.clearExpiry(ctx, req, id)
		}

	case len(parts) == 3 && parts[0] == "users" && parts[2] == "access" && req.method == http.MethodPut:
		id := parts[1]
		if !validID(id) {
			return jsonError(400, "bad account id")
		}
		return a.setAccess(ctx, req, id)

	case len(parts) == 3 && parts[0] == "users" && parts[2] == "enabled" && req.method == http.MethodPut:
		id := parts[1]
		if !validID(id) {
			return jsonError(400, "bad account id")
		}
		return a.setEnabled(ctx, req, id)

	case len(parts) == 2 && parts[0] == "users" && req.method == http.MethodDelete:
		id := parts[1]
		if !validID(id) {
			return jsonError(400, "bad account id")
		}
		return a.deleteAccount(ctx, req, id)
	}
	return jsonError(404, "not found")
}

func validID(id string) bool {
	n, err := strconv.Atoi(id)
	return err == nil && n > 0 && strconv.Itoa(n) == id
}

func (a *App) adminState(ctx context.Context) *pluginv1.HandleHTTPResponse {
	cfg := a.config()
	out := map[string]any{
		"problems": cfg.problems(),
		"now":      a.now().UTC(),
		"last_run": a.report(),
	}
	settings, err := a.store.Settings(ctx)
	if err != nil {
		return jsonError(503, err.Error())
	}
	out["settings"] = settings
	presets, _ := a.store.Presets(ctx)
	out["presets"] = presets
	logs, _ := a.store.Log(ctx)
	out["log"] = logs
	grants, err := a.store.Grants(ctx)
	if err != nil {
		return jsonError(503, err.Error())
	}

	libs := []libraryView{}
	for _, l := range a.libraries(ctx) {
		if l.GetId() == "" {
			continue
		}
		libs = append(libs, libraryView{ID: l.GetId(), Name: l.GetName(), MediaType: l.GetMediaType()})
	}
	sort.SliceStable(libs, func(i, j int) bool { return strings.ToLower(libs[i].Name) < strings.ToLower(libs[j].Name) })
	out["libraries"] = libs

	accounts := []accountView{}
	seen := map[string]bool{}
	listed := false
	if client, err := a.client(ctx); err == nil {
		list, err := client.ListAccounts(ctx)
		if err != nil {
			out["accounts_error"] = describeErr(err)
		} else {
			listed = true
		}
		for _, acct := range list {
			v := accountView{Account: acct, Manageable: !acct.isAdmin()}
			if g, ok := grants[acct.ID]; ok && g.Status != grantDeleted {
				g := g
				v.Grant = &g
			}
			seen[acct.ID] = true
			accounts = append(accounts, v)
		}
		if groups, err := client.ListAccessGroups(ctx); err == nil {
			out["access_groups"] = groups
		} else if s := statusOf(err); s == http.StatusForbidden || s == http.StatusNotFound || s == http.StatusServiceUnavailable {
			out["access_groups"] = nil
			out["groups_note"] = "Add the admin:access-groups:read scope to the plugin's API key to choose access groups here."
		} else {
			out["groups_note"] = describeErr(err)
		}
	}
	out["accounts"] = accounts

	// Grants whose account is gone (deleted in Silo, or by the plugin).
	gone := []Grant{}
	for id, g := range grants {
		if !seen[id] && (g.Status == grantDeleted || listed) {
			gone = append(gone, g)
		}
	}
	sort.Slice(gone, func(i, j int) bool { return gone[i].UpdatedAt.After(gone[j].UpdatedAt) })
	out["removed"] = gone
	return jsonResp(200, out)
}

// ExpiryInput sets when an account's access ends.
type ExpiryInput struct {
	// Mode is "days" (from now), "extend" (from the current expiry, or now
	// if it has passed), "date" (ExpiresAt) or "none" (no expiry).
	Mode      string `json:"mode"`
	Days      int    `json:"days"`
	Hours     int    `json:"hours"`
	ExpiresAt string `json:"expires_at"`
	Note      string `json:"note"`
	// Reenable overrides the "turn expired accounts back on" setting.
	Reenable *bool `json:"reenable"`
}

// resolve returns the new expiry, or the zero time for "none".
func (in ExpiryInput) resolve(now time.Time, current *Grant) (time.Time, error) {
	span := time.Duration(in.Days)*24*time.Hour + time.Duration(in.Hours)*time.Hour
	switch in.Mode {
	case "none", "":
		return time.Time{}, nil
	case "days":
		if span <= 0 || in.Days > 3650 {
			return time.Time{}, errors.New("give a number of days (or hours) between 1 hour and 10 years")
		}
		return now.Add(span), nil
	case "extend":
		if span <= 0 || in.Days > 3650 {
			return time.Time{}, errors.New("give a number of days (or hours) to extend by")
		}
		from := now
		if current != nil && current.Status == grantActive && current.ExpiresAt.After(now) {
			from = current.ExpiresAt
		}
		return from.Add(span), nil
	case "date":
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(in.ExpiresAt))
		if err != nil {
			return time.Time{}, errors.New("expires_at must be an RFC 3339 date and time")
		}
		if !t.After(now) {
			return time.Time{}, errors.New("the expiry must be in the future")
		}
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unknown expiry mode %q", in.Mode)
}

func (a *App) setExpiry(ctx context.Context, req request, id string) *pluginv1.HandleHTTPResponse {
	var in ExpiryInput
	if err := decode(req, &in); err != nil {
		return jsonError(400, err.Error())
	}
	if in.Mode == "none" {
		return a.clearExpiry(ctx, req, id)
	}
	client, err := a.client(ctx)
	if err != nil {
		return siloError(err)
	}
	acct, _, err := client.GetAccount(ctx, id)
	if err != nil {
		return siloError(err)
	}
	if acct.isAdmin() {
		return siloError(errIsAdmin)
	}
	settings, err := a.store.Settings(ctx)
	if err != nil {
		return jsonError(503, err.Error())
	}
	reenable := settings.ReenableOnExtend
	if in.Reenable != nil {
		reenable = *in.Reenable
	}
	now := a.now().UTC()
	var (
		saved Grant
		// offByPlugin: the plugin itself disabled the account at expiry, so
		// extending may turn it back on. An account an admin disabled stays off.
		offByPlugin bool
	)
	err = a.store.UpdateGrants(ctx, func(grants map[string]Grant) error {
		var current *Grant
		if g, ok := grants[id]; ok && g.Status != grantDeleted {
			current = &g
		}
		at, err := in.resolve(now, current)
		if err != nil {
			return &inputError{err}
		}
		g := Grant{UserID: id, CreatedAt: now, CreatedBy: req.actor()}
		if current != nil {
			g = *current
			offByPlugin = current.Status == grantExpired && current.DisabledByPlugin
		}
		g.Username = acct.Username
		g.ExpiresAt = at
		g.Status = grantActive
		g.ExpiredAt = time.Time{}
		g.DisabledByPlugin = false
		g.LastError = ""
		g.UpdatedAt = now
		if note := clip(in.Note, maxNote); note != "" || current == nil {
			g.Note = note
		}
		grants[id] = g
		saved = g
		return nil
	})
	var ie *inputError
	if errors.As(err, &ie) {
		return jsonError(422, ie.Error())
	}
	if err != nil {
		return jsonError(500, err.Error())
	}
	logs := []LogEntry{{Time: now, UserID: id, Username: acct.Username, Action: "expiry set", Detail: "Access until " + saved.ExpiresAt.Format(time.RFC3339) + ".", By: req.actor()}}
	resp := map[string]any{"grant": saved}
	if offByPlugin && reenable && !acct.Enabled {
		if _, err := client.UpdateAccount(ctx, id, map[string]any{"enabled": true}, notAdmin); err != nil {
			resp["warning"] = "The new expiry is saved, but the account could not be turned back on: " + describeErr(err)
			logs = append(logs, LogEntry{Time: now, UserID: id, Username: acct.Username, Action: "enable failed", Error: describeErr(err), By: req.actor()})
		} else {
			resp["reenabled"] = true
			logs = append(logs, LogEntry{Time: now, UserID: id, Username: acct.Username, Action: "enabled", Detail: "Turned back on because its access was extended.", By: req.actor()})
		}
	}
	_ = a.store.AddLog(ctx, logs...)
	return jsonResp(200, resp)
}

type inputError struct{ err error }

func (e *inputError) Error() string { return e.err.Error() }

func (a *App) clearExpiry(ctx context.Context, req request, id string) *pluginv1.HandleHTTPResponse {
	var removed *Grant
	err := a.store.UpdateGrants(ctx, func(grants map[string]Grant) error {
		if g, ok := grants[id]; ok {
			removed = &g
			delete(grants, id)
		}
		return nil
	})
	if err != nil {
		return jsonError(500, err.Error())
	}
	if removed != nil {
		_ = a.store.AddLog(ctx, LogEntry{Time: a.now().UTC(), UserID: id, Username: removed.Username, Action: "expiry removed", Detail: "The account no longer expires. Its enabled state was left as it was.", By: req.actor()})
	}
	return jsonResp(200, map[string]any{"ok": true})
}

func (a *App) setAccess(ctx context.Context, req request, id string) *pluginv1.HandleHTTPResponse {
	var in Access
	if err := decode(req, &in); err != nil {
		return jsonError(400, err.Error())
	}
	in.Set = true
	if err := a.checkLibraries(ctx, in); err != nil {
		return jsonError(422, err.Error())
	}
	client, err := a.client(ctx)
	if err != nil {
		return siloError(err)
	}
	body := map[string]any{}
	in.apply(body)
	acct, err := client.UpdateAccount(ctx, id, body, notAdmin)
	if err != nil {
		return siloError(err)
	}
	_ = a.store.AddLog(ctx, LogEntry{Time: a.now().UTC(), UserID: id, Username: acct.Username, Action: "libraries changed", Detail: a.describeAccess(ctx, in), By: req.actor()})
	updated, _, err := client.GetAccount(ctx, id)
	if err != nil {
		return jsonResp(200, map[string]any{"ok": true})
	}
	return jsonResp(200, map[string]any{"ok": true, "account": updated})
}

func (a *App) setEnabled(ctx context.Context, req request, id string) *pluginv1.HandleHTTPResponse {
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := decode(req, &in); err != nil {
		return jsonError(400, err.Error())
	}
	client, err := a.client(ctx)
	if err != nil {
		return siloError(err)
	}
	acct, err := client.UpdateAccount(ctx, id, map[string]any{"enabled": in.Enabled}, notAdmin)
	if err != nil {
		return siloError(err)
	}
	_ = a.store.UpdateGrants(ctx, func(grants map[string]Grant) error {
		if g, ok := grants[id]; ok && g.DisabledByPlugin {
			g.DisabledByPlugin = false
			grants[id] = g
		}
		return nil
	})
	action, detail := "disabled", "Disabled by hand; signed out everywhere."
	if in.Enabled {
		action, detail = "enabled", "Turned on by hand."
		grants, _ := a.store.Grants(ctx)
		if g, ok := grants[id]; ok && g.Status == grantExpired {
			detail += " Its access had expired; the plugin won't disable it again unless you set a new expiry."
		}
	}
	_ = a.store.AddLog(ctx, LogEntry{Time: a.now().UTC(), UserID: id, Username: acct.Username, Action: action, Detail: detail, By: req.actor()})
	return jsonResp(200, map[string]any{"ok": true})
}

func (a *App) deleteAccount(ctx context.Context, req request, id string) *pluginv1.HandleHTTPResponse {
	client, err := a.client(ctx)
	if err != nil {
		return siloError(err)
	}
	var name string
	err = client.DeleteAccount(ctx, id, func(acct Account) error {
		name = acct.Username
		return notAdmin(acct)
	})
	if err != nil {
		return siloError(err)
	}
	now := a.now().UTC()
	_ = a.store.UpdateGrants(ctx, func(grants map[string]Grant) error {
		if g, ok := grants[id]; ok {
			g.Status, g.UpdatedAt, g.LastError = grantDeleted, now, ""
			grants[id] = g
		}
		return nil
	})
	_ = a.store.AddLog(ctx, LogEntry{Time: now, UserID: id, Username: name, Action: "deleted", Detail: "Deleted by hand.", By: req.actor()})
	return jsonResp(200, map[string]any{"ok": true})
}

// GuestInput is the "New guest" form.
type GuestInput struct {
	Username              string      `json:"username"`
	Email                 string      `json:"email"`
	Password              string      `json:"password"`
	RequirePasswordChange bool        `json:"require_password_change"`
	CreateDefaultProfile  bool        `json:"create_default_profile"`
	ProfileName           string      `json:"profile_name"`
	AllowDownloads        bool        `json:"allow_downloads"`
	AllowRequests         bool        `json:"allow_requests"`
	Access                Access      `json:"access"`
	Expiry                ExpiryInput `json:"expiry"`
}

func (a *App) createGuest(ctx context.Context, req request) *pluginv1.HandleHTTPResponse {
	var in GuestInput
	if err := decode(req, &in); err != nil {
		return jsonError(400, err.Error())
	}
	in.Username = strings.TrimSpace(in.Username)
	in.Email = strings.TrimSpace(in.Email)
	if in.Username == "" {
		return jsonError(422, "a username is required")
	}
	if in.Email == "" {
		return jsonError(422, "Silo requires an email address for every account")
	}
	generated := false
	if in.Password == "" {
		in.Password = randomPassword(16)
		generated = true
	}
	if n := len(in.Password); n < 8 || n > 72 {
		return jsonError(422, "the password must be 8 to 72 characters")
	}
	now := a.now().UTC()
	expiresAt, err := in.Expiry.resolve(now, nil)
	if err != nil {
		return jsonError(422, err.Error())
	}
	in.Access.Set = true
	if err := a.checkLibraries(ctx, in.Access); err != nil {
		return jsonError(422, err.Error())
	}
	client, err := a.client(ctx)
	if err != nil {
		return siloError(err)
	}
	id, err := client.CreateAccount(ctx, NewAccount{
		Username:              in.Username,
		Email:                 in.Email,
		Password:              in.Password,
		RequirePasswordChange: in.RequirePasswordChange,
		CreateDefaultProfile:  in.CreateDefaultProfile,
		DefaultProfileName:    clip(in.ProfileName, 100),
		AllowDownloads:        in.AllowDownloads,
		AllowRequests:         in.AllowRequests,
		Access:                in.Access,
	})
	if err != nil {
		return siloError(err)
	}
	detail := a.describeAccess(ctx, in.Access)
	detail += fmt.Sprintf("; downloads %s, requests %s", onOff(in.AllowDownloads), onOff(in.AllowRequests))
	logs := []LogEntry{{Time: now, UserID: id, Username: in.Username, Action: "created", Detail: detail, By: req.actor()}}
	resp := map[string]any{"id": id}
	if generated {
		resp["password"] = in.Password
	}
	if !expiresAt.IsZero() {
		g := Grant{UserID: id, Username: in.Username, ExpiresAt: expiresAt, Note: clip(in.Expiry.Note, maxNote), Status: grantActive, CreatedAt: now, CreatedBy: req.actor(), UpdatedAt: now}
		if err := a.store.UpdateGrants(ctx, func(grants map[string]Grant) error {
			grants[id] = g
			return nil
		}); err != nil {
			resp["warning"] = "The account was created, but its expiry could not be saved: " + err.Error() + ". Set it again from the Accounts tab."
		} else {
			resp["grant"] = g
			logs = append(logs, LogEntry{Time: now, UserID: id, Username: in.Username, Action: "expiry set", Detail: "Access until " + expiresAt.Format(time.RFC3339) + ".", By: req.actor()})
		}
	}
	_ = a.store.AddLog(ctx, logs...)
	return jsonResp(201, resp)
}

// checkLibraries rejects library ids the host doesn't list. When the host
// list is unavailable Silo's own validation (422) still applies.
func (a *App) checkLibraries(ctx context.Context, in Access) error {
	if !in.Set || in.AllLibraries {
		return nil
	}
	libs := a.libraries(ctx)
	if len(libs) == 0 {
		return nil
	}
	known := map[string]bool{}
	for _, l := range libs {
		known[l.GetId()] = true
	}
	for _, id := range in.LibraryIDs {
		if !known[id] {
			return fmt.Errorf("library %q does not exist", id)
		}
	}
	return nil
}

func (a *App) describeAccess(ctx context.Context, in Access) string {
	var parts []string
	if in.Set {
		if in.AllLibraries {
			parts = append(parts, "Libraries: all (or the access group's)")
		} else if len(in.LibraryIDs) == 0 {
			parts = append(parts, "Libraries: none")
		} else {
			names := map[string]string{}
			for _, l := range a.libraries(ctx) {
				names[l.GetId()] = l.GetName()
			}
			var list []string
			for _, id := range in.LibraryIDs {
				if n := names[id]; n != "" {
					list = append(list, n)
				} else {
					list = append(list, "#"+id)
				}
			}
			parts = append(parts, "Libraries: "+strings.Join(list, ", "))
		}
	}
	if in.GroupSet {
		if in.GroupID == "" {
			parts = append(parts, "no access group")
		} else {
			parts = append(parts, "access group #"+in.GroupID)
		}
	}
	return strings.Join(parts, "; ")
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func cleanPresets(list []Preset) ([]Preset, error) {
	out := make([]Preset, 0, len(list))
	names := map[string]bool{}
	for _, p := range list {
		p.Name = strings.TrimSpace(p.Name)
		if p.Name == "" {
			return nil, errors.New("every preset needs a name")
		}
		if len([]rune(p.Name)) > maxName {
			return nil, fmt.Errorf("preset names can be at most %d characters", maxName)
		}
		key := strings.ToLower(p.Name)
		if names[key] {
			return nil, fmt.Errorf("two presets are called %q", p.Name)
		}
		names[key] = true
		if p.ID == "" {
			p.ID = randomID()
		}
		if p.AllLibraries {
			p.LibraryIDs = nil
		} else if p.LibraryIDs == nil {
			p.LibraryIDs = []string{}
		}
		if p.AccessGroupID != "" && !validID(p.AccessGroupID) {
			return nil, fmt.Errorf("preset %q has a bad access group id", p.Name)
		}
		out = append(out, p)
	}
	if len(out) > 100 {
		return nil, errors.New("at most 100 presets")
	}
	return out, nil
}

func randomID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// randomPassword avoids characters that are easy to misread when the
// password is passed on by hand.
func randomPassword(n int) string {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	var sb strings.Builder
	for i := 0; i < n; i++ {
		k, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		sb.WriteByte(alphabet[k.Int64()])
	}
	return sb.String()
}
