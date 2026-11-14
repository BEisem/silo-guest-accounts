package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
)

// memState stands in for the host's instance state.
type memState struct {
	mu   sync.Mutex
	rows map[string][]byte
}

func (m *memState) ReadInstanceState(_ context.Context, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.rows[key]
	return v, ok, nil
}

func (m *memState) WriteInstanceState(_ context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[key] = append([]byte(nil), value...)
	return nil
}

// fakeSilo implements the admin account routes the plugin uses, with
// revision ETags and If-Match like the real server.
type fakeSilo struct {
	t        *testing.T
	mu       sync.Mutex
	accounts map[string]map[string]any
	revs     map[string]int
	nextID   int
	puts     []map[string]any
	// staleOnce makes the next PUT answer 412 once, as if another writer
	// changed the account between the read and the write.
	staleOnce bool
	groups403 bool
}

func newFakeSilo(t *testing.T) (*fakeSilo, *httptest.Server) {
	f := &fakeSilo{t: t, accounts: map[string]map[string]any{}, revs: map[string]int{}, nextID: 1}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeSilo) add(username, role string, enabled bool) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := strconv.Itoa(f.nextID)
	f.nextID++
	f.accounts[id] = map[string]any{"id": id, "username": username, "email": username + "@example.test", "role": role, "enabled": enabled, "library_ids": nil, "access_group_id": nil, "is_owner": false}
	f.revs[id] = 1
	return id
}

func (f *fakeSilo) get(id string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.accounts[id]
}

func (f *fakeSilo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer sa_test" {
		w.WriteHeader(401)
		return
	}
	write := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	path := r.URL.Path
	switch {
	case path == "/api/v2/admin/access-groups":
		if f.groups403 {
			write(403, map[string]string{"title": "Forbidden", "detail": "scope"})
			return
		}
		write(200, map[string]any{"items": []map[string]any{{"id": "3", "name": "Friends", "library_ids": []string{"1"}}}})
	case path == "/api/v2/admin/users" && r.Method == http.MethodGet:
		items := []map[string]any{}
		for i := 1; i < f.nextID; i++ {
			if a, ok := f.accounts[strconv.Itoa(i)]; ok {
				items = append(items, a)
			}
		}
		write(200, map[string]any{"items": items, "page": map[string]any{"has_more": false}})
	case path == "/api/v2/admin/users" && r.Method == http.MethodPost:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		id := strconv.Itoa(f.nextID)
		f.nextID++
		acct := map[string]any{"id": id, "username": body["username"], "email": body["email"], "role": "user", "enabled": true, "library_ids": nil, "access_group_id": nil}
		for _, k := range []string{"library_ids", "access_group_id"} {
			if v, ok := body[k]; ok {
				acct[k] = v
			}
		}
		acct["_body"] = body
		f.accounts[id] = acct
		f.revs[id] = 1
		w.Header().Set("Location", "/api/v2/admin/users/"+id)
		write(201, map[string]any{"id": id})
	case strings.HasPrefix(path, "/api/v2/admin/users/"):
		id := strings.TrimPrefix(path, "/api/v2/admin/users/")
		acct, ok := f.accounts[id]
		if !ok {
			write(404, map[string]string{"title": "Not Found", "detail": "Account not found."})
			return
		}
		etag := fmt.Sprintf(`"r%d"`, f.revs[id])
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("ETag", etag)
			write(200, acct)
		case http.MethodPut, http.MethodDelete:
			if r.Header.Get("If-Match") == "" {
				write(428, map[string]string{"title": "Precondition Required"})
				return
			}
			if f.staleOnce || r.Header.Get("If-Match") != etag {
				f.staleOnce = false
				f.revs[id]++
				write(412, map[string]string{"title": "Precondition Failed"})
				return
			}
			if acct["role"] == "admin" {
				write(403, map[string]string{"title": "Forbidden", "detail": "scoped keys cannot change admins"})
				return
			}
			if r.Method == http.MethodDelete {
				delete(f.accounts, id)
				w.WriteHeader(204)
				return
			}
			raw, _ := io.ReadAll(r.Body)
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			f.puts = append(f.puts, body)
			for k, v := range body {
				acct[k] = v
			}
			f.revs[id]++
			w.WriteHeader(204)
		}
	default:
		write(404, map[string]string{"title": "Not Found"})
	}
}

type harness struct {
	app   *App
	silo  *fakeSilo
	state *memState
	now   time.Time
}

func newHarness(t *testing.T) *harness {
	silo, srv := newFakeSilo(t)
	h := &harness{silo: silo, state: &memState{rows: map[string][]byte{}}, now: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)}
	app := newApp(hclog.NewNullLogger())
	app.store.backend = h.state
	app.base = srv.URL
	app.now = func() time.Time { return h.now }
	app.cfg = Config{APIKey: "sa_test"}
	app.libs = []*pluginv1.Library{{Id: "1", Name: "Movies", MediaType: "movie"}, {Id: "2", Name: "TV", MediaType: "tv"}, {Id: "5", Name: "Kids", MediaType: "movie"}}
	h.app = app
	return h
}

func (h *harness) call(t *testing.T, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	rs := &routeServer{app: h.app}
	resp, err := rs.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: method, Path: path, Body: raw, Headers: map[string]string{"X-Silo-User-Name": "blake", "X-Silo-User-Role": "admin", "Content-Type": "application/json"}})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	_ = json.Unmarshal(resp.GetBody(), &out)
	return int(resp.GetStatusCode()), out
}

func (h *harness) grant(t *testing.T, id string) (Grant, bool) {
	t.Helper()
	grants, err := h.app.store.Grants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	g, ok := grants[id]
	return g, ok
}

func TestCreateGuestWithExpiryAndLibraries(t *testing.T) {
	h := newHarness(t)
	status, out := h.call(t, "POST", "/api/admin/users", map[string]any{
		"username": "cousin", "email": "cousin@example.test",
		"require_password_change": true, "create_default_profile": true,
		"access": map[string]any{"all_libraries": false, "library_ids": []string{"1", "2"}},
		"expiry": map[string]any{"mode": "days", "days": 7, "note": "visiting"},
	})
	if status != 201 {
		t.Fatalf("status %d: %v", status, out)
	}
	id := out["id"].(string)
	if pw, _ := out["password"].(string); len(pw) != 16 {
		t.Fatalf("expected a generated 16-character password, got %q", pw)
	}
	acct := h.silo.get(id)
	body := acct["_body"].(map[string]any)
	if body["role"] != "user" || body["require_password_change"] != true || body["create_default_profile"] != true {
		t.Fatalf("create body = %v", body)
	}
	if ids, _ := body["library_ids"].([]any); len(ids) != 2 {
		t.Fatalf("library_ids = %v", body["library_ids"])
	}
	if _, sent := body["access_group_id"]; sent {
		t.Fatal("access_group_id should not be sent when the group isn't changed")
	}
	g, ok := h.grant(t, id)
	if !ok || g.Status != grantActive || !g.ExpiresAt.Equal(h.now.Add(7*24*time.Hour)) || g.Note != "visiting" || g.CreatedBy != "blake" {
		t.Fatalf("grant = %+v", g)
	}
}

func TestCreateRejectsUnknownLibraryAndShortPassword(t *testing.T) {
	h := newHarness(t)
	if s, _ := h.call(t, "POST", "/api/admin/users", map[string]any{"username": "a", "email": "a@x", "access": map[string]any{"library_ids": []string{"99"}}}); s != 422 {
		t.Fatalf("unknown library: status %d", s)
	}
	if s, _ := h.call(t, "POST", "/api/admin/users", map[string]any{"username": "a", "email": "a@x", "password": "short", "access": map[string]any{"all_libraries": true}}); s != 422 {
		t.Fatalf("short password: status %d", s)
	}
	if len(h.silo.accounts) != 0 {
		t.Fatal("no account should have been created")
	}
}

func TestExpiryDisablesDueAccountsOnly(t *testing.T) {
	h := newHarness(t)
	due := h.silo.add("due", "user", true)
	later := h.silo.add("later", "user", true)
	for id, days := range map[string]int{due: 1, later: 3} {
		if s, out := h.call(t, "PUT", "/api/admin/users/"+id+"/expiry", map[string]any{"mode": "days", "days": days}); s != 200 {
			t.Fatalf("set expiry: %d %v", s, out)
		}
	}
	h.now = h.now.Add(25 * time.Hour)
	report := h.app.runExpiry(context.Background(), "test")
	if report.Due != 1 || report.Disabled != 1 || len(report.Errors) != 0 {
		t.Fatalf("report = %+v", report)
	}
	if h.silo.get(due)["enabled"] != false || h.silo.get(later)["enabled"] != true {
		t.Fatal("only the due account should be disabled")
	}
	if g, _ := h.grant(t, due); g.Status != grantExpired || !g.ExpiredAt.Equal(h.now) {
		t.Fatalf("grant = %+v", g)
	}
	// A second run does nothing more.
	if r := h.app.runExpiry(context.Background(), "test"); r.Due != 0 || r.Disabled != 0 {
		t.Fatalf("second run = %+v", r)
	}
}

func TestExpiryRetriesAfterStaleETag(t *testing.T) {
	h := newHarness(t)
	id := h.silo.add("guest", "user", true)
	h.call(t, "PUT", "/api/admin/users/"+id+"/expiry", map[string]any{"mode": "days", "hours": 1})
	h.now = h.now.Add(2 * time.Hour)
	h.silo.staleOnce = true
	if r := h.app.runExpiry(context.Background(), "test"); r.Disabled != 1 {
		t.Fatalf("report = %+v", r)
	}
	if h.silo.get(id)["enabled"] != false {
		t.Fatal("account should be disabled after the retry")
	}
}

func TestExpiryNeverTouchesAdmins(t *testing.T) {
	h := newHarness(t)
	admin := h.silo.add("boss", "admin", true)
	if s, _ := h.call(t, "PUT", "/api/admin/users/"+admin+"/expiry", map[string]any{"mode": "days", "days": 1}); s != 403 {
		t.Fatalf("setting an expiry on an admin: status %d", s)
	}
	// Even a grant written by hand (or before a promotion) is refused.
	_ = h.app.store.UpdateGrants(context.Background(), func(g map[string]Grant) error {
		g[admin] = Grant{UserID: admin, Username: "boss", ExpiresAt: h.now.Add(-time.Hour), Status: grantActive}
		return nil
	})
	r := h.app.runExpiry(context.Background(), "test")
	if r.Disabled != 0 || len(r.Errors) != 1 {
		t.Fatalf("report = %+v", r)
	}
	if h.silo.get(admin)["enabled"] != true {
		t.Fatal("admin must stay enabled")
	}
	if len(h.silo.puts) != 0 {
		t.Fatal("no write should reach Silo for an admin")
	}
}

func TestExtendReenablesExpiredAccount(t *testing.T) {
	h := newHarness(t)
	id := h.silo.add("guest", "user", true)
	h.call(t, "PUT", "/api/admin/users/"+id+"/expiry", map[string]any{"mode": "days", "days": 1})
	h.now = h.now.Add(48 * time.Hour)
	h.app.runExpiry(context.Background(), "test")
	if h.silo.get(id)["enabled"] != false {
		t.Fatal("should be disabled")
	}
	s, out := h.call(t, "PUT", "/api/admin/users/"+id+"/expiry", map[string]any{"mode": "extend", "days": 3})
	if s != 200 || out["reenabled"] != true {
		t.Fatalf("extend: %d %v", s, out)
	}
	if h.silo.get(id)["enabled"] != true {
		t.Fatal("should be enabled again")
	}
	g, _ := h.grant(t, id)
	// Extending an expired grant counts from now, not from the old date.
	if g.Status != grantActive || !g.ExpiresAt.Equal(h.now.Add(72*time.Hour)) {
		t.Fatalf("grant = %+v", g)
	}
}

func TestExtendActiveGrantAddsToCurrentExpiry(t *testing.T) {
	h := newHarness(t)
	id := h.silo.add("guest", "user", true)
	h.call(t, "PUT", "/api/admin/users/"+id+"/expiry", map[string]any{"mode": "days", "days": 2})
	h.call(t, "PUT", "/api/admin/users/"+id+"/expiry", map[string]any{"mode": "extend", "days": 5})
	if g, _ := h.grant(t, id); !g.ExpiresAt.Equal(h.now.Add(7 * 24 * time.Hour)) {
		t.Fatalf("expires %v", g.ExpiresAt)
	}
}

func TestDeleteAfterGrace(t *testing.T) {
	h := newHarness(t)
	id := h.silo.add("guest", "user", true)
	kept := h.silo.add("kept", "user", true)
	h.call(t, "PUT", "/api/admin/settings", map[string]any{"default_days": 7, "delete_after_days": 2, "reenable_on_extend": true})
	for _, u := range []string{id, kept} {
		h.call(t, "PUT", "/api/admin/users/"+u+"/expiry", map[string]any{"mode": "days", "days": 1})
	}
	h.now = h.now.Add(25 * time.Hour)
	h.app.runExpiry(context.Background(), "test")
	// Someone turns one back on by hand in Silo.
	h.call(t, "PUT", "/api/admin/users/"+kept+"/enabled", map[string]any{"enabled": true})

	h.now = h.now.Add(24 * time.Hour)
	if r := h.app.runExpiry(context.Background(), "test"); r.Deleted != 0 {
		t.Fatalf("deleted before the grace period: %+v", r)
	}
	h.now = h.now.Add(25 * time.Hour)
	if r := h.app.runExpiry(context.Background(), "test"); r.Deleted != 1 {
		t.Fatalf("report = %+v", r)
	}
	if h.silo.get(id) != nil {
		t.Fatal("expired account should be deleted")
	}
	if h.silo.get(kept) == nil {
		t.Fatal("an account re-enabled by hand must not be deleted")
	}
	if g, _ := h.grant(t, id); g.Status != grantDeleted {
		t.Fatalf("grant = %+v", g)
	}
}

func TestPausedDoesNothing(t *testing.T) {
	h := newHarness(t)
	id := h.silo.add("guest", "user", true)
	h.call(t, "PUT", "/api/admin/users/"+id+"/expiry", map[string]any{"mode": "days", "days": 1})
	h.call(t, "PUT", "/api/admin/settings", map[string]any{"default_days": 7, "paused": true})
	h.now = h.now.Add(48 * time.Hour)
	if r := h.app.runExpiry(context.Background(), "test"); r.Skipped == "" || r.Disabled != 0 {
		t.Fatalf("report = %+v", r)
	}
	if h.silo.get(id)["enabled"] != true {
		t.Fatal("paused plugin must not disable")
	}
}

func TestAccountDeletedInSiloMarksGrantDeleted(t *testing.T) {
	h := newHarness(t)
	id := h.silo.add("guest", "user", true)
	h.call(t, "PUT", "/api/admin/users/"+id+"/expiry", map[string]any{"mode": "days", "days": 1})
	delete(h.silo.accounts, id)
	h.now = h.now.Add(48 * time.Hour)
	if r := h.app.runExpiry(context.Background(), "test"); len(r.Errors) != 0 {
		t.Fatalf("report = %+v", r)
	}
	if g, _ := h.grant(t, id); g.Status != grantDeleted {
		t.Fatalf("grant = %+v", g)
	}
}

func TestSetAccessSendsNullForAllAndListOtherwise(t *testing.T) {
	h := newHarness(t)
	id := h.silo.add("guest", "user", true)
	if s, out := h.call(t, "PUT", "/api/admin/users/"+id+"/access", map[string]any{"all_libraries": false, "library_ids": []string{}}); s != 200 {
		t.Fatalf("%d %v", s, out)
	}
	if s, _ := h.call(t, "PUT", "/api/admin/users/"+id+"/access", map[string]any{"all_libraries": true, "group_set": true, "access_group_id": "3"}); s != 200 {
		t.Fatal(s)
	}
	if len(h.silo.puts) != 2 {
		t.Fatalf("puts = %v", h.silo.puts)
	}
	first, second := h.silo.puts[0], h.silo.puts[1]
	if ids, ok := first["library_ids"].([]any); !ok || len(ids) != 0 {
		t.Fatalf("empty list must be sent as [] (no libraries), got %#v", first["library_ids"])
	}
	if _, isGroup := first["access_group_id"]; isGroup {
		t.Fatal("group untouched unless group_set")
	}
	if v, ok := second["library_ids"]; !ok || v != nil {
		t.Fatalf("all libraries must be sent as null, got %#v", v)
	}
	if second["access_group_id"] != "3" {
		t.Fatalf("group = %v", second["access_group_id"])
	}
}

func TestStateListsAccountsAndGroupsNote(t *testing.T) {
	h := newHarness(t)
	h.silo.groups403 = true
	h.silo.add("boss", "admin", true)
	g := h.silo.add("guest", "user", true)
	h.call(t, "PUT", "/api/admin/users/"+g+"/expiry", map[string]any{"mode": "days", "days": 1})
	s, out := h.call(t, "GET", "/api/admin/state", nil)
	if s != 200 {
		t.Fatalf("%d %v", s, out)
	}
	accounts := out["accounts"].([]any)
	if len(accounts) != 2 {
		t.Fatalf("accounts = %v", accounts)
	}
	admin := accounts[0].(map[string]any)
	guest := accounts[1].(map[string]any)
	if admin["manageable"] != false || guest["manageable"] != true || guest["grant"] == nil {
		t.Fatalf("views = %v / %v", admin, guest)
	}
	if out["groups_note"] == nil {
		t.Fatal("expected a note about the access-groups scope")
	}
	if len(out["libraries"].([]any)) != 3 {
		t.Fatal("libraries missing")
	}
}

func TestPresetsValidated(t *testing.T) {
	h := newHarness(t)
	if s, _ := h.call(t, "PUT", "/api/admin/presets", []map[string]any{{"name": "Kids"}, {"name": "kids"}}); s != 422 {
		t.Fatalf("duplicate names: %d", s)
	}
	s, _ := h.call(t, "PUT", "/api/admin/presets", []map[string]any{{"name": "Movies only", "library_ids": []string{"1"}}})
	if s != 200 {
		t.Fatal(s)
	}
	list, _ := h.app.store.Presets(context.Background())
	if len(list) != 1 || list[0].ID == "" {
		t.Fatalf("presets = %+v", list)
	}
}

func TestRejectsNonAdminRole(t *testing.T) {
	h := newHarness(t)
	rs := &routeServer{app: h.app}
	resp, _ := rs.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: "GET", Path: "/api/admin/state", Headers: map[string]string{"X-Silo-User-Role": "user"}})
	if resp.GetStatusCode() != 403 {
		t.Fatalf("status %d", resp.GetStatusCode())
	}
}

func TestExpiryInputDate(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	if _, err := (ExpiryInput{Mode: "date", ExpiresAt: "2026-11-13T12:00:00Z"}).resolve(now, nil); err == nil {
		t.Fatal("past date accepted")
	}
	at, err := (ExpiryInput{Mode: "date", ExpiresAt: "2026-12-01T09:30:00-05:00"}).resolve(now, nil)
	if err != nil || !at.Equal(time.Date(2026, 12, 1, 14, 30, 0, 0, time.UTC)) {
		t.Fatalf("at=%v err=%v", at, err)
	}
}

func TestPageHasCSPForItsScript(t *testing.T) {
	html := string(adminPage)
	if strings.Contains(html, "__CSP__") || !strings.Contains(html, "script-src 'sha256-") {
		t.Fatal("CSP not filled in")
	}
}

func TestManifestIsValid(t *testing.T) {
	if _, err := manifest.LoadWithChecksum(manifestJSON, "0.1.0"); err != nil {
		t.Fatal(err)
	}
}

func TestMutationsNeedJSONContentType(t *testing.T) {
	h := newHarness(t)
	rs := &routeServer{app: h.app}
	// What a cross-site HTML form can send: text/plain with a JSON-looking body.
	body := []byte(`{"username":"evil","email":"e@x","access":{"all_libraries":true}}`)
	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x"} {
		resp, _ := rs.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: "POST", Path: "/api/admin/users", Body: body, Headers: map[string]string{"X-Silo-User-Role": "admin", "Content-Type": ct}})
		if resp.GetStatusCode() != 415 {
			t.Fatalf("content-type %q: status %d", ct, resp.GetStatusCode())
		}
	}
	if len(h.silo.accounts) != 0 {
		t.Fatal("no account may be created without a JSON content type")
	}
	resp, _ := rs.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: "POST", Path: "/api/admin/users", Body: body, Headers: map[string]string{"X-Silo-User-Role": "admin", "Content-Type": "application/json; charset=utf-8"}})
	if resp.GetStatusCode() != 201 {
		t.Fatalf("json: status %d %s", resp.GetStatusCode(), resp.GetBody())
	}
}

func TestGuestsGetDownloadsAndRequestsOffUnlessAllowed(t *testing.T) {
	h := newHarness(t)
	_, out := h.call(t, "POST", "/api/admin/users", map[string]any{"username": "g1", "email": "g1@x", "access": map[string]any{"all_libraries": true}})
	body := h.silo.get(out["id"].(string))["_body"].(map[string]any)
	if v, ok := body["download_allowed"]; !ok || v != false {
		t.Fatalf("download_allowed = %#v (must be sent as false)", v)
	}
	if v, ok := body["requests_allowed"]; !ok || v != false {
		t.Fatalf("requests_allowed = %#v (must be sent as false)", v)
	}
	_, out = h.call(t, "POST", "/api/admin/users", map[string]any{"username": "g2", "email": "g2@x", "allow_downloads": true, "allow_requests": true, "access": map[string]any{"all_libraries": true}})
	body = h.silo.get(out["id"].(string))["_body"].(map[string]any)
	if body["download_allowed"] != true || body["requests_allowed"] != true {
		t.Fatalf("body = %v", body)
	}
}

func TestExtendLeavesAdminDisabledAccountOff(t *testing.T) {
	h := newHarness(t)
	id := h.silo.add("guest", "user", true)
	h.call(t, "PUT", "/api/admin/users/"+id+"/expiry", map[string]any{"mode": "days", "days": 1})
	// An admin disables the account in Silo before it expires.
	h.silo.accounts[id]["enabled"] = false
	h.now = h.now.Add(48 * time.Hour)
	h.app.runExpiry(context.Background(), "test")
	if g, _ := h.grant(t, id); g.Status != grantExpired || g.DisabledByPlugin {
		t.Fatalf("grant = %+v", g)
	}
	_, out := h.call(t, "PUT", "/api/admin/users/"+id+"/expiry", map[string]any{"mode": "days", "days": 3})
	if out["reenabled"] == true || h.silo.get(id)["enabled"] != false {
		t.Fatal("an account an admin disabled must stay off when its expiry is extended")
	}
}

func TestManualDisableAfterExpiryIsRespectedOnExtend(t *testing.T) {
	h := newHarness(t)
	id := h.silo.add("guest", "user", true)
	h.call(t, "PUT", "/api/admin/users/"+id+"/expiry", map[string]any{"mode": "days", "days": 1})
	h.now = h.now.Add(48 * time.Hour)
	h.app.runExpiry(context.Background(), "test")
	// Admin turns it on, then off again by hand: the plugin no longer owns
	// the disabled state.
	h.call(t, "PUT", "/api/admin/users/"+id+"/enabled", map[string]any{"enabled": true})
	h.call(t, "PUT", "/api/admin/users/"+id+"/enabled", map[string]any{"enabled": false})
	_, out := h.call(t, "PUT", "/api/admin/users/"+id+"/expiry", map[string]any{"mode": "extend", "days": 3})
	if out["reenabled"] == true || h.silo.get(id)["enabled"] != false {
		t.Fatal("must not re-enable an account disabled by hand")
	}
}

func TestLongNotesAreClipped(t *testing.T) {
	h := newHarness(t)
	id := h.silo.add("guest", "user", true)
	h.call(t, "PUT", "/api/admin/users/"+id+"/expiry", map[string]any{"mode": "days", "days": 1, "note": strings.Repeat("x", 5000)})
	if g, _ := h.grant(t, id); len(g.Note) != maxNote {
		t.Fatalf("note length %d", len(g.Note))
	}
}
