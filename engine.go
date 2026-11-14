package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"google.golang.org/protobuf/types/known/structpb"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	sdkruntime "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"
)

// tickEvery is how often a running plugin process checks for expired
// accounts on its own, so access ends within minutes even if the scheduled
// task runs rarely.
const tickEvery = 5 * time.Minute

type App struct {
	log   hclog.Logger
	store *Store

	mu  sync.RWMutex
	cfg Config

	runMu    sync.Mutex
	loopOnce sync.Once

	reportMu   sync.Mutex
	lastReport *RunReport

	// now and base replace the clock and the Silo address in tests.
	now  func() time.Time
	base string
	// libs replaces the host's library list in tests.
	libs []*pluginv1.Library
}

func newApp(log hclog.Logger) *App {
	return &App{log: log, store: &Store{}, now: time.Now}
}

func (a *App) configure(entries []*pluginv1.ConfigEntry) {
	cfg := parseConfig(entries)
	a.mu.Lock()
	a.cfg = cfg
	a.mu.Unlock()
	a.ensureLoop()
}

func (a *App) config() Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg
}

// ensureLoop starts the background check once per process.
func (a *App) ensureLoop() {
	a.loopOnce.Do(func() {
		go func() {
			// A first check shortly after start covers accounts that ran out
			// while the plugin was stopped.
			time.Sleep(20 * time.Second)
			a.tick()
			t := time.NewTicker(tickEvery)
			defer t.Stop()
			for range t.C {
				a.tick()
			}
		}()
	})
}

func (a *App) tick() {
	if a.config().APIKey == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	a.runExpiry(ctx, "timer")
}

// siloBase is the Silo API address the plugin dials.
func (a *App) siloBase(ctx context.Context) string {
	if a.base != "" {
		return a.base
	}
	if b := a.config().BaseURL; b != "" {
		return b
	}
	if host := sdkruntime.Host(); host != nil {
		if info, err := host.GetHostInfo(ctx); err == nil {
			if u := loopbackURL(info.InternalBaseURL); u != "" {
				return u
			}
		} else {
			a.log.Warn("host info unavailable", "error", err)
		}
	}
	return "http://127.0.0.1:8080"
}

// loopbackURL turns a listener such as http://:8080 or http://0.0.0.0:8080
// into an address the plugin can dial.
func loopbackURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return strings.TrimRight(raw, "/")
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		u.Host = net.JoinHostPort("127.0.0.1", port)
	}
	return strings.TrimRight(u.String(), "/")
}

var errNoKey = errors.New("no Silo API key configured")

func (a *App) client(ctx context.Context) (*SiloClient, error) {
	cfg := a.config()
	if cfg.APIKey == "" {
		return nil, errNoKey
	}
	return newSiloClient(a.siloBase(ctx), cfg.APIKey), nil
}

func (a *App) libraries(ctx context.Context) []*pluginv1.Library {
	if a.libs != nil {
		return a.libs
	}
	if host := sdkruntime.Host(); host != nil {
		libs, err := host.ListLibraries(ctx, "")
		if err == nil {
			return libs
		}
		a.log.Warn("list libraries", "error", err)
	}
	return nil
}

// RunReport is what one expiry check did.
type RunReport struct {
	Time     time.Time `json:"time"`
	Source   string    `json:"source"`
	Due      int       `json:"due"`
	Disabled int       `json:"disabled"`
	Deleted  int       `json:"deleted"`
	Skipped  string    `json:"skipped,omitempty"`
	Errors   []string  `json:"errors,omitempty"`
}

var (
	errIsAdmin    = errors.New("administrator accounts are not managed by this plugin")
	errAlreadyOff = errors.New("already disabled")
	errReenabled  = errors.New("re-enabled since it expired")
)

// runExpiry disables every account whose time is up, then deletes expired
// accounts whose grace period has passed (when that is turned on).
func (a *App) runExpiry(ctx context.Context, source string) RunReport {
	a.runMu.Lock()
	defer a.runMu.Unlock()
	now := a.now().UTC()
	report := RunReport{Time: now, Source: source}
	defer func() {
		a.reportMu.Lock()
		r := report
		a.lastReport = &r
		a.reportMu.Unlock()
	}()

	settings, err := a.store.Settings(ctx)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}
	if settings.Paused {
		report.Skipped = "paused in Settings"
		return report
	}
	client, err := a.client(ctx)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}
	grants, err := a.store.Grants(ctx)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	type outcome struct {
		grant Grant // the grant as read, to detect a concurrent edit
		next  Grant
	}
	var (
		results []outcome
		logs    []LogEntry
	)
	for id, g := range grants {
		if g.Status != grantActive || g.ExpiresAt.After(now) {
			continue
		}
		report.Due++
		next := g
		next.UpdatedAt = now
		acct, err := client.UpdateAccount(ctx, id, map[string]any{"enabled": false}, func(acct Account) error {
			if acct.isAdmin() {
				return errIsAdmin
			}
			if !acct.Enabled {
				return errAlreadyOff
			}
			return nil
		})
		name := g.Username
		if acct.Username != "" {
			name = acct.Username
			next.Username = acct.Username
		}
		switch {
		case err == nil:
			next.Status, next.ExpiredAt, next.LastError = grantExpired, now, ""
			next.DisabledByPlugin = true
			report.Disabled++
			logs = append(logs, LogEntry{Time: now, UserID: id, Username: name, Action: "expired", Detail: "Access ended " + g.ExpiresAt.Format(time.RFC3339) + "; account disabled and signed out.", By: source})
		case errors.Is(err, errAlreadyOff):
			next.Status, next.ExpiredAt, next.LastError = grantExpired, now, ""
			next.DisabledByPlugin = false
			logs = append(logs, LogEntry{Time: now, UserID: id, Username: name, Action: "expired", Detail: "Access ended; the account was already disabled.", By: source})
		case statusOf(err) == http.StatusNotFound:
			next.Status, next.LastError = grantDeleted, ""
			logs = append(logs, LogEntry{Time: now, UserID: id, Username: name, Action: "removed", Detail: "Access ended, but the account had already been deleted in Silo.", By: source})
		default:
			msg := describeErr(err)
			if next.LastError != msg {
				logs = append(logs, LogEntry{Time: now, UserID: id, Username: name, Action: "expire failed", Error: msg, By: source})
			}
			next.LastError = msg
			report.Errors = append(report.Errors, name+": "+msg)
			a.log.Warn("expire account", "user_id", id, "error", err)
		}
		results = append(results, outcome{grant: g, next: next})
	}

	if settings.DeleteAfterDays > 0 {
		grace := time.Duration(settings.DeleteAfterDays) * 24 * time.Hour
		for id, g := range grants {
			if g.Status != grantExpired || g.ExpiredAt.IsZero() || now.Sub(g.ExpiredAt) < grace || g.LastError == errReenabled.Error() {
				continue
			}
			next := g
			next.UpdatedAt = now
			err := client.DeleteAccount(ctx, id, func(acct Account) error {
				if acct.isAdmin() {
					return errIsAdmin
				}
				if acct.Enabled {
					return errReenabled
				}
				return nil
			})
			switch {
			case err == nil, statusOf(err) == http.StatusNotFound:
				next.Status, next.LastError = grantDeleted, ""
				if err == nil {
					report.Deleted++
					logs = append(logs, LogEntry{Time: now, UserID: id, Username: g.Username, Action: "deleted", Detail: fmt.Sprintf("Deleted %d day(s) after it expired.", settings.DeleteAfterDays), By: source})
				}
			case errors.Is(err, errReenabled):
				next.LastError = errReenabled.Error()
				logs = append(logs, LogEntry{Time: now, UserID: id, Username: g.Username, Action: "kept", Detail: "Not deleted: the account was turned back on in Silo after it expired.", By: source})
			default:
				msg := describeErr(err)
				if next.LastError != msg {
					logs = append(logs, LogEntry{Time: now, UserID: id, Username: g.Username, Action: "delete failed", Error: msg, By: source})
				}
				next.LastError = msg
				report.Errors = append(report.Errors, g.Username+": "+msg)
			}
			results = append(results, outcome{grant: g, next: next})
		}
	}

	if len(results) > 0 {
		err := a.store.UpdateGrants(ctx, func(current map[string]Grant) error {
			for _, r := range results {
				cur, ok := current[r.grant.UserID]
				// An admin may have extended or removed the expiry while
				// this run talked to Silo; their edit wins.
				if !ok || !cur.ExpiresAt.Equal(r.grant.ExpiresAt) || cur.Status != r.grant.Status {
					continue
				}
				current[r.grant.UserID] = r.next
			}
			return nil
		})
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
		}
	}
	if err := a.store.AddLog(ctx, logs...); err != nil {
		a.log.Warn("write log", "error", err)
	}
	if report.Disabled > 0 || report.Deleted > 0 || len(report.Errors) > 0 {
		a.log.Info("expiry check", "source", source, "due", report.Due, "disabled", report.Disabled, "deleted", report.Deleted, "errors", len(report.Errors))
	}
	return report
}

// describeErr turns Silo's answers into something an admin can act on.
func describeErr(err error) string {
	switch statusOf(err) {
	case http.StatusUnauthorized:
		return "Silo rejected the API key (401). Check the key under the plugin's Silo connection settings."
	case http.StatusForbidden:
		var ae *apiError
		errors.As(err, &ae)
		return "Silo refused the change (403): " + ae.Detail + ". The key needs the admin:users scope, and admin accounts can't be changed with it."
	}
	return err.Error()
}

func (a *App) report() *RunReport {
	a.reportMu.Lock()
	defer a.reportMu.Unlock()
	return a.lastReport
}

type taskServer struct {
	pluginv1.UnimplementedScheduledTaskServer
	app *App
}

// Run is the scheduled task. Silo runs it at startup by default, which also
// starts the plugin process and its own timer.
func (s *taskServer) Run(ctx context.Context, _ *pluginv1.RunScheduledTaskRequest) (*pluginv1.RunScheduledTaskResponse, error) {
	s.app.ensureLoop()
	report := s.app.runExpiry(ctx, "scheduled task")
	errs := make([]any, 0, len(report.Errors))
	for _, e := range report.Errors {
		errs = append(errs, e)
	}
	out, _ := structpb.NewStruct(map[string]any{
		"due":      report.Due,
		"disabled": report.Disabled,
		"deleted":  report.Deleted,
		"skipped":  report.Skipped,
		"errors":   errs,
	})
	return &pluginv1.RunScheduledTaskResponse{Output: out}, nil
}
