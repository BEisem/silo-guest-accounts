package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	sdkruntime "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"
)

// Settings is what the admin page's Settings tab edits.
type Settings struct {
	// DefaultDays prefills the "days of access" field for a new guest.
	DefaultDays int `json:"default_days"`
	// DeleteAfterDays deletes an expired account this many days after it
	// was disabled; 0 never deletes.
	DeleteAfterDays int `json:"delete_after_days"`
	// ReenableOnExtend turns an account the plugin disabled back on when its
	// expiry is moved into the future.
	ReenableOnExtend bool `json:"reenable_on_extend"`
	// Paused stops the plugin from disabling or deleting anything.
	Paused bool `json:"paused"`
	// GuestDownloads and GuestRequests prefill the New guest form. Both are
	// off by default: offline downloads outlive the account, and requests
	// feed the arr stack.
	GuestDownloads bool `json:"guest_downloads"`
	GuestRequests  bool `json:"guest_requests"`
}

func defaultSettings() Settings {
	return Settings{DefaultDays: 7, ReenableOnExtend: true}
}

func (s *Settings) normalize() {
	if s.DefaultDays < 1 {
		s.DefaultDays = 1
	}
	if s.DefaultDays > 3650 {
		s.DefaultDays = 3650
	}
	if s.DeleteAfterDays < 0 {
		s.DeleteAfterDays = 0
	}
	if s.DeleteAfterDays > 3650 {
		s.DeleteAfterDays = 3650
	}
}

// Grant states.
const (
	grantActive  = "active"  // expiry is in the future (or due now)
	grantExpired = "expired" // the plugin disabled the account
	grantDeleted = "deleted" // the account is gone
)

// Grant is a time limit on one account.
type Grant struct {
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expires_at"`
	Note      string    `json:"note,omitempty"`
	Status    string    `json:"status"`
	ExpiredAt time.Time `json:"expired_at,omitzero"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
	// DisabledByPlugin is set when the plugin itself turned the account off
	// at expiry; only then does extending the expiry turn it back on.
	DisabledByPlugin bool `json:"disabled_by_plugin,omitempty"`
	// LastError is the most recent failure to expire the account; the
	// plugin keeps retrying on every check.
	LastError string `json:"last_error,omitempty"`
}

// Preset is a named library selection.
type Preset struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// AllLibraries sends library_ids: null; otherwise LibraryIDs is the
	// exact list.
	AllLibraries bool     `json:"all_libraries"`
	LibraryIDs   []string `json:"library_ids"`
	// AccessGroupID, when set, also puts the account in that group.
	AccessGroupID string `json:"access_group_id,omitempty"`
}

type LogEntry struct {
	Time     time.Time `json:"time"`
	UserID   string    `json:"user_id,omitempty"`
	Username string    `json:"username,omitempty"`
	Action   string    `json:"action"`
	Detail   string    `json:"detail,omitempty"`
	Error    string    `json:"error,omitempty"`
	By       string    `json:"by,omitempty"`
}

const (
	maxNote     = 300
	maxName     = 80
	keySettings = "settings"
	keyGrants   = "grants"
	keyPresets  = "presets"
	keyLog      = "log"
	logCap      = 300
	// deletedKeep is how long a grant for a deleted account stays listed.
	deletedKeep = 30 * 24 * time.Hour
)

var errNoHost = errors.New("silo host connection not ready yet")

// Store reads and writes instance state. Every process of an installation
// shares the same rows, so reads always go to the host; the mutex only
// serialises this process's read-modify-write cycles.
type Store struct {
	mu      sync.Mutex
	backend stateBackend // replaces the host's instance state in tests
}

type stateBackend interface {
	ReadInstanceState(ctx context.Context, key string) ([]byte, bool, error)
	WriteInstanceState(ctx context.Context, key string, value []byte) error
}

func (s *Store) host() stateBackend {
	if s.backend != nil {
		return s.backend
	}
	if h := sdkruntime.Host(); h != nil {
		return h
	}
	return nil
}

func (s *Store) read(ctx context.Context, key string, out any) (bool, error) {
	host := s.host()
	if host == nil {
		return false, errNoHost
	}
	raw, found, err := host.ReadInstanceState(ctx, key)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", key, err)
	}
	if !found || len(raw) == 0 {
		return false, nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return false, fmt.Errorf("decode %s: %w", key, err)
	}
	return true, nil
}

func (s *Store) write(ctx context.Context, key string, value any) error {
	host := s.host()
	if host == nil {
		return errNoHost
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := host.WriteInstanceState(ctx, key, raw); err != nil {
		return fmt.Errorf("write %s: %w", key, err)
	}
	return nil
}

func (s *Store) Settings(ctx context.Context) (Settings, error) {
	settings := defaultSettings()
	if _, err := s.read(ctx, keySettings, &settings); err != nil {
		return defaultSettings(), err
	}
	settings.normalize()
	return settings, nil
}

func (s *Store) SaveSettings(ctx context.Context, settings Settings) error {
	settings.normalize()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.write(ctx, keySettings, settings)
}

// Grants returns every grant keyed by account id.
func (s *Store) Grants(ctx context.Context) (map[string]Grant, error) {
	out := map[string]Grant{}
	if _, err := s.read(ctx, keyGrants, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateGrants runs fn on the current grants and writes the result back.
// Grants for accounts deleted more than deletedKeep ago are dropped.
func (s *Store) UpdateGrants(ctx context.Context, fn func(map[string]Grant) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	grants := map[string]Grant{}
	if _, err := s.read(ctx, keyGrants, &grants); err != nil {
		return err
	}
	if err := fn(grants); err != nil {
		return err
	}
	cutoff := time.Now().Add(-deletedKeep)
	for id, g := range grants {
		if g.Status == grantDeleted && g.UpdatedAt.Before(cutoff) {
			delete(grants, id)
		}
	}
	return s.write(ctx, keyGrants, grants)
}

func (s *Store) Presets(ctx context.Context) ([]Preset, error) {
	var out []Preset
	if _, err := s.read(ctx, keyPresets, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []Preset{}
	}
	return out, nil
}

func (s *Store) SavePresets(ctx context.Context, presets []Preset) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.write(ctx, keyPresets, presets)
}

func (s *Store) Log(ctx context.Context) ([]LogEntry, error) {
	var out []LogEntry
	if _, err := s.read(ctx, keyLog, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []LogEntry{}
	}
	return out, nil
}

// AddLog appends entries, newest first, keeping logCap of them.
func (s *Store) AddLog(ctx context.Context, entries ...LogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var list []LogEntry
	if _, err := s.read(ctx, keyLog, &list); err != nil {
		return err
	}
	list = append(entries, list...)
	sort.SliceStable(list, func(i, j int) bool { return list[i].Time.After(list[j].Time) })
	if len(list) > logCap {
		list = list[:logCap]
	}
	return s.write(ctx, keyLog, list)
}
