package approval

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type grantKey struct {
	Agent  string `json:"agent"`
	ItemID string `json:"item_id"`
	Field  string `json:"field"`
}

type grant struct {
	grantKey
	Expires time.Time `json:"expires"` // zero means forever
	ByUser  int64     `json:"by_user"`
}

type grantStore struct {
	Version int     `json:"version"`
	Owner   int64   `json:"owner_user_id"`
	Grants  []grant `json:"grants"`
}

// LoadGrants loads saved approvals before accepting requests. Malformed or
// wrong-owner files fail closed. A missing file means there are no approvals.
func (m *Manager) LoadGrants() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg.GrantsFile == "" {
		return nil
	}
	data, err := os.ReadFile(m.cfg.GrantsFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var store grantStore
	if err := json.Unmarshal(data, &store); err != nil {
		return fmt.Errorf("decode saved approvals: %w", err)
	}
	if store.Version != 1 || store.Owner != m.cfg.OwnerUserID {
		return errors.New("saved approvals have an unsupported version or different owner")
	}
	loaded := map[grantKey]grant{}
	for _, g := range store.Grants {
		if g.Agent == "" || g.ItemID == "" || g.Field == "" || g.ByUser != m.cfg.OwnerUserID {
			return errors.New("invalid saved approval")
		}
		if g.Expires.IsZero() || time.Now().Before(g.Expires) {
			loaded[g.grantKey] = g
		}
	}
	m.grants = loaded
	return nil
}

func (m *Manager) matchGrantLocked(r *Request, now time.Time) (grant, bool) {
	if r.Agent == "" || r.ItemID == "" || len(r.Fields) == 0 {
		return grant{}, false
	}
	var matched grant
	for _, field := range r.Fields {
		key := grantKey{r.Agent, r.ItemID, field}
		g, ok := m.grants[key]
		if ok && !g.Expires.IsZero() && !now.Before(g.Expires) {
			delete(m.grants, key)
			ok = false
		}
		if !ok {
			return grant{}, false
		}
		matched = g
	}
	return matched, true
}

func (m *Manager) addGrantLocked(r *Request, byUser int64, duration time.Duration, forever bool) error {
	if r.Agent == "" || r.ItemID == "" || len(r.Fields) == 0 {
		return errors.New("saved approval requires an agent, item id and fields")
	}
	until := time.Time{}
	if !forever {
		until = time.Now().Add(duration)
	}
	next := make(map[grantKey]grant, len(m.grants)+len(r.Fields))
	for key, g := range m.grants {
		if g.Expires.IsZero() || time.Now().Before(g.Expires) {
			next[key] = g
		}
	}
	for _, field := range r.Fields {
		if field == "" {
			return errors.New("saved approval requires nonempty fields")
		}
		key := grantKey{r.Agent, r.ItemID, field}
		if old, ok := next[key]; ok && (old.Expires.IsZero() || (!until.IsZero() && old.Expires.After(until))) {
			continue // Never shorten an existing approval.
		}
		next[key] = grant{grantKey: key, Expires: until, ByUser: byUser}
	}
	if err := m.saveGrantsLocked(next); err != nil {
		return err
	}
	m.grants = next
	r.grantUntil, r.grantForever = until, forever
	return nil
}

// saveGrantsLocked replaces the metadata-only file atomically with mode 0600.
// A write failure must not release credentials or install a grant in memory.
func (m *Manager) saveGrantsLocked(grants map[grantKey]grant) error {
	if m.cfg.GrantsFile == "" {
		return nil
	}
	store := grantStore{Version: 1, Owner: m.cfg.OwnerUserID, Grants: []grant{}}
	for _, g := range grants {
		store.Grants = append(store.Grants, g)
	}
	sort.Slice(store.Grants, func(i, j int) bool {
		a, b := store.Grants[i], store.Grants[j]
		if a.Agent != b.Agent {
			return a.Agent < b.Agent
		}
		if a.ItemID != b.ItemID {
			return a.ItemID < b.ItemID
		}
		return a.Field < b.Field
	})
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(m.cfg.GrantsFile), ".approvals-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), m.cfg.GrantsFile)
}

func grantDetail(r *Request) string {
	if r.outcome != Approved {
		return ""
	}
	if r.grantForever {
		return "Approval: forever (this agent, item, and fields only)."
	}
	if !r.grantUntil.IsZero() {
		return "Approval until: " + r.grantUntil.Format(time.RFC3339)
	}
	return "Approval: this request only."
}
