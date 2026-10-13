package approval

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LionZXY/bitwarden-approval-mcp/internal/telegram"
)

func grantRequest(agent, item string, fields ...string) *Request {
	return &Request{Agent: agent, ItemID: item, ItemName: "GitHub", Fields: fields, Reason: "deploy", Tool: "get_credential"}
}

// The owner presses while sendMessage is still returning. This also covers
// installing the grant before waking the blocked credential request.
func approveWith(t *testing.T, m *Manager, b *fakeBot, r *Request, action string) string {
	t.Helper()
	var data string
	b.onSend = func(_ string, buttons []telegram.Button) {
		for _, button := range buttons {
			if strings.HasPrefix(button.CallbackData, action+":") {
				data = button.CallbackData
				m.handleCallback(context.Background(), &telegram.CallbackQuery{ID: "cb", From: telegram.User{ID: owner}, Data: data})
				return
			}
		}
		t.Errorf("missing %s button", action)
	}
	out, err := m.Request(context.Background(), r)
	if err != nil || out != Approved {
		t.Fatalf("approval: %s, %v", out, err)
	}
	b.onSend = nil
	return data
}

func TestApprovalDurationButtons(t *testing.T) {
	for _, tc := range []struct {
		action, label string
		duration      time.Duration
	}{
		{"a15", "Approve for 15 min", 15 * time.Minute},
		{"a60", "Approve for 1h", time.Hour},
		{"af", "Approve forever", 0},
	} {
		t.Run(tc.action, func(t *testing.T) {
			b := newFakeBot()
			m, buf := newMgr(t, b, time.Second)
			r := grantRequest("agentA", "item1", "password", "username")
			before := time.Now()
			data := approveWith(t, m, b, r, tc.action)
			g := m.grants[grantKey{"agentA", "item1", "password"}]
			if tc.duration == 0 {
				if !g.Expires.IsZero() || !strings.Contains(b.lastEdit(), "forever") {
					t.Fatal("forever approval was not permanent")
				}
			} else if g.Expires.Before(before.Add(tc.duration)) || g.Expires.After(time.Now().Add(tc.duration)) {
				t.Fatalf("incorrect expiry: %v", g.Expires)
			}
			// Reordered fields and subsets do not require another Telegram prompt.
			for _, fields := range [][]string{{"username", "password"}, {"password"}} {
				reuse := grantRequest("agentA", "item1", fields...)
				out, err := m.Request(context.Background(), reuse)
				if err != nil || out != Approved || reuse.ID == "" || reuse.ID == r.ID {
					t.Fatalf("reuse: %s %v id=%q", out, err, reuse.ID)
				}
			}
			if b.nextID != 1 || !strings.Contains(buf.String(), "approval_reused") {
				t.Fatal("reuse sent a prompt or was not audited")
			}
			// A replay cannot create or extend a saved approval.
			m.handleCallback(context.Background(), &telegram.CallbackQuery{ID: "replay", From: telegram.User{ID: owner}, Data: data})
			if m.grants[g.grantKey] != g {
				t.Fatal("replay changed grant")
			}
		})
	}
}

func TestGrantScopeAndExpiry(t *testing.T) {
	b := newFakeBot()
	m, _ := newMgr(t, b, 10*time.Millisecond)
	approveWith(t, m, b, grantRequest("agentA", "item1", "password", "totp"), "a15")
	// An approval for totp works for get_totp as well as get_credential.
	r := grantRequest("agentA", "item1", "totp")
	r.Tool = "get_totp"
	if out, err := m.Request(context.Background(), r); err != nil || out != Approved {
		t.Fatalf("TOTP reuse: %s %v", out, err)
	}
	for _, r := range []*Request{
		grantRequest("agentB", "item1", "password"),
		grantRequest("agentA", "item2", "password"),
		grantRequest("agentA", "item1", "password", "notes"),
		grantRequest("agentA", "", "password"),
	} {
		if out, err := m.Request(context.Background(), r); err != nil || out != TimedOut {
			t.Fatalf("approval escaped scope: %s %v", out, err)
		}
	}
	key := grantKey{"agentA", "item1", "password"}
	g := m.grants[key]
	g.Expires = time.Now().Add(-time.Second)
	m.grants[key] = g
	if out, err := m.Request(context.Background(), grantRequest("agentA", "item1", "password")); err != nil || out != TimedOut {
		t.Fatalf("expired approval reused: %s %v", out, err)
	}
}

func TestSavedGrantsSurviveRestart(t *testing.T) {
	b := newFakeBot()
	m, _ := newMgr(t, b, time.Second)
	m.cfg.GrantsFile = filepath.Join(t.TempDir(), "approvals.json")
	approveWith(t, m, b, grantRequest("agentA", "item1", "password"), "af")
	approveWith(t, m, b, grantRequest("agentA", "item2", "totp"), "a60")
	info, err := os.Stat(m.cfg.GrantsFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions: %v %v", info, err)
	}
	b2 := newFakeBot()
	m2, _ := newMgr(t, b2, time.Second)
	m2.cfg.GrantsFile = m.cfg.GrantsFile
	if err := m2.LoadGrants(); err != nil {
		t.Fatal(err)
	}
	for _, r := range []*Request{grantRequest("agentA", "item1", "password"), grantRequest("agentA", "item2", "totp")} {
		if out, err := m2.Request(context.Background(), r); err != nil || out != Approved {
			t.Fatalf("restored approval: %s %v", out, err)
		}
	}
	if b2.nextID != 0 {
		t.Fatal("restored approvals sent prompts")
	}
	m2.Lock()
	if _, err := m2.Request(context.Background(), grantRequest("agentA", "item1", "password")); err != ErrLocked {
		t.Fatal("saved approval bypassed lock")
	}
	m3, _ := newMgr(t, newFakeBot(), time.Second)
	m3.cfg.GrantsFile = m.cfg.GrantsFile
	if err := m3.LoadGrants(); err != nil || len(m3.grants) != 0 {
		t.Fatalf("lock did not revoke persisted grants: %v", err)
	}
}

func TestSavedApprovalWriteFailure(t *testing.T) {
	b := newFakeBot()
	m, _ := newMgr(t, b, 10*time.Millisecond)
	m.cfg.GrantsFile = filepath.Join(t.TempDir(), "missing", "approvals.json")
	b.onSend = func(_ string, buttons []telegram.Button) {
		for _, button := range buttons {
			if strings.HasPrefix(button.CallbackData, "af:") {
				m.handleCallback(context.Background(), &telegram.CallbackQuery{ID: "cb", From: telegram.User{ID: owner}, Data: button.CallbackData})
			}
		}
	}
	out, err := m.Request(context.Background(), grantRequest("agentA", "item1", "password"))
	if err != nil || out != TimedOut || len(m.grants) != 0 {
		t.Fatalf("write failure released credentials: %s %v", out, err)
	}
	if !strings.Contains(b.toasts[0], "Could not save approval") {
		t.Fatal("write failure was not reported")
	}
}

func TestSavedApprovalOwnerAndExpiryChecks(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		wrongUser, expired, cancelled bool
	}{
		{name: "wrong user", wrongUser: true},
		{name: "expired", expired: true},
		{name: "cancelled", cancelled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newFakeBot()
			m, _ := newMgr(t, b, 10*time.Millisecond)
			r := grantRequest("agentA", "item1", "password")
			b.onSend = func(_ string, buttons []telegram.Button) {
				user := owner
				if tc.wrongUser {
					user++
				}
				if tc.expired {
					r.Expires = time.Now().Add(-time.Second)
				}
				if tc.cancelled {
					m.resolve(r.nonce, Cancelled, 0)
				}
				for _, button := range buttons {
					if strings.HasPrefix(button.CallbackData, "af:") {
						m.handleCallback(context.Background(), &telegram.CallbackQuery{ID: "cb", From: telegram.User{ID: user}, Data: button.CallbackData})
					}
				}
			}
			out, _ := m.Request(context.Background(), r)
			if out == Approved || len(m.grants) != 0 {
				t.Fatal("invalid press created a grant")
			}
		})
	}
}

func TestGrantLoadFailsClosed(t *testing.T) {
	b := newFakeBot()
	m, _ := newMgr(t, b, time.Second)
	m.cfg.GrantsFile = filepath.Join(t.TempDir(), "approvals.json")
	if err := m.LoadGrants(); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{
		`not json`,
		`{"version":1,"owner_user_id":999,"grants":[]}`,
		`{"version":1,"owner_user_id":42,"grants":[{"agent":"a","item_id":"i","field":"password","by_user":999}]}`,
	} {
		if err := os.WriteFile(m.cfg.GrantsFile, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := m.LoadGrants(); err == nil {
			t.Fatal("invalid store accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Request(ctx, grantRequest("a", "i", "password")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
