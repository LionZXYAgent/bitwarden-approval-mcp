package approval

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LionZXY/bitwarden-approval-mcp/internal/audit"
	"github.com/LionZXY/bitwarden-approval-mcp/internal/telegram"
)

// fakeBot records sent/edited messages and lets tests inject button presses.
type fakeBot struct {
	mu      sync.Mutex
	sent    map[int]string // messageID -> text
	edited  map[int]string
	toasts  []string
	nextID  int
	updates chan telegram.Update
	onSend  func(text string, buttons []telegram.Button)
}

func newFakeBot() *fakeBot {
	return &fakeBot{sent: map[int]string{}, edited: map[int]string{}, updates: make(chan telegram.Update, 16)}
}

func (b *fakeBot) SendMessage(_ context.Context, _ int64, text string, buttons []telegram.Button) (int, error) {
	b.mu.Lock()
	b.nextID++
	id := b.nextID
	b.sent[id] = text
	cb := b.onSend
	b.mu.Unlock()
	if cb != nil {
		cb(text, buttons)
	}
	return id, nil
}

func (b *fakeBot) EditMessageText(_ context.Context, _ int64, id int, text string) error {
	b.mu.Lock()
	b.edited[id] = text
	b.mu.Unlock()
	return nil
}

func (b *fakeBot) AnswerCallbackQuery(_ context.Context, _, text string) error {
	b.mu.Lock()
	b.toasts = append(b.toasts, text)
	b.mu.Unlock()
	return nil
}

func (b *fakeBot) GetUpdates(ctx context.Context, _ int64, _ int) ([]telegram.Update, error) {
	select {
	case u := <-b.updates:
		return []telegram.Update{u}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(20 * time.Millisecond):
		return nil, nil
	}
}

func waitEdit(b *fakeBot, want string) bool {
	for i := 0; i < 100; i++ {
		if strings.Contains(b.lastEdit(), want) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func (b *fakeBot) lastEdit() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var last string
	for _, v := range b.edited {
		last = v
	}
	return last
}

// syncBuf is a goroutine-safe buffer for capturing audit output in tests.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuf) waitContains(sub string) bool {
	for i := 0; i < 100; i++ {
		if strings.Contains(b.String(), sub) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

const owner = int64(42)

func pressButton(b *fakeBot, data string, user int64) {
	b.updates <- telegram.Update{UpdateID: time.Now().UnixNano(),
		CallbackQuery: &telegram.CallbackQuery{ID: "cb", From: telegram.User{ID: user}, Data: data}}
}

func newMgr(t *testing.T, b *fakeBot, timeout time.Duration) (*Manager, *syncBuf) {
	t.Helper()
	buf := &syncBuf{}
	m := NewManager(b, Config{OwnerUserID: owner, OwnerChatID: owner, Timeout: timeout,
		MaxPendingPerAgent: 2, MaxPendingTotal: 3}, audit.New(buf), nil)
	return m, buf
}

// waitButtonData captures the callback data that the Allow button carries.
func captureAllow(b *fakeBot) chan string {
	ch := make(chan string, 1)
	b.onSend = func(_ string, buttons []telegram.Button) {
		for _, bt := range buttons {
			if strings.HasPrefix(bt.CallbackData, "a:") {
				select {
				case ch <- bt.CallbackData:
				default:
				}
			}
		}
	}
	return ch
}

func TestApproveFlow(t *testing.T) {
	b := newFakeBot()
	allow := captureAllow(b)
	m, auditBuf := newMgr(t, b, 2*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	done := make(chan Outcome, 1)
	go func() {
		o, _ := m.Request(ctx, &Request{Agent: "agentA", ItemName: "GitHub", Fields: []string{"password"}, Reason: "deploy"})
		done <- o
	}()
	data := <-allow
	pressButton(b, data, owner)
	select {
	case o := <-done:
		if o != Approved {
			t.Fatalf("got %s", o)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for approval")
	}
	if !waitEdit(b, "ALLOWED") {
		t.Fatalf("message not edited to ALLOWED: %q", b.lastEdit())
	}
	if !auditBuf.waitContains(`"outcome":"approved"`) {
		t.Fatal("audit missing approved outcome")
	}
	// No secret value should appear anywhere in telegram text.
	if strings.Contains(b.sent[1], "deploy") == false {
		t.Fatal("reason should appear in prompt")
	}
}

func TestDeclineFlow(t *testing.T) {
	b := newFakeBot()
	allow := captureAllow(b)
	m, _ := newMgr(t, b, 2*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	done := make(chan Outcome, 1)
	go func() {
		o, _ := m.Request(ctx, &Request{Agent: "a", ItemName: "X", Fields: []string{"password"}, Reason: "r"})
		done <- o
	}()
	data := <-allow
	pressButton(b, "d:"+strings.TrimPrefix(data, "a:"), owner)
	if o := <-done; o != Declined {
		t.Fatalf("got %s", o)
	}
	if !waitEdit(b, "DECLINED") {
		t.Fatal("not edited to DECLINED")
	}
}

func TestWrongUserIgnored(t *testing.T) {
	b := newFakeBot()
	allow := captureAllow(b)
	m, auditBuf := newMgr(t, b, 1*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	done := make(chan Outcome, 1)
	go func() {
		o, _ := m.Request(ctx, &Request{Agent: "a", ItemName: "X", Fields: []string{"password"}, Reason: "r"})
		done <- o
	}()
	data := <-allow
	pressButton(b, data, int64(9999)) // attacker
	// Should NOT approve; should time out instead.
	select {
	case o := <-done:
		if o != TimedOut {
			t.Fatalf("wrong user caused outcome %s", o)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("did not time out")
	}
	if !auditBuf.waitContains("wrong_user_press") {
		t.Fatal("wrong user press not audited")
	}
}

func TestTimeout(t *testing.T) {
	b := newFakeBot()
	m, _ := newMgr(t, b, 300*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	o, _ := m.Request(ctx, &Request{Agent: "a", ItemName: "X", Fields: []string{"password"}, Reason: "r"})
	if o != TimedOut {
		t.Fatalf("got %s", o)
	}
	if !waitEdit(b, "TIMED OUT") {
		t.Fatal("not edited to TIMED OUT")
	}
}

func TestSingleUse(t *testing.T) {
	b := newFakeBot()
	allow := captureAllow(b)
	m, _ := newMgr(t, b, 2*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	done := make(chan Outcome, 1)
	go func() {
		o, _ := m.Request(ctx, &Request{Agent: "a", ItemName: "X", Fields: []string{"password"}, Reason: "r"})
		done <- o
	}()
	data := <-allow
	pressButton(b, data, owner)
	<-done
	waitEdit(b, "ALLOWED")
	// A second press of the same button must be a no-op (already delivered).
	before := b.lastEdit()
	pressButton(b, data, owner)
	time.Sleep(100 * time.Millisecond)
	if b.lastEdit() != before {
		t.Fatal("second press changed state")
	}
}

func TestMaxPending(t *testing.T) {
	b := newFakeBot()
	m, _ := newMgr(t, b, 5*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	// per-agent limit is 2.
	for i := 0; i < 2; i++ {
		go m.Request(ctx, &Request{Agent: "a", ItemName: "X", Fields: []string{"password"}, Reason: "r"})
	}
	time.Sleep(100 * time.Millisecond)
	_, err := m.Request(ctx, &Request{Agent: "a", ItemName: "Y", Fields: []string{"password"}, Reason: "r"})
	if err == nil {
		t.Fatal("expected too-many-pending error")
	}
}

func TestLock(t *testing.T) {
	b := newFakeBot()
	m, _ := newMgr(t, b, 5*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	done := make(chan Outcome, 1)
	go func() {
		o, _ := m.Request(ctx, &Request{Agent: "a", ItemName: "X", Fields: []string{"password"}, Reason: "r"})
		done <- o
	}()
	time.Sleep(100 * time.Millisecond)
	m.Lock()
	if o := <-done; o != Cancelled {
		t.Fatalf("got %s", o)
	}
	if _, err := m.Request(ctx, &Request{Agent: "a", ItemName: "Y", Fields: []string{"password"}, Reason: "r"}); err != ErrLocked {
		t.Fatalf("expected ErrLocked, got %v", err)
	}
}

func TestSanitize(t *testing.T) {
	got := sanitize("line1\nline2\x00\x07trailing", 0)
	if strings.ContainsAny(got, "\n\x00\x07") {
		t.Fatalf("sanitize left control chars: %q", got)
	}
	if sanitize("", 0) != "(none)" {
		t.Fatal("empty should be (none)")
	}
}
