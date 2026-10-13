// Package approval gates credential requests with owner approval on Telegram.
// Approvals can cover one request or specific fields for a chosen duration.
package approval

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/LionZXY/bitwarden-approval-mcp/internal/audit"
	"github.com/LionZXY/bitwarden-approval-mcp/internal/telegram"
)

// Bot is the subset of the Telegram client used by the manager.
type Bot interface {
	SendMessage(ctx context.Context, chatID int64, text string, buttons []telegram.Button) (int, error)
	EditMessageText(ctx context.Context, chatID int64, messageID int, text string) error
	AnswerCallbackQuery(ctx context.Context, id, text string) error
	GetUpdates(ctx context.Context, offset int64, timeoutSec int) ([]telegram.Update, error)
}

// Outcome of a request.
type Outcome string

// Outcome values.
const (
	Pending   Outcome = "pending"
	Approved  Outcome = "approved"
	Declined  Outcome = "declined"
	TimedOut  Outcome = "timed_out"
	Cancelled Outcome = "cancelled"
)

// Errors.
var (
	ErrUnknownRequest = errors.New("unknown or expired request id")
	ErrTooManyPending = errors.New("too many pending approval requests; wait for the owner to respond")
	ErrLocked         = errors.New("access has been locked by the owner")
)

// Request describes what the agent wants. All strings are untrusted except
// Agent (derived from the authenticated token) and the item metadata.
type Request struct {
	Agent    string
	Client   string
	Remote   string
	Tool     string
	ItemID   string
	ItemName string
	Folder   string
	Org      string
	Reprompt bool
	Fields   []string
	Reason   string

	ID      string
	Created time.Time
	Expires time.Time

	nonce        string
	decidedBy    int64
	messageID    int
	grantUntil   time.Time
	grantForever bool
	outcome      Outcome
	done         chan struct{}
	timer        *time.Timer
}

// Config for the manager.
type Config struct {
	OwnerUserID        int64
	OwnerChatID        int64
	Timeout            time.Duration
	MaxPendingPerAgent int
	MaxPendingTotal    int
	Location           *time.Location
	GrantsFile         string // empty keeps grants in memory (tests/embedded use)
}

// Manager coordinates approval requests and the Telegram update loop.
type Manager struct {
	cfg   Config
	bot   Bot
	audit *audit.Logger
	log   *slog.Logger

	mu      sync.Mutex
	byID    map[string]*Request
	byNonce map[string]*Request
	locked  bool
	grants  map[grantKey]grant
	offset  int64
}

// NewManager builds a manager. Defaults are filled for zero values.
func NewManager(bot Bot, cfg Config, al *audit.Logger, log *slog.Logger) *Manager {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Minute
	}
	if cfg.MaxPendingPerAgent <= 0 {
		cfg.MaxPendingPerAgent = 3
	}
	if cfg.MaxPendingTotal <= 0 {
		cfg.MaxPendingTotal = 20
	}
	if cfg.Location == nil {
		cfg.Location = time.UTC
	}
	if log == nil {
		log = slog.Default()
	}
	return &Manager{cfg: cfg, bot: bot, audit: al, log: log,
		byID: map[string]*Request{}, byNonce: map[string]*Request{}, grants: map[grantKey]grant{}}
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

// sanitize strips control characters and caps length so untrusted strings
// cannot deface the Telegram message or smuggle extra lines.
func sanitize(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if max > 0 && len(s) > max {
		s = s[:max] + "…"
	}
	if s == "" {
		return "(none)"
	}
	return s
}

// Request reuses an active saved approval or sends a Telegram prompt and
// blocks until a decision, cancellation, or timeout.
func (m *Manager) Request(ctx context.Context, r *Request) (Outcome, error) {
	if err := ctx.Err(); err != nil {
		return Cancelled, err
	}
	m.mu.Lock()
	if m.locked {
		m.mu.Unlock()
		return Cancelled, ErrLocked
	}
	if g, ok := m.matchGrantLocked(r, time.Now()); ok {
		r.ID = randToken(6)
		r.Created = time.Now()
		r.outcome = Approved
		r.decidedBy = g.ByUser
		m.mu.Unlock()
		m.audit.Log(audit.Event{Event: "approval_reused", RequestID: r.ID, Agent: r.Agent,
			Client: r.Client, Remote: r.Remote, Tool: r.Tool, ItemID: r.ItemID,
			ItemName: r.ItemName, Fields: r.Fields, Reason: r.Reason,
			Outcome: string(Approved), TelegramUser: g.ByUser})
		return Approved, nil
	}
	total, perAgent := 0, 0
	for _, x := range m.byID {
		if x.outcome == Pending {
			total++
			if x.Agent == r.Agent {
				perAgent++
			}
		}
	}
	if total >= m.cfg.MaxPendingTotal || perAgent >= m.cfg.MaxPendingPerAgent {
		m.mu.Unlock()
		return Cancelled, ErrTooManyPending
	}
	r.ID = randToken(6)
	r.nonce = randToken(16)
	r.Created = time.Now()
	r.Expires = r.Created.Add(m.cfg.Timeout)
	r.outcome = Pending
	r.done = make(chan struct{})
	m.byID[r.ID] = r
	m.byNonce[r.nonce] = r
	m.mu.Unlock()

	m.audit.Log(audit.Event{Event: "request", RequestID: r.ID, Agent: r.Agent, Client: r.Client,
		Remote: r.Remote, Tool: r.Tool, ItemID: r.ItemID, ItemName: r.ItemName, Fields: r.Fields,
		Reason: r.Reason, Outcome: string(Pending)})

	msgID, err := m.bot.SendMessage(ctx, m.cfg.OwnerChatID, m.renderPrompt(r), []telegram.Button{
		{Text: "✅ Allow once", CallbackData: "a:" + r.nonce},
		{Text: "Approve for 15 min", CallbackData: "a15:" + r.nonce},
		{Text: "Approve for 1h", CallbackData: "a60:" + r.nonce},
		{Text: "Approve forever", CallbackData: "af:" + r.nonce},
		{Text: "⛔ Decline", CallbackData: "d:" + r.nonce},
	})
	if err != nil {
		m.finish(r, Cancelled, "")
		return Cancelled, fmt.Errorf("could not reach the approver: %w", err)
	}
	m.mu.Lock()
	r.messageID = msgID
	var lateEdit string
	if r.outcome == Pending {
		r.timer = time.AfterFunc(time.Until(r.Expires), func() { m.resolve(r.nonce, TimedOut, 0) })
	} else {
		// A press was handled before sendMessage returned here, so resolve()
		// saw no message id; edit the prompt now so it doesn't keep its buttons.
		lateEdit = m.renderResult(r, r.outcome, r.decidedBy)
	}
	m.mu.Unlock()
	if lateEdit != "" {
		ectx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if err := m.bot.EditMessageText(ectx, m.cfg.OwnerChatID, msgID, lateEdit); err != nil {
			m.log.Warn("edit telegram message failed", "err", err)
		}
		cancel()
	}

	select {
	case <-r.done:
	case <-ctx.Done():
		m.resolve(r.nonce, Cancelled, 0)
	}
	m.mu.Lock()
	out := r.outcome
	m.mu.Unlock()
	return out, nil
}

// resolve transitions a pending request to a terminal outcome exactly once.
// byUser is the Telegram user id that pressed the button (0 for system events).
func (m *Manager) resolve(nonce string, out Outcome, byUser int64) {
	_ = m.resolveWithGrant(nonce, out, byUser, 0, false)
}

// resolveWithGrant stores a grant and resolves its request in one critical section.
func (m *Manager) resolveWithGrant(nonce string, out Outcome, byUser int64, duration time.Duration, forever bool) error {
	m.mu.Lock()
	r := m.byNonce[nonce]
	if r == nil || r.outcome != Pending {
		m.mu.Unlock()
		return ErrUnknownRequest
	}
	if out == Approved && (m.locked || !time.Now().Before(r.Expires)) {
		m.mu.Unlock()
		return ErrUnknownRequest
	}
	if out == Approved && (duration > 0 || forever) {
		if err := m.addGrantLocked(r, byUser, duration, forever); err != nil {
			m.mu.Unlock()
			m.audit.Log(audit.Event{Event: "grant_error", RequestID: r.ID, Outcome: "rejected"})
			m.log.Error("save approval grant failed", "err", err)
			return err
		}
	}
	m.finishLocked(r, out, "")
	r.decidedBy = byUser
	chatID, msgID := m.cfg.OwnerChatID, r.messageID
	text := m.renderResult(r, out, byUser)
	m.mu.Unlock()

	m.audit.Log(audit.Event{Event: "decision", RequestID: r.ID, Agent: r.Agent, Tool: r.Tool,
		ItemID: r.ItemID, ItemName: r.ItemName, Fields: r.Fields, Outcome: string(out), TelegramUser: byUser, Detail: grantDetail(r)})
	if msgID != 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := m.bot.EditMessageText(ctx, chatID, msgID, text); err != nil {
			m.log.Warn("edit telegram message failed", "err", err)
		}
	}
	return nil
}

func (m *Manager) finish(r *Request, out Outcome, _ string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.finishLocked(r, out, "")
}

func (m *Manager) finishLocked(r *Request, out Outcome, _ string) {
	if r.outcome != Pending {
		return
	}
	r.outcome = out
	if r.timer != nil {
		r.timer.Stop()
	}
	delete(m.byNonce, r.nonce)
	close(r.done)
}

// Lock declines all pending requests and refuses new ones until Unlock.
func (m *Manager) Lock() {
	m.mu.Lock()
	m.locked = true
	if err := m.saveGrantsLocked(map[grantKey]grant{}); err != nil {
		m.log.Error("clear saved approvals failed; access remains locked", "err", err)
	}
	clear(m.grants)
	var pend []*Request
	for _, r := range m.byID {
		if r.outcome == Pending {
			pend = append(pend, r)
		}
	}
	m.mu.Unlock()
	for _, r := range pend {
		m.resolve(r.nonce, Cancelled, 0)
	}
	m.audit.Log(audit.Event{Event: "lock", Outcome: "locked"})
}

// Status returns counts for observability.
func (m *Manager) Status() (pending int, locked bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.byID {
		if r.outcome == Pending {
			pending++
		}
	}
	return pending, m.locked
}

func (m *Manager) renderPrompt(r *Request) string {
	var b strings.Builder
	b.WriteString("🔐 Credential request\n\n")
	fmt.Fprintf(&b, "Item: %s\n", sanitize(r.ItemName, 120))
	if r.Folder != "" {
		fmt.Fprintf(&b, "Folder: %s\n", sanitize(r.Folder, 80))
	}
	if r.Org != "" {
		fmt.Fprintf(&b, "Org: %s\n", sanitize(r.Org, 80))
	}
	fmt.Fprintf(&b, "Fields: %s\n", sanitize(strings.Join(r.Fields, ", "), 120))
	fmt.Fprintf(&b, "Agent: %s\n", sanitize(r.Agent, 80))
	if r.Client != "" {
		fmt.Fprintf(&b, "Client: %s\n", sanitize(r.Client, 80))
	}
	if r.Remote != "" {
		fmt.Fprintf(&b, "From: %s\n", sanitize(r.Remote, 60))
	}
	fmt.Fprintf(&b, "Reason: %s\n", sanitize(r.Reason, 300))
	if r.Reprompt {
		b.WriteString("⚠️ This item is marked “master-password re-prompt”.\n")
	}
	fmt.Fprintf(&b, "\nRequest %s · %s\n", r.ID, r.Created.In(m.cfg.Location).Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&b, "Expires in %s. No secret values are shown here.\nSaved approvals cover only this agent, item, and these fields.", m.cfg.Timeout.Round(time.Second))
	return b.String()
}

func (m *Manager) renderResult(r *Request, out Outcome, byUser int64) string {
	var head string
	switch out {
	case Approved:
		head = "✅ ALLOWED"
	case Declined:
		head = "⛔ DECLINED"
	case TimedOut:
		head = "⌛ TIMED OUT (auto-declined)"
	default:
		head = "✖️ CANCELLED"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\nItem: %s\nFields: %s\nAgent: %s\nRequest %s\n",
		head, sanitize(r.ItemName, 120), sanitize(strings.Join(r.Fields, ", "), 120), sanitize(r.Agent, 80), r.ID)
	if out == Approved {
		fmt.Fprintln(&b, grantDetail(r))
	}
	if byUser != 0 {
		fmt.Fprintf(&b, "By: Telegram user %d\n", byUser)
	}
	fmt.Fprintf(&b, "At: %s", time.Now().In(m.cfg.Location).Format("2006-01-02 15:04:05 MST"))
	return b.String()
}

// handleCallback processes one inline button press.
func (m *Manager) handleCallback(ctx context.Context, cq *telegram.CallbackQuery) {
	parts := strings.SplitN(cq.Data, ":", 2)
	if len(parts) != 2 {
		return
	}
	action, nonce := parts[0], parts[1]

	// Only the configured owner may decide. Wrong users get a refusal toast and
	// the request is left pending.
	if cq.From.ID != m.cfg.OwnerUserID {
		m.audit.Log(audit.Event{Event: "wrong_user_press", Outcome: "rejected", TelegramUser: cq.From.ID})
		_ = m.bot.AnswerCallbackQuery(ctx, cq.ID, "You are not authorised to approve these requests.")
		return
	}
	var out Outcome
	var toast string
	var duration time.Duration
	var forever bool
	switch action {
	case "a":
		out, toast = Approved, "Allowed once."
	case "a15":
		out, toast, duration = Approved, "Approved for 15 min.", 15*time.Minute
	case "a60":
		out, toast, duration = Approved, "Approved for 1h.", time.Hour
	case "af":
		out, toast, forever = Approved, "Approved forever.", true
	case "d":
		out, toast = Declined, "Declined."
	default:
		return
	}
	if err := m.resolveWithGrant(nonce, out, cq.From.ID, duration, forever); err != nil {
		if errors.Is(err, ErrUnknownRequest) {
			toast = "This request is no longer pending."
		} else {
			toast = "Could not save approval. Try again or choose Allow once."
		}
	}
	_ = m.bot.AnswerCallbackQuery(ctx, cq.ID, toast)
}

// Run consumes Telegram updates until the context is cancelled. It is the only
// consumer of getUpdates and must be run exactly once.
func (m *Manager) Run(ctx context.Context) error {
	m.log.Info("approval update loop started")
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		ups, err := m.bot.GetUpdates(ctx, m.offset, 30)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, telegram.ErrConflict) {
				m.log.Error("telegram conflict; stopping update loop", "err", err)
				return err
			}
			m.log.Warn("getUpdates failed; retrying", "err", err)
			select {
			case <-time.After(3 * time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
			continue
		}
		for _, u := range ups {
			if u.UpdateID >= m.offset {
				m.offset = u.UpdateID + 1
			}
			if u.CallbackQuery != nil {
				m.handleCallback(ctx, u.CallbackQuery)
			}
		}
	}
}
