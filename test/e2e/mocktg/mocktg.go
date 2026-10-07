// Package mocktg is a minimal in-process stand-in for the Telegram Bot API.
// It records sendMessage/editMessageText/answerCallbackQuery calls and lets the
// test deliver callback_query updates (Allow/Decline/wrong-user presses) via
// long-polled getUpdates, exactly like the real API.
package mocktg

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// Sent is a recorded outbound message.
type Sent struct {
	ChatID    int64
	MessageID int
	Text      string
	Buttons   map[string]string // label -> callback_data
}

// Server is the mock.
type Server struct {
	ts   *httptest.Server
	mu   sync.Mutex
	next int
	sent map[int]*Sent
	last int // last message id

	updates []map[string]any
	updID   int64
	toasts  []string
}

// New starts the mock server.
func New() *Server {
	s := &Server{sent: map[int]*Sent{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	s.ts = httptest.NewServer(mux)
	return s
}

// BaseURL returns the base URL to pass to telegram.New.
func (s *Server) BaseURL() string { return s.ts.URL }

// Close stops the server.
func (s *Server) Close() { s.ts.Close() }

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	method := r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	ok := func(result any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
	}
	switch method {
	case "getMe":
		ok(map[string]any{"id": 1, "is_bot": true, "username": "mockbot", "first_name": "mock"})
	case "sendMessage":
		s.mu.Lock()
		s.next++
		id := s.next
		s.last = id
		sent := &Sent{ChatID: toInt64(body["chat_id"]), MessageID: id, Text: str(body["text"]), Buttons: parseButtons(body["reply_markup"])}
		s.sent[id] = sent
		s.mu.Unlock()
		ok(map[string]any{"message_id": id, "chat": map[string]any{"id": sent.ChatID}, "text": sent.Text})
	case "editMessageText":
		s.mu.Lock()
		id := int(toInt64(body["message_id"]))
		if m := s.sent[id]; m != nil {
			m.Text = str(body["text"])
			m.Buttons = nil
		}
		s.mu.Unlock()
		ok(true)
	case "answerCallbackQuery":
		s.mu.Lock()
		s.toasts = append(s.toasts, str(body["text"]))
		s.mu.Unlock()
		ok(true)
	case "getUpdates":
		offset := toInt64(body["offset"])
		deadline := time.Now().Add(1 * time.Second)
		for {
			s.mu.Lock()
			var out []map[string]any
			for _, u := range s.updates {
				if toInt64(u["update_id"]) >= offset {
					out = append(out, u)
				}
			}
			s.mu.Unlock()
			if len(out) > 0 || time.Now().After(deadline) {
				ok(out)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	default:
		ok(true)
	}
}

// Press delivers a callback_query (button press) from the given user to the
// last-sent message, choosing the button whose label contains want.
func (s *Server) Press(user int64, want string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.sent[s.last]
	if m == nil {
		return false
	}
	var data string
	for label, cb := range m.Buttons {
		if strings.Contains(strings.ToLower(label), strings.ToLower(want)) {
			data = cb
		}
	}
	if data == "" {
		return false
	}
	s.updID++
	s.updates = append(s.updates, map[string]any{
		"update_id": s.updID,
		"callback_query": map[string]any{
			"id":   "cb",
			"from": map[string]any{"id": user, "is_bot": false, "first_name": "tester"},
			"data": data,
		},
	})
	return true
}

// LastText returns the text of the last message (after any edits).
func (s *Server) LastText() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m := s.sent[s.last]; m != nil {
		return m.Text
	}
	return ""
}

// WaitButtons blocks until the last message has inline buttons (i.e. a prompt was sent).
func (s *Server) WaitButtons(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		m := s.sent[s.last]
		has := m != nil && len(m.Buttons) > 0
		s.mu.Unlock()
		if has {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// MessageCount returns how many messages have been sent.
func (s *Server) MessageCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
}

func parseButtons(rm any) map[string]string {
	out := map[string]string{}
	m, ok := rm.(map[string]any)
	if !ok {
		return out
	}
	rows, _ := m["inline_keyboard"].([]any)
	for _, row := range rows {
		btns, _ := row.([]any)
		for _, b := range btns {
			bm, _ := b.(map[string]any)
			out[str(bm["text"])] = str(bm["callback_data"])
		}
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	}
	return 0
}
