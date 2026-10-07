// Package audit writes an append-only JSON-lines audit log. Callers must never
// pass secret values; the logger only accepts a fixed Event struct.
package audit

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Event is one audit record. There is deliberately no field for secret values.
type Event struct {
	Time         time.Time `json:"time"`
	Event        string    `json:"event"`
	RequestID    string    `json:"request_id,omitempty"`
	Agent        string    `json:"agent,omitempty"`
	Client       string    `json:"client,omitempty"`
	Remote       string    `json:"remote,omitempty"`
	Tool         string    `json:"tool,omitempty"`
	ItemID       string    `json:"item_id,omitempty"`
	ItemName     string    `json:"item_name,omitempty"`
	Fields       []string  `json:"fields,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	Outcome      string    `json:"outcome,omitempty"`
	Detail       string    `json:"detail,omitempty"`
	TelegramUser int64     `json:"telegram_user,omitempty"`
}

// Logger serialises events.
type Logger struct {
	mu sync.Mutex
	w  io.Writer
	c  io.Closer
}

// Open opens path for appending (0600). Empty path or "-" logs to stderr.
func Open(path string) (*Logger, error) {
	if path == "" || path == "-" {
		return &Logger{w: os.Stderr}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{w: f, c: f}, nil
}

// New wraps an arbitrary writer (tests).
func New(w io.Writer) *Logger { return &Logger{w: w} }

// Log writes one event.
func (l *Logger) Log(e Event) {
	if l == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(b, '\n'))
}

// Close closes the underlying file.
func (l *Logger) Close() error {
	if l == nil || l.c == nil {
		return nil
	}
	return l.c.Close()
}
