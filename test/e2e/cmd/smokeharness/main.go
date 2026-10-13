//go:build smoke

// Command smokeharness seeds a Vaultwarden account with test items and runs a
// mock Telegram Bot API that auto-presses "Allow" for the configured owner.
// Used by the container-level smoke test; not part of the shipped server.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/LionZXY/bitwarden-approval-mcp/test/e2e/seed"
)

const ownerID = int64(555)

func main() {
	base := envOr("VW_BASE", "http://127.0.0.1:8111")
	email := envOr("SEED_EMAIL", fmt.Sprintf("smoke-%d@example.com", time.Now().Unix()))
	pw := envOr("SEED_PW", "smoke-master-pw-123")
	addr := envOr("MOCK_TG_ADDR", "127.0.0.1:8112")
	hc := &http.Client{Timeout: 30 * time.Second}
	ctx := context.Background()

	if err := seed.WaitReady(ctx, base, hc, 60*time.Second); err != nil {
		log.Fatalf("vaultwarden not ready: %v", err)
	}
	if err := seed.Account(ctx, base, email, pw, hc); err != nil {
		log.Printf("account note: %v", err)
	}
	items := []seed.Item{
		{Name: "GitHub", Username: "octocat", Password: "ghp_smoke_secret", URI: "https://github.com",
			TOTP: "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP"},
		{Name: "Prod DB", Username: "root", Password: "prod-db-pw"},
	}
	if err := seed.Items(ctx, base, email, pw, items, hc); err != nil {
		log.Fatalf("seed items: %v", err)
	}
	fmt.Printf("SEEDED email=%s pw=%s\n", email, pw)

	mux := http.NewServeMux()
	m := &mockTG{sent: map[int]map[string]string{}}
	mux.HandleFunc("/", m.handle)
	log.Printf("mock telegram (auto-allow owner=%d) on %s", ownerID, addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

type mockTG struct {
	mu     sync.Mutex
	next   int
	sent   map[int]map[string]string // id -> label:callbackdata
	queued []update
	updID  int64
	cbID   int64
}

// update is a queued Telegram update. update_id is kept as a typed int64 so the
// getUpdates offset filter compares real values (a map[string]any round-trip
// previously turned it into 0, so only the first callback was ever delivered).
type update struct {
	UpdateID      int64          `json:"update_id"`
	CallbackQuery map[string]any `json:"callback_query"`
}

func (m *mockTG) handle(w http.ResponseWriter, r *http.Request) {
	method := r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	ok := func(res any) { _ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": res}) }
	switch method {
	case "getMe":
		ok(map[string]any{"id": 1, "is_bot": true, "username": "smokebot"})
	case "sendMessage":
		m.mu.Lock()
		m.next++
		id := m.next
		btns := parseButtons(body["reply_markup"])
		m.sent[id] = btns
		// Auto-allow: queue a callback_query pressing the Allow button.
		for label, data := range btns {
			if strings.Contains(strings.ToLower(label), "allow") {
				m.updID++
				m.cbID++
				m.queued = append(m.queued, update{UpdateID: m.updID, CallbackQuery: map[string]any{
					"id":      fmt.Sprintf("cb-%d", m.cbID),
					"from":    map[string]any{"id": ownerID, "is_bot": false, "first_name": "owner"},
					"message": map[string]any{"message_id": id, "chat": map[string]any{"id": ownerID}},
					"data":    data}})
				break // press exactly one Allow button per prompt
			}
		}
		m.mu.Unlock()
		ok(map[string]any{"message_id": id, "text": body["text"]})
	case "getUpdates":
		deadline := time.Now().Add(1 * time.Second)
		offset := toI64(body["offset"])
		for {
			m.mu.Lock()
			// Like Telegram: an offset confirms (drops) all earlier updates.
			kept := m.queued[:0]
			for _, u := range m.queued {
				if u.UpdateID >= offset {
					kept = append(kept, u)
				}
			}
			m.queued = kept
			out := append([]update{}, kept...)
			m.mu.Unlock()
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

func parseButtons(rm any) map[string]string {
	out := map[string]string{}
	mm, _ := rm.(map[string]any)
	rows, _ := mm["inline_keyboard"].([]any)
	for _, row := range rows {
		for _, b := range row.([]any) {
			bm := b.(map[string]any)
			out[str(bm["text"])] = str(bm["callback_data"])
		}
	}
	return out
}
func str(v any) string { s, _ := v.(string); return s }
func toI64(v any) int64 {
	if f, ok := v.(float64); ok {
		return int64(f)
	}
	return 0
}
func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
