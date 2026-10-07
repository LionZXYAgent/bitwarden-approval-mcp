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
	queued []map[string]any
	updID  int64
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
				m.queued = append(m.queued, map[string]any{
					"update_id": m.updID,
					"callback_query": map[string]any{"id": "cb",
						"from": map[string]any{"id": ownerID, "is_bot": false, "first_name": "owner"},
						"data": data},
				})
			}
		}
		m.mu.Unlock()
		ok(map[string]any{"message_id": id, "text": body["text"]})
	case "getUpdates":
		deadline := time.Now().Add(1 * time.Second)
		offset := toI64(body["offset"])
		for {
			m.mu.Lock()
			var out []map[string]any
			for _, u := range m.queued {
				if toI64(u["update_id"]) >= offset {
					out = append(out, u)
				}
			}
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
