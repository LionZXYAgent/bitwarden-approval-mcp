//go:build e2e

// Package e2e drives the whole server against a real Vaultwarden instance and a
// mock Telegram Bot API, through a real MCP client over streamable HTTP.
//
// Run with:  VW_BASE=http://127.0.0.1:8111 go test -tags e2e ./test/e2e/ -v
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LionZXY/bitwarden-approval-mcp/internal/approval"
	"github.com/LionZXY/bitwarden-approval-mcp/internal/audit"
	"github.com/LionZXY/bitwarden-approval-mcp/internal/server"
	"github.com/LionZXY/bitwarden-approval-mcp/internal/telegram"
	"github.com/LionZXY/bitwarden-approval-mcp/internal/vault"
	"github.com/LionZXY/bitwarden-approval-mcp/test/e2e/mocktg"
	"github.com/LionZXY/bitwarden-approval-mcp/test/e2e/seed"
)

const (
	owner      = int64(777)
	attacker   = int64(666)
	agentToken = "e2e-agent-token-0123456789abcdef"
	masterPw   = "correct-horse-battery-staple"
)

// email is unique per test-binary run so repeated runs against the same
// persistent Vaultwarden container never collide or create duplicate items.
var email = fmt.Sprintf("e2e-%d@example.com", time.Now().UnixNano())

var seedOnce sync.Once
var seedErr error

// bearerRT adds the Authorization header to every request.
type bearerRT struct {
	tok  string
	base http.RoundTripper
}

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return b.base.RoundTrip(r)
}

type harness struct {
	tg       *mocktg.Server
	audit    *strings.Builder
	httpAddr string
	vault    *vault.Vault
	mgr      *approval.Manager
	cancel   context.CancelFunc
}

func setup(t *testing.T) *harness {
	t.Helper()
	base := os.Getenv("VW_BASE")
	if base == "" {
		t.Skip("VW_BASE not set; skipping e2e (needs a running Vaultwarden)")
	}
	hc := &http.Client{Timeout: 30 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())

	if err := seed.WaitReady(ctx, base, hc, 60*time.Second); err != nil {
		cancel()
		t.Fatalf("vaultwarden not ready: %v", err)
	}
	// Register and seed items exactly once per test binary, so repeated setup()
	// calls don't create duplicate items (which would make Resolve ambiguous).
	seedOnce.Do(func() {
		// Registration may fail if the account already exists; that's fine.
		if err := seed.Account(ctx, base, email, masterPw, hc); err != nil {
			t.Logf("account registration note: %v", err)
		}
		items := []seed.Item{
			{Name: "GitHub", Username: "octocat", Password: "ghp_secretvalue123", URI: "https://github.com",
				TOTP: "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub", Notes: "deploy key notes",
				Fields: map[string]string{"API Key": "sk-customfield-xyz"}},
			{Name: "AWS prod", Username: "admin", Password: "prod-aws-password", URI: "https://console.aws.amazon.com"},
			{Name: "Dev DB", Username: "dev", Password: "devdbpass", URI: "postgres://localhost"},
		}
		seedErr = seed.Items(ctx, base, email, masterPw, items, hc)
	})
	if seedErr != nil {
		cancel()
		t.Fatalf("seed items: %v", seedErr)
	}

	// Unlock the vault with the project's client.
	v, err := vault.New(vault.Config{ServerURL: base, Email: email, Password: []byte(masterPw), HTTPClient: hc})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := v.Unlock(ctx); err != nil {
		cancel()
		t.Fatalf("unlock: %v", err)
	}
	if v.Status().ItemCount < 3 {
		t.Logf("warning: vault has %d items", v.Status().ItemCount)
	}

	tg := mocktg.New()
	tgClient := telegram.New("mock-token", tg.BaseURL(), &http.Client{Timeout: 5 * time.Second})
	var auditBuf strings.Builder
	al := audit.New(&auditBuf)
	mgr := approval.NewManager(tgClient, approval.Config{OwnerUserID: owner, OwnerChatID: owner,
		Timeout: 2 * time.Second, MaxPendingPerAgent: 5, MaxPendingTotal: 10}, al, nil)
	go mgr.Run(ctx)

	srv := server.New(server.Options{Vault: v, Approver: mgr, Audit: al,
		Denylist: []string{"AWS prod"}, ListUngated: true, RateLimit: 100,
		AgentTokens: map[string]string{agentToken: "e2e-agent"}})

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		m := mcp.NewServer(&mcp.Implementation{Name: "bitwarden-approval-mcp", Version: "test"}, nil)
		srv.Register(m)
		return m
	}, nil)
	protected := auth.RequireBearerToken(srv.Verifier(), &auth.RequireBearerTokenOptions{Scopes: []string{"bwgate"}})(handler)
	mux := http.NewServeMux()
	mux.Handle("/mcp", protected)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	hsrv := &http.Server{Handler: mux}
	go hsrv.Serve(ln)

	h := &harness{tg: tg, audit: &auditBuf, httpAddr: ln.Addr().String(), vault: v, mgr: mgr, cancel: cancel}
	t.Cleanup(func() {
		cancel()
		hsrv.Close()
		tg.Close()
		v.Lock()
	})
	return h
}

func (h *harness) connect(t *testing.T, token string) *mcp.ClientSession {
	t.Helper()
	hc := &http.Client{Timeout: 15 * time.Second, Transport: bearerRT{tok: token, base: http.DefaultTransport}}
	tr := &mcp.StreamableClientTransport{Endpoint: "http://" + h.httpAddr + "/mcp", HTTPClient: hc}
	c := mcp.NewClient(&mcp.Implementation{Name: "e2e-client", Version: "1.0"}, nil)
	cs, err := c.Connect(context.Background(), tr, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func decode[T any](t *testing.T, res *mcp.CallToolResult) T {
	t.Helper()
	var out T
	if res.StructuredContent != nil {
		b, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("decode structured: %v", err)
		}
		return out
	}
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			_ = json.Unmarshal([]byte(tc.Text), &out)
		}
	}
	return out
}

func resultText(res *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func TestAuthRequired(t *testing.T) {
	h := setup(t)
	hc := &http.Client{Timeout: 5 * time.Second} // no bearer
	tr := &mcp.StreamableClientTransport{Endpoint: "http://" + h.httpAddr + "/mcp", HTTPClient: hc}
	c := mcp.NewClient(&mcp.Implementation{Name: "noauth", Version: "1"}, nil)
	if _, err := c.Connect(context.Background(), tr, nil); err == nil {
		t.Fatal("expected unauthenticated connection to fail")
	}
}

func TestSearchUngated(t *testing.T) {
	h := setup(t)
	cs := h.connect(t, agentToken)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "search_items", Arguments: map[string]any{"query": "git"}})
	if err != nil {
		t.Fatal(err)
	}
	out := decode[struct {
		Items []struct {
			Name            string   `json:"name"`
			AvailableFields []string `json:"available_fields"`
		} `json:"items"`
		Count int `json:"count"`
	}](t, res)
	if out.Count < 1 {
		t.Fatalf("expected at least one github item, got %d (%s)", out.Count, resultText(res))
	}
	// No secrets, and no telegram message sent for a search.
	if h.tg.MessageCount() != 0 {
		t.Fatal("search must not trigger a telegram message")
	}
	if strings.Contains(resultText(res), "ghp_secretvalue") {
		t.Fatal("search leaked a password")
	}
}

func TestGetCredentialApprove(t *testing.T) {
	h := setup(t)
	cs := h.connect(t, agentToken)
	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_credential",
			Arguments: map[string]any{"item": "GitHub", "fields": []string{"username", "password"}, "reason": "deploy to prod"}})
		if err != nil {
			t.Errorf("call: %v", err)
		}
		done <- res
	}()
	if !h.tg.WaitButtons(3 * time.Second) {
		t.Fatal("no approval prompt appeared")
	}
	// Prompt must not contain the secret value.
	if strings.Contains(h.tg.LastText(), "ghp_secretvalue") {
		t.Fatal("telegram prompt leaked password")
	}
	if !strings.Contains(h.tg.LastText(), "deploy to prod") {
		t.Fatal("prompt missing reason")
	}
	h.tg.Press(owner, "allow")
	res := <-done
	out := decode[struct {
		Fields map[string]string `json:"fields"`
	}](t, res)
	if out.Fields["password"] != "ghp_secretvalue123" || out.Fields["username"] != "octocat" {
		t.Fatalf("wrong credential returned: %+v (%s)", out.Fields, resultText(res))
	}
	if !strings.Contains(h.tg.LastText(), "ALLOWED") {
		t.Fatalf("message not updated to ALLOWED: %q", h.tg.LastText())
	}
	if strings.Contains(h.audit.String(), "ghp_secretvalue") {
		t.Fatal("audit log leaked secret")
	}
}

func TestGetCredentialDecline(t *testing.T) {
	h := setup(t)
	cs := h.connect(t, agentToken)
	type callRes struct {
		res *mcp.CallToolResult
		err error
	}
	done := make(chan callRes, 1)
	go func() {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_credential",
			Arguments: map[string]any{"item": "GitHub", "fields": []string{"password"}, "reason": "sketchy"}})
		done <- callRes{res, err}
	}()
	if !h.tg.WaitButtons(3 * time.Second) {
		t.Fatal("no prompt")
	}
	h.tg.Press(owner, "decline")
	r := <-done
	if r.err != nil {
		t.Fatalf("call error: %v", r.err)
	}
	if !r.res.IsError || !strings.Contains(resultText(r.res), "declined") {
		t.Fatalf("expected declined error, got %q", resultText(r.res))
	}
}

func TestWrongUserThenTimeout(t *testing.T) {
	h := setup(t)
	cs := h.connect(t, agentToken)
	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		res, _ := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_credential",
			Arguments: map[string]any{"item": "GitHub", "fields": []string{"password"}, "reason": "attack"}})
		done <- res
	}()
	if !h.tg.WaitButtons(3 * time.Second) {
		t.Fatal("no prompt")
	}
	h.tg.Press(attacker, "allow") // must be ignored
	res := <-done                 // should resolve by timeout (2s)
	if !res.IsError || !strings.Contains(resultText(res), "timed_out") {
		t.Fatalf("expected timeout after wrong-user press, got %q", resultText(res))
	}
	if !strings.Contains(h.audit.String(), "wrong_user_press") {
		t.Fatal("wrong user press not audited")
	}
}

func TestPolicyDeny(t *testing.T) {
	h := setup(t)
	cs := h.connect(t, agentToken)
	res, _ := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_credential",
		Arguments: map[string]any{"item": "AWS prod", "fields": []string{"password"}, "reason": "x"}})
	if !res.IsError || !strings.Contains(resultText(res), "policy") {
		t.Fatalf("expected policy denial, got %q", resultText(res))
	}
	if h.tg.MessageCount() != 0 {
		t.Fatal("denied item must not reach telegram")
	}
}

func TestGetTOTP(t *testing.T) {
	h := setup(t)
	cs := h.connect(t, agentToken)
	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		res, _ := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_totp",
			Arguments: map[string]any{"item": "GitHub", "reason": "login"}})
		done <- res
	}()
	if !h.tg.WaitButtons(3 * time.Second) {
		t.Fatal("no prompt")
	}
	h.tg.Press(owner, "allow")
	res := <-done
	out := decode[struct {
		Code string `json:"code"`
	}](t, res)
	if len(out.Code) != 6 {
		t.Fatalf("expected 6-digit code, got %q (%s)", out.Code, resultText(res))
	}
	// The seed is JBSWY3DPEHPK3PXP; the returned value must not be the seed.
	if strings.Contains(resultText(res), "JBSWY3DPEHPK3PXP") {
		t.Fatal("totp seed leaked")
	}
}
