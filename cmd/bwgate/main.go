// Command bwgate is a lightweight MCP server that gates Bitwarden vault access
// behind per-request Telegram approval. See the repository README for setup.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LionZXY/bitwarden-approval-mcp/internal/approval"
	"github.com/LionZXY/bitwarden-approval-mcp/internal/audit"
	"github.com/LionZXY/bitwarden-approval-mcp/internal/config"
	"github.com/LionZXY/bitwarden-approval-mcp/internal/server"
	"github.com/LionZXY/bitwarden-approval-mcp/internal/telegram"
	"github.com/LionZXY/bitwarden-approval-mcp/internal/vault"
)

// version is overridable at build time with -ldflags "-X main.version=...".
var version = "0.1.0"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bwgate: "+err.Error())
		os.Exit(1)
	}
}

func run() error {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	al, err := audit.Open(cfg.AuditLog)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer al.Close()

	// Telegram: verify token and owner before touching the vault.
	tg := telegram.New(cfg.TGToken, cfg.TGAPIBase, &http.Client{Timeout: 70 * time.Second})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	me, err := tg.GetMe(ctx)
	if err != nil {
		return fmt.Errorf("telegram getMe: %w", err)
	}
	log.Info("telegram bot verified", "username", me.Username)

	// Unlock the vault (master password wiped inside Unlock).
	v, err := vault.New(vault.Config{
		ServerURL: cfg.BWServer, APIURL: cfg.BWAPIURL, IdentityURL: cfg.BWIdentityURL,
		Email: cfg.BWEmail, Password: cfg.BWPassword, ClientID: cfg.BWClientID,
		ClientSecret: cfg.BWClientSecret, DeviceID: cfg.BWDeviceID, DeviceName: "bwgate",
	})
	if err != nil {
		return err
	}
	log.Info("unlocking vault", "server", cfg.BWServer, "email", cfg.BWEmail)
	if err := v.Unlock(ctx); err != nil {
		return err
	}
	defer v.Lock()
	log.Info("vault unlocked", "items", v.Status().ItemCount)

	loc, _ := time.LoadLocation(os.Getenv("TZ"))
	if loc == nil {
		loc = time.UTC
	}
	mgr := approval.NewManager(tg, approval.Config{
		OwnerUserID: cfg.OwnerUserID, OwnerChatID: cfg.OwnerChatID, Timeout: cfg.Timeout,
		MaxPendingPerAgent: cfg.MaxPendingPerAgent, MaxPendingTotal: cfg.MaxPendingTotal, Location: loc,
	}, al, log)

	tokens := map[string]string{}
	for _, a := range cfg.Agents {
		tokens[a.Token] = a.Name
	}
	srv := server.New(server.Options{
		Vault: v, Approver: mgr, Audit: al,
		Allowlist: cfg.Allowlist, Denylist: cfg.Denylist, ListUngated: cfg.ListUngated,
		RateLimit: cfg.RateLimitPerMin, AgentTokens: tokens, Version: version,
	})

	newMCP := func() *mcp.Server {
		m := mcp.NewServer(&mcp.Implementation{Name: "bitwarden-approval-mcp", Version: version}, nil)
		srv.Register(m)
		return m
	}

	// Background: Telegram update loop + periodic vault sync.
	go func() {
		if err := mgr.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("approval loop exited", "err", err)
			stop()
		}
	}()
	if cfg.SyncInterval > 0 {
		go func() {
			t := time.NewTicker(cfg.SyncInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := v.Sync(ctx); err != nil {
						log.Warn("vault sync failed", "err", err)
					} else {
						log.Info("vault synced", "items", v.Status().ItemCount)
					}
				}
			}
		}()
	}

	errCh := make(chan error, 2)

	if cfg.Transport == "stdio" || cfg.Transport == "both" {
		go func() {
			log.Info("serving MCP over stdio")
			errCh <- newMCP().Run(ctx, &mcp.StdioTransport{})
		}()
	}

	var httpSrv *http.Server
	if cfg.Transport == "http" || cfg.Transport == "both" {
		handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return newMCP() }, nil)
		protected := auth.RequireBearerToken(srv.Verifier(), &auth.RequireBearerTokenOptions{Scopes: []string{"bwgate"}})(handler)

		mux := http.NewServeMux()
		mux.Handle("/mcp", protected)
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			pending, locked := mgr.Status()
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"status":"ok","items":%d,"pending":%d,"locked":%t}`, v.Status().ItemCount, pending, locked)
		})
		httpSrv = &http.Server{Addr: cfg.Addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		ln, err := net.Listen("tcp", cfg.Addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", cfg.Addr, err)
		}
		log.Info("serving MCP over streamable HTTP", "addr", cfg.Addr, "path", "/mcp")
		go func() { errCh <- httpSrv.Serve(ln) }()
	}

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, context.Canceled) {
			log.Error("server error", "err", err)
		}
	}
	if httpSrv != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(sctx)
	}
	v.Lock()
	log.Info("vault locked; bye")
	return nil
}
