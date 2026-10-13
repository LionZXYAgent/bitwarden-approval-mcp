//go:build smoke

// Command smokeclient drives a running bwgate (backed by smokeharness, which
// auto-allows every prompt) with sequential and concurrent get_credential calls
// and exits non-zero unless every one is approved.
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

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type bearerRT struct{ tok string }

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

func main() {
	url := envOr("BWGATE_URL", "http://127.0.0.1:8099/mcp")
	hc := &http.Client{Timeout: 60 * time.Second, Transport: bearerRT{os.Getenv("SMOKE_TOKEN")}}
	c := mcp.NewClient(&mcp.Implementation{Name: "smokeclient", Version: "1"}, nil)
	cs, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: url, HTTPClient: hc}, nil)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer cs.Close()
	get := func(item, want string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_credential",
			Arguments: map[string]any{"item": item, "fields": []string{"password"}, "reason": "smoke"}})
		if err != nil {
			return err
		}
		b, _ := json.Marshal(res.StructuredContent)
		if !strings.Contains(string(b), want) {
			return fmt.Errorf("%s not approved: %s", item, b)
		}
		return nil
	}
	fail := false
	for i := 0; i < 3; i++ {
		if err := get("GitHub", "ghp_smoke_secret"); err != nil {
			log.Printf("sequential %d: %v", i, err)
			fail = true
		}
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := get("Prod DB", "prod-db-pw"); err != nil {
				mu.Lock()
				log.Printf("concurrent %d: %v", i, err)
				fail = true
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if fail {
		os.Exit(1)
	}
	fmt.Println("SMOKE OK: 3 sequential + 3 concurrent approvals")
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
