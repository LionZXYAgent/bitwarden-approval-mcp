// Package seed registers a test account and test items against a running
// Bitwarden-compatible server (Vaultwarden). It performs the same client-side
// encryption a real client would, using the project's own crypto package, so
// the server only ever stores ciphertext.
package seed

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LionZXY/bitwarden-approval-mcp/internal/vault"
)

// Item is a login to seed.
type Item struct {
	Name     string
	Username string
	Password string
	TOTP     string
	URI      string
	Notes    string
	Fields   map[string]string
}

const iterations = 600000

// Account registers a user and returns nothing on success.
func Account(ctx context.Context, base, email, password string, hc *http.Client) error {
	mk, err := vault.DeriveMasterKey([]byte(password), email, vault.KDFParams{Type: vault.KDFPBKDF2, Iterations: iterations})
	if err != nil {
		return err
	}
	stretched, err := vault.StretchMasterKey(mk)
	if err != nil {
		return err
	}
	// Random 64-byte user key.
	ukRaw := make([]byte, 64)
	if _, err := rand.Read(ukRaw); err != nil {
		return err
	}
	userKey, err := vault.SymKeyFromBytes(ukRaw)
	if err != nil {
		return err
	}
	protectedKey, err := vault.EncryptSym(ukRaw, stretched)
	if err != nil {
		return err
	}
	// RSA keypair; private key encrypted with the user key.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	encPriv, err := vault.EncryptSym(pkcs8, userKey)
	if err != nil {
		return err
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return err
	}
	body := map[string]any{
		"email":              email,
		"name":               "e2e",
		"masterPasswordHash": vault.MasterPasswordHash(mk, []byte(password)),
		"key":                protectedKey,
		"kdf":                vault.KDFPBKDF2,
		"kdfIterations":      iterations,
		"keys": map[string]string{
			"publicKey":           base64.StdEncoding.EncodeToString(spki),
			"encryptedPrivateKey": encPriv,
		},
	}
	body["masterPasswordHint"] = nil

	// Modern Vaultwarden flow: ask for a verification token first. With SMTP
	// disabled (the e2e default) the server returns the JWT directly, which the
	// register/finish call then echoes back.
	if tok, err := verificationToken(ctx, hc, base, email); err == nil && tok != "" {
		body["emailVerificationToken"] = tok
		code, resp, err := postJSON(ctx, hc, base+"/identity/accounts/register/finish", "", body)
		if err == nil && (code == http.StatusOK || code == http.StatusCreated || code == http.StatusNoContent) {
			return nil
		}
		if err == nil {
			return fmt.Errorf("register/finish: HTTP %d: %s", code, truncate(resp))
		}
		return err
	}

	// Fallback: older Vaultwarden/Bitwarden register endpoints.
	body["token"] = nil
	var lastErr error
	for _, ep := range []string{"/identity/accounts/register", "/api/accounts/register"} {
		code, resp, err := postJSON(ctx, hc, base+ep, "", body)
		if err != nil {
			lastErr = err
			continue
		}
		if code == http.StatusOK || code == http.StatusCreated || code == http.StatusNoContent {
			return nil
		}
		lastErr = fmt.Errorf("register %s: HTTP %d: %s", ep, code, truncate(resp))
	}
	return lastErr
}

// verificationToken requests a registration verification token. When SMTP is
// disabled the server returns the JWT in the response body (a JSON string).
func verificationToken(ctx context.Context, hc *http.Client, base, email string) (string, error) {
	b, _ := json.Marshal(map[string]any{"email": email, "name": "e2e"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/identity/accounts/register/send-verification-email", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNoContent || len(data) == 0 {
		return "", nil // mail was actually sent; no inline token
	}
	var tok string
	if err := json.Unmarshal(data, &tok); err != nil {
		return "", nil // not a bare token; fall back to legacy endpoints
	}
	return tok, nil
}

type tokenResp struct {
	AccessToken string `json:"access_token"`
}

// login returns an access token, the decrypted user key and the user id.
func login(ctx context.Context, base, email, password string, hc *http.Client) (string, *vault.SymKey, string, error) {
	mk, err := vault.DeriveMasterKey([]byte(password), email, vault.KDFParams{Type: vault.KDFPBKDF2, Iterations: iterations})
	if err != nil {
		return "", nil, "", err
	}
	stretched, err := vault.StretchMasterKey(mk)
	if err != nil {
		return "", nil, "", err
	}
	form := url.Values{
		"grant_type":       {"password"},
		"username":         {email},
		"password":         {vault.MasterPasswordHash(mk, []byte(password))},
		"scope":            {"api offline_access"},
		"client_id":        {"cli"},
		"deviceType":       {"25"},
		"deviceIdentifier": {vault.RandomUUID()},
		"deviceName":       {"seed"},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/identity/connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return "", nil, "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", nil, "", fmt.Errorf("token: HTTP %d: %s", resp.StatusCode, truncate(data))
	}
	var tr tokenResp
	if err := json.Unmarshal(data, &tr); err != nil {
		return "", nil, "", err
	}
	// Fetch sync to get the protected user key.
	req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/sync?excludeDomains=true", nil)
	req2.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	resp2, err := hc.Do(req2)
	if err != nil {
		return "", nil, "", err
	}
	defer resp2.Body.Close()
	var sr struct {
		Profile struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		} `json:"profile"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&sr); err != nil {
		return "", nil, "", err
	}
	ukBytes, err := vault.DecryptSym(sr.Profile.Key, stretched)
	if err != nil {
		return "", nil, "", fmt.Errorf("decrypt user key: %w", err)
	}
	uk, err := vault.SymKeyFromBytes(ukBytes)
	return tr.AccessToken, uk, sr.Profile.ID, err
}

// Items logs in and creates the given login items.
func Items(ctx context.Context, base, email, password string, items []Item, hc *http.Client) error {
	token, uk, userID, err := login(ctx, base, email, password, hc)
	if err != nil {
		return err
	}
	enc := func(s string) string {
		if s == "" {
			return ""
		}
		out, _ := vault.EncryptSym([]byte(s), uk)
		return out
	}
	for _, it := range items {
		login := map[string]any{
			"username": enc(it.Username),
			"password": enc(it.Password),
		}
		if it.TOTP != "" {
			login["totp"] = enc(it.TOTP)
		}
		if it.URI != "" {
			login["uris"] = []map[string]any{{"uri": enc(it.URI), "match": nil}}
		}
		cipher := map[string]any{
			"type":         1,
			"name":         enc(it.Name),
			"notes":        enc(it.Notes),
			"login":        login,
			"encryptedFor": userID,
		}
		if len(it.Fields) > 0 {
			var fields []map[string]any
			for k, v := range it.Fields {
				fields = append(fields, map[string]any{"type": 1, "name": enc(k), "value": enc(v)})
			}
			cipher["fields"] = fields
		}
		code, resp, err := postJSON(ctx, hc, base+"/api/ciphers", token, cipher)
		if err != nil {
			return err
		}
		if code != http.StatusOK && code != http.StatusCreated {
			return fmt.Errorf("create cipher %q: HTTP %d: %s", it.Name, code, truncate(resp))
		}
	}
	return nil
}

func postJSON(ctx context.Context, hc *http.Client, url, token string, body any) (int, []byte, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, data, nil
}

func truncate(b []byte) string {
	s := string(b)
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// WaitReady polls the server /alive endpoint until it responds or timeout.
func WaitReady(ctx context.Context, base string, hc *http.Client, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/alive", nil)
		resp, err := hc.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		} else {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("server not ready after %s", timeout)
}
