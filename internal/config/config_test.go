package config

import (
	"os"
	"path/filepath"
	"testing"
)

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"BW_SERVER", "BW_API_URL", "BW_IDENTITY_URL", "BW_EMAIL", "BW_PASSWORD",
		"BW_PASSWORD_FILE", "BW_CLIENTID", "BW_CLIENTSECRET", "BWGATE_AGENT_TOKENS", "BWGATE_AGENTS_FILE",
		"TELEGRAM_BOT_TOKEN", "TELEGRAM_BOT_TOKEN_FILE", "TELEGRAM_OWNER_USER_ID", "TELEGRAM_OWNER_CHAT_ID",
		"BWGATE_TRANSPORT", "BWGATE_ALLOWLIST", "BWGATE_DENYLIST", "BWGATE_APPROVALS_FILE"} {
		os.Unsetenv(k)
	}
}

func TestLoadMinimal(t *testing.T) {
	clearEnv(t)
	os.Setenv("BW_EMAIL", "me@example.com")
	os.Setenv("BW_PASSWORD", "masterpw")
	os.Setenv("TELEGRAM_BOT_TOKEN", "123:abc")
	os.Setenv("TELEGRAM_OWNER_USER_ID", "42")
	os.Setenv("BWGATE_AGENT_TOKENS", "deployer:0123456789abcdef0123,ci:fedcba9876543210aaaa")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Agents) != 2 || c.Agents[0].Name != "deployer" {
		t.Fatalf("agents parsed wrong: %+v", c.Agents)
	}
	if c.GrantsFile != "approvals.json" {
		t.Fatalf("unexpected approvals file: %q", c.GrantsFile)
	}
	if c.OwnerChatID != 42 {
		t.Fatalf("chat id should default to user id, got %d", c.OwnerChatID)
	}
}

func TestFileIndirection(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw")
	os.WriteFile(pwFile, []byte("filesecret\n"), 0o600)
	os.Setenv("BW_EMAIL", "me@example.com")
	os.Setenv("BW_PASSWORD_FILE", pwFile)
	os.Setenv("BWGATE_APPROVALS_FILE", filepath.Join(dir, "approvals.json"))
	os.Setenv("TELEGRAM_BOT_TOKEN", "123:abc")
	os.Setenv("TELEGRAM_OWNER_USER_ID", "42")
	os.Setenv("BWGATE_AGENT_TOKENS", "a:0123456789abcdef0123")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.GrantsFile != filepath.Join(dir, "approvals.json") {
		t.Fatalf("approvals file override ignored: %q", c.GrantsFile)
	}
	if string(c.BWPassword) != "filesecret" {
		t.Fatalf("password from file wrong: %q", c.BWPassword)
	}
}

func TestMissingRequired(t *testing.T) {
	clearEnv(t)
	if _, err := Load(); err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestShortTokenRejected(t *testing.T) {
	clearEnv(t)
	os.Setenv("BW_EMAIL", "me@example.com")
	os.Setenv("BW_PASSWORD", "x")
	os.Setenv("TELEGRAM_BOT_TOKEN", "123:abc")
	os.Setenv("TELEGRAM_OWNER_USER_ID", "42")
	os.Setenv("BWGATE_AGENT_TOKENS", "a:short")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for short token")
	}
}
