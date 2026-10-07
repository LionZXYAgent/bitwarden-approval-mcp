// Package config loads server configuration from environment variables, with
// *_FILE indirection for every secret (Docker/Podman secrets style).
package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// AgentToken maps a bearer token to an agent identity.
type AgentToken struct {
	Name  string
	Token string
}

// Config is the fully-resolved runtime configuration. Secret byte slices are
// owned by the caller and should be wiped after use where practical.
type Config struct {
	// Server
	Addr          string
	Transport     string // "http", "stdio", or "both"
	PublicBaseURL string

	// Bitwarden
	BWServer       string
	BWAPIURL       string
	BWIdentityURL  string
	BWEmail        string
	BWPassword     []byte
	BWClientID     string
	BWClientSecret []byte
	BWDeviceID     string

	// Telegram
	TGToken     string
	TGAPIBase   string
	OwnerUserID int64
	OwnerChatID int64

	// Approval / policy
	Timeout            time.Duration
	MaxPendingPerAgent int
	MaxPendingTotal    int
	ListUngated        bool
	Allowlist          []string
	Denylist           []string
	RateLimitPerMin    int
	SyncInterval       time.Duration

	// Agents & audit
	Agents   []AgentToken
	AuditLog string
}

func getFileOrEnv(name string) (string, error) {
	if p := os.Getenv(name + "_FILE"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("%s_FILE: %w", name, err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return os.Getenv(name), nil
}

func getBytes(name string) ([]byte, error) {
	s, err := getFileOrEnv(name)
	if err != nil {
		return nil, err
	}
	if s == "" {
		return nil, nil
	}
	return []byte(s), nil
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseAgents parses "name1:token1,name2:token2". Tokens may also come from
// BWGATE_AGENT_TOKENS_FILE with one "name:token" per line.
func parseAgents(raw string) ([]AgentToken, error) {
	var out []AgentToken
	seenTok := map[string]bool{}
	add := func(entry string) error {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "#") {
			return nil
		}
		i := strings.IndexByte(entry, ':')
		if i < 1 {
			return fmt.Errorf("agent entry %q must be name:token", entry)
		}
		name, tok := strings.TrimSpace(entry[:i]), strings.TrimSpace(entry[i+1:])
		if name == "" || len(tok) < 16 {
			return fmt.Errorf("agent %q: token must be at least 16 chars", name)
		}
		if seenTok[tok] {
			return fmt.Errorf("duplicate agent token")
		}
		seenTok[tok] = true
		out = append(out, AgentToken{Name: name, Token: tok})
		return nil
	}
	for _, e := range strings.Split(raw, ",") {
		if err := add(e); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Load reads configuration from the environment.
func Load() (*Config, error) {
	c := &Config{}
	var err error

	c.Addr = envDefault("BWGATE_ADDR", "127.0.0.1:8099")
	c.Transport = strings.ToLower(envDefault("BWGATE_TRANSPORT", "http"))
	c.PublicBaseURL = os.Getenv("BWGATE_PUBLIC_BASE_URL")

	c.BWServer = envDefault("BW_SERVER", "https://vault.bitwarden.com")
	c.BWAPIURL = os.Getenv("BW_API_URL")
	c.BWIdentityURL = os.Getenv("BW_IDENTITY_URL")
	c.BWEmail = os.Getenv("BW_EMAIL")
	if c.BWPassword, err = getBytes("BW_PASSWORD"); err != nil {
		return nil, err
	}
	c.BWClientID = os.Getenv("BW_CLIENTID")
	if c.BWClientSecret, err = getBytes("BW_CLIENTSECRET"); err != nil {
		return nil, err
	}
	c.BWDeviceID = os.Getenv("BW_DEVICE_ID")

	if c.TGToken, err = getFileOrEnv("TELEGRAM_BOT_TOKEN"); err != nil {
		return nil, err
	}
	c.TGAPIBase = os.Getenv("TELEGRAM_API_BASE")
	c.OwnerUserID = int64(atoiDefault(os.Getenv("TELEGRAM_OWNER_USER_ID"), 0))
	c.OwnerChatID = int64(atoiDefault(os.Getenv("TELEGRAM_OWNER_CHAT_ID"), 0))
	if c.OwnerChatID == 0 {
		c.OwnerChatID = c.OwnerUserID
	}

	c.Timeout = time.Duration(atoiDefault(os.Getenv("BWGATE_APPROVAL_TIMEOUT_SEC"), 120)) * time.Second
	c.MaxPendingPerAgent = atoiDefault(os.Getenv("BWGATE_MAX_PENDING_PER_AGENT"), 3)
	c.MaxPendingTotal = atoiDefault(os.Getenv("BWGATE_MAX_PENDING_TOTAL"), 20)
	c.ListUngated = strings.EqualFold(envDefault("BWGATE_LIST_UNGATED", "true"), "true")
	c.Allowlist = splitList(os.Getenv("BWGATE_ALLOWLIST"))
	c.Denylist = splitList(os.Getenv("BWGATE_DENYLIST"))
	c.RateLimitPerMin = atoiDefault(os.Getenv("BWGATE_RATE_LIMIT_PER_MIN"), 30)
	c.SyncInterval = time.Duration(atoiDefault(os.Getenv("BWGATE_SYNC_INTERVAL_SEC"), 900)) * time.Second
	c.AuditLog = envDefault("BWGATE_AUDIT_LOG", "-")

	agentsRaw, err := getFileOrEnv("BWGATE_AGENT_TOKENS")
	if err != nil {
		return nil, err
	}
	if agentsRaw == "" {
		// Allow a file with newline-separated entries via BWGATE_AGENT_TOKENS_FILE handled above,
		// but also support a dedicated multi-line file.
		if p := os.Getenv("BWGATE_AGENTS_FILE"); p != "" {
			f, ferr := os.Open(p)
			if ferr != nil {
				return nil, fmt.Errorf("BWGATE_AGENTS_FILE: %w", ferr)
			}
			defer f.Close()
			var sb strings.Builder
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				sb.WriteString(sc.Text())
				sb.WriteByte(',')
			}
			agentsRaw = sb.String()
		}
	}
	if c.Agents, err = parseAgents(agentsRaw); err != nil {
		return nil, err
	}

	return c, c.Validate()
}

func envDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Validate checks required fields.
func (c *Config) Validate() error {
	var missing []string
	if c.BWEmail == "" {
		missing = append(missing, "BW_EMAIL")
	}
	if len(c.BWPassword) == 0 {
		missing = append(missing, "BW_PASSWORD")
	}
	if c.TGToken == "" {
		missing = append(missing, "TELEGRAM_BOT_TOKEN")
	}
	if c.OwnerUserID == 0 {
		missing = append(missing, "TELEGRAM_OWNER_USER_ID")
	}
	if len(c.Agents) == 0 {
		missing = append(missing, "BWGATE_AGENT_TOKENS")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
	}
	switch c.Transport {
	case "http", "stdio", "both":
	default:
		return fmt.Errorf("BWGATE_TRANSPORT must be http, stdio or both")
	}
	if c.Timeout < 5*time.Second {
		return errors.New("BWGATE_APPROVAL_TIMEOUT_SEC must be at least 5")
	}
	return nil
}
