// Package server wires the vault, approval gate and policy into MCP tools and
// serves them over streamable HTTP (and/or stdio). Secret values only ever
// appear in the tool result returned to an authenticated, approved agent.
package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LionZXY/bitwarden-approval-mcp/internal/approval"
	"github.com/LionZXY/bitwarden-approval-mcp/internal/audit"
	"github.com/LionZXY/bitwarden-approval-mcp/internal/totp"
	"github.com/LionZXY/bitwarden-approval-mcp/internal/vault"
)

// Vault is the read-only vault surface the server depends on (satisfied by
// *vault.Vault; mockable in tests).
type Vault interface {
	Search(query string) ([]vault.ItemMeta, error)
	Resolve(ref string) (vault.ItemMeta, error)
	GetFields(id string, fields []string) (map[string]string, error)
	Status() vault.Status
}

// Approver is the approval gate (satisfied by *approval.Manager).
type Approver interface {
	Request(ctx context.Context, r *approval.Request) (approval.Outcome, error)
}

// Options configures the server.
type Options struct {
	Vault       Vault
	Approver    Approver
	Audit       *audit.Logger
	Allowlist   []string
	Denylist    []string
	ListUngated bool
	RateLimit   int
	AgentTokens map[string]string // token -> agent name
	ServerName  string
	Version     string
}

// Server holds shared state for tool handlers.
type Server struct {
	opts    Options
	policy  policy
	limiter *rateLimiter
}

// agentKey is the context key for the authenticated agent name.
type agentKeyT struct{}

var agentKey = agentKeyT{}

// New builds a Server.
func New(o Options) *Server {
	if o.ServerName == "" {
		o.ServerName = "bitwarden-approval-mcp"
	}
	if o.Version == "" {
		o.Version = "0.1.0"
	}
	return &Server{opts: o, policy: newPolicy(o.Allowlist, o.Denylist), limiter: newRateLimiter(o.RateLimit)}
}

// Verifier is a bearer-token verifier for use with auth.RequireBearerToken.
func (s *Server) Verifier() auth.TokenVerifier {
	return func(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		for tok, name := range s.opts.AgentTokens {
			if subtle.ConstantTimeCompare([]byte(tok), []byte(token)) == 1 {
				return &auth.TokenInfo{UserID: name, Scopes: []string{"bwgate"},
					Expiration: time.Now().Add(time.Hour)}, nil
			}
		}
		return nil, auth.ErrInvalidToken
	}
}

func agentFromRequest(req *mcp.CallToolRequest) string {
	if req != nil && req.Extra != nil && req.Extra.TokenInfo != nil && req.Extra.TokenInfo.UserID != "" {
		return req.Extra.TokenInfo.UserID
	}
	if a, ok := req.GetSession().(interface{ ID() string }); ok {
		_ = a
	}
	return "stdio-local"
}

func clientLabel(req *mcp.CallToolRequest) string {
	if ci := req.ClientInfo(); ci != nil {
		if ci.Version != "" {
			return ci.Name + "/" + ci.Version
		}
		return ci.Name
	}
	return ""
}

func remoteLabel(req *mcp.CallToolRequest) string {
	if req.Extra != nil && req.Extra.Header != nil {
		if v := req.Extra.Header.Get("X-Forwarded-For"); v != "" {
			return strings.TrimSpace(strings.Split(v, ",")[0])
		}
	}
	return ""
}

// ----- tool input/output types -----

// SearchInput is the input for search_items.
type SearchInput struct {
	Query string `json:"query,omitempty" jsonschema:"Case-insensitive text to match against item name, URL, folder or organization. Empty lists everything."`
}

// ItemOut is non-secret item metadata.
type ItemOut struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	Type                   string   `json:"type"`
	Folder                 string   `json:"folder,omitempty"`
	Organization           string   `json:"organization,omitempty"`
	URIs                   []string `json:"uris,omitempty"`
	AvailableFields        []string `json:"available_fields"`
	MasterPasswordReprompt bool     `json:"master_password_reprompt,omitempty"`
}

// SearchOutput is the output for search_items.
type SearchOutput struct {
	Items []ItemOut `json:"items"`
	Count int       `json:"count"`
}

func toItemOut(m vault.ItemMeta) ItemOut {
	var fields []string
	if m.HasUsername {
		fields = append(fields, "username")
	}
	if m.HasPassword {
		fields = append(fields, "password")
	}
	if m.HasTOTP {
		fields = append(fields, "totp")
	}
	if m.HasNotes {
		fields = append(fields, "notes")
	}
	if len(m.URIs) > 0 {
		fields = append(fields, "uris")
	}
	for _, cf := range m.CustomFields {
		fields = append(fields, "field:"+cf)
	}
	return ItemOut{ID: m.ID, Name: m.Name, Type: m.Type, Folder: m.Folder, Organization: m.Organization,
		URIs: m.URIs, AvailableFields: fields, MasterPasswordReprompt: m.Reprompt}
}

// GetInput is the input for get_credential.
type GetInput struct {
	Item   string   `json:"item" jsonschema:"Item id (preferred) or exact item name."`
	Fields []string `json:"fields" jsonschema:"Which fields to return: username, password, totp, notes, uris, or field:<custom field name>."`
	Reason string   `json:"reason" jsonschema:"Short human-readable reason shown to the owner for approval."`
}

// GetOutput is the output for get_credential.
type GetOutput struct {
	Item      string            `json:"item"`
	ItemName  string            `json:"item_name"`
	RequestID string            `json:"request_id"`
	Fields    map[string]string `json:"fields"`
}

// TOTPInput is the input for get_totp.
type TOTPInput struct {
	Item   string `json:"item" jsonschema:"Item id or exact name."`
	Reason string `json:"reason" jsonschema:"Short reason shown to the owner for approval."`
}

// TOTPOutput is the output for get_totp.
type TOTPOutput struct {
	Item             string `json:"item"`
	ItemName         string `json:"item_name"`
	RequestID        string `json:"request_id"`
	Code             string `json:"code"`
	SecondsRemaining int    `json:"seconds_remaining"`
}

var validFields = map[string]bool{"username": true, "password": true, "totp": true, "notes": true, "uris": true}

func validateFields(fields []string) error {
	if len(fields) == 0 {
		return errors.New("at least one field is required")
	}
	for _, f := range fields {
		if !validFields[f] && !strings.HasPrefix(f, "field:") {
			return fmt.Errorf("unknown field %q", f)
		}
	}
	return nil
}

// Register adds all tools to an MCP server.
func (s *Server) Register(m *mcp.Server) {
	mcp.AddTool(m, &mcp.Tool{
		Name:        "search_items",
		Description: "Search the vault and return item metadata only (names, types, folders, URLs and which fields exist). Never returns secret values. Use this to find the item id to pass to get_credential.",
	}, s.searchItems)

	mcp.AddTool(m, &mcp.Tool{
		Name:        "get_credential",
		Description: "Request one or more secret fields of a vault item (username, password, totp, notes, uris, field:<name>). Requires owner approval on Telegram or an active saved approval for this agent, item, and requested fields. Without a saved approval, the call blocks until the owner decides or it times out.",
	}, s.getCredential)

	mcp.AddTool(m, &mcp.Tool{
		Name:        "get_totp",
		Description: "Request the current time-based one-time code (2FA) for a vault item. Requires owner approval on Telegram or an active saved approval for this agent and item covering the totp field. Returns the generated code, never the TOTP seed.",
	}, s.getTOTP)
}

func (s *Server) searchItems(ctx context.Context, req *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, SearchOutput, error) {
	agent := agentFromRequest(req)
	items, err := s.opts.Vault.Search(in.Query)
	if err != nil {
		return nil, SearchOutput{}, err
	}
	out := SearchOutput{}
	for _, m := range items {
		if !s.policy.allowed(m.Name, m.ID) {
			continue
		}
		out.Items = append(out.Items, toItemOut(m))
	}
	out.Count = len(out.Items)
	s.opts.Audit.Log(audit.Event{Event: "search", Agent: agent, Tool: "search_items",
		Detail: fmt.Sprintf("query=%q results=%d", in.Query, out.Count), Outcome: "ok"})
	if !s.opts.ListUngated {
		// If listing is gated this tool should not exist; included for completeness.
	}
	return nil, out, nil
}

func (s *Server) gate(ctx context.Context, req *mcp.CallToolRequest, tool, itemRef, reason string, fields []string) (vault.ItemMeta, string, error) {
	agent := agentFromRequest(req)
	if !s.limiter.allow(agent) {
		s.opts.Audit.Log(audit.Event{Event: "rate_limited", Agent: agent, Tool: tool, Outcome: "denied"})
		return vault.ItemMeta{}, "", errors.New("rate limit exceeded; slow down")
	}
	meta, err := s.opts.Vault.Resolve(itemRef)
	if err != nil {
		return vault.ItemMeta{}, "", err
	}
	if !s.policy.allowed(meta.Name, meta.ID) {
		s.opts.Audit.Log(audit.Event{Event: "policy_denied", Agent: agent, Tool: tool, ItemID: meta.ID, ItemName: meta.Name, Outcome: "denied"})
		return vault.ItemMeta{}, "", errors.New("this item is not permitted by server policy")
	}
	ar := &approval.Request{
		Agent: agent, Client: clientLabel(req), Remote: remoteLabel(req), Tool: tool,
		ItemID: meta.ID, ItemName: meta.Name, Folder: meta.Folder, Org: meta.Organization,
		Reprompt: meta.Reprompt, Fields: fields, Reason: reason,
	}
	outcome, err := s.opts.Approver.Request(ctx, ar)
	if err != nil {
		return vault.ItemMeta{}, ar.ID, err
	}
	if outcome != approval.Approved {
		return vault.ItemMeta{}, ar.ID, fmt.Errorf("request %s was %s by the owner", ar.ID, outcome)
	}
	return meta, ar.ID, nil
}

func (s *Server) getCredential(ctx context.Context, req *mcp.CallToolRequest, in GetInput) (*mcp.CallToolResult, GetOutput, error) {
	if err := validateFields(in.Fields); err != nil {
		return nil, GetOutput{}, err
	}
	if strings.TrimSpace(in.Reason) == "" {
		return nil, GetOutput{}, errors.New("a reason is required")
	}
	meta, reqID, err := s.gate(ctx, req, "get_credential", in.Item, in.Reason, in.Fields)
	if err != nil {
		return nil, GetOutput{}, err
	}
	vals, err := s.opts.Vault.GetFields(meta.ID, in.Fields)
	if err != nil {
		return nil, GetOutput{}, err
	}
	// For the totp field, return a live code rather than the seed.
	if raw, ok := vals["totp"]; ok && raw != "" {
		if p, perr := totp.Parse(raw); perr == nil {
			code, _ := p.Code(time.Now())
			vals["totp"] = code
		}
	}
	return nil, GetOutput{Item: meta.ID, ItemName: meta.Name, RequestID: reqID, Fields: vals}, nil
}

func (s *Server) getTOTP(ctx context.Context, req *mcp.CallToolRequest, in TOTPInput) (*mcp.CallToolResult, TOTPOutput, error) {
	if strings.TrimSpace(in.Reason) == "" {
		return nil, TOTPOutput{}, errors.New("a reason is required")
	}
	meta, reqID, err := s.gate(ctx, req, "get_totp", in.Item, in.Reason, []string{"totp"})
	if err != nil {
		return nil, TOTPOutput{}, err
	}
	vals, err := s.opts.Vault.GetFields(meta.ID, []string{"totp"})
	if err != nil {
		return nil, TOTPOutput{}, err
	}
	raw := vals["totp"]
	if raw == "" {
		return nil, TOTPOutput{}, errors.New("this item has no TOTP configured")
	}
	p, err := totp.Parse(raw)
	if err != nil {
		return nil, TOTPOutput{}, err
	}
	code, rem := p.Code(time.Now())
	return nil, TOTPOutput{Item: meta.ID, ItemName: meta.Name, RequestID: reqID, Code: code, SecondsRemaining: rem}, nil
}
