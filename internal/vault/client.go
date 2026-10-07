package vault

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Version is reported to the Bitwarden server as the client version.
const clientVersion = "2025.1.0"

// Device type 25 = LinuxCLI in the Bitwarden DeviceType enum.
const deviceTypeLinuxCLI = "25"

// Config holds everything needed to log in. Secret fields are wiped after Unlock.
type Config struct {
	ServerURL    string // e.g. https://vault.bitwarden.com or https://vw.example.com
	APIURL       string // optional override
	IdentityURL  string // optional override
	Email        string
	Password     []byte // master password (needed to decrypt the vault)
	ClientID     string // optional personal API key client_id ("user.xxxx")
	ClientSecret []byte // optional personal API key client_secret
	DeviceID     string // stable device identifier (UUID)
	DeviceName   string
	HTTPClient   *http.Client
}

// ErrLocked is returned when the vault is locked.
var ErrLocked = errors.New("vault is locked")

// ErrNotFound is returned when an item cannot be found.
var ErrNotFound = errors.New("item not found")

// Field names understood by GetFields.
const (
	FieldUsername = "username"
	FieldPassword = "password"
	FieldTOTP     = "totp" // raw TOTP secret/URI; callers usually convert to a code
	FieldNotes    = "notes"
	FieldURIs     = "uris"
	FieldPrefix   = "field:" // custom field, e.g. field:API Key
)

// ItemMeta is non-secret metadata about a vault item.
type ItemMeta struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Folder       string   `json:"folder,omitempty"`
	Organization string   `json:"organization,omitempty"`
	URIs         []string `json:"uris,omitempty"`
	HasUsername  bool     `json:"has_username"`
	HasPassword  bool     `json:"has_password"`
	HasTOTP      bool     `json:"has_totp"`
	HasNotes     bool     `json:"has_notes"`
	CustomFields []string `json:"custom_fields,omitempty"`
	Reprompt     bool     `json:"master_password_reprompt,omitempty"`
}

type rawURI struct {
	URI string `json:"uri"`
}

type rawLogin struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	TOTP     string   `json:"totp"`
	URIs     []rawURI `json:"uris"`
}

type rawField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  int    `json:"type"`
}

type rawCipher struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organizationId"`
	FolderID       string     `json:"folderId"`
	Type           int        `json:"type"`
	Name           string     `json:"name"`
	Notes          string     `json:"notes"`
	Key            string     `json:"key"`
	Login          *rawLogin  `json:"login"`
	Fields         []rawField `json:"fields"`
	Reprompt       int        `json:"reprompt"`
	DeletedDate    *string    `json:"deletedDate"`
}

type syncResponse struct {
	Profile struct {
		Email         string `json:"email"`
		Key           string `json:"key"`
		PrivateKey    string `json:"privateKey"`
		Organizations []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Key  string `json:"key"`
		} `json:"organizations"`
	} `json:"profile"`
	Folders []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"folders"`
	Ciphers []rawCipher `json:"ciphers"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Key          string `json:"Key"`
	PrivateKey   string `json:"PrivateKey"`
	Kdf          *int   `json:"Kdf"`
	KdfIter      *int   `json:"KdfIterations"`
	KdfMemory    *int   `json:"KdfMemory"`
	KdfParallel  *int   `json:"KdfParallelism"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
	TwoFactor    any    `json:"TwoFactorProviders"`
	ErrorModel   *struct {
		Message string `json:"Message"`
	} `json:"ErrorModel"`
}

// Vault is an unlocked, in-memory, read-only view of a Bitwarden vault.
type Vault struct {
	cfg      Config
	api      string
	identity string
	hc       *http.Client

	mu           sync.RWMutex
	accessToken  string
	refreshToken string
	tokenExpiry  time.Time
	clientSecret []byte
	userKey      *SymKey
	orgKeys      map[string]*SymKey
	orgNames     map[string]string
	folders      map[string]string
	ciphers      map[string]*rawCipher
	meta         []ItemMeta
	lastSync     time.Time
	locked       bool
}

// New prepares a client. Call Unlock to log in and decrypt.
func New(cfg Config) (*Vault, error) {
	api, identity, err := resolveURLs(cfg.ServerURL, cfg.APIURL, cfg.IdentityURL)
	if err != nil {
		return nil, err
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.DeviceID == "" {
		cfg.DeviceID = RandomUUID()
	}
	if cfg.DeviceName == "" {
		cfg.DeviceName = "bwgate"
	}
	return &Vault{cfg: cfg, api: api, identity: identity, hc: hc, locked: true}, nil
}

func resolveURLs(server, api, identity string) (string, string, error) {
	if api != "" && identity != "" {
		return strings.TrimRight(api, "/"), strings.TrimRight(identity, "/"), nil
	}
	if server == "" {
		server = "https://vault.bitwarden.com"
	}
	u, err := url.Parse(strings.TrimRight(server, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", "", fmt.Errorf("invalid Bitwarden server URL")
	}
	var a, i string
	switch u.Host {
	case "vault.bitwarden.com", "bitwarden.com":
		a, i = "https://api.bitwarden.com", "https://identity.bitwarden.com"
	case "vault.bitwarden.eu", "bitwarden.eu":
		a, i = "https://api.bitwarden.eu", "https://identity.bitwarden.eu"
	default:
		base := u.String()
		a, i = base+"/api", base+"/identity"
	}
	if api != "" {
		a = strings.TrimRight(api, "/")
	}
	if identity != "" {
		i = strings.TrimRight(identity, "/")
	}
	return a, i, nil
}

// RandomUUID returns a random v4 UUID string.
func RandomUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func (v *Vault) setHeaders(r *http.Request) {
	r.Header.Set("Device-Type", deviceTypeLinuxCLI)
	r.Header.Set("Bitwarden-Client-Name", "cli")
	r.Header.Set("Bitwarden-Client-Version", clientVersion)
	r.Header.Set("User-Agent", "bwgate/"+clientVersion)
	r.Header.Set("Accept", "application/json")
}

// httpErr strips URLs and bodies from transport errors to avoid leaking anything.
func httpErr(op string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %v", op, ue.Err)
	}
	return fmt.Errorf("%s: %v", op, err)
}

func (v *Vault) prelogin(ctx context.Context) (KDFParams, error) {
	body, _ := json.Marshal(map[string]string{"email": v.cfg.Email})
	var last error
	for _, u := range []string{v.identity + "/accounts/prelogin", v.api + "/accounts/prelogin"} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		v.setHeaders(req)
		resp, err := v.hc.Do(req)
		if err != nil {
			last = httpErr("prelogin", err)
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			last = fmt.Errorf("prelogin: HTTP %d", resp.StatusCode)
			continue
		}
		var k KDFParams
		if err := json.Unmarshal(data, &k); err != nil {
			return k, fmt.Errorf("prelogin: decode: %v", err)
		}
		return k, nil
	}
	return KDFParams{}, last
}

func (v *Vault) token(ctx context.Context, form url.Values) (*tokenResponse, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, v.identity+"/connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	v.setHeaders(req)
	if form.Get("grant_type") == "password" {
		req.Header.Set("Auth-Email", base64.RawURLEncoding.EncodeToString([]byte(v.cfg.Email)))
	}
	resp, err := v.hc.Do(req)
	if err != nil {
		return nil, httpErr("login", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var tr tokenResponse
	_ = json.Unmarshal(data, &tr)
	if resp.StatusCode != http.StatusOK || tr.AccessToken == "" {
		if tr.TwoFactor != nil {
			return nil, errors.New("login: two-factor authentication required; use a personal API key (BW_CLIENTID/BW_CLIENTSECRET) instead")
		}
		msg := tr.ErrorDesc
		if tr.ErrorModel != nil && tr.ErrorModel.Message != "" {
			msg = tr.ErrorModel.Message
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, fmt.Errorf("login: HTTP %d %s %s", resp.StatusCode, tr.Error, msg)
	}
	return &tr, nil
}

func (v *Vault) deviceForm(form url.Values) url.Values {
	form.Set("deviceType", deviceTypeLinuxCLI)
	form.Set("deviceIdentifier", v.cfg.DeviceID)
	form.Set("deviceName", v.cfg.DeviceName)
	return form
}

// Unlock logs in, syncs and decrypts the vault keys. The master password and
// master key are wiped from memory when it returns.
func (v *Vault) Unlock(ctx context.Context) error {
	defer wipe(v.cfg.Password)
	kdf, err := v.prelogin(ctx)
	if err != nil {
		return err
	}
	masterKey, err := DeriveMasterKey(v.cfg.Password, v.cfg.Email, kdf)
	if err != nil {
		return err
	}
	defer wipe(masterKey)

	var tr *tokenResponse
	if v.cfg.ClientID != "" {
		tr, err = v.token(ctx, v.deviceForm(url.Values{
			"grant_type":    {"client_credentials"},
			"scope":         {"api"},
			"client_id":     {v.cfg.ClientID},
			"client_secret": {string(v.cfg.ClientSecret)},
		}))
	} else {
		tr, err = v.token(ctx, v.deviceForm(url.Values{
			"grant_type": {"password"},
			"username":   {v.cfg.Email},
			"password":   {MasterPasswordHash(masterKey, v.cfg.Password)},
			"scope":      {"api offline_access"},
			"client_id":  {"cli"},
		}))
	}
	if err != nil {
		return err
	}
	stretched, err := StretchMasterKey(masterKey)
	if err != nil {
		return err
	}
	defer stretched.Wipe()

	sr, err := v.fetchSync(ctx, tr.AccessToken)
	if err != nil {
		return err
	}
	protKey := sr.Profile.Key
	if protKey == "" {
		protKey = tr.Key
	}
	ukBytes, err := DecryptSym(protKey, stretched)
	if err != nil {
		return fmt.Errorf("unlock: cannot decrypt user key (wrong master password?): %w", err)
	}
	userKey, err := SymKeyFromBytes(ukBytes)
	wipe(ukBytes)
	if err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	v.accessToken = tr.AccessToken
	v.refreshToken = tr.RefreshToken
	v.tokenExpiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	if len(v.cfg.ClientSecret) > 0 {
		v.clientSecret = append([]byte(nil), v.cfg.ClientSecret...)
		wipe(v.cfg.ClientSecret)
	}
	v.userKey = userKey
	privEnc := sr.Profile.PrivateKey
	if privEnc == "" {
		privEnc = tr.PrivateKey
	}
	if err := v.applySync(sr, privEnc); err != nil {
		v.lockLocked()
		return err
	}
	v.locked = false
	return nil
}

func (v *Vault) fetchSync(ctx context.Context, token string) (*syncResponse, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, v.api+"/sync?excludeDomains=true", nil)
	v.setHeaders(req)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := v.hc.Do(req)
	if err != nil {
		return nil, httpErr("sync", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sync: HTTP %d", resp.StatusCode)
	}
	var sr syncResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<20)).Decode(&sr); err != nil {
		return nil, fmt.Errorf("sync: decode: %v", err)
	}
	return &sr, nil
}

// applySync must be called with v.mu held.
func (v *Vault) applySync(sr *syncResponse, privEnc string) error {
	orgKeys := map[string]*SymKey{}
	orgNames := map[string]string{}
	if len(sr.Profile.Organizations) > 0 {
		var priv *rsa.PrivateKey
		if privEnc != "" {
			der, err := DecryptSym(privEnc, v.userKey)
			if err != nil {
				return fmt.Errorf("decrypt private key: %w", err)
			}
			priv, err = ParsePrivateKey(der)
			wipe(der)
			if err != nil {
				return fmt.Errorf("parse private key: %w", err)
			}
		}
		for _, o := range sr.Profile.Organizations {
			orgNames[o.ID] = o.Name
			if priv == nil || o.Key == "" {
				continue
			}
			kb, err := DecryptRSA(o.Key, priv)
			if err != nil {
				continue // org items will be skipped
			}
			k, err := SymKeyFromBytes(kb)
			wipe(kb)
			if err == nil {
				orgKeys[strings.ToLower(o.ID)] = k
			}
		}
	}
	folders := map[string]string{}
	for _, f := range sr.Folders {
		if n, err := DecryptSymString(f.Name, v.userKey); err == nil {
			folders[f.ID] = n
		}
	}
	for _, k := range v.orgKeys {
		k.Wipe()
	}
	v.orgKeys, v.orgNames, v.folders = orgKeys, orgNames, folders

	ciphers := map[string]*rawCipher{}
	var meta []ItemMeta
	for i := range sr.Ciphers {
		c := &sr.Ciphers[i]
		if c.DeletedDate != nil {
			continue
		}
		key, err := v.cipherKey(c)
		if err != nil {
			continue
		}
		m, err := v.buildMeta(c, key)
		if err != nil {
			continue
		}
		ciphers[strings.ToLower(c.ID)] = c
		meta = append(meta, m)
	}
	sort.Slice(meta, func(i, j int) bool { return strings.ToLower(meta[i].Name) < strings.ToLower(meta[j].Name) })
	v.ciphers, v.meta = ciphers, meta
	v.lastSync = time.Now()
	return nil
}

func (v *Vault) cipherKey(c *rawCipher) (*SymKey, error) {
	base := v.userKey
	if c.OrganizationID != "" {
		k, ok := v.orgKeys[strings.ToLower(c.OrganizationID)]
		if !ok {
			return nil, errors.New("missing organization key")
		}
		base = k
	}
	if c.Key == "" {
		return base, nil
	}
	kb, err := DecryptSym(c.Key, base)
	if err != nil {
		return nil, err
	}
	defer wipe(kb)
	return SymKeyFromBytes(kb)
}

var typeNames = map[int]string{1: "login", 2: "secure_note", 3: "card", 4: "identity", 5: "ssh_key"}

func (v *Vault) buildMeta(c *rawCipher, key *SymKey) (ItemMeta, error) {
	name, err := DecryptSymString(c.Name, key)
	if err != nil {
		return ItemMeta{}, err
	}
	m := ItemMeta{ID: c.ID, Name: name, Type: typeNames[c.Type], Reprompt: c.Reprompt == 1,
		Folder: v.folders[c.FolderID], Organization: v.orgNames[c.OrganizationID], HasNotes: c.Notes != ""}
	if m.Type == "" {
		m.Type = fmt.Sprintf("type_%d", c.Type)
	}
	if c.Login != nil {
		m.HasUsername = c.Login.Username != ""
		m.HasPassword = c.Login.Password != ""
		m.HasTOTP = c.Login.TOTP != ""
		for _, u := range c.Login.URIs {
			if s, err := DecryptSymString(u.URI, key); err == nil && s != "" {
				m.URIs = append(m.URIs, s)
			}
		}
	}
	for _, f := range c.Fields {
		if s, err := DecryptSymString(f.Name, key); err == nil && s != "" {
			m.CustomFields = append(m.CustomFields, s)
		}
	}
	return m, nil
}

// Sync refreshes the vault contents from the server.
func (v *Vault) Sync(ctx context.Context) error {
	tok, err := v.ensureToken(ctx)
	if err != nil {
		return err
	}
	sr, err := v.fetchSync(ctx, tok)
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.locked {
		return ErrLocked
	}
	privEnc := sr.Profile.PrivateKey
	return v.applySync(sr, privEnc)
}

func (v *Vault) ensureToken(ctx context.Context) (string, error) {
	v.mu.RLock()
	if v.locked {
		v.mu.RUnlock()
		return "", ErrLocked
	}
	tok, exp, rt := v.accessToken, v.tokenExpiry, v.refreshToken
	secret := append([]byte(nil), v.clientSecret...)
	v.mu.RUnlock()
	defer wipe(secret)
	if time.Until(exp) > 2*time.Minute {
		return tok, nil
	}
	var tr *tokenResponse
	var err error
	if v.cfg.ClientID != "" {
		tr, err = v.token(ctx, v.deviceForm(url.Values{
			"grant_type": {"client_credentials"}, "scope": {"api"},
			"client_id": {v.cfg.ClientID}, "client_secret": {string(secret)},
		}))
	} else if rt != "" {
		tr, err = v.token(ctx, url.Values{"grant_type": {"refresh_token"}, "client_id": {"cli"}, "refresh_token": {rt}})
	} else {
		return "", errors.New("access token expired and no way to refresh")
	}
	if err != nil {
		return "", err
	}
	v.mu.Lock()
	v.accessToken = tr.AccessToken
	if tr.RefreshToken != "" {
		v.refreshToken = tr.RefreshToken
	}
	v.tokenExpiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	v.mu.Unlock()
	return tr.AccessToken, nil
}

// Lock wipes all keys and decrypted metadata from memory.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.lockLocked()
}

func (v *Vault) lockLocked() {
	v.userKey.Wipe()
	for _, k := range v.orgKeys {
		k.Wipe()
	}
	wipe(v.clientSecret)
	v.userKey, v.orgKeys, v.ciphers, v.meta, v.folders = nil, nil, nil, nil, nil
	v.accessToken, v.refreshToken, v.clientSecret = "", "", nil
	v.locked = true
}

// Status describes the vault state without secrets.
type Status struct {
	Unlocked  bool      `json:"unlocked"`
	ItemCount int       `json:"item_count"`
	LastSync  time.Time `json:"last_sync,omitempty"`
}

// Status returns the current state.
func (v *Vault) Status() Status {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return Status{Unlocked: !v.locked, ItemCount: len(v.meta), LastSync: v.lastSync}
}

// LastSync returns the time of the last successful sync.
func (v *Vault) LastSync() time.Time {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.lastSync
}

// Items returns metadata for all items.
func (v *Vault) Items() ([]ItemMeta, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.locked {
		return nil, ErrLocked
	}
	out := make([]ItemMeta, len(v.meta))
	copy(out, v.meta)
	return out, nil
}

// Search returns items whose name, URI, folder or organization contains the query.
func (v *Vault) Search(query string) ([]ItemMeta, error) {
	items, err := v.Items()
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return items, nil
	}
	var out []ItemMeta
	for _, m := range items {
		hay := strings.ToLower(m.Name + "\n" + m.Folder + "\n" + m.Organization + "\n" + strings.Join(m.URIs, "\n") + "\n" + m.ID)
		if strings.Contains(hay, q) {
			out = append(out, m)
		}
	}
	return out, nil
}

// ErrAmbiguous is returned when a name matches more than one item.
type ErrAmbiguous struct{ IDs []string }

func (e *ErrAmbiguous) Error() string {
	return "more than one item matches that name; use one of these ids: " + strings.Join(e.IDs, ", ")
}

// Resolve finds a single item by ID or exact (case-insensitive) name.
func (v *Vault) Resolve(ref string) (ItemMeta, error) {
	items, err := v.Items()
	if err != nil {
		return ItemMeta{}, err
	}
	ref = strings.TrimSpace(ref)
	var matches []ItemMeta
	for _, m := range items {
		if strings.EqualFold(m.ID, ref) {
			return m, nil
		}
		if strings.EqualFold(m.Name, ref) {
			matches = append(matches, m)
		}
	}
	switch len(matches) {
	case 0:
		return ItemMeta{}, ErrNotFound
	case 1:
		return matches[0], nil
	}
	ids := make([]string, len(matches))
	for i, m := range matches {
		ids[i] = m.ID
	}
	return ItemMeta{}, &ErrAmbiguous{IDs: ids}
}

// GetFields decrypts and returns only the requested fields of an item.
// Fields that the item does not have are returned as empty strings.
func (v *Vault) GetFields(id string, fields []string) (map[string]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.locked {
		return nil, ErrLocked
	}
	c, ok := v.ciphers[strings.ToLower(id)]
	if !ok {
		return nil, ErrNotFound
	}
	key, err := v.cipherKey(c)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	dec := func(s string) (string, error) { return DecryptSymString(s, key) }
	for _, f := range fields {
		var val string
		switch {
		case f == FieldUsername && c.Login != nil:
			val, err = dec(c.Login.Username)
		case f == FieldPassword && c.Login != nil:
			val, err = dec(c.Login.Password)
		case f == FieldTOTP && c.Login != nil:
			val, err = dec(c.Login.TOTP)
		case f == FieldNotes:
			val, err = dec(c.Notes)
		case f == FieldURIs && c.Login != nil:
			var uris []string
			for _, u := range c.Login.URIs {
				s, e := dec(u.URI)
				if e != nil {
					err = e
					break
				}
				uris = append(uris, s)
			}
			val = strings.Join(uris, "\n")
		case strings.HasPrefix(f, FieldPrefix):
			want := strings.TrimPrefix(f, FieldPrefix)
			for _, cf := range c.Fields {
				n, e := dec(cf.Name)
				if e == nil && n == want {
					val, err = dec(cf.Value)
					break
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", f, err)
		}
		out[f] = val
	}
	return out, nil
}
