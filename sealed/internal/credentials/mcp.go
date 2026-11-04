package credentials

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// MCPSpec makes an entry a login entry: the owner logs sealed in to the MCP
// server at URL, following the MCP authorization spec (OAuth 2.1 with PKCE,
// protected resource metadata, dynamic client registration), and sealed
// keeps the tokens. The entry's value is the access token, filled where the
// owner allowed it (Authorization: Bearer {v} on the server's host); sealed
// refreshes it itself and writes the result back.
type MCPSpec struct {
	URL string `json:"url"`
	// ClientID is for a server that does not register clients itself.
	ClientID string `json:"client_id,omitempty"`
	// ClientSecretEntry names the entry holding that client's secret.
	ClientSecretEntry string   `json:"client_secret_entry,omitempty"`
	Scopes            []string `json:"scopes,omitempty"`
}

// mcpState is what a login yields: sealed to agentSeal and written back, so
// a restart keeps the login.
type mcpState struct {
	V            int    `json:"v"`
	Type         string `json:"type"` // "mcp_login"
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	TokenURL     string `json:"token_url"`
	Resource     string `json:"resource"`
}

func parseMCPState(b []byte) (*mcpState, bool) {
	var st mcpState
	if json.Unmarshal(b, &st) != nil || st.V != 1 || st.Type != "mcp_login" || st.AccessToken == "" {
		return nil, false
	}
	return &st, true
}

// loginAttempt is a login the owner started and has not finished.
type loginAttempt struct {
	name, verifier, redirectURI string
	clientID, clientSecret      string
	tokenURL, resource          string
	expires                     time.Time
}

const (
	loginTTL      = 10 * time.Minute
	refreshBefore = time.Minute
	maxMetadata   = 1 << 20
)

// authServer is what discovery finds for an MCP server.
type authServer struct {
	authorize, token, register string
	resource                   string
	scopes                     []string
}

func randomURLSafe(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// LoginError is a login that cannot start or finish, with a reason that
// carries no secret.
type LoginError struct{ Reason string }

func (e *LoginError) Error() string { return e.Reason }

func loginErr(format string, args ...any) error { return &LoginError{fmt.Sprintf(format, args...)} }

// StartLogin begins the owner's login to a login entry's MCP server and
// returns the URL the owner opens to consent. The authorization server
// redirects to redirectURI (this agent's /_seal/oauth/callback), where
// FinishLogin completes it. The PKCE verifier never leaves sealed.
func (s *Store) StartLogin(ctx context.Context, name, redirectURI string) (string, error) {
	s.mu.Lock()
	def := s.defs[name]
	var secret string
	if def != nil && def.MCP != nil && def.MCP.ClientSecretEntry != "" {
		secret = string(s.values[def.MCP.ClientSecretEntry])
	}
	s.mu.Unlock()
	if def == nil || def.MCP == nil {
		return "", loginErr("no login entry named %q", name)
	}
	if !strings.HasPrefix(redirectURI, "https://") {
		return "", loginErr("this agent has no https address for the login to return to")
	}
	as, err := s.discover(ctx, def.MCP.URL)
	if err != nil {
		return "", err
	}
	clientID := def.MCP.ClientID
	if clientID == "" {
		if as.register == "" {
			return "", loginErr("the authorization server does not register clients; give the entry a client_id")
		}
		if clientID, secret, err = s.registerClient(ctx, as.register, redirectURI); err != nil {
			return "", err
		}
	}
	verifier := randomURLSafe(32)
	sum := sha256.Sum256([]byte(verifier))
	state := randomURLSafe(24)
	s.mu.Lock()
	now := s.now()
	for k, a := range s.logins {
		if now.After(a.expires) {
			delete(s.logins, k)
		}
	}
	s.logins[state] = &loginAttempt{name: name, verifier: verifier, redirectURI: redirectURI, clientID: clientID,
		clientSecret: secret, tokenURL: as.token, resource: as.resource, expires: now.Add(loginTTL)}
	s.mu.Unlock()

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"resource":              {as.resource},
	}
	scopes := def.MCP.Scopes
	if len(scopes) == 0 {
		scopes = as.scopes
	}
	if len(scopes) > 0 {
		q.Set("scope", strings.Join(scopes, " "))
	}
	sep := "?"
	if strings.Contains(as.authorize, "?") {
		sep = "&"
	}
	s.audit("login", name, as.authorize, "started")
	return as.authorize + sep + q.Encode(), nil
}

// FinishLogin completes a login from the authorization server's redirect:
// the state names the attempt (once), the code is exchanged with the PKCE
// verifier, and the tokens become the entry's value.
func (s *Store) FinishLogin(ctx context.Context, state, code, oauthError string) (string, error) {
	s.mu.Lock()
	a := s.logins[state]
	delete(s.logins, state)
	s.mu.Unlock()
	if a == nil || s.now().After(a.expires) {
		return "", loginErr("this login link is unknown or has expired; start the login again")
	}
	if oauthError != "" {
		s.audit("login", a.name, a.tokenURL, "refused: "+sanitizeCode(oauthError))
		return a.name, loginErr("the authorization server answered %s", sanitizeCode(oauthError))
	}
	if code == "" {
		return a.name, loginErr("the authorization server sent no code")
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {a.redirectURI},
		"client_id":     {a.clientID},
		"code_verifier": {a.verifier},
		"resource":      {a.resource},
	}
	if a.clientSecret != "" {
		form.Set("client_secret", a.clientSecret)
	}
	tok, err := s.tokenCall(ctx, a.tokenURL, form)
	if err != nil {
		s.audit("login", a.name, a.tokenURL, "failed")
		return a.name, err
	}
	st := &mcpState{V: 1, Type: "mcp_login", AccessToken: tok.access, RefreshToken: tok.refresh, ClientID: a.clientID,
		ClientSecret: a.clientSecret, TokenURL: a.tokenURL, Resource: a.resource}
	if tok.expiresIn > 0 {
		st.ExpiresAt = s.now().Unix() + tok.expiresIn
	}
	s.applyLogin(ctx, a.name, st)
	s.audit("login", a.name, a.tokenURL, "ok")
	return a.name, nil
}

// applyLogin makes st the entry's value, writes it back, and schedules the
// next refresh.
func (s *Store) applyLogin(ctx context.Context, name string, st *mcpState) {
	raw, _ := json.Marshal(st)
	s.mu.Lock()
	def := s.defs[name]
	if def == nil {
		s.mu.Unlock()
		return // removed meanwhile
	}
	_, had := s.values[name]
	s.mu.Unlock()
	s.rotate(ctx, def, raw)
	if !had {
		s.mu.Lock()
		s.events.add(Event{Type: "entry_added", Name: name})
		s.mu.Unlock()
	}
	s.scheduleRefresh(name, st)
}

// scheduleRefresh refreshes a login entry's access token shortly before it
// expires. A newer schedule for the same entry replaces this one.
func (s *Store) scheduleRefresh(name string, st *mcpState) {
	if st.RefreshToken == "" || st.ExpiresAt == 0 {
		return
	}
	wait := time.Until(time.Unix(st.ExpiresAt, 0).Add(-refreshBefore))
	if wait < 0 {
		wait = 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.refreshTimers[name]; t != nil {
		t.Stop()
	}
	s.refreshTimers[name] = time.AfterFunc(wait, func() { s.refreshLogin(name, 0) })
}

// refreshLogin trades the refresh token for a new access token (and the
// rotated refresh token the server returns). A failure is retried with
// backoff; a refused refresh token ends the login, and the owner is told
// through a login request.
func (s *Store) refreshLogin(name string, attempt int) {
	s.mu.Lock()
	raw := s.values[name]
	def := s.defs[name]
	s.mu.Unlock()
	st, ok := parseMCPState(raw)
	if def == nil || def.MCP == nil || !ok || st.RefreshToken == "" {
		return
	}
	lock := s.lockFor(name)
	lock.Lock()
	defer lock.Unlock()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {st.RefreshToken},
		"client_id":     {st.ClientID},
		"resource":      {st.Resource},
	}
	if st.ClientSecret != "" {
		form.Set("client_secret", st.ClientSecret)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tok, err := s.tokenCall(ctx, st.TokenURL, form)
	if err != nil {
		var le *LoginError
		if errors.As(err, &le) && strings.Contains(le.Reason, "invalid_grant") {
			s.audit("refresh", name, st.TokenURL, "invalid_grant")
			s.mu.Lock()
			s.pendingForLocked("login", name, map[string]string{"url": def.MCP.URL}, "", map[string]any{"source": "sealed", "why": "the login expired or was revoked"})
			s.mu.Unlock()
			return
		}
		s.audit("refresh", name, st.TokenURL, "failed")
		if attempt < 6 {
			delay := time.Duration(1<<attempt) * 10 * time.Second
			time.AfterFunc(delay, func() { s.refreshLogin(name, attempt+1) })
		}
		return
	}
	next := *st
	next.AccessToken = tok.access
	if tok.refresh != "" {
		next.RefreshToken = tok.refresh
	}
	next.ExpiresAt = 0
	if tok.expiresIn > 0 {
		next.ExpiresAt = s.now().Unix() + tok.expiresIn
	}
	s.audit("refresh", name, st.TokenURL, "ok")
	s.applyLogin(ctx, name, &next)
}

type tokenResult struct {
	access, refresh string
	expiresIn       int64
}

// tokenCall posts form to a token endpoint and reads the tokens; an error
// carries the OAuth error code only, never the response body.
func (s *Store) tokenCall(ctx context.Context, tokenURL string, form url.Values) (*tokenResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, loginErr("bad token endpoint")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return nil, loginErr("the token endpoint is unreachable")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	got := parseTokenResponse(body)
	if resp.StatusCode/100 != 2 {
		code, _ := got["error"].(string)
		return nil, loginErr("the token endpoint answered %d %s", resp.StatusCode, sanitizeCode(code))
	}
	out := &tokenResult{}
	out.access, _ = got["access_token"].(string)
	out.refresh, _ = got["refresh_token"].(string)
	switch v := got["expires_in"].(type) {
	case float64:
		out.expiresIn = int64(v)
	case string:
		out.expiresIn, _ = strconv.ParseInt(v, 10, 64)
	}
	if out.access == "" {
		return nil, loginErr("the token endpoint returned no access token")
	}
	return out, nil
}

// registerClient registers sealed as a public client (RFC 7591).
func (s *Store) registerClient(ctx context.Context, endpoint, redirectURI string) (string, string, error) {
	body, _ := json.Marshal(map[string]any{
		"client_name":                "AgentDNA agent",
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return "", "", loginErr("bad registration endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return "", "", loginErr("the registration endpoint is unreachable")
	}
	defer resp.Body.Close()
	var out struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxMetadata))
	if resp.StatusCode/100 != 2 || json.Unmarshal(raw, &out) != nil || out.ClientID == "" {
		return "", "", loginErr("client registration failed (HTTP %d)", resp.StatusCode)
	}
	return out.ClientID, out.ClientSecret, nil
}

// discover finds the authorization server of the MCP server at mcpURL: the
// protected resource metadata (RFC 9728) named by a 401's
// WWW-Authenticate, or at its well-known paths, then the authorization
// server's metadata (RFC 8414, or OpenID discovery). A server that offers
// neither is taken to be its own authorization server.
func (s *Store) discover(ctx context.Context, mcpURL string) (*authServer, error) {
	u, err := url.Parse(mcpURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, loginErr("the MCP server URL must be https")
	}
	origin := u.Scheme + "://" + u.Host
	path := strings.TrimSuffix(u.EscapedPath(), "/")

	var prmURLs []string
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, mcpURL, nil); err == nil {
		if resp, err := s.httpClient().Do(req); err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxMetadata))
			resp.Body.Close()
			if m := resourceMetadataParam(resp.Header.Get("WWW-Authenticate")); m != "" {
				prmURLs = append(prmURLs, m)
			}
		}
	}
	if path != "" {
		prmURLs = append(prmURLs, origin+"/.well-known/oauth-protected-resource"+path)
	}
	prmURLs = append(prmURLs, origin+"/.well-known/oauth-protected-resource")

	as := &authServer{resource: mcpURL}
	issuer := origin
	for _, p := range prmURLs {
		var prm struct {
			Resource             string   `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
			ScopesSupported      []string `json:"scopes_supported"`
		}
		if s.getJSON(ctx, p, &prm) != nil || len(prm.AuthorizationServers) == 0 {
			continue
		}
		issuer = strings.TrimSuffix(prm.AuthorizationServers[0], "/")
		if prm.Resource != "" {
			as.resource = prm.Resource
		}
		as.scopes = prm.ScopesSupported
		break
	}

	iu, err := url.Parse(issuer)
	if err != nil || iu.Scheme != "https" || iu.Host == "" {
		return nil, loginErr("the authorization server must be https")
	}
	ipath := strings.TrimSuffix(iu.EscapedPath(), "/")
	iorigin := iu.Scheme + "://" + iu.Host
	for _, m := range []string{
		iorigin + "/.well-known/oauth-authorization-server" + ipath,
		iorigin + "/.well-known/openid-configuration" + ipath,
		issuer + "/.well-known/openid-configuration",
	} {
		var meta struct {
			AuthorizationEndpoint         string   `json:"authorization_endpoint"`
			TokenEndpoint                 string   `json:"token_endpoint"`
			RegistrationEndpoint          string   `json:"registration_endpoint"`
			CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
			ScopesSupported               []string `json:"scopes_supported"`
		}
		if s.getJSON(ctx, m, &meta) != nil || meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" {
			continue
		}
		if len(meta.CodeChallengeMethodsSupported) > 0 && !contains(meta.CodeChallengeMethodsSupported, "S256") {
			return nil, loginErr("the authorization server does not support PKCE with S256")
		}
		for _, e := range []string{meta.AuthorizationEndpoint, meta.TokenEndpoint} {
			if !strings.HasPrefix(e, "https://") {
				return nil, loginErr("the authorization server's endpoints must be https")
			}
		}
		if meta.RegistrationEndpoint != "" && !strings.HasPrefix(meta.RegistrationEndpoint, "https://") {
			meta.RegistrationEndpoint = ""
		}
		as.authorize, as.token, as.register = meta.AuthorizationEndpoint, meta.TokenEndpoint, meta.RegistrationEndpoint
		if len(as.scopes) == 0 {
			as.scopes = meta.ScopesSupported
		}
		return as, nil
	}
	return nil, loginErr("no authorization server metadata found for %s", u.Host)
}

func (s *Store) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxMetadata)).Decode(v)
}

// resourceMetadataParam reads resource_metadata="…" from a WWW-Authenticate
// header.
func resourceMetadataParam(h string) string {
	const key = "resource_metadata="
	i := strings.Index(h, key)
	if i < 0 {
		return ""
	}
	v := h[i+len(key):]
	if strings.HasPrefix(v, `"`) {
		if j := strings.IndexByte(v[1:], '"'); j >= 0 {
			return v[1 : j+1]
		}
		return ""
	}
	if j := strings.IndexAny(v, ", "); j >= 0 {
		v = v[:j]
	}
	return v
}

// usableValue is what an entry's value is to everything but the login code:
// a login entry's access token, not its stored login state.
func usableValue(def *Definition, raw []byte) []byte {
	if def == nil || def.MCP == nil {
		return raw
	}
	if st, ok := parseMCPState(raw); ok {
		return []byte(st.AccessToken)
	}
	return nil
}
