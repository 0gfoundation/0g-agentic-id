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

	"seal-verify/internal/credproxy"
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
	LoggedInAt   int64  `json:"logged_in_at,omitempty"`
	// RevocationURL is the authorization server's RFC 7009 endpoint, when
	// its metadata names one: a disconnect asks it to revoke the tokens.
	RevocationURL string `json:"revocation_url,omitempty"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret,omitempty"`
	TokenURL      string `json:"token_url"`
	Resource      string `json:"resource"`
}

func parseMCPState(b []byte) (*mcpState, bool) {
	var st mcpState
	if json.Unmarshal(b, &st) != nil || st.V != 1 || st.Type != "mcp_login" || st.AccessToken == "" {
		return nil, false
	}
	return &st, true
}

// loginAttempt is a login the owner started and has not finished: under
// def, while nothing was cleared since gen.
type loginAttempt struct {
	name, verifier, redirectURI string
	clientID, clientSecret      string
	tokenURL, resource          string
	revocationURL               string
	expires                     time.Time
	def                         *Definition
	gen                         uint64
	// secretFromEntry: the client secret is the owner's
	// client_secret_entry, read at each use; clientSecret then stays empty
	// (it holds only a secret the server issued at registration).
	secretFromEntry bool
	// issuer is the authorization server the owner was sent to; its
	// redirect names it (RFC 9207) when issRequired, and must not name
	// another when it names one.
	issuer      string
	issRequired bool
}

const (
	loginTTL      = 10 * time.Minute
	refreshBefore = time.Minute
	// minRefreshWait keeps a server that issues very short-lived tokens
	// from being asked again and again.
	minRefreshWait = 10 * time.Second
	maxMetadata    = 1 << 20
)

// authServer is what discovery finds for an MCP server.
type authServer struct {
	issuer                     string
	authorize, token, register string
	revocation                 string // RFC 7009; empty when not offered
	resource                   string
	scopes                     []string
	issParam                   bool // RFC 9207: the redirect names the issuer
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
	if cerr := s.ensureOwner(ctx); cerr != nil {
		return "", loginErr("%s", cerr.Message)
	}
	s.mu.Lock()
	def, gen := s.defs[name], s.gen
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
	secret, fromEntry, err := s.entrySecret(def, as.token)
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
	if s.gen != gen {
		s.mu.Unlock()
		return "", loginErr("the agent's owner changed; start the login again")
	}
	if fromEntry {
		secret = "" // read again at the code exchange
	}
	s.logins[state] = &loginAttempt{name: name, verifier: verifier, redirectURI: redirectURI, clientID: clientID,
		clientSecret: secret, tokenURL: as.token, resource: as.resource, revocationURL: as.revocation, expires: now.Add(loginTTL),
		def: def, gen: gen, secretFromEntry: fromEntry, issuer: as.issuer, issRequired: as.issParam}
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
// the state names the attempt (once), iss (RFC 9207) the server that sent
// it back, the code is exchanged with the PKCE verifier, and the tokens
// become the entry's value.
func (s *Store) FinishLogin(ctx context.Context, state, code, oauthError, iss string) (string, error) {
	// The state first: an unknown one costs nothing, not a chain lookup.
	s.mu.Lock()
	a := s.logins[state]
	s.mu.Unlock()
	if a == nil || s.now().After(a.expires) {
		return "", loginErr("this login link is unknown or has expired; start the login again")
	}
	// The attempt is kept while the owner cannot be confirmed, so the
	// browser can come back; an owner change clears it.
	if cerr := s.ensureOwner(ctx); cerr != nil {
		return "", loginErr("%s", cerr.Message)
	}
	s.mu.Lock()
	taken := s.logins[state] == a && s.gen == a.gen
	delete(s.logins, state)
	s.mu.Unlock()
	if !taken {
		return "", loginErr("this login link is unknown or has expired; start the login again")
	}
	// The redirect must come from the server the owner was sent to: a code
	// from another one is never posted to this login's token endpoint.
	if (iss != "" || a.issRequired) && strings.TrimSuffix(iss, "/") != a.issuer {
		s.audit("login", a.name, a.tokenURL, "refused: the redirect names another authorization server")
		return a.name, loginErr("the login came back from another authorization server; start the login again")
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
	secret := a.clientSecret
	if a.secretFromEntry {
		s.mu.Lock()
		cur := s.defs[a.name]
		s.mu.Unlock()
		if cur == nil || cur.Binding() != a.def.Binding() {
			return a.name, loginErr("the entry changed while the login ran; start the login again")
		}
		var serr error
		if secret, _, serr = s.entrySecret(cur, a.tokenURL); serr != nil {
			s.audit("login", a.name, a.tokenURL, "not sent: "+serr.Error())
			return a.name, serr
		}
	}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	tok, err := s.tokenCall(ctx, a.tokenURL, form)
	if err != nil {
		s.audit("login", a.name, a.tokenURL, "failed")
		return a.name, err
	}
	if len(tok.access) > credproxy.MaxValueLen {
		s.audit("login", a.name, a.tokenURL, "refused: the access token is over the size sealed holds")
		return a.name, loginErr("the server's access token is over %d bytes, more than sealed holds", credproxy.MaxValueLen)
	}
	st := &mcpState{V: 1, Type: "mcp_login", AccessToken: tok.access, RefreshToken: tok.refresh, LoggedInAt: s.now().Unix(),
		ClientID: a.clientID, TokenURL: a.tokenURL, Resource: a.resource, RevocationURL: a.revocationURL}
	if !a.secretFromEntry {
		st.ClientSecret = a.clientSecret // issued at registration: the login's own
	}
	if tok.expiresIn > 0 {
		st.ExpiresAt = s.now().Unix() + tok.expiresIn
	}
	// Not while a refresh or a disconnect of the entry runs: the newer login
	// is the one that stands.
	lock := s.lockFor(a.name)
	lock.Lock()
	applied := s.applyLogin(ctx, a.def, a.gen, st)
	lock.Unlock()
	if !applied {
		s.audit("login", a.name, a.tokenURL, "dropped: the entry changed meanwhile")
		return a.name, loginErr("the entry changed while the login ran; start the login again")
	}
	// A login request is answered by a completed login, not by the owner
	// adding the entry.
	s.mu.Lock()
	for id, p := range s.pending {
		if p.Op == "login" && p.Name == a.name && p.Status == "pending" {
			p.Status = "approved"
			s.events.add(Event{Type: "pending_decided", Name: p.Name, AuthReqID: id, Status: p.Status})
		}
	}
	s.mu.Unlock()
	s.audit("login", a.name, a.tokenURL, "ok")
	return a.name, nil
}

// applyLogin makes st the entry's value (unless the entry changed since gen,
// see rotate), writes it back, and schedules the next refresh.
func (s *Store) applyLogin(ctx context.Context, def *Definition, gen uint64, st *mcpState) bool {
	raw, _ := json.Marshal(st)
	applied, had := s.rotate(ctx, def, gen, raw)
	if !applied {
		return false
	}
	if !had {
		s.mu.Lock()
		s.events.add(Event{Type: "entry_added", Name: def.Name})
		s.mu.Unlock()
	}
	s.scheduleRefresh(def.Name, st)
	return true
}

// scheduleRefresh refreshes a login entry's access token shortly before it
// expires (halfway through a lifetime under two minutes, and never sooner
// than minRefreshWait). A newer schedule for the same entry replaces this
// one.
func (s *Store) scheduleRefresh(name string, st *mcpState) {
	if st.RefreshToken == "" || st.ExpiresAt == 0 {
		return
	}
	lifetime := time.Unix(st.ExpiresAt, 0).Sub(s.now())
	before := refreshBefore
	if lifetime < 2*refreshBefore {
		before = lifetime / 2
	}
	wait := lifetime - before
	if wait < minRefreshWait {
		wait = minRefreshWait
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.refreshTimers[name]; t != nil {
		t.Stop()
	}
	access := st.AccessToken
	s.refreshTimers[name] = time.AfterFunc(wait, func() { s.refreshLogin(name, access, 0) })
}

// refreshLogin trades the refresh token for a new access token (and the
// rotated refresh token the server returns), if the entry still holds the
// access token this refresh was scheduled for. A failure is retried with
// backoff; a refused refresh token ends the login, and the owner is told
// through a login request.
func (s *Store) refreshLogin(name, access string, attempt int) {
	lock := s.lockFor(name)
	lock.Lock()
	defer lock.Unlock()
	s.mu.Lock()
	raw, def, gen := s.values[name], s.defs[name], s.gen
	s.mu.Unlock()
	st, ok := parseMCPState(raw)
	if def == nil || def.MCP == nil || !ok || st.RefreshToken == "" || st.AccessToken != access {
		return // gone, or refreshed or logged in again meanwhile
	}
	secret, fromEntry, serr := s.entrySecret(def, st.TokenURL)
	if serr != nil {
		s.auditRepeat("refresh", name, st.TokenURL, "not sent: "+serr.Error())
		s.askLogin(name, def, gen, serr.Error())
		return
	}
	if !fromEntry {
		secret = st.ClientSecret
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {st.RefreshToken},
		"client_id":     {st.ClientID},
		"resource":      {st.Resource},
	}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tok, err := s.tokenCall(ctx, st.TokenURL, form)
	if err != nil {
		var le *LoginError
		if errors.As(err, &le) && strings.Contains(le.Reason, "invalid_grant") {
			s.auditRepeat("refresh", name, st.TokenURL, "invalid_grant")
			s.askLogin(name, def, gen, "the login expired or was revoked")
			return
		}
		s.auditRepeat("refresh", name, st.TokenURL, "failed")
		if attempt < 6 {
			delay := time.Duration(1<<attempt) * 10 * time.Second
			time.AfterFunc(delay, func() { s.refreshLogin(name, access, attempt+1) })
			return
		}
		s.askLogin(name, def, gen, "the login could not be refreshed")
		return
	}
	if len(tok.access) > credproxy.MaxValueLen {
		s.auditRepeat("refresh", name, st.TokenURL, "refused: the access token is over the size sealed holds")
		s.askLogin(name, def, gen, "the server's access token is over the size sealed holds")
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
	s.auditRepeat("refresh", name, st.TokenURL, "ok")
	s.applyLogin(ctx, def, gen, &next)
}

// askLogin opens a login request for the owner when the entry's login can
// no longer be refreshed (why says so), unless everything was cleared since gen.
func (s *Store) askLogin(name string, def *Definition, gen uint64, why string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen == gen {
		// Bound apart from the agent's own requests, so one of those (denied,
		// say) never stands in for it.
		_, _ = s.pendingForLocked("login", name, map[string]string{"url": def.MCP.URL}, "sealed", "", map[string]any{"source": "sealed", "why": why})
	}
}

// entrySecret is the client secret a login sends to tokenURL from the owner's
// client_secret_entry, as the entry stands now: loaded, unexpired, not a
// signing key, and allowing tokenURL's host when it lists hosts (the
// endpoint comes from the server's metadata). fromEntry is false when the
// login has no such entry (no client_id of the owner's).
func (s *Store) entrySecret(def *Definition, tokenURL string) (secret string, fromEntry bool, err error) {
	if def.MCP == nil || def.MCP.ClientID == "" || def.MCP.ClientSecretEntry == "" {
		return "", false, nil
	}
	se := def.MCP.ClientSecretEntry
	s.mu.Lock()
	sd := s.defs[se]
	v := usableValue(sd, s.values[se])
	s.mu.Unlock()
	switch {
	case sd == nil || len(v) == 0:
		return "", true, loginErr("the client secret entry %q is not loaded", se)
	case useOf(sd) == credproxy.UseSign:
		return "", true, loginErr("the client secret entry %q is a signing key and is never sent", se)
	case s.expired(se):
		return "", true, loginErr("the client secret entry %q has expired", se)
	case len(sd.Hosts) > 0 && !hostListed(tokenURL, sd.Hosts):
		return "", true, loginErr("the client secret entry %q does not allow the token endpoint's host", se)
	}
	return string(v), true, nil
}

// sameHost reports whether two URLs name the same host.
func sameHost(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && ua.Host != "" && credproxy.NormalizeHost(ua.Host) == credproxy.NormalizeHost(ub.Host)
}

// hostListed reports whether rawURL's host is one of hosts.
func hostListed(rawURL string, hosts []string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	h := credproxy.NormalizeHost(u.Host)
	for _, x := range hosts {
		if credproxy.NormalizeHost(x) == h {
			return true
		}
	}
	return false
}

// loggedOut is what a disconnected login entry is written back as, so a
// restart does not bring the login back.
var loggedOut = []byte(`{"v":1,"type":"mcp_logout"}`)

// Disconnect ends a login entry's login. When the authorization server
// offered token revocation (RFC 7009) at login, on the token endpoint's
// host, it is asked to revoke the refresh token and the access token;
// either way sealed forgets them and writes that back, so the entry waits
// for a new login, across restarts too. The owner removes the entry after.
// revoked says whether the server confirmed; note, when it did not, why.
func (s *Store) Disconnect(ctx context.Context, name string) (revoked bool, note string, err error) {
	s.mu.Lock()
	_, defined := s.defs[name]
	s.mu.Unlock()
	if !defined {
		return false, "", loginErr("no login entry named %q", name)
	}
	lock := s.lockFor(name) // not while a refresh or a login applies tokens
	lock.Lock()
	defer lock.Unlock()
	s.mu.Lock()
	def, raw, owner, gen := s.defs[name], s.values[name], s.owner, s.gen
	s.mu.Unlock()
	if def == nil || def.MCP == nil {
		return false, "", loginErr("no login entry named %q", name)
	}
	endpoint := ""
	if st, ok := parseMCPState(raw); !ok {
		note = "not connected: there was nothing to revoke"
	} else {
		// Only the endpoint the server named at login: tokens and a client
		// secret never go where the server's metadata points to today.
		endpoint = st.RevocationURL
		if endpoint == "" {
			note = "the server offered no token revocation: revoke the app's access at the service"
		} else {
			// Not cut short by the owner's client giving up: the tokens are
			// forgotten next, so this is the one chance to revoke them.
			rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			revoked, note = s.revoke(rctx, endpoint, def, st)
			cancel()
		}
	}
	s.mu.Lock()
	if cur := s.defs[name]; s.gen != gen || cur == nil || cur.Binding() != def.Binding() {
		// Cleared, or a new login definition, while the server was asked:
		// what is there now is not this login's to forget.
		s.mu.Unlock()
		s.audit("disconnect", name, endpoint, "the entry changed meanwhile; nothing forgotten")
		return revoked, note, loginErr("the entry changed while the disconnect ran; nothing was forgotten, disconnect again")
	}
	if t := s.refreshTimers[name]; t != nil {
		t.Stop()
		delete(s.refreshTimers, name)
	}
	if raw != nil {
		s.values[name] = nil
		s.events.add(Event{Type: "entry_removed", Name: name})
	}
	s.syncRegistryLocked()
	s.mu.Unlock()
	if raw != nil && def.Writeback && s.env.Writeback != nil {
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		werr := s.writeBackOnce(wctx, name, def.Binding(), owner, loggedOut)
		cancel()
		if werr != nil {
			note = strings.TrimPrefix(note+"; the attestor still holds the login until the entry is removed", "; ")
		}
	}
	result := "revoked at the server"
	if !revoked {
		result = "forgotten; " + note
	}
	s.audit("disconnect", name, endpoint, result)
	return revoked, note, nil
}

// revoke asks endpoint to revoke the login's refresh token, then its access
// token (RFC 7009 §2.1); the answer to the first one decides. Only an
// endpoint on the token endpoint's host is asked, since the tokens and the
// client secret go there and nowhere else.
func (s *Store) revoke(ctx context.Context, endpoint string, def *Definition, st *mcpState) (bool, string) {
	if !sameHost(endpoint, st.TokenURL) {
		return false, "the revocation endpoint is not on the token endpoint's host: revoke the app's access at the service"
	}
	secret, fromEntry, _ := s.entrySecret(def, st.TokenURL)
	if !fromEntry {
		secret = st.ClientSecret
	}
	tokens := [][2]string{{st.RefreshToken, "refresh_token"}, {st.AccessToken, "access_token"}}
	confirmed, asked := false, false
	note := ""
	for _, t := range tokens {
		if t[0] == "" {
			continue
		}
		form := url.Values{"token": {t[0]}, "token_type_hint": {t[1]}, "client_id": {st.ClientID}}
		if secret != "" {
			form.Set("client_secret", secret)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return false, "the revocation endpoint is not valid"
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := s.httpClient().Do(req)
		ok := err == nil && resp.StatusCode/100 == 2
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxTokenResponse))
			resp.Body.Close()
		}
		if !asked {
			asked, confirmed = true, ok
			switch {
			case err != nil:
				note = "the revocation endpoint is unreachable: revoke the app's access at the service"
			case !ok:
				note = fmt.Sprintf("the revocation endpoint answered %d: revoke the app's access at the service", resp.StatusCode)
			}
		}
	}
	return confirmed, note
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
	// Some endpoints refuse with a 200 that carries an error.
	if code, _ := got["error"].(string); resp.StatusCode/100 != 2 || code != "" {
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
			if m := resourceMetadataParam(resp.Header.Get("WWW-Authenticate")); strings.HasPrefix(m, "https://") {
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
			// RFC 9728 §3.3: the metadata is about this server, so the
			// token is asked for this resource and no other.
			if !resourceCovers(prm.Resource, mcpURL) {
				return nil, loginErr("the server's resource metadata names another resource")
			}
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
			Issuer                        string   `json:"issuer"`
			AuthorizationEndpoint         string   `json:"authorization_endpoint"`
			TokenEndpoint                 string   `json:"token_endpoint"`
			RegistrationEndpoint          string   `json:"registration_endpoint"`
			RevocationEndpoint            string   `json:"revocation_endpoint"`
			IssParameterSupported         bool     `json:"authorization_response_iss_parameter_supported"`
			CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
			ScopesSupported               []string `json:"scopes_supported"`
		}
		if s.getJSON(ctx, m, &meta) != nil || meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" {
			continue
		}
		// RFC 8414 §3.3: metadata naming another issuer is not this one's.
		if meta.Issuer != "" && strings.TrimSuffix(meta.Issuer, "/") != issuer {
			continue
		}
		if len(meta.CodeChallengeMethodsSupported) > 0 && !contains(meta.CodeChallengeMethodsSupported, "S256") {
			return nil, loginErr("the authorization server does not support PKCE with S256")
		}
		for _, e := range []string{meta.AuthorizationEndpoint, meta.TokenEndpoint} {
			if !cleanHTTPS(e) {
				return nil, loginErr("the authorization server's endpoints must be plain https URLs")
			}
		}
		if meta.RegistrationEndpoint != "" && !cleanHTTPS(meta.RegistrationEndpoint) {
			meta.RegistrationEndpoint = ""
		}
		as.authorize, as.token, as.register = meta.AuthorizationEndpoint, meta.TokenEndpoint, meta.RegistrationEndpoint
		as.issuer, as.issParam = issuer, meta.IssParameterSupported
		// Revocation is asked only on the token endpoint's host, where the
		// tokens and a client secret already go.
		if cleanHTTPS(meta.RevocationEndpoint) && sameHost(meta.RevocationEndpoint, meta.TokenEndpoint) {
			as.revocation = meta.RevocationEndpoint
		}
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

// cleanHTTPS reports whether u is an https URL with a host, no userinfo,
// and no control or format characters: what sealed sends the owner to (the
// authorization link) or posts to.
func cleanHTTPS(u string) bool {
	p, err := url.Parse(u)
	return err == nil && p.Scheme == "https" && p.Hostname() != "" && p.User == nil && !hasControl(u) && !strings.ContainsAny(u, " ")
}

// resourceCovers reports whether resource identifies the MCP server at
// mcpURL: the same https origin, and its path the server's or a whole-
// segment prefix of it (the well-known paths name either).
func resourceCovers(resource, mcpURL string) bool {
	r, err1 := url.Parse(resource)
	m, err2 := url.Parse(mcpURL)
	if err1 != nil || err2 != nil || r.Scheme != "https" || r.RawQuery != "" || r.Fragment != "" ||
		credproxy.NormalizeHost(r.Host) != credproxy.NormalizeHost(m.Host) {
		return false
	}
	rp, mp := strings.TrimSuffix(r.EscapedPath(), "/"), strings.TrimSuffix(m.EscapedPath(), "/")
	return rp == "" || rp == mp || strings.HasPrefix(mp, rp+"/")
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
