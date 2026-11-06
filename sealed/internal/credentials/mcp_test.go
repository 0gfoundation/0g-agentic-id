package credentials

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"seal-verify/internal/credproxy"
)

// fakeAuth is an MCP server with its own authorization server: 401 with
// resource_metadata, RFC 9728 and 8414 metadata, dynamic registration, and
// a token endpoint that checks PKCE and rotates refresh tokens.
type fakeAuth struct {
	ts         *httptest.Server
	mu         sync.Mutex
	challenge  string
	refresh    string
	issued     int
	revoked    bool
	registered []string
	// RFC 7009: offered unless noRevocation; what was revoked, in order.
	noRevocation bool
	revokedSeen  []string
}

func newFakeAuth(t *testing.T) *fakeAuth {
	f := &fakeAuth{}
	mux := http.NewServeMux()
	f.ts = httptest.NewTLSServer(mux)
	t.Cleanup(f.ts.Close)
	base := f.ts.URL
	json200 := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+base+`/.well-known/oauth-protected-resource/mcp"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		json200(w, map[string]any{"resource": base + "/mcp", "authorization_servers": []string{base + "/auth"}, "scopes_supported": []string{"read"}})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server/auth", func(w http.ResponseWriter, r *http.Request) {
		meta := map[string]any{"authorization_endpoint": base + "/auth/authorize", "token_endpoint": base + "/auth/token",
			"registration_endpoint": base + "/auth/register", "code_challenge_methods_supported": []string{"S256"}}
		f.mu.Lock()
		if !f.noRevocation {
			meta["revocation_endpoint"] = base + "/auth/revoke"
		}
		f.mu.Unlock()
		json200(w, meta)
	})
	mux.HandleFunc("/auth/revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.PostForm.Get("client_id") != "client-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.revokedSeen = append(f.revokedSeen, r.PostForm.Get("token_type_hint")+":"+r.PostForm.Get("token"))
		if r.PostForm.Get("token") == f.refresh {
			f.revoked = true
		}
	})
	mux.HandleFunc("/auth/register", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			RedirectURIs []string `json:"redirect_uris"`
			AuthMethod   string   `json:"token_endpoint_auth_method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.registered = append(f.registered, in.RedirectURIs...)
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		json200(w, map[string]any{"client_id": "client-1"})
	})
	mux.HandleFunc("/auth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		fail := func() { w.WriteHeader(http.StatusBadRequest); json200(w, map[string]string{"error": "invalid_grant"}) }
		if r.PostForm.Get("client_id") != "client-1" || r.PostForm.Get("resource") != base+"/mcp" {
			fail()
			return
		}
		switch r.PostForm.Get("grant_type") {
		case "authorization_code":
			sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if r.PostForm.Get("code") != "the-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
				fail()
				return
			}
		case "refresh_token":
			if f.revoked || r.PostForm.Get("refresh_token") != f.refresh {
				fail()
				return
			}
		default:
			fail()
			return
		}
		f.issued++
		f.refresh = "rt-" + string(rune('0'+f.issued))
		json200(w, map[string]any{"access_token": "at-" + string(rune('0'+f.issued)), "refresh_token": f.refresh, "expires_in": 3600})
	})
	return f
}

func TestMCPLoginRefreshAndRevoke(t *testing.T) {
	auth := newFakeAuth(t)
	f := newFixture(t)
	var mu sync.Mutex
	var wrote []string
	s, reg, _ := f.store(t, func(_ context.Context, name string, w Writeback) error {
		mu.Lock()
		wrote = append(wrote, name)
		mu.Unlock()
		return nil
	}, auth.ts.Client())
	host := strings.TrimPrefix(auth.ts.URL, "https://")
	doc := f.doc(t, 1, map[string]string{"linear": "unused"})
	f.editDefs(t, &doc, func(d *Definition) {
		d.MCP = &MCPSpec{URL: auth.ts.URL + "/mcp"}
		d.ValueHash, d.Writeback, d.Hosts, d.AllowReveal = "", true, []string{host}, true
	})
	delete(doc.Values, "linear")
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	if reg.Get("linear") != nil {
		t.Fatal("a login entry was served before the login")
	}
	if e := listed(s, "linear"); e == nil || e.Status != "awaiting_login" || e.LoggedInAt != 0 {
		t.Fatalf("before the login the entry is listed as awaiting it: %+v", e)
	}
	// The agent asked for this login; the owner adding the entry does not answer it.
	s.mu.Lock()
	req, _ := s.pendingForLocked("login", "linear", map[string]string{"url": auth.ts.URL + "/mcp"}, "", "", nil)
	s.mu.Unlock()
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	if status(s, req.AuthReqID) != "pending" {
		t.Fatal("a login request was answered before the login")
	}
	if added(s, "linear") {
		t.Fatal("entry_added before the login")
	}

	const redirect = "https://8080-sandbox.preview.example/_seal/oauth/callback"
	link, err := s.StartLogin(context.Background(), "linear", redirect)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(link)
	q := u.Query()
	if u.Path != "/auth/authorize" || q.Get("client_id") != "client-1" || q.Get("redirect_uri") != redirect ||
		q.Get("code_challenge_method") != "S256" || q.Get("resource") != auth.ts.URL+"/mcp" || q.Get("scope") != "read" {
		t.Fatalf("authorize link %s", link)
	}
	if len(auth.registered) != 1 || auth.registered[0] != redirect {
		t.Fatalf("registered %v", auth.registered)
	}
	auth.mu.Lock()
	auth.challenge = q.Get("code_challenge")
	auth.mu.Unlock()

	// A forged state does nothing; the real one logs in, once.
	if _, err := s.FinishLogin(context.Background(), "forged", "the-code", ""); err == nil {
		t.Fatal("a forged state was accepted")
	}
	if name, err := s.FinishLogin(context.Background(), q.Get("state"), "the-code", ""); err != nil || name != "linear" {
		t.Fatalf("finish: %v", err)
	}
	if _, err := s.FinishLogin(context.Background(), q.Get("state"), "the-code", ""); err == nil {
		t.Fatal("a state was used twice")
	}
	e := reg.Get("linear")
	if e == nil || string(e.Value) != "at-1" || e.ExpiresAt.IsZero() {
		t.Fatalf("entry after login: %+v", e)
	}
	e2 := listed(s, "linear")
	first := e2.LoggedInAt
	if e2.Status != "" || first <= 0 || !added(s, "linear") || status(s, req.AuthReqID) != "approved" {
		t.Fatalf("after login: listed at %d, entry_added %v, request %s", first, added(s, "linear"), status(s, req.AuthReqID))
	}
	// Revealing a login entry gives its access token, never the stored
	// login state with the refresh token in it.
	if v, cerr := s.Reveal(context.Background(), "linear", ""); cerr != nil || string(v) != "at-1" {
		t.Fatalf("reveal gave %q (%v), not the access token", v, cerr)
	}
	mu.Lock()
	if len(wrote) != 1 || wrote[0] != "linear" {
		t.Fatalf("writebacks %v", wrote)
	}
	mu.Unlock()

	// Refresh rotates both tokens; the proxy fills the new access token.
	s.refreshLogin("linear", "at-1", 0)
	if e := reg.Get("linear"); string(e.Value) != "at-2" {
		t.Fatalf("after refresh: %q", e.Value)
	}
	// A revoked refresh token ends the login and asks the owner to log in again.
	auth.mu.Lock()
	auth.revoked = true
	auth.mu.Unlock()
	s.refreshLogin("linear", "at-2", 6)
	var found bool
	for _, p := range s.PendingList() {
		if p.Op == "login" && p.Name == "linear" {
			found = true
		}
	}
	if !found {
		t.Fatal("a revoked login did not ask the owner")
	}
	if listed(s, "linear").LoggedInAt != first {
		t.Fatal("a refresh changed when the login was done")
	}
}

// listed is what List says of an entry; nil if it is not listed.
func listed(s *Store, name string) *EntryInfo {
	for _, e := range s.List() {
		if e.Name == name {
			return &e
		}
	}
	return nil
}

func added(s *Store, name string) bool {
	evs, _ := s.events.since(0)
	for _, e := range evs {
		if e.Type == "entry_added" && e.Name == name {
			return true
		}
	}
	return false
}

func status(s *Store, id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.pending[id]; p != nil {
		return p.Status
	}
	return ""
}

// loginLinear runs the owner's login to auth for an entry named linear.
func loginLinear(t *testing.T, f *fixture, auth *fakeAuth) (*Store, *credproxy.Registry) {
	t.Helper()
	s, reg, _ := f.store(t, nil, auth.ts.Client())
	doc := f.doc(t, 1, map[string]string{"linear": "unused"})
	f.editDefs(t, &doc, func(d *Definition) {
		d.MCP = &MCPSpec{URL: auth.ts.URL + "/mcp"}
		d.ValueHash, d.Writeback, d.Hosts = "", true, []string{strings.TrimPrefix(auth.ts.URL, "https://")}
	})
	delete(doc.Values, "linear")
	if _, err := s.Load(context.Background(), doc, 0); err != nil {
		t.Fatal(err)
	}
	link, err := s.StartLogin(context.Background(), "linear", "https://8080-sandbox.preview.example/_seal/oauth/callback")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(link)
	auth.mu.Lock()
	auth.challenge = u.Query().Get("code_challenge")
	auth.mu.Unlock()
	if _, err := s.FinishLogin(context.Background(), u.Query().Get("state"), "the-code", ""); err != nil {
		t.Fatal(err)
	}
	return s, reg
}

// Disconnect revokes at the server (refresh token first), and sealed
// forgets the login: the entry waits for a new one and fills nothing.
func TestMCPDisconnectRevokesAndForgets(t *testing.T) {
	auth := newFakeAuth(t)
	s, reg := loginLinear(t, newFixture(t), auth)
	revoked, note, err := s.Disconnect(context.Background(), "linear")
	if err != nil || !revoked || note != "" {
		t.Fatalf("disconnect: revoked=%v note=%q err=%v", revoked, note, err)
	}
	auth.mu.Lock()
	seen := auth.revokedSeen
	auth.mu.Unlock()
	if len(seen) != 2 || seen[0] != "refresh_token:rt-1" || seen[1] != "access_token:at-1" {
		t.Fatalf("revoked at the server: %v", seen)
	}
	if reg.Get("linear") != nil {
		t.Fatal("the proxy still fills the login")
	}
	if e := listed(s, "linear"); e == nil || e.Status != "awaiting_login" {
		t.Fatalf("after disconnect: %+v", e)
	}
	recs := s.AuditSince(0)
	if last := recs[len(recs)-1]; last.Op != "disconnect" || last.Result != "revoked at the server" {
		t.Fatalf("audit: %+v", last)
	}
	if _, _, err := s.Disconnect(context.Background(), "nope"); err == nil {
		t.Fatal("disconnect of an unknown entry succeeded")
	}
}

// A server with no revocation endpoint: sealed still forgets the login and
// says the owner must revoke at the service.
func TestMCPDisconnectWithoutRevocation(t *testing.T) {
	auth := newFakeAuth(t)
	auth.noRevocation = true
	s, reg := loginLinear(t, newFixture(t), auth)
	revoked, note, err := s.Disconnect(context.Background(), "linear")
	if err != nil || revoked || !strings.Contains(note, "revoke the app's access at the service") {
		t.Fatalf("disconnect: revoked=%v note=%q err=%v", revoked, note, err)
	}
	if reg.Get("linear") != nil || len(auth.revokedSeen) != 0 {
		t.Fatal("not forgotten, or something was sent to revoke")
	}
}
