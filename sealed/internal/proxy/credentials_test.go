package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"seal-verify/internal/credentials"
	"seal-verify/internal/state"
)

// fakeCredentials records what the owner routes hand the store.
type fakeCredentials struct {
	loaded        []credentials.Document
	loadErr       error
	decided       []string
	decideErr     error
	loginRedirect string
}

func (f *fakeCredentials) Load(_ context.Context, doc credentials.Document, _ uint64) (*credentials.Opened, error) {
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	f.loaded = append(f.loaded, doc)
	return &credentials.Opened{Set: doc.Set}, nil
}
func (f *fakeCredentials) Version() uint64 { return 7 }
func (f *fakeCredentials) List() []credentials.EntryInfo {
	return []credentials.EntryInfo{{Name: "github", Source: "owner"}}
}
func (f *fakeCredentials) PendingList() []credentials.Pending {
	return []credentials.Pending{{AuthReqID: "0xaa", Op: "reveal", Name: "github"}}
}
func (f *fakeCredentials) Decide(_ context.Context, id, decision string, _ *credentials.Approval, _ string) error {
	if f.decideErr != nil {
		return f.decideErr
	}
	f.decided = append(f.decided, id+":"+decision)
	return nil
}
func (f *fakeCredentials) AuditSince(int64) []credentials.AuditRecord { return nil }
func (f *fakeCredentials) StartLogin(_ context.Context, name, redirect string) (string, error) {
	f.loginRedirect = redirect
	return "https://auth.example/authorize?state=s1", nil
}
func (f *fakeCredentials) Disconnect(_ context.Context, name string) (bool, string, error) {
	if name != "linear" {
		return false, "", &credentials.LoginError{Reason: "no login entry named " + name}
	}
	return true, "", nil
}

func (f *fakeCredentials) FinishLogin(_ context.Context, state, code, _ string) (string, error) {
	if state != "s1" || code == "" {
		return "", &credentials.LoginError{Reason: "this login link is unknown or has expired; start the login again"}
	}
	return "linear", nil
}

const credAudience = "http://agent.example:8080"

func credServer(t *testing.T, owner string) (*Server, *fakeCredentials) {
	t.Helper()
	ag := state.New()
	ag.Set([]byte{1}, "http://127.0.0.1:1", "deadbeef", owner, "1", "0x00", "1", "0x00", "")
	s := &Server{agent: ag, publicURL: credAudience}
	f := &fakeCredentials{}
	s.SetCredentials(f)
	return s, f
}

// credReq signs a request in the owner grammar: digest (when there is a body)
// before the audience, which is always last.
func credReq(sign func(string) string, method, path, tag, body string) *http.Request {
	msg := fmt.Sprintf("%s:0xdeadbeef:%d:%s", tag, time.Now().Unix(), credAudience)
	if body != "" {
		msg = fmt.Sprintf("%s:0xdeadbeef:%d:%s:%s", tag, time.Now().Unix(), sha256hex(body), credAudience)
	}
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("X-Auth-Message", msg)
	r.Header.Set("X-Auth-Signature", sign(msg))
	return r
}

const credDoc = `{"set":{"seal_id":"0xdeadbeef","owner_epoch":0,"version":8,"entries":[]},"signature":"0x00","defs":{},"values":{}}`

func TestCredentialRoutes_OwnerSignedOnly(t *testing.T) {
	sign, owner := mustKey(t)
	s, f := credServer(t, owner)
	other, _ := mustKey(t)

	// Unsigned and wrongly signed requests are refused on every route.
	for _, h := range []http.HandlerFunc{s.handleCredentials, s.handleCredentialPending, s.handleCredentialAudit} {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodGet, "/_seal/credentials", nil))
		if w.Code == http.StatusOK {
			t.Fatal("an unsigned read succeeded")
		}
	}
	w := httptest.NewRecorder()
	s.handleCredentials(w, credReq(other, http.MethodPost, "/_seal/credentials", "0GSealCredentials", credDoc))
	if w.Code != http.StatusUnauthorized || len(f.loaded) != 0 {
		t.Fatalf("HTTP %d, %d loaded: a stranger's push must be refused", w.Code, len(f.loaded))
	}

	// The owner reads the list (names, never values).
	w = httptest.NewRecorder()
	s.handleCredentials(w, credReq(sign, http.MethodGet, "/_seal/credentials", "0GSealCredentials", ""))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"github"`) || !strings.Contains(w.Body.String(), `"version":7`) {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}

	// And pushes a set.
	w = httptest.NewRecorder()
	s.handleCredentials(w, credReq(sign, http.MethodPost, "/_seal/credentials", "0GSealCredentials", credDoc))
	if w.Code != http.StatusOK || len(f.loaded) != 1 || f.loaded[0].Set.Version != 8 {
		t.Fatalf("HTTP %d (%s), loaded %d", w.Code, w.Body.String(), len(f.loaded))
	}
}

// A signature made for another route (settings, or another credential
// route) does not open this one: the tag is part of what is signed.
func TestCredentialRoutes_TagSeparatesRoutes(t *testing.T) {
	sign, owner := mustKey(t)
	s, f := credServer(t, owner)
	for _, tag := range []string{"0GSealSettings", "0GSealCredDecide"} {
		w := httptest.NewRecorder()
		s.handleCredentials(w, credReq(sign, http.MethodPost, "/_seal/credentials", tag, credDoc))
		if w.Code == http.StatusOK || len(f.loaded) != 0 {
			t.Fatalf("tag %s opened the credentials route (HTTP %d)", tag, w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.handleCredentialPending(w, credReq(sign, http.MethodGet, "/_seal/credentials/pending", "0GSealCredAudit", ""))
	if w.Code == http.StatusOK {
		t.Fatal("an audit signature listed pending requests")
	}
}

// The signature covers the body: a swapped document is refused.
func TestCredentialRoutes_BodyBound(t *testing.T) {
	sign, owner := mustKey(t)
	s, f := credServer(t, owner)
	signed := credReq(sign, http.MethodPost, "/_seal/credentials", "0GSealCredentials", credDoc)
	swapped := httptest.NewRequest(http.MethodPost, "/_seal/credentials", strings.NewReader(strings.Replace(credDoc, `"version":8`, `"version":9`, 1)))
	swapped.Header = signed.Header
	w := httptest.NewRecorder()
	s.handleCredentials(w, swapped)
	if w.Code != http.StatusUnauthorized || len(f.loaded) != 0 {
		t.Fatalf("HTTP %d: a body other than the signed one must be refused", w.Code)
	}
}

func TestCredentialRoutes_StaleSetIsAConflict(t *testing.T) {
	sign, owner := mustKey(t)
	s, f := credServer(t, owner)
	f.loadErr = fmt.Errorf("wrap: %w", credentials.ErrStale)
	w := httptest.NewRecorder()
	s.handleCredentials(w, credReq(sign, http.MethodPost, "/_seal/credentials", "0GSealCredentials", credDoc))
	if w.Code != http.StatusConflict {
		t.Fatalf("HTTP %d, want 409", w.Code)
	}
	var body struct {
		Code    string `json:"code"`
		Version uint64 `json:"version"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Code != "stale_version" || body.Version != 7 {
		t.Fatalf("body %s", w.Body.String())
	}
}

func TestCredentialRoutes_Decide(t *testing.T) {
	sign, owner := mustKey(t)
	s, f := credServer(t, owner)
	body := `{"auth_req_id":"0xaa","decision":"deny"}`
	w := httptest.NewRecorder()
	s.handleCredentialDecide(w, credReq(sign, http.MethodPost, "/_seal/credentials/decide", "0GSealCredDecide", body))
	if w.Code != http.StatusOK || len(f.decided) != 1 || f.decided[0] != "0xaa:deny" {
		t.Fatalf("HTTP %d (%s), decided %v", w.Code, w.Body.String(), f.decided)
	}
	f.decideErr = credentials.ErrUnknownRequest
	w = httptest.NewRecorder()
	s.handleCredentialDecide(w, credReq(sign, http.MethodPost, "/_seal/credentials/decide", "0GSealCredDecide", body))
	if w.Code != http.StatusNotFound {
		t.Fatalf("HTTP %d, want 404 for a request that is not open", w.Code)
	}
}

func TestCredentialRoutes_NotReady(t *testing.T) {
	sign, owner := mustKey(t)
	ag := state.New()
	ag.Set([]byte{1}, "http://127.0.0.1:1", "deadbeef", owner, "1", "0x00", "1", "0x00", "")
	s := &Server{agent: ag, publicURL: credAudience}
	w := httptest.NewRecorder()
	s.handleCredentials(w, credReq(sign, http.MethodGet, "/_seal/credentials", "0GSealCredentials", ""))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("HTTP %d, want 503 before the store is installed", w.Code)
	}
}

// scrubValues replaces one value, as credproxy.Registry does.
type scrubValues struct{ value string }

func (v scrubValues) Scrub(b []byte) []byte {
	return []byte(strings.ReplaceAll(string(b), v.value, "[[credential:github]]"))
}
func (v scrubValues) ScrubReader(src io.Reader) io.Reader {
	b, _ := io.ReadAll(src)
	return strings.NewReader(string(v.Scrub(b)))
}

// A registered service that echoes a credential value: the caller gets the
// placeholder, in the body and in headers.
func TestProxy_ScrubsCredentialValuesFromAgentResponses(t *testing.T) {
	const value = "ghp_the_value_itself_0123456789"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Debug", "token="+value)
		_, _ = w.Write([]byte(`{"token":"` + value + `"}`))
	}))
	defer backend.Close()

	ag := state.New()
	ag.Set([]byte{1}, backend.URL, "deadbeef", "0x00", "1", "0x00", "1", "0x00", "")
	s := &Server{agent: ag}
	s.SetScrubber(scrubValues{value})
	s.services = []ServiceEntry{{Path: "/api/echo", Method: http.MethodGet, Backend: backend.URL}}

	w := httptest.NewRecorder()
	s.handleProxy(w, httptest.NewRequest(http.MethodGet, "/api/echo", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), value) || strings.Contains(w.Header().Get("X-Debug"), value) {
		t.Fatalf("the value left: body %s, header %q", w.Body.String(), w.Header().Get("X-Debug"))
	}
	if !strings.Contains(w.Body.String(), "[[credential:github]]") {
		t.Fatalf("body %s", w.Body.String())
	}
}

func TestCredentialLoginRoutes(t *testing.T) {
	sign, owner := mustKey(t)
	s, f := credServer(t, owner)
	body := `{"name":"linear"}`
	w := httptest.NewRecorder()
	s.handleCredentialLogin(w, credReq(sign, http.MethodPost, "/_seal/credentials/login", "0GSealCredLogin", body))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "auth.example/authorize") {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	if f.loginRedirect != credAudience+"/_seal/oauth/callback" {
		t.Fatalf("redirect %q", f.loginRedirect)
	}
	// Only the owner starts a login.
	other, _ := mustKey(t)
	w = httptest.NewRecorder()
	s.handleCredentialLogin(w, credReq(other, http.MethodPost, "/_seal/credentials/login", "0GSealCredLogin", body))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("HTTP %d for a stranger", w.Code)
	}
	// The callback needs the state sealed issued; what it echoes is escaped.
	w = httptest.NewRecorder()
	s.handleOAuthCallback(w, httptest.NewRequest(http.MethodGet, "/_seal/oauth/callback?state=s1&code=c", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "logged in for linear") {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handleOAuthCallback(w, httptest.NewRequest(http.MethodGet, "/_seal/oauth/callback?state=forged&code=%3Cscript%3E", nil))
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "<script>") {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
}
