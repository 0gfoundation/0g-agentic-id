package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"seal-verify/internal/settings"
	"seal-verify/internal/state"
)

// sessionServer is a ready agent owned by a fresh key, with a framework
// adapter (so /_seal/auth answers), an agent log file and a clear applier.
// owner is a pointer the live-owner resolver reads, so a test can transfer
// the agent mid-way.
func sessionServer(t *testing.T) (s *Server, sign func(string) string, owner *string) {
	t.Helper()
	sign, o := mustKey(t)
	owner = &o
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ag := state.New()
	ag.Set(crypto.FromECDSA(k), "http://127.0.0.1:1", "deadbeef", o, "1", "0x00", "1", "0x00")
	logPath := filepath.Join(t.TempDir(), "agent.log")
	if err := os.WriteFile(logPath, []byte("agent says hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s = &Server{agent: ag, adapter: &synthFakeAdapter{token: "fw"}, agentLogPath: logPath}
	s.SetLiveOwner(func(context.Context) (string, error) { return *owner, nil })
	s.SetClear(func(context.Context) error { return nil })
	return s, sign, owner
}

// signIn runs the one owner signature the session exists to make the only one.
func signIn(t *testing.T, s *Server, sign func(string) string) (token string, exp int64) {
	t.Helper()
	msg := fmt.Sprintf("0GSealAuth:0xdeadbeef:%d:", time.Now().Unix())
	r := httptest.NewRequest(http.MethodPost, "/_seal/auth", nil)
	r.Header.Set("X-Auth-Message", msg)
	r.Header.Set("X-Auth-Signature", sign(msg))
	w := httptest.NewRecorder()
	s.handleAuth(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("/_seal/auth: HTTP %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Token   string `json:"token"`
		Session string `json:"seal_session"`
		Exp     int64  `json:"seal_session_exp"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Token != "fw" {
		t.Fatalf("framework payload lost: token=%q", body.Token)
	}
	if body.Session == "" {
		t.Fatalf("no seal_session in %s", w.Body.String())
	}
	return body.Session, body.Exp
}

func withSession(r *http.Request, tok string) *http.Request {
	r.Header.Set(SessionHeader, tok)
	return r
}

func logWith(s *Server, tok string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.handleAgentLog(w, withSession(httptest.NewRequest(http.MethodGet, "/log/agent", nil), tok))
	return w
}

// The point of the change: after one signature, log reads and a clear need
// no further wallet prompt.
func TestSession_OneSignatureCoversLogAndClear(t *testing.T) {
	s, sign, _ := sessionServer(t)
	tok, exp := signIn(t, s, sign)
	if d := exp - time.Now().Unix(); d < sessionTTLSec-5 || d > sessionTTLSec {
		t.Fatalf("session lives %ds, want ~%ds", d, sessionTTLSec)
	}

	if w := logWith(s, tok); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "agent says hi") {
		t.Fatalf("/log/agent with session: HTTP %d: %s", w.Code, w.Body.String())
	}
	w := httptest.NewRecorder()
	s.handleAgentLogHTML(w, withSession(httptest.NewRequest(http.MethodGet, "/log/agent.html", nil), tok))
	if w.Code != http.StatusOK {
		t.Fatalf("/log/agent.html with session: HTTP %d: %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handleClear(w, withSession(httptest.NewRequest(http.MethodPost, "/_seal/clear", strings.NewReader("{}")), tok))
	if w.Code != http.StatusOK {
		t.Fatalf("/_seal/clear with session: HTTP %d: %s", w.Code, w.Body.String())
	}
}

// A sold agent must stop answering its previous owner's session at once —
// the same guarantee the live owner lookup gives signatures.
func TestSession_DiesOnTransfer(t *testing.T) {
	s, sign, owner := sessionServer(t)
	tok, _ := signIn(t, s, sign)
	_, buyer := mustKey(t)
	*owner = buyer
	if w := logWith(s, tok); w.Code != http.StatusUnauthorized {
		t.Fatalf("seller's session after transfer: HTTP %d, want 401", w.Code)
	}
}

// The key is per process: a restarted container (a new Server) must not
// honour a session it never issued.
func TestSession_RestartInvalidates(t *testing.T) {
	s, sign, owner := sessionServer(t)
	tok, _ := signIn(t, s, sign)
	restarted := &Server{agent: s.agent, adapter: s.adapter, agentLogPath: s.agentLogPath}
	restarted.SetLiveOwner(func(context.Context) (string, error) { return *owner, nil })
	if w := logWith(restarted, tok); w.Code != http.StatusUnauthorized {
		t.Fatalf("session on a restarted server: HTTP %d, want 401", w.Code)
	}
}

func TestSession_ExpiredRejected(t *testing.T) {
	s, _, owner := sessionServer(t)
	tok, _ := s.mintSession("deadbeef", *owner, time.Now().Unix()-sessionTTLSec-1)
	if w := logWith(s, tok); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "expired") {
		t.Fatalf("expired session: HTTP %d: %s", w.Code, w.Body.String())
	}
}

// Every field is under the MAC: changing the owner (to impersonate the
// current one) or stretching the expiry breaks it.
func TestSession_TamperRejected(t *testing.T) {
	s, sign, owner := sessionServer(t)
	tok, _ := signIn(t, s, sign)
	parts := strings.Split(tok, ".")

	_, other := mustKey(t)
	*owner = other
	forged := strings.Join([]string{parts[0], strings.ToLower(other), parts[2]}, ".")
	if w := logWith(s, forged); w.Code != http.StatusUnauthorized {
		t.Fatalf("owner-swapped session: HTTP %d, want 401", w.Code)
	}

	stretched := strings.Join([]string{fmt.Sprint(time.Now().Unix() + 10*sessionTTLSec), parts[1], parts[2]}, ".")
	if w := logWith(s, stretched); w.Code != http.StatusUnauthorized {
		t.Fatalf("expiry-stretched session: HTTP %d, want 401", w.Code)
	}
	for _, junk := range []string{"x", "a.b", "1.2.3.4", "1.0xabc.zz"} {
		if w := logWith(s, junk); w.Code != http.StatusUnauthorized {
			t.Fatalf("malformed session %q: HTTP %d, want 401", junk, w.Code)
		}
	}
}

// Settings bind the body digest into the signature; a session cannot, so
// settings must not accept one.
func TestSession_NotAcceptedForSettings(t *testing.T) {
	s, sign, _ := sessionServer(t)
	tok, _ := signIn(t, s, sign)
	s.SetSettings(func() settings.Doc { return settings.Doc{} }, nil)
	w := httptest.NewRecorder()
	s.handleSettings(w, withSession(httptest.NewRequest(http.MethodGet, "/_seal/settings", nil), tok))
	if w.Code == http.StatusOK {
		t.Fatalf("settings read with only a session: HTTP 200, want refusal")
	}
}

// The signature path is unchanged for clients that never adopt sessions.
func TestSession_SignatureStillWorks(t *testing.T) {
	s, sign, _ := sessionServer(t)
	msg := fmt.Sprintf("0GSealLog:0xdeadbeef:%d:", time.Now().Unix())
	w := httptest.NewRecorder()
	s.handleAgentLog(w, authReq(msg, sign(msg)))
	if w.Code != http.StatusOK {
		t.Fatalf("signed /log/agent: HTTP %d: %s", w.Code, w.Body.String())
	}
}
