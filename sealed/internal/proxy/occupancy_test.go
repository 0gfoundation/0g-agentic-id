package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"seal-verify/internal/state"
)

func claimReq(t *testing.T, sign func(string) string, instance string) *http.Request {
	t.Helper()
	body := fmt.Sprintf(`{"instance":%q}`, instance)
	sum := sha256.Sum256([]byte(body))
	msg := fmt.Sprintf("0GSealClaim:0xdeadbeef:%d:%s:", time.Now().Unix(), hex.EncodeToString(sum[:]))
	r := httptest.NewRequest(http.MethodPost, "/_seal/claim", strings.NewReader(body))
	r.Header.Set("X-Auth-Message", msg)
	r.Header.Set("X-Auth-Signature", sign(msg))
	return r
}

func occupancyServer(t *testing.T) (*Server, func(string) string) {
	t.Helper()
	sign, owner := mustKey(t)
	ag := state.New()
	ag.Set([]byte{1}, "http://127.0.0.1:1", "deadbeef", owner, "1", "0x00", "1", "0x00")
	return &Server{agent: ag}, sign
}

func chatPost(instance string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("{}"))
	if instance != "" {
		r.Header.Set(clientInstanceHeader, instance)
	}
	return r
}

// The WeChat rule: entering claims the seat unconditionally; the DISPLACED
// side learns when it next speaks, not the newcomer when it arrives.
func TestOccupancy_NewLoginWinsAndTheOldOneIsToldOnNextSpeak(t *testing.T) {
	s, sign := occupancyServer(t)

	// Window A claims and speaks.
	w := httptest.NewRecorder()
	s.handleClaim(w, claimReq(t, sign, "window-A"))
	if w.Code != http.StatusOK {
		t.Fatalf("claim A: HTTP %d: %s", w.Code, w.Body.String())
	}
	if !s.occupancyGate(httptest.NewRecorder(), chatPost("window-A")) {
		t.Fatal("the seat holder must pass")
	}

	// Window B claims — succeeds immediately, no negotiation.
	w = httptest.NewRecorder()
	s.handleClaim(w, claimReq(t, sign, "window-B"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"displaced":true`) {
		t.Fatalf("claim B must win and report it displaced someone: HTTP %d %s", w.Code, w.Body.String())
	}
	if !s.occupancyGate(httptest.NewRecorder(), chatPost("window-B")) {
		t.Fatal("the new holder must pass")
	}

	// A speaks again: 409, message says since when.
	rec := httptest.NewRecorder()
	if s.occupancyGate(rec, chatPost("window-A")) {
		t.Fatal("the displaced client must be stopped")
	}
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "displaced") {
		t.Fatalf("HTTP %d %s — want a legible 409", rec.Code, rec.Body.String())
	}
}

// Headerless callers — SDK scripts, older CLIs, third parties on agent
// services — must pass untouched: this is self-collision protection for
// windows that opt in, not an auth layer.
func TestOccupancy_HeaderlessCallersBypass(t *testing.T) {
	s, sign := occupancyServer(t)
	s.handleClaim(httptest.NewRecorder(), claimReq(t, sign, "window-A"))
	if !s.occupancyGate(httptest.NewRecorder(), chatPost("")) {
		t.Fatal("a headerless request must never be blocked")
	}
}

// With no claim on record (fresh container), the first speaker sits down —
// so a single window keeps working without ever calling /_seal/claim.
func TestOccupancy_FirstSpeakerSitsDown(t *testing.T) {
	s, _ := occupancyServer(t)
	if !s.occupancyGate(httptest.NewRecorder(), chatPost("window-A")) {
		t.Fatal("first speaker must pass")
	}
	rec := httptest.NewRecorder()
	if s.occupancyGate(rec, chatPost("window-B")) {
		t.Fatal("second window must be told the seat is taken")
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("HTTP %d, want 409", rec.Code)
	}
}

// The claim is an owner act: a stranger's signature cannot flip the seat.
func TestOccupancy_ClaimIsOwnerSigned(t *testing.T) {
	s, _ := occupancyServer(t)
	strangerSign, _ := mustKey(t)
	w := httptest.NewRecorder()
	s.handleClaim(w, claimReq(t, strangerSign, "intruder"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("HTTP %d, want 401", w.Code)
	}
}
