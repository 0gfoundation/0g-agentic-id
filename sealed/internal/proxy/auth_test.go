package proxy

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

// mustKey returns a throwaway keypair as (EIP-191 signer over a message, owner
// address) for building test auth headers.
func mustKey(t *testing.T) (msgSigner func(msg string) string, owner string) {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	owner = crypto.PubkeyToAddress(k.PublicKey).Hex()
	msgSigner = func(msg string) string {
		prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(msg))
		hash := crypto.Keccak256([]byte(prefix), []byte(msg))
		sig, err := crypto.Sign(hash, k)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return "0x" + hex.EncodeToString(sig)
	}
	return msgSigner, owner
}

func authReq(msg, sig string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/log/agent", nil)
	if msg != "" {
		r.Header.Set("X-Auth-Message", msg)
	}
	if sig != "" {
		r.Header.Set("X-Auth-Signature", sig)
	}
	return r
}

func TestVerifyOwnerSig_AcceptsOwnerBoundToAudience(t *testing.T) {
	sign, owner := mustKey(t)
	s := &Server{publicURL: "https://8080-abc.example.com"}
	sealID := "deadbeef"
	msg := fmt.Sprintf("0GSealLog:0x%s:%d:%s", sealID, time.Now().Unix(), s.publicURL)

	w := httptest.NewRecorder()
	if _, ok := s.verifyOwnerSig(w, authReq(msg, sign(msg)), "0GSealLog", sealID, owner); !ok {
		t.Fatalf("expected ok, got HTTP %d: %s", w.Code, w.Body.String())
	}
}

func TestVerifyOwnerSig_RejectsAudienceMismatch(t *testing.T) {
	sign, owner := mustKey(t)
	s := &Server{publicURL: "https://8080-real.example.com"}
	sealID := "deadbeef"
	// Owner signs for the ATTACKER's URL; a relay presents it to the real agent.
	attacker := "https://8080-attacker.evil.com"
	msg := fmt.Sprintf("0GSealLog:0x%s:%d:%s", sealID, time.Now().Unix(), attacker)

	w := httptest.NewRecorder()
	if _, ok := s.verifyOwnerSig(w, authReq(msg, sign(msg)), "0GSealLog", sealID, owner); ok {
		t.Fatal("expected reject on audience mismatch (issue #62), got ok")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestVerifyOwnerSig_RejectsCrossTagReplay(t *testing.T) {
	sign, owner := mustKey(t)
	s := &Server{publicURL: "https://8080-abc.example.com"}
	sealID := "deadbeef"
	// A signature produced for the auth-token exchange (0GSealAuth) must not be
	// replayable to the log endpoint (verified with tag 0GSealLog).
	msg := fmt.Sprintf("0GSealAuth:0x%s:%d:%s", sealID, time.Now().Unix(), s.publicURL)

	w := httptest.NewRecorder()
	if _, ok := s.verifyOwnerSig(w, authReq(msg, sign(msg)), "0GSealLog", sealID, owner); ok {
		t.Fatal("expected reject on cross-tag replay, got ok")
	}
}

func TestVerifyOwnerSig_RejectsNonOwner(t *testing.T) {
	sign, _ := mustKey(t)   // signs
	_, owner := mustKey(t)  // a DIFFERENT address is the "owner"
	s := &Server{publicURL: "https://8080-abc.example.com"}
	sealID := "deadbeef"
	msg := fmt.Sprintf("0GSealLog:0x%s:%d:%s", sealID, time.Now().Unix(), s.publicURL)

	w := httptest.NewRecorder()
	if _, ok := s.verifyOwnerSig(w, authReq(msg, sign(msg)), "0GSealLog", sealID, owner); ok {
		t.Fatal("expected reject when signer != owner, got ok")
	}
}

func TestVerifyOwnerSig_RejectsStaleTimestamp(t *testing.T) {
	sign, owner := mustKey(t)
	s := &Server{publicURL: "https://8080-abc.example.com"}
	sealID := "deadbeef"
	stale := time.Now().Unix() - authWindowSec - 60
	msg := fmt.Sprintf("0GSealLog:0x%s:%d:%s", sealID, stale, s.publicURL)

	w := httptest.NewRecorder()
	if _, ok := s.verifyOwnerSig(w, authReq(msg, sign(msg)), "0GSealLog", sealID, owner); ok {
		t.Fatal("expected reject on stale timestamp, got ok")
	}
}

func TestVerifyOwnerSig_DevSkipsAudienceWhenNoPublicURL(t *testing.T) {
	sign, owner := mustKey(t)
	s := &Server{publicURL: ""} // dev: no external URL to phish
	sealID := "deadbeef"
	// Any audience is accepted when the runtime has no canonical URL of its own.
	msg := fmt.Sprintf("0GSealLog:0x%s:%d:%s", sealID, time.Now().Unix(), "http://localhost:9999")

	w := httptest.NewRecorder()
	if _, ok := s.verifyOwnerSig(w, authReq(msg, sign(msg)), "0GSealLog", sealID, owner); !ok {
		t.Fatalf("expected ok in dev, got HTTP %d: %s", w.Code, w.Body.String())
	}
}
