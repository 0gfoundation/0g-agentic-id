package proxy

import (
	"context"
	"encoding/hex"
	"errors"
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
	if _, ok := s.verifyOwnerSig(w, authReq(msg, sign(msg)), "0GSealLog", sealID, owner, ""); !ok {
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
	if _, ok := s.verifyOwnerSig(w, authReq(msg, sign(msg)), "0GSealLog", sealID, owner, ""); ok {
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
	if _, ok := s.verifyOwnerSig(w, authReq(msg, sign(msg)), "0GSealLog", sealID, owner, ""); ok {
		t.Fatal("expected reject on cross-tag replay, got ok")
	}
}

func TestVerifyOwnerSig_RejectsNonOwner(t *testing.T) {
	sign, _ := mustKey(t)  // signs
	_, owner := mustKey(t) // a DIFFERENT address is the "owner"
	s := &Server{publicURL: "https://8080-abc.example.com"}
	sealID := "deadbeef"
	msg := fmt.Sprintf("0GSealLog:0x%s:%d:%s", sealID, time.Now().Unix(), s.publicURL)

	w := httptest.NewRecorder()
	if _, ok := s.verifyOwnerSig(w, authReq(msg, sign(msg)), "0GSealLog", sealID, owner, ""); ok {
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
	if _, ok := s.verifyOwnerSig(w, authReq(msg, sign(msg)), "0GSealLog", sealID, owner, ""); ok {
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
	if _, ok := s.verifyOwnerSig(w, authReq(msg, sign(msg)), "0GSealLog", sealID, owner, ""); !ok {
		t.Fatalf("expected ok in dev, got HTTP %d: %s", w.Code, w.Body.String())
	}
}

// ── live owner resolution ────────────────────────────────────────────────────

// The lockout: when the bootstrap OwnerOf call failed, the cached owner stayed
// empty, every recovered address then compared unequal to "", and the real
// owner got 401 for the container's whole life. An empty owner must be a
// transient 503, never a verdict on who signed.
func TestVerifyOwnerSig_EmptyCachedOwnerIsTransientNotDenial(t *testing.T) {
	sign, _ := mustKey(t)
	s := &Server{}
	sealID := "deadbeef"
	msg := fmt.Sprintf("0GSealLog:0x%s:%d:", sealID, time.Now().Unix())

	w := httptest.NewRecorder()
	if _, ok := s.verifyOwnerSig(w, authReq(msg, sign(msg)), "0GSealLog", sealID, "", ""); ok {
		t.Fatal("expected failure with no owner known")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("HTTP %d — an unknown owner is retryable (503), not a denial (401)", w.Code)
	}
}

// A resolver error is likewise transient. This is the RPC blip that used to
// poison the whole container lifetime; now it poisons one request.
func TestVerifyOwnerSig_ResolverErrorIsTransient(t *testing.T) {
	sign, owner := mustKey(t)
	s := &Server{}
	s.SetLiveOwner(func(context.Context) (string, error) { return "", errors.New("rpc down") })
	sealID := "deadbeef"
	msg := fmt.Sprintf("0GSealLog:0x%s:%d:", sealID, time.Now().Unix())

	w := httptest.NewRecorder()
	if _, ok := s.verifyOwnerSig(w, authReq(msg, sign(msg)), "0GSealLog", sealID, owner, ""); ok {
		t.Fatal("expected failure while the chain is unreachable")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("HTTP %d, want 503", w.Code)
	}

	// And it recovers on the very next request, without a restart.
	s.SetLiveOwner(func(context.Context) (string, error) { return owner, nil })
	w = httptest.NewRecorder()
	if _, ok := s.verifyOwnerSig(w, authReq(msg, sign(msg)), "0GSealLog", sealID, owner, ""); !ok {
		t.Fatalf("expected recovery, got HTTP %d: %s", w.Code, w.Body.String())
	}
}

// After a transfer the chain says someone else owns this agent. The seller
// must stop being able to drive /_seal/* immediately, not whenever the
// container next restarts — attestor already gates on the live owner for
// exactly this reason.
func TestVerifyOwnerSig_TransferTakesEffectWithoutRestart(t *testing.T) {
	sellerSign, seller := mustKey(t)
	buyerSign, buyer := mustKey(t)
	sealID := "deadbeef"
	msg := fmt.Sprintf("0GSealLog:0x%s:%d:", sealID, time.Now().Unix())

	s := &Server{}
	// Bootstrap cached the seller; the chain now says the buyer.
	s.SetLiveOwner(func(context.Context) (string, error) { return buyer, nil })

	w := httptest.NewRecorder()
	if _, ok := s.verifyOwnerSig(w, authReq(msg, sellerSign(msg)), "0GSealLog", sealID, seller, ""); ok {
		t.Fatal("the previous owner must lose access the moment the chain says so")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("HTTP %d, want 401 — this one IS a denial", w.Code)
	}

	w = httptest.NewRecorder()
	if _, ok := s.verifyOwnerSig(w, authReq(msg, buyerSign(msg)), "0GSealLog", sealID, seller, ""); !ok {
		t.Fatalf("the new owner must be accepted against the stale cache, got HTTP %d: %s", w.Code, w.Body.String())
	}
}
