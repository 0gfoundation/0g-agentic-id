package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func clearReq(t *testing.T, sign func(string) string, tag, instance string) *http.Request {
	t.Helper()
	body := "{}"
	sum := sha256.Sum256([]byte(body))
	msg := fmt.Sprintf("%s:0xdeadbeef:%d:%s:", tag, time.Now().Unix(), hex.EncodeToString(sum[:]))
	r := httptest.NewRequest(http.MethodPost, "/_seal/clear", strings.NewReader(body))
	r.Header.Set("X-Auth-Message", msg)
	r.Header.Set("X-Auth-Signature", sign(msg))
	if instance != "" {
		r.Header.Set(clientInstanceHeader, instance)
	}
	return r
}

func TestClear_WipesAndReportsTheRestart(t *testing.T) {
	s, sign := occupancyServer(t)
	cleared := 0
	s.SetClear(func(context.Context) error { cleared++; return nil })

	w := httptest.NewRecorder()
	s.handleClear(w, clearReq(t, sign, "0GSealClear", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("clear: HTTP %d: %s", w.Code, w.Body.String())
	}
	if cleared != 1 {
		t.Fatalf("applier ran %d times, want 1", cleared)
	}
	if !strings.Contains(w.Body.String(), "memory is untouched") {
		t.Fatalf("the response must say what /clear does NOT touch: %s", w.Body.String())
	}
}

// An adapter with no server-side conversation answers 501 — "nothing here to
// clear" is information for the client, not a hidden success.
func TestClear_NoStoreIs501(t *testing.T) {
	s, sign := occupancyServer(t)
	w := httptest.NewRecorder()
	s.handleClear(w, clearReq(t, sign, "0GSealClear", ""))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("HTTP %d, want 501", w.Code)
	}
}

// The tag is part of the signed grammar: a settings-push signature must not
// authorize a clear.
func TestClear_WrongTagRejected(t *testing.T) {
	s, sign := occupancyServer(t)
	s.SetClear(func(context.Context) error { t.Fatal("must not run"); return nil })
	w := httptest.NewRecorder()
	s.handleClear(w, clearReq(t, sign, "0GSealSettings", ""))
	// verifyOwnerSig refuses a foreign tag at the grammar stage (400), before
	// any signature check — either way, nothing runs.
	if w.Code != http.StatusBadRequest && w.Code != http.StatusUnauthorized {
		t.Fatalf("HTTP %d, want a refusal", w.Code)
	}
}

// A clear is a driving action: a displaced window cannot wipe the
// conversation out from under the seat holder.
func TestClear_SeatGated(t *testing.T) {
	s, sign := occupancyServer(t)
	s.SetClear(func(context.Context) error { t.Fatal("must not run"); return nil })
	w := httptest.NewRecorder()
	s.handleClaim(w, claimReq(t, sign, "window-B"))
	if w.Code != http.StatusOK {
		t.Fatalf("claim: %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleClear(w, clearReq(t, sign, "0GSealClear", "window-A"))
	if w.Code != http.StatusConflict {
		t.Fatalf("HTTP %d, want 409 (seat held by B)", w.Code)
	}
}
