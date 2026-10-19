package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/framework"
)

// compactReq signs a compact request. skew shifts the signed timestamp so two
// requests made in the same second are still distinct signed messages.
func compactReq(t *testing.T, sign func(string) string, tag, instance string, skew int64) *http.Request {
	t.Helper()
	body := "{}"
	sum := sha256.Sum256([]byte(body))
	msg := fmt.Sprintf("%s:0xdeadbeef:%d:%s:", tag, time.Now().Unix()-skew, hex.EncodeToString(sum[:]))
	r := httptest.NewRequest(http.MethodPost, "/_seal/compact", strings.NewReader(body))
	r.Header.Set("X-Auth-Message", msg)
	r.Header.Set("X-Auth-Signature", sign(msg))
	if instance != "" {
		r.Header.Set(clientInstanceHeader, instance)
	}
	return r
}

func TestCompact_RunsAndReturnsTheNote(t *testing.T) {
	s, sign := occupancyServer(t)
	runs := 0
	s.SetCompact(func(context.Context) (string, error) { runs++; return "compacted 12 messages", nil })

	w := httptest.NewRecorder()
	s.handleCompact(w, compactReq(t, sign, "0GSealCompact", "", 0))
	if w.Code != http.StatusOK {
		t.Fatalf("compact: HTTP %d: %s", w.Code, w.Body.String())
	}
	if runs != 1 {
		t.Fatalf("applier ran %d times, want 1", runs)
	}
	if !strings.Contains(w.Body.String(), "compacted 12 messages") {
		t.Fatalf("the response must carry the adapter's note: %s", w.Body.String())
	}
}

// An adapter that cannot compact on demand answers 501 — information for the
// client, not a hidden success.
func TestCompact_UnsupportedIs501(t *testing.T) {
	s, sign := occupancyServer(t)
	w := httptest.NewRecorder()
	s.handleCompact(w, compactReq(t, sign, "0GSealCompact", "", 0))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("HTTP %d, want 501", w.Code)
	}
}

// The tag is part of the signed grammar: a clear signature must not authorize
// a compaction (nor the reverse — TestClear_WrongTagRejected).
func TestCompact_WrongTagRejected(t *testing.T) {
	s, sign := occupancyServer(t)
	s.SetCompact(func(context.Context) (string, error) { t.Fatal("must not run"); return "", nil })
	w := httptest.NewRecorder()
	s.handleCompact(w, compactReq(t, sign, "0GSealClear", "", 0))
	if w.Code != http.StatusBadRequest && w.Code != http.StatusUnauthorized {
		t.Fatalf("HTTP %d, want a refusal", w.Code)
	}
}

// A compaction is a driving action: a displaced window cannot compact the
// conversation out from under the seat holder.
func TestCompact_SeatGated(t *testing.T) {
	s, sign := occupancyServer(t)
	s.SetCompact(func(context.Context) (string, error) { t.Fatal("must not run"); return "", nil })
	w := httptest.NewRecorder()
	s.handleClaim(w, claimReq(t, sign, "window-B"))
	if w.Code != http.StatusOK {
		t.Fatalf("claim: %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleCompact(w, compactReq(t, sign, "0GSealCompact", "window-A", 0))
	if w.Code != http.StatusConflict {
		t.Fatalf("HTTP %d, want 409 (seat held by B)", w.Code)
	}
}

// Unlike a clear, a compaction is not idempotent, so a captured signed
// request must not buy a second one inside the freshness window.
func TestCompact_ReplayRefused(t *testing.T) {
	s, sign := occupancyServer(t)
	runs := 0
	s.SetCompact(func(context.Context) (string, error) { runs++; return "ok", nil })

	first := compactReq(t, sign, "0GSealCompact", "", 0)
	replay := httptest.NewRequest(http.MethodPost, "/_seal/compact", strings.NewReader("{}"))
	replay.Header = first.Header.Clone()

	w := httptest.NewRecorder()
	s.handleCompact(w, first)
	if w.Code != http.StatusOK {
		t.Fatalf("first: HTTP %d: %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handleCompact(w, replay)
	if w.Code != http.StatusConflict {
		t.Fatalf("replay: HTTP %d, want 409", w.Code)
	}
	if runs != 1 {
		t.Fatalf("applier ran %d times, want 1", runs)
	}

	// The verifier accepts one signature in several spellings, so each must
	// still count as the same request.
	sig := first.Header.Get("X-Auth-Signature")
	raw, err := hex.DecodeString(strings.TrimPrefix(sig, "0x"))
	if err != nil || len(raw) != 65 {
		t.Fatalf("test signer produced %q", sig)
	}
	vPlus27 := append([]byte(nil), raw...)
	vPlus27[64] += 27
	for name, spelling := range map[string]string{
		"no 0x prefix":  strings.TrimPrefix(sig, "0x"),
		"uppercase hex": "0x" + strings.ToUpper(strings.TrimPrefix(sig, "0x")),
		"v as 27/28":    "0x" + hex.EncodeToString(vPlus27),
	} {
		respelled := httptest.NewRequest(http.MethodPost, "/_seal/compact", strings.NewReader("{}"))
		respelled.Header = first.Header.Clone()
		respelled.Header.Set("X-Auth-Signature", spelling)
		w = httptest.NewRecorder()
		s.handleCompact(w, respelled)
		if w.Code != http.StatusConflict {
			t.Fatalf("replay re-spelled (%s): HTTP %d, want 409: %s", name, w.Code, w.Body.String())
		}
	}
	// ECDSA malleability: (r, N-s, v^1) is a second valid signature over the
	// same message that anyone can derive without the key — go-ethereum's
	// SigToPub does not enforce low s, so it recovers the owner from it.
	malleated := append([]byte(nil), raw...)
	highS := new(big.Int).Sub(crypto.S256().Params().N, new(big.Int).SetBytes(raw[32:64]))
	highS.FillBytes(malleated[32:64])
	malleated[64] ^= 1
	mreq := httptest.NewRequest(http.MethodPost, "/_seal/compact", strings.NewReader("{}"))
	mreq.Header = first.Header.Clone()
	mreq.Header.Set("X-Auth-Signature", "0x"+hex.EncodeToString(malleated))
	w = httptest.NewRecorder()
	s.handleCompact(w, mreq)
	if w.Code != http.StatusConflict {
		t.Fatalf("replay with a malleated signature: HTTP %d, want 409: %s", w.Code, w.Body.String())
	}
	if runs != 1 {
		t.Fatalf("applier ran %d times after re-spelled replays, want 1", runs)
	}

	// A freshly signed request still goes through.
	w = httptest.NewRecorder()
	s.handleCompact(w, compactReq(t, sign, "0GSealCompact", "", 1))
	if w.Code != http.StatusOK || runs != 2 {
		t.Fatalf("fresh request after a replay: HTTP %d, runs %d", w.Code, runs)
	}
}

// One compaction at a time: a second request while one runs is refused, not
// queued behind it.
func TestCompact_SingleFlight(t *testing.T) {
	s, sign := occupancyServer(t)
	started, release := make(chan struct{}), make(chan struct{})
	s.SetCompact(func(context.Context) (string, error) {
		close(started)
		<-release
		return "ok", nil
	})

	done := make(chan int)
	go func() {
		w := httptest.NewRecorder()
		s.handleCompact(w, compactReq(t, sign, "0GSealCompact", "", 0))
		done <- w.Code
	}()
	<-started

	w := httptest.NewRecorder()
	s.handleCompact(w, compactReq(t, sign, "0GSealCompact", "", 1))
	if w.Code != http.StatusConflict {
		t.Fatalf("concurrent compact: HTTP %d, want 409", w.Code)
	}
	close(release)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("first compact: HTTP %d", code)
	}
}

// A dropped connection must not abort a compaction mid-summary: the applier's
// context is detached from the request's cancellation.
func TestCompact_DetachedFromClientCancellation(t *testing.T) {
	s, sign := occupancyServer(t)
	var applierErr error
	s.SetCompact(func(ctx context.Context) (string, error) {
		applierErr = ctx.Err()
		return "ok", nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := httptest.NewRecorder()
	s.handleCompact(w, compactReq(t, sign, "0GSealCompact", "", 0).WithContext(ctx))
	if applierErr != nil {
		t.Fatalf("applier saw the client's cancellation: %v", applierErr)
	}
}

// A failed compaction reports 500 and releases the single-flight slot.
func TestCompact_FailureIs500AndReleases(t *testing.T) {
	s, sign := occupancyServer(t)
	fail := true
	s.SetCompact(func(context.Context) (string, error) {
		if fail {
			return "", errors.New("summary call failed")
		}
		return "ok", nil
	})
	w := httptest.NewRecorder()
	s.handleCompact(w, compactReq(t, sign, "0GSealCompact", "", 0))
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "summary call failed") {
		t.Fatalf("HTTP %d %q, want 500 carrying the cause", w.Code, w.Body.String())
	}
	fail = false
	w = httptest.NewRecorder()
	s.handleCompact(w, compactReq(t, sign, "0GSealCompact", "", 1))
	if w.Code != http.StatusOK {
		t.Fatalf("after a failure: HTTP %d, want the slot released", w.Code)
	}
}

// openclaw's compaction aborts a running turn, so compacting is refused while
// a turn on the synthesized door is queued or running — and allowed after.
func TestCompact_RefusedDuringALiveTurn(t *testing.T) {
	s, sign := occupancyServer(t)
	s.synth = newSynthHub()
	runs := 0
	s.SetCompact(func(context.Context) (string, error) { runs++; return "ok", nil })

	rec := s.synth.create() // a turn just accepted: "queued"
	for i, status := range []string{"queued", "in_progress"} {
		rec.mu.Lock()
		rec.status = status
		rec.mu.Unlock()
		w := httptest.NewRecorder()
		s.handleCompact(w, compactReq(t, sign, "0GSealCompact", "", int64(i)))
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "turn is in progress") {
			t.Fatalf("during a %s turn: HTTP %d %q, want 409", status, w.Code, w.Body.String())
		}
	}

	rec.mu.Lock()
	rec.status = "completed"
	rec.mu.Unlock()
	w := httptest.NewRecorder()
	s.handleCompact(w, compactReq(t, sign, "0GSealCompact", "", 2))
	if w.Code != http.StatusOK || runs != 1 {
		t.Fatalf("after the turn: HTTP %d, runs %d", w.Code, runs)
	}
}

// The other direction: a turn sent to the synthesized door while a compaction
// runs is refused, not admitted into a session the compaction would abort —
// and is admitted again once the compaction is done.
func TestCompact_TurnRefusedWhileCompacting(t *testing.T) {
	s, sign := occupancyServer(t)
	s.synth = newSynthHub()
	started, release := make(chan struct{}), make(chan struct{})
	s.SetCompact(func(context.Context) (string, error) {
		close(started)
		<-release
		return "ok", nil
	})
	done := make(chan int)
	go func() {
		w := httptest.NewRecorder()
		s.handleCompact(w, compactReq(t, sign, "0GSealCompact", "", 0))
		done <- w.Code
	}()
	<-started

	w := httptest.NewRecorder()
	turn := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"input":"hello"}`))
	s.handleSynthCreate(w, turn, "http://127.0.0.1:1", "")
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "being compacted") {
		t.Fatalf("turn during a compaction: HTTP %d %q, want 409", w.Code, w.Body.String())
	}
	if s.synth.busy() {
		t.Fatal("the refused turn must not leave a record behind")
	}

	close(release)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("compact: HTTP %d", code)
	}
	if _, ok := s.admitSynthTurn(); !ok {
		t.Fatal("a turn must be admitted again once the compaction is done")
	}
}

// A framework's "not now" is a 409 the owner can retry, not a failure — and
// it releases the slot like any other outcome.
func TestCompact_FrameworkRefusalIs409(t *testing.T) {
	s, sign := occupancyServer(t)
	refuse := true
	s.SetCompact(func(context.Context) (string, error) {
		if refuse {
			return "", fmt.Errorf("x.CompactSession: %w: busy: a compaction is already queued", framework.ErrCompactRefused)
		}
		return "ok", nil
	})
	w := httptest.NewRecorder()
	s.handleCompact(w, compactReq(t, sign, "0GSealCompact", "", 0))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "already queued") || !strings.Contains(w.Body.String(), "try again") {
		t.Fatalf("HTTP %d %q, want 409 carrying the reason", w.Code, w.Body.String())
	}
	refuse = false
	w = httptest.NewRecorder()
	s.handleCompact(w, compactReq(t, sign, "0GSealCompact", "", 1))
	if w.Code != http.StatusOK {
		t.Fatalf("after a refusal: HTTP %d, want the slot released", w.Code)
	}
}

// Remembered messages are forgotten once they could no longer pass the
// freshness check, so the replay set stays bounded.
func TestCompact_UsedMessagesArePruned(t *testing.T) {
	s, sign := occupancyServer(t)
	s.SetCompact(func(context.Context) (string, error) { return "ok", nil })
	now := time.Now().Unix()
	// "live" sits past 1x the window but inside 2x: a message accepted then
	// may have been timestamped up to a window ahead, so it can still verify.
	s.compact.used = map[string]int64{
		"expired": now - 2*authWindowSec - 1,
		"live":    now - 2*authWindowSec + 10,
	}
	w := httptest.NewRecorder()
	s.handleCompact(w, compactReq(t, sign, "0GSealCompact", "", 0))
	if w.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	if _, ok := s.compact.used["expired"]; ok {
		t.Error("an entry past 2x the auth window must be pruned")
	}
	if _, ok := s.compact.used["live"]; !ok {
		t.Error("an entry still inside 2x the auth window must be kept")
	}
	if len(s.compact.used) != 2 {
		t.Errorf("used = %v; want the live entry plus this request's", s.compact.used)
	}
}
