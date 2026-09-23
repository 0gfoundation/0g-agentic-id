package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"seal-verify/internal/settings"
	"seal-verify/internal/state"
)

// settingsServer wires a Server with a bootstrapped agent and an applier that
// records what it was handed.
func settingsServer(t *testing.T, owner string) (*Server, *settings.Doc) {
	t.Helper()
	ag := state.New()
	ag.Set([]byte{1}, "http://127.0.0.1:1", "deadbeef", owner, "1", "0x00", "1", "0x00")
	s := &Server{agent: ag}
	cur := settings.Doc{Provider: "0g-compute", Model: "glm-5.2", Thinking: "low"}
	applied := &settings.Doc{}
	s.SetSettings(
		func() settings.Doc { return cur },
		func(_ context.Context, d settings.Doc) error { *applied = d; cur = d; return nil },
	)
	s.SetSessionSettings(func(_ context.Context, d settings.Doc) error { *applied = d; return nil })
	return s, applied
}

func settingsReq(t *testing.T, sign func(string) string, body string, digest string) *http.Request {
	t.Helper()
	// Digest before audience — an audience carries its own colons, so it can
	// only survive as the last field. See verifyOwnerSig.
	msg := fmt.Sprintf("0GSealSettings:0xdeadbeef:%d:", time.Now().Unix())
	if digest != "" {
		msg = fmt.Sprintf("0GSealSettings:0xdeadbeef:%d:%s:", time.Now().Unix(), digest)
	}
	r := httptest.NewRequest(http.MethodPost, "/_seal/settings", strings.NewReader(body))
	r.Header.Set("X-Auth-Message", msg)
	r.Header.Set("X-Auth-Signature", sign(msg))
	return r
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// The whole reason this route binds the body: a signature that covers only
// who is calling lets anything able to alter the request swap the document
// and keep the signature valid.
func TestSettingsPost_RejectsASwappedBody(t *testing.T) {
	sign, owner := mustKey(t)
	s, applied := settingsServer(t, owner)

	signedFor := `{"provider":"0g-compute","model":"glm-5.2"}`
	sentInstead := `{"provider":"0g-compute","model":"evil-model"}`

	w := httptest.NewRecorder()
	s.handleSettings(w, settingsReq(t, sign, sentInstead, sha256hex(signedFor)))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("HTTP %d (%s), want 401 for a body that does not match the signed digest", w.Code, w.Body.String())
	}
	if applied.Model != "" {
		t.Fatalf("applier ran with %+v — nothing may be applied on a digest mismatch", *applied)
	}
}

// A message with no digest field at all must not pass on a body-carrying
// route, or the binding is trivially bypassed by omitting it.
func TestSettingsPost_RequiresTheDigestField(t *testing.T) {
	sign, owner := mustKey(t)
	s, _ := settingsServer(t, owner)

	w := httptest.NewRecorder()
	s.handleSettings(w, settingsReq(t, sign, `{"model":"glm-5.2"}`, ""))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("HTTP %d (%s), want 400 when the signed message carries no body digest", w.Code, w.Body.String())
	}
}

func TestSettingsPost_AppliesAValidDocument(t *testing.T) {
	sign, owner := mustKey(t)
	s, applied := settingsServer(t, owner)

	body := `{"provider":"0g-compute","model":"glm-5.3","thinking":"high"}`
	w := httptest.NewRecorder()
	s.handleSettings(w, settingsReq(t, sign, body, sha256hex(body)))

	if w.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	if applied.Model != "glm-5.3" || applied.Thinking != "high" {
		t.Fatalf("applied = %+v, want the pushed document", *applied)
	}
	// The response must admit what it cost: the framework process restarts.
	if !strings.Contains(w.Body.String(), "interrupted") {
		t.Fatalf("response %s — an owner must be told the restart interrupts work", w.Body.String())
	}
}

// A document that cannot validate must be refused before anything is applied:
// a push that cannot take effect must not be able to take the agent down.
func TestSettingsPost_InvalidDocumentChangesNothing(t *testing.T) {
	sign, owner := mustKey(t)
	s, applied := settingsServer(t, owner)

	body := `{"provider":"0g-compute","model":"glm-5.3","thinking":"ludicrous"}`
	w := httptest.NewRecorder()
	s.handleSettings(w, settingsReq(t, sign, body, sha256hex(body)))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("HTTP %d, want 400", w.Code)
	}
	if applied.Model != "" {
		t.Fatalf("applier ran with %+v on an invalid document", *applied)
	}
}

// The agent sends only what it wants to change. Treating that as the whole
// document would blank the model pin it never mentioned.
func TestAgentSettings_PartialChangeKeepsTheRest(t *testing.T) {
	s, applied := settingsServer(t, "0x00")

	r := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader(`{"thinking":"high"}`))
	w := httptest.NewRecorder()
	s.handleAgentSettings(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	if applied.Model != "glm-5.2" {
		t.Fatalf("applied = %+v — the pin the agent did not mention must survive", *applied)
	}
	if applied.Thinking != "high" {
		t.Fatalf("applied = %+v — the agent's change must take effect", *applied)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["durable"] != false {
		t.Fatalf("response %v — the agent must be told the change does not persist", resp)
	}
}

// The grammar bug a client-side test surfaced: an audience is a URL and
// carries its own colons, so a digest appended AFTER it lands in the wrong
// field and every request 401s — which looks like a signature problem and is
// not one. An https audience with no port hides it; a host:port one does not.
func TestSettingsPost_AudienceWithAPortStillVerifies(t *testing.T) {
	sign, owner := mustKey(t)
	s, applied := settingsServer(t, owner)
	s.publicURL = "http://127.0.0.1:41117"

	body := `{"provider":"0g-compute","model":"glm-5.3"}`
	msg := fmt.Sprintf("0GSealSettings:0xdeadbeef:%d:%s:%s", time.Now().Unix(), sha256hex(body), s.publicURL)
	r := httptest.NewRequest(http.MethodPost, "/_seal/settings", strings.NewReader(body))
	r.Header.Set("X-Auth-Message", msg)
	r.Header.Set("X-Auth-Signature", sign(msg))

	w := httptest.NewRecorder()
	s.handleSettings(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("HTTP %d (%s) — a host:port audience must not break the digest field", w.Code, w.Body.String())
	}
	if applied.Model != "glm-5.3" {
		t.Fatalf("applied = %+v", *applied)
	}
}
