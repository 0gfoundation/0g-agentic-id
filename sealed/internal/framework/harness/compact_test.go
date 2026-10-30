package harness

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"seal-verify/internal/framework"
)

var _ framework.SessionCompactor = (*Adapter)(nil)

// stubBridge points CompactSession at a test server for the duration of t.
func stubBridge(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	prev := compactBridgeURL
	compactBridgeURL = srv.URL + "/v1/compact"
	t.Cleanup(func() { compactBridgeURL = prev; srv.Close() })
}

func TestCompactSession_CallsTheBridgeWithItsToken(t *testing.T) {
	var gotAuth, gotMethod, gotPath string
	stubBridge(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotMethod, gotPath = r.Header.Get("Authorization"), r.Method, r.URL.Path
		_, _ = w.Write([]byte(`{"ok":true,"compacted":true,"note":"compacted: 12 older history items"}`))
	})
	a := New()
	a.bridgeToken = "tok"

	note, err := a.CompactSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/compact" || gotAuth != "Bearer tok" {
		t.Errorf("bridge saw %s %s auth=%q; want POST /v1/compact with the bridge token", gotMethod, gotPath, gotAuth)
	}
	if note != "compacted: 12 older history items" {
		t.Errorf("note = %q; want the bridge's note passed through", note)
	}
}

// The bridge's 409 is "not now": typed as a refusal (the proxy answers 409),
// carrying the bridge's class and message to the owner.
func TestCompactSession_BridgeRefusalIsTyped(t *testing.T) {
	stubBridge(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"message":"session is in use","code":"busy"}}`))
	})
	a := New()
	a.bridgeToken = "tok"

	_, err := a.CompactSession(context.Background())
	if !errors.Is(err, framework.ErrCompactRefused) || !strings.Contains(err.Error(), "busy: session is in use") {
		t.Fatalf("err = %v; want ErrCompactRefused with the class and message", err)
	}
}

// Any other failure is a failure, with the status, class and message.
func TestCompactSession_BridgeFailureIsAnError(t *testing.T) {
	stubBridge(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"summarization produced no text summary content","code":"summary"}}`))
	})
	a := New()
	a.bridgeToken = "tok"

	_, err := a.CompactSession(context.Background())
	if err == nil || errors.Is(err, framework.ErrCompactRefused) ||
		!strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "summary: summarization produced") {
		t.Fatalf("err = %v; want a non-refusal error with the status, class and message", err)
	}
}

// Before the bridge has started there is no token and nothing to call.
func TestCompactSession_BeforeStartIsAnError(t *testing.T) {
	stubBridge(t, func(http.ResponseWriter, *http.Request) { t.Fatal("must not call the bridge") })
	if _, err := New().CompactSession(context.Background()); err == nil {
		t.Fatal("want an error before the bridge has a token")
	}
}

// Giving up waiting is reported as such: the bridge may still finish.
func TestCompactSession_TimeoutSaysItMayStillFinish(t *testing.T) {
	release := make(chan struct{})
	stubBridge(t, func(http.ResponseWriter, *http.Request) { <-release })
	t.Cleanup(func() { close(release) })
	a := New()
	a.bridgeToken = "tok"
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := a.CompactSession(ctx)
	if err == nil || !strings.Contains(err.Error(), "may still finish") {
		t.Fatalf("err = %v; want the may-still-finish note", err)
	}
}
