package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"seal-verify/internal/state"
	studioapi "seal-verify/internal/studio"
)

type proxyStudioProvider struct{ root string }

func (p proxyStudioProvider) Name() string { return "test" }
func (p proxyStudioProvider) StudioLayout() studioapi.Layout {
	return studioapi.Layout{Resources: []studioapi.Resource{{Kind: studioapi.KindPersonality, Format: "markdown", Activation: studioapi.ActivationActive, Role: "persona", Mode: studioapi.ModeSingleton, Root: filepath.Join(p.root, "SOUL.md"), SingletonID: "main"}}}
}
func (p proxyStudioProvider) EvolutionFor(context.Context, string) ([]byte, error) { return nil, nil }

func studioHTTPServer(t *testing.T, resolver func(context.Context) (string, error)) *Server {
	t.Helper()
	agent := state.New()
	agent.Set(nil, "", "seal", "0x1111111111111111111111111111111111111111", "1", "", "", "")
	s := &Server{agent: agent, adapter: &synthFakeAdapter{token: "owner-token"}, studio: studioapi.New(proxyStudioProvider{root: t.TempDir()}, agent), ownerResolver: resolver}
	return s
}

func studioRequest(s *Server, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/_seal/studio/state", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.handleStudio(w, r)
	return w
}

func TestStudioHTTPRequiresBearerAndFreshUnchangedOwner(t *testing.T) {
	var calls atomic.Int32
	s := studioHTTPServer(t, func(context.Context) (string, error) {
		calls.Add(1)
		return "0x1111111111111111111111111111111111111111", nil
	})
	if got := studioRequest(s, "wrong"); got.Code != http.StatusUnauthorized {
		t.Fatalf("wrong bearer status=%d body=%s", got.Code, got.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("owner lookup ran before bearer validation: %d", calls.Load())
	}
	if got := studioRequest(s, "owner-token"); got.Code != http.StatusOK {
		t.Fatalf("valid status=%d body=%s", got.Code, got.Body.String())
	}
	if got := studioRequest(s, "owner-token"); got.Code != http.StatusOK {
		t.Fatalf("second valid status=%d body=%s", got.Code, got.Body.String())
	}
	if calls.Load() != 2 {
		t.Fatalf("live owner lookup calls=%d want 2", calls.Load())
	}
}

func TestStudioHTTPFailsClosedForOwnerLookupFailureAndTransfer(t *testing.T) {
	failure := studioHTTPServer(t, func(context.Context) (string, error) { return "", errors.New("rpc down") })
	if got := studioRequest(failure, "owner-token"); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("lookup failure status=%d body=%s", got.Code, got.Body.String())
	}
	changed := studioHTTPServer(t, func(context.Context) (string, error) { return "0x2222222222222222222222222222222222222222", nil })
	if got := studioRequest(changed, "owner-token"); got.Code != http.StatusConflict {
		t.Fatalf("transfer status=%d body=%s", got.Code, got.Body.String())
	}
}
