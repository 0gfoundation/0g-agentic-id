package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"seal-verify/internal/state"
)

func TestHarnessRestart(t *testing.T) {
	s := New(state.New(), "")
	mux, _ := s.signSocketMux()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/harness/restart", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("without a restart wired: %d, want 501", rec.Code)
	}

	ran := make(chan struct{})
	s.SetHarnessRestart(func(context.Context) error {
		close(ran)
		return nil
	})
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/harness/restart", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d, want 405", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/harness/restart", nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST: %d, want 202", rec.Code)
	}
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("the restart did not run")
	}
}

// A framework that runs from a harness package, asking before the restart
// is wired (during its first start), is told to ask again (503), not that it
// has none.
func TestHarnessRestart_NotYetWired(t *testing.T) {
	s, _ := signServer(t)
	s.adapter = harnessAdapter{}
	mux, _ := s.signSocketMux()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/harness/restart", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("restart before it is wired: %d %s", rec.Code, rec.Body)
	}
}
