package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func restartReq(t *testing.T, sign func(string) string, tag, body, instance string) *http.Request {
	t.Helper()
	sum := sha256.Sum256([]byte(body))
	msg := fmt.Sprintf("%s:0xdeadbeef:%d:%s:", tag, time.Now().Unix(), hex.EncodeToString(sum[:]))
	r := httptest.NewRequest(http.MethodPost, "/_seal/restart", strings.NewReader(body))
	r.Header.Set("X-Auth-Message", msg)
	r.Header.Set("X-Auth-Signature", sign(msg))
	if instance != "" {
		r.Header.Set(clientInstanceHeader, instance)
	}
	return r
}

func TestOwnerRestart_RunsTheLayerOnce(t *testing.T) {
	s, sign := occupancyServer(t)
	var layers []string
	s.SetOwnerRestart(func(layer string) error { layers = append(layers, layer); return nil })

	req := restartReq(t, sign, "0GSealRestart", `{"layer":"harness"}`, "")
	w := httptest.NewRecorder()
	s.handleOwnerRestart(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("restart: HTTP %d: %s", w.Code, w.Body.String())
	}
	if len(layers) != 1 || layers[0] != "harness" {
		t.Fatalf("applier ran with %v", layers)
	}

	// The same signed request again: refused, nothing runs.
	again := restartReq(t, sign, "0GSealRestart", `{"layer":"harness"}`, "")
	again.Header.Set("X-Auth-Message", req.Header.Get("X-Auth-Message"))
	again.Header.Set("X-Auth-Signature", req.Header.Get("X-Auth-Signature"))
	w = httptest.NewRecorder()
	s.handleOwnerRestart(w, again)
	if w.Code != http.StatusConflict || len(layers) != 1 {
		t.Fatalf("replay: HTTP %d, applier ran %d times", w.Code, len(layers))
	}

	// Another signed request (another body, so another message) restarts sealed.
	w = httptest.NewRecorder()
	s.handleOwnerRestart(w, restartReq(t, sign, "0GSealRestart", `{"layer":"sealed"}`, ""))
	if w.Code != http.StatusAccepted || len(layers) != 2 || layers[1] != "sealed" {
		t.Fatalf("sealed: HTTP %d, layers %v", w.Code, layers)
	}
}

// The sealed a restart starts refuses the request that restarted the one
// before it: the requests used are kept on disk.
func TestOwnerRestart_ReplayAfterARestartIsRefused(t *testing.T) {
	record := filepath.Join(t.TempDir(), "owner-restarts.json")
	s, sign := occupancyServer(t)
	s.SetOwnerRestartRecord(record)
	runs := 0
	s.SetOwnerRestart(func(string) error { runs++; return nil })
	req := restartReq(t, sign, "0GSealRestart", `{"layer":"sealed"}`, "")
	w := httptest.NewRecorder()
	s.handleOwnerRestart(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("restart: HTTP %d: %s", w.Code, w.Body.String())
	}

	// The next sealed: a new server, the same agent and record.
	next := &Server{agent: s.agent}
	next.SetOwnerRestartRecord(record)
	next.SetOwnerRestart(func(string) error { runs++; return nil })
	again := restartReq(t, sign, "0GSealRestart", `{"layer":"sealed"}`, "")
	again.Header.Set("X-Auth-Message", req.Header.Get("X-Auth-Message"))
	again.Header.Set("X-Auth-Signature", req.Header.Get("X-Auth-Signature"))
	w = httptest.NewRecorder()
	next.handleOwnerRestart(w, again)
	if w.Code != http.StatusConflict || runs != 1 {
		t.Fatalf("replay after a restart: HTTP %d, applier ran %d times", w.Code, runs)
	}
}

func TestOwnerRestart_NoApplierIs501(t *testing.T) {
	s, sign := occupancyServer(t)
	w := httptest.NewRecorder()
	s.handleOwnerRestart(w, restartReq(t, sign, "0GSealRestart", `{"layer":"harness"}`, ""))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("HTTP %d, want 501", w.Code)
	}
}

func TestOwnerRestart_RefusalsMapToStatuses(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{
		{fmt.Errorf("%w: no loader", ErrRestartUnavailable), http.StatusNotImplemented},
		{fmt.Errorf("%w: starting", ErrRestartBusy), http.StatusServiceUnavailable},
		{fmt.Errorf("%w: x", ErrRestartLayer), http.StatusBadRequest},
	} {
		s, sign := occupancyServer(t)
		s.SetOwnerRestart(func(string) error { return tc.err })
		w := httptest.NewRecorder()
		s.handleOwnerRestart(w, restartReq(t, sign, "0GSealRestart", `{"layer":"sealed"}`, ""))
		if w.Code != tc.code {
			t.Fatalf("%v: HTTP %d, want %d", tc.err, w.Code, tc.code)
		}
	}
}

func TestOwnerRestart_RejectsBadBodiesAndTags(t *testing.T) {
	s, sign := occupancyServer(t)
	s.SetOwnerRestart(func(string) error { t.Fatal("must not run"); return nil })
	for _, body := range []string{`{}`, `{"layer":"container"}`, `not json`} {
		w := httptest.NewRecorder()
		s.handleOwnerRestart(w, restartReq(t, sign, "0GSealRestart", body, ""))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: HTTP %d, want 400", body, w.Code)
		}
	}
	// Another owner op's signature does not authorize a restart.
	w := httptest.NewRecorder()
	s.handleOwnerRestart(w, restartReq(t, sign, "0GSealClear", `{"layer":"harness"}`, ""))
	if w.Code != http.StatusBadRequest && w.Code != http.StatusUnauthorized {
		t.Fatalf("foreign tag: HTTP %d, want a refusal", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleOwnerRestart(w, httptest.NewRequest(http.MethodGet, "/_seal/restart", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: HTTP %d, want 405", w.Code)
	}
}

// A restart is a driving action: a displaced window cannot restart under
// the seat holder.
func TestOwnerRestart_SeatGated(t *testing.T) {
	s, sign := occupancyServer(t)
	s.SetOwnerRestart(func(string) error { t.Fatal("must not run"); return nil })
	w := httptest.NewRecorder()
	s.handleClaim(w, claimReq(t, sign, "window-B"))
	if w.Code != http.StatusOK {
		t.Fatalf("claim: %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleOwnerRestart(w, restartReq(t, sign, "0GSealRestart", `{"layer":"harness"}`, "window-A"))
	if w.Code != http.StatusConflict {
		t.Fatalf("displaced: HTTP %d, want 409", w.Code)
	}
}
