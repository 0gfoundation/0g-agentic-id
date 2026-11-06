package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"seal-verify/internal/state"
)

// A scrubbed non-101 reply to an upgrade request is relayed without the
// upstream's Content-Length, which the scrubbed body no longer matches.
func TestUpgradeNon101ScrubbedLength(t *testing.T) {
	const value = "ghp_the_value_itself_0123456789"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"no upgrade","token":"` + value + `","tail":"end"}`))
	}))
	defer backend.Close()

	ag := state.New()
	ag.Set([]byte{1}, backend.URL, "deadbeef", "0x00", "1", "0x00", "1", "0x00", "")
	s := &Server{agent: ag}
	s.SetScrubber(scrubValues{value})
	s.services = []ServiceEntry{{Path: "/api/echo", Method: http.MethodGet, Backend: backend.URL}}
	front := httptest.NewServer(http.HandlerFunc(s.handleProxy))
	defer front.Close()

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/api/echo", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(resp.Body)
	t.Logf("HTTP %d, Content-Length header %q, read %d bytes, err=%v, body=%q", resp.StatusCode, resp.Header.Get("Content-Length"), len(body), rerr, body)
	if strings.Contains(string(body), value) {
		t.Fatal("value leaked")
	}
	if rerr != nil || !strings.HasSuffix(string(body), `"tail":"end"}`) {
		t.Fatalf("the scrubbed reply does not arrive whole: err=%v body=%q", rerr, body)
	}
}

// Trailers of a non-101 reply to an upgrade request are scrubbed too.
func TestUpgradeNon101TrailersScrubbed(t *testing.T) {
	const value = "ghp_the_value_itself_0123456789"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Debug")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"no upgrade"}`))
		w.Header().Set("X-Debug", "token="+value)
	}))
	defer backend.Close()

	ag := state.New()
	ag.Set([]byte{1}, backend.URL, "deadbeef", "0x00", "1", "0x00", "1", "0x00", "")
	s := &Server{agent: ag}
	s.SetScrubber(scrubValues{value})
	s.services = []ServiceEntry{{Path: "/api/echo", Method: http.MethodGet, Backend: backend.URL}}
	front := httptest.NewServer(http.HandlerFunc(s.handleProxy))
	defer front.Close()

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/api/echo", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("HTTP %d trailer %v", resp.StatusCode, resp.Trailer)
	if strings.Contains(resp.Trailer.Get("X-Debug"), value) {
		t.Fatalf("the value left in a trailer: %q", resp.Trailer.Get("X-Debug"))
	}
}
