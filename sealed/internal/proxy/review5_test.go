package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"seal-verify/internal/credproxy"
	"seal-verify/internal/state"
)

// A header name holding a mixed-case value is dropped whatever case the
// transport gives the name.
func TestHeaderNameMixedCaseValueDropped(t *testing.T) {
	// Built at run time, so no token-shaped literal sits in the source.
	value := "ghp" + "_" + "AbCdEfGhIjKlMnOpQrStUvWxYz" + "0123456789"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["X-"+value] = []string{"1"}
		_, _ = w.Write([]byte(`ok`))
	}))
	defer backend.Close()

	reg := credproxy.NewRegistry()
	if err := reg.Put(&credproxy.Entry{Name: "github", Hosts: []string{"api.github.com"}, Use: credproxy.UseInject, Value: []byte(value),
		Positions: []credproxy.Position{{Kind: credproxy.PosHeader, Name: "Authorization", Template: "Bearer {v}"}}}); err != nil {
		t.Fatal(err)
	}
	ag := state.New()
	ag.Set([]byte{1}, backend.URL, "deadbeef", "0x00", "1", "0x00", "1", "0x00", "")
	s := &Server{agent: ag}
	s.SetScrubber(reg)
	s.services = []ServiceEntry{{Path: "/api/echo", Method: http.MethodGet, Backend: backend.URL}}

	w := httptest.NewRecorder()
	s.handleProxy(w, httptest.NewRequest(http.MethodGet, "/api/echo", nil))
	for k := range w.Header() {
		if strings.Contains(strings.ToLower(k), strings.ToLower(value)) {
			t.Fatalf("the value (letter case folded) left in a header name: %q", k)
		}
	}
}
