package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// defaultMuxAtInit is http.DefaultServeMux as the imported packages left
// it: package-level variables are initialised before the package's init
// functions run.
var defaultMuxAtInit = http.DefaultServeMux

// TestDefaultServeMux_NoDebugRoutes: the /debug routes the linked
// libraries register on http.DefaultServeMux (which shows they are linked)
// are not on the default mux sealed runs with.
func TestDefaultServeMux_NoDebugRoutes(t *testing.T) {
	route := func(mux *http.ServeMux, path string) string {
		_, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, path, nil))
		return pattern
	}
	for _, path := range []string{"/debug/pprof/", "/debug/pprof/goroutine", "/debug/pprof/heap", "/debug/vars"} {
		if route(defaultMuxAtInit, path) == "" {
			t.Errorf("no library registered %s on the default mux; this test no longer shows anything", path)
		}
		if p := route(http.DefaultServeMux, path); p != "" {
			t.Errorf("http.DefaultServeMux serves %s (pattern %q)", path, p)
		}
	}
	if http.DefaultServeMux == defaultMuxAtInit {
		t.Error("http.DefaultServeMux was not replaced")
	}
}
