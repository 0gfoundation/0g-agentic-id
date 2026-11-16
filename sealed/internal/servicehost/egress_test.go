package servicehost

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"seal-verify/internal/credproxy"
)

func TestEgressEnforcesHostPolicyAndPrivateAddressBlock(t *testing.T) {
	var called atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		if r.Header.Get("X-Hop") != "" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("hop/proxy credentials reached upstream")
		}
		w.Header().Set("Connection", "X-Hop")
		w.Header().Set("X-Hop", "discard")
		io.WriteString(w, "allowed")
	}))
	defer target.Close()
	p := &egressProxy{ctx: context.Background(), allowed: map[string]bool{"allowed.example:80": true}, slots: make(chan struct{}, 1)}
	p.transport = &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "allowed.example:80" {
			t.Errorf("dialed unexpected destination %s", addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, target.Listener.Addr().String())
	}}
	defer p.transport.CloseIdleConnections()
	for _, url := range []string{"http://other.example/", "http://allowed.example:81/", "http://127.0.0.1/", "https://allowed.example/"} {
		out := httptest.NewRecorder()
		p.ServeHTTP(out, httptest.NewRequest("GET", url, nil))
		if out.Code != 403 || called.Load() != 0 {
			t.Fatalf("unallowed destination reached upstream: %s %d", url, out.Code)
		}
	}
	req := httptest.NewRequest("GET", "http://allowed.example/path", nil)
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "discard")
	req.Header.Set("Proxy-Authorization", "fixture")
	out := httptest.NewRecorder()
	p.ServeHTTP(out, req)
	if out.Code != 200 || out.Body.String() != "allowed" || out.Header().Get("X-Hop") != "" || called.Load() != 1 {
		t.Fatalf("allowed egress failed: %d %s", out.Code, out.Body.String())
	}
	// Even an explicitly allowed host:port must not dial loopback in production.
	p.allowed = map[string]bool{target.Listener.Addr().String(): true}
	p.transport = &http.Transport{DialContext: credproxy.SafeDial}
	out = httptest.NewRecorder()
	p.ServeHTTP(out, httptest.NewRequest("GET", target.URL, nil))
	if out.Code != 502 || called.Load() != 1 {
		t.Fatal("allowlisting bypassed private-address rejection")
	}
}
