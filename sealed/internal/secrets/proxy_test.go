package secrets

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeHost is a realistic (non-loopback) target the proxy will accept; a custom
// dialer redirects it to the local test server.
const fakeHost = "api.stripe.com"

// setup builds a proxy whose upstream dials land on `upstream`, with the given
// secrets configured.
func setup(t *testing.T, m map[string]Secret, upstream *httptest.Server) *Proxy {
	t.Helper()
	st := NewStore()
	st.Replace(m)
	p := NewProxy(st, t.Logf)
	target := strings.TrimPrefix(upstream.URL, "http://")
	p.setTransport(&http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, target)
		},
	})
	return p
}

func do(t *testing.T, p *Proxy, method, target string, header http.Header, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, "http://127.0.0.1"+target, strings.NewReader(body))
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec.Result()
}

func TestProxy_substitutesForAllowedHost(t *testing.T) {
	var gotAuth string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer up.Close()
	p := setup(t, map[string]Secret{"STRIPE": {Value: "sk_live_abc123", Hosts: []string{fakeHost}}}, up)

	resp := do(t, p, "GET", "/http/"+fakeHost+"/charge",
		http.Header{"Authorization": {"Bearer {{secret:STRIPE}}"}}, "")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if gotAuth != "Bearer sk_live_abc123" {
		t.Fatalf("upstream saw %q, want the real value", gotAuth)
	}
}

func TestProxy_placeholderStaysForDisallowedHost(t *testing.T) {
	var gotAuth string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	}))
	defer up.Close()
	// Allowed only for a DIFFERENT host than the one we call.
	p := setup(t, map[string]Secret{"STRIPE": {Value: "sk_live_abc123", Hosts: []string{"api.other.com"}}}, up)

	do(t, p, "GET", "/http/"+fakeHost+"/x", http.Header{"Authorization": {"Bearer {{secret:STRIPE}}"}}, "")
	if gotAuth != "Bearer {{secret:STRIPE}}" {
		t.Fatalf("disallowed host must receive the placeholder, got %q", gotAuth)
	}
	if strings.Contains(gotAuth, "sk_live_abc123") {
		t.Fatal("real value leaked to a disallowed host")
	}
}

func TestProxy_substitutesInBody(t *testing.T) {
	var gotBody string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
	}))
	defer up.Close()
	p := setup(t, map[string]Secret{"TG": {Value: "tg_tok_999999", Hosts: []string{fakeHost}}}, up)

	do(t, p, "POST", "/http/"+fakeHost+"/send", nil, `{"token":"{{secret:TG}}"}`)
	if gotBody != `{"token":"tg_tok_999999"}` {
		t.Fatalf("body not substituted: %q", gotBody)
	}
}

func TestProxy_redactsResponse(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", "sk_live_abc123")
		_, _ = io.WriteString(w, `{"error":"invalid key sk_live_abc123"}`)
	}))
	defer up.Close()
	p := setup(t, map[string]Secret{"STRIPE": {Value: "sk_live_abc123", Hosts: []string{fakeHost}}}, up)

	resp := do(t, p, "GET", "/http/"+fakeHost+"/x", http.Header{"Authorization": {"Bearer {{secret:STRIPE}}"}}, "")
	b, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(b), "sk_live_abc123") {
		t.Fatalf("response body leaked the value: %s", b)
	}
	if !strings.Contains(string(b), "{{secret:STRIPE}}") {
		t.Fatalf("response not redacted: %s", b)
	}
	if strings.Contains(resp.Header.Get("X-Echo"), "sk_live_abc123") {
		t.Fatalf("response header leaked the value: %s", resp.Header.Get("X-Echo"))
	}
}

func TestProxy_refusesLoopbackTarget(t *testing.T) {
	st := NewStore()
	p := NewProxy(st, t.Logf)
	for _, tgt := range []string{"/http/127.0.0.1/x", "/http/localhost/x", "/http/[::1]/x"} {
		resp := do(t, p, "GET", tgt, nil, "")
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d", tgt, resp.StatusCode)
		}
	}
}

func TestProxy_rejectsBadPath(t *testing.T) {
	p := NewProxy(NewStore(), t.Logf)
	for _, tgt := range []string{"/", "/ftp/host/x", "/https"} {
		resp := do(t, p, "GET", tgt, nil, "")
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d", tgt, resp.StatusCode)
		}
	}
}

func TestParseTarget(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:9000/https/api.stripe.com/v1/charges")
	scheme, host, rest, err := parseTarget(u)
	if err != nil || scheme != "https" || host != "api.stripe.com" || rest != "/v1/charges" {
		t.Fatalf("parse: %q %q %q %v", scheme, host, rest, err)
	}
}
