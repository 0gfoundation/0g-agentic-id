package secrets

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeHost is a realistic (non-loopback) https target the proxy accepts; a
// custom dialer redirects it to the local TLS test server.
const fakeHost = "api.stripe.com"

// setup builds a proxy whose https upstream dials land on `upstream` (a TLS
// test server), with the given secrets configured.
func setup(t *testing.T, m map[string]Secret, upstream *httptest.Server) *Proxy {
	t.Helper()
	st := NewStore()
	st.Replace(m)
	p := NewProxy(st, t.Logf)
	target := strings.TrimPrefix(upstream.URL, "https://")
	p.setTransport(&http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, target)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test server's self-signed cert
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
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer up.Close()
	p := setup(t, map[string]Secret{"STRIPE": {Value: "sk_live_abc123", Hosts: []string{fakeHost}}}, up)

	resp := do(t, p, "GET", "/https/"+fakeHost+"/charge",
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
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	}))
	defer up.Close()
	p := setup(t, map[string]Secret{"STRIPE": {Value: "sk_live_abc123", Hosts: []string{"api.other.com"}}}, up)

	do(t, p, "GET", "/https/"+fakeHost+"/x", http.Header{"Authorization": {"Bearer {{secret:STRIPE}}"}}, "")
	if gotAuth != "Bearer {{secret:STRIPE}}" {
		t.Fatalf("disallowed host must receive the placeholder, got %q", gotAuth)
	}
	if strings.Contains(gotAuth, "sk_live_abc123") {
		t.Fatal("real value leaked to a disallowed host")
	}
}

func TestProxy_substitutesInBody(t *testing.T) {
	var gotBody string
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
	}))
	defer up.Close()
	p := setup(t, map[string]Secret{"TG": {Value: "tg_tok_999999", Hosts: []string{fakeHost}}}, up)

	do(t, p, "POST", "/https/"+fakeHost+"/send", nil, `{"token":"{{secret:TG}}"}`)
	if gotBody != `{"token":"tg_tok_999999"}` {
		t.Fatalf("body not substituted: %q", gotBody)
	}
}

func TestProxy_redactsResponse(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", "sk_live_abc123")
		_, _ = io.WriteString(w, `{"error":"invalid key sk_live_abc123"}`)
	}))
	defer up.Close()
	p := setup(t, map[string]Secret{"STRIPE": {Value: "sk_live_abc123", Hosts: []string{fakeHost}}}, up)

	resp := do(t, p, "GET", "/https/"+fakeHost+"/x", http.Header{"Authorization": {"Bearer {{secret:STRIPE}}"}}, "")
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

// F1: an upstream that compresses despite our identity request must be refused,
// not relayed — otherwise redaction sees only compressed bytes.
func TestProxy_refusesEncodedResponse(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte(`{"error":"invalid key sk_live_abc123"}`))
		_ = gz.Close()
	}))
	defer up.Close()
	p := setup(t, map[string]Secret{"STRIPE": {Value: "sk_live_abc123", Hosts: []string{fakeHost}}}, up)

	resp := do(t, p, "GET", "/https/"+fakeHost+"/x", http.Header{"Authorization": {"Bearer {{secret:STRIPE}}"}}, "")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("encoded response must be refused (502), got %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(b), "sk_live_abc123") {
		t.Fatalf("value leaked through an encoded response: %s", b)
	}
}

// F2: a request body over the cap is refused (413), not truncated-and-forwarded.
func TestProxy_refusesOversizeRequestBody(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer up.Close()
	p := setup(t, map[string]Secret{"X": {Value: "value1", Hosts: []string{fakeHost}}}, up)
	big := strings.Repeat("a", maxBodyBytes+1)
	resp := do(t, p, "POST", "/https/"+fakeHost+"/x", nil, big)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body must be 413, got %d", resp.StatusCode)
	}
}

// F4: the http scheme is refused — a secret must not ride cleartext.
func TestProxy_refusesHTTPScheme(t *testing.T) {
	p := NewProxy(NewStore(), t.Logf)
	resp := do(t, p, "GET", "/http/api.stripe.com/x", nil, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("http scheme must be 400, got %d", resp.StatusCode)
	}
}

func TestProxy_refusesLoopbackTarget(t *testing.T) {
	p := NewProxy(NewStore(), t.Logf)
	for _, tgt := range []string{"/https/127.0.0.1/x", "/https/localhost/x", "/https/[::1]/x"} {
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
