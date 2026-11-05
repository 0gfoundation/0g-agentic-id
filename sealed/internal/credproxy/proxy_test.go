package credproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const secretValue = "ghp_Sup3rS3cretValue0123456789abcdef"

// seen is what the fake upstream received.
type snap struct {
	header  http.Header
	path    string
	rawPath string
	query   string
	body    string
	proto   string
}

type seen struct {
	mu sync.Mutex
	snap
}

func (s *seen) snapshot() snap {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snap
}

// upstream echoes the request it got, value included, so the test can check
// both that the value arrived and that the client only saw a placeholder.
func upstream(t *testing.T) (*httptest.Server, *seen) {
	t.Helper()
	got := &seen{}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.mu.Lock()
		got.header, got.path, got.rawPath, got.query, got.body, got.proto = r.Header.Clone(), r.URL.Path, r.URL.RawPath, r.URL.RawQuery, string(b), r.Proto
		got.mu.Unlock()
		w.Header().Set("X-Echo", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]string{"auth": r.Header.Get("Authorization"), "body": string(b), "b64": base64.StdEncoding.EncodeToString([]byte("x" + secretValue))})
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, got
}

type harness struct {
	srv   *Server
	addr  string
	token string
	ca    *CA
	uses  []Record
	mu    sync.Mutex
}

// newHarness starts the proxy with one entry for example.com and points
// every upstream dial at ts.
func newHarness(t *testing.T, ts *httptest.Server, entries ...*Entry) *harness {
	t.Helper()
	reg := NewRegistry()
	if len(entries) == 0 {
		entries = []*Entry{{
			Name:  "github",
			Hosts: []string{"example.com"},
			Positions: []Position{
				{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"},
				{Kind: PosBasic, Username: "x-access-token"},
				{Kind: PosQuery, Param: "key"},
				{Kind: PosPath},
				{Kind: PosBody, Field: "token"},
			},
			Value: []byte(secretValue),
		}}
	}
	if err := reg.Replace(entries); err != nil {
		t.Fatal(err)
	}
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	h := &harness{token: "tok3n", ca: ca}
	h.srv = New(Config{
		Registry:    reg,
		CA:          ca,
		Token:       h.token,
		UpstreamTLS: &tls.Config{RootCAs: pool},
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, ts.Listener.Addr().String())
		},
		OnUse: func(r Record) { h.mu.Lock(); h.uses = append(h.uses, r); h.mu.Unlock() },
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = h.srv.Serve(ln) }()
	t.Cleanup(func() { ln.Close() })
	h.addr = ln.Addr().String()
	return h
}

func (h *harness) explicitURL(rest string) string {
	return "http://" + h.addr + "/" + h.token + "/https/example.com" + rest
}

// interceptClient goes through CONNECT and trusts only the proxy's CA.
func (h *harness) interceptClient(token string) *http.Client {
	pu, _ := url.Parse("http://agent:" + token + "@" + h.addr)
	return &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(pu),
		TLSClientConfig:   &tls.Config{RootCAs: h.ca.Pool()},
		ForceAttemptHTTP2: true,
	}}
}

func readAll(t *testing.T, r *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestExplicitHeaderFillAndRedact(t *testing.T) {
	ts, got := upstream(t)
	h := newHarness(t, ts)
	req, _ := http.NewRequest("GET", h.explicitURL("/user"), nil)
	req.Header.Set("Authorization", "Bearer [[credential:github]]")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if g := got.snapshot(); g.header.Get("Authorization") != "Bearer "+secretValue || g.path != "/user" {
		t.Fatalf("upstream got %q %q", g.header.Get("Authorization"), g.path)
	}
	if strings.Contains(body, secretValue) || strings.Contains(resp.Header.Get("X-Echo"), secretValue) {
		t.Fatalf("value leaked back: %s / %s", body, resp.Header.Get("X-Echo"))
	}
	if !strings.Contains(body, "[[credential:github]]") {
		t.Fatalf("expected placeholder in echoed body: %s", body)
	}
	b64 := base64.StdEncoding.EncodeToString([]byte("x" + secretValue))
	if strings.Contains(body, b64[4:20]) {
		t.Fatalf("base64 form of the value leaked: %s", body)
	}
	if len(h.uses) != 1 || h.uses[0].Names[0] != "github" || h.uses[0].Status != 200 {
		t.Fatalf("audit records: %+v", h.uses)
	}
}

func TestExplicitPositions(t *testing.T) {
	ts, got := upstream(t)
	h := newHarness(t, ts)
	cases := []struct {
		name  string
		build func() *http.Request
		check func(snap) bool
	}{
		{"basic", func() *http.Request {
			r, _ := http.NewRequest("GET", h.explicitURL("/repo.git/info/refs"), nil)
			r.SetBasicAuth("x-access-token", "[[credential:github]]")
			return r
		}, func(g snap) bool {
			return g.header.Get("Authorization") == "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+secretValue))
		}},
		{"query", func() *http.Request {
			r, _ := http.NewRequest("GET", h.explicitURL("/v1/x?a=1&key=%5B%5Bcredential%3Agithub%5D%5D"), nil)
			return r
		}, func(g snap) bool { return g.query == "a=1&key="+url.QueryEscape(secretValue) }},
		{"path", func() *http.Request {
			r, _ := http.NewRequest("GET", h.explicitURL("/"+url.PathEscape("[[credential:github]]")+"/x"), nil)
			return r
		}, func(g snap) bool { return g.path == "/"+secretValue+"/x" }},
		{"json body", func() *http.Request {
			r, _ := http.NewRequest("POST", h.explicitURL("/hook"), strings.NewReader(`{"a":1,"token":"[[credential:github]]"}`))
			r.Header.Set("Content-Type", "application/json")
			return r
		}, func(g snap) bool { return g.body == `{"a":1,"token":"`+secretValue+`"}` }},
		{"form body", func() *http.Request {
			r, _ := http.NewRequest("POST", h.explicitURL("/hook"), strings.NewReader("a=1&token="+url.QueryEscape("[[credential:github]]")))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return r
		}, func(g snap) bool { return g.body == "a=1&token="+url.QueryEscape(secretValue) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := http.DefaultClient.Do(c.build())
			if err != nil {
				t.Fatal(err)
			}
			body := readAll(t, resp)
			if resp.StatusCode != 200 || !c.check(got.snapshot()) {
				g := got.snapshot()
				t.Fatalf("status %d body %s; upstream header %v path %q query %q body %q", resp.StatusCode, body, g.header, g.path, g.query, g.body)
			}
		})
	}
}

func TestExplicitRefusals(t *testing.T) {
	ts, _ := upstream(t)
	reg := []*Entry{
		{Name: "github", Hosts: []string{"example.com"}, Positions: []Position{{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"}}, Value: []byte(secretValue)},
		{Name: "other", Hosts: []string{"other.example"}, Positions: []Position{{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"}}, Value: []byte("other-secret-value")},
		{Name: "rt", Hosts: []string{"example.com"}, Use: UseTokenOnly, Value: []byte("refresh-token-value")},
		{Name: "old", Hosts: []string{"example.com"}, Positions: []Position{{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"}}, Value: []byte("old-secret-value"), ExpiresAt: time.Now().Add(-time.Hour)},
	}
	h := newHarness(t, ts, reg...)
	cases := []struct {
		name   string
		header [2]string
		body   string
		ctype  string
		path   string
		status int
		code   string
	}{
		{"unknown entry", [2]string{"Authorization", "Bearer [[credential:nope]]"}, "", "", "/x", 403, "unknown_entry"},
		{"wrong host", [2]string{"Authorization", "Bearer [[credential:other]]"}, "", "", "/x", 403, "host_not_allowed"},
		{"wrong header", [2]string{"X-Api-Key", "[[credential:github]]"}, "", "", "/x", 403, "position_not_allowed"},
		{"wrong template", [2]string{"Authorization", "token [[credential:github]]"}, "", "", "/x", 403, "position_not_allowed"},
		{"cookie", [2]string{"Cookie", "s=[[credential:github]]"}, "", "", "/x", 403, "forbidden_header"},
		{"token only", [2]string{"Authorization", "Bearer [[credential:rt]]"}, "", "", "/x", 403, "token_only"},
		{"expired", [2]string{"Authorization", "Bearer [[credential:old]]"}, "", "", "/x", 410, "expired"},
		{"query not allowed", [2]string{}, "", "", "/x?key=%5B%5Bcredential%3Agithub%5D%5D", 403, "position_not_allowed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var body io.Reader
			if c.body != "" {
				body = strings.NewReader(c.body)
			}
			req, _ := http.NewRequest("POST", h.explicitURL(c.path), body)
			if c.header[0] != "" {
				req.Header.Set(c.header[0], c.header[1])
			}
			if c.ctype != "" {
				req.Header.Set("Content-Type", c.ctype)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			out := readAll(t, resp)
			if resp.StatusCode != c.status || resp.Header.Get("X-Seal-Credential-Error") != c.code {
				t.Fatalf("got %d %q (%s), want %d %q", resp.StatusCode, resp.Header.Get("X-Seal-Credential-Error"), out, c.status, c.code)
			}
			for _, v := range []string{secretValue, "other-secret-value", "refresh-token-value", "old-secret-value"} {
				if strings.Contains(out, v) {
					t.Fatalf("refusal leaked a value: %s", out)
				}
			}
		})
	}
}

func TestExplicitWrongToken(t *testing.T) {
	ts, _ := upstream(t)
	h := newHarness(t, ts)
	resp, err := http.Get("http://" + h.addr + "/wrong/https/example.com/x")
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if resp.StatusCode != http.StatusProxyAuthRequired || resp.Header.Get("X-Seal-Credential-Error") != "proxy_auth" {
		t.Fatalf("got %d %q", resp.StatusCode, resp.Header.Get("X-Seal-Credential-Error"))
	}
}

func TestBigBodyWithPlaceholderRefused(t *testing.T) {
	ts, _ := upstream(t)
	h := newHarness(t, ts)
	big := `{"token":"[[credential:github]]","pad":"` + strings.Repeat("a", maxBodyBytes) + `"}`
	req, _ := http.NewRequest("POST", h.explicitURL("/x"), strings.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestInterceptFillsOverHTTP2(t *testing.T) {
	ts, got := upstream(t)
	h := newHarness(t, ts)
	req, _ := http.NewRequest("GET", "https://example.com/user?x=1", nil)
	req.Header.Set("Authorization", "Bearer [[credential:github]]")
	resp, err := h.interceptClient(h.token).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != 200 || resp.ProtoMajor != 2 {
		t.Fatalf("status %d proto %s: %s", resp.StatusCode, resp.Proto, body)
	}
	if g := got.snapshot(); g.header.Get("Authorization") != "Bearer "+secretValue || g.query != "x=1" {
		t.Fatalf("upstream got %q %q", g.header.Get("Authorization"), g.query)
	}
	if strings.Contains(body, secretValue) {
		t.Fatalf("value leaked back: %s", body)
	}
}

func TestInterceptHTTP1(t *testing.T) {
	ts, got := upstream(t)
	h := newHarness(t, ts)
	c := h.interceptClient(h.token)
	c.Transport.(*http.Transport).ForceAttemptHTTP2 = false
	c.Transport.(*http.Transport).TLSClientConfig.NextProtos = []string{"http/1.1"}
	req, _ := http.NewRequest("GET", "https://example.com/user", nil)
	req.Header.Set("Authorization", "Bearer [[credential:github]]")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if resp.StatusCode != 200 || resp.ProtoMajor != 1 || got.snapshot().header.Get("Authorization") != "Bearer "+secretValue {
		t.Fatalf("status %d proto %s", resp.StatusCode, resp.Proto)
	}
}

func TestInterceptRejectsMissingToken(t *testing.T) {
	ts, _ := upstream(t)
	h := newHarness(t, ts)
	_, err := h.interceptClient("wrong").Get("https://example.com/x")
	if err == nil || !strings.Contains(err.Error(), "Proxy Authentication Required") {
		t.Fatalf("expected a 407 CONNECT failure, got %v", err)
	}
}

func TestInterceptHostMismatch(t *testing.T) {
	ts, _ := upstream(t)
	h := newHarness(t, ts)
	req, _ := http.NewRequest("GET", "https://example.com/x", nil)
	req.Host = "evil.example"
	resp, err := h.interceptClient(h.token).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if resp.StatusCode != http.StatusMisdirectedRequest || resp.Header.Get("X-Seal-Credential-Error") != "target_mismatch" {
		t.Fatalf("got %d %q", resp.StatusCode, resp.Header.Get("X-Seal-Credential-Error"))
	}
}

func TestInterceptSNIMismatch(t *testing.T) {
	ts, _ := upstream(t)
	h := newHarness(t, ts)
	c := h.interceptClient(h.token)
	c.Transport.(*http.Transport).TLSClientConfig.ServerName = "evil.example"
	if _, err := c.Get("https://example.com/x"); err == nil {
		t.Fatal("expected the TLS handshake to fail when SNI differs from the CONNECT target")
	}
}

func TestTunnelForOtherHosts(t *testing.T) {
	ts, got := upstream(t)
	h := newHarness(t, ts)
	// Not intercepted: the client must see the upstream's own certificate,
	// so trusting only the upstream's root (not the proxy CA) works.
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	pu, _ := url.Parse("http://agent:" + h.token + "@" + h.addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}}}
	req, _ := http.NewRequest("GET", "https://not-listed.example/x", nil)
	req.Header.Set("Authorization", "Bearer [[credential:github]]")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if g := got.snapshot(); g.header.Get("Authorization") != "Bearer [[credential:github]]" {
		t.Fatalf("a tunnelled request must keep its placeholder, upstream got %q", g.header.Get("Authorization"))
	}
}

func TestRedactorAcrossReads(t *testing.T) {
	red := newRedactor(map[string][]byte{"k": []byte(secretValue)})
	stream := "a" + secretValue + "b" + base64.StdEncoding.EncodeToString([]byte("zz"+secretValue)) + "c"
	for split := 1; split < len(stream); split += 3 {
		r := red.reader(io.MultiReader(strings.NewReader(stream[:split]), strings.NewReader(stream[split:])))
		out, _ := io.ReadAll(r)
		if bytes.Contains(out, []byte(secretValue)) || strings.Contains(string(out), base64.StdEncoding.EncodeToString([]byte(secretValue))[4:16]) {
			t.Fatalf("split %d leaked: %s", split, out)
		}
	}
}

func TestRedactorDoesNotHoldUnrelatedTail(t *testing.T) {
	red := newRedactor(map[string][]byte{"k": []byte(secretValue)})
	pr, pw := io.Pipe()
	r := red.reader(pr)
	go func() { _, _ = pw.Write([]byte("data: {\"x\":1}\n\n")) }()
	buf := make([]byte, 64)
	done := make(chan int, 1)
	go func() { n, _ := r.Read(buf); done <- n }()
	select {
	case n := <-done:
		if string(buf[:n]) != "data: {\"x\":1}\n\n" {
			t.Fatalf("got %q", buf[:n])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an event with no value prefix at its end was held back")
	}
	pw.Close()
}

func TestMaskRedactorKeepsLength(t *testing.T) {
	red := newMaskRedactor(map[string][]byte{"k": []byte(secretValue)})
	in := "x" + secretValue + "y"
	out := red.applyString(in)
	if len(out) != len(in) || strings.Contains(out, secretValue) {
		t.Fatalf("got %q", out)
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{
		"API.GitHub.com.":    "api.github.com",
		"api.github.com:443": "api.github.com",
		"example.com:8443":   "example.com:8443",
	} {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBlockedIP(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "100.64.0.1", "::1", "fd00::1", "0.0.0.0"} {
		if !blockedIP(net.ParseIP(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	for _, s := range []string{"203.0.113.7", "2001:db8::1"} { // privacy-check: allow (RFC 5737 / RFC 3849 documentation addresses)
		if blockedIP(net.ParseIP(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}

func TestWebSocketUpgradeMasksValue(t *testing.T) {
	var gotAuth string
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.Header.Get("Sec-WebSocket-Extensions") != "" {
			http.Error(w, "extensions must be stripped", 400)
			return
		}
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = buf.Flush()
		line := make([]byte, 5)
		_, _ = io.ReadFull(buf, line)
		_, _ = conn.Write([]byte(string(line) + "|" + secretValue + "|"))
	}))
	ts.StartTLS()
	t.Cleanup(ts.Close)
	h := newHarness(t, ts)

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := "GET /" + h.token + "/https/example.com/ws HTTP/1.1\r\nHost: " + h.addr + "\r\n" +
		"Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Extensions: permessage-deflate\r\nAuthorization: Bearer [[credential:github]]\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufioReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	want := "hello|" + strings.Repeat("*", len(secretValue)) + "|"
	got := make([]byte, len(want))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer "+secretValue {
		t.Fatalf("upstream got %q", gotAuth)
	}
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func bufioReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

// A body is read only on a host where some entry may fill a body field (or
// signs requests). Elsewhere it is relayed as it is, whatever its size: a
// conversation or a model prompt that quotes a placeholder is not a request
// to fill one, and placeholder text leaks nothing.
func TestBodyOnlyReadWhereAnEntryNeedsIt(t *testing.T) {
	ts, got := upstream(t)
	h := newHarness(t, ts, &Entry{Name: "github", Hosts: []string{"example.com"},
		Positions: []Position{{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"}}, Value: []byte(secretValue)})
	big := `{"messages":[{"content":"call it with [[credential:github]] ` + strings.Repeat("x", 100<<10) + `"}]}`
	for _, body := range []string{`{"a":{"token":"[[credential:github]]"}}`, `[[credential:github]]`, big} {
		req, _ := http.NewRequest("POST", h.explicitURL("/v1/chat"), strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer [[credential:github]]")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		readAll(t, resp)
		g := got.snapshot()
		if resp.StatusCode != 200 || g.body != body || g.header.Get("Authorization") != "Bearer "+secretValue {
			t.Fatalf("HTTP %d; upstream body intact %v, header filled %v", resp.StatusCode, g.body == body, g.header.Get("Authorization") == "Bearer "+secretValue)
		}
	}

	// A host where an entry does fill a body field still refuses a
	// placeholder anywhere else in the body.
	h2 := newHarness(t, ts)
	req, _ := http.NewRequest("POST", h2.explicitURL("/x"), strings.NewReader(`{"a":{"token":"[[credential:github]]"}}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if resp.StatusCode != 403 || resp.Header.Get("X-Seal-Credential-Error") != "position_not_allowed" {
		t.Fatalf("got %d %q", resp.StatusCode, resp.Header.Get("X-Seal-Credential-Error"))
	}
}
