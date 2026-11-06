package credproxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
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
	return newHarnessWith(t, ts, nil, entries...)
}

// newHarnessWith is newHarness with tune applied to the proxy's Config.
func newHarnessWith(t *testing.T, ts *httptest.Server, tune func(*Config), entries ...*Entry) *harness {
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
	cfg := Config{
		Registry:    reg,
		CA:          ca,
		Token:       h.token,
		UpstreamTLS: &tls.Config{RootCAs: pool},
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, ts.Listener.Addr().String())
		},
		OnUse: func(r Record) { h.mu.Lock(); h.uses = append(h.uses, r); h.mu.Unlock() },
	}
	if tune != nil {
		tune(&cfg)
	}
	h.srv = New(cfg)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = h.srv.Serve(ln) }()
	t.Cleanup(func() { ln.Close() })
	h.addr = ln.Addr().String()
	return h
}

// records is the audit records so far.
func (h *harness) records() []Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Record(nil), h.uses...)
}

// lastRecord is the latest audit record, failing the test when there is none.
func (h *harness) lastRecord(t *testing.T) Record {
	t.Helper()
	recs := h.records()
	if len(recs) == 0 {
		t.Fatal("no audit record")
	}
	return recs[len(recs)-1]
}

func (h *harness) reg() *Registry { return h.srv.cfg.Registry }

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
	if recs := h.records(); len(recs) != 1 || recs[0].Names[0] != "github" || recs[0].Status != 200 {
		t.Fatalf("audit records: %+v", recs)
	}
	// The echo shows the placeholder again; the header says it was filled.
	if resp.Header.Get(FilledHeader) != "github" {
		t.Fatalf("%s = %q", FilledHeader, resp.Header.Get(FilledHeader))
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
		{"basic with trailing newline", func() *http.Request {
			r, _ := http.NewRequest("GET", h.explicitURL("/repo.git/info/refs"), nil)
			r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:[[credential:github]]\n")))
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
			// Every request that named a credential is in the owner's
			// audit log, a refused one with its code.
			if rec := h.lastRecord(t); rec.Code != c.code || rec.Status != c.status || len(rec.Names) == 0 {
				t.Fatalf("audit record %+v", rec)
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
	if rec := h.lastRecord(t); rec.Code != "body_too_large" || len(rec.Names) != 1 || rec.Names[0] != "github" {
		t.Fatalf("audit record %+v", rec)
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
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "100.64.0.1", "::1", "fd00::1", "0.0.0.0",
		"64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::a00:1"} { // NAT64 forms of 127.0.0.1, 169.254.169.254, 10.0.0.1
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

const switching = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"

// wsUpstream is an HTTP/1.1 upstream that answers an upgrade with head (the
// whole 101 response) and then runs serve on the connection. check, when
// set, may refuse the upgrade first with an ordinary response.
func wsUpstream(t *testing.T, head string, check func(http.ResponseWriter, *http.Request) bool, serve func(net.Conn, *bufio.ReadWriter)) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Sec-WebSocket-Extensions") != "" {
			http.Error(w, "extensions must be stripped", 400)
			return
		}
		if check != nil && !check(w, r) {
			return
		}
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString(head)
		_ = buf.Flush()
		if serve != nil {
			serve(conn, buf)
		}
	}))
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

// wsDial sends an upgrade through the explicit form, with extra request
// header lines, and reads the response head.
func wsDial(t *testing.T, h *harness, extra string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	req := "GET /" + h.token + "/https/example.com/ws HTTP/1.1\r\nHost: " + h.addr + "\r\n" +
		"Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Extensions: permessage-deflate\r\n" + extra + "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	return conn, br, resp
}

// wsFrame is a final server frame: FIN set, unmasked.
func wsFrame(op byte, payload []byte) []byte {
	b := []byte{0x80 | op}
	switch n := len(payload); {
	case n < 126:
		b = append(b, byte(n))
	case n <= 0xffff:
		b = append(b, 126, byte(n>>8), byte(n))
	default:
		b = binary.BigEndian.AppendUint64(append(b, 127), uint64(n))
	}
	return append(b, payload...)
}

// readFrame reads one unmasked frame: its first byte and its payload.
func readFrame(t *testing.T, r io.Reader) (byte, []byte) {
	t.Helper()
	var hdr [10]byte
	if _, err := io.ReadFull(r, hdr[:2]); err != nil {
		t.Fatal(err)
	}
	n := uint64(hdr[1] & 0x7f)
	switch n {
	case 126:
		if _, err := io.ReadFull(r, hdr[2:4]); err != nil {
			t.Fatal(err)
		}
		n = uint64(binary.BigEndian.Uint16(hdr[2:4]))
	case 127:
		if _, err := io.ReadFull(r, hdr[2:10]); err != nil {
			t.Fatal(err)
		}
		n = binary.BigEndian.Uint64(hdr[2:10])
	}
	if hdr[1]&0x80 != 0 || n > 8<<20 {
		t.Fatalf("bad frame header % x", hdr[:2])
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		t.Fatal(err)
	}
	return hdr[0], p
}

func TestWebSocketUpgradeMasksValue(t *testing.T) {
	var gotAuth string
	ts := wsUpstream(t, switching, func(_ http.ResponseWriter, r *http.Request) bool {
		gotAuth = r.Header.Get("Authorization")
		return true
	}, func(conn net.Conn, buf *bufio.ReadWriter) {
		line := make([]byte, 5)
		_, _ = io.ReadFull(buf, line)
		_, _ = conn.Write(wsFrame(0x1, []byte(string(line)+"|"+secretValue+"|")))
	})
	h := newHarness(t, ts)
	conn, br, resp := wsDial(t, h, "Authorization: Bearer [[credential:github]]\r\n")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	b0, got := readFrame(t, br)
	if gotAuth != "Bearer "+secretValue {
		t.Fatalf("upstream got %q", gotAuth)
	}
	if want := "hello|" + strings.Repeat("*", len(secretValue)) + "|"; b0 != 0x81 || string(got) != want {
		t.Fatalf("got %x %q, want %q", b0, got, want)
	}
}

// The 101 response is redacted like any other: header values and the reason
// phrase, hop-by-hop headers dropped, and only the proxy says what it filled.
func TestWebSocket101IsRedacted(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		auth := r.Header.Get("Authorization")
		_, _ = buf.WriteString("HTTP/1.1 101 Switching " + auth + "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
			"X-Echo: " + auth + "\r\n" + FilledHeader + ": forged\r\n" + ErrorHeader + ": forged\r\n" +
			"Keep-Alive: timeout=5\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n")
		_ = buf.Flush()
		time.Sleep(200 * time.Millisecond)
	}))
	ts.StartTLS()
	t.Cleanup(ts.Close)
	h := newHarness(t, ts)
	_, _, resp := wsDial(t, h, "Authorization: Bearer [[credential:github]]\r\n")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if strings.Contains(resp.Status, secretValue) || !strings.Contains(resp.Status, "[[credential:github]]") {
		t.Fatalf("status line %q", resp.Status)
	}
	if got := resp.Header.Get("X-Echo"); got != "Bearer [[credential:github]]" {
		t.Fatalf("X-Echo %q", got)
	}
	if resp.Header.Get(FilledHeader) != "github" || resp.Header.Get(ErrorHeader) != "" {
		t.Fatalf("%s %q, %s %q", FilledHeader, resp.Header.Get(FilledHeader), ErrorHeader, resp.Header.Get(ErrorHeader))
	}
	if resp.Header.Get("Keep-Alive") != "" || resp.Header.Get("Sec-WebSocket-Extensions") != "" || resp.Header.Get("Upgrade") != "websocket" {
		t.Fatalf("headers %v", resp.Header)
	}
}

// Server frames are parsed and each payload redacted as a whole: nothing is
// held back waiting for the next frame, a frame header is never rewritten,
// a large frame is masked as it streams, and a close frame's reason is
// masked after its status code.
func TestWebSocketFrames(t *testing.T) {
	const value = "frame-value-0123456789"
	value2 := []byte(value)
	big := bytes.Repeat([]byte("."), maxFramePayload+100<<10)
	copy(big[32<<10-5:], value) // across the first 32 KiB chunk boundary
	copy(big[len(big)-len(value):], value)
	bigWant := bytes.Repeat([]byte("."), len(big))
	copy(bigWant[32<<10-5:], strings.Repeat("*", len(value)))
	copy(bigWant[len(big)-len(value):], strings.Repeat("*", len(value)))
	// 0x73 is 's': a raw stream would read "sk-" and a token from the
	// length byte on.
	lengthByte := "k-" + strings.Repeat("a", 0x73-2)
	closeFrame := append([]byte{0x03, 0xe8}, "bye "+value...)
	closeWant := append([]byte{0x03, 0xe8}, "bye "+strings.Repeat("*", len(value))...)

	ts := wsUpstream(t, switching, nil, func(conn net.Conn, buf *bufio.ReadWriter) {
		one := make([]byte, 1)
		_, _ = conn.Write(wsFrame(0x1, []byte("a|"+value+"|b")))
		// Ends with the start of a value; the rest of the stream comes only
		// once the client has read this frame and answered.
		_, _ = conn.Write(wsFrame(0x1, append([]byte("tail "), value2[:10]...)))
		_, _ = io.ReadFull(buf, one)
		_, _ = conn.Write(wsFrame(0x1, []byte(lengthByte)))
		_, _ = conn.Write(wsFrame(0x2, big))
		_, _ = conn.Write(wsFrame(0x8, closeFrame))
		_, _ = io.ReadFull(buf, one)
	})
	h := newHarness(t, ts, &Entry{Name: "ws", Hosts: []string{"example.com"},
		Positions: []Position{{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"}}, Value: []byte(value)})
	conn, br, resp := wsDial(t, h, "")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for i, want := range []struct {
		b0      byte
		payload string
	}{
		{0x81, "a|" + strings.Repeat("*", len(value)) + "|b"},
		{0x81, "tail " + value[:10]},
	} {
		b0, p := readFrame(t, br)
		if b0 != want.b0 || string(p) != want.payload {
			t.Fatalf("frame %d: %x %q, want %q", i, b0, p, want.payload)
		}
	}
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if b0, p := readFrame(t, br); b0 != 0x81 || string(p) != lengthByte {
		t.Fatalf("length-byte frame: %x %q", b0, p)
	}
	if b0, p := readFrame(t, br); b0 != 0x82 || !bytes.Equal(p, bigWant) {
		t.Fatalf("large frame: %x, %d bytes, masked as expected %v", b0, len(p), bytes.Equal(p, bigWant))
	}
	if b0, p := readFrame(t, br); b0 != 0x88 || !bytes.Equal(p, closeWant) {
		t.Fatalf("close frame: %x %q", b0, p)
	}
	_, _ = conn.Write([]byte("x"))
}

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

// A value filled into a request is redacted from its response even when its
// entry is deleted or replaced while the request is in flight, as the agent
// itself can arrange (deleting a derived entry, running a new token
// request), and even once the registry has let go of the value entirely.
func TestRedactsValueRemovedMidRequest(t *testing.T) {
	const name, value = "derived:gh.access_token", "derived-access-value-0123456789"
	for _, c := range []struct {
		name   string
		mutate func(*Registry)
	}{
		{"deleted", func(reg *Registry) { reg.Delete(name) }},
		{"replaced", func(reg *Registry) {
			_ = reg.Put(&Entry{Name: name, Hosts: []string{"example.com"}, Value: []byte("derived-access-value-next")})
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			arrived, release := make(chan struct{}), make(chan struct{})
			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				close(arrived)
				<-release
				w.Header().Set("X-Echo", auth)
				_, _ = io.WriteString(w, auth)
			}))
			ts.EnableHTTP2 = true
			ts.StartTLS()
			t.Cleanup(ts.Close)
			h := newHarness(t, ts, &Entry{Name: name, Hosts: []string{"example.com"},
				Positions: []Position{{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"}}, Value: []byte(value)})
			type result struct {
				body, echo string
				err        error
			}
			done := make(chan result, 1)
			go func() {
				req, _ := http.NewRequest("GET", h.explicitURL("/user"), nil)
				req.Header.Set("Authorization", "Bearer "+Placeholder(name))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					done <- result{err: err}
					return
				}
				b, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				done <- result{body: string(b), echo: resp.Header.Get("X-Echo"), err: err}
			}()
			<-arrived
			c.mutate(h.reg())
			// Push the value out of the retired values as well: only the
			// request's own record of what it filled is left.
			for i := 0; i <= maxRetiredDerived; i++ {
				churn := fmt.Sprintf("derived:churn%d", i)
				_ = h.reg().Put(&Entry{Name: churn, Hosts: []string{"churn.example"}, Value: []byte(fmt.Sprintf("churn-value-%06d", i))})
				h.reg().Delete(churn)
			}
			if string(h.reg().Scrub([]byte(value))) != value {
				t.Fatal("setup: the registry still scrubs the value")
			}
			close(release)
			res := <-done
			if res.err != nil {
				t.Fatal(res.err)
			}
			want := "Bearer " + Placeholder(name)
			if res.body != want || res.echo != want {
				t.Fatalf("body %q, X-Echo %q", res.body, res.echo)
			}
		})
	}
}

// An upstream cannot speak for the proxy: its X-Seal-Credential-* headers
// never reach the harness.
func TestUpstreamCannotSetProxyHeaders(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(FilledHeader, "forged")
		w.Header().Set(ErrorHeader, "forged")
		_, _ = io.WriteString(w, "ok")
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	h := newHarness(t, ts)
	for _, auth := range []string{"", "Bearer [[credential:github]]"} {
		req, _ := http.NewRequest("GET", h.explicitURL("/x"), nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		readAll(t, resp)
		wantFilled := ""
		if auth != "" {
			wantFilled = "github"
		}
		if resp.StatusCode != 200 || resp.Header.Get(FilledHeader) != wantFilled || resp.Header.Get(ErrorHeader) != "" {
			t.Fatalf("%d %s=%q %s=%q", resp.StatusCode, FilledHeader, resp.Header.Get(FilledHeader), ErrorHeader, resp.Header.Get(ErrorHeader))
		}
	}
}

// A body fill is refused wherever the server could read the body otherwise
// than the proxy did, or the placeholder would not really be filled.
func TestBodyFillRefusals(t *testing.T) {
	ts, _ := upstream(t)
	h := newHarness(t, ts)
	const form, js = "application/x-www-form-urlencoded", "application/json"
	for _, c := range []struct {
		name   string
		ctypes []string
		body   string
	}{
		// Filled as a form, read as JSON: the value lands in "x".
		{"form body that is JSON", []string{form}, `{"x":"&token=%5B%5Bcredential%3Agithub%5D%5D&y=","z":1}`},
		{"form body with whitespace", []string{form}, "a=1 &token=%5B%5Bcredential%3Agithub%5D%5D"},
		{"form body not url-encoded once filled", []string{form}, `a=[x]&token=[[credential:github]]`},
		{"form placeholder not a whole value", []string{form}, `token=x[[credential:github]]`},
		{"form placeholder JSON-escaped", []string{form}, `token=%5B%5Bcredential%3Agithub%5D%5D&b=\u005b\u005bcredential:github]]`},
		{"two content types", []string{js, form}, `{"token":"[[credential:github]]"}`},
		{"JSON-escaped placeholder", []string{js}, `{"token":"[[credential:git\u0068ub]]"}`},
		{"JSON-escaped brackets", []string{js}, `{"token":"\u005b\u005bcredential:github]]"}`},
		{"placeholder only in a nested value", []string{js}, `{"token":"x","a":{"b":"\u005b[credential:github]]"}}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", h.explicitURL("/hook"), strings.NewReader(c.body))
			for _, ct := range c.ctypes {
				req.Header.Add("Content-Type", ct)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			out := readAll(t, resp)
			if resp.StatusCode != 403 || resp.Header.Get(ErrorHeader) != "position_not_allowed" || resp.Header.Get(FilledHeader) != "" {
				t.Fatalf("got %d %q filled %q: %s", resp.StatusCode, resp.Header.Get(ErrorHeader), resp.Header.Get(FilledHeader), out)
			}
			if rec := h.lastRecord(t); rec.Code != "position_not_allowed" || len(rec.Names) != 1 || rec.Names[0] != "github" {
				t.Fatalf("audit record %+v", rec)
			}
		})
	}
}

// A refused X-Seal-Sign is audited under the name it gave.
func TestSignRefusalAudited(t *testing.T) {
	ts, _ := upstream(t)
	h := newHarness(t, ts)
	req, _ := http.NewRequest("GET", h.explicitURL("/x"), nil)
	req.Header.Set(SignHeader, "nope")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if resp.StatusCode != 403 {
		t.Fatalf("got %d", resp.StatusCode)
	}
	if rec := h.lastRecord(t); rec.Code != "unknown_entry" || len(rec.Names) != 1 || rec.Names[0] != "nope" {
		t.Fatalf("audit record %+v", rec)
	}
}

// The registry keeps its own copy of an entry: it never writes to one it is
// handed, which sealed reads back from it and hands over again while proxy
// goroutines read the same entry (run with -race).
func TestRegistryDoesNotWriteToEntriesItIsHanded(t *testing.T) {
	reg := NewRegistry()
	e := &Entry{Name: "a", Hosts: []string{"API.Example.com."},
		Positions: []Position{{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"}}, Value: []byte("value-aaaaaaaa")}
	if err := reg.Replace([]*Entry{e}); err != nil {
		t.Fatal(err)
	}
	if e.Hosts[0] != "API.Example.com." || e.Use != "" {
		t.Fatalf("Replace wrote to the entry it was handed: %+v", e)
	}
	if g := reg.Get("a"); g.Hosts[0] != "api.example.com" || g.Use != UseInject {
		t.Fatalf("held entry %+v", g)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_ = reg.Replace([]*Entry{reg.Get("a")})
			_ = reg.Put(reg.Get("a"))
		}
	}()
	for i := 0; i < 200; i++ {
		if !reg.InterceptsHost("api.example.com") || reg.Get("a").Use != UseInject {
			t.Fatal("entry changed under a reader")
		}
	}
	<-done
}

// A status WriteHeader cannot write, or that is not a final one, becomes a
// 502, audited before anything is written.
func TestUpstreamInvalidStatus(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 099 Odd\r\nContent-Length: 2\r\n\r\nok")
		_ = buf.Flush()
	}))
	ts.StartTLS()
	t.Cleanup(ts.Close)
	h := newHarness(t, ts)
	req, _ := http.NewRequest("GET", h.explicitURL("/x"), nil)
	req.Header.Set("Authorization", "Bearer [[credential:github]]")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get(ErrorHeader) != "upstream_error" {
		t.Fatalf("got %d %q", resp.StatusCode, resp.Header.Get(ErrorHeader))
	}
	if rec := h.lastRecord(t); rec.Status != http.StatusBadGateway || rec.Code != "upstream_error" {
		t.Fatalf("audit record %+v", rec)
	}
}

// An entry may name an IP address: the client sends no SNI for one, and the
// Host header must still agree with the CONNECT target.
func TestInterceptIPLiteral(t *testing.T) {
	ts, got := upstream(t)
	h := newHarness(t, ts, &Entry{Name: "github", Hosts: []string{"127.0.0.1"},
		Positions: []Position{{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"}}, Value: []byte(secretValue)})
	req, _ := http.NewRequest("GET", "https://127.0.0.1/user", nil)
	req.Header.Set("Authorization", "Bearer [[credential:github]]")
	resp, err := h.interceptClient(h.token).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != 200 || got.snapshot().header.Get("Authorization") != "Bearer "+secretValue || strings.Contains(body, secretValue) {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	req, _ = http.NewRequest("GET", "https://127.0.0.1/user", nil)
	req.Host = "evil.example"
	resp, err = h.interceptClient(h.token).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("Host mismatch: got %d", resp.StatusCode)
	}
}

// Encodings beyond the raw value: JSON with escaped slashes, lower-case
// percent escapes, Python's quote().
func TestRedactorEncodings(t *testing.T) {
	const v = "ab/cd+ef=gh&ij kl~mn"
	red := newRedactor(map[string][]byte{"k": []byte(v)})
	for _, form := range []string{
		`ab\/cd+ef=gh\u0026ij kl~mn`,     // Go's JSON, slashes escaped (PHP)
		`ab\/cd+ef=gh&ij kl~mn`,          // other encoders' JSON, slashes escaped
		`ab%2fcd%2bef%3dgh%26ij+kl~mn`,   // query escaping, lower-case hex
		`ab/cd%2Bef%3Dgh%26ij%20kl~mn`,   // Python quote()
		`ab/cd%2bef%3dgh%26ij%20kl~mn`,   // the same, lower-case hex
		`ab%2Fcd%2Bef%3Dgh%26ij%20kl~mn`, // quote(safe="")
	} {
		if got := string(red.apply([]byte("<" + form + ">"))); got != "<[[credential:k]]>" {
			t.Errorf("%s: got %s", form, got)
		}
	}
}

// Idle client connections are closed: the listener's, and an intercepted
// one over HTTP/1.1 and HTTP/2.
func TestIdleConnectionsClosed(t *testing.T) {
	ts, _ := upstream(t)
	h := newHarnessWith(t, ts, func(c *Config) { c.IdleTimeout = 200 * time.Millisecond })
	waitClosed := func(t *testing.T, r io.Reader) {
		t.Helper()
		start := time.Now()
		_, err := io.Copy(io.Discard, r)
		if err != nil {
			t.Fatalf("not closed after %v: %v", time.Since(start), err)
		}
	}
	connect := func(t *testing.T, proto string) *tls.Conn {
		t.Helper()
		conn, err := net.Dial("tcp", h.addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		auth := base64.StdEncoding.EncodeToString([]byte("agent:" + h.token))
		_, _ = conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic " + auth + "\r\n\r\n"))
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
		if err != nil || resp.StatusCode != 200 || br.Buffered() != 0 {
			t.Fatalf("CONNECT: %v %v", resp, err)
		}
		tc := tls.Client(conn, &tls.Config{RootCAs: h.ca.Pool(), ServerName: "example.com", NextProtos: []string{proto}})
		if err := tc.Handshake(); err != nil || tc.ConnectionState().NegotiatedProtocol != proto {
			t.Fatalf("handshake: %v %q", err, tc.ConnectionState().NegotiatedProtocol)
		}
		return tc
	}
	request := func(t *testing.T, c net.Conn, path string) *bufio.Reader {
		t.Helper()
		_, _ = c.Write([]byte("GET " + path + " HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		readAll(t, resp)
		return br
	}
	t.Run("listener", func(t *testing.T) {
		conn, err := net.Dial("tcp", h.addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		waitClosed(t, request(t, conn, "/"+h.token+"/https/example.com/x"))
	})
	t.Run("intercepted HTTP/1.1", func(t *testing.T) {
		tc := connect(t, "http/1.1")
		waitClosed(t, request(t, tc, "/x"))
	})
	t.Run("intercepted HTTP/2", func(t *testing.T) {
		tc := connect(t, "h2")
		// The client preface and an empty SETTINGS frame, then nothing.
		_, _ = tc.Write(append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 0, 0, 0, 4, 0, 0, 0, 0, 0))
		waitClosed(t, tc)
	})
}

// Every Content-Encoding value counts, on the ordinary and the WebSocket
// path.
func TestEncodedResponseRefused(t *testing.T) {
	gz := func(s string) []byte {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		_, _ = zw.Write([]byte(s))
		_ = zw.Close()
		return b.Bytes()
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Encoding", "identity")
		w.Header().Add("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(gz(r.Header.Get("Authorization")))
	}))
	ts.StartTLS()
	t.Cleanup(ts.Close)
	h := newHarness(t, ts)
	req, _ := http.NewRequest("GET", h.explicitURL("/x"), nil)
	req.Header.Set("Authorization", "Bearer [[credential:github]]")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get(ErrorHeader) != "upstream_error" {
		t.Fatalf("got %d %q", resp.StatusCode, resp.Header.Get(ErrorHeader))
	}
	_, _, resp = wsDial(t, h, "Authorization: Bearer [[credential:github]]\r\n")
	readAll(t, resp)
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get(ErrorHeader) != "upstream_error" {
		t.Fatalf("WebSocket: got %d %q", resp.StatusCode, resp.Header.Get(ErrorHeader))
	}
}

// A value replaced or removed stays scrubbed for the rest of the boot, the
// previous owner's after Replace(nil) included, and is never filled again.
func TestRetiredValuesStillScrubbed(t *testing.T) {
	const v1, v2 = "first-value-0123456789", "second-value-0123456789"
	entry := func(v string) *Entry {
		return &Entry{Name: "api", Hosts: []string{"example.com"},
			Positions: []Position{{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"}}, Value: []byte(v)}
	}
	ts, _ := upstream(t)
	h := newHarness(t, ts, entry(v1))
	reg := h.reg()
	if err := reg.Put(entry(v2)); err != nil {
		t.Fatal(err)
	}
	if got := string(reg.Scrub([]byte(v1))); got != "[[credential:api]]" {
		t.Fatalf("a value Put replaced: %q", got)
	}
	// The proxy redacts it too.
	req, _ := http.NewRequest("POST", h.explicitURL("/echo"), strings.NewReader("old "+v1))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if body := readAll(t, resp); strings.Contains(body, v1) {
		t.Fatalf("a retired value came back: %s", body)
	}
	// Loading the same value again retires nothing.
	n := reg.Len()
	for i := 0; i < 3; i++ {
		if err := reg.Replace([]*Entry{entry(v2)}); err != nil {
			t.Fatal(err)
		}
	}
	if reg.Len() != n {
		t.Fatalf("Len %d, was %d", reg.Len(), n)
	}
	// The owner changed: every entry goes, its values are still scrubbed.
	if err := reg.Replace(nil); err != nil {
		t.Fatal(err)
	}
	if reg.Len() == 0 {
		t.Fatal("Len 0 after Replace(nil): scrubbing what sealed commits would stop")
	}
	in := v1 + " " + v2
	want := "[[credential:api]] [[credential:api]]"
	if got := string(reg.Scrub([]byte(in))); got != want {
		t.Fatalf("Scrub: %q", got)
	}
	if got, _ := io.ReadAll(reg.ScrubReader(strings.NewReader(in))); string(got) != want {
		t.Fatalf("ScrubReader: %q", got)
	}
	fr, _ := http.NewRequest("GET", "https://example.com/", nil)
	fr.Header.Set("Authorization", "Bearer [[credential:api]]")
	if _, _, _, ferr := reg.fillRequest(fr, "example.com", nil); ferr == nil || ferr.Code != "unknown_entry" {
		t.Fatalf("a retired value was fillable: %v", ferr)
	}
	// Bounded: the oldest go first.
	for i := 0; i < maxRetired+10; i++ {
		churn := fmt.Sprintf("churn%d", i)
		_ = reg.Put(&Entry{Name: churn, Hosts: []string{"churn.example"}, Value: []byte(fmt.Sprintf("churn-value-%06d", i))})
		reg.Delete(churn)
	}
	if reg.Len() > maxRetired+1 || string(reg.Scrub([]byte(v1))) != v1 {
		t.Fatalf("Len %d", reg.Len())
	}
}

// A value in a server control frame (a ping or pong payload, a close frame's
// reason) is masked like one in a data frame, length kept; the close code is
// kept as it is.
func TestWebSocketControlFramesMasked(t *testing.T) {
	ts := wsUpstream(t, switching, nil, func(conn net.Conn, buf *bufio.ReadWriter) {
		_, _ = conn.Write(wsFrame(0x9, []byte("p:"+secretValue)))
		_, _ = conn.Write(wsFrame(0xa, []byte(secretValue)))
		_, _ = conn.Write(wsFrame(0x8, append([]byte{0x0f, 0xa1}, "bad token "+secretValue...)))
		one := make([]byte, 1)
		_, _ = buf.Read(one)
	})
	h := newHarness(t, ts)
	conn, br, resp := wsDial(t, h, "Authorization: Bearer [[credential:github]]\r\n")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	stars := strings.Repeat("*", len(secretValue))
	for _, want := range []struct {
		b0      byte
		payload string
	}{
		{0x89, "p:" + stars},
		{0x8a, stars},
		{0x88, "\x0f\xa1bad token " + stars},
	} {
		if b0, p := readFrame(t, br); b0 != want.b0 || string(p) != want.payload {
			t.Fatalf("got %x %q, want %x %q", b0, p, want.b0, want.payload)
		}
	}
	_, _ = conn.Write([]byte("x"))
}

// A frame with an RSV bit set ends the relay: no extension is negotiated, so
// its payload may be in a form the proxy cannot read.
func TestWebSocketRSVEndsRelay(t *testing.T) {
	ts := wsUpstream(t, switching, nil, func(conn net.Conn, buf *bufio.ReadWriter) {
		_, _ = conn.Write(wsFrame(0x1, []byte("first")))
		f := wsFrame(0x1, []byte("rsv1 frame"))
		f[0] |= 0x40
		_, _ = conn.Write(f)
		_, _ = conn.Write(wsFrame(0x1, []byte("after")))
		one := make([]byte, 1)
		_, _ = buf.Read(one)
	})
	h := newHarness(t, ts)
	_, br, resp := wsDial(t, h, "")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if b0, p := readFrame(t, br); b0 != 0x81 || string(p) != "first" {
		t.Fatalf("first frame %x %q", b0, p)
	}
	if rest, err := io.ReadAll(br); err != nil || len(rest) != 0 {
		t.Fatalf("after an RSV frame: %q, %v", rest, err)
	}
}

// A JSON body is filled with every '&' and ';' of its own written as a \u
// escape: the same JSON to a JSON parser, and no field separator to a server
// that reads it as a form.
func TestJSONBodyFillHasNoFormSeparator(t *testing.T) {
	ts, got := upstream(t)
	h := newHarness(t, ts)
	for _, body := range []string{
		`{"x":";note=","token":"[[credential:github]]"}`,
		`{"cb":"https://x/y?a=1&b=2;c","token":"[[credential:github]]"}`,
	} {
		req, _ := http.NewRequest("POST", h.explicitURL("/x"), strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		out := readAll(t, resp)
		sent := got.snapshot().body
		if resp.StatusCode != 200 || strings.ContainsAny(sent, "&;") {
			t.Fatalf("%s: status %d (%s), upstream got %s", body, resp.StatusCode, out, sent)
		}
		var want, have map[string]any
		_ = json.Unmarshal([]byte(body), &want)
		want["token"] = secretValue
		if err := json.Unmarshal([]byte(sent), &have); err != nil || fmt.Sprint(have) != fmt.Sprint(want) {
			t.Fatalf("%s: upstream read %v, want %v", body, have, want)
		}
	}
}

// A form body is checked for url-encoding once filled, so a placeholder
// written raw as the whole value of a field is filled.
func TestFormBodyRawPlaceholderFilled(t *testing.T) {
	ts, got := upstream(t)
	h := newHarness(t, ts)
	req, _ := http.NewRequest("POST", h.explicitURL("/x"), strings.NewReader(`a=1&token=[[credential:github]]`))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out := readAll(t, resp)
	if g := got.snapshot(); resp.StatusCode != 200 || g.body != "a=1&token="+url.QueryEscape(secretValue) {
		t.Fatalf("status %d (%s), upstream got %q", resp.StatusCode, out, g.body)
	}
}

// A 6-byte value is redacted in base64 at each of the three alignments,
// e.g. inside an echoed Basic header.
func TestSixByteValueBase64(t *testing.T) {
	const v = "Xy7#q2"
	red := newRedactor(map[string][]byte{"pw": []byte(v)})
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for k := 0; k < 3; k++ {
			full := enc.EncodeToString(append(append(make([]byte, k), v...), "tail"...))
			inner := full[(8*k+5)/6 : 8*(k+len(v))/6]
			if out := red.applyString(full); strings.Contains(out, inner) {
				t.Errorf("alignment %d: %s came back as %s", k, full, out)
			}
		}
	}

	ts, _ := upstream(t)
	h := newHarness(t, ts, &Entry{Name: "pw", Hosts: []string{"example.com"},
		Positions: []Position{{Kind: PosBasic, Username: "a"}}, Value: []byte(v)})
	req, _ := http.NewRequest("GET", h.explicitURL("/"), nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("a:[[credential:pw]]")))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	echo := strings.TrimPrefix(resp.Header.Get("X-Echo"), "Basic ")
	if dec, _ := base64.StdEncoding.DecodeString(echo); resp.StatusCode != 200 || strings.Contains(string(dec), v) {
		t.Fatalf("status %d, echoed Basic header %q decodes to %q", resp.StatusCode, echo, dec)
	}
}

// The refusal of an encoded response does not quote upstream's
// Content-Encoding.
func TestEncodedResponseRefusalQuotesNothing(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte("x"))
	}))
	ts.StartTLS()
	t.Cleanup(ts.Close)
	h := newHarness(t, ts)
	req, _ := http.NewRequest("GET", h.explicitURL("/"), nil)
	req.Header.Set("Authorization", "Bearer [[credential:github]]")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if body := readAll(t, resp); resp.StatusCode != http.StatusBadGateway || strings.Contains(body, "Bearer") {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
}

// chunkReader returns its chunks one per Read.
type chunkReader [][]byte

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(*c) == 0 {
		return 0, io.EOF
	}
	n := copy(p, (*c)[0])
	if n < len((*c)[0]) {
		(*c)[0] = (*c)[0][n:]
	} else {
		*c = (*c)[1:]
	}
	return n, nil
}

// Where one value is a prefix of another, a stream split anywhere in the
// longer one, just after the shorter one included, redacts the longer one
// whole.
func TestRedactorValueThatIsAPrefixOfAnother(t *testing.T) {
	const a, b = "shared-prefix-0123", "shared-prefix-0123-tail-SECRET"
	red := newProxyRedactor(map[string][]byte{"a": []byte(a), "b": []byte(b)})
	stream := "x " + b + " y " + a + " z"
	want := "x [[credential:b]] y [[credential:a]] z"
	for split := 1; split < len(stream); split++ {
		src := &chunkReader{[]byte(stream[:split]), []byte(stream[split:])}
		if out, _ := io.ReadAll(red.reader(src)); string(out) != want {
			t.Fatalf("split %d: %q", split, out)
		}
	}
	if out := red.applyString(stream); out != want {
		t.Fatalf("whole: %q", out)
	}
}

// The explicit form refuses a target host holding a control character or a
// space once percent-decoded, before it reaches a message or the audit log.
func TestExplicitHostWithControlCharactersRefused(t *testing.T) {
	ts, _ := upstream(t)
	h := newHarness(t, ts)
	for _, host := range []string{"exa%20mple.com", "example.com%0d%0aX-Injected:%201", "%09example.com", "example.com%7f", "example.com%c2%85", "example.com%e2%80%ae"} {
		before := len(h.records())
		req, _ := http.NewRequest("GET", "http://"+h.addr+"/"+h.token+"/https/"+host+"/x", nil)
		req.Header.Set("Authorization", "Bearer [[credential:github]]")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		readAll(t, resp)
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get(ErrorHeader) != "bad_target" || len(h.records()) != before {
			t.Fatalf("%s: got %d %q, records %+v", host, resp.StatusCode, resp.Header.Get(ErrorHeader), h.records()[before:])
		}
	}
}

// A path segment that is a placeholder once percent-decoded is filled, like
// a query parameter or a form field, whichever bytes of it are escaped.
func TestPathPlaceholderPercentEncodedFilled(t *testing.T) {
	ts, got := upstream(t)
	h := newHarness(t, ts)
	resp, err := http.Get(h.explicitURL("/%5B%5B%63redential%3Agithub%5D%5D/x"))
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if g := got.snapshot(); resp.StatusCode != 200 || g.path != "/"+secretValue+"/x" {
		t.Fatalf("status %d, upstream path %q", resp.StatusCode, g.path)
	}
}

// A placeholder anywhere in a body too large to fill is refused, past the
// first 64 KiB too: the upload stops there and the request is answered 413.
// A large body naming none goes through whole.
func TestBigBodyPlaceholderPastFirstChunkRefused(t *testing.T) {
	ts, got := upstream(t)
	h := newHarness(t, ts)
	pad := strings.Repeat("a", maxBodyBytes+10)
	for _, ph := range []string{"[[credential:github]]", "%5B%5Bcredential%3Agithub%5D%5D", `[[credential:github]]`} {
		req, _ := http.NewRequest("POST", h.explicitURL("/x"), strings.NewReader(`{"pad":"`+pad+`","token":"`+ph+`"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		readAll(t, resp)
		if resp.StatusCode != http.StatusRequestEntityTooLarge || resp.Header.Get(ErrorHeader) != "body_too_large" {
			t.Fatalf("%s: got %d %q", ph, resp.StatusCode, resp.Header.Get(ErrorHeader))
		}
		if rec := h.lastRecord(t); rec.Code != "body_too_large" || len(rec.Names) != 1 || rec.Names[0] != "github" {
			t.Fatalf("%s: audit record %+v", ph, rec)
		}
	}
	body := `{"pad":"` + pad + `","note":"[[credential"}`
	req, _ := http.NewRequest("POST", h.explicitURL("/x"), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if resp.StatusCode != 200 || got.snapshot().body != body {
		t.Fatalf("a large body naming no placeholder: status %d", resp.StatusCode)
	}
}

// The listener serves at most MaxConns connections at once; the next one
// waits until one of them closes.
func TestConnectionCap(t *testing.T) {
	ts, _ := upstream(t)
	h := newHarnessWith(t, ts, func(c *Config) { c.MaxConns = 2 })
	get := "GET /" + h.token + "/https/example.com/x HTTP/1.1\r\nHost: " + h.addr + "\r\n\r\n"
	var open []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", h.addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write([]byte(get))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		readAll(t, resp)
		open = append(open, c)
	}
	third, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { third.Close() })
	_, _ = third.Write([]byte(get))
	_ = third.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var ne net.Error
	if n, err := third.Read(make([]byte, 1)); n != 0 || !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("a connection over the cap was served: %d %v", n, err)
	}
	open[0].Close()
	_ = third.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(third), nil)
	if err != nil {
		t.Fatalf("not served once a connection closed: %v", err)
	}
	readAll(t, resp)
}

// A CONNECT tunnel or a WebSocket relay is closed once no bytes have moved
// either way for RelayIdleTimeout; one with bytes moving stays open past it.
func TestRelayIdleTimeout(t *testing.T) {
	const idle = 500 * time.Millisecond
	waitClosed := func(t *testing.T, r io.Reader) {
		t.Helper()
		start := time.Now()
		_, err := io.Copy(io.Discard, r)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("not closed after %v", time.Since(start))
		}
	}
	t.Run("tunnel", func(t *testing.T) {
		ts, _ := upstream(t)
		h := newHarnessWith(t, ts, func(c *Config) { c.RelayIdleTimeout = idle })
		conn, err := net.Dial("tcp", h.addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		auth := base64.StdEncoding.EncodeToString([]byte("agent:" + h.token))
		_, _ = conn.Write([]byte("CONNECT not-listed.example:443 HTTP/1.1\r\nHost: not-listed.example:443\r\nProxy-Authorization: Basic " + auth + "\r\n\r\n"))
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("CONNECT: %v %v", resp, err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(ts.Certificate())
		tc := tls.Client(conn, &tls.Config{RootCAs: pool, ServerName: "example.com", NextProtos: []string{"http/1.1"}})
		tr := bufio.NewReader(tc)
		for i := 0; i < 8; i++ {
			time.Sleep(idle / 5)
			_, _ = tc.Write([]byte("GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n"))
			resp, err := http.ReadResponse(tr, nil)
			if err != nil {
				t.Fatalf("request %d through an active tunnel: %v", i, err)
			}
			readAll(t, resp)
		}
		waitClosed(t, tr)
	})
	t.Run("websocket", func(t *testing.T) {
		ts := wsUpstream(t, switching, nil, func(conn net.Conn, buf *bufio.ReadWriter) {
			for i := 0; i < 8; i++ {
				time.Sleep(idle / 5)
				_, _ = conn.Write(wsFrame(0x1, []byte("tick")))
			}
			one := make([]byte, 1)
			_, _ = buf.Read(one)
		})
		h := newHarnessWith(t, ts, func(c *Config) { c.RelayIdleTimeout = idle })
		_, br, resp := wsDial(t, h, "")
		if resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("status %d", resp.StatusCode)
		}
		for i := 0; i < 8; i++ {
			if _, p := readFrame(t, br); string(p) != "tick" {
				t.Fatalf("frame %d: %q", i, p)
			}
		}
		waitClosed(t, br)
	})
}

// Values retired from owner entries (an entry removed, the owner changed)
// stay scrubbed however often derived entries are replaced or deleted, and
// however often one value is rotated: that churn pushes out only values of
// derived entries, or the rotated entry's own earlier ones.
func TestRetiredOwnerValuesOutlastChurn(t *testing.T) {
	const removed, cleared = "removed-owner-value-0123", "cleared-owner-value-0123"
	entry := func(name, v string) *Entry {
		return &Entry{Name: name, Hosts: []string{"example.com"},
			Positions: []Position{{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"}}, Value: []byte(v)}
	}
	reg := NewRegistry()
	for _, set := range [][]*Entry{{entry("api", removed), entry("other", cleared)}, {entry("other", cleared)}, nil} {
		if err := reg.Replace(set); err != nil {
			t.Fatal(err)
		}
	}
	n := 2 * (maxRetired + maxRetiredDerived)
	for i := 0; i < n; i++ {
		// A token request replacing a derived entry, and a derived entry
		// obtained and deleted.
		_ = reg.Put(entry("derived:gh.access_token", fmt.Sprintf("derived-value-%06d", i)))
		_ = reg.Put(entry(fmt.Sprintf("derived:x%d", i), fmt.Sprintf("deleted-value-%06d", i)))
		reg.Delete(fmt.Sprintf("derived:x%d", i))
		// A refresh token rotated by a token request.
		_ = reg.Replace([]*Entry{entry("rt", fmt.Sprintf("rotated-value-%06d", i))})
	}
	for _, v := range []string{removed, cleared} {
		if got := string(reg.Scrub([]byte(v))); got == v {
			t.Fatalf("%s is no longer scrubbed", v)
		}
	}
	if l := reg.Len(); l > 1+maxRetired+maxRetiredDerived {
		t.Fatalf("Len %d", l)
	}
	// The newest values of the churned names are still scrubbed.
	for _, v := range []string{fmt.Sprintf("derived-value-%06d", n-2), fmt.Sprintf("rotated-value-%06d", n-2)} {
		if got := string(reg.Scrub([]byte(v))); got == v {
			t.Fatalf("%s is no longer scrubbed", v)
		}
	}
}

// waitUntil polls cond until it holds, failing the test after d.
func waitUntil(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(d); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// blockingUpstream counts the requests in flight to it and holds every
// request for /block until release is closed (on cleanup at the latest).
func blockingUpstream(t *testing.T) (ts *httptest.Server, inflight, peak *atomic.Int64, release func()) {
	t.Helper()
	inflight, peak = new(atomic.Int64), new(atomic.Int64)
	ch := make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(ch) }) }
	ts = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inflight.Add(1)
		defer inflight.Add(-1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		if r.URL.Path == "/block" {
			<-ch
		}
	}))
	ts.StartTLS()
	t.Cleanup(ts.Close)
	t.Cleanup(release) // runs first, so Close does not wait on a held request
	return ts, inflight, peak, release
}

// One terminated HTTP/2 connection carries at most MaxStreamsPerConn
// requests at once, however many the client starts on it.
func TestHTTP2StreamsPerConnectionCapped(t *testing.T) {
	ts, _, peak, release := blockingUpstream(t)
	h := newHarnessWith(t, ts, func(c *Config) { c.MaxConns = 1; c.IdleTimeout = 200 * time.Millisecond })
	c := h.interceptClient(h.token)
	const n = defaultMaxStreamsPerConn + 8
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			req, _ := http.NewRequest("GET", "https://example.com/block", nil)
			req.Header.Set("Authorization", "Bearer [[credential:github]]")
			resp, err := c.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK || resp.Proto != "HTTP/2.0" {
					err = fmt.Errorf("%s %d", resp.Proto, resp.StatusCode)
				}
			}
			errs <- err
		}()
	}
	waitUntil(t, 10*time.Second, "requests upstream", func() bool { return peak.Load() >= defaultMaxStreamsPerConn })
	time.Sleep(300 * time.Millisecond)
	got := peak.Load()
	release()
	if got != defaultMaxStreamsPerConn {
		t.Fatalf("%d requests in flight upstream over one connection, want %d", got, defaultMaxStreamsPerConn)
	}
	for i := 0; i < n; i++ {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("a request waiting for a stream never completed")
		}
	}
}

// The requests the proxy works on at once are capped across connections: over
// the cap a request is answered 503 busy at once. The slots reserved for
// requests that fill sealed: entries alone stay free for them, and a request
// that fills another entry as well cannot take one.
func TestRequestCapReservesSealedSlots(t *testing.T) {
	ts, inflight, _, release := blockingUpstream(t)
	github := &Entry{Name: "github", Hosts: []string{"example.com"}, Value: []byte(secretValue), Positions: []Position{
		{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"}, {Kind: PosBody, Field: "token"}}}
	inference := &Entry{Name: "sealed:inference", Hosts: []string{"example.com"}, Value: []byte("sealed-inference-key-0123"),
		Positions: []Position{{Kind: PosHeader, Name: "x-api-key", Template: "{v}"}}}
	h := newHarnessWith(t, ts, func(c *Config) { c.MaxRequests = 4; c.ReservedRequests = 2 }, github, inference)

	send := func(method, path, header, value, body string) *http.Response {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, h.explicitURL(path), rd)
		if header != "" {
			req.Header.Set(header, value)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		readAll(t, resp)
		return resp
	}
	held := make(chan int, 4)
	hold := func(header, value string) {
		go func() {
			req, _ := http.NewRequest("GET", h.explicitURL("/block"), nil)
			req.Header.Set(header, value)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				held <- 0
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			held <- resp.StatusCode
		}()
	}
	busy := func(what string, resp *http.Response) {
		t.Helper()
		if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get(ErrorHeader) != "busy" || resp.Header.Get("Retry-After") == "" {
			t.Fatalf("%s: got %d %q", what, resp.StatusCode, resp.Header.Get(ErrorHeader))
		}
	}

	// Two general slots, both taken.
	hold("Authorization", "Bearer [[credential:github]]")
	hold("Authorization", "Bearer [[credential:github]]")
	waitUntil(t, 5*time.Second, "two requests upstream", func() bool { return inflight.Load() == 2 })
	busy("a third request", send("GET", "/x", "Authorization", "Bearer [[credential:github]]", ""))
	if rec := h.lastRecord(t); rec.Code != "busy" || rec.Status != http.StatusServiceUnavailable || len(rec.Names) != 1 || rec.Names[0] != "github" {
		t.Fatalf("audit record %+v", rec)
	}
	busy("a request naming no entry", send("GET", "/x", "", "", ""))
	busy("a request whose body fills another entry", send("POST", "/x", "x-api-key", "[[credential:sealed:inference]]", `{"token":"[[credential:github]]"}`))
	if resp := send("GET", "/x", "x-api-key", "[[credential:sealed:inference]]", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("a request filling sealed:inference alone: got %d %q", resp.StatusCode, resp.Header.Get(ErrorHeader))
	}

	// The reserved slots taken too: nothing more goes.
	hold("x-api-key", "[[credential:sealed:inference]]")
	hold("x-api-key", "[[credential:sealed:inference]]")
	waitUntil(t, 5*time.Second, "four requests upstream", func() bool { return inflight.Load() == 4 })
	busy("a fifth request", send("GET", "/x", "x-api-key", "[[credential:sealed:inference]]", ""))

	// Every slot is given back.
	release()
	for i := 0; i < 4; i++ {
		if code := <-held; code != http.StatusOK {
			t.Fatalf("a held request: got %d", code)
		}
	}
	for i := 0; i < 4; i++ {
		if resp := send("GET", "/x", "Authorization", "Bearer [[credential:github]]", ""); resp.StatusCode != http.StatusOK {
			t.Fatalf("after release: got %d %q", resp.StatusCode, resp.Header.Get(ErrorHeader))
		}
	}
}

// The part of a body the proxy buffers to fill must arrive within
// BodyReadTimeout: a request whose body stalls is answered 408 and gives its
// request slot back.
func TestBufferedBodyReadTimeout(t *testing.T) {
	ts, _ := upstream(t)
	h := newHarnessWith(t, ts, func(c *Config) { c.BodyReadTimeout = 300 * time.Millisecond; c.MaxRequests = 1 })
	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte("POST /" + h.token + "/https/example.com/x HTTP/1.1\r\nHost: " + h.addr +
		"\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"token\":"))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("a stalled body got no answer: %v", err)
	}
	readAll(t, resp)
	if resp.StatusCode != http.StatusRequestTimeout || resp.Header.Get(ErrorHeader) != "bad_request" {
		t.Fatalf("got %d %q", resp.StatusCode, resp.Header.Get(ErrorHeader))
	}
	resp, err = http.Get(h.explicitURL("/x"))
	if err != nil {
		t.Fatal(err)
	}
	if readAll(t, resp); resp.StatusCode != http.StatusOK {
		t.Fatalf("the next request: got %d %q", resp.StatusCode, resp.Header.Get(ErrorHeader))
	}
}

// A request head over 64 KiB is refused, on the listener and on a
// terminated connection (HTTP/1.1 and HTTP/2); one well under it goes out.
func TestRequestHeadSizeCapped(t *testing.T) {
	ts, _ := upstream(t)
	h := newHarness(t, ts)
	clients := map[string]*http.Client{"explicit": http.DefaultClient, "h2": h.interceptClient(h.token), "h1": h.interceptClient(h.token)}
	clients["h1"].Transport.(*http.Transport).ForceAttemptHTTP2 = false
	for name, c := range clients {
		for _, size := range []int{16 << 10, 100 << 10} {
			target := "https://example.com/x"
			if name == "explicit" {
				target = h.explicitURL("/x")
			}
			req, _ := http.NewRequest("GET", target, nil)
			req.Header.Set("X-Pad", strings.Repeat("p", size))
			resp, err := c.Do(req)
			status := 0
			if err == nil {
				// The server closes the connection after a 431.
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				status = resp.StatusCode
			}
			// Over HTTP/2 the client itself refuses a head over the limit the
			// proxy advertises.
			if refused := status != http.StatusOK; refused != (size > maxHeaderBytes) {
				t.Fatalf("%s, %d-byte header: status %d, err %v", name, size, status, err)
			}
		}
	}
}

// A header whose name holds a value is dropped, whatever the case the name
// comes back in (Go canonicalizes it, HTTP/2 lower-cases it).
func TestResponseHeaderNameWithValueDroppedInAnyCase(t *testing.T) {
	const hexValue, mixedValue = "deadbeefcafebabe0123456789abcdef", "MiXeD-cAsE-vAlUe-0123"
	for _, h2 := range []bool{false, true} {
		ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			w.Header()["X-Echo-"+v] = []string{"1"}
			w.Header()["X-Upper-"+strings.ToUpper(v)] = []string{"1"}
			w.Header().Set("X-Kept", "1")
		}))
		ts.EnableHTTP2 = h2
		ts.StartTLS()
		t.Cleanup(ts.Close)
		entry := func(name, v string) *Entry {
			return &Entry{Name: name, Hosts: []string{"example.com"}, Value: []byte(v),
				Positions: []Position{{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"}}}
		}
		h := newHarness(t, ts, entry("hex", hexValue), entry("mixed", mixedValue))
		for name, v := range map[string]string{"hex": hexValue, "mixed": mixedValue} {
			req, _ := http.NewRequest("GET", h.explicitURL("/"), nil)
			req.Header.Set("Authorization", "Bearer [[credential:"+name+"]]")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			readAll(t, resp)
			for k := range resp.Header {
				if strings.Contains(strings.ToLower(k), strings.ToLower(v)) {
					t.Fatalf("HTTP/2 upstream %v: a value came back in header name %q", h2, k)
				}
			}
			if resp.Header.Get("X-Kept") != "1" {
				t.Fatalf("HTTP/2 upstream %v: other headers were dropped too: %v", h2, resp.Header)
			}
		}
	}
}

// Streamed, a response is redacted as it is whole, wherever reads split it:
// also where one value lies inside another, is a prefix of it, or overlaps
// it.
func TestRedactorStreamMatchesWhole(t *testing.T) {
	for _, c := range []struct {
		values map[string][]byte
		stream string
	}{
		{map[string][]byte{"in": []byte("inner-secret-0123"), "out": []byte("OUTERHEAD-inner-secret-0123-OUTERTAIL")},
			"x OUTERHEAD-inner-secret-0123-OUTERTAIL y inner-secret-0123 z OUTERHEAD-inner-secret-0123-OUTER"},
		{map[string][]byte{"a": []byte("shared-prefix-0123"), "b": []byte("shared-prefix-0123-tail-SECRET")},
			"x shared-prefix-0123-tail-SECRET y shared-prefix-0123 z shared-prefix-0123-tail"},
		{map[string][]byte{"a": []byte("overlap-left-0123"), "b": []byte("left-0123-and-right")},
			"x overlap-left-0123-and-right y left-0123-and-right z overlap-left-0123"},
	} {
		red := newProxyRedactor(c.values)
		want := red.applyString(c.stream)
		for _, v := range c.values {
			if strings.Contains(want, string(v)) {
				t.Fatalf("whole: %q", want)
			}
		}
		for split := 1; split < len(c.stream); split++ {
			src := &chunkReader{[]byte(c.stream[:split]), []byte(c.stream[split:])}
			if out, _ := io.ReadAll(red.reader(src)); string(out) != want {
				t.Fatalf("split %d: %q, whole %q", split, out, want)
			}
		}
		var bytewise chunkReader
		for i := range c.stream {
			bytewise = append(bytewise, []byte{c.stream[i]})
		}
		if out, _ := io.ReadAll(red.reader(&bytewise)); string(out) != want {
			t.Fatalf("byte by byte: %q, whole %q", out, want)
		}
	}
}

// bodyScan finds a placeholder in a large body exactly when the whole body
// names one, wherever reads split it: also where the tail it keeps between
// reads would start inside a run of backslashes before an escaped
// placeholder.
func TestBodyScanSplitInBackslashRun(t *testing.T) {
	var opening string
	for _, c := range "[[credential:" {
		opening += fmt.Sprintf(`\u%04x`, c)
	}
	pad := strings.Repeat("a", 100)
	for _, run := range []int{0, 1, 2, 3, 4, 100, 101} {
		body := pad + strings.Repeat(`\`, run) + opening + `github]]"}`
		want := mentionsPlaceholder([]byte(body))
		if want != (run%2 == 0) {
			t.Fatalf("run %d: the whole body names a placeholder: %v", run, want)
		}
		for split := 1; split < len(body); split++ {
			b := &bodyScan{r: &chunkReader{[]byte(body[:split]), []byte(body[split:])}, c: io.NopCloser(nil)}
			_, _ = io.ReadAll(b)
			if found, _ := b.result(); found != want {
				t.Fatalf("run %d, split %d: found %v, want %v", run, split, found, want)
			}
		}
	}
}

// A value reflected by a JSON encoder other than Go's is redacted: plus
// sign, apostrophe, equals sign and backtick escaped, \u hex in upper case.
func TestRedactorJSONEscapesOfOtherEncoders(t *testing.T) {
	for v, forms := range map[string][]string{
		"AbCd+EfGh/IjKl<0123": {
			"AbCd\\u002BEfGh/IjKl\\u003C0123",   // System.Text.Json
			"AbCd+EfGh/IjKl\\u003C0123",         // upper-case hex HTML escapes
			"AbCd+EfGh\\/IjKl\\u003C0123",       // the same, '/' escaped (PHP)
			"AbCd\\u002bEfGh\\/IjKl\\u003c0123", // every escape, lower case
		},
		"Ab+Cd='Ef`Gh<0123": {
			"Ab\\u002BCd=\\u0027Ef\\u0060Gh\\u003C0123",       // System.Text.Json
			"Ab+Cd\\u003d\\u0027Ef`Gh\\u003c0123",             // Gson
			"Ab+Cd=\\u0027Ef`Gh\\u003c0123",                   // Json.NET with EscapeHtml
			"Ab\\u002BCd\\u003D\\u0027Ef\\u0060Gh\\u003C0123", // every escape, upper case
		},
	} {
		red := newProxyRedactor(map[string][]byte{"k": []byte(v)})
		for _, form := range forms {
			if got := red.applyString(`{"echo":"` + form + `"}`); got != `{"echo":"[[credential:k]]"}` {
				t.Errorf("%s: got %s", form, got)
			}
		}
	}
}

// A value over MaxValueLen is not held: each value is kept in many encoded
// forms for redaction.
func TestValueSizeCapped(t *testing.T) {
	big := &Entry{Name: "big", Hosts: []string{"api.example"}, Use: UseInject, Value: bytes.Repeat([]byte("a"), MaxValueLen+1),
		Positions: []Position{{Kind: PosHeader, Name: "Authorization", Template: "Bearer {v}"}}}
	if err := NewRegistry().Put(big); err == nil {
		t.Fatal("a value over the cap was held")
	}
}

// A value of bytes no encoder escapes is its own JSON form in every
// encoder's style, which is why jsonStrings skips running them for it.
func TestPlainValueIsItsOwnJSONForm(t *testing.T) {
	const v = "ghp_AbC123-def.GHI~xyz"
	if !plainJSON(v) {
		t.Fatal("not plain")
	}
	if q, _ := json.Marshal(v); string(q[1:len(q)-1]) != v {
		t.Fatalf("encoding/json: %s", q)
	}
	for _, p := range jsonProfiles {
		if got := p.quote(v); got != v {
			t.Fatalf("%+v: %q", p, got)
		}
	}
}
