package credproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Record is one request that carried credentials, for the audit log. It never
// holds a value.
type Record struct {
	Time   time.Time
	Names  []string
	Host   string
	Method string
	Status int
	Code   string // refusal code; empty when the request went out
}

// Config wires a Server.
type Config struct {
	Registry *Registry
	CA       *CA
	// Token is the per-boot access token: the first path segment of the
	// explicit form, and the Basic password of Proxy-Authorization.
	Token string
	Logf  func(string, ...any)
	// OnUse receives every request that named a credential, filled or refused.
	OnUse func(Record)
	// Dial dials upstream. Nil dials directly, refusing private, loopback,
	// link-local and metadata addresses. Tests override it.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// UpstreamTLS overrides the TLS config used toward upstream (tests).
	UpstreamTLS *tls.Config
}

// Server is the proxy. It is an http.Handler for the loopback listener.
type Server struct {
	cfg       Config
	transport *http.Transport
}

// ErrPrivateAddress is returned by SafeDial for a refused address.
var ErrPrivateAddress = errors.New("target resolves to a private, loopback, link-local or metadata address")

// New builds a Server.
func New(cfg Config) *Server {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	s := &Server{cfg: cfg}
	s.transport = &http.Transport{
		DialContext:         s.dial,
		TLSClientConfig:     cfg.UpstreamTLS,
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
		MaxIdleConns:        64,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	return s
}

// Serve accepts on ln until it is closed.
func (s *Server) Serve(ln net.Listener) error {
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	return srv.Serve(ln)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.connect(w, r)
		return
	}
	s.explicit(w, r)
}

func tokenEqual(got, want string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// explicit serves http://127.0.0.1:<port>/<token>/https/<host>/<path>?<query>.
func (s *Server) explicit(w http.ResponseWriter, r *http.Request) {
	segs := strings.SplitN(strings.TrimPrefix(r.URL.EscapedPath(), "/"), "/", 4)
	if len(segs) < 1 || !tokenEqual(segs[0], s.cfg.Token) {
		writeErr(w, refuse(http.StatusProxyAuthRequired, "proxy_auth", "missing or wrong access token"))
		return
	}
	if len(segs) < 3 || segs[1] != "https" {
		writeErr(w, refuse(http.StatusBadRequest, "bad_target", "path must be /<token>/https/<host>/<path>"))
		return
	}
	rawHost, uerr := url.PathUnescape(segs[2])
	if uerr != nil || rawHost == "" || strings.ContainsAny(rawHost, "@/?#") {
		writeErr(w, refuse(http.StatusBadRequest, "bad_target", "invalid host"))
		return
	}
	host := NormalizeHost(rawHost)
	rest := "/"
	if len(segs) == 4 {
		rest = "/" + segs[3]
	}
	out := r.Clone(r.Context())
	path, perr := url.PathUnescape(rest)
	if perr != nil {
		writeErr(w, refuse(http.StatusBadRequest, "bad_target", "invalid path"))
		return
	}
	out.URL = &url.URL{Scheme: "https", Host: host, Path: path, RawPath: rest, RawQuery: r.URL.RawQuery}
	out.Host = host
	s.forward(w, out, host)
}

// connect handles CONNECT: hosts an entry names are terminated and filled,
// every other host is tunnelled untouched.
func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	if !s.proxyAuthOK(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="sealed"`)
		writeErr(w, refuse(http.StatusProxyAuthRequired, "proxy_auth", "missing or wrong access token"))
		return
	}
	target := r.Host
	if target == "" || strings.Contains(target, "@") {
		writeErr(w, refuse(http.StatusBadRequest, "bad_target", "invalid CONNECT target"))
		return
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	host := NormalizeHost(target)
	hj, ok := w.(http.Hijacker)
	if !ok {
		writeErr(w, refuse(http.StatusInternalServerError, "internal", "connection cannot be taken over"))
		return
	}
	if !s.cfg.Registry.InterceptsHost(host) {
		s.tunnel(w, hj, r, target)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		conn.Close()
		return
	}
	s.terminate(&bufferedConn{Conn: conn, r: buf.Reader}, host)
}

func (s *Server) proxyAuthOK(r *http.Request) bool {
	h := r.Header.Get("Proxy-Authorization")
	if len(h) < 6 || !strings.EqualFold(h[:6], "Basic ") {
		return false
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[6:]))
	if err != nil {
		return false
	}
	_, pass, _ := strings.Cut(string(dec), ":")
	return tokenEqual(pass, s.cfg.Token)
}

func (s *Server) tunnel(w http.ResponseWriter, hj http.Hijacker, r *http.Request, target string) {
	up, err := s.dial(r.Context(), "tcp", target)
	if err != nil {
		if errors.Is(err, ErrPrivateAddress) {
			writeErr(w, refuse(http.StatusForbidden, "private_address", "%s", ErrPrivateAddress.Error()))
		} else {
			writeErr(w, refuse(http.StatusBadGateway, "upstream_error", "cannot reach %s", target))
		}
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		conn.Close()
		up.Close()
		return
	}
	var once sync.Once
	closeBoth := func() { conn.Close(); up.Close() }
	go func() {
		_, _ = io.Copy(up, buf.Reader)
		once.Do(closeBoth)
	}()
	_, _ = io.Copy(conn, up)
	once.Do(closeBoth)
}

// terminate speaks TLS to the client with a leaf for host from the per-boot
// CA, then serves HTTP/1.1 or HTTP/2 (as the client negotiates) on that one
// connection.
func (s *Server) terminate(conn net.Conn, host string) {
	hostname := hostOnly(host)
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if NormalizeHost(hello.ServerName) != hostname {
				return nil, fmt.Errorf("SNI %q does not match CONNECT target %q", hello.ServerName, hostname)
			}
			return s.cfg.CA.leaf(hostname)
		},
	}
	ln := newOneConnListener(tls.Server(conn, tlsCfg))
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.intercepted(w, r, host) }),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
		ConnState: func(_ net.Conn, st http.ConnState) {
			if st == http.StateClosed || st == http.StateHijacked {
				ln.Close()
			}
		},
	}
	_ = srv.Serve(ln)
}

func (s *Server) intercepted(w http.ResponseWriter, r *http.Request, host string) {
	if NormalizeHost(r.Host) != host && NormalizeHost(r.Host) != hostOnly(host) {
		writeErr(w, refuse(http.StatusMisdirectedRequest, "target_mismatch", "Host %q does not match CONNECT target %q", r.Host, host))
		return
	}
	out := r.Clone(r.Context())
	u := *r.URL
	u.Scheme, u.Host = "https", host
	out.URL = &u
	out.Host = r.Host
	s.forward(w, out, host)
}

// hopHeaders are connection-scoped and never forwarded.
var hopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func stripHop(h http.Header) {
	for _, k := range hopHeaders {
		h.Del(k)
	}
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "proxy-") {
			h.Del(k)
		}
	}
}

func isWebSocket(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// forward fills r (already pointed at https://host), sends it, and streams
// the response back redacted.
func (s *Server) forward(w http.ResponseWriter, r *http.Request, host string) {
	small, large, berr := readBody(r)
	if berr != nil {
		writeErr(w, berr)
		return
	}
	ws := isWebSocket(r)
	out := r.Clone(r.Context())
	out.RequestURI = ""
	stripHop(out.Header)
	body, names, ferr := s.cfg.Registry.fillRequest(out, host, small)
	if ferr != nil {
		s.record(names, host, r.Method, ferr.Status, ferr.Code)
		writeErr(w, ferr)
		return
	}
	if large != nil {
		out.Body = large
		out.ContentLength = r.ContentLength
	} else {
		out.Body = io.NopCloser(bytes.NewReader(body))
		out.ContentLength = int64(len(body))
		out.Header.Del("Content-Length")
		if len(body) == 0 {
			out.Body = http.NoBody
		}
	}
	out.Header.Set("Accept-Encoding", "identity")
	if ws {
		s.websocket(w, out, host, names)
		return
	}

	resp, err := s.transport.RoundTrip(out)
	if err != nil {
		e := refuse(http.StatusBadGateway, "upstream_error", "upstream request to %s failed", host)
		if errors.Is(err, ErrPrivateAddress) {
			e = refuse(http.StatusForbidden, "private_address", "%s", ErrPrivateAddress.Error())
		}
		s.record(names, host, r.Method, e.Status, e.Code)
		writeErr(w, e)
		return
	}
	defer resp.Body.Close()
	if ce := strings.TrimSpace(resp.Header.Get("Content-Encoding")); ce != "" && !strings.EqualFold(ce, "identity") {
		e := refuse(http.StatusBadGateway, "upstream_error", "upstream sent an encoded body (%s) that cannot be redacted", ce)
		s.record(names, host, r.Method, e.Status, e.Code)
		writeErr(w, e)
		return
	}
	red := newRedactor(s.cfg.Registry.secrets())
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, red.applyString(v))
		}
	}
	stripHop(w.Header())
	w.Header().Del("Content-Length")
	w.WriteHeader(resp.StatusCode)
	s.record(names, host, r.Method, resp.StatusCode, "")
	copyFlush(w, red.reader(resp.Body))
}

// copyFlush streams src to w, flushing after every read so event streams
// reach the client as they arrive.
func copyFlush(w http.ResponseWriter, src io.Reader) {
	fl, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// websocket relays an upgraded HTTP/1.1 connection. The extension header is
// dropped so frames stay uncompressed, and values in server frames are masked
// byte-for-byte, which keeps every frame length intact.
func (s *Server) websocket(w http.ResponseWriter, out *http.Request, host string, names []string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		writeErr(w, refuse(http.StatusBadRequest, "bad_target", "WebSocket needs HTTP/1.1 toward the proxy"))
		return
	}
	out.Header.Set("Connection", "Upgrade")
	out.Header.Set("Upgrade", "websocket")
	out.Header.Del("Sec-WebSocket-Extensions")
	resp, err := s.transport.RoundTrip(out)
	if err != nil {
		s.record(names, host, out.Method, http.StatusBadGateway, "upstream_error")
		writeErr(w, refuse(http.StatusBadGateway, "upstream_error", "upstream request to %s failed", host))
		return
	}
	s.record(names, host, out.Method, resp.StatusCode, "")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer resp.Body.Close()
		red := newRedactor(s.cfg.Registry.secrets())
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, red.applyString(v))
			}
		}
		stripHop(w.Header())
		w.Header().Del("Content-Length")
		w.WriteHeader(resp.StatusCode)
		copyFlush(w, red.reader(resp.Body))
		return
	}
	up, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		resp.Body.Close()
		return
	}
	defer up.Close()
	resp.Header.Del("Sec-WebSocket-Extensions")
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	resp.Body = nil
	if err := resp.Write(conn); err != nil {
		return
	}
	mask := newMaskRedactor(s.cfg.Registry.secrets())
	go func() {
		_, _ = io.Copy(up, buf.Reader)
		up.Close()
	}()
	_, _ = io.Copy(conn, mask.reader(up))
}

func (s *Server) record(names []string, host, method string, status int, code string) {
	if s.cfg.OnUse == nil || len(names) == 0 {
		return
	}
	s.cfg.OnUse(Record{Time: time.Now(), Names: names, Host: host, Method: method, Status: status, Code: code})
}

// readBody buffers a body up to maxBodyBytes so placeholders in it can be
// filled. A larger body is passed through untouched; if its first bytes
// already show a placeholder it is refused instead, so a value is never left
// unfilled without the harness hearing about it.
func readBody(r *http.Request) ([]byte, io.ReadCloser, *Error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil, nil
	}
	head, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return nil, nil, refuse(http.StatusBadRequest, "bad_request", "cannot read request body")
	}
	if len(head) <= maxBodyBytes {
		return head, nil, nil
	}
	if bytes.Contains(head, []byte("[[credential:")) || bytes.Contains(bytes.ToUpper(head), bytes.ToUpper(encodedPlaceholder)) {
		return nil, nil, refuse(http.StatusRequestEntityTooLarge, "body_too_large", "a placeholder in a body over %d bytes cannot be filled", maxBodyBytes)
	}
	return nil, struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(head), r.Body), r.Body}, nil
}

func writeErr(w http.ResponseWriter, e *Error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Seal-Credential-Error", e.Code)
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(e)
}

func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(host, "[]")
}

func (s *Server) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.cfg.Dial != nil {
		return s.cfg.Dial(ctx, network, addr)
	}
	return SafeDial(ctx, network, addr)
}

// SafeDial resolves addr and refuses any address sealed must never reach on
// the agent's behalf (private, loopback, link-local, metadata), then dials
// the vetted IP, so a second lookup cannot swap in a different one.
func SafeDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if blockedIP(ip.IP) {
			return nil, ErrPrivateAddress
		}
	}
	var d net.Dialer
	var lastErr error
	for _, ip := range ips {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no address for %s", host)
	}
	return nil, lastErr
}

var blockedNets = func() []*net.IPNet {
	var out []*net.IPNet
	// IANA special-purpose ranges (RFC 6890) on top of what net.IP classifies.
	for _, c := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "fc00::/7"} { // privacy-check: allow
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

func blockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// bufferedConn returns bytes the hijacked reader already buffered before
// reading from the connection itself.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// oneConnListener hands out a single connection, then blocks until closed.
type oneConnListener struct {
	conn   net.Conn
	once   sync.Once
	closed chan struct{}
	close  sync.Once
}

func newOneConnListener(c net.Conn) *oneConnListener {
	return &oneConnListener{conn: c, closed: make(chan struct{})}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error {
	l.close.Do(func() { close(l.closed) })
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
