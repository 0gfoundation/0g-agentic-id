package credproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
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
	// IdleTimeout closes a client connection that stays idle this long
	// between requests (HTTP/1.1 keep-alive, or HTTP/2 with no stream
	// open); zero means defaultIdleTimeout. There is no read timeout: an
	// upload takes as long as it takes.
	IdleTimeout time.Duration
}

const defaultIdleTimeout = 2 * time.Minute

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
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTimeout
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
		IdleTimeout:       s.cfg.IdleTimeout,
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
			// A client sends no SNI for an IP address (RFC 6066); the Host
			// header is still checked against the CONNECT target.
			if hello.ServerName == "" && net.ParseIP(hostname) != nil {
				return s.cfg.CA.leaf(hostname)
			}
			if NormalizeHost(hello.ServerName) != hostname {
				return nil, fmt.Errorf("SNI %q does not match CONNECT target %q", hello.ServerName, hostname)
			}
			return s.cfg.CA.leaf(hostname)
		},
	}
	ln := newOneConnListener(tls.Server(conn, tlsCfg))
	// HTTP/2 on this server takes its idle timeout from IdleTimeout.
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.intercepted(w, r, host) }),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       s.cfg.IdleTimeout,
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
	small, large, bodyNames, berr := readBody(r, s.cfg.Registry.inspectsBody(host))
	if berr != nil {
		s.record(bodyNames, host, r.Method, berr.Status, berr.Code)
		writeErr(w, berr)
		return
	}
	ws := isWebSocket(r)
	out := r.Clone(r.Context())
	out.RequestURI = ""
	stripHop(out.Header)
	body, names, filled, ferr := s.cfg.Registry.fillRequest(out, host, small)
	if ferr != nil {
		s.record(names, host, r.Method, ferr.Status, ferr.Code)
		writeErr(w, ferr)
		return
	}
	// Every header the proxy itself sets is in place before signing, so the
	// signature covers the request as it is sent.
	if large != nil {
		out.Body = large
		out.ContentLength = r.ContentLength
	} else {
		out.Body = io.NopCloser(bytes.NewReader(body))
		out.ContentLength = int64(len(body))
		if len(body) == 0 {
			out.Body = http.NoBody
		}
	}
	setContentLength(out)
	out.Header.Set("Accept-Encoding", "identity")
	if ws {
		// The extension header is dropped so frames stay uncompressed.
		out.Header.Set("Connection", "Upgrade")
		out.Header.Set("Upgrade", "websocket")
		out.Header.Del("Sec-WebSocket-Extensions")
	}
	signedWith, serr := s.cfg.Registry.signRequest(out, host, body, large != nil)
	names = append(names, signedWith...)
	if serr != nil {
		s.record(names, host, r.Method, serr.Status, serr.Code)
		writeErr(w, serr)
		return
	}
	if ws {
		s.websocket(w, out, host, names, filled)
		return
	}

	resp, err := s.transport.RoundTrip(out)
	if err != nil {
		e := upstreamErr(err, host)
		s.record(names, host, r.Method, e.Status, e.Code)
		writeErr(w, e)
		return
	}
	defer resp.Body.Close()
	s.relay(w, resp, host, r.Method, names, filled)
}

// setContentLength makes the Content-Length header say what the transport
// writes (from req.ContentLength), or removes it when the transport writes
// none, so a signature over it signs what goes out.
func setContentLength(req *http.Request) {
	switch {
	case req.ContentLength > 0:
		req.Header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
	case req.ContentLength == 0 && (req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodPatch):
		req.Header.Set("Content-Length", "0")
	default:
		req.Header.Del("Content-Length")
	}
}

// upstreamErr is the refusal for a request that could not reach upstream.
func upstreamErr(err error, host string) *Error {
	if errors.Is(err, ErrPrivateAddress) {
		return refuse(http.StatusForbidden, "private_address", "%s", ErrPrivateAddress.Error())
	}
	return refuse(http.StatusBadGateway, "upstream_error", "upstream request to %s failed", host)
}

// relay writes a final (non-101) upstream response back redacted. The audit
// record is written before the response is.
func (s *Server) relay(w http.ResponseWriter, resp *http.Response, host, method string, names []string, filled map[string][]byte) {
	if e := checkResponse(resp); e != nil {
		s.record(names, host, method, e.Status, e.Code)
		writeErr(w, e)
		return
	}
	red := s.cfg.Registry.proxyRedactor(false, filled)
	copyResponseHeader(w.Header(), resp.Header, red)
	setFilled(w.Header(), names)
	s.record(names, host, method, resp.StatusCode, "")
	w.WriteHeader(resp.StatusCode)
	copyFlush(w, red.reader(resp.Body))
}

// checkResponse refuses a response the proxy cannot relay redacted: a status
// that is not a final one (WriteHeader would panic on some), or a body in
// any content coding but identity, which redaction cannot see into.
func checkResponse(resp *http.Response) *Error {
	if resp.StatusCode < 200 || resp.StatusCode > 999 {
		return refuse(http.StatusBadGateway, "upstream_error", "upstream sent status %d", resp.StatusCode)
	}
	for _, v := range resp.Header.Values("Content-Encoding") {
		for _, ce := range strings.Split(v, ",") {
			if ce = strings.TrimSpace(ce); ce != "" && !strings.EqualFold(ce, "identity") {
				return refuse(http.StatusBadGateway, "upstream_error", "upstream sent an encoded body (%s) that cannot be redacted", ce)
			}
		}
	}
	return nil
}

// copyResponseHeader copies upstream's response headers into dst with every
// value redacted. Hop-by-hop headers, Content-Length and the headers only the
// proxy may set are dropped, and so is a header whose name holds a value.
func copyResponseHeader(dst, src http.Header, red *redactor) {
	for k, vs := range src {
		if red.applyString(k) != k {
			continue
		}
		for _, v := range vs {
			dst.Add(k, red.applyString(v))
		}
	}
	stripHop(dst)
	dst.Del("Content-Length")
	dst.Del(FilledHeader)
	dst.Del(ErrorHeader)
}

// FilledHeader names, on a response, the entries whose values went out in
// the request: an echo of the request shows their placeholders again (the
// values are hidden on the way back), so this is how the harness tells a
// filled request from one that was not.
const FilledHeader = "X-Seal-Credential-Filled"

// ErrorHeader carries the code of a refusal the proxy answers itself.
const ErrorHeader = "X-Seal-Credential-Error"

func setFilled(h http.Header, names []string) {
	h.Del(FilledHeader) // only the proxy says what it filled
	seen := map[string]bool{}
	var list []string
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			list = append(list, n)
		}
	}
	if len(list) > 0 {
		h.Set(FilledHeader, strings.Join(list, ","))
	}
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

// websocket relays an upgraded HTTP/1.1 connection (its request headers set
// by forward). The 101 response is redacted like any other; then values in
// server frames are masked byte for byte, frame by frame (relayFrames).
func (s *Server) websocket(w http.ResponseWriter, out *http.Request, host string, names []string, filled map[string][]byte) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		e := refuse(http.StatusBadRequest, "bad_target", "WebSocket needs HTTP/1.1 toward the proxy")
		s.record(names, host, out.Method, e.Status, e.Code)
		writeErr(w, e)
		return
	}
	resp, err := s.transport.RoundTrip(out)
	if err != nil {
		e := upstreamErr(err, host)
		s.record(names, host, out.Method, e.Status, e.Code)
		writeErr(w, e)
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer resp.Body.Close()
		s.relay(w, resp, host, out.Method, names, filled)
		return
	}
	up, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		resp.Body.Close()
		e := refuse(http.StatusBadGateway, "upstream_error", "upstream switched protocols without a connection to relay")
		s.record(names, host, out.Method, e.Status, e.Code)
		writeErr(w, e)
		return
	}
	defer up.Close()
	red := s.cfg.Registry.proxyRedactor(false, filled)
	h := http.Header{}
	copyResponseHeader(h, resp.Header, red)
	h.Set("Connection", "Upgrade")
	h.Set("Upgrade", "websocket")
	h.Del("Sec-WebSocket-Extensions")
	setFilled(h, names)
	reason := strings.TrimSpace(strings.TrimPrefix(resp.Status, "101"))
	if reason == "" {
		reason = "Switching Protocols"
	}
	var head bytes.Buffer
	fmt.Fprintf(&head, "HTTP/1.1 101 %s\r\n", red.applyString(reason))
	_ = h.Write(&head)
	head.WriteString("\r\n")
	s.record(names, host, out.Method, resp.StatusCode, "")

	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err := conn.Write(head.Bytes()); err != nil {
		return
	}
	mask := s.cfg.Registry.proxyRedactor(true, filled)
	go func() {
		_, _ = io.Copy(up, buf.Reader)
		up.Close()
	}()
	_ = relayFrames(conn, bufio.NewReader(up), mask)
}

// maxFramePayload is the largest frame payload held in memory and redacted
// as a whole; a larger one is redacted in chunks as it streams.
const maxFramePayload = 1 << 20

var errBadFrame = errors.New("websocket: a frame a server may not send")

// relayFrames copies server-to-client WebSocket frames (RFC 6455) from src to
// dst. Each data frame's payload is redacted with red, a mask redactor, so it
// keeps its length and the frame header goes out unchanged: up to
// maxFramePayload as a whole, beyond that in chunks (a value split across
// chunks is still matched). A value split across the fragments of a message
// is not matched: each fragment is a frame of its own. Control frames (close,
// ping, pong) pass as they are. A masked frame, which a server never sends,
// or a control frame over 125 bytes ends the relay.
func relayFrames(dst io.Writer, src *bufio.Reader, red *redactor) error {
	var hdr [10]byte // a server frame carries no masking key
	for {
		if _, err := io.ReadFull(src, hdr[:2]); err != nil {
			return err
		}
		n, length := 2, uint64(hdr[1]&0x7f)
		switch length {
		case 126:
			if _, err := io.ReadFull(src, hdr[2:4]); err != nil {
				return err
			}
			n, length = 4, uint64(binary.BigEndian.Uint16(hdr[2:4]))
		case 127:
			if _, err := io.ReadFull(src, hdr[2:10]); err != nil {
				return err
			}
			n, length = 10, binary.BigEndian.Uint64(hdr[2:10])
			if length>>63 != 0 {
				return errBadFrame
			}
		}
		if hdr[1]&0x80 != 0 {
			return errBadFrame
		}
		control := hdr[0]&0x0f >= 0x8 && hdr[0]&0x0f <= 0xa
		if control && length > 125 {
			return errBadFrame
		}
		if length > maxFramePayload {
			if _, err := dst.Write(hdr[:n]); err != nil {
				return err
			}
			got, err := io.Copy(dst, red.reader(io.LimitReader(src, int64(length))))
			if err != nil {
				return err
			}
			if uint64(got) != length {
				return io.ErrUnexpectedEOF
			}
			continue
		}
		frame := make([]byte, n+int(length))
		copy(frame, hdr[:n])
		if _, err := io.ReadFull(src, frame[n:]); err != nil {
			return err
		}
		if !control {
			p := red.apply(frame[n:])
			if len(p) != int(length) {
				return errBadFrame // a mask redactor keeps the length; never reached
			}
			copy(frame[n:], p)
		}
		if _, err := dst.Write(frame); err != nil {
			return err
		}
	}
}

func (s *Server) record(names []string, host, method string, status int, code string) {
	if s.cfg.OnUse == nil || len(names) == 0 {
		return
	}
	s.cfg.OnUse(Record{Time: time.Now(), Names: names, Host: host, Method: method, Status: status, Code: code})
}

// readBody buffers a body up to maxBodyBytes so placeholders in it can be
// filled, or it can be signed. A larger body is passed through untouched; if
// its first bytes already name a placeholder it is refused instead (with the
// names, for the audit record), so a value is never left unfilled without
// the harness hearing about it.
//
// Only a host where some entry can fill a body field or must sign the body
// has its bodies read at all. Anywhere else a body is relayed as it is,
// whatever its size: bodies carry text (a conversation, an issue, a model
// prompt) that may quote a placeholder, and nothing could be filled there.
func readBody(r *http.Request, inspect bool) ([]byte, io.ReadCloser, []string, *Error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil, nil, nil
	}
	if !inspect {
		return nil, r.Body, nil, nil
	}
	head, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return nil, nil, nil, refuse(http.StatusBadRequest, "bad_request", "cannot read request body")
	}
	if len(head) <= maxBodyBytes {
		return head, nil, nil, nil
	}
	if mentionsPlaceholder(head) {
		return nil, nil, mentionedNames(head), refuse(http.StatusRequestEntityTooLarge, "body_too_large", "a placeholder in a body over %d bytes cannot be filled", maxBodyBytes)
	}
	return nil, struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(head), r.Body), r.Body}, nil, nil
}

func writeErr(w http.ResponseWriter, e *Error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(ErrorHeader, e.Code)
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
	// NAT64 prefixes (RFC 6052, RFC 8215) reach IPv4 addresses, private
	// ones included, through a translator.
	for _, c := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "fc00::/7", "64:ff9b::/96", "64:ff9b:1::/48"} { // privacy-check: allow
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
