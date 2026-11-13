package servicehost

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"seal-verify/internal/privsep"
)

// egressProxy has no credential registry, signing authority or access to owner
// loopback services. Even a program that ignores proxy settings has no route
// out of its private network namespace.
type egressProxy struct {
	ctx       context.Context
	allowed   map[string]bool
	dial      func(context.Context, string, string) (net.Conn, error)
	transport *http.Transport
	slots     chan struct{}
}

func (m *Manager) startEgress(ctx context.Context, hosts []string, uid uint32, socket string) error {
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return fmt.Errorf("prepare restricted egress")
	}
	if err := os.Chown(socket, int(uid), int(uid)); err != nil {
		ln.Close()
		return err
	}
	if err := privsep.Chmod(socket, 0600); err != nil {
		ln.Close()
		return err
	}
	p := &egressProxy{ctx: ctx, allowed: map[string]bool{}, dial: m.egressDial, slots: make(chan struct{}, 16)}
	for _, h := range hosts {
		p.allowed[h] = true
	}
	p.transport = &http.Transport{DialContext: p.dial, TLSHandshakeTimeout: 10 * time.Second, IdleConnTimeout: 30 * time.Second, MaxIdleConns: 16}
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}
	go func() { _ = srv.Serve(ln) }()
	go func() { <-ctx.Done(); srv.Close(); p.transport.CloseIdleConnections() }()
	return nil
}

func (p *egressProxy) allowedTarget(addr string) bool {
	h, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return p.allowed[net.JoinHostPort(strings.TrimSuffix(strings.ToLower(h), "."), port)]
}

func (p *egressProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		http.Error(w, "egress connection limit", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	addr := r.URL.Host
	if r.URL.Port() == "" {
		addr = net.JoinHostPort(r.URL.Hostname(), "80")
	}
	if r.URL.Scheme != "http" || r.URL.User != nil || !p.allowedTarget(addr) {
		http.Error(w, "egress target not allowed", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() {
		select {
		case <-p.ctx.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	up := r.Clone(ctx)
	up.RequestURI, up.Host = "", up.URL.Host
	up.Header = r.Header.Clone()
	stripEgressHopHeaders(up.Header)
	resp, err := p.transport.RoundTrip(up)
	if err != nil {
		http.Error(w, "egress connection refused", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	stripEgressHopHeaders(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func stripEgressHopHeaders(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Proxy-Authorization", "Proxy-Authenticate", "Proxy-Connection", "Connection", "Upgrade", "Keep-Alive", "Trailer", "Transfer-Encoding", "Te"} {
		h.Del(name)
	}
}

func (p *egressProxy) connect(w http.ResponseWriter, r *http.Request) {
	if !p.allowedTarget(r.Host) {
		http.Error(w, "egress target not allowed", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
	up, err := p.dial(ctx, "tcp", r.Host)
	cancel()
	if err != nil {
		http.Error(w, "egress connection refused", http.StatusBadGateway)
		return
	}
	defer up.Close()
	conn, buf, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err := buf.Flush(); err != nil {
		return
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-p.ctx.Done():
			conn.Close()
			up.Close()
		case <-stop:
		}
	}()
	done := make(chan struct{})
	go func() { _, _ = io.Copy(up, buf); up.Close(); close(done) }()
	_, _ = io.Copy(conn, up)
	conn.Close()
	<-done
}
