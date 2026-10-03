package secrets

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxBodyBytes caps a buffered request/response body. v1 targets agent tool
// calls (small JSON); large/streaming bodies (framework inference, SSE) are a
// v2 concern — see SECRETS.md §5. A body over the cap is passed through
// UNsubstituted and UNredacted rather than held in memory, logged loudly.
const maxBodyBytes = 1 << 20 // 1 MiB

// Proxy is sealed's loopback egress proxy. The agent sends a request to
//
//	http://127.0.0.1:<port>/<scheme>/<host>/<path...>?<query>
//
// with {{secret:NAME}} placeholders in headers, query or body. The proxy
// substitutes a placeholder's real value ONLY when <host> is in that secret's
// allowlist, dials <scheme>://<host>/<path> itself, and relays the response
// with every known secret value redacted back to its placeholder. The real
// value never crosses back to the agent, and a placeholder sent for a
// disallowed host stays a placeholder.
//
// Loopback only: the agent (same container) reaches it; nothing external does.
// It is NOT a registerable service — the /services guard rejects its port.
type Proxy struct {
	store  *Store
	client *http.Client
	logf   func(string, ...any)
}

// NewProxy builds the handler. client defaults to one that does NOT follow
// redirects (a 3xx Location to another host must not carry a substituted
// secret off its allowlist — the agent gets the redirect and must re-issue).
func NewProxy(store *Store, logf func(string, ...any)) *Proxy {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Proxy{
		store: store,
		client: &http.Client{
			Timeout: 60 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logf: logf,
	}
}

// setTransport overrides the HTTP transport. Tests use it to redirect a
// realistic (non-loopback) target host to a local test server.
func (p *Proxy) setTransport(rt http.RoundTripper) { p.client.Transport = rt }

// hopByHop headers are connection-scoped and must not be forwarded.
var hopByHop = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true,
	"Transfer-Encoding": true, "Te": true, "Trailer": true, "Upgrade": true,
	"Proxy-Authenticate": true, "Proxy-Authorization": true,
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	scheme, host, rest, err := parseTarget(r.URL)
	if err != nil {
		http.Error(w, "secret proxy: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Read the request body (bounded) so a {{secret:…}} in it can be
	// substituted. Over the cap → refuse (review #171 F2): forwarding a
	// truncated prefix breaks Content-Length and leaks nothing useful, so fail
	// closed, symmetric with the response-size refusal below.
	bodyBytes, truncated, err := readCapped(r.Body, maxBodyBytes)
	if err != nil {
		http.Error(w, "secret proxy: read body", http.StatusBadGateway)
		return
	}
	if truncated {
		http.Error(w, fmt.Sprintf("secret proxy: request body over %d bytes not supported", maxBodyBytes), http.StatusRequestEntityTooLarge)
		return
	}
	var allBlocked []string
	body, blocked := p.store.substituteForHost(string(bodyBytes), host)
	allBlocked = append(allBlocked, blocked...)

	// Substitute in the target query string too.
	query := r.URL.RawQuery
	if query != "" {
		q, blocked := p.store.substituteForHost(query, host)
		query = q
		allBlocked = append(allBlocked, blocked...)
	}

	upURL := scheme + "://" + host + rest
	if query != "" {
		upURL += "?" + query
	}
	up, err := http.NewRequestWithContext(r.Context(), r.Method, upURL, strings.NewReader(body))
	if err != nil {
		http.Error(w, "secret proxy: build upstream request", http.StatusBadGateway)
		return
	}

	// Copy headers, substituting placeholders in each value for this host.
	for k, vs := range r.Header {
		if hopByHop[http.CanonicalHeaderKey(k)] || k == "Host" {
			continue
		}
		for _, v := range vs {
			sv, hblocked := p.store.substituteForHost(v, host)
			allBlocked = append(allBlocked, hblocked...)
			up.Header.Add(k, sv)
		}
	}
	up.ContentLength = int64(len(body))
	up.Header.Del("Content-Length") // let the client set it from the new body
	// Force an identity (uncompressed) response so redaction can see the bytes
	// (review #171 F1): a client-set Accept-Encoding is forwarded and Go's
	// Transport then does NOT auto-decompress, so a compressed body would reach
	// redaction as opaque bytes and the agent could decompress the value
	// locally. We also fail closed below if the upstream encodes anyway.
	up.Header.Set("Accept-Encoding", "identity")

	if len(allBlocked) > 0 {
		// A secret was referenced for a host NOT in its allowlist: left as a
		// placeholder, never sent. Name only, never the value.
		p.logf("warn: secret proxy: %d placeholder(s) not substituted for host %q (not in allowlist): %s",
			len(uniq(allBlocked)), host, strings.Join(uniq(allBlocked), ", "))
	}

	resp, err := p.client.Do(up)
	if err != nil {
		http.Error(w, "secret proxy: upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Fail closed on an encoded body (review #171 F1): we asked for identity,
	// but if the upstream compressed anyway, redaction over the raw bytes would
	// miss the value and the agent would decompress it locally. Refuse rather
	// than relay something we cannot scan. (decompress-redact-recompress is v2.)
	if ce := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))); ce != "" && ce != "identity" {
		p.logf("warn: secret proxy: upstream used Content-Encoding %q despite identity request — refusing to relay unredactable body", ce)
		http.Error(w, "secret proxy: upstream returned an encoded body that cannot be redacted", http.StatusBadGateway)
		return
	}

	// Redact any real value from the response headers before relaying.
	for k, vs := range resp.Header {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, p.store.redact(v))
		}
	}

	respBytes, respTrunc, err := readCapped(resp.Body, maxBodyBytes)
	if err != nil {
		http.Error(w, "secret proxy: read upstream body", http.StatusBadGateway)
		return
	}
	out := respBytes
	if respTrunc {
		// Could not buffer to redact — do NOT risk relaying a value. Fail
		// closed rather than leak.
		p.logf("warn: secret proxy: upstream body over %d bytes — refusing to relay unredacted", maxBodyBytes)
		http.Error(w, "secret proxy: upstream response too large to redact", http.StatusBadGateway)
		return
	}
	w.Header().Del("Content-Length")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write([]byte(p.store.redact(string(out))))
}

// parseTarget splits /<scheme>/<host>/<path...> from the proxy URL path.
func parseTarget(u *url.URL) (scheme, host, rest string, err error) {
	path := strings.TrimPrefix(u.EscapedPath(), "/")
	seg := strings.SplitN(path, "/", 3)
	// v1: https only (review #171 F4). http would put the substituted value on
	// a cleartext stream observable on the egress path; every v1 target is
	// https, and the allowlist is scheme-less so the owner cannot opt in to
	// http. See SECRETS.md §5.
	if len(seg) < 2 || seg[0] != "https" {
		return "", "", "", fmt.Errorf("path must be /https/<host>/<path> (http is refused: a secret must not ride cleartext)")
	}
	scheme = seg[0]
	host = seg[1]
	if host == "" {
		return "", "", "", fmt.Errorf("empty host")
	}
	// Reject a loopback/empty target: the proxy must not be turned back on the
	// container's own services (SSRF to localhost).
	if h, _, _ := net.SplitHostPort(host); isLoopbackName(h) || isLoopbackName(host) {
		return "", "", "", fmt.Errorf("refusing loopback target")
	}
	rest = "/"
	if len(seg) == 3 {
		rest = "/" + seg[2]
	}
	return scheme, host, rest, nil
}

func isLoopbackName(h string) bool {
	h = strings.ToLower(strings.Trim(h, "[]"))
	if h == "localhost" || strings.HasPrefix(h, "127.") || h == "::1" || h == "0.0.0.0" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func readCapped(r io.Reader, max int) (b []byte, truncated bool, err error) {
	if r == nil {
		return nil, false, nil
	}
	b, err = io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, false, err
	}
	if len(b) > max {
		return b[:max], true, nil
	}
	return b, false, nil
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
