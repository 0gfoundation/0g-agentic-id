// Package attestorhttp is sealed's HTTP client for the attestor
// (ATTESTOR_URL). It pins the attestor's TLS key to a statement signed by
// the sandbox provider that issued this container's certificate:
//
//	GET {ATTESTOR_URL}/attestor-tls?provider=<provider address>
//
// is fetched without CA validation, then accepted only if its EIP-712
// signature recovers the provider recovered from the container certificate
// in Phase 0, it carries the certificate's chain and TappRegistry, its lease
// is current, and the key of the TLS connection it arrived over is one of
// its pins. Every other request to ATTESTOR_URL then goes over a transport
// whose leaf SPKI must be one of those pins, and must finish before the
// statement expires. Workloads never receive the tapp socket.
package attestorhttp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
)

// DevEnv turns pinning off for local development when set to "true". The
// provider removes it, with every caller SANDBOX_* key, from the env of each
// sealed container it certifies, which is every container the attestor
// creates.
const DevEnv = "ATTESTOR_ALLOW_UNPINNED_DEV"

const (
	// statementTimeout bounds one statement fetch.
	statementTimeout = 10 * time.Second
	// maxStatementBytes caps a statement body.
	maxStatementBytes = 16 << 10
	// mismatchRefresh is the minimum interval between statement refreshes
	// caused by the attestor presenting a key the held statement lacks.
	mismatchRefresh = 30
	// maxExcerpt bounds how much of an attestor response body reaches /log.
	maxExcerpt = 256
)

// errPinMismatch is the pinned transport's handshake error when the
// attestor's key is not in the held statement.
var errPinMismatch = errors.New("attestor TLS key is not in the provider-signed pins")

// Anchor is what an attestor TLS statement must be signed under: the chain
// and TappRegistry of this container's certificate, and the provider key
// that signed the certificate.
type Anchor struct {
	ChainID  uint64
	Registry common.Address
	Provider common.Address
}

var clients = struct {
	sync.Mutex
	anchor *Anchor
	values map[string]*http.Client
}{values: make(map[string]*http.Client)}

// Configure records the anchor Phase 0 recovered. Clients handed out before
// it are not reused.
func Configure(anchor Anchor) {
	clients.Lock()
	defer clients.Unlock()
	clients.anchor = &anchor
	clients.values = make(map[string]*http.Client)
}

// Client returns the one client used for /provision, /status, /settings/seed
// and the provider registry under locator (ATTESTOR_URL).
func Client(locator string) (*http.Client, error) {
	dev := os.Getenv(DevEnv) == "true"
	key := fmt.Sprintf("%s\x00%t", locator, dev)
	clients.Lock()
	defer clients.Unlock()
	if client := clients.values[key]; client != nil {
		return client, nil
	}
	var client *http.Client
	var err error
	switch {
	case dev:
		client = &http.Client{Timeout: 120 * time.Second, CheckRedirect: noRedirect}
	case clients.anchor == nil:
		err = fmt.Errorf("attestor TLS anchor not configured (no verified container certificate)")
	default:
		client, err = New(locator, *clients.anchor)
	}
	if err == nil {
		clients.values[key] = client
	}
	return client, err
}

// New returns a client that pins requests under locator to the attestor TLS
// statement signed under anchor. The first request fetches the statement.
func New(locator string, anchor Anchor) (*http.Client, error) {
	base, err := httpsURL(locator)
	if err != nil {
		return nil, err
	}
	if anchor.ChainID == 0 || anchor.Registry == (common.Address{}) || anchor.Provider == (common.Address{}) {
		return nil, fmt.Errorf("incomplete attestor TLS anchor")
	}
	r := &resolver{anchor: anchor, base: base,
		statementURL: strings.TrimRight(base.String(), "/") + "/attestor-tls?provider=" + strings.ToLower(anchor.Provider.Hex())}
	return &http.Client{Transport: r, Timeout: 120 * time.Second, CheckRedirect: noRedirect}, nil
}

// resolver holds the current lease and the transport pinned to it.
type resolver struct {
	anchor       Anchor
	base         *url.URL
	statementURL string
	// now is the clock; nil means time.Now.
	now func() time.Time

	mu        sync.Mutex
	transport *http.Transport
	issuedAt  int64
	expiresAt int64
	// mismatchAt is when a pin mismatch last forced a refresh (unix seconds).
	mismatchAt int64
}

func (r *resolver) clock() int64 {
	if r.now != nil {
		return r.now().Unix()
	}
	return time.Now().Unix()
}

func (r *resolver) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != r.base.Scheme || req.URL.Host != r.base.Host ||
		!strings.HasPrefix(req.URL.Path, strings.TrimRight(r.base.Path, "/")+"/") {
		return nil, fmt.Errorf("attestor request left the configured business URL")
	}
	transport, expiry, err := r.current(req.Context())
	if err != nil {
		return nil, err
	}
	response, err := roundTripBefore(transport, req, time.Unix(expiry, 0))
	if !errors.Is(err, errPinMismatch) {
		return response, err
	}
	// The attestor presented a key the held statement does not list (it may
	// have moved to another node). The handshake failed before any request
	// bytes were sent, so one retry under a newer statement is safe.
	transport, expiry, refreshErr := r.refreshAfterMismatch(req.Context(), transport)
	if refreshErr != nil {
		return nil, fmt.Errorf("%w (statement refresh: %v)", err, refreshErr)
	}
	retry, rewindErr := rewind(req)
	if rewindErr != nil {
		return nil, err
	}
	return roundTripBefore(transport, retry, time.Unix(expiry, 0))
}

// current returns the pinned transport, fetching a statement first when none
// is held or the held one has five seconds or less left.
func (r *resolver) current(ctx context.Context) (*http.Transport, int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.transport == nil || r.clock()+minRemaining >= r.expiresAt {
		if err := r.refresh(ctx); err != nil {
			return nil, 0, err
		}
	}
	return r.transport, r.expiresAt, nil
}

// refreshAfterMismatch returns a transport to retry on after failed
// presented an unlisted key. When another request has already replaced
// failed, that transport is returned as is; only a mismatch on the current
// transport fetches a statement, at most once per mismatchRefresh.
func (r *resolver) refreshAfterMismatch(ctx context.Context, failed *http.Transport) (*http.Transport, int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()
	if r.transport != nil && r.transport != failed && now+minRemaining < r.expiresAt {
		return r.transport, r.expiresAt, nil
	}
	if r.mismatchAt != 0 && now < r.mismatchAt+mismatchRefresh {
		return nil, 0, fmt.Errorf("refreshed less than %ds ago", mismatchRefresh)
	}
	r.mismatchAt = now
	if err := r.refresh(ctx); err != nil {
		return nil, 0, err
	}
	return r.transport, r.expiresAt, nil
}

// refresh replaces the held lease with a newly fetched one. r.mu is held.
func (r *resolver) refresh(ctx context.Context) error {
	l, err := r.fetch(ctx)
	if err != nil {
		return err
	}
	if r.transport != nil {
		r.transport.CloseIdleConnections()
	}
	r.transport, r.issuedAt, r.expiresAt = pinnedTransport(l.pins, l.expiresAt), l.issuedAt, l.expiresAt
	return nil
}

// fetch reads the attestor's relayed statement and accepts it only when the
// connection it arrived over presented one of its pins.
func (r *resolver) fetch(ctx context.Context) (lease, error) {
	ctx, cancel := context.WithTimeout(ctx, statementTimeout)
	defer cancel()
	transport := statementTransport()
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.statementURL, nil)
	if err != nil {
		return lease{}, err
	}
	// RoundTrip, not a client: a redirect is a failure, never followed.
	response, err := transport.RoundTrip(req)
	if err != nil {
		return lease{}, fmt.Errorf("fetch attestor TLS statement: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return lease{}, fmt.Errorf("fetch attestor TLS statement: HTTP %d", response.StatusCode)
	}
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		return lease{}, fmt.Errorf("attestor TLS statement did not arrive over TLS")
	}
	spki := spkiHash(response.TLS.PeerCertificates[0])
	body, err := io.ReadAll(io.LimitReader(response.Body, maxStatementBytes+1))
	if err != nil {
		return lease{}, fmt.Errorf("read attestor TLS statement: %w", err)
	}
	if len(body) > maxStatementBytes {
		return lease{}, fmt.Errorf("attestor TLS statement larger than %d bytes", maxStatementBytes)
	}
	statement, err := parseStatement(body)
	if err != nil {
		return lease{}, err
	}
	l, err := statement.accept(r.anchor, r.clock(), r.issuedAt)
	if err != nil {
		return lease{}, err
	}
	if !hasPin(l.pins, spki) {
		return lease{}, fmt.Errorf("attestor TLS statement does not list the key of the connection it arrived over")
	}
	return l, nil
}

// rewind returns req with a fresh copy of its body for a second attempt.
func rewind(req *http.Request) (*http.Request, error) {
	retry := req.Clone(req.Context())
	if req.Body == nil || req.Body == http.NoBody {
		return retry, nil
	}
	if req.GetBody == nil {
		return nil, fmt.Errorf("request body cannot be replayed")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	retry.Body = body
	return retry, nil
}

// Keep one transport snapshot for the entire exchange, including response-body
// reads. A successful response header cannot extend the statement's lease.
func roundTripBefore(transport http.RoundTripper, req *http.Request, deadline time.Time) (*http.Response, error) {
	ctx, cancel := context.WithDeadline(req.Context(), deadline)
	if err := ctx.Err(); err != nil {
		cancel()
		return nil, err
	}
	response, err := transport.RoundTrip(req.Clone(ctx))
	if err != nil {
		cancel()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		cancel()
		if response.Body != nil {
			response.Body.Close()
		}
		return nil, err
	}
	if response.Body == nil {
		cancel()
	} else {
		response.Body = &leasedBody{ReadCloser: response.Body, ctx: ctx, cancel: cancel}
	}
	return response, nil
}

type leasedBody struct {
	io.ReadCloser
	ctx    context.Context
	cancel context.CancelFunc
}

func (b *leasedBody) Read(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := b.ReadCloser.Read(p)
	if ctxErr := b.ctx.Err(); ctxErr != nil {
		return 0, ctxErr
	}
	return n, err
}

func (b *leasedBody) Close() error {
	b.cancel()
	return b.ReadCloser.Close()
}

// pinnedTransport accepts only a leaf certificate whose SPKI SHA-256 is one
// of pins, and no connection once expiresAt (unix seconds, 0 for none) has
// passed.
func pinnedTransport(pins []string, expiresAt int64) *http.Transport {
	pinned := append([]string(nil), pins...)
	return &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second, IdleConnTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12,
			// The provider-signed SPKI pins replace CA and name validation.
			InsecureSkipVerify: true, //nolint:gosec
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return fmt.Errorf("attestor presented no certificate")
				}
				if expiresAt != 0 && time.Now().Unix() >= expiresAt {
					return fmt.Errorf("attestor TLS statement expired")
				}
				if !hasPin(pinned, spkiHash(cs.PeerCertificates[0])) {
					return errPinMismatch
				}
				return nil
			}}}
}

// statementTransport is a one-connection transport for fetching a statement.
// The statement authenticates itself by its signature; the key of the
// connection it arrives over is checked against it after it is read.
func statementTransport() *http.Transport {
	return &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: statementTimeout, DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}} //nolint:gosec
}

func spkiHash(leaf *x509.Certificate) string {
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func noRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

func httpsURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("ATTESTOR_URL must be HTTPS without credentials, query or fragment")
	}
	return u, nil
}

// Excerpt is an attestor response body as it may appear in the public /log:
// at most its first 256 bytes, cut on a character boundary, on one line.
// logger escapes any other control characters.
func Excerpt(body []byte) string {
	truncated := len(body) > maxExcerpt
	if truncated {
		body = body[:maxExcerpt]
		// Drop a character the cut split; ToValidUTF8 handles the rest.
		for i := 1; i < utf8.UTFMax && len(body) > 0; i++ {
			if r, size := utf8.DecodeLastRune(body); r != utf8.RuneError || size != 1 {
				break
			}
			body = body[:len(body)-1]
		}
	}
	text := strings.Join(strings.Fields(strings.ToValidUTF8(string(body), "?")), " ")
	if truncated {
		text += " ..."
	}
	return text
}
