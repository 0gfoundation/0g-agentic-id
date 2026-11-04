package attestorhttp

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type leaseRoundTripper func(*http.Request) (*http.Response, error)

func (f leaseRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type leaseWaitingBody struct {
	ctx    context.Context
	closed bool
}

func (b *leaseWaitingBody) Read([]byte) (int, error) {
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (b *leaseWaitingBody) Close() error {
	b.closed = true
	return nil
}

func leaseRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://fixture.invalid/provision", strings.NewReader("proof"))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestLeaseBoundsInFlightRoundTripWithoutRetry(t *testing.T) {
	calls := 0
	deadline := time.Now().Add(20 * time.Millisecond)
	transport := leaseRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls++
		got, ok := req.Context().Deadline()
		if !ok || !got.Equal(deadline) {
			t.Fatal("outbound request did not retain the statement's absolute deadline")
		}
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	response, err := roundTripBefore(transport, leaseRequest(t), deadline)
	if response != nil || !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
		t.Fatalf("expired in-flight request must fail without retry: response=%v err=%v calls=%d", response, err, calls)
	}
}

func TestLeaseBoundsResponseBodyWithoutRetry(t *testing.T) {
	calls := 0
	var body *leaseWaitingBody
	transport := leaseRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls++
		body = &leaseWaitingBody{ctx: req.Context()}
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	})
	response, err := roundTripBefore(transport, leaseRequest(t), time.Now().Add(20*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(response.Body)
	response.Body.Close()
	if !errors.Is(err, context.DeadlineExceeded) || calls != 1 || !body.closed {
		t.Fatalf("successful headers must not extend the lease or retry: err=%v calls=%d closed=%v", err, calls, body.closed)
	}
}

func TestLeaseRejectsBufferedBodyAfterExpiry(t *testing.T) {
	var requestCtx context.Context
	transport := leaseRoundTripper(func(req *http.Request) (*http.Response, error) {
		requestCtx = req.Context()
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"encrypted_agent_seal_priv":"fixture"}`))}, nil
	})
	response, err := roundTripBefore(transport, leaseRequest(t), time.Now().Add(20*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	<-requestCtx.Done()
	body, err := io.ReadAll(response.Body)
	if len(body) != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("buffered data must not be accepted after expiry: body=%q err=%v", body, err)
	}
}

func TestLeaseBodyCloseReleasesContextAndPreservesCompleteResponse(t *testing.T) {
	var requestCtx context.Context
	transport := leaseRoundTripper(func(req *http.Request) (*http.Response, error) {
		requestCtx = req.Context()
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	response, err := roundTripBefore(transport, leaseRequest(t), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "ok" || requestCtx.Err() != nil {
		t.Fatalf("valid response was cancelled before the caller finished reading: body=%q err=%v", body, err)
	}
	response.Body.Close()
	if !errors.Is(requestCtx.Err(), context.Canceled) {
		t.Fatal("closing the response did not release its deadline context")
	}
}

func TestExpiredLeaseDoesNotStartAnExchange(t *testing.T) {
	calls := 0
	transport := leaseRoundTripper(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("expired request reached the transport")
	})
	_, err := roundTripBefore(transport, leaseRequest(t), time.Now().Add(-time.Second))
	if !errors.Is(err, context.DeadlineExceeded) || calls != 0 {
		t.Fatalf("expired snapshot started an outbound exchange: err=%v calls=%d", err, calls)
	}
}

// Exercise resolver.RoundTrip itself so accidentally removing its lease helper
// cannot leave only the helper-level tests green. net.Pipe needs no listener,
// while the real HTTPS transport still verifies the certificate's SPKI pin.
func TestResolverLeaseBoundsRealPinnedHTTPSBody(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	peer, incoming := net.Pipe()
	stop := make(chan struct{})
	// Seven seconds keeps the snapshot outside the five-second refresh margin.
	expires := time.Now().Unix() + 7
	base, _ := url.Parse("https://fixture.invalid")
	transport := pinnedTransport([]string{hex.EncodeToString(pin[:])}, expires)
	var dials atomic.Int64
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return peer, nil
	}
	t.Cleanup(func() {
		close(stop)
		peer.Close()
		incoming.Close()
		transport.CloseIdleConnections()
	})
	r := &resolver{base: base, transport: transport, expiresAt: expires}
	client := &http.Client{Transport: r, Timeout: 120 * time.Second, CheckRedirect: noRedirect}
	completed := make(chan error, 1)
	go func() {
		defer incoming.Close()
		conn := tls.Server(incoming, &tls.Config{Certificates: []tls.Certificate{cert}})
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			completed <- err
			return
		}
		body, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil || string(body) != "proof" {
			completed <- errors.New("fixture did not receive the original request body")
			return
		}
		if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"); err != nil {
			completed <- err
			return
		}
		// Consume the client's close_notify so net.Pipe does not add TLS's
		// five-second shutdown timeout after the request lease expires.
		go io.Copy(io.Discard, conn)
		delay := time.NewTimer(time.Until(time.Unix(expires, 0).Add(100 * time.Millisecond)))
		defer delay.Stop()
		select {
		case <-stop:
			return
		case <-delay.C:
		}
		_, err = io.WriteString(conn, "ok")
		completed <- err
	}()
	response, err := client.Post(base.String()+"/provision", "application/json", strings.NewReader("proof"))
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	select {
	case serverErr := <-completed:
		if serverErr != nil && readErr == nil {
			t.Fatal(serverErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTPS fixture did not finish after its delayed body")
	}
	if !errors.Is(readErr, context.DeadlineExceeded) {
		t.Fatalf("resolver accepted a successful body after statement expiry: body=%q err=%v", body, readErr)
	}
	if dials.Load() != 1 {
		t.Fatalf("processed request was retried: dials=%d", dials.Load())
	}
}
