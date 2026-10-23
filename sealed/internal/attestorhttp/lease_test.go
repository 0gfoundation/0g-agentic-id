package attestorhttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
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
			t.Fatal("outbound request did not retain the identity's absolute deadline")
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
