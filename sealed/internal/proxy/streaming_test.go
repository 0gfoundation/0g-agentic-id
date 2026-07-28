package proxy

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsEventStream(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{"text/event-stream", true},
		{"text/event-stream; charset=utf-8", true},
		{"  Text/Event-Stream ", true}, // trimmed + case-insensitive
		{"application/json", false},
		{"text/plain", false},
		{"", false},
	}
	for _, c := range cases {
		resp := &http.Response{Header: http.Header{}}
		if c.ct != "" {
			resp.Header.Set("Content-Type", c.ct)
		}
		if got := isEventStream(resp); got != c.want {
			t.Errorf("isEventStream(%q) = %v, want %v", c.ct, got, c.want)
		}
	}
}

// streamRelay must copy an SSE body through verbatim, preserve the status,
// drop Content-Length (chunked), attach NO X-Agent-Proof, and flush so frames
// are not buffered to the end.
func TestStreamRelay_VerbatimUnsignedFlushed(t *testing.T) {
	const payload = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n" +
		"data: [DONE]\n\n"
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":                {"text/event-stream"},
			"Content-Length":              {"999"}, // must be dropped
			"Access-Control-Allow-Origin": {"*"},    // must be skipped (cors sets ours)
		},
		Body: io.NopCloser(strings.NewReader(payload)),
	}

	rec := httptest.NewRecorder()
	streamRelay(rec, resp)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if got := rec.Body.String(); got != payload {
		t.Errorf("body relayed = %q, want verbatim %q", got, payload)
	}
	if res.Header.Get("X-Agent-Proof") != "" {
		t.Error("streamed response must NOT carry X-Agent-Proof")
	}
	if res.Header.Get("Content-Length") != "" {
		t.Error("Content-Length must be dropped for a stream")
	}
	if res.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("Access-Control-* must be skipped (corsMiddleware owns it)")
	}
	if res.Header.Get("Content-Type") != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", res.Header.Get("Content-Type"))
	}
	if !rec.Flushed {
		t.Error("streamRelay must Flush so SSE frames are not buffered")
	}
}

// A body that yields data before EOF should already be visible to the client
// (flushed) rather than held until the stream closes.
func TestStreamRelay_FlushesEachChunk(t *testing.T) {
	pr, pw := io.Pipe()
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/event-stream"}},
		Body:       pr,
	}
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		streamRelay(rec, resp)
		close(done)
	}()

	io.WriteString(pw, "data: one\n\n")
	pw.Close()
	<-done

	sc := bufio.NewScanner(strings.NewReader(rec.Body.String()))
	sc.Scan()
	if got := sc.Text(); got != "data: one" {
		t.Errorf("first relayed line = %q, want %q", got, "data: one")
	}
	if !rec.Flushed {
		t.Error("expected a flush after the chunk")
	}
}
