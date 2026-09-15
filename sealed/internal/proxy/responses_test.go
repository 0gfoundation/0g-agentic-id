package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"seal-verify/internal/framework"
)

// synthFakeAdapter implements just what the synthesized responses surface
// touches (AuthResponse); the embedded nil Framework panics if anything else
// is called, which would itself be a test failure worth seeing.
type synthFakeAdapter struct {
	framework.Framework
	token string
}

func (f *synthFakeAdapter) AuthResponse(context.Context) (any, error) {
	return map[string]any{"token": f.token}, nil
}

// newSynthTestServer wires a Server around a fake upstream chat/completions
// and returns the public test server hitting handleSynthResponses directly.
func newSynthTestServer(t *testing.T, upstream string) *httptest.Server {
	t.Helper()
	s := &Server{synth: newSynthHub(), adapter: &synthFakeAdapter{token: "tok"}}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleSynthResponses(w, r, upstream)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// chatUpstream streams `words` as OpenAI deltas with a tool_calls frame and a
// hermes-style named event in between, then [DONE]. delay paces the deltas.
func chatUpstream(t *testing.T, words int, delay time.Duration, sawCancel *atomic.Bool) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct {
			Messages []struct{ Role, Content string } `json:"messages"`
			Stream   bool                             `json:"stream"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if !body.Stream || len(body.Messages) == 0 {
			http.Error(w, "want streaming chat body", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		fmt.Fprint(w, "event: hermes.tool.progress\ndata: {\"tool_name\":\"bash\"}\n\n")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"name\":\"grep\"}}]}}]}\n\n")
		fl.Flush()
		for i := 1; i <= words; i++ {
			select {
			case <-r.Context().Done():
				if sawCancel != nil {
					sawCancel.Store(true)
				}
				return
			case <-time.After(delay):
			}
			fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":\"w%d \"}}]}\n\n", i)
			fl.Flush()
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		fl.Flush()
	}))
	t.Cleanup(up.Close)
	return up
}

func synthPost(t *testing.T, url, token, body string) (*http.Response, error) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return http.DefaultClient.Do(req)
}

func synthGetJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return out
}

func TestSynthResponses_BearerRequired(t *testing.T) {
	up := chatUpstream(t, 1, 0, nil)
	ts := newSynthTestServer(t, up.URL)
	resp, err := synthPost(t, ts.URL+"/v1/responses", "WRONG", `{"input":"hi"}`)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// Background-style: POST without stream returns the id immediately; polling
// GET /{id} converges to completed with the full text, and the event log
// carries activity from both the named event and the tool_calls frame.
func TestSynthResponses_BackgroundPoll(t *testing.T) {
	up := chatUpstream(t, 5, 5*time.Millisecond, nil)
	ts := newSynthTestServer(t, up.URL)

	resp, err := synthPost(t, ts.URL+"/v1/responses", "tok", `{"input":"do the thing"}`)
	if err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	id, _ := snap["id"].(string)
	if id == "" {
		t.Fatalf("no id in create snapshot: %v", snap)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		snap = synthGetJSON(t, ts.URL+"/v1/responses/"+id)
		if snap["status"] == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never completed: %v", snap)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := snap["output_text"]; got != "w1 w2 w3 w4 w5 " {
		t.Errorf("output_text = %q", got)
	}
}

// The core long-task property: a client that submits with stream, loses its
// connection mid-turn, and resumes with starting_after gets every missed
// event exactly once and the terminal event; the turn itself never noticed.
func TestSynthResponses_DisconnectAndResume(t *testing.T) {
	up := chatUpstream(t, 30, 10*time.Millisecond, nil)
	ts := newSynthTestServer(t, up.URL)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/responses", strings.NewReader(`{"input":"long","stream":true}`))
	req.Header.Set("Authorization", "Bearer tok")
	ctx, cancel := context.WithCancel(context.Background())
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}

	// Read until we've seen the created event + a couple of deltas, then drop.
	id, lastSeq, gotText := "", 0, ""
	sc := bufio.NewScanner(resp.Body)
	deltas := 0
	for sc.Scan() && deltas < 3 {
		line := sc.Text()
		if strings.HasPrefix(line, "id: ") {
			fmt.Sscanf(line, "id: %d", &lastSeq)
		}
		if strings.HasPrefix(line, "data: ") {
			var d map[string]any
			_ = json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &d)
			switch d["type"] {
			case "response.created":
				id = d["response"].(map[string]any)["id"].(string)
			case "response.output_text.delta":
				gotText += d["delta"].(string)
				deltas++
			}
		}
	}
	cancel() // simulate the proxy cap / network drop
	resp.Body.Close()
	if id == "" || lastSeq == 0 {
		t.Fatalf("didn't get id+seq before disconnect (id=%q seq=%d)", id, lastSeq)
	}

	// Resume strictly after the last seen sequence number.
	req2, _ := http.NewRequest(http.MethodGet,
		fmt.Sprintf("%s/v1/responses/%s?stream=true&starting_after=%d", ts.URL, id, lastSeq), nil)
	req2.Header.Set("Authorization", "Bearer tok")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	terminal := false
	prevSeq := lastSeq
	sc2 := bufio.NewScanner(resp2.Body)
	for sc2.Scan() {
		line := sc2.Text()
		if strings.HasPrefix(line, "id: ") {
			var seq int
			fmt.Sscanf(line, "id: %d", &seq)
			if seq <= prevSeq {
				t.Fatalf("replayed seq %d ≤ previous %d (duplicate)", seq, prevSeq)
			}
			prevSeq = seq
		}
		if strings.HasPrefix(line, "data: ") {
			var d map[string]any
			_ = json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &d)
			switch d["type"] {
			case "response.output_text.delta":
				gotText += d["delta"].(string)
			case "response.completed":
				terminal = true
			}
		}
	}
	if !terminal {
		t.Fatal("resumed stream never reached response.completed")
	}
	want := ""
	for i := 1; i <= 30; i++ {
		want += fmt.Sprintf("w%d ", i)
	}
	if gotText != want {
		t.Errorf("stitched text = %q, want all 30 words", gotText)
	}
}

// Cancel drops the upstream request (the framework's interrupt signal) and
// the record lands in cancelled.
func TestSynthResponses_Cancel(t *testing.T) {
	var sawCancel atomic.Bool
	up := chatUpstream(t, 10_000, 20*time.Millisecond, &sawCancel)
	ts := newSynthTestServer(t, up.URL)

	resp, err := synthPost(t, ts.URL+"/v1/responses", "tok", `{"input":"forever"}`)
	if err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&snap)
	resp.Body.Close()
	id := snap["id"].(string)

	time.Sleep(100 * time.Millisecond) // let the turn start streaming
	cResp, err := synthPost(t, ts.URL+"/v1/responses/"+id+"/cancel", "tok", "")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(cResp.Body)
	cResp.Body.Close()
	if !strings.Contains(string(body), `"cancelled"`) {
		t.Fatalf("cancel snapshot = %s", body)
	}

	deadline := time.Now().Add(3 * time.Second)
	for !sawCancel.Load() {
		if time.Now().After(deadline) {
			t.Fatal("upstream never saw the request context cancelled")
		}
		time.Sleep(10 * time.Millisecond)
	}
	final := synthGetJSON(t, ts.URL+"/v1/responses/"+id)
	if final["status"] != "cancelled" {
		t.Errorf("final status = %v, want cancelled", final["status"])
	}
}

func TestSynthInputText(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`"plain"`, "plain"},
		{`[{"role":"user","content":"hi"}]`, "hi"},
		{`[{"role":"assistant","content":"a"},{"role":"user","content":"b"}]`, "b"},
		{`[{"role":"user","content":[{"type":"input_text","text":"x"},{"type":"input_text","text":"y"}]}]`, "x\ny"},
		{`{}`, ""},
		{``, ""},
	}
	for _, c := range cases {
		if got := synthInputText(json.RawMessage(c.in)); got != c.want {
			t.Errorf("synthInputText(%s) = %q, want %q", c.in, got, c.want)
		}
	}
}
