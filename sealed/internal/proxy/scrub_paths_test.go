package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"seal-verify/internal/state"
)

// Upgrade headers on an ordinary request to a registered service do not
// skip scrubbing: a backend that answers anything but 101 is relayed as a
// response like any other.
func TestUpgradeHeadersDoNotSkipScrub(t *testing.T) {
	const value = "ghp_the_value_itself_0123456789"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Debug", "token="+value)
		_, _ = w.Write([]byte(`{"token":"` + value + `"}`))
	}))
	defer backend.Close()

	ag := state.New()
	ag.Set([]byte{1}, backend.URL, "deadbeef", "0x00", "1", "0x00", "1", "0x00", "")
	s := &Server{agent: ag}
	s.SetScrubber(scrubValues{value})
	s.services = []ServiceEntry{{Path: "/api/echo", Method: http.MethodGet, Backend: backend.URL}}

	r := httptest.NewRequest(http.MethodGet, "/api/echo", nil)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	w := httptest.NewRecorder()
	s.handleProxy(w, r)
	if strings.Contains(w.Body.String(), value) || strings.Contains(w.Header().Get("X-Debug"), value) {
		t.Fatalf("HTTP %d: the value left unscrubbed: body %s, header %q", w.Code, w.Body.String(), w.Header().Get("X-Debug"))
	}
}

// A value the model streams in two deltas is whole only in the stored
// output_text of the synthesized /v1/responses, which is scrubbed as such.
func TestSynthStoredResultScrubbedWhole(t *testing.T) {
	const value = "ghp_the_value_itself_0123456789"
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q}}]}\n\n", value[:12])
		fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q}}]}\n\n", value[12:])
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer up.Close()
	s := &Server{synth: newSynthHub(), adapter: &synthFakeAdapter{token: "tok"}}
	s.SetScrubber(scrubValues{value})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.handleSynthResponses(w, r, up.URL) }))
	defer ts.Close()
	resp, err := synthPost(t, ts.URL+"/v1/responses", "tok", `{"input":"hi"}`)
	if err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&snap)
	resp.Body.Close()
	id, _ := snap["id"].(string)
	deadline := time.Now().Add(5 * time.Second)
	for snap["status"] != "completed" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		snap = synthGetJSON(t, ts.URL+"/v1/responses/"+id)
	}
	if out, _ := snap["output_text"].(string); strings.Contains(out, value) {
		t.Fatalf("stored result holds the value: %q", out)
	}
}

// /hello lists the agent's services in its own words: scrubbed before the
// proof covers them.
func TestHelloServicesScrubbed(t *testing.T) {
	const value = "ghp_the_value_itself_0123456789"
	ag := state.New()
	ag.Set([]byte{1}, "http://127.0.0.1:1", "deadbeef", "0x00", "1", "0x00", "1", "0x00", "")
	s := &Server{agent: ag}
	s.SetScrubber(scrubValues{value})
	s.services = []ServiceEntry{{Path: "/api/echo", Method: http.MethodGet, Backend: "http://127.0.0.1:1", Description: "uses " + value}}
	w := httptest.NewRecorder()
	s.handleHello(w, httptest.NewRequest(http.MethodGet, "/hello", nil))
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), value) {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
}
