package inferproxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRewriteChat(t *testing.T) {
	for _, test := range []struct {
		name, in string
		check    func(t *testing.T, msgs []any)
	}{
		{"a string system message", `{"model":"x","stream":true,"messages":[{"role":"system","content":"persona"},{"role":"user","content":"hi"}]}`,
			func(t *testing.T, msgs []any) {
				if got := msgs[0].(map[string]any)["content"]; got != "persona\n\nPLATFORM" {
					t.Fatalf("system content %q", got)
				}
				if len(msgs) != 2 {
					t.Fatalf("%d messages", len(msgs))
				}
			}},
		{"a developer message of parts", `{"messages":[{"role":"developer","content":[{"type":"text","text":"persona"}]},{"role":"user","content":"hi"}]}`,
			func(t *testing.T, msgs []any) {
				parts := msgs[0].(map[string]any)["content"].([]any)
				if len(parts) != 2 || parts[1].(map[string]any)["text"] != "PLATFORM" {
					t.Fatalf("parts %v", parts)
				}
			}},
		{"no system message", `{"messages":[{"role":"user","content":"hi"}]}`,
			func(t *testing.T, msgs []any) {
				first := msgs[0].(map[string]any)
				if first["role"] != "system" || first["content"] != "PLATFORM" || len(msgs) != 2 {
					t.Fatalf("messages %v", msgs)
				}
			}},
	} {
		t.Run(test.name, func(t *testing.T) {
			out, err := Rewrite("chat", []byte(test.in), "owner-model", "PLATFORM")
			if err != nil {
				t.Fatal(err)
			}
			m := decode(t, out)
			if m["model"] != "owner-model" {
				t.Fatalf("model %v", m["model"])
			}
			if strings.Contains(test.in, `"stream":true`) && m["stream"] != true {
				t.Fatal("stream lost")
			}
			test.check(t, m["messages"].([]any))
		})
	}
}

func TestRewriteMessagesAndResponses(t *testing.T) {
	out, err := Rewrite("messages", []byte(`{"model":"x","system":"persona","messages":[]}`), "m", "PLATFORM")
	if err != nil {
		t.Fatal(err)
	}
	if got := decode(t, out)["system"]; got != "persona\n\nPLATFORM" {
		t.Fatalf("system %q", got)
	}
	out, err = Rewrite("messages", []byte(`{"system":[{"type":"text","text":"persona","cache_control":{"type":"ephemeral"}}]}`), "m", "PLATFORM")
	if err != nil {
		t.Fatal(err)
	}
	blocks := decode(t, out)["system"].([]any)
	if len(blocks) != 2 || blocks[0].(map[string]any)["cache_control"] == nil || blocks[1].(map[string]any)["text"] != "PLATFORM" {
		t.Fatalf("system blocks %v", blocks)
	}
	out, err = Rewrite("messages", []byte(`{"messages":[]}`), "m", "PLATFORM")
	if err != nil || decode(t, out)["system"] != "PLATFORM" {
		t.Fatalf("no system: %s %v", out, err)
	}
	out, err = Rewrite("responses", []byte(`{"instructions":"persona","input":"hi"}`), "m", "PLATFORM")
	if err != nil || decode(t, out)["instructions"] != "persona\n\nPLATFORM" {
		t.Fatalf("responses: %s %v", out, err)
	}
	if _, err := Rewrite("chat", []byte(`[1,2]`), "m", "P"); err == nil {
		t.Fatal("a non-object body was rewritten")
	}
}

// The proxy: only model calls pass, with the model, the platform text and
// the route's headers; the framework's credential headers never go out; a
// stream comes back as it is.
func TestServerForwards(t *testing.T) {
	var got struct {
		path, auth, apiKey, other string
		body                      map[string]any
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.path, got.auth, got.apiKey, got.other = r.URL.RequestURI(), r.Header.Get("Authorization"), r.Header.Get("X-Api-Key"), r.Header.Get("X-Other")
		b, _ := io.ReadAll(r.Body)
		got.body = nil
		if len(b) > 0 {
			got.body = decode(t, b)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: ok\n\n")
	}))
	defer upstream.Close()

	s, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path, body string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, s.BaseURL()+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer framework-key")
		req.Header.Set("X-Api-Key", "framework-key")
		req.Header.Set("X-Other", "kept")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	if resp := do(http.MethodPost, "/chat/completions", `{"messages":[]}`); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("before a route is set: %d", resp.StatusCode)
	}
	s.SetRoute(Route{Upstream: upstream.URL + "/v1", Headers: map[string]string{"Authorization": "Bearer {placeholder}"}, Model: "owner-model", System: "PLATFORM"})

	resp := do(http.MethodPost, "/chat/completions?x=1", `{"model":"other","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(b) != "data: ok\n\n" || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("answer %d %q %q", resp.StatusCode, b, resp.Header.Get("Content-Type"))
	}
	if got.path != "/v1/chat/completions?x=1" || got.auth != "Bearer {placeholder}" || got.apiKey != "" || got.other != "kept" {
		t.Fatalf("upstream got %+v", got)
	}
	if got.body["model"] != "owner-model" || got.body["messages"].([]any)[0].(map[string]any)["content"] != "PLATFORM" {
		t.Fatalf("upstream body %v", got.body)
	}

	if resp := do(http.MethodGet, "/models", ""); resp.StatusCode != http.StatusOK || got.path != "/v1/models" {
		t.Fatalf("models: %d %s", resp.StatusCode, got.path)
	}
	// The Anthropic wire's path, as its client builds it on a base URL
	// without /v1 (this route's upstream has one, so it doubles here).
	if resp := do(http.MethodPost, "/v1/messages", `{"messages":[]}`); resp.StatusCode != http.StatusOK || got.path != "/v1/v1/messages" {
		t.Fatalf("messages: %d %s", resp.StatusCode, got.path)
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/files"},
		{http.MethodGet, "/chat/completions"},
		{http.MethodDelete, "/models"},
		// Paths that only end like a model call.
		{http.MethodPost, "/threads/thread_1/messages"},
		{http.MethodPost, "/v1/threads/thread_1/messages"},
		{http.MethodPost, "/x/chat/completions"},
		{http.MethodGet, "/fine_tuning/models"},
		{http.MethodPost, "/v1/v1/messages"},
	} {
		if resp := do(c.method, c.path, "{}"); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s: %d, want 404", c.method, c.path, resp.StatusCode)
		}
	}
	// The path token: without it, nothing.
	resp, err = http.Post(strings.TrimSuffix(s.BaseURL(), "/"+s.token)+"/chat/completions", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("without the token: %d", resp.StatusCode)
	}
}
