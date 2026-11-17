package inferproxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// upstreamRecorder serves canned answers and records the last request.
type upstreamRecorder struct {
	path, auth, apiKey, version string
	body                        map[string]any
	status                      int
	answer                      string
}

func (u *upstreamRecorder) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		u.path, u.auth, u.apiKey, u.version = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("X-Api-Key"), r.Header.Get("Anthropic-Version")
		u.body = nil
		_ = json.Unmarshal(raw, &u.body)
		status := u.status
		if status == 0 {
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, u.answer)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func startProxy(t *testing.T) *Server {
	t.Helper()
	s, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func postJSON(t *testing.T, url, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m
}

func results(t *testing.T, m map[string]any) []map[string]any {
	t.Helper()
	list, ok := m["results"].([]any)
	if !ok {
		t.Fatalf("no results in %v", m)
	}
	out := make([]map[string]any, len(list))
	for i, r := range list {
		out[i] = r.(map[string]any)
	}
	return out
}

// An OpenAI search is one Responses call with the web_search tool and the
// sources included; the answer comes back first, then each source once.
func TestWebSearchOpenAI(t *testing.T) {
	up := &upstreamRecorder{answer: `{"output":[
		{"type":"web_search_call","status":"completed","action":{"type":"search","query":"q","sources":[{"type":"url","url":"https://a.example/1"},{"type":"url","url":"https://b.example/2"}]}},
		{"type":"message","content":[{"type":"output_text","text":"Zero gravity is weightlessness.","annotations":[
			{"type":"url_citation","start_index":0,"end_index":4,"url":"https://a.example/1","title":"Page A"}]}]}]}`}
	srv := up.server(t)
	s := startProxy(t)
	s.SetRoute(Route{Upstream: srv.URL, Model: "gpt-main", WebSearch: &WebSearch{Service: ServiceOpenAI, URL: srv.URL + "/v1/responses", Headers: map[string]string{"Authorization": "Bearer {placeholder}"}, Model: "gpt-search"}})
	code, m := postJSON(t, s.BaseURL()+"/v1/web/search", `{"query":"zero gravity"}`)
	if code != http.StatusOK {
		t.Fatalf("status %d %v", code, m)
	}
	if up.path != "/v1/responses" || up.auth != "Bearer {placeholder}" {
		t.Fatalf("request %s auth %q", up.path, up.auth)
	}
	tools, _ := up.body["tools"].([]any)
	if up.body["model"] != "gpt-search" || up.body["input"] != "zero gravity" || up.body["store"] != false || len(tools) != 1 || tools[0].(map[string]any)["type"] != "web_search" {
		t.Fatalf("body %v", up.body)
	}
	if inc, _ := up.body["include"].([]any); len(inc) != 1 || inc[0] != "web_search_call.action.sources" {
		t.Fatalf("include %v", up.body["include"])
	}
	rs := results(t, m)
	if len(rs) != 3 || rs[0]["url"] != "" || rs[0]["content"] != "Zero gravity is weightlessness." || !strings.Contains(rs[0]["title"].(string), "gpt-search") {
		t.Fatalf("results %v", rs)
	}
	if rs[1]["url"] != "https://a.example/1" || rs[1]["title"] != "Page A" || rs[2]["url"] != "https://b.example/2" {
		t.Fatalf("sources %v", rs[1:])
	}
}

// An Anthropic search is one Messages call with the basic web search server
// tool; citations carry their cited text, results their page age.
func TestWebSearchAnthropic(t *testing.T) {
	up := &upstreamRecorder{answer: `{"content":[
		{"type":"server_tool_use","id":"s1","name":"web_search","input":{"query":"q"}},
		{"type":"web_search_tool_result","tool_use_id":"s1","content":[
			{"type":"web_search_result","url":"https://a.example/1","title":"Page A","encrypted_content":"x","page_age":"April 30, 2025"},
			{"type":"web_search_result","url":"https://c.example/3","title":"Page C","encrypted_content":"y"}]},
		{"type":"text","text":"Born in 1916.","citations":[{"type":"web_search_result_location","url":"https://a.example/1","title":"Page A","encrypted_index":"z","cited_text":"April 30, 1916"}]}],
		"stop_reason":"end_turn"}`}
	srv := up.server(t)
	s := startProxy(t)
	s.SetRoute(Route{Upstream: srv.URL, Model: "claude-main", WebSearch: &WebSearch{Service: ServiceAnthropic, URL: srv.URL + "/v1/messages", Headers: map[string]string{"x-api-key": "{placeholder}"}, Model: "claude-main"}})
	code, m := postJSON(t, s.BaseURL()+"/web/search", `{"query":"shannon"}`)
	if code != http.StatusOK {
		t.Fatalf("status %d %v", code, m)
	}
	if up.path != "/v1/messages" || up.apiKey != "{placeholder}" || up.version != anthropicVersion || up.auth != "" {
		t.Fatalf("request %s key %q version %q auth %q", up.path, up.apiKey, up.version, up.auth)
	}
	tool := up.body["tools"].([]any)[0].(map[string]any)
	if tool["type"] != anthropicSearchTool || tool["name"] != "web_search" || tool["max_uses"] != float64(maxModelSearches) || up.body["model"] != "claude-main" {
		t.Fatalf("body %v", up.body)
	}
	rs := results(t, m)
	if len(rs) != 3 || rs[0]["content"] != "Born in 1916." {
		t.Fatalf("results %v", rs)
	}
	if rs[1]["url"] != "https://a.example/1" || rs[1]["content"] != "April 30, 1916" || rs[1]["published_date"] != "April 30, 2025" || rs[2]["url"] != "https://c.example/3" {
		t.Fatalf("sources %v", rs[1:])
	}
}

// Errors come back in the shape the harness reads a message from: the
// provider's own status and message, or a search error with no answer.
func TestWebSearchModelErrors(t *testing.T) {
	up := &upstreamRecorder{}
	srv := up.server(t)
	s := startProxy(t)
	for _, c := range []struct {
		name, service string
		status        int
		answer        string
		wantCode      int
		wantMessage   string
	}{
		{"provider refuses", ServiceOpenAI, http.StatusUnauthorized, `{"error":{"message":"bad key"}}`, http.StatusUnauthorized, "openai web search: bad key"},
		{"search error and no answer", ServiceAnthropic, 0, `{"content":[{"type":"web_search_tool_result","tool_use_id":"s","content":{"type":"web_search_tool_result_error","error_code":"too_many_requests"}}],"stop_reason":"end_turn"}`, http.StatusBadGateway, "too_many_requests"},
		{"not JSON", ServiceOpenAI, 0, `<html>`, http.StatusBadGateway, "not a Responses object"},
	} {
		t.Run(c.name, func(t *testing.T) {
			up.status, up.answer = c.status, c.answer
			s.SetRoute(Route{Upstream: srv.URL, Model: "m", WebSearch: &WebSearch{Service: c.service, URL: srv.URL + "/v1/x", Model: "m"}})
			code, m := postJSON(t, s.BaseURL()+"/v1/web/search", `{"query":"q"}`)
			msg, _ := m["error"].(map[string]any)["message"].(string)
			if code != c.wantCode || !strings.Contains(msg, c.wantMessage) {
				t.Fatalf("status %d message %q", code, msg)
			}
		})
	}
	// The bounds hold before anything is sent.
	up.path = ""
	s.SetRoute(Route{Upstream: srv.URL, Model: "m", WebSearch: &WebSearch{Service: ServiceOpenAI, URL: srv.URL + "/v1/responses", Model: "m"}})
	for _, bad := range []string{`{}`, `{"query":""}`, `{"query":"` + strings.Repeat("q", maxSearchQuery+1) + `"}`} {
		if code, _ := postJSON(t, s.BaseURL()+"/v1/web/search", bad); code != http.StatusBadRequest {
			t.Fatalf("%s: %d", bad, code)
		}
	}
	if up.path != "" {
		t.Fatal("a refused search reached the provider")
	}
}

// Named routes: each has its own upstream, credential headers and model set;
// a model outside the set is refused there, sent as the pin on the main
// route, and web/search exists on the main route only.
func TestNamedRoutes(t *testing.T) {
	main, second := &upstreamRecorder{answer: `{}`}, &upstreamRecorder{answer: `{}`}
	mainSrv, secondSrv := main.server(t), second.server(t)
	s := startProxy(t)
	err := s.SetRoutes(
		Route{Upstream: mainSrv.URL + "/v1", Headers: map[string]string{"Authorization": "Bearer main"}, Model: "glm-5.3", Models: []string{"deepseek-v3"}, System: "DOC",
			WebSearch: &WebSearch{URL: mainSrv.URL + "/v1/web/search"}},
		map[string]Route{"openai+key": {Upstream: secondSrv.URL + "/v1", Headers: map[string]string{"Authorization": "Bearer [[credential:key]]"}, Model: "gpt-x", Models: []string{"gpt-y"}, System: "DOC",
			WebSearch: &WebSearch{URL: secondSrv.URL + "/v1/web/search"}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	chat := func(model string) string {
		return `{"model":"` + model + `","messages":[{"role":"user","content":"hi"}]}`
	}

	// Main route: its own models pass, any other name is sent as the pin.
	for model, want := range map[string]string{"glm-5.3": "glm-5.3", "deepseek-v3": "deepseek-v3", "gpt-x": "glm-5.3", "": "glm-5.3"} {
		if code, _ := postJSON(t, s.BaseURL()+"/chat/completions", chat(model)); code != http.StatusOK || main.body["model"] != want {
			t.Fatalf("main route, %q: %d sent %v", model, code, main.body["model"])
		}
	}
	if main.auth != "Bearer main" {
		t.Fatalf("main auth %q", main.auth)
	}

	// Named route: its own upstream and key, its models, the platform doc.
	base := s.NamedBaseURL("openai+key")
	for _, model := range []string{"gpt-x", "gpt-y"} {
		if code, _ := postJSON(t, base+"/chat/completions", chat(model)); code != http.StatusOK || second.body["model"] != model || second.path != "/v1/chat/completions" {
			t.Fatalf("named route, %s: %d sent %v to %s", model, code, second.body["model"], second.path)
		}
	}
	if second.auth != "Bearer [[credential:key]]" {
		t.Fatalf("named auth %q", second.auth)
	}
	msgs := second.body["messages"].([]any)
	if first := msgs[0].(map[string]any); first["role"] != "system" || first["content"] != "DOC" {
		t.Fatalf("platform doc missing on a named route: %v", msgs)
	}
	second.path = ""
	for _, model := range []string{"glm-5.3", "unknown", ""} {
		if code, _ := postJSON(t, base+"/chat/completions", chat(model)); code != http.StatusBadRequest {
			t.Fatalf("named route, %q: %d, want 400", model, code)
		}
	}
	if second.path != "" {
		t.Fatal("a refused model reached the named route's upstream")
	}

	// The log names each further model once per route (noteModel), never
	// the main route's own model.
	for key, want := range map[string]bool{"main\x00deepseek-v3": true, "openai+key\x00gpt-x": true, "openai+key\x00gpt-y": true, "main\x00glm-5.3": false} {
		if s.used[key] != want {
			t.Fatalf("model use %q recorded %v, want %v", key, s.used[key], want)
		}
	}

	// No such route; no web search on a named route; bad ids are refused.
	if code, _ := postJSON(t, s.NamedBaseURL("nope")+"/chat/completions", chat("gpt-x")); code != http.StatusNotFound {
		t.Fatalf("unknown route: %d", code)
	}
	if code, _ := postJSON(t, base+"/v1/web/search", `{"query":"q"}`); code != http.StatusNotFound {
		t.Fatalf("named web/search: %d", code)
	}
	if err := s.SetRoutes(Route{Model: "m"}, map[string]Route{"Bad Id": {}}); err == nil {
		t.Fatal("a bad route id was accepted")
	}

	// SetRoute drops the named routes.
	s.SetRoute(Route{Upstream: mainSrv.URL + "/v1", Model: "glm-5.3"})
	if code, _ := postJSON(t, base+"/chat/completions", chat("gpt-x")); code != http.StatusNotFound {
		t.Fatalf("after SetRoute: %d", code)
	}
}

// A search paid with a named owner credential the credential proxy refuses
// (an unknown name, a host it may not go to) reports the proxy's reason, not
// "no error message".
func TestUpstreamMessageCredentialRefusal(t *testing.T) {
	body := []byte(`{"code":"unknown_entry","message":"no credential named \"no-such-cred\""}`)
	got := upstreamMessage(body, "unknown_entry")
	want := `the credential proxy refused it (unknown_entry): no credential named "no-such-cred"`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := upstreamMessage([]byte(`{"error":{"message":"bad key"}}`), ""); got != "bad key" {
		t.Fatalf("provider error: got %q", got)
	}
	if got := upstreamMessage([]byte(`not json`), ""); got != "no error message" {
		t.Fatalf("no message: got %q", got)
	}
}
