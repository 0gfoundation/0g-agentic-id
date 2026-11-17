package harness

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/inference"
	"seal-verify/internal/settings"
)

// The agent doc path reaches the harness only when the doc is a file (a
// framework built-in model); through sealed's inference route it rides the
// model requests instead, and the harness is told of no file.
func TestBridgeEnvAgentDocOnlyAsAFile(t *testing.T) {
	has := func(env []string) bool {
		for _, kv := range env {
			if strings.HasPrefix(kv, "SEAL_AGENT_DOC=") {
				return true
			}
		}
		return false
	}
	if has(bridgeEnv{token: "tok"}.environ()) {
		t.Error("SEAL_AGENT_DOC set without a doc file")
	}
	if !has(bridgeEnv{token: "tok", agentDoc: agentDocPath()}.environ()) {
		t.Error("SEAL_AGENT_DOC missing with a doc file")
	}
}

// The inference route carries the key the way each wire takes it.
func TestInferenceHeaders(t *testing.T) {
	if h := inferenceHeaders(inference.WireOpenAI, "k"); len(h) != 1 || h["Authorization"] != "Bearer k" {
		t.Fatalf("openai: %v", h)
	}
	if h := inferenceHeaders(inference.WireAnthropic, "k"); len(h) != 1 || h["x-api-key"] != "k" {
		t.Fatalf("anthropic: %v", h)
	}
}

// One inference route per adapter, kept across starts.
func TestInferenceRouteIsKept(t *testing.T) {
	a := New()
	first, err := a.inferenceRoute()
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.inferenceRoute()
	if err != nil || second != first {
		t.Fatalf("a second route (%v)", err)
	}
	if !strings.HasPrefix(first.BaseURL(), "http://127.0.0.1:") {
		t.Fatalf("base URL %q is not loopback", first.BaseURL())
	}
}

// Every provider sealed knows goes through the inference route: a
// platform-routed model to its registry endpoint, a native provider to its
// official endpoint.
func TestModelEndpoint(t *testing.T) {
	routed := &inference.Endpoint{ProviderID: "0g-compute", Format: inference.WireOpenAI, BaseURL: "https://router.example/v1"}
	if ep := modelEndpoint(settings.Resolved{Doc: settings.Doc{Provider: "0g-compute"}, Endpoint: routed}); ep != routed {
		t.Fatalf("platform-routed: %+v", ep)
	}
	for provider, base := range map[string]string{"openai": "https://api.openai.com/v1", "anthropic": "https://api.anthropic.com"} {
		if ep := modelEndpoint(settings.Resolved{Doc: settings.Doc{Provider: provider}}); ep == nil || ep.BaseURL != base {
			t.Fatalf("%s: %+v", provider, ep)
		}
	}
	if ep := modelEndpoint(settings.Resolved{Doc: settings.Doc{Provider: "unknown"}}); ep != nil {
		t.Fatalf("unknown provider: %+v", ep)
	}
}

// Through the inference route the harness is told the route's address and
// wire protocol and a placeholder key, over whatever the settings rendered.
func TestBridgeEnvThroughTheRoute(t *testing.T) {
	env := bridgeEnv{token: "tok", apiKey: routedKeyPlaceholder, modelBaseURL: "http://127.0.0.1:1/t", modelAPI: "anthropic-messages",
		settingsEnv: []string{"SEAL_MODEL_API=openai-completions", "SEAL_MODEL_BASE_URL=https://router.example/v1", "SEAL_MODEL_ID=m"}}.environ()
	got := map[string][]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = append(got[k], v)
	}
	for k, want := range map[string]string{
		"SEAL_MODEL_API":      "anthropic-messages",
		"SEAL_MODEL_BASE_URL": "http://127.0.0.1:1/t",
		"SEAL_MODEL_API_KEY":  routedKeyPlaceholder,
		"SEAL_MODEL_ID":       "m",
	} {
		if len(got[k]) != 1 || got[k][0] != want {
			t.Errorf("%s = %v, want [%s]", k, got[k], want)
		}
	}
}

// The search endpoint reaches the harness only when Start set one (a model
// on the 0G router with the web tools on).
func TestBridgeEnvWebSearch(t *testing.T) {
	has := func(env []string) string {
		for _, kv := range env {
			if v, ok := strings.CutPrefix(kv, "SEAL_HARNESS_WEB_SEARCH_URL="); ok {
				return v
			}
		}
		return ""
	}
	if got := has(bridgeEnv{token: "tok"}.environ()); got != "" {
		t.Fatalf("no search URL set, yet %q", got)
	}
	if got := has(bridgeEnv{token: "tok", webSearchURL: "http://127.0.0.1:1/t/v1/web/search"}.environ()); got != "http://127.0.0.1:1/t/v1/web/search" {
		t.Fatalf("search URL %q", got)
	}
}

// Start lets web/search through the inference route only for a model on the
// 0G router with the web tools on: a malformed search is then refused as
// such (400), and everywhere else the path does not exist (404). No request
// leaves the box: the body is checked before anything is forwarded.
func TestStart_WebSearchOnlyForTheRouter(t *testing.T) {
	catalogServer(t, reasoningModel("glm-5.3"))
	for _, c := range []struct {
		name     string
		doc      settings.Doc
		wantCode int
	}{
		{"0g router, web tools on", settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3"}, http.StatusBadRequest},
		{"0g router, web tools off", settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3", Others: json.RawMessage(`{"webTools":false}`)}, http.StatusNotFound},
		{"a native provider", settings.Doc{Provider: "openai", Model: "gpt-x"}, http.StatusNotFound},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := New()
			dshHome = t.TempDir()
			if err := a.RenderSettings(context.Background(), settings.Resolve(context.Background(), c.doc, "")); err != nil {
				t.Fatalf("RenderSettings: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, _ = a.Start(ctx, framework.RuntimeContext{APIKey: "k"})
			defer func() { _ = a.Stop(context.Background(), 0) }()
			route, err := a.inferenceRoute()
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.Post(route.BaseURL()+"/v1/web/search", "application/json", strings.NewReader(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != c.wantCode {
				t.Fatalf("web/search: %d, want %d", resp.StatusCode, c.wantCode)
			}
		})
	}
}
