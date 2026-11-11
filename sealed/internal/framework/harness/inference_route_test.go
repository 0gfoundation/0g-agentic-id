package harness

import (
	"strings"
	"testing"

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
