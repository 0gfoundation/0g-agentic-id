package inference

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func withCatalog(t *testing.T, body string) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	old := zgModelsURL
	zgModelsURL = srv.URL
	t.Cleanup(func() { zgModelsURL = old })
}

func TestResolveZG_AnthropicOnlyModel(t *testing.T) {
	// The exact shape that broke openclaw live: claude models are served
	// on the anthropic endpoint only.
	withCatalog(t, `{"data":[{"id":"claude-sonnet-5","supported_formats":["anthropic"],"context_length":1000000,"max_completion_tokens":131072}]}`)
	r := ResolveZG(context.Background(), "claude-sonnet-5")
	if r.Format != WireAnthropic || r.BaseURL != ZGAnthropicBaseURL || r.EnvKey != "ANTHROPIC_API_KEY" {
		t.Errorf("route = %+v; want anthropic wire", r)
	}
	if r.ContextWindow != 1000000 || r.MaxTokens != 131072 {
		t.Errorf("catalog limits not applied: %+v", r)
	}
}

func TestResolveZG_DualFormatPrefersOpenAI(t *testing.T) {
	withCatalog(t, `{"data":[{"id":"glm-5.2","supported_formats":["openai","anthropic"],"context_length":204800,"max_completion_tokens":16384}]}`)
	r := ResolveZG(context.Background(), "glm-5.2")
	if r.Format != WireOpenAI || r.BaseURL != ZGOpenAIBaseURL || r.EnvKey != "OPENAI_API_KEY" {
		t.Errorf("route = %+v; want openai wire preferred", r)
	}
}

func TestResolveZG_FallbackHeuristicOnOutage(t *testing.T) {
	old := zgModelsURL
	zgModelsURL = "http://127.0.0.1:1/nope" // connection refused
	t.Cleanup(func() { zgModelsURL = old })

	if r := ResolveZG(context.Background(), "claude-sonnet-5"); r.Format != WireAnthropic {
		t.Errorf("claude heuristic = %+v; want anthropic", r)
	}
	if r := ResolveZG(context.Background(), "glm-5.2"); r.Format != WireOpenAI {
		t.Errorf("glm heuristic = %+v; want openai", r)
	}
}

func TestResolveZG_UnlistedModelUsesHeuristic(t *testing.T) {
	withCatalog(t, `{"data":[{"id":"something-else","supported_formats":["openai"]}]}`)
	if r := ResolveZG(context.Background(), "claude-fable-5"); r.Format != WireAnthropic {
		t.Errorf("unlisted claude model = %+v; want anthropic heuristic", r)
	}
}

func TestResolveZG_ListedModelWithoutFormatsUsesHeuristic(t *testing.T) {
	// Router-side schema drift: the model IS in the catalog but
	// supported_formats is missing/renamed/empty. Hardcoding OpenAI here
	// would re-create the original first-inference 400 for every claude
	// model — the name heuristic must apply, same as an outage.
	withCatalog(t, `{"data":[{"id":"claude-sonnet-5","context_length":1000000},{"id":"glm-5.2"}]}`)
	if r := ResolveZG(context.Background(), "claude-sonnet-5"); r.Format != WireAnthropic {
		t.Errorf("formats-less claude model = %+v; want anthropic heuristic", r)
	}
	if r := ResolveZG(context.Background(), "glm-5.2"); r.Format != WireOpenAI {
		t.Errorf("formats-less glm model = %+v; want openai heuristic", r)
	}
}

// The catalog's architecture.input_modalities says whether a model takes
// images (the 0G router's shape); an entry without it says nothing.
func TestResolveZG_InputModalities(t *testing.T) {
	withCatalog(t, `{"data":[
		{"id":"glm-5.3","supported_formats":["openai"],"architecture":{"input_modalities":["text"],"output_modalities":["text"]}},
		{"id":"glm-5.3-flash","supported_formats":["openai"],"architecture":{"input_modalities":["text","image"]}},
		{"id":"plain","supported_formats":["openai"]}]}`)
	for _, c := range []struct {
		model        string
		takes, known bool
	}{{"glm-5.3", false, true}, {"glm-5.3-flash", true, true}, {"plain", false, false}} {
		takes, known := ResolveZG(context.Background(), c.model).TakesImages()
		if takes != c.takes || known != c.known {
			t.Errorf("%s: TakesImages = %v, %v; want %v, %v", c.model, takes, known, c.takes, c.known)
		}
	}
	// A catalog outage is not "text-only": nothing is known.
	zgModelsURL = "http://127.0.0.1:1/nope"
	if _, known := ResolveZG(context.Background(), "glm-5.3").TakesImages(); known {
		t.Error("the heuristic claims to know the model's input")
	}
}
