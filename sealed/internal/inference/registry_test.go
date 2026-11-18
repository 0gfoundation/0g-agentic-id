package inference

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProviderRegistryRejectsInvalidDefinitions(t *testing.T) {
	for _, raw := range []string{
		`[{"id":"bad provider","formats":["openai"]}]`,
		`[{"id":"a","native":true,"formats":["openai"]},{"id":"a","native":true,"formats":["openai"]}]`,
		`[{"id":"a","formats":["openai"],"defaultFormat":"openai","endpoints":{"openai":"http://example.com"}}]`,
		`[{"id":"a","formats":["openai"],"defaultFormat":"openai","endpoints":{"openai":"https://user:secret@example.com"}}]`,
		`[{"id":"a","native":true,"formats":["openai"],"endpoints":{"openai":"https://example.com"}}]`,
		`[{"id":"a","formats":["other"]}]`,
	} {
		if _, err := NewRegistry([]byte(raw)); err == nil {
			t.Fatalf("accepted invalid definitions: %s", raw)
		}
	}
}

func TestIDOnlyCatalogDoesNotClaimReasoningIsUnsupported(t *testing.T) {
	r, err := NewRegistry([]byte(`[{"id":"partner","formats":["openai"],"defaultFormat":"openai","endpoints":{"openai":"https://partner.example/v1"},"models":[{"id":"id-only"}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	facts, _, err := r.Resolve(context.Background(), "partner", "id-only")
	if err != nil {
		t.Fatal(err)
	}
	if facts.CatalogSourced {
		t.Fatal("an ID-only listing must not clear existing reasoning settings")
	}
}

func TestAdditionalProviderUsesItsOwnEndpointMetadataAndCompatibility(t *testing.T) {
	r, err := NewRegistry([]byte(`[{"id":"partner","name":"Partner","formats":["openai"],"defaultFormat":"openai","endpoints":{"openai":"https://partner.example/v1"},"compatibility":{"supportsDeveloperRole":true},"models":[{"id":"claude-private","context_length":64000,"max_completion_tokens":12000,"supported_formats":["openai"],"supported_parameters":["reasoning_effort"]}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	facts, endpoint, err := r.Resolve(context.Background(), "partner", "claude-private")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.BaseURL != "https://partner.example/v1" || endpoint.Format != WireOpenAI || endpoint.ProviderID != "partner" {
		t.Fatalf("wrong provider route: %+v", endpoint)
	}
	if !facts.CatalogSourced || !facts.SupportsReasoningEffort || facts.MaxTokens != 12000 {
		t.Fatalf("wrong facts: %+v", facts)
	}
	if endpoint.Compatibility["supportsDeveloperRole"] != true {
		t.Fatal("provider compatibility lost")
	}
	endpoint.Compatibility["supportsDeveloperRole"] = false
	_, fresh, _ := r.Resolve(context.Background(), "partner", "unlisted-model")
	if fresh.Compatibility["supportsDeveloperRole"] != true {
		t.Fatal("a rendered config mutated the registry")
	}
	if _, _, err := r.Resolve(context.Background(), "typo", "m"); err == nil {
		t.Fatal("unknown provider must fail")
	}
}

func TestAdditionalProviderCatalogDoesNotFallBackToCompute(t *testing.T) {
	fail := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "" {
			t.Error("a public catalog received credentials")
		}
		if fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "private", "supported_formats": []string{"anthropic"}, "supported_parameters": []string{}, "max_completion_tokens": 9000}}})
	}))
	defer server.Close()
	raw, _ := json.Marshal([]Provider{{ID: "partner", Formats: []WireFormat{WireOpenAI, WireAnthropic}, DefaultFormat: WireOpenAI, Endpoints: map[WireFormat]string{WireOpenAI: "https://partner.example/v1", WireAnthropic: "https://partner.example"}, ModelCatalog: server.URL}})
	r, err := NewRegistry(raw)
	if err != nil {
		t.Fatal(err)
	}
	r.client = server.Client()
	facts, endpoint, err := r.Resolve(context.Background(), "partner", "private")
	if err != nil || endpoint.Format != WireAnthropic || facts.MaxTokens != 9000 {
		t.Fatalf("catalog route: %+v %+v %v", facts, endpoint, err)
	}
	fail = true
	facts, endpoint, err = r.Resolve(context.Background(), "partner", "claude-private")
	if err != nil || endpoint.Format != WireOpenAI || facts.CatalogSourced || facts.MaxTokens != 0 {
		t.Fatalf("outage must keep provider fallback without compute guesses: %+v %+v %v", facts, endpoint, err)
	}
}

// The native providers' official endpoints: one per native provider in the
// registry, each speaking that provider's one wire format.
func TestNativeEndpoints(t *testing.T) {
	for id, want := range map[string]struct {
		base   string
		format WireFormat
	}{
		"openai":    {"https://api.openai.com/v1", WireOpenAI},
		"anthropic": {"https://api.anthropic.com", WireAnthropic},
	} {
		ep, ok := NativeEndpoint(id)
		if !ok || ep.BaseURL != want.base || ep.Format != want.format || ep.ProviderID != id {
			t.Fatalf("%s: %+v, %v", id, ep, ok)
		}
		if p := DefaultRegistry.providers[id]; !p.Native || len(p.Formats) != 1 || p.Formats[0] != want.format {
			t.Fatalf("%s is not the registry's native provider of that format: %+v", id, p)
		}
	}
	if _, ok := NativeEndpoint(ZGComputeProvider); ok {
		t.Fatal("0g-compute has a native endpoint")
	}
	for id, p := range DefaultRegistry.providers {
		if _, ok := NativeEndpoint(id); p.Native && !ok {
			t.Fatalf("native provider %s has no official endpoint", id)
		}
	}
}

// Each provider names the web search service its key pays for; the field is
// outside the route hash, and an unknown service is refused.
func TestProviderWebSearch(t *testing.T) {
	want := map[string]string{ZGComputeProvider: SearchZGRouter, "openai": SearchOpenAI, "anthropic": SearchAnthropic}
	for id, service := range want {
		if got := DefaultRegistry.providers[id].WebSearch; got != service {
			t.Fatalf("%s: webSearch %q, want %q", id, got, service)
		}
	}
	for id, service := range map[string]string{"openai": SearchOpenAI, "anthropic": SearchAnthropic} {
		if ep, _ := NativeEndpoint(id); ep.WebSearch != service {
			t.Fatalf("native %s endpoint: webSearch %q", id, ep.WebSearch)
		}
	}
	if SearchBaseURL(SearchZGRouter) != "https://router-api.0g.ai/v1" || SearchBaseURL(SearchOpenAI) != "https://api.openai.com/v1" ||
		SearchBaseURL(SearchAnthropic) != "https://api.anthropic.com" || SearchBaseURL("bing") != "" {
		t.Fatal("search base URLs")
	}
	// A registry published before the field keeps the router's search.
	old, err := NewRegistry([]byte(`[{"id":"0g-compute","name":"0G","formats":["openai"],"defaultFormat":"openai","endpoints":{"openai":"https://router.example/v1"},"models":[{"id":"m"}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ep, err := old.Resolve(context.Background(), ZGComputeProvider, "m"); err != nil || ep.WebSearch != SearchZGRouter {
		t.Fatalf("legacy registry: %+v %v", ep, err)
	}
	withField, _ := NewRegistry([]byte(`[{"id":"0g-compute","name":"0G","formats":["openai"],"defaultFormat":"openai","endpoints":{"openai":"https://router.example/v1"},"webSearch":"0g-router"}]`))
	before, _ := old.RouteHash(ZGComputeProvider)
	after, _ := withField.RouteHash(ZGComputeProvider)
	if before != after {
		t.Fatal("webSearch changed the route hash")
	}
	if _, err := NewRegistry([]byte(`[{"id":"a","name":"A","formats":["openai"],"defaultFormat":"openai","endpoints":{"openai":"https://a.example/v1"},"webSearch":"bing"}]`)); err == nil {
		t.Fatal("an unknown search service was accepted")
	}
}
