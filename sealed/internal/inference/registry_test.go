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
