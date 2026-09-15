package openclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"seal-verify/internal/inference"
)

// The live regression: 0g-compute serves claude-* on its Anthropic-format
// endpoint only; the augmentation must emit the anthropic dialect
// (provider/api/baseUrl/env key), not force everything through the
// OpenAI path (which 400'd on testnet: "model 'claude-sonnet-5' is not
// available on the openai API format").
func TestZGAugmentation_AnthropicWire(t *testing.T) {
	cfg := map[string]any{}
	route := inference.Route{
		Format: inference.WireAnthropic, BaseURL: inference.ZGAnthropicBaseURL,
		EnvKey: "ANTHROPIC_API_KEY", ContextWindow: 1000000, MaxTokens: 131072, CatalogSourced: true,
	}
	applyZGComputeToConfig(cfg, "claude-sonnet-5", route)

	pick := inferencePickFromConfig(cfg)
	if pick.Provider != "anthropic" || pick.Model != "claude-sonnet-5" {
		t.Errorf("primary = %s/%s; want anthropic/claude-sonnet-5", pick.Provider, pick.Model)
	}
	providers := cfg["models"].(map[string]any)["providers"].(map[string]any)
	entry, ok := providers["anthropic"].(map[string]any)
	if !ok {
		t.Fatalf("no anthropic provider entry: %v", providers)
	}
	if entry["api"] != "anthropic-messages" {
		t.Errorf("api = %v; want anthropic-messages", entry["api"])
	}
	if entry["baseUrl"] != inference.ZGAnthropicBaseURL {
		t.Errorf("baseUrl = %v; want %s (no /v1 — anthropic clients append /v1/messages)", entry["baseUrl"], inference.ZGAnthropicBaseURL)
	}
	if entry["apiKey"].(map[string]any)["id"] != "ANTHROPIC_API_KEY" {
		t.Errorf("apiKey env = %v; want ANTHROPIC_API_KEY", entry["apiKey"])
	}
	modelDef := entry["models"].([]any)[0].(map[string]any)
	if _, hasCompat := modelDef["compat"]; hasCompat {
		t.Error("anthropic wire must not carry the openai compat block")
	}
	if modelDef["contextWindow"] != 1000000 || modelDef["maxTokens"] != 131072 {
		t.Errorf("catalog limits not applied: %v", modelDef)
	}
}

// Dual/openai-format models keep the existing OpenAI dialect, including
// the requiresStringContent compat that 0G's OpenAI endpoint needs.
func TestZGAugmentation_OpenAIWire(t *testing.T) {
	cfg := map[string]any{}
	route := inference.Route{
		Format: inference.WireOpenAI, BaseURL: inference.ZGOpenAIBaseURL,
		EnvKey: "OPENAI_API_KEY", ContextWindow: 204800, MaxTokens: 16384, CatalogSourced: true,
	}
	applyZGComputeToConfig(cfg, "glm-5.2", route)

	pick := inferencePickFromConfig(cfg)
	if pick.Provider != "openai" || pick.Model != "glm-5.2" {
		t.Errorf("primary = %s/%s; want openai/glm-5.2", pick.Provider, pick.Model)
	}
	entry := cfg["models"].(map[string]any)["providers"].(map[string]any)["openai"].(map[string]any)
	if entry["api"] != "openai-completions" || entry["baseUrl"] != inference.ZGOpenAIBaseURL {
		t.Errorf("openai wire mis-shaped: %v", entry)
	}
	modelDef := entry["models"].([]any)[0].(map[string]any)
	if modelDef["compat"].(map[string]any)["requiresStringContent"] != true {
		t.Error("openai wire requires the string-content compat")
	}
}

// healOpenclawConfig must reach EXISTING agents (review P0): their
// chain-restored openclaw.json is in resolved form (provider "openai", router
// baseUrl) that applyZGComputeAugmentation never recognizes again, carrying
// the old machine shapes: reasoning=false, supportsReasoningEffort=false, the
// heuristic 8192 budget, no timeoutSeconds, no watchdog headroom. The healer
// flips exactly those — and leaves owner-set values alone.
func TestHealOpenclawConfig_ExistingAgentShapes(t *testing.T) {
	openclawHome = t.TempDir()
	catalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"glm-5.3","supported_formats":["openai"],"context_length":1000000,"max_completion_tokens":131072,"supported_parameters":["max_tokens","reasoning_effort"]}]}`))
	}))
	defer catalog.Close()
	defer inference.SetCatalogURLForTest(catalog.URL)()

	legacy := map[string]any{
		"agents": map[string]any{"defaults": map[string]any{"model": map[string]any{"primary": "openai/glm-5.3"}}},
		"models": map[string]any{"providers": map[string]any{"openai": map[string]any{
			"baseUrl": inference.ZGOpenAIBaseURL,
			"api":     "openai-completions",
			"models": []any{map[string]any{
				"id": "glm-5.3", "reasoning": false, "maxTokens": float64(8192),
				"compat": map[string]any{"supportsReasoningEffort": false, "requiresStringContent": true},
			}},
		}}},
	}
	if err := saveOpenclawJSON(legacy); err != nil {
		t.Fatal(err)
	}
	if err := healOpenclawConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadOpenclawJSON()
	if err != nil {
		t.Fatal(err)
	}
	p := cfg["models"].(map[string]any)["providers"].(map[string]any)["openai"].(map[string]any)
	m := p["models"].([]any)[0].(map[string]any)
	if m["reasoning"] != true {
		t.Errorf("reasoning not healed: %v", m["reasoning"])
	}
	if m["compat"].(map[string]any)["supportsReasoningEffort"] != true {
		t.Error("compat.supportsReasoningEffort not healed")
	}
	if mt, _ := m["maxTokens"].(float64); int(mt) != 131072 {
		t.Errorf("poisoned 8192 not healed to catalog value: %v", m["maxTokens"])
	}
	if ts, _ := p["timeoutSeconds"].(float64); int(ts) != 600 {
		t.Errorf("timeoutSeconds not healed: %v", p["timeoutSeconds"])
	}
	if lvl := cfg["agents"].(map[string]any)["defaults"].(map[string]any)["thinkingDefault"]; lvl != "low" {
		t.Errorf("thinkingDefault not healed: %v", lvl)
	}
	if ms, _ := cfg["diagnostics"].(map[string]any)["stuckSessionAbortMs"].(float64); int(ms) != 900_000 {
		t.Errorf("watchdog headroom not healed: %v", cfg["diagnostics"])
	}

	// Owner-set values survive a second heal untouched.
	cfg["agents"].(map[string]any)["defaults"].(map[string]any)["thinkingDefault"] = "high"
	m["maxTokens"] = float64(1234)
	if err := saveOpenclawJSON(cfg); err != nil {
		t.Fatal(err)
	}
	if err := healOpenclawConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg2, _ := loadOpenclawJSON()
	p2 := cfg2["models"].(map[string]any)["providers"].(map[string]any)["openai"].(map[string]any)
	m2 := p2["models"].([]any)[0].(map[string]any)
	if mt, _ := m2["maxTokens"].(float64); int(mt) != 1234 {
		t.Errorf("hand-set maxTokens clobbered: %v", m2["maxTokens"])
	}
	if lvl := cfg2["agents"].(map[string]any)["defaults"].(map[string]any)["thinkingDefault"]; lvl != "high" {
		t.Errorf("owner thinkingDefault clobbered: %v", lvl)
	}
}

// Non-router providers are never touched by the healer (only the diagnostics
// default is added — that knob is routing-agnostic, review F3).
func TestHealOpenclawConfig_NativeProviderUntouched(t *testing.T) {
	openclawHome = t.TempDir()
	legacy := map[string]any{
		"models": map[string]any{"providers": map[string]any{"anthropic": map[string]any{
			"baseUrl": "https://api.anthropic.com",
			"models":  []any{map[string]any{"id": "claude-opus-4-6", "reasoning": false, "maxTokens": float64(8192)}},
		}}},
	}
	if err := saveOpenclawJSON(legacy); err != nil {
		t.Fatal(err)
	}
	if err := healOpenclawConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg, _ := loadOpenclawJSON()
	m := cfg["models"].(map[string]any)["providers"].(map[string]any)["anthropic"].(map[string]any)["models"].([]any)[0].(map[string]any)
	if m["reasoning"] != false || m["maxTokens"].(float64) != 8192 {
		t.Errorf("non-router provider entry was modified: %v", m)
	}
	if ms, _ := cfg["diagnostics"].(map[string]any)["stuckSessionAbortMs"].(float64); int(ms) != 900_000 {
		t.Errorf("diagnostics default should apply regardless of provider: %v", cfg["diagnostics"])
	}
}
