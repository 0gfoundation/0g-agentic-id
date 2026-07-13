package openclaw

import (
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
		EnvKey: "ANTHROPIC_API_KEY", ContextWindow: 1000000, MaxTokens: 131072,
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
		EnvKey: "OPENAI_API_KEY", ContextWindow: 204800, MaxTokens: 16384,
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
