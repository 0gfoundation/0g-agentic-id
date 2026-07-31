package hermes

import (
	"context"
	"strings"
	"testing"

	"seal-verify/internal/inference"
)

// TestZGAugmentationWritesKeyThenStripped locks the fix for the live 401:
// hermes's `custom` provider (which 0g-compute maps to) reads the inference
// key ONLY from config.yaml model.api_key, never from env — so the
// augmentation must write it to disk. The SAME key must then be stripped by
// the capture path so it never reaches chain. One test covers both halves
// because they're two ends of one invariant: key on disk, never on chain.
func TestZGAugmentationWritesKeyThenStripped(t *testing.T) {
	hermesHome = t.TempDir()
	route := &inference.Route{Format: inference.WireOpenAI, BaseURL: inference.ZGOpenAIBaseURL, EnvKey: "OPENAI_API_KEY"}

	if err := applyZGComputeAugmentation("0g-compute", "0gm-1.0-35b-a3b", "sk-secret-router-key", route); err != nil {
		t.Fatal(err)
	}

	// On disk: hermes must find the key where the custom provider looks.
	cfg, err := loadConfigYAML()
	if err != nil {
		t.Fatal(err)
	}
	m, _ := cfg["model"].(map[string]any)
	if m == nil || m["api_key"] != "sk-secret-router-key" {
		t.Fatalf("api_key not written to config.yaml model: %v", cfg["model"])
	}
	if m["provider"] != "custom" || m["base_url"] != inference.ZGOpenAIBaseURL {
		t.Errorf("custom-endpoint rewrite missing: %v", m)
	}

	// On chain (capture path): the key must be gone.
	a := New()
	got, err := a.EvolutionFor(context.Background(), "config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "sk-secret-router-key") || strings.Contains(string(got), "api_key") {
		t.Errorf("api_key leaked into chain payload: %s", got)
	}
}

// TestZGAugmentationRejectsAnthropicFormat: an anthropic-format model can't
// ride the custom (openai-wire) endpoint — fail loud at Start, not 400 at
// first chat.
func TestZGAugmentationRejectsAnthropicFormat(t *testing.T) {
	hermesHome = t.TempDir()
	route := &inference.Route{Format: inference.WireAnthropic, BaseURL: inference.ZGAnthropicBaseURL}
	if err := applyZGComputeAugmentation("0g-compute", "claude-opus-4-8", "sk-x", route); err == nil {
		t.Error("expected anthropic-format model to be rejected")
	}
}
