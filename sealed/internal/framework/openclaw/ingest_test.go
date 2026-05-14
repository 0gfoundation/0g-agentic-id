package openclaw

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// HandleLegacy is the one-shot translator that converts the mint-time
// `persona` semantic role into path-driven disk artifacts. These tests
// pin the translation contract sealed promises to the attestor.

func TestHandleLegacy_Persona_AnthropicProvider(t *testing.T) {
	useTempHome(t)
	a := &Adapter{}

	plaintext := []byte(`{
		"system_prompt": "You are Sage. DeFi helper\n",
		"inference": {"provider": "anthropic", "model": "claude-opus-4-6"}
	}`)
	if err := a.HandleLegacy(context.Background(), "persona", plaintext); err != nil {
		t.Fatalf("HandleLegacy[persona]: %v", err)
	}

	// SOUL.md should contain the verbatim system_prompt.
	soul, err := os.ReadFile(soulMDPath())
	if err != nil {
		t.Fatalf("read SOUL.md: %v", err)
	}
	if string(soul) != "You are Sage. DeFi helper\n" {
		t.Errorf("SOUL.md content mismatch: got %q", string(soul))
	}

	// openclaw.json should carry agents.defaults.model.primary + auth.
	cfg, err := loadOpenclawJSON()
	if err != nil {
		t.Fatalf("load openclaw.json: %v", err)
	}
	primary := jsonString(t, cfg, "agents", "defaults", "model", "primary")
	if primary != "anthropic/claude-opus-4-6" {
		t.Errorf("agents.defaults.model.primary = %q; want anthropic/claude-opus-4-6", primary)
	}
	mode := jsonString(t, cfg, "auth", "profiles", "anthropic:api", "mode")
	if mode != "api_key" {
		t.Errorf("auth.profiles[anthropic:api].mode = %q; want api_key", mode)
	}
	provider := jsonString(t, cfg, "auth", "profiles", "anthropic:api", "provider")
	if provider != "anthropic" {
		t.Errorf("auth.profiles[anthropic:api].provider = %q; want anthropic", provider)
	}
	orderList := jsonList(t, cfg, "auth", "order", "anthropic")
	if len(orderList) != 1 || orderList[0] != "anthropic:api" {
		t.Errorf("auth.order.anthropic = %v; want [anthropic:api]", orderList)
	}
}

func TestHandleLegacy_Persona_PreservesUserChoiceFor0GCompute(t *testing.T) {
	// 0g-compute → openai endpoint mapping is a per-boot runtime concern
	// (spawn.go's applyZGComputeAugmentation). Ingestion records the
	// user's literal choice on chain; runtime translates each boot.
	useTempHome(t)
	a := &Adapter{}

	plaintext := []byte(`{
		"system_prompt": "x",
		"inference": {"provider": "0g-compute", "model": "glm-4.5-air"}
	}`)
	if err := a.HandleLegacy(context.Background(), "persona", plaintext); err != nil {
		t.Fatalf("HandleLegacy[persona]: %v", err)
	}
	cfg, err := loadOpenclawJSON()
	if err != nil {
		t.Fatalf("load openclaw.json: %v", err)
	}
	primary := jsonString(t, cfg, "agents", "defaults", "model", "primary")
	if primary != "0g-compute/glm-4.5-air" {
		t.Errorf("primary = %q; want 0g-compute/glm-4.5-air (literal, no runtime mapping)", primary)
	}
	provider := jsonString(t, cfg, "auth", "profiles", "0g-compute:api", "provider")
	if provider != "0g-compute" {
		t.Errorf("auth.profiles[0g-compute:api].provider = %q; want 0g-compute", provider)
	}
}

func TestHandleLegacy_Persona_EmptyPlaintextRejected(t *testing.T) {
	useTempHome(t)
	a := &Adapter{}
	if err := a.HandleLegacy(context.Background(), "persona", nil); err == nil {
		t.Errorf("expected error on empty plaintext, got nil")
	}
}

func TestHandleLegacy_Persona_MalformedJSONRejected(t *testing.T) {
	useTempHome(t)
	a := &Adapter{}
	if err := a.HandleLegacy(context.Background(), "persona", []byte("{ not json")); err == nil {
		t.Errorf("expected error on malformed JSON, got nil")
	}
}

func TestHandleLegacy_Persona_Idempotent(t *testing.T) {
	useTempHome(t)
	a := &Adapter{}

	plaintext := []byte(`{
		"system_prompt": "twice",
		"inference": {"provider": "anthropic", "model": "claude-haiku-4-5"}
	}`)
	if err := a.HandleLegacy(context.Background(), "persona", plaintext); err != nil {
		t.Fatalf("first HandleLegacy: %v", err)
	}
	first, err := os.ReadFile(openclawJSONPath())
	if err != nil {
		t.Fatalf("read openclaw.json: %v", err)
	}
	firstSoul, err := os.ReadFile(soulMDPath())
	if err != nil {
		t.Fatalf("read SOUL.md: %v", err)
	}

	if err := a.HandleLegacy(context.Background(), "persona", plaintext); err != nil {
		t.Fatalf("second HandleLegacy: %v", err)
	}
	second, err := os.ReadFile(openclawJSONPath())
	if err != nil {
		t.Fatalf("read openclaw.json (2): %v", err)
	}
	secondSoul, err := os.ReadFile(soulMDPath())
	if err != nil {
		t.Fatalf("read SOUL.md (2): %v", err)
	}

	if string(first) != string(second) {
		t.Errorf("openclaw.json not idempotent:\n  first:  %s\n  second: %s", first, second)
	}
	if string(firstSoul) != string(secondSoul) {
		t.Errorf("SOUL.md not idempotent")
	}
}

func TestHandleLegacy_Persona_EmptyInferenceSkipsOpenclawJSONFields(t *testing.T) {
	// If persona omits inference (e.g. user only wants to override the
	// prompt), openclaw.json gets no model/auth keys — those fall back
	// to openclaw's own internal defaults at first chat.
	useTempHome(t)
	a := &Adapter{}

	plaintext := []byte(`{"system_prompt": "naked prompt", "inference": {}}`)
	if err := a.HandleLegacy(context.Background(), "persona", plaintext); err != nil {
		t.Fatalf("HandleLegacy: %v", err)
	}
	cfg, err := loadOpenclawJSON()
	if err != nil {
		t.Fatalf("load openclaw.json: %v", err)
	}
	if _, ok := cfg["agents"]; ok {
		t.Errorf("openclaw.json should not have agents key when inference is empty: %v", cfg)
	}
	if _, ok := cfg["auth"]; ok {
		t.Errorf("openclaw.json should not have auth key when inference is empty: %v", cfg)
	}
	soul, err := os.ReadFile(soulMDPath())
	if err != nil {
		t.Fatalf("read SOUL.md: %v", err)
	}
	if string(soul) != "naked prompt" {
		t.Errorf("SOUL.md = %q; want naked prompt", string(soul))
	}
}

func TestHandleLegacy_UnknownRoleIgnored(t *testing.T) {
	// Unknown legacy roles (a future role this adapter version doesn't
	// know) must NOT error — boot should proceed with what it does
	// understand, and the unknown role gets dropped from chain on the
	// next wholesale chain.Update.
	useTempHome(t)
	a := &Adapter{}
	if err := a.HandleLegacy(context.Background(), "mystery", []byte(`{"x":1}`)); err != nil {
		t.Errorf("unknown legacy role should be a no-op, got error: %v", err)
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func jsonString(t *testing.T, m map[string]any, keys ...string) string {
	t.Helper()
	cur := any(m)
	for i, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("jsonString: path %v stops at index %d (not a map): %T", keys, i, cur)
		}
		v, ok := mm[k]
		if !ok {
			t.Fatalf("jsonString: key %q missing at path %v: %v", k, keys[:i+1], mm)
		}
		cur = v
	}
	s, ok := cur.(string)
	if !ok {
		raw, _ := json.Marshal(cur)
		t.Fatalf("jsonString: terminal value at %v is not a string: %s", keys, raw)
	}
	return s
}

func jsonList(t *testing.T, m map[string]any, keys ...string) []string {
	t.Helper()
	cur := any(m)
	for i, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("jsonList: path %v stops at index %d (not a map): %T", keys, i, cur)
		}
		v, ok := mm[k]
		if !ok {
			t.Fatalf("jsonList: key %q missing at path %v: %v", k, keys[:i+1], mm)
		}
		cur = v
	}
	arr, ok := cur.([]any)
	if !ok {
		t.Fatalf("jsonList: terminal value at %v is not a list: %T", keys, cur)
	}
	out := make([]string, len(arr))
	for i, v := range arr {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("jsonList: element %d is not a string: %T", i, v)
		}
		out[i] = s
	}
	return out
}
