package hermes

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/inference"
	"seal-verify/internal/settings"
)

// routed builds a Resolved for a platform-routed (0g-compute) model.
func routed(model, thinking string, facts inference.ModelFacts) settings.Resolved {
	return settings.Resolved{
		Doc: settings.Doc{
			Provider: inference.ZGComputeProvider,
			Model:    model,
			Thinking: thinking,
		},
		Facts: facts,
		Endpoint: &inference.Endpoint{
			Format:  inference.WireOpenAI,
			BaseURL: inference.ZGOpenAIBaseURL,
			EnvKey:  "OPENAI_API_KEY",
		},
		APIKey: "sk-secret-router-key",
	}
}

func readConfig(t *testing.T) map[string]any {
	t.Helper()
	cfg, err := loadConfigYAML()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func modelSection(t *testing.T) map[string]any {
	t.Helper()
	m, _ := readConfig(t)["model"].(map[string]any)
	if m == nil {
		t.Fatal("config.yaml has no model section")
	}
	return m
}

func agentSection(t *testing.T) map[string]any {
	t.Helper()
	a, _ := readConfig(t)["agent"].(map[string]any)
	return a
}

// TestRenderWritesLiteralKey locks the fix for the live 401: hermes's
// `custom` provider (which the 0g router maps to) declares env_vars=() and
// reads the inference key ONLY from config.yaml model.api_key, never from
// env — so every render must put the literal key on disk. The key is safe
// there because config.yaml is no longer a chain-tracked role: the capture
// path that once needed stripSecrets does not exist (asserted below).
func TestRenderWritesLiteralKey(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()

	if err := a.RenderSettings(ctx, routed("0gm-1.0-35b-a3b", "", inference.ModelFacts{CatalogSourced: true})); err != nil {
		t.Fatal(err)
	}
	m := modelSection(t)
	if m["api_key"] != "sk-secret-router-key" {
		t.Fatalf("api_key not written to config.yaml model: %v", m)
	}
	if m["provider"] != "custom" || m["base_url"] != inference.ZGOpenAIBaseURL || m["default"] != "0gm-1.0-35b-a3b" {
		t.Errorf("custom-endpoint rewrite missing: %v", m)
	}

	// No capture path: the role is gone from Roles() and EvolutionFor
	// refuses it, so the key on disk has nowhere to leak to.
	for _, r := range a.Roles() {
		if r.Name == "config.yaml" {
			t.Error("config.yaml is still a declared role — the key on disk would reach chain")
		}
	}
	if _, err := a.EvolutionFor(ctx, "config.yaml"); err != framework.ErrUnsupportedDim {
		t.Errorf("EvolutionFor(config.yaml) = %v, want ErrUnsupportedDim", err)
	}
}

// TestRenderIdempotent: same Resolved in, same bytes out. The watcher hashes
// on-disk artifacts, and a render that varied between boots would report
// drift on every tick.
func TestRenderIdempotent(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	s := routed("glm-5.3", "high", inference.ModelFacts{
		MaxTokens: 131072, SupportsReasoningEffort: true, CatalogSourced: true,
	})
	s.Others = json.RawMessage(`{"approvals":{"mode":"off"}}`)

	if err := a.RenderSettings(ctx, s); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(configYAMLPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RenderSettings(ctx, s); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(configYAMLPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Errorf("render is not idempotent:\n first  = %s\n second = %s", first, second)
	}
}

// TestRenderNativeProviderKeepsEffortBound is the bug this port fixes: the
// bound used to sit inside the 0g-compute branch, so choosing a native
// provider dropped it — and an always-thinking model with no bound reasons
// forever (measured on glm-5.3: 100k+ chars, zero reply, upstream kill).
// Endpoint==nil only means "the framework knows where to send it".
func TestRenderNativeProviderKeepsEffortBound(t *testing.T) {
	a := newTestAdapter(t)
	s := settings.Resolved{
		Doc:   settings.Doc{Provider: "anthropic", Model: "claude-opus-4-8", Thinking: "high"},
		Facts: inference.ModelFacts{SupportsReasoningEffort: true, CatalogSourced: true},
		// Endpoint nil: anthropic is a framework built-in.
		APIKey: "sk-native",
	}
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if got := agentSection(t)["reasoning_effort"]; got != "high" {
		t.Fatalf("native provider lost the effort bound: agent.reasoning_effort = %v, want high", got)
	}
	m := modelSection(t)
	if m["provider"] != "anthropic" || m["default"] != "claude-opus-4-8" {
		t.Errorf("native pin not rendered: %v", m)
	}
	if _, set := m["base_url"]; set {
		t.Errorf("base_url written for a framework built-in: %v", m)
	}
}

// A thinking-capable model with no owner preference still gets a bound
// (settings.Resolved.Effort defaults to "low"); a model the catalog does not
// flag gets none — the parameter is a hard 400 on a model that rejects it —
// and a value left by a previous model's render is cleared.
func TestRenderEffortDefaultAndClear(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()

	if err := a.RenderSettings(ctx, routed("glm-5.3", "", inference.ModelFacts{
		SupportsReasoningEffort: true, CatalogSourced: true,
	})); err != nil {
		t.Fatal(err)
	}
	if got := agentSection(t)["reasoning_effort"]; got != "low" {
		t.Fatalf("agent.reasoning_effort = %v, want low", got)
	}

	// Switch to a model the catalog doesn't flag: the stale bound must go.
	if err := a.RenderSettings(ctx, routed("some-plain-model", "", inference.ModelFacts{CatalogSourced: true})); err != nil {
		t.Fatal(err)
	}
	if agent := agentSection(t); agent != nil {
		if _, set := agent["reasoning_effort"]; set {
			t.Fatalf("stale reasoning_effort survived a model switch: %v", agent)
		}
	}
}

// TestRenderOverlayAppliedButLoses: the owner's opaque Framework section is
// merged in, but never over a platform-owned key. Ordering, not an exclusion
// list, is what stops an overlay from disabling bounded reasoning or pinning
// a wire format the catalog later changes.
func TestRenderOverlayAppliedButLoses(t *testing.T) {
	a := newTestAdapter(t)
	s := routed("glm-5.3", "high", inference.ModelFacts{
		SupportsReasoningEffort: true, CatalogSourced: true,
	})
	s.Others = json.RawMessage(`{
		"approvals": {"mode": "off"},
		"terminal": {"backend": "tmux"},
		"agent": {"reasoning_effort": false, "name": "hermes"},
		"model": {"base_url": "https://evil.example/v1", "api_key": "sk-owner", "temperature": 0.2}
	}`)
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}

	cfg := readConfig(t)
	// Overlay-only keys survive — this is where approvals/terminal live now.
	if ap, _ := cfg["approvals"].(map[string]any); ap == nil || ap["mode"] != "off" {
		t.Errorf("overlay key \"approvals\" not applied: %v", cfg["approvals"])
	}
	if tm, _ := cfg["terminal"].(map[string]any); tm == nil || tm["backend"] != "tmux" {
		t.Errorf("overlay key \"terminal\" not applied: %v", cfg["terminal"])
	}

	// Platform-owned keys win over the overlay's values…
	m := modelSection(t)
	if m["base_url"] != inference.ZGOpenAIBaseURL {
		t.Errorf("overlay pinned base_url over the platform's: %v", m["base_url"])
	}
	if m["api_key"] != "sk-secret-router-key" {
		t.Errorf("overlay pinned api_key over this boot's credential: %v", m["api_key"])
	}
	if got := agentSection(t)["reasoning_effort"]; got != "high" {
		t.Errorf("overlay disabled bounded reasoning: agent.reasoning_effort = %v, want high", got)
	}
	// …while non-platform keys inside the same sections are kept.
	if m["temperature"] != 0.2 {
		t.Errorf("overlay's own model key dropped: %v", m)
	}
	if got := agentSection(t)["name"]; got != "hermes" {
		t.Errorf("overlay's own agent key dropped: %v", agentSection(t))
	}
}

// TestRenderNoPersistedBudget: hermes writes no output budget into
// config.yaml at all, and a non-catalog-sourced one must never start being
// written — a heuristic guess (8192) written during a catalog outage looks
// hand-set forever after and starves a reasoning model's shared budget.
func TestRenderNoPersistedBudget(t *testing.T) {
	a := newTestAdapter(t)
	s := routed("glm-5.3", "", inference.ModelFacts{
		MaxTokens:               inference.HeuristicOpenAIMaxTokens,
		SupportsReasoningEffort: true,
		CatalogSourced:          false, // catalog outage → heuristic
	})
	if s.PersistableMaxTokens() != 0 {
		t.Fatalf("PersistableMaxTokens() = %d for a heuristic route, want 0", s.PersistableMaxTokens())
	}
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(configYAMLPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(disk), "8192") || strings.Contains(string(disk), "max_tokens") {
		t.Errorf("heuristic output budget persisted to config.yaml:\n%s", disk)
	}
}

// TestRenderPreservesLocalKeys: hermes's own sections (gateway runtime
// state, messaging blocks, whatever a future version adds) are none of the
// platform's business and must survive a render.
func TestRenderPreservesLocalKeys(t *testing.T) {
	a := newTestAdapter(t)
	writeFile(t, configYAMLPath(), "gateway:\n  port: 18789\nmodel:\n  provider: stale\n")

	if err := a.RenderSettings(context.Background(), routed("0gm-1.0-35b-a3b", "", inference.ModelFacts{CatalogSourced: true})); err != nil {
		t.Fatal(err)
	}
	cfg := readConfig(t)
	if gw, _ := cfg["gateway"].(map[string]any); gw == nil || gw["port"] != 18789 {
		t.Errorf("local key \"gateway\" clobbered by the render: %v", cfg["gateway"])
	}
	if got := modelSection(t)["provider"]; got != "custom" {
		t.Errorf("stale provider not overwritten: %v", got)
	}
}

// TestRenderRejectsAnthropicFormat: an anthropic-format model can't ride the
// custom (openai-wire) endpoint — fail loud at render, not 400 at first chat.
func TestRenderRejectsAnthropicFormat(t *testing.T) {
	a := newTestAdapter(t)
	s := routed("claude-opus-4-8", "", inference.ModelFacts{CatalogSourced: true})
	s.Endpoint = &inference.Endpoint{Format: inference.WireAnthropic, BaseURL: inference.ZGAnthropicBaseURL}
	if err := a.RenderSettings(context.Background(), s); err == nil {
		t.Error("expected anthropic-format model to be rejected")
	}
}

// A platform-routed endpoint with no credential is the live-401 shape: fail
// at render rather than let hermes dial the router unauthenticated.
func TestRenderRejectsRoutedWithoutKey(t *testing.T) {
	a := newTestAdapter(t)
	s := routed("glm-5.3", "", inference.ModelFacts{CatalogSourced: true})
	s.APIKey = ""
	if err := a.RenderSettings(context.Background(), s); err == nil {
		t.Error("expected a routed endpoint with no API key to be rejected")
	}
}

// Start without a prior render is a bootstrap bug, not an owner error: the
// pin lives in the settings document now, so there is nothing to boot from.
func TestStartWithoutRenderFails(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	if err := a.Restore(ctx, "framework", []byte(`{"name":"hermes","schema_version":1}`)); err != nil {
		t.Fatal(err)
	}
	_, err := a.Start(ctx, framework.RuntimeContext{})
	if err == nil || !strings.Contains(err.Error(), "RenderSettings") {
		t.Fatalf("Start without RenderSettings: err = %v, want a RenderSettings complaint", err)
	}
}

// TestRenderClearsStaleRouterKey: model.api_key is THIS boot's credential,
// so it has to be removed when the boot has none — exactly like its sibling
// base_url. Writing-but-never-clearing left the previous boot's 0G router key
// on disk under whatever provider owned the section next, i.e. handed the
// router credential to a third-party endpoint.
func TestRenderClearsStaleRouterKey(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()

	if err := a.RenderSettings(ctx, routed("glm-5.3", "high", inference.ModelFacts{
		SupportsReasoningEffort: true, CatalogSourced: true,
	})); err != nil {
		t.Fatal(err)
	}
	if got := modelSection(t)["api_key"]; got != "sk-secret-router-key" {
		t.Fatalf("setup: routed render did not write the key: %v", got)
	}

	// The owner switches to a framework built-in; no platform credential
	// this boot (the built-in brings its own, by env or its own auth file).
	if err := a.RenderSettings(ctx, settings.Resolved{
		Doc:   settings.Doc{Provider: "anthropic", Model: "claude-opus-4-8"},
		Facts: inference.ModelFacts{CatalogSourced: true},
	}); err != nil {
		t.Fatal(err)
	}
	if v, set := modelSection(t)["api_key"]; set {
		t.Errorf("previous boot's router key survived under a new provider: api_key = %v", v)
	}
	disk, err := os.ReadFile(configYAMLPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(disk), "sk-secret-router-key") {
		t.Errorf("router key still on disk after the provider switch:\n%s", disk)
	}
}

// TestRenderDropsCustomProviderWithTheEndpoint: "custom" is only hermes's
// marker for "dial model.base_url". When the render deletes base_url it must
// delete that marker too, or the section says to dial an endpoint that is no
// longer in the file.
func TestRenderDropsCustomProviderWithTheEndpoint(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()

	if err := a.RenderSettings(ctx, routed("glm-5.3", "", inference.ModelFacts{CatalogSourced: true})); err != nil {
		t.Fatal(err)
	}
	if got := modelSection(t)["provider"]; got != "custom" {
		t.Fatalf("setup: routed render should pin provider=custom, got %v", got)
	}

	// A document that names a model but no provider: nothing routes it.
	if err := a.RenderSettings(ctx, settings.Resolved{
		Doc:   settings.Doc{Model: "glm-5.3"},
		Facts: inference.ModelFacts{CatalogSourced: true},
	}); err != nil {
		t.Fatal(err)
	}
	m := modelSection(t)
	if _, set := m["base_url"]; set {
		t.Errorf("base_url survived a render with no endpoint: %v", m)
	}
	if p, set := m["provider"]; set {
		t.Errorf("provider = %v with no base_url to dial — \"custom\" must not outlive the endpoint: %v", p, m)
	}
}

// …and that delete is narrow. A provider that brings its own wiring (the
// mint-time persona seed, or hermes's own default) is the framework's
// business and must survive a render whose document says nothing about it.
func TestRenderKeepsSeededNativeProvider(t *testing.T) {
	a := newTestAdapter(t)
	writeFile(t, configYAMLPath(), "model:\n  provider: anthropic\n  default: seeded-model\n")

	if err := a.RenderSettings(context.Background(), settings.Resolved{}); err != nil {
		t.Fatal(err)
	}
	m := modelSection(t)
	if m["provider"] != "anthropic" || m["default"] != "seeded-model" {
		t.Errorf("mint-time seed clobbered by an empty-document render: %v", m)
	}
}

// TestRenderOverlayMergesIntoSection: the overlay merge is deep. A shallow
// top-level assignment let an overlay carrying one nested knob replace the
// whole section — `{"model":{"temperature":0.2}}` over a disk section
// holding the pin blanked the pin.
func TestRenderOverlayMergesIntoSection(t *testing.T) {
	a := newTestAdapter(t)
	writeFile(t, configYAMLPath(), "model:\n  provider: anthropic\n  default: seeded-model\n")

	if err := a.RenderSettings(context.Background(), settings.Resolved{
		Doc: settings.Doc{Others: json.RawMessage(`{"model":{"temperature":0.2}}`)},
	}); err != nil {
		t.Fatal(err)
	}
	m := modelSection(t)
	if m["default"] != "seeded-model" {
		t.Errorf("overlay replaced the model section instead of merging into it — pin lost: %v", m)
	}
	if m["provider"] != "anthropic" {
		t.Errorf("overlay replaced the model section instead of merging into it — provider lost: %v", m)
	}
	if m["temperature"] != 0.2 {
		t.Errorf("overlay's own nested key not applied: %v", m)
	}
}

// TestRenderCatalogOutageLeavesEffortAlone is the third Effort() state, and
// the reason it returns two values. During an outage the platform knows
// nothing about the model: writing a level risks a hard 400, and deleting one
// strips the bound from an always-thinking model, which then reasons without
// end and never writes a reply. Leave the on-disk value alone.
func TestRenderCatalogOutageLeavesEffortAlone(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()

	// A previous boot, with a reachable catalog, bounded the model.
	if err := a.RenderSettings(ctx, routed("glm-5.3", "", inference.ModelFacts{
		SupportsReasoningEffort: true, CatalogSourced: true,
	})); err != nil {
		t.Fatal(err)
	}
	if got := agentSection(t)["reasoning_effort"]; got != "low" {
		t.Fatalf("setup: agent.reasoning_effort = %v, want low", got)
	}

	// Now the catalog is unreachable: heuristic facts, no owner preference.
	outage := routed("glm-5.3", "", inference.ModelFacts{
		MaxTokens: inference.HeuristicOpenAIMaxTokens, CatalogSourced: false,
	})
	if lvl, decided := outage.Effort(); decided {
		t.Fatalf("fixture: Effort() = (%q,true); this test needs the undecided state", lvl)
	}
	if err := a.RenderSettings(ctx, outage); err != nil {
		t.Fatal(err)
	}
	if got := agentSection(t)["reasoning_effort"]; got != "low" {
		t.Errorf("catalog outage changed the reasoning bound: agent.reasoning_effort = %v, want the on-disk low", got)
	}

	// A deliberate owner choice is still decided during an outage.
	if err := a.RenderSettings(ctx, routed("glm-5.3", "high", inference.ModelFacts{CatalogSourced: false})); err != nil {
		t.Fatal(err)
	}
	if got := agentSection(t)["reasoning_effort"]; got != "high" {
		t.Errorf("owner's level dropped during an outage: agent.reasoning_effort = %v, want high", got)
	}
}

// TestRenderIdempotentTrickyOverlay: idempotence has to hold through the
// deep merge, over an overlay carrying every JSON scalar shape plus nesting.
// The watcher hashes these bytes; a render that varied between boots would
// report drift on every tick.
func TestRenderIdempotentTrickyOverlay(t *testing.T) {
	a := newTestAdapter(t)
	s := routed("glm-5.3", "high", inference.ModelFacts{
		SupportsReasoningEffort: true, CatalogSourced: true,
	})
	s.Others = json.RawMessage(`{"z":{"b":1,"a":[1,2,{"k":"v"}]},"num":1.0,"big":1e9,"s":"yes","t":true,"n":null,"date":"2026-01-02","model":{"temperature":0.2}}`)

	var prev string
	for i := 0; i < 3; i++ {
		if err := a.RenderSettings(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(configYAMLPath())
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && string(b) != prev {
			t.Fatalf("render %d differs from render %d:\n prev = %s\n got  = %s", i, i-1, prev, b)
		}
		prev = string(b)
	}
}

// TestGatewayEnvTakesCredentialFromSettings: the inference credential is the
// settings document's, not RuntimeContext's. RuntimeContext is losing these
// fields, and the two are not interchangeable — dialing a platform-routed
// endpoint with the wrong one is a live 401.
func TestGatewayEnvTakesCredentialFromSettings(t *testing.T) {
	rt := framework.RuntimeContext{APIKey: "sk-runtimecontext-stale"}

	env := gatewayEnv("ANTHROPIC_API_KEY", "sk-from-settings", "server-key", rt)
	found := false
	for _, e := range env {
		if e == "ANTHROPIC_API_KEY=sk-from-settings" {
			found = true
		}
		if strings.Contains(e, "sk-runtimecontext-stale") {
			t.Errorf("RuntimeContext.APIKey reached the gateway env: %q", e)
		}
	}
	if !found {
		t.Errorf("settings credential missing from the gateway env: %v", env)
	}

	// No credential this boot → no variable at all, rather than an empty one
	// that would shadow whatever the framework built-in reads.
	for _, e := range gatewayEnv("ANTHROPIC_API_KEY", "", "server-key", rt) {
		if strings.HasPrefix(e, "ANTHROPIC_API_KEY=") {
			t.Errorf("credential-less boot still set %q", e)
		}
	}
}
