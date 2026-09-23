package openclaw

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/inference"
	"seal-verify/internal/settings"
)

// routedSettings is a platform-routed Resolved: the 0g router supplies the
// endpoint, the catalog supplied the facts.
func routedSettings(format inference.WireFormat, model string) settings.Resolved {
	baseURL, envKey := inference.ZGOpenAIBaseURL, "OPENAI_API_KEY"
	if format == inference.WireAnthropic {
		baseURL, envKey = inference.ZGAnthropicBaseURL, "ANTHROPIC_API_KEY"
	}
	return settings.Resolved{
		Doc: settings.Doc{Provider: inference.ZGComputeProvider, Model: model, Thinking: "high"},
		Facts: inference.ModelFacts{
			ContextWindow: 1000000, MaxTokens: 131072,
			SupportsReasoningEffort: true, CatalogSourced: true,
		},
		Endpoint: &inference.Endpoint{Format: format, BaseURL: baseURL, EnvKey: envKey},
	}
}

// primaryPin reads agents.defaults.model.primary back out of a rendered
// config. The adapter no longer has a pin READER (the settings document is
// the pin); this is a test-side accessor for asserting what was written.
func primaryPin(t *testing.T, cfg map[string]any) string {
	t.Helper()
	agents, _ := cfg["agents"].(map[string]any)
	defaults, _ := agents["defaults"].(map[string]any)
	model, _ := defaults["model"].(map[string]any)
	primary, _ := model["primary"].(string)
	return primary
}

func renderInto(t *testing.T, s settings.Resolved) map[string]any {
	t.Helper()
	a := New()
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatalf("RenderSettings: %v", err)
	}
	cfg, err := loadOpenclawJSON()
	if err != nil {
		t.Fatalf("load rendered config: %v", err)
	}
	return cfg
}

// The live regression: 0g-compute serves claude-* on its Anthropic-format
// endpoint only; the render must emit the anthropic dialect
// (provider/api/baseUrl/env key), not force everything through the OpenAI
// path (which 400'd on testnet: "model 'claude-sonnet-5' is not available
// on the openai API format").
func TestRenderSettings_AnthropicWire(t *testing.T) {
	useTempHome(t)
	cfg := renderInto(t, routedSettings(inference.WireAnthropic, "claude-sonnet-5"))

	if got := primaryPin(t, cfg); got != "anthropic/claude-sonnet-5" {
		t.Errorf("primary = %s; want anthropic/claude-sonnet-5", got)
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
	if modelDef["contextWindow"] != float64(1000000) || modelDef["maxTokens"] != float64(131072) {
		t.Errorf("catalog limits not applied: %v", modelDef)
	}
}

// Dual/openai-format models keep the OpenAI dialect, including the
// requiresStringContent compat that 0G's OpenAI endpoint needs.
func TestRenderSettings_OpenAIWire(t *testing.T) {
	useTempHome(t)
	cfg := renderInto(t, routedSettings(inference.WireOpenAI, "glm-5.2"))

	if got := primaryPin(t, cfg); got != "openai/glm-5.2" {
		t.Errorf("primary = %s; want openai/glm-5.2", got)
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

// The render runs on EVERY Start, so it has to be a fixed point: the
// watcher hashes the workspace after it, and a render that kept changing
// its own output would report drift on every tick.
func TestRenderSettings_Idempotent(t *testing.T) {
	useTempHome(t)
	s := routedSettings(inference.WireOpenAI, "glm-5.3")
	s.Others = json.RawMessage(`{"agents":{"defaults":{"maxParallelToolCalls":3}}}`)

	a := New()
	ctx := context.Background()
	if err := a.RenderSettings(ctx, s); err != nil {
		t.Fatalf("RenderSettings 1: %v", err)
	}
	first := readRenderedBytes(t)
	if err := a.RenderSettings(ctx, s); err != nil {
		t.Fatalf("RenderSettings 2: %v", err)
	}
	if second := readRenderedBytes(t); second != first {
		t.Errorf("render is not a fixed point:\n first  = %s\n second = %s", first, second)
	}
}

// The fixes healOpenclawConfig used to retrofit are now written by the
// render itself, so they reach an already-minted agent on its next boot:
// the model idle timeout, the stuck-session watchdog headroom, the
// reasoning flags and the catalog budget.
func TestRenderSettings_CarriesTheFormerHealFixes(t *testing.T) {
	useTempHome(t)
	cfg := renderInto(t, routedSettings(inference.WireOpenAI, "glm-5.3"))

	entry := cfg["models"].(map[string]any)["providers"].(map[string]any)["openai"].(map[string]any)
	if ts, _ := entry["timeoutSeconds"].(float64); int(ts) != 600 {
		t.Errorf("provider timeoutSeconds = %v; want 600 (thinking models take ~150s to first token)", entry["timeoutSeconds"])
	}
	modelDef := entry["models"].([]any)[0].(map[string]any)
	if modelDef["reasoning"] != true {
		t.Errorf("reasoning = %v; want true for a model the catalog says takes reasoning_effort", modelDef["reasoning"])
	}
	if modelDef["compat"].(map[string]any)["supportsReasoningEffort"] != true {
		t.Error("compat.supportsReasoningEffort must follow the catalog")
	}
	if mt, _ := modelDef["maxTokens"].(float64); int(mt) != 131072 {
		t.Errorf("maxTokens = %v; want the catalog value", modelDef["maxTokens"])
	}
	ms, _ := cfg["diagnostics"].(map[string]any)["stuckSessionAbortMs"].(float64)
	if int(ms) != 900_000 {
		t.Errorf("watchdog headroom = %v; want 900000 (must stay above the 600s idle timeout)", cfg["diagnostics"])
	}
}

// The bound is a property of the MODEL, not of who serves it. A framework
// built-in (Endpoint == nil) must still get it — hanging the bound off the
// provider check is how two other adapters silently dropped it — while the
// endpoint wiring stays absent, because the framework supplies its own.
func TestRenderSettings_NativeProviderStillGetsTheEffortBound(t *testing.T) {
	useTempHome(t)
	cfg := renderInto(t, settings.Resolved{
		Doc:   settings.Doc{Provider: "anthropic", Model: "claude-sonnet-5", Thinking: "high"},
		Facts: inference.ModelFacts{SupportsReasoningEffort: true, CatalogSourced: true, MaxTokens: 64000},
	})

	defaults := cfg["agents"].(map[string]any)["defaults"].(map[string]any)
	if defaults["thinkingDefault"] != "high" {
		t.Errorf("thinkingDefault = %v; want high for a native provider too", defaults["thinkingDefault"])
	}
	if got := primaryPin(t, cfg); got != "anthropic/claude-sonnet-5" {
		t.Errorf("primary = %s; want the owner's provider label", got)
	}
	if models, ok := cfg["models"].(map[string]any); ok {
		if providers, ok := models["providers"].(map[string]any); ok && len(providers) > 0 {
			t.Errorf("a framework built-in must keep openclaw's own endpoint table: %v", providers)
		}
	}
	// The watchdog is sealed's own supervision, not routing — it applies
	// regardless of who serves the model.
	if ms, _ := cfg["diagnostics"].(map[string]any)["stuckSessionAbortMs"].(float64); int(ms) != 900_000 {
		t.Errorf("watchdog headroom missing for a native provider: %v", cfg["diagnostics"])
	}
}

// A model that takes no bound must receive NO level: reasoning_effort on a
// model that rejects it is a hard 400, and a value left over from a
// previous pin would do exactly that.
func TestRenderSettings_NonReasoningModelClearsTheBound(t *testing.T) {
	useTempHome(t)
	// Pre-seed the file with a bound written for an earlier, thinking model.
	writeJSONConfig(t, map[string]any{
		"agents": map[string]any{"defaults": map[string]any{"thinkingDefault": "high"}},
	})
	cfg := renderInto(t, settings.Resolved{
		Doc:   settings.Doc{Provider: inference.ZGComputeProvider, Model: "plain-1", Thinking: "high"},
		Facts: inference.ModelFacts{ContextWindow: 128000, MaxTokens: 4096, CatalogSourced: true},
		Endpoint: &inference.Endpoint{
			Format: inference.WireOpenAI, BaseURL: inference.ZGOpenAIBaseURL, EnvKey: "OPENAI_API_KEY",
		},
	})

	defaults := cfg["agents"].(map[string]any)["defaults"].(map[string]any)
	if lvl, present := defaults["thinkingDefault"]; present {
		t.Errorf("thinkingDefault = %v; want the key absent for a model that takes no bound", lvl)
	}
}

// The owner's overlay lands, but it cannot outrank a platform-owned key:
// ordering (overlay first, platform second) is what keeps an overlay from
// disabling bounded reasoning or pinning a wire format the catalog later
// changes.
func TestRenderSettings_OverlayAppliedButPlatformWins(t *testing.T) {
	useTempHome(t)
	s := routedSettings(inference.WireOpenAI, "glm-5.3")
	s.Others = json.RawMessage(`{
		"agents": {"defaults": {"maxParallelToolCalls": 3, "thinkingDefault": "off"}},
		"models": {"providers": {"openai": {"baseUrl": "https://evil.example.com"}}},
		"diagnostics": {"stuckSessionAbortMs": 1},
		"gateway": {"auth": {"token": "overlay-supplied"}},
		"logging": {"level": "debug"}
	}`)
	cfg := renderInto(t, s)

	defaults := cfg["agents"].(map[string]any)["defaults"].(map[string]any)
	// Owner key the platform doesn't own: applied.
	if mp, _ := defaults["maxParallelToolCalls"].(float64); int(mp) != 3 {
		t.Errorf("overlay key not applied: %v", defaults)
	}
	if lvl, _ := cfg["logging"].(map[string]any)["level"]; lvl != "debug" {
		t.Errorf("overlay top-level section not applied: %v", cfg["logging"])
	}
	// Platform-owned keys: the overlay loses every one of them.
	if defaults["thinkingDefault"] != "high" {
		t.Errorf("overlay disabled the reasoning bound: %v", defaults["thinkingDefault"])
	}
	entry := cfg["models"].(map[string]any)["providers"].(map[string]any)["openai"].(map[string]any)
	if entry["baseUrl"] != inference.ZGOpenAIBaseURL {
		t.Errorf("overlay pinned the endpoint: %v", entry["baseUrl"])
	}
	if ms, _ := cfg["diagnostics"].(map[string]any)["stuckSessionAbortMs"].(float64); int(ms) != 900_000 {
		t.Errorf("overlay shrank the watchdog headroom: %v", cfg["diagnostics"])
	}
	// gateway is the one key ordering cannot protect (spawn.go writes it at
	// first Start with a live credential), so the overlay never carries it.
	if _, present := cfg["gateway"]; present {
		t.Errorf("overlay must not be able to supply the gateway subtree: %v", cfg["gateway"])
	}
}

// A budget the catalog didn't source is a heuristic guess. Written to disk
// it looks hand-set forever after and — reasoning and reply SHARING the
// budget — permanently starves replies.
func TestRenderSettings_HeuristicBudgetIsNotWritten(t *testing.T) {
	useTempHome(t)
	cfg := renderInto(t, settings.Resolved{
		Doc: settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3"},
		Facts: inference.ModelFacts{
			ContextWindow: 128000, MaxTokens: inference.HeuristicOpenAIMaxTokens,
			SupportsReasoningEffort: false, CatalogSourced: false,
		},
		Endpoint: &inference.Endpoint{
			Format: inference.WireOpenAI, BaseURL: inference.ZGOpenAIBaseURL, EnvKey: "OPENAI_API_KEY",
		},
	})

	entry := cfg["models"].(map[string]any)["providers"].(map[string]any)["openai"].(map[string]any)
	modelDef := entry["models"].([]any)[0].(map[string]any)
	if mt, present := modelDef["maxTokens"]; present {
		t.Errorf("maxTokens = %v; want the field absent so openclaw omits max_tokens and the model's own ceiling applies", mt)
	}
}

// Start cannot invent a pin: the config file is an output of the render
// now, so a Start without one is a platform sequencing bug and must say so
// instead of spawning a gateway with no model wired up.
func TestStart_WithoutRenderSettingsFails(t *testing.T) {
	useTempHome(t)
	a := &Adapter{}
	ctx := context.Background()
	if err := a.Restore(ctx, "framework", nil); err != nil {
		t.Fatalf("Restore(framework): %v", err)
	}
	_, err := a.Start(ctx, framework.RuntimeContext{})
	if err == nil {
		t.Fatal("Start without RenderSettings must fail")
	}
	if !strings.Contains(err.Error(), "RenderSettings") {
		t.Errorf("error should name the missing step, got: %v", err)
	}
}

// readRenderedBytes returns openclaw.json exactly as it sits on disk —
// byte comparison, not a re-marshal, because idempotence is a property of
// the written bytes the watcher hashes.
func readRenderedBytes(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(openclawJSONPath())
	if err != nil {
		t.Fatalf("read rendered config: %v", err)
	}
	return string(b)
}

// The fix round's own regression, caught by an adversarial probe and not by
// any test: mergeInto inserted the overlay's nested maps into cfg BY
// REFERENCE, applySettingsToConfig then wrote the platform's keys through
// those shared maps, and the overlay recorded as "last applied" therefore
// claimed to have supplied them. On the next render dropRemovedOverlayKeys
// read that record and withdrew the platform's own values.
//
// Note what it takes to SEE this. A same-settings second render hides it: the
// key is withdrawn and then written straight back by the same pass. It only
// surfaces when the platform declines to rewrite — which is precisely the
// catalog-outage case, where Effort() returns undecided and the render must
// leave the existing bound alone. So the bug and the tri-state it defeats are
// the same scenario, and a test that does not vary the catalog between renders
// is not testing anything. (The first version of this test did not, and passed
// against the unfixed code.)
func TestRenderSettings_OverlayIsNotAliasedIntoTheConfig(t *testing.T) {
	useTempHome(t)

	overlay := []byte(`{"agents":{"defaults":{"model":{"fallback":"openai/glm-4.5"}}}}`)

	// Boot 1: catalog reachable, so the platform writes the bound.
	up := routedSettings(inference.WireOpenAI, "glm-5.3")
	up.Others = overlay
	_ = renderInto(t, up)

	// Boot 2: catalog silent. Effort() is undecided, so the render must leave
	// the bound exactly as it found it.
	outage := settings.Resolved{
		Doc:      settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3", Others: overlay},
		Facts:    inference.ModelFacts{ContextWindow: 128000, MaxTokens: 8192},
		Endpoint: &inference.Endpoint{Format: inference.WireOpenAI, BaseURL: inference.ZGOpenAIBaseURL, EnvKey: "OPENAI_API_KEY"},
	}
	cfg := renderInto(t, outage)

	agents, _ := cfg["agents"].(map[string]any)
	defaults, _ := agents["defaults"].(map[string]any)
	if got := defaults["thinkingDefault"]; got != "high" {
		t.Fatalf("thinkingDefault = %v after an outage render, want \"high\" kept — "+
			"the platform's own key was recorded as overlay-supplied and then withdrawn", got)
	}
	model, _ := defaults["model"].(map[string]any)
	if got := model["fallback"]; got != "openai/glm-4.5" {
		t.Fatalf("overlay value = %v, want it still applied", got)
	}
}

// A document naming a model but no provider tells the render nothing about
// routing, so it deliberately leaves the existing pin in place. Pruning the
// provider entry that pin resolves through would dismantle the very
// configuration that branch is preserving.
func TestRenderSettings_ModelWithoutProviderKeepsTheRouterEntry(t *testing.T) {
	useTempHome(t)

	_ = renderInto(t, routedSettings(inference.WireOpenAI, "glm-5.3"))
	cfg := renderInto(t, settings.Resolved{Doc: settings.Doc{Model: "glm-5.3"}})

	models, _ := cfg["models"].(map[string]any)
	providers, _ := models["providers"].(map[string]any)
	if len(providers) == 0 {
		t.Fatal("the router provider entry the surviving pin depends on was pruned")
	}
	auth, _ := cfg["auth"].(map[string]any)
	profiles, _ := auth["profiles"].(map[string]any)
	if len(profiles) == 0 {
		t.Fatal("the auth profile the surviving pin depends on was pruned")
	}
	if got := primaryPin(t, cfg); got == "" {
		t.Fatal("the pin itself was dropped")
	}
}

// The T2 drill's first live catch (agent 411): openclaw validates its config
// STRICTLY, so one junk key in the owner's opaque overlay — merged into the
// same file — took the whole agent offline. The gate uses openclaw's own
// validator and, on rejection, withdraws the overlay and boots the platform
// half. The owner's junk costs the owner their knobs, never their agent.
func TestEnsureConfigAcceptable_JunkOverlayIsWithdrawnNotFatal(t *testing.T) {
	useTempHome(t)
	a := New()

	s := routedSettings(inference.WireOpenAI, "glm-5.3")
	s.Others = []byte(`{"备注":"junk openclaw's schema rejects"}`)
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatalf("RenderSettings: %v", err)
	}

	// Stand in for `openclaw config validate`: reject any config that still
	// carries the junk key, exactly as the real validator did live.
	prev := validateOpenclawConfig
	defer func() { validateOpenclawConfig = prev }()
	calls := 0
	validateOpenclawConfig = func() error {
		calls++
		cfg, err := loadOpenclawJSON()
		if err != nil {
			return err
		}
		if _, bad := cfg["备注"]; bad {
			return fmt.Errorf("<root>: Invalid input")
		}
		return nil
	}

	if err := a.ensureConfigAcceptable(context.Background()); err != nil {
		t.Fatalf("ensureConfigAcceptable = %v — a junk overlay must cost the overlay, not the boot", err)
	}
	if calls != 2 {
		t.Fatalf("validator ran %d times, want reject-then-accept", calls)
	}

	cfg, err := loadOpenclawJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, still := cfg["备注"]; still {
		t.Fatal("junk key survived the withdrawal")
	}
	if got := primaryPin(t, cfg); got != "openai/glm-5.3" {
		t.Fatalf("platform half lost in the re-render: pin=%q", got)
	}
}

// A rejection with NO overlay in force is the platform's own bug: booting on a
// config openclaw already refused would just move the failure somewhere
// harder to read. Fail the start loudly instead.
func TestEnsureConfigAcceptable_PlatformBugFailsLoudly(t *testing.T) {
	useTempHome(t)
	a := New()
	if err := a.RenderSettings(context.Background(), routedSettings(inference.WireOpenAI, "glm-5.3")); err != nil {
		t.Fatal(err)
	}
	prev := validateOpenclawConfig
	defer func() { validateOpenclawConfig = prev }()
	validateOpenclawConfig = func() error { return fmt.Errorf("<root>: Invalid input") }

	err := a.ensureConfigAcceptable(context.Background())
	if err == nil {
		t.Fatal("expected a loud failure when the platform's own render is rejected")
	}
	if !strings.Contains(err.Error(), "platform bug") {
		t.Fatalf("error %q must say whose bug it is", err)
	}
}
