package dsh

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/inference"
	"seal-verify/internal/settings"
)

// catalogServer serves a one-model router catalog for the duration of a test.
func catalogServer(t *testing.T, entry map[string]any) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{entry}})
	}))
	restore := inference.SetCatalogURLForTest(srv.URL)
	t.Cleanup(func() { restore(); srv.Close() })
}

// deadCatalog simulates a catalog outage, which forces the name heuristic.
func deadCatalog(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "catalog down", http.StatusBadGateway)
	}))
	restore := inference.SetCatalogURLForTest(srv.URL)
	t.Cleanup(func() { restore(); srv.Close() })
}

// reasoningModel is a catalog entry for an OpenAI-format model that accepts a
// reasoning bound (the glm-5.3 shape).
func reasoningModel(id string) map[string]any {
	return map[string]any{
		"id": id, "supported_formats": []string{"openai"},
		"context_length": 128000, "max_completion_tokens": 32768,
		"supported_parameters": []string{"reasoning_effort"},
	}
}

// render resolves a document and runs it through the adapter, returning the
// bridge environment as a map.
func render(t *testing.T, a *Adapter, d settings.Doc) map[string]string {
	t.Helper()
	if err := a.RenderSettings(context.Background(), settings.Resolve(context.Background(), d, "sk-test")); err != nil {
		t.Fatalf("RenderSettings: %v", err)
	}
	if a.rendered == nil {
		t.Fatal("RenderSettings did not stash its result")
	}
	out := map[string]string{}
	for _, e := range a.rendered.env {
		k, v, _ := strings.Cut(e, "=")
		out[k] = v
	}
	return out
}

// Idempotence is a contract the watcher depends on: a render that varied
// between calls would report drift on every tick.
func TestRenderSettings_Idempotent(t *testing.T) {
	catalogServer(t, reasoningModel("glm-5.3"))
	doc := settings.Doc{
		Provider:  inference.ZGComputeProvider,
		Model:     "glm-5.3",
		Thinking:  "high",
		Framework: json.RawMessage(`{"toolJobs":true,"maxParallelToolCalls":3}`),
	}
	resolved := settings.Resolve(context.Background(), doc, "sk-test")

	a := New()
	if err := a.RenderSettings(context.Background(), resolved); err != nil {
		t.Fatalf("first render: %v", err)
	}
	first := append([]string(nil), a.rendered.env...)
	if err := a.RenderSettings(context.Background(), resolved); err != nil {
		t.Fatalf("second render: %v", err)
	}
	if !reflect.DeepEqual(first, a.rendered.env) {
		t.Errorf("render is not idempotent:\n first = %v\nsecond = %v", first, a.rendered.env)
	}
}

// The bug this port fixes: the effort bound used to sit inside
// resolveInference's `provider != 0g-compute` early return, so a native
// provider silently ran unbounded — and an always-thinking model with no
// bound reasons forever (measured on glm-5.3: 100k+ chars, zero reply).
// Only the ENDPOINT wiring is provider-dependent.
func TestRenderSettings_NativeProviderStillGetsTheEffortBound(t *testing.T) {
	catalogServer(t, reasoningModel("glm-5.3"))

	routed := render(t, New(), settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3", Thinking: "high"})
	native := render(t, New(), settings.Doc{Provider: "deepseek", Model: "glm-5.3", Thinking: "high"})

	if routed["SEAL_MODEL_EFFORT"] != "high" || native["SEAL_MODEL_EFFORT"] != "high" {
		t.Errorf("effort: routed=%q native=%q — both must be bounded",
			routed["SEAL_MODEL_EFFORT"], native["SEAL_MODEL_EFFORT"])
	}
	if routed["SEAL_MODEL_BASE_URL"] != inference.ZGOpenAIBaseURL || routed["SEAL_MODEL_API"] != "openai-completions" {
		t.Errorf("platform-routed endpoint wiring missing: %v", routed)
	}
	if _, ok := native["SEAL_MODEL_BASE_URL"]; ok {
		t.Errorf("a framework built-in supplies its own endpoint; we must not point it anywhere: %v", native)
	}
	if _, ok := native["SEAL_MODEL_API"]; ok {
		t.Errorf("wire format is endpoint wiring and belongs behind the endpoint check: %v", native)
	}
}

// A model that takes no bound must receive no variable at all: sending
// reasoning_effort to a model that rejects it is a hard 400.
func TestRenderSettings_NonReasoningModelGetsNoBound(t *testing.T) {
	catalogServer(t, map[string]any{
		"id": "plain-1", "supported_formats": []string{"openai"},
		"max_completion_tokens": 4096, "supported_parameters": []string{},
	})
	env := render(t, New(), settings.Doc{Provider: inference.ZGComputeProvider, Model: "plain-1", Thinking: "high"})
	if v, ok := env["SEAL_MODEL_EFFORT"]; ok {
		t.Errorf("SEAL_MODEL_EFFORT=%q set for a model that takes no bound", v)
	}
}

// An Anthropic-format model must reach pi-ai as anthropic-messages on the
// Anthropic base — the openclaw regression this resolver exists to prevent
// (every 0g model routed through the OpenAI endpoint, first inference 400).
func TestRenderSettings_AnthropicFormatWiring(t *testing.T) {
	catalogServer(t, map[string]any{
		"id": "claude-x", "supported_formats": []string{"anthropic"},
		"max_completion_tokens": 64000, "supported_parameters": []string{},
	})
	env := render(t, New(), settings.Doc{Provider: inference.ZGComputeProvider, Model: "claude-x"})
	if env["SEAL_MODEL_API"] != "anthropic-messages" || env["SEAL_MODEL_BASE_URL"] != inference.ZGAnthropicBaseURL {
		t.Errorf("anthropic wiring wrong: api=%q baseURL=%q", env["SEAL_MODEL_API"], env["SEAL_MODEL_BASE_URL"])
	}
}

// The owner's overlay reaches the composition; it does not get to decide
// anything the platform owns. The knob set is typed, so a platform key in the
// overlay is simply not a knob — and the platform's value stands.
func TestRenderSettings_OverlayAppliedButPlatformWins(t *testing.T) {
	catalogServer(t, reasoningModel("glm-5.3"))
	env := render(t, New(), settings.Doc{
		Provider: inference.ZGComputeProvider,
		Model:    "glm-5.3",
		Thinking: "low",
		Framework: json.RawMessage(`{
			"toolJobs": true,
			"maxParallelToolCalls": 4,
			"model": "owner-picks-something-else",
			"SEAL_MODEL_BASE_URL": "http://attacker.invalid",
			"someFutureKnob": {"nested": true}
		}`),
	})

	if env["SEAL_DSH_TOOL_JOBS"] != "1" || env["SEAL_DSH_MAX_PARALLEL_TOOL_CALLS"] != "4" {
		t.Errorf("owner knobs were not applied: %v", env)
	}
	if env["SEAL_MODEL_ID"] != "glm-5.3" {
		t.Errorf("overlay overrode the platform's model pin: %q", env["SEAL_MODEL_ID"])
	}
	if env["SEAL_MODEL_BASE_URL"] != inference.ZGOpenAIBaseURL {
		t.Errorf("overlay overrode the platform's endpoint: %q", env["SEAL_MODEL_BASE_URL"])
	}
	if env["SEAL_MODEL_EFFORT"] != "low" {
		t.Errorf("overlay disturbed the reasoning bound: %q", env["SEAL_MODEL_EFFORT"])
	}
}

// An empty overlay must reproduce exactly the composition the bridge shipped
// with — the knobs are an owner option, not a behaviour change.
func TestRenderSettings_DefaultKnobsAreTheShippedComposition(t *testing.T) {
	catalogServer(t, reasoningModel("glm-5.3"))
	env := render(t, New(), settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3"})
	for k, want := range map[string]string{
		"SEAL_DSH_TOOL_JOBS":               "0",
		"SEAL_DSH_MAX_PARALLEL_TOOL_CALLS": "1",
	} {
		if env[k] != want {
			t.Errorf("%s = %q, want %q (today's hardcoded literal)", k, env[k], want)
		}
	}
}

// One policy for every way an overlay can be wrong. The first cut clamped an
// out-of-range value ("a typo must not brick an agent") but returned an error
// for a wrongly-typed one — and that error comes out of RenderSettings, which
// the manager calls before EVERY spawn, so the typo did brick the agent: it
// could not boot, and the document that caused it is the stored one.
func TestRenderSettings_BadOverlayValuesNeverFailTheRender(t *testing.T) {
	catalogServer(t, reasoningModel("glm-5.3"))
	for _, c := range []struct {
		name    string
		overlay string
		want    map[string]string
	}{
		{
			"wrongly-typed knob falls back and leaves its neighbours alone",
			`{"toolJobs":"yes","maxParallelToolCalls":4}`,
			map[string]string{"SEAL_DSH_TOOL_JOBS": "0", "SEAL_DSH_MAX_PARALLEL_TOOL_CALLS": "4"},
		},
		{
			"out-of-range value clamps, same as before",
			`{"toolJobs":true,"maxParallelToolCalls":0}`,
			map[string]string{"SEAL_DSH_TOOL_JOBS": "1", "SEAL_DSH_MAX_PARALLEL_TOOL_CALLS": "1"},
		},
		{
			"wrongly-typed number",
			`{"maxParallelToolCalls":"lots"}`,
			map[string]string{"SEAL_DSH_MAX_PARALLEL_TOOL_CALLS": "1"},
		},
		{
			"section is not an object at all",
			`["toolJobs"]`,
			map[string]string{"SEAL_DSH_TOOL_JOBS": "0", "SEAL_DSH_MAX_PARALLEL_TOOL_CALLS": "1"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := New()
			err := a.RenderSettings(context.Background(), settings.Resolve(context.Background(),
				settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3", Framework: json.RawMessage(c.overlay)}, "sk-test"))
			if err != nil {
				t.Fatalf("render must not fail on an owner-authored overlay: %v", err)
			}
			env := map[string]string{}
			for _, e := range a.rendered.env {
				k, v, _ := strings.Cut(e, "=")
				env[k] = v
			}
			for k, want := range c.want {
				if env[k] != want {
					t.Errorf("%s = %q, want %q (env: %v)", k, env[k], want, env)
				}
			}
		})
	}
}

// workspaceContext is refused, not applied: it mounts the extra that reads
// ~/.dsh/AGENTS.md into every turn's system context, and that file is
// agent-writable and belongs to no role — an untracked channel into the system
// prompt is not something an owner knob may open.
func TestRenderSettings_WorkspaceContextKnobIsRefused(t *testing.T) {
	catalogServer(t, reasoningModel("glm-5.3"))
	a := New()
	env := render(t, a, settings.Doc{
		Provider:  inference.ZGComputeProvider,
		Model:     "glm-5.3",
		Framework: json.RawMessage(`{"workspaceContext":true,"toolJobs":true}`),
	})
	for k, v := range env {
		if strings.Contains(k, "WORKSPACE") {
			t.Errorf("the refused knob still reaches the bridge: %s=%s", k, v)
		}
	}
	// Refusing one knob must not cost the owner the legitimate ones.
	if env["SEAL_DSH_TOOL_JOBS"] != "1" {
		t.Errorf("toolJobs = %q, want 1 — a refused knob must not take its neighbours down", env["SEAL_DSH_TOOL_JOBS"])
	}
}

// The three outcomes of settings.Resolved.Effort, which this adapter must keep
// apart. The regression an adversarial review reproduced elsewhere: treating a
// catalog outage as "this model takes no bound" strips the bound from an
// always-thinking model, which then reasons forever and never replies. Here
// the owner's stated level is what must survive the outage — Effort() decides
// for a stated preference even when the catalog is silent, and gating the
// variable on the catalog instead would drop it.
func TestRenderSettings_EffortHandlesAllThreeOutcomes(t *testing.T) {
	t.Run("decided level is named", func(t *testing.T) {
		catalogServer(t, reasoningModel("glm-5.3"))
		env := render(t, New(), settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3", Thinking: "high"})
		if env["SEAL_MODEL_EFFORT"] != "high" {
			t.Errorf("SEAL_MODEL_EFFORT = %q, want high", env["SEAL_MODEL_EFFORT"])
		}
	})

	t.Run("decided clear names nothing", func(t *testing.T) {
		catalogServer(t, map[string]any{
			"id": "plain-1", "supported_formats": []string{"openai"},
			"max_completion_tokens": 4096, "supported_parameters": []string{},
		})
		env := render(t, New(), settings.Doc{Provider: inference.ZGComputeProvider, Model: "plain-1", Thinking: "high"})
		if v, ok := env["SEAL_MODEL_EFFORT"]; ok {
			t.Errorf("SEAL_MODEL_EFFORT=%q on a model the catalog says rejects it — a hard 400 on every turn", v)
		}
	})

	t.Run("undecided invents nothing", func(t *testing.T) {
		deadCatalog(t)
		env := render(t, New(), settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3"})
		if v, ok := env["SEAL_MODEL_EFFORT"]; ok {
			t.Errorf("SEAL_MODEL_EFFORT=%q invented during a catalog outage; the platform knows nothing here and a level it cannot support is a 400", v)
		}
	})

	t.Run("an owner's level survives the outage", func(t *testing.T) {
		deadCatalog(t)
		env := render(t, New(), settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3", Thinking: "high"})
		if env["SEAL_MODEL_EFFORT"] != "high" {
			t.Errorf("SEAL_MODEL_EFFORT = %q, want high — a stated preference must not be dropped over an outage, or an always-thinking model runs unbounded", env["SEAL_MODEL_EFFORT"])
		}
	})
}

// During a catalog outage the heuristic still supplies a runtime budget, but
// that guess (8192) must never be handed to the bridge: it is written into
// the pi-ai model entry, where it starves a reasoning model's shared
// thinking+reply budget into permanently empty replies. No variable means
// pi-ai's own default applies.
func TestRenderSettings_HeuristicBudgetIsNotPassedToTheBridge(t *testing.T) {
	deadCatalog(t)
	resolved := settings.Resolve(context.Background(),
		settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3"}, "sk-test")
	if resolved.Facts.MaxTokens == 0 {
		t.Fatal("precondition: the heuristic should still supply a runtime budget")
	}

	a := New()
	if err := a.RenderSettings(context.Background(), resolved); err != nil {
		t.Fatalf("RenderSettings: %v", err)
	}
	for _, e := range a.rendered.env {
		if strings.HasPrefix(e, "SEAL_MODEL_MAX_TOKENS=") {
			t.Errorf("heuristic budget reached the bridge: %s", e)
		}
	}
}

// The credential is not one of the rendered variables. It IS held — the
// resolved document stashed here carries it, because Start needs it at spawn
// (spawn.go) — but it stays out of the deterministic KEY=VALUE slice that is
// rebuilt, compared and logged on every boot.
func TestRenderSettings_KeyIsNotInTheRenderedEnv(t *testing.T) {
	catalogServer(t, reasoningModel("glm-5.3"))
	a := New()
	if err := a.RenderSettings(context.Background(), settings.Resolve(context.Background(),
		settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3"}, "sk-secret")); err != nil {
		t.Fatalf("RenderSettings: %v", err)
	}
	for _, e := range a.rendered.env {
		if strings.Contains(e, "sk-secret") {
			t.Errorf("inference key leaked into the rendered env: %s", e)
		}
	}
}

// Start has no file left to recover a pin from, so an unrendered adapter is a
// bootstrap bug — it must say so instead of booting modelless.
func TestStart_WithoutRenderSettingsFails(t *testing.T) {
	a := &Adapter{}
	_, err := a.Start(context.Background(), framework.RuntimeContext{})
	if err == nil {
		t.Fatal("Start before RenderSettings must fail, got nil error")
	}
	if !strings.Contains(err.Error(), "RenderSettings") {
		t.Errorf("error should name the missing step, got: %v", err)
	}
}

// A document that names no model is the other Start-blocking case: the bridge
// exits rather than substitute a model the owner never picked.
func TestStart_WithoutAPinFails(t *testing.T) {
	deadCatalog(t)
	a := New()
	if err := a.RenderSettings(context.Background(), settings.Resolve(context.Background(), settings.Doc{}, "")); err != nil {
		t.Fatalf("RenderSettings: %v", err)
	}
	if _, err := a.Start(context.Background(), framework.RuntimeContext{}); err == nil {
		t.Fatal("Start with no provider/model must fail, got nil error")
	}
}

// The credential this adapter hands the bridge comes from the resolved
// settings document, not from RuntimeContext. RuntimeContext carries an
// APIKey field, is losing it, and is frozen at the first Start; taking the key
// from there is what dialled a platform-routed endpoint keyless and 401'd
// live, and dsh was the last adapter still doing it.
func TestBridgeEnv_CredentialComesFromTheSettingsDocument(t *testing.T) {
	catalogServer(t, reasoningModel("glm-5.3"))
	a := New()
	resolved := settings.Resolve(context.Background(),
		settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3"}, "sk-from-settings")
	if err := a.RenderSettings(context.Background(), resolved); err != nil {
		t.Fatalf("RenderSettings: %v", err)
	}

	env := strings.Join(bridgeEnv{
		token:       "tok",
		apiKey:      a.rendered.resolved.APIKey,
		settingsEnv: a.rendered.env,
		rt:          framework.RuntimeContext{APIKey: "sk-from-runtimecontext"},
	}.environ("/node_modules"), "\n")

	if !strings.Contains(env, "SEAL_MODEL_API_KEY=sk-from-settings") {
		t.Errorf("the bridge was not handed the resolved settings credential:\n%s", env)
	}
	if strings.Contains(env, "sk-from-runtimecontext") {
		t.Errorf("the bridge was handed RuntimeContext.APIKey:\n%s", env)
	}
}

// A platform-routed endpoint with no key must not reach the spawn: the router
// answers an unauthenticated call with a 401, so the container would come up
// healthy and fail every single turn.
func TestStart_RoutedEndpointWithoutAKeyFails(t *testing.T) {
	catalogServer(t, reasoningModel("glm-5.3"))
	a := New()
	if err := a.RenderSettings(context.Background(), settings.Resolve(context.Background(),
		settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3"}, "")); err != nil {
		t.Fatalf("RenderSettings: %v", err)
	}
	_, err := a.Start(context.Background(), framework.RuntimeContext{APIKey: "sk-from-runtimecontext"})
	if err == nil {
		t.Fatal("Start on a routed endpoint with no resolved key must fail, got nil error")
	}
	if !strings.Contains(err.Error(), "no inference key") {
		t.Errorf("the error must name the missing credential, got: %v", err)
	}
}

// The half of the settings.yaml migration only this package can write.
//
// Dropping the role from Roles() makes the uploader drop the on-chain entry on
// the first watcher tick — correct and intended, because bootstrap hands the
// old entry to HandleLegacy first and the platform persists what comes back
// (report.SeedSettings). This is the reading half: an agent minted while the
// role existed keeps its pin instead of coming up modelless, which for this
// adapter means not coming up at all.
func TestHandleLegacy_SettingsYAML_RecoversThePin(t *testing.T) {
	a := New()
	dshHome = t.TempDir()

	// Exactly what the retired writer put on chain: canonical JSON of DSH's
	// settings-file shape.
	entry := []byte(`{"llm-pi-ai":{"providers":{"0g-compute":{"apiKeyEnv":"SEAL_MODEL_API_KEY","models":[{"id":"glm-5.3"}]}}}}`)
	if err := a.HandleLegacy(context.Background(), "settings.yaml", entry); err != nil {
		t.Fatalf("HandleLegacy: %v", err)
	}

	doc, ok := a.SeededSettings()
	if !ok {
		t.Fatal("SeededSettings() found nothing; a legacy agent would boot with no pin and dsh.Start refuses that")
	}
	if doc.Provider != "0g-compute" || doc.Model != "glm-5.3" {
		t.Errorf("recovered %+v, want provider=0g-compute model=glm-5.3", doc)
	}
	if err := doc.Validate(); err != nil {
		t.Errorf("the recovered document must be one the platform can store: %v", err)
	}

	// Recovery reads; it does not resurrect the file the role used to write.
	if entries, err := os.ReadDir(dshHome); err != nil {
		t.Fatal(err)
	} else if len(entries) != 0 {
		t.Errorf("recovery wrote into the home: %v", entries)
	}
}

// Nothing recoverable is a quiet no-op, never a failed boot: the agent simply
// keeps whatever document attestor already holds.
func TestHandleLegacy_SettingsYAML_UnrecoverableEntriesAreNoops(t *testing.T) {
	for _, c := range []struct {
		name  string
		entry []byte
	}{
		{"empty", nil},
		{"not json", []byte("llm-pi-ai:\n  providers: {}\n")},
		{"no route", []byte(`{"llm-pi-ai":{"providers":{}}}`)},
		{"route with no model", []byte(`{"llm-pi-ai":{"providers":{"0g-compute":{"apiKeyEnv":"SEAL_MODEL_API_KEY"}}}}`)},
		{"some other plugin's settings", []byte(`{"token-meter":{"budget":1000}}`)},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := New()
			dshHome = t.TempDir()
			if err := a.HandleLegacy(context.Background(), "settings.yaml", c.entry); err != nil {
				t.Fatalf("an unreadable legacy entry must not fail the boot: %v", err)
			}
			if doc, ok := a.SeededSettings(); ok {
				t.Errorf("SeededSettings() = %+v, true — nothing was recoverable here", doc)
			}
		})
	}
}

// A multi-provider file (never written by this adapter, but a hand edit could
// have left one) must recover the same pin on every boot.
func TestHandleLegacy_SettingsYAML_PickIsDeterministic(t *testing.T) {
	entry := []byte(`{"llm-pi-ai":{"providers":{
		"zeta":{"models":[{"id":"z-1"}]},
		"0g-compute":{"models":[{"id":"glm-5.3"}]},
		"alpha":{"models":[{"id":"a-1"}]}}}}`)
	for i := 0; i < 8; i++ {
		a := New()
		dshHome = t.TempDir()
		if err := a.HandleLegacy(context.Background(), "settings.yaml", entry); err != nil {
			t.Fatal(err)
		}
		doc, _ := a.SeededSettings()
		if doc.Provider != "0g-compute" || doc.Model != "glm-5.3" {
			t.Fatalf("run %d recovered %+v; the pick must not depend on map order", i, doc)
		}
	}
}
