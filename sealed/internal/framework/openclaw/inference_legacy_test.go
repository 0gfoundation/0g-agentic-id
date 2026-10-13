package openclaw

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/inference"
	"seal-verify/internal/settings"
)

// The half of the openclaw.json migration only this package can write.
//
// Dropping the role from Roles() makes the uploader drop the on-chain entry on
// the first watcher tick — correct and intended, because bootstrap hands the
// old entry to HandleLegacy first and the platform persists what comes back
// (report.SeedSettings). This is the reading half: an agent minted while the
// role existed keeps its pin instead of coming up modelless, which for
// openclaw means a healthy-looking container that fails the owner's first
// message.

// legacyRoutedEntry is the shape a platform-routed agent actually left on
// chain: openclaw.json filtered to {agents, auth, models}, with the pin
// already REWRITTEN to the resolved provider by the augmentation that ran
// before the first drift commit. The base URLs are spelled out rather than
// built from inference's constants on purpose — these bytes are historical,
// they cannot be re-rendered, so a constant that moved away from them is a
// migration that silently stopped working and this test must fail.
const legacyRoutedEntry = `{
  "agents": {
    "defaults": {
      "model": {"primary": "openai/glm-5.3"},
      "thinkingDefault": "high",
      "timeoutSeconds": 600
    }
  },
  "auth": {
    "order": {"0g-compute": ["0g-compute:api"], "openai": ["openai:api"]},
    "profiles": {
      "0g-compute:api": {"provider": "0g-compute", "mode": "api_key"},
      "openai:api": {"provider": "openai", "mode": "api_key"}
    }
  },
  "models": {
    "providers": {
      "openai": {
        "api": "openai-completions",
        "baseUrl": "https://router-api.0g.ai/v1",
        "timeoutSeconds": 600,
        "apiKey": {"source": "env", "provider": "default", "id": "OPENAI_API_KEY"},
        "models": [{"id": "glm-5.3", "name": "glm-5.3", "reasoning": true,
                    "contextWindow": 1000000, "maxTokens": 131072}]
      }
    }
  }
}`

// recover runs the legacy branch the way bootstrap's Phase C does and returns
// what the platform would read back out.
func recoverLegacy(t *testing.T, entry string) (*Adapter, settings.Doc, bool) {
	t.Helper()
	useTempHome(t)
	a := New()
	if err := a.HandleLegacy(context.Background(), "openclaw.json", []byte(entry)); err != nil {
		t.Fatalf("HandleLegacy must never fail a boot: %v", err)
	}
	doc, ok := a.SeededSettings()
	return a, doc, ok
}

// A routed agent's pin survives the upgrade, and survives it as the provider
// the OWNER chose — not the resolved label the augmentation wrote over it.
func TestHandleLegacy_OpenclawJSON_RecoversTheOwnersPin(t *testing.T) {
	a, doc, ok := recoverLegacy(t, legacyRoutedEntry)
	if !ok {
		t.Fatal("SeededSettings() found nothing; this agent would come up with no model and fail the owner's first message")
	}
	if doc.Provider != inference.ZGComputeProvider {
		t.Errorf("provider = %q, want %q — the config's %q label is the augmentation's rewrite, and recovering it verbatim files a platform-routed pin as a framework built-in",
			doc.Provider, inference.ZGComputeProvider, "openai")
	}
	if doc.Model != "glm-5.3" {
		t.Errorf("model = %q, want glm-5.3", doc.Model)
	}
	if doc.Thinking != "high" {
		t.Errorf("thinking = %q, want high — the level sat in the tracked `agents` subtree, so the owner's choice is recoverable here", doc.Thinking)
	}

	// The platform reaches the recovery through the optional interface, so the
	// assertion main.go makes has to hold on the concrete adapter.
	if _, implements := any(a).(framework.LegacySettingsSeeder); !implements {
		t.Fatal("*Adapter does not satisfy framework.LegacySettingsSeeder; bootstrap's type assertion would skip the recovery entirely")
	}

	// Recovery reads. It does not write openclaw.json back — that file belongs
	// to RenderSettings now and is rebuilt from the document every Start.
	if _, err := os.Stat(openclawJSONPath()); !os.IsNotExist(err) {
		t.Errorf("recovery touched %s (stat err = %v); the retired role must not resurrect the file", openclawJSONPath(), err)
	}
}

// The document that comes back is the one the platform will store and render
// from forever after. A document that fails Validate is the same outage the
// migration exists to prevent, written down.
func TestHandleLegacy_OpenclawJSON_RecoveredDocumentValidates(t *testing.T) {
	for _, c := range []struct {
		name  string
		entry string
	}{
		{"routed glm", legacyRoutedEntry},
		{"routed claude on the anthropic wire", `{"agents":{"defaults":{"model":{"primary":"anthropic/claude-sonnet-5"}}},
			"models":{"providers":{"anthropic":{"api":"anthropic-messages","baseUrl":"https://router-api.0g.ai"}}}}`},
		{"framework built-in", `{"agents":{"defaults":{"model":{"primary":"anthropic/claude-sonnet-5"},"thinkingDefault":"max"}}}`},
		{"level openclaw accepts but settings does not", `{"agents":{"defaults":{"model":{"primary":"openai/glm-5.3"},"thinkingDefault":"medium"}}}`},
		{"level is not even a string", `{"agents":{"defaults":{"model":{"primary":"openai/glm-5.3"},"thinkingDefault":true}}}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, doc, ok := recoverLegacy(t, c.entry)
			if !ok {
				t.Fatal("nothing recovered from an entry that carries a pin")
			}
			if err := doc.Validate(); err != nil {
				t.Fatalf("recovered %+v, which the platform cannot store: %v", doc, err)
			}
		})
	}
}

// A pin openclaw served out of its OWN provider table keeps the owner's own
// provider name: there is no router base URL next to it, so nothing says the
// platform was supplying the endpoint.
func TestHandleLegacy_OpenclawJSON_BuiltInProviderKeepsItsName(t *testing.T) {
	// The model id carries a slash of its own, which is why the split is on
	// the FIRST one only.
	entry := `{"agents":{"defaults":{"model":{"primary":"openrouter/anthropic/claude-3-5-sonnet-latest"}}},
		"models":{"providers":{"openrouter":{"baseUrl":"https://openrouter.ai/api/v1"}}}}`
	_, doc, ok := recoverLegacy(t, entry)
	if !ok {
		t.Fatal("nothing recovered")
	}
	if doc.Provider != "openrouter" {
		t.Errorf("provider = %q, want openrouter — no 0g router base URL next to this pin, so it is a genuine built-in", doc.Provider)
	}
	if doc.Model != "anthropic/claude-3-5-sonnet-latest" {
		t.Errorf("model = %q, want anthropic/claude-3-5-sonnet-latest (split on the FIRST slash only)", doc.Model)
	}
}

// Nothing recoverable is a quiet no-op, never a failed boot: the agent keeps
// whatever document attestor already holds, which is where it would have been
// with no migration at all.
func TestHandleLegacy_OpenclawJSON_UnrecoverableEntriesAreNoops(t *testing.T) {
	for _, c := range []struct {
		name  string
		entry string
	}{
		{"empty", ""},
		{"whitespace", "  \n\t "},
		{"not json", "agents:\n  defaults: {}\n"},
		{"truncated json", `{"agents":{"defaults":{"model":{"primary":"openai/glm-5.3"`},
		{"json but not an object", `["agents"]`},
		{"no agents section", `{"auth":{"order":{}},"models":{"providers":{}}}`},
		{"agents of the wrong shape", `{"agents":"defaults"}`},
		{"no pin", `{"agents":{"defaults":{"thinkingDefault":"high"}}}`},
		{"pin is not a string", `{"agents":{"defaults":{"model":{"primary":42}}}}`},
		{"pin has no provider label", `{"agents":{"defaults":{"model":{"primary":"glm-5.3"}}}}`},
		{"pin has no model", `{"agents":{"defaults":{"model":{"primary":"openai/"}}}}`},
		{"pin has an empty label", `{"agents":{"defaults":{"model":{"primary":"/glm-5.3"}}}}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, doc, ok := recoverLegacy(t, c.entry)
			if ok {
				t.Errorf("SeededSettings() = %+v, true — nothing here is a pin openclaw could have used, and a half-recovered document would be persisted and then outrank every later attempt", doc)
			}
		})
	}
}

// The normal case for every agent minted after the channel shipped: no legacy
// entry at all, so there is nothing to report.
func TestSeededSettings_NothingRecovered(t *testing.T) {
	useTempHome(t)
	a := New()
	if doc, ok := a.SeededSettings(); ok {
		t.Errorf("SeededSettings() = %+v, true on an adapter that never saw a legacy entry", doc)
	}

	// An unrelated legacy role must not change that (and must not error).
	if err := a.HandleLegacy(context.Background(), "some-experimental-role", []byte(`{"x":1}`)); err != nil {
		t.Fatalf("an unknown legacy role must be ignored, not fatal: %v", err)
	}
	if doc, ok := a.SeededSettings(); ok {
		t.Errorf("SeededSettings() = %+v, true after an unrelated role", doc)
	}
}

// Levels the settings vocabulary does not offer are left unset rather than
// mapped onto a neighbour: an invented level is a configuration the owner
// never chose, and Effort() derives a sound bound for an absent one.
func TestHandleLegacy_OpenclawJSON_ThinkingLevel(t *testing.T) {
	for _, c := range []struct{ raw, want string }{
		{`"low"`, "low"},
		{`"high"`, "high"},
		{`"max"`, "max"},
		{`"HIGH"`, "high"}, // normalized, so Validate's own comparison can't fail
		{`"medium"`, ""},   // openclaw's vocabulary, not the platform's
		{`"off"`, "low"},   // no platform word for it; recovered at the floor
		{`""`, ""},
		{`true`, ""},
		{`null`, ""},
	} {
		t.Run(c.raw, func(t *testing.T) {
			entry := `{"agents":{"defaults":{"model":{"primary":"openai/glm-5.3"},"thinkingDefault":` + c.raw + `}}}`
			_, doc, ok := recoverLegacy(t, entry)
			if !ok {
				t.Fatal("the pin must still be recovered whatever the level says")
			}
			if doc.Thinking != c.want {
				t.Errorf("thinking = %q, want %q", doc.Thinking, c.want)
			}
			if err := doc.Validate(); err != nil {
				t.Errorf("recovered document does not validate: %v", err)
			}
		})
	}
}

// HandleLegacy can run again on a later boot while the chain entry is still
// there, so it has to be idempotent and to keep its hands off everything but
// the stash.
func TestHandleLegacy_OpenclawJSON_Idempotent(t *testing.T) {
	a, first, ok := recoverLegacy(t, legacyRoutedEntry)
	if !ok {
		t.Fatal("nothing recovered")
	}
	if err := a.HandleLegacy(context.Background(), "openclaw.json", []byte(legacyRoutedEntry)); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	second, ok := a.SeededSettings()
	if !ok || !reflect.DeepEqual(second, first) {
		t.Errorf("second pass recovered %+v (ok=%t), first pass %+v", second, ok, first)
	}
}

// What the provider decision is FOR: feed the recovered document back through
// the render and the agent is wired to the 0g router again, exactly as it was
// before the upgrade. Under a catalog outage, so the assertion is about
// routing and not about catalog facts.
func TestHandleLegacy_OpenclawJSON_RecoveredPinRendersBackOntoTheRouter(t *testing.T) {
	deadCatalog(t)
	_, doc, ok := recoverLegacy(t, legacyRoutedEntry)
	if !ok {
		t.Fatal("nothing recovered")
	}

	cfg := renderInto(t, settings.Resolve(context.Background(), doc, "sk-test"))
	if got := primaryPin(t, cfg); got != "openai/glm-5.3" {
		t.Errorf("re-rendered pin = %q, want openai/glm-5.3 (the resolved label the router route implies)", got)
	}
	models, _ := cfg["models"].(map[string]any)
	providers, _ := models["providers"].(map[string]any)
	entry, ok := providers["openai"].(map[string]any)
	if !ok {
		t.Fatalf("no 0g-router provider entry after the render (models = %v); this agent is no longer routed and its key is a router key", models)
	}
	if entry["baseUrl"] != inference.ZGOpenAIBaseURL {
		t.Errorf("baseUrl = %v, want %s — recovering the resolved label instead of the owner's provider is what points this agent at api.openai.com with a router key", entry["baseUrl"], inference.ZGOpenAIBaseURL)
	}
}

// The contrast case: a genuine built-in must NOT acquire a router entry.
func TestHandleLegacy_OpenclawJSON_BuiltInRendersWithoutTheRouter(t *testing.T) {
	deadCatalog(t)
	_, doc, ok := recoverLegacy(t, `{"agents":{"defaults":{"model":{"primary":"anthropic/claude-sonnet-5"}}}}`)
	if !ok {
		t.Fatal("nothing recovered")
	}

	cfg := renderInto(t, settings.Resolve(context.Background(), doc, "sk-test"))
	if got := primaryPin(t, cfg); got != "anthropic/claude-sonnet-5" {
		t.Errorf("re-rendered pin = %q, want anthropic/claude-sonnet-5", got)
	}
	models, _ := cfg["models"].(map[string]any)
	if providers, _ := models["providers"].(map[string]any); len(providers) != 0 {
		t.Errorf("render declared provider entries %v for a framework built-in; openclaw supplies its own endpoint for those", providers)
	}
}

// ── the mint seed half ──────────────────────────────────────────────────────
//
// attestor mints exactly two iData roles, `framework` and `persona`, so an
// agent minted before the settings channel that has never committed drift has
// no retired config role at all: its pin exists only in the mint seed. The
// config half above cannot reach that population, and openclaw.json — where
// the seed writes the pin on disk — is rebuilt from the owner's document by
// RenderSettings on every Start, so the disk write alone leaves the agent
// modelless.

// legacyPersonaSeed is what attestor's default_i_data emits at mint: the
// owner's literal choice, provider named as the owner picked it.
const legacyPersonaSeed = `{
  "system_prompt": "You are Sage. DeFi helper\n",
  "inference": {"provider": "0g-compute", "model": "glm-5.3"}
}`

// recoverPersona runs the persona branch the way bootstrap's Phase C does.
func recoverPersona(t *testing.T, entry string) (*Adapter, settings.Doc, bool) {
	t.Helper()
	useTempHome(t)
	a := New()
	if err := a.HandleLegacy(context.Background(), "persona", []byte(entry)); err != nil {
		t.Fatalf("HandleLegacy must never fail a boot: %v", err)
	}
	doc, ok := a.SeededSettings()
	return a, doc, ok
}

// The gap this branch closes: a never-drifted agent keeps its pin, the
// document the platform will store validates, and feeding it back through the
// render wires the agent to the same route it was on before the upgrade —
// which for a "0g-compute" owner choice means the 0g router, reached through
// the resolved provider label openclaw indexes it under.
func TestHandleLegacy_Persona_RecoversAPinThatRoutesTheSame(t *testing.T) {
	deadCatalog(t) // routing must not depend on the catalog being up
	a, doc, ok := recoverPersona(t, legacyPersonaSeed)
	if !ok {
		t.Fatal("SeededSettings() found nothing for a persona-only agent; this is the population that has no config role to fall back on — openclaw comes up modelless and prime refuses to Start at all")
	}
	if doc.Provider != inference.ZGComputeProvider || doc.Model != "glm-5.3" {
		t.Fatalf("recovered %+v, want the owner's literal choice 0g-compute/glm-5.3", doc)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("recovered %+v, which the platform cannot store: %v", doc, err)
	}

	// The platform reaches the recovery through the optional interface.
	if _, implements := any(a).(framework.LegacySettingsSeeder); !implements {
		t.Fatal("*Adapter does not satisfy framework.LegacySettingsSeeder; bootstrap's type assertion would skip the recovery entirely")
	}

	cfg := renderInto(t, settings.Resolve(context.Background(), doc, "sk-test"))
	if got := primaryPin(t, cfg); got != "openai/glm-5.3" {
		t.Errorf("re-rendered pin = %q, want openai/glm-5.3 — the resolved label a routed agent has always run under", got)
	}
	models, _ := cfg["models"].(map[string]any)
	providers, _ := models["providers"].(map[string]any)
	entry, ok := providers["openai"].(map[string]any)
	if !ok {
		t.Fatalf("no 0g-router provider entry after the render (models = %v); this agent is no longer routed and its key is a router key", models)
	}
	if entry["baseUrl"] != inference.ZGOpenAIBaseURL {
		t.Errorf("baseUrl = %v, want %s", entry["baseUrl"], inference.ZGOpenAIBaseURL)
	}
}

// Phase C walks the chain entries in whatever order they arrived, so the
// precedence rule has to be in the code and not in the iteration. Both orders
// must land on the config role's pin: it is the agent's LATER state (the seed
// says glm-4.5-air, the config says the glm-5.3 it was actually running), and
// it is the only one of the two that can carry a level at all.
func TestHandleLegacy_PrecedenceHoldsInEitherOrder(t *testing.T) {
	const seed = `{"system_prompt":"x","inference":{"provider":"0g-compute","model":"glm-4.5-air"}}`

	orders := map[string][][2]string{
		"config first":  {{"openclaw.json", legacyRoutedEntry}, {"persona", seed}},
		"persona first": {{"persona", seed}, {"openclaw.json", legacyRoutedEntry}},
	}
	for name, order := range orders {
		t.Run(name, func(t *testing.T) {
			useTempHome(t)
			a := New()
			for _, e := range order {
				if err := a.HandleLegacy(context.Background(), e[0], []byte(e[1])); err != nil {
					t.Fatalf("HandleLegacy[%s] must never fail a boot: %v", e[0], err)
				}
			}
			doc, ok := a.SeededSettings()
			if !ok {
				t.Fatal("nothing recovered from two entries that both carry a pin")
			}
			if doc.Model != "glm-5.3" {
				t.Errorf("model = %q, want glm-5.3 — the mint seed's %q is the route this agent stopped using, and recovering it rolls the agent back", doc.Model, "glm-4.5-air")
			}
			if doc.Provider != inference.ZGComputeProvider {
				t.Errorf("provider = %q, want %q", doc.Provider, inference.ZGComputeProvider)
			}
			if doc.Thinking != "high" {
				t.Errorf("thinking = %q, want high — only the config role can carry a level, so preferring the seed silently drops the owner's bound", doc.Thinking)
			}
		})
	}
}

// Nothing usable in the seed is a quiet no-op. It must not fail the boot (an
// error out of HandleLegacy is propagated by Phase C and takes the container
// offline) and it must not report a half document: what comes back is
// persisted and then consulted ahead of this recovery on every later boot.
func TestHandleLegacy_Persona_UnrecoverableSeedsAreNoops(t *testing.T) {
	for _, c := range []struct{ name, entry string }{
		{"empty", ""},
		{"whitespace", "  \n\t "},
		{"not json", "system_prompt: hi\n"},
		{"truncated json", `{"inference":{"provider":"0g-compute"`},
		{"json but not an object", `["persona"]`},
		{"inference of the wrong shape", `{"system_prompt":"x","inference":"0g-compute/glm-5.3"}`},
		{"no inference section", `{"system_prompt":"prompt only"}`},
		{"empty inference", `{"system_prompt":"x","inference":{}}`},
		{"model but no provider", `{"inference":{"model":"glm-5.3"}}`},
		{"provider but no model", `{"inference":{"provider":"0g-compute"}}`},
		{"blank after trimming", `{"inference":{"provider":" ","model":" "}}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, doc, ok := recoverPersona(t, c.entry)
			if ok {
				t.Errorf("SeededSettings() = %+v, true — nothing here is a pin openclaw could render, and a half-recovered document would be persisted and then outrank every later attempt", doc)
			}
		})
	}
}

// The pin is stashed before either disk write, so a disk that cannot take
// SOUL.md costs the prompt and not the model — and still does not fail the
// boot. openclawHome is pointed at a regular file, which fails MkdirAll.
func TestHandleLegacy_Persona_DiskFailureKeepsThePinAndTheBoot(t *testing.T) {
	prev := openclawHome
	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	openclawHome = blocked
	t.Cleanup(func() { openclawHome = prev })

	a := New()
	if err := a.HandleLegacy(context.Background(), "persona", []byte(legacyPersonaSeed)); err != nil {
		t.Fatalf("a disk failure must not fail the boot: %v", err)
	}
	doc, ok := a.SeededSettings()
	if !ok || doc.Model != "glm-5.3" {
		t.Errorf("SeededSettings() = %+v, %t — the pin is recovered in memory and must not be lost to a disk error", doc, ok)
	}
}

// Phase C can run again on a later boot while the seed is still on chain.
func TestHandleLegacy_Persona_SeedingIsIdempotent(t *testing.T) {
	a, first, ok := recoverPersona(t, legacyPersonaSeed)
	if !ok {
		t.Fatal("nothing recovered")
	}
	if err := a.HandleLegacy(context.Background(), "persona", []byte(legacyPersonaSeed)); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	second, ok := a.SeededSettings()
	if !ok || !reflect.DeepEqual(second, first) {
		t.Errorf("second pass recovered %+v (ok=%t), first pass %+v", second, ok, first)
	}
}
