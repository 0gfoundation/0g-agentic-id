package hermes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"seal-verify/internal/inference"
	"seal-verify/internal/settings"
)

// Both halves of the pre-channel pin recovery, exercised through the two calls
// bootstrap actually makes: HandleLegacy in Phase C (once per legacy chain
// entry, in chain order), then SeededSettings before the watcher starts.
// Transitional, like the code they cover — these tests go when the recovery
// goes.
//
//   - the retired "config.yaml" role: the pin of an agent that has drifted
//   - the mint "persona" seed: the pin of one that has not, and the only place
//     it is written down at all (attestor mints `framework` + `persona`)
//   - which of the two wins when a chain carries both

// legacyEntry is what evoConfigYAML put on chain: canonical JSON of the owned
// top-level keys, api_key stripped. This is the drift-committed shape, i.e.
// the one nearly every pre-channel agent carries — the owner asked for
// 0g-compute and the boot-time rewrite replaced that with hermes's resolved
// custom-endpoint form before the watcher photographed it.
const legacyEntry = `{"approvals":{"exec":"ask"},` +
	`"model":{"base_url":"https://router-api.0g.ai/v1","default":"glm-5.3","provider":"custom"},` +
	`"terminal":{"backend":"tmux"}}`

// The headline case: the pin survives the role's retirement, and it survives
// as the provider the OWNER chose rather than the one the rewrite left on
// chain. Recovering "custom" verbatim would leave settings.Resolve with a
// nil Endpoint and RenderSettings deleting base_url + api_key — hermes in
// custom mode with nothing to dial, which is an outage, not a migration.
func TestHandleLegacy_ConfigYAML_RecoversTheOwnersProvider(t *testing.T) {
	a := newTestAdapter(t)

	if err := a.HandleLegacy(context.Background(), "config.yaml", []byte(legacyEntry)); err != nil {
		t.Fatalf("HandleLegacy: %v", err)
	}

	doc, ok := a.SeededSettings()
	if !ok {
		t.Fatal("SeededSettings() found nothing; this agent boots modelless and the owner's first message fails")
	}
	if doc.Provider != inference.ZGComputeProvider {
		t.Errorf("provider = %q, want %q — base_url is the evidence that the platform routed this model",
			doc.Provider, inference.ZGComputeProvider)
	}
	if doc.Model != "glm-5.3" {
		t.Errorf("model = %q, want glm-5.3", doc.Model)
	}
	// A level sealed never wrote to chain must not be invented here: the old
	// role's allowlist was {approvals, model, terminal}, so
	// agent.reasoning_effort was never in it. Unset is also what makes
	// Effort() re-apply the same "low" floor the old boot did.
	if doc.Thinking != "" {
		t.Errorf("thinking = %q, want unset — the retired role never carried one", doc.Thinking)
	}
	// approvals + terminal are a photograph of the framework's own on-disk
	// defaults at the last drift commit, not an owner's choice; carrying them
	// would freeze one release's defaults into the document forever.
	if len(doc.Others) != 0 {
		t.Errorf("framework section = %s, want empty", doc.Others)
	}
}

// The one that matters most: a document that fails validation is the same
// outage this migration exists to prevent, so every realistic legacy shape
// must produce a storable one.
func TestHandleLegacy_ConfigYAML_RecoveredDocValidates(t *testing.T) {
	for _, c := range []struct {
		name         string
		entry        string
		wantProvider string
	}{
		{"drift-committed rewrite", legacyEntry, inference.ZGComputeProvider},
		{
			// Never drifted: the mint seed's literal choice, which the
			// rewrite only ever touched at Start.
			"mint-time seed", `{"model":{"default":"glm-5.3","provider":"0g-compute"}}`,
			inference.ZGComputeProvider,
		},
		{
			// A framework built-in brings its own wiring and is recovered
			// verbatim — rewriting it to 0g-compute would re-point the agent.
			"framework built-in", `{"model":{"default":"claude-sonnet-5","provider":"anthropic"}}`,
			"anthropic",
		},
		{
			// "custom" with no base_url names no endpoint and is not a
			// provider an owner can have chosen; the model still carries, so
			// the document stays valid and one push away from correct.
			"custom with no endpoint", `{"model":{"default":"glm-5.3","provider":"custom"}}`,
			"",
		},
		{
			// hermes's own default provider, never rewritten.
			"no provider at all", `{"model":{"default":"glm-5.3"}}`,
			"",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := newTestAdapter(t)
			if err := a.HandleLegacy(context.Background(), "config.yaml", []byte(c.entry)); err != nil {
				t.Fatalf("HandleLegacy: %v", err)
			}
			doc, ok := a.SeededSettings()
			if !ok {
				t.Fatal("SeededSettings() found nothing")
			}
			if doc.Provider != c.wantProvider {
				t.Errorf("provider = %q, want %q", doc.Provider, c.wantProvider)
			}
			if err := doc.Validate(); err != nil {
				t.Errorf("the recovered document must be one the platform can store: %v", err)
			}
		})
	}
}

// Nothing recoverable is a quiet no-op, never a failed boot: main.go's Phase C
// turns a HandleLegacy error into an offline container, and an entry this
// adapter version cannot read is not worth that — the agent keeps whatever
// document attestor already holds.
func TestHandleLegacy_ConfigYAML_UnrecoverableEntriesAreNoops(t *testing.T) {
	for _, c := range []struct {
		name  string
		entry []byte
	}{
		{"nil", nil},
		{"blank", []byte("   \n")},
		{"not json", []byte("model:\n  default: glm-5.3\n")},
		{"truncated json", []byte(`{"model":{"default":"glm-5.3"`)},
		{"top level is not an object", []byte(`["model"]`)},
		{"no model section", []byte(`{"approvals":{"exec":"ask"},"terminal":{"backend":"tmux"}}`)},
		{"model is not an object", []byte(`{"model":"glm-5.3"}`)},
		{"model section with no default", []byte(`{"model":{"provider":"custom","base_url":"https://router-api.0g.ai/v1"}}`)},
		{"blank default", []byte(`{"model":{"default":"  "}}`)},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := newTestAdapter(t)
			if err := a.HandleLegacy(context.Background(), "config.yaml", c.entry); err != nil {
				t.Fatalf("an unreadable legacy entry must not fail the boot: %v", err)
			}
			if doc, ok := a.SeededSettings(); ok {
				t.Errorf("SeededSettings() = %+v, true — nothing was recoverable here", doc)
			}
		})
	}
}

// Every agent minted after the channel shipped takes this path: no legacy
// entry, so nothing is reported and main.go keeps the stored document.
func TestSeededSettings_ReportsFalseWithoutARecovery(t *testing.T) {
	a := newTestAdapter(t)
	if doc, ok := a.SeededSettings(); ok {
		t.Fatalf("SeededSettings() = %+v, true on an adapter that saw no legacy entry", doc)
	}

	// An unrelated legacy role must not arm it either.
	if err := a.HandleLegacy(context.Background(), "settings.yaml", []byte(legacyEntry)); err != nil {
		t.Fatalf("unknown legacy role must be ignored, not fatal: %v", err)
	}
	if doc, ok := a.SeededSettings(); ok {
		t.Fatalf("SeededSettings() = %+v, true — that role belongs to another adapter", doc)
	}
}

// HandleLegacy runs again on any later boot where the chain entry is still
// there, so it must be idempotent and must not touch disk: config.yaml is
// RenderSettings's artifact now, and a copy written here would be a second
// source of truth that wins exactly when the document is empty.
func TestHandleLegacy_ConfigYAML_IdempotentAndWritesNoConfig(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()

	var first settings.Doc
	for i := 0; i < 3; i++ {
		if err := a.HandleLegacy(ctx, "config.yaml", []byte(legacyEntry)); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		doc, ok := a.SeededSettings()
		if !ok {
			t.Fatalf("run %d recovered nothing", i)
		}
		if i == 0 {
			first = doc
			continue
		}
		if doc.Provider != first.Provider || doc.Model != first.Model ||
			doc.Thinking != first.Thinking || len(doc.Others) != len(first.Others) {
			t.Fatalf("run %d recovered %+v, want %+v — recovery must be idempotent", i, doc, first)
		}
	}

	if _, err := os.Stat(configYAMLPath()); !os.IsNotExist(err) {
		t.Errorf("recovery wrote %s (err=%v); it reads the chain entry, it does not resurrect the file",
			configYAMLPath(), err)
	}
}

// ── the mint `persona` seed ─────────────────────────────────────────────────

// personaSeed is what attestor mints: the owner's literal deploy choice, with
// no rewrite anywhere in its history. Spelled out rather than built from
// constants — these are bytes already on chain.
const personaSeed = `{"system_prompt":"You are Sage. DeFi helper\n",` +
	`"inference":{"provider":"0g-compute","model":"glm-5.3"}}`

// deadCatalog points the router catalog at a server that refuses, so a test
// that asserts ROUTING is not also asserting live catalog facts (and never
// reaches the network).
func deadCatalog(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "catalog down", http.StatusBadGateway)
	}))
	restore := inference.SetCatalogURLForTest(srv.URL)
	t.Cleanup(func() { restore(); srv.Close() })
}

// The population three reviews found: minted before the settings channel,
// never drifted, so the chain carries `framework` + `persona` and NO retired
// config role. Before this, sealed ingested the seed to disk and reported
// nothing, and the agent came up with an empty document.
func TestHandleLegacy_Persona_RecoversThePinOfANeverDriftedAgent(t *testing.T) {
	a := newTestAdapter(t)

	if err := a.HandleLegacy(context.Background(), "persona", []byte(personaSeed)); err != nil {
		t.Fatalf("HandleLegacy: %v", err)
	}

	doc, ok := a.SeededSettings()
	if !ok {
		t.Fatal("SeededSettings() found nothing; with no config role on chain this seed is the agent's only pin, and without it hermes renders modelless and the owner's first message fails")
	}
	if doc.Provider != inference.ZGComputeProvider || doc.Model != "glm-5.3" {
		t.Errorf("recovered %s/%s, want %s/glm-5.3 — the seed is the owner's literal choice and is taken verbatim",
			doc.Provider, doc.Model, inference.ZGComputeProvider)
	}
	// The platform persists this document and renders from it forever after,
	// so one that fails Validate is the same outage, written down.
	if err := doc.Validate(); err != nil {
		t.Errorf("the recovered document must be one the platform can store: %v", err)
	}

	// The identity half of the ingestion is unchanged and must still land.
	soul, err := os.ReadFile(soulMDPath())
	if err != nil {
		t.Fatalf("read SOUL.md: %v", err)
	}
	if !strings.Contains(string(soul), "You are Sage.") {
		t.Errorf("SOUL.md = %q, want the seed's system_prompt", soul)
	}
}

// What the recovery is FOR: feed the recovered document back through the
// render and hermes is wired to the 0G router exactly as the pre-upgrade boot
// wired it — the old path was ingestPersona writing provider=0g-compute into
// config.yaml and applyZGComputeAugmentation rewriting that to the custom
// endpoint at Start. Same four keys, same values.
func TestHandleLegacy_Persona_RecoveredPinRendersBackOntoTheRouter(t *testing.T) {
	deadCatalog(t)
	a := newTestAdapter(t)
	ctx := context.Background()

	if err := a.HandleLegacy(ctx, "persona", []byte(personaSeed)); err != nil {
		t.Fatalf("HandleLegacy: %v", err)
	}
	doc, ok := a.SeededSettings()
	if !ok {
		t.Fatal("nothing recovered")
	}

	if err := a.RenderSettings(ctx, settings.Resolve(ctx, doc, "sk-test-router-key")); err != nil {
		t.Fatalf("RenderSettings on the recovered document: %v", err)
	}
	m := modelSection(t)
	if m["default"] != "glm-5.3" {
		t.Errorf("model.default = %v, want glm-5.3", m["default"])
	}
	if m["provider"] != "custom" || m["base_url"] != inference.ZGOpenAIBaseURL {
		t.Errorf("model = %v; want hermes's custom-endpoint form on %s — a document that does not say %q leaves Endpoint nil, and the render then deletes base_url and api_key and hermes has nothing to dial",
			m, inference.ZGOpenAIBaseURL, inference.ZGComputeProvider)
	}
	if m["api_key"] != "sk-test-router-key" {
		t.Errorf("model.api_key = %v, want this boot's key — hermes's custom provider reads the key only from here", m["api_key"])
	}
}

// A seed this adapter cannot read is a no-op, never a failed boot: main.go's
// Phase C turns a HandleLegacy error into an OFFLINE container, which is
// strictly worse than the degraded agent the old code produced.
func TestHandleLegacy_Persona_UnreadableSeedsAreNoops(t *testing.T) {
	for _, c := range []struct {
		name string
		seed []byte
	}{
		{"nil", nil},
		{"blank", []byte("  \n")},
		{"not json", []byte("system_prompt: hi\n")},
		{"truncated json", []byte(`{"inference":{"provider":"0g-compute"`)},
		{"top level is not an object", []byte(`["persona"]`)},
		{"inference is not an object", []byte(`{"system_prompt":"x","inference":"0g-compute/glm-5.3"}`)},
		{"no inference at all", []byte(`{"system_prompt":"x"}`)},
		{"no model", []byte(`{"inference":{"provider":"0g-compute"}}`)},
		{"blank model", []byte(`{"inference":{"provider":"0g-compute","model":"  "}}`)},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := newTestAdapter(t)
			if err := a.HandleLegacy(context.Background(), "persona", c.seed); err != nil {
				t.Fatalf("an unreadable mint seed must not fail the boot: %v", err)
			}
			if doc, ok := a.SeededSettings(); ok {
				t.Errorf("SeededSettings() = %+v, true — there is no pin in this seed, and a half document is persisted and then consulted ahead of every later recovery", doc)
			}
		})
	}
}

// The two failures inside the branch are independent. A home directory that
// refuses SOUL.md must not also cost the owner their model — that is one
// unwritable path taking out inference for the whole agent.
func TestHandleLegacy_Persona_DiskFailureStillRecoversThePin(t *testing.T) {
	a := newTestAdapter(t)
	blocker := hermesHome + "/not-a-dir"
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := hermesHome
	hermesHome = blocker + "/home" // every write under it fails with ENOTDIR
	t.Cleanup(func() { hermesHome = prev })

	if err := a.HandleLegacy(context.Background(), "persona", []byte(personaSeed)); err != nil {
		t.Fatalf("a disk failure must not fail the boot: %v", err)
	}
	doc, ok := a.SeededSettings()
	if !ok || doc.Model != "glm-5.3" {
		t.Errorf("SeededSettings() = %+v, %t; the pin is stashed in memory and does not depend on the disk write", doc, ok)
	}
}

// ── which recovery wins ─────────────────────────────────────────────────────

// laterConfigEntry is the retired role carrying a DIFFERENT pin from the seed,
// so the two orders below cannot both pass by accident.
const laterConfigEntry = `{"model":{"base_url":"https://router-api.0g.ai/v1","default":"glm-4.6","provider":"custom"}}`

// Phase C walks the chain's entries in whatever order they appear, so the
// ranking has to hold both ways round. The seed wins: it is the pin the
// pre-upgrade container actually dialed (Phase C's persona ingest wrote over
// the restored config.yaml, and Start read the pin off that file), and it is
// the only one of the two that states the owner's provider rather than
// inferring it.
func TestHandleLegacy_PersonaOutranksTheRetiredRole_EitherOrder(t *testing.T) {
	for _, c := range []struct {
		name  string
		roles []string
	}{
		{"seed first", []string{"persona", "config.yaml"}},
		{"retired role first", []string{"config.yaml", "persona"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := newTestAdapter(t)
			ctx := context.Background()
			for _, role := range c.roles {
				entry := personaSeed
				if role == "config.yaml" {
					entry = laterConfigEntry
				}
				if err := a.HandleLegacy(ctx, role, []byte(entry)); err != nil {
					t.Fatalf("HandleLegacy[%s]: %v", role, err)
				}
			}

			doc, ok := a.SeededSettings()
			if !ok {
				t.Fatal("SeededSettings() found nothing")
			}
			if doc.Model != "glm-5.3" {
				t.Errorf("model = %q, want glm-5.3 (the seed's) — precedence must be the rank, not the order Phase C happened to reach the entries in",
					doc.Model)
			}
			if doc.Provider != inference.ZGComputeProvider {
				t.Errorf("provider = %q, want %q", doc.Provider, inference.ZGComputeProvider)
			}
		})
	}
}

// Same ranking where it changes the outcome rather than just the model id: the
// retired role's endpoint is one the settings document cannot express, so its
// recovery names no provider at all, while the seed names the owner's. Taking
// the "later" entry here would hand a routable agent a document with no route.
func TestHandleLegacy_PersonaWins_WhenTheRetiredRoleCannotNameTheProvider(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	const ownEndpoint = `{"model":{"base_url":"https://llm.example.com/v1","default":"glm-5.3","provider":"custom"}}`

	for _, role := range []string{"config.yaml", "persona"} {
		entry := personaSeed
		if role == "config.yaml" {
			entry = ownEndpoint
		}
		if err := a.HandleLegacy(ctx, role, []byte(entry)); err != nil {
			t.Fatalf("HandleLegacy[%s]: %v", role, err)
		}
	}

	doc, _ := a.SeededSettings()
	if doc.Provider != inference.ZGComputeProvider {
		t.Errorf("provider = %q, want %q — the seed states it, the retired role can only infer it and here cannot",
			doc.Provider, inference.ZGComputeProvider)
	}
}

// ── the retired role's base_url is evidence, and only the router's counts ───

// A review caught this: ANY non-empty base_url used to mean 0g-compute, so an
// owner's own OpenAI-compatible endpoint came back pointing at the 0G router
// — inference re-pointed at a service the owner did not pick, billed to the
// platform's key. Only a base_url sealed itself wrote is evidence of routing.
func TestHandleLegacy_ConfigYAML_ForeignEndpointIsNotTheRouter(t *testing.T) {
	deadCatalog(t)
	for _, baseURL := range []string{
		"https://llm.example.com/v1",
		"https://api.openai.com/v1",
		"http://127.0.0.1:1234/v1",
		inference.ZGOpenAIBaseURL + "x", // near-miss on the router's own spelling
	} {
		t.Run(baseURL, func(t *testing.T) {
			a := newTestAdapter(t)
			ctx := context.Background()
			entry := `{"model":{"base_url":"` + baseURL + `","default":"glm-5.3","provider":"custom"}}`
			if err := a.HandleLegacy(ctx, "config.yaml", []byte(entry)); err != nil {
				t.Fatalf("HandleLegacy: %v", err)
			}

			doc, ok := a.SeededSettings()
			if !ok {
				t.Fatal("SeededSettings() found nothing; the model is still recoverable even when the endpoint is not")
			}
			if doc.Provider == inference.ZGComputeProvider {
				t.Fatalf("provider = %q for base_url %s — that endpoint is the owner's, and claiming 0g-compute for it points the agent at the 0G router with the platform's key",
					doc.Provider, baseURL)
			}
			if doc.Model != "glm-5.3" {
				t.Errorf("model = %q, want glm-5.3 — the endpoint is unrecoverable, the pin is not", doc.Model)
			}
			if err := doc.Validate(); err != nil {
				t.Errorf("the recovered document must still be storable: %v", err)
			}

			// And the render must not conjure the router back.
			if err := a.RenderSettings(ctx, settings.Resolve(ctx, doc, "sk-test-router-key")); err != nil {
				t.Fatalf("RenderSettings: %v", err)
			}
			if m := modelSection(t); m["base_url"] != nil || m["provider"] == "custom" {
				t.Errorf("rendered model = %v, want no endpoint wiring at all", m)
			}
		})
	}
}

// The contrast: the router's own base URLs still are the evidence they always
// were, on both wire formats (hermes rejects the anthropic one at render time,
// but the recovery must not silently drop the pin before it gets there).
func TestHandleLegacy_ConfigYAML_RouterEndpointsStillMapToZGCompute(t *testing.T) {
	for _, baseURL := range []string{inference.ZGOpenAIBaseURL, inference.ZGAnthropicBaseURL} {
		t.Run(baseURL, func(t *testing.T) {
			a := newTestAdapter(t)
			entry := `{"model":{"base_url":"` + baseURL + `","default":"glm-5.3","provider":"custom"}}`
			if err := a.HandleLegacy(context.Background(), "config.yaml", []byte(entry)); err != nil {
				t.Fatalf("HandleLegacy: %v", err)
			}
			doc, ok := a.SeededSettings()
			if !ok || doc.Provider != inference.ZGComputeProvider {
				t.Errorf("recovered %+v (ok=%t), want provider %q", doc, ok, inference.ZGComputeProvider)
			}
		})
	}
}
