package prime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/inference"
	"seal-verify/internal/settings"
)

// RenderSettings is the whole configuration channel for this adapter: it
// writes the model registration the SDK reads, and it is the only thing that
// hands Start an inference pin now that no file and no chain role carries one.

// reasoningModel is a catalog entry for an always-thinking model — the case
// where a missing bound means unbounded reasoning and an empty reply.
var reasoningModel = map[string]any{
	"id":                    "glm-5.3",
	"supported_formats":     []string{"openai"},
	"context_length":        131072,
	"max_completion_tokens": 131072,
	"supported_parameters":  []string{"reasoning_effort"},
}

// stubCatalog points the router catalog at a one-model test server.
func stubCatalog(t *testing.T, entry map[string]any) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{entry}})
	}))
	restore := inference.SetCatalogURLForTest(srv.URL)
	t.Cleanup(func() { restore(); srv.Close() })
}

// readRendered parses the rendered file as generic JSON — deliberately not
// through modelsConfig, so a key the typed shape would silently drop still
// shows up in these assertions.
func readRendered(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(modelsJSONPath())
	if err != nil {
		t.Fatalf("read %s: %v", modelsJSONPath(), err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("rendered models.json is not valid JSON: %v\n%s", err, raw)
	}
	return doc
}

func providerEntry(t *testing.T, doc map[string]any, name string) map[string]any {
	t.Helper()
	providers, ok := doc["providers"].(map[string]any)
	if !ok {
		t.Fatalf("no providers object: %v", doc)
	}
	p, ok := providers[name].(map[string]any)
	if !ok {
		t.Fatalf("provider %q missing: %v", name, providers)
	}
	return p
}

// Same Resolved in, same bytes out. The render runs on every Start, so a
// non-deterministic one would rewrite the file (and, for the roles that are
// still tracked, teach the watcher to report drift) on every boot.
func TestRenderSettingsIsIdempotent(t *testing.T) {
	primeHome = t.TempDir()
	stubCatalog(t, reasoningModel)
	a := New()

	s := settings.Resolve(context.Background(), settings.Doc{
		Provider:  inference.ZGComputeProvider,
		Model:     "glm-5.3",
		Thinking:  "high",
		Framework: json.RawMessage(`{"providers":{"my-own":{"baseUrl":"http://127.0.0.1:1234","models":[{"id":"local"}]}}}`),
	}, "sk-live-secret")

	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatalf("RenderSettings: %v", err)
	}
	first, err := os.ReadFile(modelsJSONPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatalf("RenderSettings (second): %v", err)
	}
	second, err := os.ReadFile(modelsJSONPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("render is not idempotent:\n 1 = %s\n 2 = %s", first, second)
	}

	// The credential is referenced by env-var NAME. A literal key here would
	// sit in the agent's home, readable by the framework process.
	if bytes.Contains(first, []byte("sk-live-secret")) {
		t.Errorf("the API key was written to disk: %s", first)
	}
	if !bytes.Contains(first, []byte(apiKeyEnvRef)) {
		t.Errorf("apiKey should reference %s: %s", apiKeyEnvRef, first)
	}

	// And the pin is stashed for Start, which has nothing else to read it from.
	if a.settings == nil || a.settings.Model != "glm-5.3" {
		t.Errorf("RenderSettings did not stash the resolved settings: %+v", a.settings)
	}
}

// The level must not hang off the provider check. A built-in provider with no
// overlay gets no registration file at all, so SEAL_OWNER_THINKING is all the
// platform gets to say about reasoning here — and an always-thinking model
// without a bound reasons forever and never replies. (Whether the level then
// reaches the wire is the framework's call, from its own model tables; see
// bridgeEnvFor.)
func TestNativeProviderStillGetsTheEffortBound(t *testing.T) {
	primeHome = t.TempDir()
	stubCatalog(t, reasoningModel)
	a := New()

	s := settings.Resolve(context.Background(), settings.Doc{
		Provider: "anthropic", Model: "glm-5.3", Thinking: "high",
	}, "sk")
	if s.Endpoint != nil {
		t.Fatalf("precondition: a built-in provider must resolve to no endpoint, got %+v", s.Endpoint)
	}
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatalf("RenderSettings: %v", err)
	}
	if _, err := os.Stat(modelsJSONPath()); !os.IsNotExist(err) {
		t.Errorf("a built-in provider needs no registration file, but %s exists", modelsJSONPath())
	}

	be := bridgeEnvFor(s, "tok", framework.RuntimeContext{})
	if be.effort != "high" {
		t.Errorf("effort = %q, want high — the bound is provider-independent", be.effort)
	}
	env := strings.Join(be.environ("/node_modules"), "\n")
	if !strings.Contains(env, "SEAL_OWNER_THINKING=high") {
		t.Errorf("the bridge is not told the effort level:\n%s", env)
	}
	if strings.Contains(env, "SEAL_MODEL_BASE_URL") {
		t.Errorf("a built-in provider must not be handed an endpoint:\n%s", env)
	}
}

// The owner's overlay is applied, and then loses every key the platform owns.
// Ordering is the whole mechanism: an exclusion list would have to enumerate
// the keys that matter, and would miss the next one.
func TestOverlayAppliesButNeverBeatsAPlatformKey(t *testing.T) {
	primeHome = t.TempDir()
	stubCatalog(t, reasoningModel)
	a := New()

	overlay := `{"providers":{
		"0g-compute":{
			"baseUrl":"http://attacker.invalid",
			"compat":{"supportsReasoningEffort":false,"supportsDeveloperRole":true},
			"models":[{"id":"some-other-model"}],
			"headers":{"x-owner":"1"}
		},
		"my-own":{"baseUrl":"http://127.0.0.1:1234"}
	}}`
	s := settings.Resolve(context.Background(), settings.Doc{
		Provider: inference.ZGComputeProvider, Model: "glm-5.3", Thinking: "high",
		Framework: json.RawMessage(overlay),
	}, "sk")
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatalf("RenderSettings: %v", err)
	}
	doc := readRendered(t)

	routed := providerEntry(t, doc, inference.ZGComputeProvider)
	if got := routed["baseUrl"]; got != inference.ZGOpenAIBaseURL {
		t.Errorf("baseUrl = %v, want the catalog's %q — an overlay must not pin an endpoint", got, inference.ZGOpenAIBaseURL)
	}
	compat, _ := routed["compat"].(map[string]any)
	if compat["supportsReasoningEffort"] != true {
		t.Errorf("an overlay disabled bounded reasoning: %v", compat)
	}
	if compat["supportsDeveloperRole"] != false {
		t.Errorf("supportsDeveloperRole = %v, want false (the platform owns it)", compat["supportsDeveloperRole"])
	}
	models, _ := routed["models"].([]any)
	if len(models) != 1 {
		t.Fatalf("models = %v, want exactly the pinned one", models)
	}
	if first, _ := models[0].(map[string]any); first["id"] != "glm-5.3" {
		t.Errorf("models[0].id = %v, want the pinned glm-5.3 — the platform's array replaces the owner's", first["id"])
	}

	// …and the half of the overlay the platform does not own survives, which
	// is the point of merging rather than ignoring it.
	headers, _ := routed["headers"].(map[string]any)
	if headers["x-owner"] != "1" {
		t.Errorf("the owner's own key was dropped: %v", routed)
	}
	if _, ok := providerEntry(t, doc, "my-own")["baseUrl"]; !ok {
		t.Errorf("the owner's own provider was dropped: %v", doc)
	}
}

// A budget the catalog did not supply must not be written down. The heuristic's
// 8192 looks hand-set forever after and starves a reasoning model's shared
// thinking+reply budget into permanently empty replies (agent 404).
func TestHeuristicBudgetIsNotWrittenToDisk(t *testing.T) {
	primeHome = t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "catalog down", http.StatusBadGateway)
	}))
	defer srv.Close()
	restore := inference.SetCatalogURLForTest(srv.URL)
	defer restore()

	s := settings.Resolve(context.Background(), settings.Doc{
		Provider: inference.ZGComputeProvider, Model: "glm-5.3",
	}, "sk")
	if err := New().RenderSettings(context.Background(), s); err != nil {
		t.Fatalf("RenderSettings: %v", err)
	}

	routed := providerEntry(t, readRendered(t), inference.ZGComputeProvider)
	models, _ := routed["models"].([]any)
	if len(models) != 1 {
		t.Fatalf("models = %v", models)
	}
	entry, _ := models[0].(map[string]any)
	if _, written := entry["maxTokens"]; written {
		t.Errorf("a heuristic budget reached disk: %v", entry)
	}
	// The boot still has to work through a catalog outage: the endpoint is
	// registered, only the guessed budget is withheld.
	if routed["baseUrl"] == "" || routed["baseUrl"] == nil {
		t.Errorf("no endpoint registered during a catalog outage: %v", routed)
	}
}

// Start has no config file left to discover the pin from, so reaching it
// without a render is a bootstrap-sequence bug and must say so — not fail
// later with an opaque "pinned model is not resolvable" from the bridge.
func TestStartWithoutRenderSettingsIsAProgrammingError(t *testing.T) {
	primeHome = t.TempDir()
	_, err := New().Start(context.Background(), framework.RuntimeContext{})
	if err == nil || !strings.Contains(err.Error(), "RenderSettings") {
		t.Fatalf("Start without RenderSettings = %v, want an error naming RenderSettings", err)
	}
}

// The hole the built-in path shipped with: the overlay was written out
// verbatim, so an owner document could wire the PINNED provider anywhere it
// liked while the bridge exported the inference credential for it. The probe
// below is the one that found it.
func TestBuiltinProviderOverlayCannotRewireThePinnedModel(t *testing.T) {
	primeHome = t.TempDir()
	stubCatalog(t, reasoningModel)
	a := New()

	overlay := `{"providers":{"anthropic":{
		"baseUrl":"http://attacker.invalid",
		"api":"openai-completions",
		"apiKey":"SEAL_MODEL_API_KEY",
		"authHeader":true,
		"compat":{"supportsReasoningEffort":false},
		"models":[{"id":"glm-5.3","reasoning":false}],
		"headers":{"x-owner":"1"}
	}}}`
	s := settings.Resolve(context.Background(), settings.Doc{
		Provider: "anthropic", Model: "glm-5.3", Thinking: "high",
		Framework: json.RawMessage(overlay),
	}, "sk-live-secret")
	if s.Endpoint != nil {
		t.Fatalf("precondition: a built-in provider must resolve to no endpoint, got %+v", s.Endpoint)
	}
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatalf("RenderSettings: %v", err)
	}

	entry := providerEntry(t, readRendered(t), "anthropic")
	for _, k := range builtinWiringKeys {
		if v, present := entry[k]; present {
			t.Errorf("providers.anthropic.%s = %v survived — an overlay must not wire the provider serving the pinned model", k, v)
		}
	}

	// The platform's claims land on top instead.
	compat, _ := entry["compat"].(map[string]any)
	if compat["supportsReasoningEffort"] != true {
		t.Errorf("the overlay disabled bounded reasoning: compat = %v", compat)
	}
	models, _ := entry["models"].([]any)
	if len(models) != 1 {
		t.Fatalf("models = %v, want exactly the pinned one", models)
	}
	first, _ := models[0].(map[string]any)
	if first["id"] != "glm-5.3" || first["reasoning"] != true {
		t.Errorf("models[0] = %v, want the pinned model marked reasoning-capable", first)
	}

	// What the platform does not own still survives — the point of merging.
	if headers, _ := entry["headers"].(map[string]any); headers["x-owner"] != "1" {
		t.Errorf("the owner's own key was dropped: %v", entry)
	}
	raw, err := os.ReadFile(modelsJSONPath())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("sk-live-secret")) {
		t.Errorf("the API key was written to disk: %s", raw)
	}
}

// …but only over a provider the overlay actually declared. Inventing a
// half-filled entry for a provider the SDK has a built-in for would replace a
// working registration with one that carries no endpoint at all.
func TestBuiltinProviderLeavesAnUndeclaredPinAlone(t *testing.T) {
	primeHome = t.TempDir()
	stubCatalog(t, reasoningModel)
	a := New()

	s := settings.Resolve(context.Background(), settings.Doc{
		Provider: "anthropic", Model: "glm-5.3", Thinking: "high",
		Framework: json.RawMessage(`{"providers":{"my-own":{"baseUrl":"http://127.0.0.1:1234","models":[{"id":"local"}]}}}`),
	}, "sk")
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatalf("RenderSettings: %v", err)
	}

	doc := readRendered(t)
	providers, _ := doc["providers"].(map[string]any)
	if _, invented := providers["anthropic"]; invented {
		t.Errorf("an entry was invented for the built-in pin: %v", providers)
	}
	if got := providerEntry(t, doc, "my-own")["baseUrl"]; got != "http://127.0.0.1:1234" {
		t.Errorf("my-own.baseUrl = %v — a provider the platform does not serve is the owner's to wire", got)
	}
}

// The third Effort outcome. During a catalog outage with no owner preference
// the platform knows nothing about this model's reasoning, and both available
// claims are wrong: false strips the bound from an always-thinking model
// (unbounded reasoning, empty replies), true earns a 400 from a model that
// takes none. So it writes neither key — which is what distinguishes "unknown"
// from the decided clear asserted in the next test.
func TestCatalogOutageClaimsNothingAboutReasoning(t *testing.T) {
	primeHome = t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "catalog down", http.StatusBadGateway)
	}))
	defer srv.Close()
	defer inference.SetCatalogURLForTest(srv.URL)()

	s := settings.Resolve(context.Background(), settings.Doc{
		Provider: inference.ZGComputeProvider, Model: "glm-5.3",
	}, "sk")
	if _, decided := s.Effort(); decided {
		t.Fatal("precondition: an outage with no owner preference must leave Effort undecided")
	}
	if err := New().RenderSettings(context.Background(), s); err != nil {
		t.Fatalf("RenderSettings: %v", err)
	}

	routed := providerEntry(t, readRendered(t), inference.ZGComputeProvider)
	compat, _ := routed["compat"].(map[string]any)
	if v, present := compat["supportsReasoningEffort"]; present {
		t.Errorf("supportsReasoningEffort = %v was written during a catalog outage; the platform knows nothing here and must claim nothing", v)
	}
	models, _ := routed["models"].([]any)
	entry, _ := models[0].(map[string]any)
	if v, present := entry["reasoning"]; present {
		t.Errorf("reasoning = %v was written during a catalog outage: %v", v, entry)
	}
	if v, present := entry["thinkingLevelMap"]; present {
		t.Errorf("thinkingLevelMap = %v was written during a catalog outage: %v", v, entry)
	}

	// And no level is named: the env var names one, and there is none to name.
	env := strings.Join(bridgeEnvFor(s, "tok", framework.RuntimeContext{}).environ("/node_modules"), "\n")
	if strings.Contains(env, "SEAL_OWNER_THINKING") {
		t.Errorf("a level was named during a catalog outage:\n%s", env)
	}
}

// The decided clear, for contrast: the catalog positively says this model
// rejects reasoning_effort, so the platform says so too — sending it anyway is
// a hard 400.
func TestNonReasoningModelIsMarkedUnsupported(t *testing.T) {
	primeHome = t.TempDir()
	stubCatalog(t, map[string]any{
		"id": "plain-1", "supported_formats": []string{"openai"},
		"max_completion_tokens": 4096, "supported_parameters": []string{},
	})

	s := settings.Resolve(context.Background(), settings.Doc{
		Provider: inference.ZGComputeProvider, Model: "plain-1", Thinking: "high",
	}, "sk")
	if err := New().RenderSettings(context.Background(), s); err != nil {
		t.Fatalf("RenderSettings: %v", err)
	}

	routed := providerEntry(t, readRendered(t), inference.ZGComputeProvider)
	compat, _ := routed["compat"].(map[string]any)
	if v, present := compat["supportsReasoningEffort"]; !present || v != false {
		t.Errorf("supportsReasoningEffort = %v (present=%v), want an explicit false", v, present)
	}
	models, _ := routed["models"].([]any)
	if entry, _ := models[0].(map[string]any); entry["reasoning"] == true {
		t.Errorf("a model the catalog says takes no bound was marked reasoning-capable: %v", entry)
	}
	env := strings.Join(bridgeEnvFor(s, "tok", framework.RuntimeContext{}).environ("/node_modules"), "\n")
	if strings.Contains(env, "SEAL_OWNER_THINKING") {
		t.Errorf("a level was named for a model that takes none:\n%s", env)
	}
}

// The credential is the resolved settings' to supply. RuntimeContext still
// carries an APIKey field and is losing it; taking it from there once dialed a
// platform-routed endpoint keyless and 401'd.
func TestBridgeCredentialComesFromTheResolvedSettings(t *testing.T) {
	primeHome = t.TempDir()
	stubCatalog(t, reasoningModel)

	s := settings.Resolve(context.Background(), settings.Doc{
		Provider: inference.ZGComputeProvider, Model: "glm-5.3",
	}, "sk-from-settings")
	env := strings.Join(
		bridgeEnvFor(s, "tok", framework.RuntimeContext{APIKey: "sk-from-runtimecontext"}).environ("/node_modules"),
		"\n")

	if !strings.Contains(env, "SEAL_MODEL_API_KEY=sk-from-settings") {
		t.Errorf("the bridge was not handed the resolved settings' credential:\n%s", env)
	}
	if strings.Contains(env, "sk-from-runtimecontext") {
		t.Errorf("the bridge was handed RuntimeContext.APIKey:\n%s", env)
	}
}

// This renderer rebuilds models.json from scratch each boot, so "contribute
// nothing when undecided" is not the neutral act it is for a merging
// renderer: it RETRACTS a claim an earlier catalog-backed boot established.
// An always-thinking model with no bound reasons without end and never
// replies — measured live at 23k characters over ten minutes, zero output.
func TestRenderSettings_OutageKeepsThePreviousReasoningClaim(t *testing.T) {
	prev := primeHome
	primeHome = t.TempDir()
	t.Cleanup(func() { primeHome = prev })
	if err := ensureDir(primeHome); err != nil {
		t.Fatal(err)
	}
	a := New()

	known := settings.Resolved{
		Doc: settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3", Thinking: "high"},
		Facts: inference.ModelFacts{
			MaxTokens: 131072, SupportsReasoningEffort: true, CatalogSourced: true,
		},
		Endpoint: &inference.Endpoint{Format: inference.WireOpenAI, BaseURL: inference.ZGOpenAIBaseURL, EnvKey: "OPENAI_API_KEY"},
	}
	if err := a.RenderSettings(context.Background(), known); err != nil {
		t.Fatalf("first render: %v", err)
	}

	// Same pin, catalog silent: Facts carry nothing and CatalogSourced is false.
	outage := settings.Resolved{
		Doc:      settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3"},
		Endpoint: &inference.Endpoint{Format: inference.WireOpenAI, BaseURL: inference.ZGOpenAIBaseURL, EnvKey: "OPENAI_API_KEY"},
	}
	if err := a.RenderSettings(context.Background(), outage); err != nil {
		t.Fatalf("outage render: %v", err)
	}

	raw, err := os.ReadFile(modelsJSONPath())
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Providers map[string]struct {
			Compat map[string]bool `json:"compat"`
			Models []struct {
				Reasoning bool `json:"reasoning"`
			} `json:"models"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parse rendered models.json: %v\n%s", err, raw)
	}
	p, ok := cfg.Providers[inference.ZGComputeProvider]
	if !ok || len(p.Models) == 0 {
		t.Fatalf("no provider entry after the outage render: %s", raw)
	}
	if !p.Models[0].Reasoning {
		t.Fatalf("reasoning retracted by an outage render: %s", raw)
	}
	if !p.Compat["supportsReasoningEffort"] {
		t.Fatalf("compat.supportsReasoningEffort retracted by an outage render: %s", raw)
	}
}

// ── the retired models.json role ────────────────────────────────────────────

// legacyEntry is what the retired writer put on chain for a routed,
// always-thinking model: buildModelsConfig's canonical JSON, with the
// catalog-sourced budget and the reasoning flags it wrote alongside the pin.
const legacyEntry = `{"providers":{"0g-compute":{"baseUrl":"https://router-api.0g.ai/v1",` +
	`"api":"openai-completions","apiKey":"SEAL_MODEL_API_KEY","authHeader":true,` +
	`"compat":{"supportsDeveloperRole":false,"supportsReasoningEffort":true},` +
	`"models":[{"id":"glm-5.3","maxTokens":131072,"reasoning":true,` +
	`"thinkingLevelMap":{"high":"high","low":"low","max":"max","medium":"low"}}]}}}`

// The half of the models.json migration only this package can write.
//
// Dropping the role from Roles() makes the uploader drop the on-chain entry on
// the first watcher tick — correct and intended, because bootstrap hands the
// old entry to HandleLegacy first and the platform persists what comes back
// (report.SeedSettings). This is the reading half, and for THIS adapter it is
// the difference between an agent that boots and one that does not: Start
// hard-fails on a missing pin, so an unrecovered legacy agent goes offline.
func TestHandleLegacy_ModelsJSON_RecoversThePin(t *testing.T) {
	primeHome = t.TempDir()
	a := New()

	if err := a.HandleLegacy(context.Background(), "models.json", []byte(legacyEntry)); err != nil {
		t.Fatalf("HandleLegacy: %v", err)
	}

	doc, ok := a.SeededSettings()
	if !ok {
		t.Fatal("SeededSettings() found nothing; this agent would boot with no pin and prime.Start refuses that — the container goes offline")
	}
	if doc.Provider != inference.ZGComputeProvider || doc.Model != "glm-5.3" {
		t.Errorf("recovered %+v, want provider=%s model=glm-5.3", doc, inference.ZGComputeProvider)
	}

	// The platform-derived half must NOT come along: it is recomputed from the
	// catalog at every render, and a stale copy is the 8192-max-tokens
	// incident. Doc has no field for any of it, so the check is that the
	// recovered document carries nothing but the pin.
	if doc.Thinking != "" {
		t.Errorf("thinking = %q; the retired entry records which levels are OFFERED, never which one the owner chose — inventing one configures the agent for them", doc.Thinking)
	}
	if len(doc.Framework) != 0 {
		t.Errorf("framework overlay = %s; nothing in the legacy entry is owner-authored framework knobs", doc.Framework)
	}

	// A document that fails validation is the same outage this migration
	// exists to prevent: the platform would log it and boot modelless anyway.
	if err := doc.Validate(); err != nil {
		t.Errorf("the recovered document must be one the platform can store: %v", err)
	}

	// Recovery reads; it does not resurrect the file the role used to write.
	// RenderSettings owns that path now and rebuilds it from the document.
	if entries, err := os.ReadDir(primeHome); err != nil {
		t.Fatal(err)
	} else if len(entries) != 0 {
		t.Errorf("recovery wrote into the framework home: %v", entries)
	}
}

// End to end: the recovered document has to be one this adapter can actually
// boot on, not merely one that parses. Resolve + RenderSettings is exactly
// what main.go does with it, and the registration it produces is what the SDK
// reads.
func TestHandleLegacy_ModelsJSON_RecoveredPinBoots(t *testing.T) {
	primeHome = t.TempDir()
	stubCatalog(t, reasoningModel)
	a := New()

	ctx := context.Background()
	if err := a.HandleLegacy(ctx, "models.json", []byte(legacyEntry)); err != nil {
		t.Fatalf("HandleLegacy: %v", err)
	}
	recovered, ok := a.SeededSettings()
	if !ok {
		t.Fatal("nothing recovered")
	}

	s := settings.Resolve(ctx, recovered, "sk")
	if s.Endpoint == nil {
		t.Fatalf("the recovered pin must resolve to a platform-routed endpoint; got none for provider %q", recovered.Provider)
	}
	if err := a.RenderSettings(ctx, s); err != nil {
		t.Fatalf("RenderSettings on the recovered document: %v", err)
	}
	entry := providerEntry(t, readRendered(t), inference.ZGComputeProvider)
	if entry["baseUrl"] != inference.ZGOpenAIBaseURL {
		t.Errorf("baseUrl = %v, want %s", entry["baseUrl"], inference.ZGOpenAIBaseURL)
	}
	// Start reads the stash, and refuses an empty half of the pin.
	if a.settings == nil || a.settings.Provider == "" || a.settings.Model != "glm-5.3" {
		t.Errorf("the recovered pin did not reach Start's stash: %+v", a.settings)
	}
}

// Nothing recoverable is a quiet no-op, never a failed boot: the agent keeps
// whatever document attestor already holds, which is the best this adapter
// version can do with bytes it cannot read.
func TestHandleLegacy_ModelsJSON_UnrecoverableEntriesAreNoops(t *testing.T) {
	for _, c := range []struct {
		name  string
		entry []byte
	}{
		{"absent", nil},
		{"blank", []byte("   \n")},
		{"not json", []byte("providers:\n  0g-compute: {}\n")},
		{"json but not an object", []byte(`["0g-compute"]`)},
		{"no providers", []byte(`{}`)},
		{"empty providers", []byte(`{"providers":{}}`)},
		{"provider with no models", []byte(`{"providers":{"0g-compute":{"baseUrl":"https://router-api.0g.ai/v1","models":[]}}}`)},
		{"model with no id", []byte(`{"providers":{"0g-compute":{"models":[{"maxTokens":131072}]}}}`)},
		// Provider key blank and no router baseUrl to name it from: Start
		// refuses an empty provider, so half a pin is not a recovery.
		{"nameless built-in provider", []byte(`{"providers":{"":{"models":[{"id":"glm-5.3"}]}}}`)},
	} {
		t.Run(c.name, func(t *testing.T) {
			primeHome = t.TempDir()
			a := New()
			if err := a.HandleLegacy(context.Background(), "models.json", c.entry); err != nil {
				t.Fatalf("an unreadable legacy entry must not fail the boot: %v", err)
			}
			if doc, ok := a.SeededSettings(); ok {
				t.Errorf("SeededSettings() = %+v, true — nothing was recoverable here", doc)
			}
		})
	}
}

// An adapter nobody handed a legacy entry to reports nothing. This is the
// normal case: every agent minted after the settings channel shipped.
func TestSeededSettings_NothingRecovered(t *testing.T) {
	primeHome = t.TempDir()
	a := New()
	if doc, ok := a.SeededSettings(); ok {
		t.Errorf("SeededSettings() = %+v, true on a fresh adapter; the platform would overwrite a stored document with it", doc)
	}
	if err := a.HandleLegacy(context.Background(), "some-experimental-role", []byte("{}")); err != nil {
		t.Errorf("an unknown legacy role must be ignored, got: %v", err)
	}
	if _, ok := a.SeededSettings(); ok {
		t.Error("an unrelated legacy role seeded a settings document")
	}
}

// models.json was chain-tracked AND agent-writable, so the bytes on chain are
// not necessarily the ones this adapter wrote. An entry that points at the 0g
// router under some other provider name recovers as the platform-routed
// provider: recovering the name verbatim would make the SDK treat it as a
// built-in and send the router's key to that provider's own endpoint (401
// "incorrect API key", which reads like a credential problem).
func TestHandleLegacy_ModelsJSON_RouterEntryRecoversAsPlatformRouted(t *testing.T) {
	for _, baseURL := range []string{inference.ZGOpenAIBaseURL, inference.ZGAnthropicBaseURL} {
		primeHome = t.TempDir()
		a := New()
		entry := []byte(`{"providers":{"openai":{"baseUrl":"` + baseURL + `","api":"openai-completions","models":[{"id":"glm-5.3"}]}}}`)
		if err := a.HandleLegacy(context.Background(), "models.json", entry); err != nil {
			t.Fatalf("HandleLegacy: %v", err)
		}
		doc, ok := a.SeededSettings()
		if !ok {
			t.Fatalf("%s: nothing recovered", baseURL)
		}
		if doc.Provider != inference.ZGComputeProvider {
			t.Errorf("%s: recovered provider %q, want %q", baseURL, doc.Provider, inference.ZGComputeProvider)
		}
	}
}

// The mirror image: an entry that is not the router keeps its provider name,
// and a look-alike host is not the router. Rewriting either one would move the
// agent's inference somewhere the owner never pointed it.
func TestHandleLegacy_ModelsJSON_NonRouterEntriesKeepTheirProvider(t *testing.T) {
	for _, c := range []struct{ name, baseURL string }{
		{"anthropic", ""},
		{"my-own", "http://127.0.0.1:1234/v1"},
		{"look-alike", "https://router-api.0g.ai.example.com/v1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			primeHome = t.TempDir()
			a := New()
			entry := []byte(`{"providers":{"` + c.name + `":{"baseUrl":"` + c.baseURL + `","models":[{"id":"glm-5.3"}]}}}`)
			if err := a.HandleLegacy(context.Background(), "models.json", entry); err != nil {
				t.Fatalf("HandleLegacy: %v", err)
			}
			doc, ok := a.SeededSettings()
			if !ok {
				t.Fatal("nothing recovered")
			}
			if doc.Provider != c.name {
				t.Errorf("recovered provider %q, want %q", doc.Provider, c.name)
			}
		})
	}
}

// A multi-provider file (this adapter never wrote one, but the file was
// agent-writable) must recover the same pin on every boot rather than one
// picked by Go's map order.
func TestHandleLegacy_ModelsJSON_PickIsDeterministic(t *testing.T) {
	entry := []byte(`{"providers":{
		"zeta":{"models":[{"id":"z-1"}]},
		"0g-compute":{"baseUrl":"https://router-api.0g.ai/v1","models":[{"id":"glm-5.3"}]},
		"alpha":{"models":[{"id":"a-1"}]}}}`)
	for i := 0; i < 8; i++ {
		primeHome = t.TempDir()
		a := New()
		if err := a.HandleLegacy(context.Background(), "models.json", entry); err != nil {
			t.Fatal(err)
		}
		doc, _ := a.SeededSettings()
		if doc.Provider != inference.ZGComputeProvider || doc.Model != "glm-5.3" {
			t.Fatalf("run %d recovered %+v; the pick must not depend on map order", i, doc)
		}
	}
}

// HandleLegacy runs again on any later boot the chain entry survives into, so
// a second pass must land the same pin and touch nothing else.
func TestHandleLegacy_ModelsJSON_IsIdempotent(t *testing.T) {
	primeHome = t.TempDir()
	a := New()
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := a.HandleLegacy(ctx, "models.json", []byte(legacyEntry)); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
		doc, ok := a.SeededSettings()
		if !ok || doc.Provider != inference.ZGComputeProvider || doc.Model != "glm-5.3" {
			t.Fatalf("pass %d recovered %+v (ok=%v)", i, doc, ok)
		}
	}
	if entries, err := os.ReadDir(primeHome); err != nil {
		t.Fatal(err)
	} else if len(entries) != 0 {
		t.Errorf("recovery has a side effect on disk: %v", entries)
	}
}
