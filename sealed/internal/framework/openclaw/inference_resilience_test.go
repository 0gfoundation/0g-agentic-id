package openclaw

import (
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

// ── helpers ─────────────────────────────────────────────────────────────────

// deadCatalog points the router catalog at a server that 500s, so
// settings.Resolve produces the real outage shape: heuristic facts,
// CatalogSourced=false, Effort() undecided.
func deadCatalog(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "catalog down", http.StatusBadGateway)
	}))
	restore := inference.SetCatalogURLForTest(srv.URL)
	t.Cleanup(func() { restore(); srv.Close() })
}

func agentsDefaults(t *testing.T, cfg map[string]any) map[string]any {
	t.Helper()
	agents, _ := cfg["agents"].(map[string]any)
	defaults, _ := agents["defaults"].(map[string]any)
	return defaults
}

func providerEntry(t *testing.T, cfg map[string]any, label string) map[string]any {
	t.Helper()
	models, _ := cfg["models"].(map[string]any)
	providers, _ := models["providers"].(map[string]any)
	entry, ok := providers[label].(map[string]any)
	if !ok {
		t.Fatalf("no %q provider entry: %v", label, providers)
	}
	return entry
}

func firstModelDef(t *testing.T, entry map[string]any) map[string]any {
	t.Helper()
	defs, _ := entry["models"].([]any)
	if len(defs) == 0 {
		t.Fatalf("provider entry carries no model definition: %v", entry)
	}
	def, _ := defs[0].(map[string]any)
	return def
}

// healthyEntry is what a render with a reachable catalog leaves on disk for
// glm-5.3 on the router's OpenAI endpoint.
func healthyEntry() map[string]any {
	return map[string]any{
		"models": map[string]any{"providers": map[string]any{
			"openai": map[string]any{
				"baseUrl":        inference.ZGOpenAIBaseURL,
				"api":            "openai-completions",
				"timeoutSeconds": 600,
				"models": []any{map[string]any{
					"id": "glm-5.3", "name": "glm-5.3",
					"contextWindow": 1000000, "maxTokens": 131072, "reasoning": true,
					"compat": map[string]any{
						"requiresStringContent":   true,
						"supportsReasoningEffort": true,
					},
				}},
			},
		}},
	}
}

// ── the catalog outage must not decide anything ─────────────────────────────

// The blocker an adversarial review reproduced: the render deleted
// agents.defaults.thinkingDefault whenever Effort() came back empty, and the
// single-valued Effort() also came back empty when the CATALOG WAS
// UNREACHABLE. An outage boot therefore stripped the bound off an
// always-thinking model, which then reasons without end and never writes a
// reply (23k chars / 10min, zero output, killed upstream).
//
// Drives the real thing end to end — a 500ing catalog through
// settings.Resolve — because the defect lived in the seam between the two.
func TestRenderSettings_CatalogOutageKeepsTheBound(t *testing.T) {
	useTempHome(t)
	deadCatalog(t)
	writeJSONConfig(t, map[string]any{
		"agents": map[string]any{"defaults": map[string]any{"thinkingDefault": "high"}},
	})

	s := settings.Resolve(context.Background(),
		settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3"}, "sk-test")
	if _, decided := s.Effort(); decided {
		t.Fatal("test precondition: an outage must leave Effort() undecided")
	}

	cfg := renderInto(t, s)
	if lvl := agentsDefaults(t, cfg)["thinkingDefault"]; lvl != "high" {
		t.Fatalf("thinkingDefault = %v; want the bound to SURVIVE a catalog outage — deleting it is what makes an always-thinking model reason forever", lvl)
	}
}

// The same rule for the model facts: an outage boot must not overwrite
// catalog-sourced limits with name-heuristic guesses (contextWindow 128000
// for a model the catalog calls 1000000, reasoning false for a model that
// always reasons, and the budget guard only ever covered maxTokens). Nothing
// heals those before the next boot, so writing a guess is destructive.
func TestRenderSettings_CatalogOutageKeepsFactsOnDisk(t *testing.T) {
	useTempHome(t)
	deadCatalog(t)
	writeJSONConfig(t, healthyEntry())

	s := settings.Resolve(context.Background(),
		settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3"}, "sk-test")
	if s.Facts.CatalogSourced {
		t.Fatal("test precondition: an outage must yield heuristic facts")
	}

	cfg := renderInto(t, s)
	entry := providerEntry(t, cfg, "openai")
	def := firstModelDef(t, entry)

	if cw, _ := def["contextWindow"].(float64); int(cw) != 1000000 {
		t.Errorf("contextWindow = %v; want the catalog value kept, not the heuristic's 128000", def["contextWindow"])
	}
	if mt, _ := def["maxTokens"].(float64); int(mt) != 131072 {
		t.Errorf("maxTokens = %v; want the catalog budget kept", def["maxTokens"])
	}
	if def["reasoning"] != true {
		t.Errorf("reasoning = %v; want the catalog value kept — an outage saying false disables thinking", def["reasoning"])
	}
	if def["compat"].(map[string]any)["supportsReasoningEffort"] != true {
		t.Errorf("compat.supportsReasoningEffort lost: %v", def["compat"])
	}
	// The WIRING half is still the platform's current decision and must be
	// rewritten: it has to agree with the env var spawn.go exports into.
	if entry["baseUrl"] != inference.ZGOpenAIBaseURL || entry["api"] != "openai-completions" {
		t.Errorf("endpoint wiring not rendered during an outage: %v", entry)
	}
	if entry["apiKey"].(map[string]any)["id"] != "OPENAI_API_KEY" {
		t.Errorf("key env not rendered during an outage: %v", entry["apiKey"])
	}
}

// With no prior entry to carry forward, an unsourced fact is simply absent —
// openclaw applies its own default rather than a number sealed invented and
// left looking hand-set.
func TestRenderSettings_OutageOnFirstBootWritesNoGuessedFacts(t *testing.T) {
	useTempHome(t)
	deadCatalog(t)

	s := settings.Resolve(context.Background(),
		settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3"}, "sk-test")
	cfg := renderInto(t, s)
	def := firstModelDef(t, providerEntry(t, cfg, "openai"))

	for _, k := range []string{"contextWindow", "maxTokens", "reasoning"} {
		if v, present := def[k]; present {
			t.Errorf("%s = %v; want the key absent — the catalog never said, so sealed must not guess on disk", k, v)
		}
	}
	if _, present := def["compat"].(map[string]any)["supportsReasoningEffort"]; present {
		t.Errorf("compat.supportsReasoningEffort must be absent when the catalog is silent: %v", def["compat"])
	}
}

// Carrying facts forward must stay a fixed point: the watcher hashes what
// the render leaves behind, and a carry-over that re-shaped the file on
// every tick would report drift forever.
func TestRenderSettings_OutageRenderIsIdempotent(t *testing.T) {
	useTempHome(t)
	deadCatalog(t)
	writeJSONConfig(t, healthyEntry())

	s := settings.Resolve(context.Background(),
		settings.Doc{Provider: inference.ZGComputeProvider, Model: "glm-5.3"}, "sk-test")
	s.Others = json.RawMessage(`{"logging":{"level":"debug"}}`)

	a := New()
	ctx := context.Background()
	if err := a.RenderSettings(ctx, s); err != nil {
		t.Fatal(err)
	}
	first := readRenderedBytes(t)
	if err := a.RenderSettings(ctx, s); err != nil {
		t.Fatal(err)
	}
	if second := readRenderedBytes(t); second != first {
		t.Errorf("outage render is not a fixed point:\n first  = %s\n second = %s", first, second)
	}
}

// The other direction, which the old tests could not see because they all
// rendered into an EMPTY home: a catalog-sourced render must heal an entry a
// previous outage boot poisoned.
func TestRenderSettings_CatalogSourcedHealsPoisonedEntry(t *testing.T) {
	useTempHome(t)
	writeJSONConfig(t, map[string]any{
		"models": map[string]any{"providers": map[string]any{
			"openai": map[string]any{
				"baseUrl": inference.ZGOpenAIBaseURL,
				"api":     "openai-completions",
				"models": []any{map[string]any{
					"id": "glm-5.3", "name": "glm-5.3",
					"contextWindow": 128000,
					"maxTokens":     inference.HeuristicOpenAIMaxTokens,
					"reasoning":     false,
					"compat":        map[string]any{"supportsReasoningEffort": false},
				}},
			},
		}},
	})

	cfg := renderInto(t, routedSettings(inference.WireOpenAI, "glm-5.3"))
	def := firstModelDef(t, providerEntry(t, cfg, "openai"))

	if mt, _ := def["maxTokens"].(float64); int(mt) != 131072 {
		t.Errorf("maxTokens = %v; want the poisoned 8192 replaced by the catalog budget", def["maxTokens"])
	}
	if cw, _ := def["contextWindow"].(float64); int(cw) != 1000000 {
		t.Errorf("contextWindow = %v; want the catalog value", def["contextWindow"])
	}
	if def["reasoning"] != true {
		t.Errorf("reasoning = %v; want the catalog value", def["reasoning"])
	}
	if def["compat"].(map[string]any)["supportsReasoningEffort"] != true {
		t.Errorf("compat.supportsReasoningEffort = %v; want the catalog value", def["compat"])
	}
	if lvl := agentsDefaults(t, cfg)["thinkingDefault"]; lvl != "high" {
		t.Errorf("thinkingDefault = %v; want the owner's level", lvl)
	}
}

// ── a corrupt config must not be terminal ───────────────────────────────────

// An unparseable openclaw.json used to be fatal AND self-perpetuating: the
// parse error propagated out of RenderSettings, Start refuses to run without
// a successful render, and nothing repaired the file, so the agent stayed
// offline until a container reset. The render owns this file, so it rebuilds
// it.
func TestRenderSettings_CorruptConfigIsRebuiltNotFatal(t *testing.T) {
	useTempHome(t)
	corrupt := []byte(`{"agents": {"defaults": {"model": {"primary": "openai/glm`)
	if err := os.MkdirAll(openclawHome, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(openclawJSONPath(), corrupt, 0o600); err != nil {
		t.Fatal(err)
	}

	a := New()
	if err := a.RenderSettings(context.Background(), routedSettings(inference.WireOpenAI, "glm-5.3")); err != nil {
		t.Fatalf("RenderSettings over a corrupt config must recover, got: %v", err)
	}
	cfg, err := loadOpenclawJSON()
	if err != nil {
		t.Fatalf("rebuilt config does not parse: %v", err)
	}
	if got := primaryPin(t, cfg); got != "openai/glm-5.3" {
		t.Errorf("primary = %q; want the pin rebuilt from the settings document", got)
	}
	// The unreadable bytes are kept, not deleted: they are the only record
	// of whatever edit broke the file.
	kept, err := os.ReadFile(openclawJSONPath() + ".corrupt")
	if err != nil {
		t.Fatalf("corrupt config was not set aside: %v", err)
	}
	if string(kept) != string(corrupt) {
		t.Errorf("set-aside copy = %q; want the original bytes", kept)
	}
	// The gateway subtree lived in the file that was lost, so Start must be
	// told to write it again even on a restart.
	a.mu.RLock()
	rebuilt := a.configRebuilt
	a.mu.RUnlock()
	if !rebuilt {
		t.Error("a rebuild must flag the lost gateway section for Start to re-write")
	}
}

func TestRenderSettings_HealthyConfigIsNotFlaggedAsRebuilt(t *testing.T) {
	useTempHome(t)
	a := New()
	if err := a.RenderSettings(context.Background(), routedSettings(inference.WireOpenAI, "glm-5.3")); err != nil {
		t.Fatal(err)
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.configRebuilt {
		t.Error("a normal render must not claim the config was rebuilt — Start would needlessly rewrite the gateway section")
	}
}

// writeRuntimeSections is what Start re-runs after a rebuild; it must put
// the SAME token back, or /_seal/auth hands owners a credential the gateway
// rejects.
func TestWriteRuntimeSectionsRestoresTheGatewayToken(t *testing.T) {
	useTempHome(t)
	if err := writeRuntimeSections("tok-123"); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadOpenclawJSON()
	if err != nil {
		t.Fatal(err)
	}
	gateway, _ := cfg["gateway"].(map[string]any)
	auth, _ := gateway["auth"].(map[string]any)
	if auth["token"] != "tok-123" {
		t.Errorf("gateway token = %v; want the adapter's cached token", auth["token"])
	}
}

// ── the file is a function of the document ──────────────────────────────────

// setAgentsDefaults(cfg, "model", …) replaced the whole agents.defaults.model
// object, destroying overlay siblings merged one line earlier.
func TestRenderSettings_OverlayModelSiblingsSurviveThePin(t *testing.T) {
	useTempHome(t)
	s := routedSettings(inference.WireOpenAI, "glm-5.3")
	s.Others = json.RawMessage(`{"agents":{"defaults":{"model":{"fallback":"openai/glm-4.5","maxRetries":2}}}}`)

	cfg := renderInto(t, s)
	model, _ := agentsDefaults(t, cfg)["model"].(map[string]any)
	if model["primary"] != "openai/glm-5.3" {
		t.Errorf("primary = %v; the platform still owns it", model["primary"])
	}
	if model["fallback"] != "openai/glm-4.5" {
		t.Errorf("overlay sibling fallback destroyed by the pin: %v", model)
	}
	if mr, _ := model["maxRetries"].(float64); int(mr) != 2 {
		t.Errorf("overlay sibling maxRetries destroyed by the pin: %v", model)
	}
}

// A merge can only add, so a key the owner REMOVES from the overlay used to
// sit on disk forever and the file was not a function of the document.
func TestRenderSettings_OverlayKeyRemovedFromTheDocumentIsDropped(t *testing.T) {
	useTempHome(t)
	s := routedSettings(inference.WireOpenAI, "glm-5.3")
	s.Others = json.RawMessage(`{"logging":{"level":"debug","file":"/tmp/x.log"},"experimental":{"beta":true}}`)
	renderInto(t, s)

	s.Others = json.RawMessage(`{"logging":{"level":"debug"}}`)
	cfg := renderInto(t, s)

	if _, present := cfg["experimental"]; present {
		t.Errorf("a section removed from the document must not persist: %v", cfg["experimental"])
	}
	logging, _ := cfg["logging"].(map[string]any)
	if _, present := logging["file"]; present {
		t.Errorf("a nested key removed from the document must not persist: %v", logging)
	}
	if logging["level"] != "debug" {
		t.Errorf("a key still in the document must stay: %v", logging)
	}
}

// …but only values THIS adapter put there are withdrawn. Anything the agent
// or openclaw itself has changed since is the agent's, and the platform
// reverts its own writes, never the agent's.
func TestRenderSettings_AgentEditOfAFormerOverlayKeySurvives(t *testing.T) {
	useTempHome(t)
	s := routedSettings(inference.WireOpenAI, "glm-5.3")
	s.Others = json.RawMessage(`{"logging":{"level":"debug"}}`)
	renderInto(t, s)

	// The agent edits the same key while running.
	cfg, err := loadOpenclawJSON()
	if err != nil {
		t.Fatal(err)
	}
	cfg["logging"].(map[string]any)["level"] = "trace"
	if err := saveOpenclawJSON(cfg); err != nil {
		t.Fatal(err)
	}

	s.Others = nil
	cfg = renderInto(t, s)
	logging, _ := cfg["logging"].(map[string]any)
	if logging["level"] != "trace" {
		t.Errorf("logging.level = %v; the platform may withdraw its own value, not the agent's edit", logging)
	}
}

// Rendering one wire dialect and then the other used to leave BOTH router
// endpoints declared, with the dead one still selectable.
func TestRenderSettings_StaleRouterProviderIsDropped(t *testing.T) {
	useTempHome(t)
	renderInto(t, routedSettings(inference.WireOpenAI, "glm-5.3"))
	cfg := renderInto(t, routedSettings(inference.WireAnthropic, "claude-sonnet-5"))

	providers := cfg["models"].(map[string]any)["providers"].(map[string]any)
	if _, present := providers["openai"]; present {
		t.Errorf("the previous pin's router entry must be gone: %v", providers)
	}
	if _, present := providers["anthropic"]; !present {
		t.Errorf("the current pin's router entry must be present: %v", providers)
	}
	auth, _ := cfg["auth"].(map[string]any)
	profiles, _ := auth["profiles"].(map[string]any)
	if _, present := profiles["openai:api"]; present {
		t.Errorf("the previous pin's auth profile must go with it: %v", profiles)
	}
	order, _ := auth["order"].(map[string]any)
	if _, present := order["openai"]; present {
		t.Errorf("the previous pin's auth order must go with it: %v", order)
	}
}

// Switching from the router to a framework built-in must leave no router
// entry behind under the built-in's own label — it would override openclaw's
// baseUrl and keep a "native anthropic" pin talking to the router.
func TestRenderSettings_SwitchingToANativeProviderDropsTheRouterEntry(t *testing.T) {
	useTempHome(t)
	renderInto(t, routedSettings(inference.WireAnthropic, "claude-sonnet-5"))

	cfg := renderInto(t, settings.Resolved{
		Doc:   settings.Doc{Provider: "anthropic", Model: "claude-sonnet-5", Thinking: "high"},
		Facts: inference.ModelFacts{SupportsReasoningEffort: true, CatalogSourced: true, MaxTokens: 64000},
	})

	models, _ := cfg["models"].(map[string]any)
	providers, _ := models["providers"].(map[string]any)
	if len(providers) != 0 {
		t.Errorf("a framework built-in must keep openclaw's own endpoint table: %v", providers)
	}
	// Its auth profile is still legitimate — the key still comes from env.
	profiles := cfg["auth"].(map[string]any)["profiles"].(map[string]any)
	if _, present := profiles["anthropic:api"]; !present {
		t.Errorf("the built-in provider still needs its auth profile: %v", profiles)
	}
}

// An owner-declared provider of their own is not router state and must
// survive a pin change.
func TestRenderSettings_OwnerDeclaredProviderIsNotPruned(t *testing.T) {
	useTempHome(t)
	s := routedSettings(inference.WireAnthropic, "claude-sonnet-5")
	s.Others = json.RawMessage(`{"models":{"providers":{"lmstudio":{"baseUrl":"http://127.0.0.1:1234/v1","api":"openai-completions"}}}}`)
	cfg := renderInto(t, s)

	providers := cfg["models"].(map[string]any)["providers"].(map[string]any)
	if _, present := providers["lmstudio"]; !present {
		t.Errorf("owner-declared provider pruned: %v", providers)
	}
}

// ── a document openclaw cannot pin ──────────────────────────────────────────

// Doc.Validate permits a model with no provider. openclaw indexes its config
// BY provider label, so there is nothing to pin it under — and guessing
// would mean this adapter re-deciding a routing question the platform
// already resolved. It must not silently render an empty config over a
// working one.
func TestRenderSettings_ModelWithoutProviderLeavesTheExistingPin(t *testing.T) {
	useTempHome(t)
	renderInto(t, routedSettings(inference.WireOpenAI, "glm-5.3"))

	cfg := renderInto(t, settings.Resolved{Doc: settings.Doc{Model: "glm-5.3"}})

	if got := primaryPin(t, cfg); got != "openai/glm-5.3" {
		t.Errorf("primary = %q; an uninterpretable document must not destroy a working pin", got)
	}
	if lvl := agentsDefaults(t, cfg)["thinkingDefault"]; lvl != "high" {
		t.Errorf("thinkingDefault = %v; the bound must be left alone too", lvl)
	}
	if ms, _ := cfg["diagnostics"].(map[string]any)["stuckSessionAbortMs"].(float64); int(ms) != 900_000 {
		t.Errorf("sealed's own watchdog value is known regardless: %v", cfg["diagnostics"])
	}
}

// ── the inference credential ────────────────────────────────────────────────

// The credential is the one in the resolved settings document, not
// RuntimeContext.APIKey: that field is going away, and dialling a
// platform-routed endpoint with the wrong one produced a live 401.
func TestInferenceCredentialComesFromTheSettingsDocument(t *testing.T) {
	s := routedSettings(inference.WireAnthropic, "claude-sonnet-5")
	s.APIKey = "sk-from-settings"
	env, key := inferenceCredential(s)
	if env != "ANTHROPIC_API_KEY" {
		t.Errorf("env = %q; want the wire format's variable", env)
	}
	if key != "sk-from-settings" {
		t.Errorf("key = %q; want settings.Resolved.APIKey", key)
	}
}

func TestGatewayEnvCarriesTheSettingsCredential(t *testing.T) {
	rt := framework.RuntimeContext{
		APIKey:       "sk-from-runtimecontext",
		PublicURL:    "http://8080-x.example.com",
		SealSignSock: "/run/seal-sign.sock",
		AgentSeal:    "0xSeal",
	}
	env := gatewayEnv("OPENAI_API_KEY", "sk-from-settings", rt)

	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "OPENAI_API_KEY=sk-from-settings") {
		t.Errorf("subprocess env lacks the settings credential: %v", env)
	}
	if strings.Contains(joined, "sk-from-runtimecontext") {
		t.Errorf("subprocess env carries RuntimeContext.APIKey: %v", env)
	}
	// The rest of RuntimeContext is still the source for non-credential
	// values, and the whitelist stays a whitelist.
	if !strings.Contains(joined, "AGENT_PUBLIC_URL=http://8080-x.example.com") ||
		!strings.Contains(joined, "SEAL_SIGN_SOCK=/run/seal-sign.sock") ||
		!strings.Contains(joined, "AGENT_SEAL=0xSeal") {
		t.Errorf("subprocess env lost a runtime value: %v", env)
	}
	for _, e := range env {
		if strings.HasPrefix(e, "SANDBOX_SEAL_KEY=") {
			t.Fatalf("whitelist leaked a sealed secret: %v", env)
		}
	}
}

// An empty credential must not put a bare "VAR=" in the child's env: an
// empty-string key reads as "configured" to a client and turns a clear
// "no key" into a confusing 401.
func TestGatewayEnvOmitsAnEmptyCredential(t *testing.T) {
	env := gatewayEnv("OPENAI_API_KEY", "", framework.RuntimeContext{})
	for _, e := range env {
		if strings.HasPrefix(e, "OPENAI_API_KEY") {
			t.Fatalf("empty credential must not be exported: %v", env)
		}
	}
}
