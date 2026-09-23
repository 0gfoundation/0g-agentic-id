package openclaw

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"

	"seal-verify/internal/framework"
	"seal-verify/internal/inference"
	"seal-verify/internal/logger"
	"seal-verify/internal/settings"
)

// RenderSettings is openclaw's half of the owner's configuration channel:
// it writes the resolved settings document into ~/.openclaw/openclaw.json,
// the only file openclaw reads its configuration from.
//
// This file is NOT chain-tracked any more — it is an artifact re-rendered
// from the owner's document at every Start. Re-rendered, not rewritten: the
// platform-owned keys below are written over whatever is on disk and the
// rest of the file (openclaw's own bookkeeping, the agent's edits) is left
// standing. That is what retires the old
// healOpenclawConfig: the render used to run once, on a fresh agent's very
// first Start, and it rewrote the pin from "0g-compute" to the resolved
// "openai"/"anthropic" form, so the chain-restored config of an existing
// agent was never recognized again and every fix shipped after mint (bounded
// reasoning, catalog budgets, watchdog headroom, the model idle timeout)
// stopped at the mint-time copy. Rendering every boot means a fix reaches
// every agent on its next Start, with no shape-recognition heuristics and
// nothing to leave alone.
//
// Contract (framework.Framework.RenderSettings):
//
//   - Idempotent. The inputs are Resolved, the file already on disk, and the
//     overlay this adapter recorded as applied last time; a second render
//     over the first produces identical bytes.
//   - Platform values win. The owner's opaque overlay goes in FIRST and the
//     platform-owned keys are written over it.
//
// What the platform-owned keys are written FROM is gated, and the gate is
// the same in all three places it appears: a value the platform does not
// actually know is not written, and it does not erase what is already on
// disk either. Resolved.Effort()'s second return distinguishes "this model
// takes no bound" (clear the key) from "the catalog was unreachable" (leave
// the key); Resolved.PersistableMaxTokens() and ModelFacts.CatalogSourced
// draw the same line for the output budget, the context window and the
// reasoning flags. An outage boot must not be able to strip a bound from an
// always-thinking model, nor shrink a 1M context window to a guessed 128k
// that then looks hand-set forever.
//
// The inference credential is never rendered: openclaw takes it by env
// reference (`apiKey: {source: env, id: <VAR>}`), so only the variable NAME
// reaches disk. spawn.go exports the value (settings.Resolved.APIKey) into
// the child's env.
func (a *Adapter) RenderSettings(ctx context.Context, s settings.Resolved) error {
	cfg, rebuilt := loadConfigForRender()

	overlay := frameworkOverlay(s.Framework)
	dropRemovedOverlayKeys(cfg, loadAppliedOverlay(), overlay)
	mergeInto(cfg, overlay)

	applySettingsToConfig(cfg, s)

	if err := saveOpenclawJSON(cfg); err != nil {
		return err
	}
	saveAppliedOverlay(overlay)

	// Start reads the pin from here rather than re-parsing the config file:
	// the file is an output of this function now, not a source of truth.
	a.mu.Lock()
	a.rendered = &s
	if rebuilt {
		a.configRebuilt = true
	}
	a.mu.Unlock()
	level, decided := s.Effort()
	logger.Logf("openclaw: rendered settings provider=%s model=%s thinking=%q(decided=%t) routed=%t catalog=%t",
		s.Provider, s.Model, level, decided, s.Endpoint != nil, s.Facts.CatalogSourced)
	return nil
}

// loadConfigForRender reads openclaw.json for a render, recovering from a
// file that no longer parses.
//
// A corrupt config used to be terminal and self-perpetuating: the parse
// error propagated out of RenderSettings, Start refuses to run without a
// successful render, and nothing on the next boot repaired the file — the
// agent stayed offline until someone reset the container. The old
// chain-tracked openclaw.json role repaired exactly this by rewriting the
// file wholesale from chain on every boot; now that the render owns the
// file, the render owns the repair too.
//
// The unreadable bytes are set aside rather than deleted (one fixed name —
// a per-boot suffix would pile up), so an owner or the agent can still look
// at whatever hand edit broke it.
//
// Returns rebuilt=true when the previous contents were lost. Start uses
// that to re-write the gateway subtree, which lives in this same file and
// carries the auth token minted for this boot.
func loadConfigForRender() (cfg map[string]any, rebuilt bool) {
	cfg, err := loadOpenclawJSON()
	if err == nil {
		return cfg, false
	}
	quarantine := openclawJSONPath() + ".corrupt"
	if rerr := os.Rename(openclawJSONPath(), quarantine); rerr != nil {
		logger.Logf("openclaw: %s is unusable (%v) and could not be set aside (%v); rebuilding it from the owner's settings", openclawJSONPath(), err, rerr)
	} else {
		logger.Logf("openclaw: %s is unusable (%v); moved to %s and rebuilding it from the owner's settings", openclawJSONPath(), err, quarantine)
	}
	return map[string]any{}, true
}

// ── the owner's opaque framework overlay ────────────────────────────────────

// frameworkOverlay decodes the owner's opaque per-framework section into
// the openclaw config shape. It is not interpreted: whatever object the
// owner put under `framework` is deep-merged into the top level of
// openclaw.json, and the platform keys written afterwards outrank it.
//
// One key cannot be protected by ordering and is therefore dropped:
// `gateway` carries a per-boot credential written by spawn.go
// (writeRuntimeSections) at first Start only, so a later render that
// merged an owner-supplied `gateway` would overwrite the live auth token
// instead of being overwritten by it.
func frameworkOverlay(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var overlay map[string]any
	if err := json.Unmarshal(raw, &overlay); err != nil {
		logger.Logf("openclaw: settings.framework overlay ignored (not a JSON object): %v", err)
		return nil
	}
	if _, present := overlay["gateway"]; present {
		logger.Logf("openclaw: settings.framework overlay dropped key \"gateway\" (per-boot runtime state, platform-written)")
		delete(overlay, "gateway")
	}
	return overlay
}

// mergeInto deep-merges src into dst: nested objects merge key by key,
// every other value replaces. A shallow merge would make an overlay
// touching one key under `agents` drop the whole rest of the section.
//
// A merge can only ADD, which is why dropRemovedOverlayKeys runs first.
//
// Values are DEEP-COPIED in, never aliased. Aliasing was a real defect: the
// overlay's nested maps ended up shared with cfg, applySettingsToConfig then
// wrote the platform's own keys through those shared maps, and the overlay
// recorded by saveAppliedOverlay therefore claimed to have supplied them. On
// the next boot dropRemovedOverlayKeys read that record, saw keys the new
// overlay no longer carried, and withdrew the platform's own values —
// including the reasoning bound, which is the failure the whole tri-state
// Effort() exists to prevent.
func mergeInto(dst, src map[string]any) {
	for k, v := range src {
		if sub, ok := v.(map[string]any); ok {
			if cur, ok := dst[k].(map[string]any); ok {
				mergeInto(cur, sub)
				continue
			}
		}
		dst[k] = deepCopyJSON(v)
	}
}

// deepCopyJSON copies a decoded-JSON value so the copy shares no map or
// slice with the original.
func deepCopyJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			out[k] = deepCopyJSON(vv)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, vv := range t {
			out[i] = deepCopyJSON(vv)
		}
		return out
	default:
		return v
	}
}

// appliedOverlayPath records the overlay the last render merged — the
// "last applied configuration" trick, kept in a sidecar because
// openclaw.json is openclaw's own schema and an unknown top-level key
// there is not ours to add. Not chain-tracked (nothing under
// ~/.openclaw outside workspace/ is), so it dies with the container
// exactly like the config it describes.
func appliedOverlayPath() string { return openclawHome + "/.sealed-overlay.json" }

func loadAppliedOverlay() map[string]any {
	b, err := os.ReadFile(appliedOverlayPath())
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		logger.Logf("openclaw: applied-overlay record %s did not parse (%v); an overlay key removed from the settings document this boot may linger in openclaw.json", appliedOverlayPath(), err)
		return nil
	}
	return m
}

func saveAppliedOverlay(overlay map[string]any) {
	if len(overlay) == 0 {
		if err := os.Remove(appliedOverlayPath()); err != nil && !os.IsNotExist(err) {
			logger.Logf("openclaw: could not clear applied-overlay record: %v", err)
		}
		return
	}
	b, err := json.MarshalIndent(overlay, "", "  ")
	if err != nil {
		logger.Logf("openclaw: could not encode applied-overlay record: %v", err)
		return
	}
	if err := os.WriteFile(appliedOverlayPath(), b, 0o600); err != nil {
		logger.Logf("openclaw: could not write applied-overlay record: %v", err)
	}
}

// dropRemovedOverlayKeys makes openclaw.json a function of the settings
// document instead of an accumulation of every document ever pushed: a key
// the owner DELETES from the overlay is removed from disk, where a merge
// alone would leave it there forever.
//
// Only a value this adapter actually put there is removed — the current
// value must still deep-equal what the recorded overlay set. Anything the
// agent or openclaw itself has changed since is left alone: the platform
// reverts its own writes, never the agent's.
func dropRemovedOverlayKeys(cfg, prev, next map[string]any) {
	for k, prevVal := range prev {
		curVal, onDisk := cfg[k]
		if !onDisk {
			continue
		}
		prevMap, prevIsMap := prevVal.(map[string]any)
		curMap, curIsMap := curVal.(map[string]any)

		if nextVal, still := next[k]; still {
			// Still in the document: recurse so a removed NESTED key is
			// dropped even though its parent object survives.
			if nextMap, nextIsMap := nextVal.(map[string]any); prevIsMap && curIsMap && nextIsMap {
				dropRemovedOverlayKeys(curMap, prevMap, nextMap)
			}
			continue
		}
		if prevIsMap && curIsMap {
			dropRemovedOverlayKeys(curMap, prevMap, nil)
			if len(curMap) == 0 {
				delete(cfg, k)
			}
			continue
		}
		if reflect.DeepEqual(prevVal, curVal) {
			delete(cfg, k)
		}
	}
}

// ── platform-owned keys ─────────────────────────────────────────────────────

// applySettingsToConfig writes the platform-owned keys. They are gated
// differently, which is why they are written separately:
//
//   - the pin and its auth profile apply to every provider the document
//     gives openclaw a label for — and to nothing else (see the no-provider
//     case below);
//   - the reasoning bound and the stuck-session watchdog apply to every
//     provider too — they are properties of the MODEL and of sealed's own
//     supervision, not of who serves the request;
//   - only the endpoint wiring (base URL, wire dialect, compat flags, key
//     env name, idle timeout) is gated on the platform actually routing
//     this model. A framework built-in brings its own.
//
// It also withdraws what a previous pin left behind, so the provider table
// reflects the current document rather than every document ever pushed.
func applySettingsToConfig(cfg map[string]any, s settings.Resolved) {
	clawProvider := clawProviderName(s)

	// A previous render's router provider entry for a pin no longer in
	// force is dead weight that can still be selected; drop it before
	// writing this pin's.
	//
	// Pruning requires KNOWING the new routing. Endpoint != nil means the
	// platform routes this model and every other router entry is stale;
	// Endpoint == nil with a provider named means a framework built-in, and a
	// leftover router entry would shadow openclaw's own baseUrl for it. But
	// Endpoint == nil with NO provider means the document told us nothing —
	// the render leaves the existing pin alone in that case, so pruning the
	// provider entry that pin depends on would dismantle exactly the
	// configuration this branch is trying to preserve.
	if s.Provider != "" {
		keep := ""
		if s.Endpoint != nil {
			keep = clawProvider
		}
		pruneStaleRouterProviders(cfg, keep)
	}

	switch {
	case clawProvider != "" && s.Model != "":
		setModelPrimary(cfg, clawProvider+"/"+s.Model)
		applyAuthProfile(cfg, clawProvider)
	case s.Model != "":
		// Doc.Validate permits a model with no provider (a blank model is
		// the only fatal case there), and openclaw cannot use one: its
		// config indexes models BY provider label, so there is no pin to
		// write, no auth profile to point at and no key env to name.
		//
		// Guessing a provider here would mean this adapter re-deciding a
		// routing question the platform already resolved (Endpoint is nil
		// precisely because settings.Resolve found no platform route), so
		// instead: say so loudly and leave whatever pin is already on disk
		// in place. Same rule as the bound — an input we cannot interpret
		// does not get to destroy a working one. Start warns again, and
		// the agent stays reachable so the owner can push a fix.
		logger.Logf("warn: openclaw: settings pin model %q with no provider; openclaw has no provider label to file it under, so no pin/auth/key-env was rendered (set `provider`, e.g. %q, and push settings again)", s.Model, inference.ZGComputeProvider)
	}

	// Always-thinking models (glm-5.3) reason WITHOUT BOUND unless the
	// request carries reasoning_effort: 23k chars / 10min of reasoning, zero
	// reply, stream killed upstream — measured live; effort=low returns a
	// full reply in ~2.5min. thinkingDefault is the level openclaw applies
	// when no /think directive is present.
	//
	// Resolved.Effort() already folds in the owner's choice, the normalizing
	// onto levels the wire accepts, and the "thinking model, no preference →
	// low floor" rule. It is deliberately NOT gated on s.Endpoint: a native
	// provider serving a thinking model needs the bound just as much, and
	// hanging it off the provider check is how two other adapters silently
	// dropped it.
	//
	// Its three outcomes must stay three here. A decided empty level means
	// this model takes no bound and the key must be ABSENT — sending
	// reasoning_effort to a model that rejects it is a hard 400, and a value
	// left over from a previous model pin would do exactly that. An
	// UNDECIDED empty level means the catalog was unreachable: deleting the
	// key on that basis is what an adversarial review reproduced, an outage
	// boot stripping the bound off an always-thinking model, which then
	// reasons forever and never replies. This key is platform-owned; an
	// owner who wants a different level sets `thinking` in the settings
	// document.
	switch level, decided := s.Effort(); {
	case level != "":
		_ = setAgentsDefaults(cfg, "thinkingDefault", json.RawMessage(mustMarshal(level)))
	case decided:
		_ = setAgentsDefaults(cfg, "thinkingDefault", nil)
	default:
		logger.Logf("openclaw: catalog silent on %q; leaving agents.defaults.thinkingDefault as it stands", s.Model)
	}

	// Stuck-session watchdog headroom. openclaw's default (360s = warn 120s
	// × 3) is tuned for fast models; a thinking model legitimately shows no
	// "progress" for minutes — live, a PR-review run was killed at 446s as
	// stalled_agent_run and the owner saw "internal error". 900s must stay
	// ABOVE the provider idle timeout below (600s) so a single silent model
	// call dies to that timeout first and 600–900s only ever catches a real
	// deadlock. Deliberate stops don't depend on it (Esc / cancel).
	//
	// Not gated on routing: a native-provider thinking model stalls the same
	// way, and the value is coupled to the timeout the platform writes, not
	// to who serves the model. Not gated on the catalog either: it is
	// sealed's own number, known whether or not the router answers.
	diagnostics, _ := cfg["diagnostics"].(map[string]any)
	if diagnostics == nil {
		diagnostics = map[string]any{}
	}
	diagnostics["stuckSessionAbortMs"] = 900_000
	cfg["diagnostics"] = diagnostics

	if s.Endpoint != nil {
		applyEndpointToConfig(cfg, clawProvider, s)
	}
}

// clawProviderName is the provider LABEL openclaw indexes its config by.
//
// For a platform-routed model that is the wire dialect, not the owner's
// "0g-compute": openclaw has no such built-in provider, so sealed declares
// the router as an "openai"/"anthropic" provider pointing at the router's
// base URL. For a framework built-in the owner's own name is the label.
func clawProviderName(s settings.Resolved) string {
	if s.Endpoint == nil {
		return s.Provider
	}
	if s.Endpoint.Format == inference.WireAnthropic {
		return "anthropic"
	}
	return "openai"
}

// setModelPrimary writes agents.defaults.model.primary WITHOUT replacing
// the whole `model` object. The owner's overlay is merged one step earlier
// and may carry siblings there (fallbacks, per-agent overrides); assigning
// a fresh {"primary": …} object over it deleted every one of them.
func setModelPrimary(cfg map[string]any, pin string) {
	agents, ok := cfg["agents"].(map[string]any)
	if !ok {
		agents = map[string]any{}
		cfg["agents"] = agents
	}
	defaults, ok := agents["defaults"].(map[string]any)
	if !ok {
		defaults = map[string]any{}
		agents["defaults"] = defaults
	}
	model, ok := defaults["model"].(map[string]any)
	if !ok {
		model = map[string]any{}
		defaults["model"] = model
	}
	model["primary"] = pin
}

// applyAuthProfile points openclaw at an api_key credential for the pinned
// provider (auth.profiles[<p>:api] + auth.order[<p>]). Same shape for a
// routed and a built-in provider — only the label differs; the key itself
// is read from the environment either way.
func applyAuthProfile(cfg map[string]any, clawProvider string) {
	authBlock, _ := cfg["auth"].(map[string]any)
	if authBlock == nil {
		authBlock = map[string]any{}
	}
	profiles, _ := authBlock["profiles"].(map[string]any)
	if profiles == nil {
		profiles = map[string]any{}
	}
	profiles[clawProvider+":api"] = map[string]any{
		"provider": clawProvider,
		"mode":     "api_key",
	}
	authBlock["profiles"] = profiles
	order, _ := authBlock["order"].(map[string]any)
	if order == nil {
		order = map[string]any{}
	}
	order[clawProvider] = []any{clawProvider + ":api"}
	authBlock["order"] = order
	cfg["auth"] = authBlock
}

// pruneStaleRouterProviders removes models.providers entries a PREVIOUS
// render declared for the 0g router under a label the current pin no
// longer uses, together with the auth profile that render wrote for them.
//
// Without this the file accumulates: rendering glm-5.3 (openai wire) and
// then claude-sonnet-5 (anthropic wire) leaves BOTH endpoints declared,
// and the dead one stays selectable by anything that reads the provider
// table. Switching from the router to a framework built-in leaves a router
// entry that overrides openclaw's own baseUrl for that provider — a
// built-in "anthropic" pin silently still talking to the router.
//
// Only entries pointing at a 0g router base URL are touched, and only auth
// profiles in the exact two-key shape applyAuthProfile writes, so an
// owner-declared provider of their own is never collateral.
func pruneStaleRouterProviders(cfg map[string]any, keep string) {
	models, _ := cfg["models"].(map[string]any)
	providers, _ := models["providers"].(map[string]any)
	for label, v := range providers {
		if label == keep {
			continue
		}
		entry, ok := v.(map[string]any)
		if !ok {
			continue
		}
		switch baseURL, _ := entry["baseUrl"].(string); baseURL {
		case inference.ZGOpenAIBaseURL, inference.ZGAnthropicBaseURL:
		default:
			continue
		}
		delete(providers, label)
		dropPlatformAuthProfile(cfg, label)
		logger.Logf("openclaw: dropped stale 0g-router provider entry %q (no longer the pinned route)", label)
	}
}

// dropPlatformAuthProfile removes the auth profile + order entry
// applyAuthProfile wrote for a label, and only if they still have exactly
// that shape — an owner who hand-shaped a profile for the same label keeps
// it.
func dropPlatformAuthProfile(cfg map[string]any, label string) {
	authBlock, _ := cfg["auth"].(map[string]any)
	profiles, _ := authBlock["profiles"].(map[string]any)
	if p, ok := profiles[label+":api"].(map[string]any); ok {
		if len(p) == 2 && p["provider"] == label && p["mode"] == "api_key" {
			delete(profiles, label+":api")
		}
	}
	order, _ := authBlock["order"].(map[string]any)
	if ord, ok := order[label].([]any); ok {
		if len(ord) == 1 && ord[0] == label+":api" {
			delete(order, label)
		}
	}
}

// applyEndpointToConfig declares the platform-routed endpoint as an
// openclaw model provider. Authoritative shape per openclaw's plugin-sdk
// type defs (ModelProviderConfig + ModelDefinitionConfig).
//
// The wire format decides the dialect:
//   - OpenAI wire: provider "openai", api "openai-completions".
//     compat.requiresStringContent is critical — 0G rejects OpenAI's
//     multimodal array form ({type:"text",...}) so content must serialise
//     as a plain string.
//   - Anthropic wire: provider "anthropic", api "anthropic-messages"
//     (claude-* on the router are served on that endpoint ONLY — hardcoding
//     the OpenAI format here is exactly what 400'd live: "model
//     'claude-sonnet-5' is not available on the openai API format"). No
//     compat block — the anthropic client path speaks string content
//     natively.
//
// The WIRING half (baseUrl, api, key env, idle timeout) is rewritten
// unconditionally: it is the platform's current routing decision, it must
// agree with the env var spawn.go exports the key into, and a stale dialect
// here is what 400s at first inference.
//
// The MODEL-FACTS half (contextWindow, maxTokens, reasoning, the
// reasoning-effort compat flag) is written only when the catalog sourced
// it. On a catalog outage those values are name-heuristic guesses —
// contextWindow 128000 for a model the catalog calls 1000000, reasoning
// false for a model that always reasons — and overwriting good values with
// them is destructive in exactly the way Resolved.PersistableMaxTokens was
// introduced to prevent, with nothing to heal it before the next boot. So
// an unsourced render carries the previous entry's facts forward, and omits
// what has never been known: openclaw then applies its own defaults rather
// than a number sealed invented and left looking hand-set.
func applyEndpointToConfig(cfg map[string]any, clawProvider string, s settings.Resolved) {
	api := "openai-completions"
	if s.Endpoint.Format == inference.WireAnthropic {
		api = "anthropic-messages"
	}

	prev := existingModelDef(cfg, clawProvider, s.Model)

	modelDef := map[string]any{
		"id":    s.Model,
		"name":  s.Model,
		"input": []string{"text"},
		"cost":  map[string]any{"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
	}
	compat := map[string]any{
		"requiresStringContent":    true,
		"supportsStore":            false,
		"supportsDeveloperRole":    false,
		"supportsUsageInStreaming": false,
		"supportsStrictMode":       false,
		"maxTokensField":           "max_tokens",
	}

	if s.Facts.CatalogSourced {
		modelDef["contextWindow"] = s.Facts.ContextWindow
		modelDef["reasoning"] = s.Facts.SupportsReasoningEffort
		compat["supportsReasoningEffort"] = s.Facts.SupportsReasoningEffort
		// Output budget: only a CATALOG-sourced value may be written to disk
		// (Resolved.PersistableMaxTokens enforces it). During an outage the
		// heuristic's 8192 would — with reasoning and the reply SHARING the
		// budget — permanently starve replies. With the field absent openclaw
		// sends no max_tokens at all and the model's own ceiling applies.
		if mt := s.PersistableMaxTokens(); mt > 0 {
			modelDef["maxTokens"] = mt
		}
	} else {
		carryOver(prev, modelDef, "contextWindow", "maxTokens", "reasoning")
		prevCompat, _ := prev["compat"].(map[string]any)
		carryOver(prevCompat, compat, "supportsReasoningEffort")
		logger.Logf("openclaw: catalog silent on %q; keeping the model facts already on disk rather than writing heuristic ones", s.Model)
	}

	if s.Endpoint.Format == inference.WireOpenAI {
		modelDef["compat"] = compat
	}

	providerEntry := map[string]any{
		"baseUrl": s.Endpoint.BaseURL,
		"api":     api,
		// Model idle timeout. openclaw's default gives up long before a
		// reasoning model's silent thinking phase ends (glm on the 0g router
		// measures ~150s to the first token on complex prompts), killing every
		// long-horizon task with "model did not produce a response before the
		// model idle timeout". 600 matches agents.defaults.timeoutSeconds's
		// own default — the run ceiling openclaw enforces anyway.
		"timeoutSeconds": 600,
		"apiKey": map[string]any{
			"source":   "env",
			"provider": "default",
			"id":       s.Endpoint.EnvKey,
		},
		"models": []any{modelDef},
	}

	models, _ := cfg["models"].(map[string]any)
	if models == nil {
		models = map[string]any{}
	}
	providers, _ := models["providers"].(map[string]any)
	if providers == nil {
		providers = map[string]any{}
	}
	providers[clawProvider] = providerEntry
	models["providers"] = providers
	cfg["models"] = models
}

// existingModelDef finds the model definition a previous render left for
// this provider/model, or nil. Read-only: the render builds a fresh entry
// and carries values over deliberately, so a key the current render knows
// about can never be inherited by accident.
func existingModelDef(cfg map[string]any, clawProvider, model string) map[string]any {
	models, _ := cfg["models"].(map[string]any)
	providers, _ := models["providers"].(map[string]any)
	entry, _ := providers[clawProvider].(map[string]any)
	defs, _ := entry["models"].([]any)
	for _, d := range defs {
		def, ok := d.(map[string]any)
		if ok && def["id"] == model {
			return def
		}
	}
	return nil
}

// carryOver copies keys that exist in src into dst. A nil src (nothing on
// disk yet) copies nothing, which leaves the key absent — the honest state
// for a fact nobody has ever known.
func carryOver(src, dst map[string]any, keys ...string) {
	for _, k := range keys {
		if v, ok := src[k]; ok && v != nil {
			dst[k] = v
		}
	}
}

// isZGComputeRouted reports whether the platform, rather than openclaw's
// own provider table, supplies the endpoint for this provider. spawn.go
// uses it to populate RuntimeSnapshot.ZGComputeRouted for the agent's
// runtime context.
func isZGComputeRouted(provider string) bool {
	return provider == inference.ZGComputeProvider
}

// ── the retired openclaw.json role ──────────────────────────────────────────

// legacyConfigRole is the chain role that used to carry openclaw.json: the
// config file filtered to the three top-level keys this adapter owned
// (agents, auth, models), as canonical JSON. It is no longer in Roles(), so
// bootstrap hands whatever the chain still carries under that name to
// HandleLegacy — once, before the watcher's first tick rebuilds the entry list
// from Roles() and commits it wholesale without this entry.
//
// That drop is correct and is not worked around here: the pin's home is the
// owner's settings document now, and the platform persists what this recovery
// hands back (report.SeedSettings) before the entry goes. What only this
// package can do is READ the old entry — openclaw's config schema is this
// adapter's dialect and nobody else's — which is why the branch exists. A lost
// pin does not take openclaw offline the way it does prime (Start only warns),
// it produces something worse to diagnose: an agent that comes up healthy,
// reports running, and fails the owner's first message with no model.
//
// Transitional by construction. Once no live agent still carries this role,
// everything below this line — the branch in HandleLegacy, the stash, the
// LegacySettingsSeeder implementation — is deletable in one piece.
const legacyConfigRole = "openclaw.json"

// legacyThinkingOff is openclaw's "reasoning disabled" level, and
// legacyThinkingFloor is the nearest thing the settings vocabulary offers.
// See legacyThinking for why the recovery maps one onto the other instead of
// dropping it.
const (
	legacyThinkingOff   = "off"
	legacyThinkingFloor = "low"
)

// legacySource ranks the retired chain roles a pin can be recovered from.
// Higher wins. The rank exists because bootstrap's Phase C walks the chain
// entries in whatever order they arrived (main.go), so "whichever branch ran
// last" is a coin flip, not a rule — and two branches can now stash.
//
// THE RETIRED CONFIG ROLE OUTRANKS THE MINT-TIME PERSONA SEED.
//
// Start honest about the input: the two entries CANNOT coexist on a real
// chain. The drift commit that first writes the config role rebuilds the
// iData array from Roles() wholesale in the same transaction, and persona is
// not in it — so an agent carries the config entry or the mint seed, never
// both. Every real agent recovers from its single source whichever way this
// rank points; the rank arbitrates only a hand-assembled or half-migrated
// chain, where a deterministic answer beats a coin flip.
//
// For that residual case, do NOT justify the direction by "the config pin is
// what the agent was dialing" — it is not: the old ingestPersona wrote the
// seed's pin over the restored config on every Phase C pass
// (applyInferenceToConfig sets agents.defaults.model unconditionally), so on
// a both-present chain the OLD boots dialed the seed's pin. The config entry
// wins on two grounds that survive that fact:
//
//   - It can carry a LEVEL: thinkingDefault sits in the tracked `agents`
//     subtree, and persona has no such field. Letting persona win would
//     silently drop a reasoning bound the owner chose.
//   - It costs no provider fidelity: the one field persona states more
//     faithfully — the provider as the OWNER picked it ("0g-compute"), where
//     the config copy carries the augmentation's resolved label — is already
//     recovered from the config entry, because ownerProvider() un-resolves
//     that label from the router baseUrl sealed itself wrote beside the pin.
//
// (hermes ranks the same pair the other way, on the dialing argument above —
// equally untestable against real chains, for the same reason. The tests pin
// each adapter's direction so neither drifts by accident.)
type legacySource int

const (
	sourceNone legacySource = iota
	sourcePersona
	sourceConfig
)

// stashSeededPin records doc as what SeededSettings reports, unless a
// higher-ranked source already stashed one. Reports whether it took.
//
// Equal rank overwrites, so re-running the same branch on a later boot that
// still finds the chain entry recovers the same document — HandleLegacy's
// idempotence rule — rather than depending on a first-write-wins accident.
func (a *Adapter) stashSeededPin(src legacySource, doc settings.Doc) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.seededFrom != sourceNone && a.seededFrom > src {
		return false
	}
	a.seededPin = &doc
	a.seededFrom = src
	return true
}

// handleLegacyConfig recovers the pin out of the retired role's plaintext and
// stashes it for SeededSettings.
//
// Never an error, whatever the entry holds: a legacy config this adapter
// version cannot read must not stop a boot — it leaves the agent on whatever
// document attestor already holds, which is the state it would have been in
// without this migration at all.
//
// Idempotent and side-effect-free apart from the stash. Nothing is written to
// disk — least of all openclaw.json, which RenderSettings owns now and
// rebuilds from the owner's document every Start — so a later boot that still
// finds the chain entry recovers the same document again.
func (a *Adapter) handleLegacyConfig(plaintext []byte) error {
	doc, ok := legacyPin(plaintext)
	if !ok {
		logger.Logf("openclaw.HandleLegacy[%s]: no usable pin in the legacy entry (%d bytes); nothing to recover",
			legacyConfigRole, len(plaintext))
		return nil
	}

	// Top of the rank (legacySource): this wins over a mint seed recovered by
	// the persona branch, whichever of the two Phase C reached first.
	a.stashSeededPin(sourceConfig, doc)

	logger.Logf("openclaw.HandleLegacy[%s]: recovered pin provider=%s model=%s thinking=%q from the retired role; the platform will persist it as the owner's settings document",
		legacyConfigRole, doc.Provider, doc.Model, doc.Thinking)
	return nil
}

// SeededSettings implements framework.LegacySettingsSeeder: hand the recovered
// document to the platform, which persists it to attestor and renders from it.
// Only consulted when the stored document names no model, so a real document
// always outranks this one — this reports what was found, it does not decide
// what wins.
func (a *Adapter) SeededSettings() (settings.Doc, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.seededPin == nil {
		return settings.Doc{}, false
	}
	return *a.seededPin, true
}

// Transitional, like the rest of this section (see legacyConfigRole): the
// assertion goes when the implementation does.
var _ framework.LegacySettingsSeeder = (*Adapter)(nil)

// legacyPin digs an owner settings document out of the retired role's
// plaintext. A blank entry, a parse failure, or a config carrying no usable
// pin is "nothing to recover", reported by ok=false and never by an error.
//
// What comes back MUST pass settings.Doc.Validate: the platform persists it as
// the owner's document and renders from it on every boot afterwards, so a
// document that fails validation is the same outage this migration exists to
// prevent, only now written down. Two things keep that true — a document is
// returned only with a non-empty model, and the level is either absent or one
// settings.Levels offers.
func legacyPin(plaintext []byte) (settings.Doc, bool) {
	if len(strings.TrimSpace(string(plaintext))) == 0 {
		return settings.Doc{}, false
	}
	var cfg map[string]any
	if err := json.Unmarshal(plaintext, &cfg); err != nil {
		logger.Logf("openclaw.HandleLegacy[%s]: WARN parse failed (%v); nothing recovered",
			legacyConfigRole, err)
		return settings.Doc{}, false
	}

	agents, _ := cfg["agents"].(map[string]any)
	defaults, _ := agents["defaults"].(map[string]any)
	modelSection, _ := defaults["model"].(map[string]any)
	primary, _ := modelSection["primary"].(string)

	// The split the deleted pin reader used, unchanged: everything before the
	// FIRST slash is the provider label, everything after is the model id —
	// which may itself contain slashes ("anthropic/claude-3-5-sonnet-latest").
	label, model, _ := strings.Cut(primary, "/")
	if label == "" || model == "" {
		// A pin openclaw itself could not have used: no label to file the
		// model under, or no model. Reporting half of it would have the
		// platform persist a document that pins nothing, and a stored document
		// is consulted BEFORE this recovery on every later boot — so the half
		// answer would also be the last one.
		return settings.Doc{}, false
	}

	return settings.Doc{
		Provider: ownerProvider(cfg, label),
		Model:    model,
		Thinking: legacyThinking(defaults),
	}, true
}

// ownerProvider maps the config's provider LABEL back onto the provider the
// OWNER chose. For a platform-routed agent those are not the same string.
//
// Any agent that ever reached its first drift commit has the RESOLVED label on
// chain: the augmentation rewrote "0g-compute/glm-5.3" into "openai/glm-5.3"
// (and a claude pin into "anthropic/…") before the config was ever uploaded.
// Recovering that label verbatim would re-file the pin as a framework
// BUILT-IN — settings.Resolve returns no Endpoint for it, so the next render
// points openclaw at its own api.openai.com entry while spawn hands it a 0g
// router key, and pruneStaleRouterProviders deletes the router entry on the
// way past. Every request 401s, on an agent that was working before the
// upgrade.
//
// The evidence that tells the two apart was written alongside the pin: a
// models.providers entry under that exact label whose baseUrl is one of the 0g
// router's. Only sealed writes those, so a label pointing at one means the
// PLATFORM supplied the endpoint and the owner's provider was "0g-compute".
// Anything else — a label with no provider entry at all, or one pointing
// somewhere else — is a genuine built-in and keeps its own name.
//
// The auth block is deliberately not consulted, even though the mint-time
// write usually left an auth.order["0g-compute"] behind next to the
// augmentation's own entry: auth is the set of credentials that accumulated
// over the agent's life, not a statement of which route was in force.
func ownerProvider(cfg map[string]any, label string) string {
	models, _ := cfg["models"].(map[string]any)
	providers, _ := models["providers"].(map[string]any)
	entry, _ := providers[label].(map[string]any)
	switch baseURL, _ := entry["baseUrl"].(string); baseURL {
	case inference.ZGOpenAIBaseURL, inference.ZGAnthropicBaseURL:
		return inference.ZGComputeProvider
	}
	return label
}

// legacyThinking recovers agents.defaults.thinkingDefault when it names a
// level the settings vocabulary offers, and "" otherwise.
//
// openclaw is the one adapter whose retired role can carry a level at all —
// the key sat inside the tracked `agents` subtree — so an owner who chose
// "high" or "max" keeps it instead of being quietly returned to the platform's
// floor. A value outside settings.Levels is left UNSET rather than mapped onto
// the nearest one: openclaw has levels of its own and the agent may have
// written one, and an invented level is a configuration the owner never chose.
// Effort() derives a sound bound for an unset level anyway.
//
// A recovered level may equally have been the PLATFORM's own floor rather than
// a choice — the old writer set "low" whenever the catalog called the model
// reasoning-capable and the key was absent. Carrying that forward as a stated
// preference is deliberate: it is a level this platform would re-derive for
// the same model, and the one boot where stated and derived differ is a
// catalog outage — where a stated level keeps Effort() decided, and the
// difference is a bound applied instead of an always-thinking model left to
// reason without end.
//
// "off" is the ONE value outside settings.Levels that is not left unset. It
// is not an invented level, it is openclaw's word for the floor of a scale
// this platform starts at "low" — and the alternative is measurably worse
// during a catalog outage. See the branch below.
func legacyThinking(defaults map[string]any) string {
	raw, _ := defaults["thinkingDefault"].(string)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.EqualFold(raw, legacyThinkingOff) {
		// "off" is openclaw's way of saying DON'T REASON, and the settings
		// vocabulary has no word for it (settings.Levels is low/high/max).
		// Faithful here is the FLOOR, not silence.
		//
		// The level cannot be preserved either way: RenderSettings owns
		// agents.defaults.thinkingDefault now and rewrites it from Effort()
		// on the very next Start, so an on-disk "off" is overwritten by the
		// derived floor whatever this function returns. The only thing in
		// question is whether the owner's DOCUMENT says "low" or says
		// nothing — and on a boot where the catalog is silent, saying
		// nothing leaves Effort() undecided, which leaves an always-thinking
		// model with no bound at all. Recording the floor is therefore never
		// more reasoning than dropping the key, and sometimes strictly less.
		//
		// It is still not "off". This platform cannot express "off"; the day
		// settings.Levels can, this mapping is the one line that changes.
		// Logged rather than silent, so "the owner had reasoning turned off
		// and the agent is reasoning" has an answer in the boot log.
		logger.Logf("openclaw.HandleLegacy[%s]: thinkingDefault %q has no equivalent in %v, so the pin is recovered at the floor (%q) — the least reasoning this platform can state; the render would derive that floor anyway, and stating it keeps the bound in force when the catalog is unreachable",
			legacyConfigRole, raw, settings.Levels, legacyThinkingFloor)
		return legacyThinkingFloor
	}
	for _, level := range settings.Levels {
		if strings.EqualFold(raw, level) {
			return level
		}
	}
	logger.Logf("openclaw.HandleLegacy[%s]: thinkingDefault %q is not one of %v; recovering the pin without a level",
		legacyConfigRole, raw, settings.Levels)
	return ""
}

// ── overlay acceptance ────────────────────────────────────────────────────────

// validateOpenclawConfig asks openclaw itself whether the on-disk config is
// acceptable. A func var so tests can stand in for the CLI; production runs
// `openclaw config validate`, which is the same judgment the gateway applies
// at startup — the platform deliberately holds no copy of that schema.
var validateOpenclawConfig = func() error {
	out, err := exec.Command("openclaw", "config", "validate").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ensureConfigAcceptable makes the rendered config one openclaw will run.
//
// The platform half is always written; the OWNER's opaque overlay is applied
// on trust and checked here against openclaw's own validator, because openclaw
// rejects unknown keys at the root and a rejected config takes the whole agent
// offline (live: agent 411). If the file is rejected and an overlay is in
// force, the overlay is withdrawn (a re-render with an empty Framework section
// — dropRemovedOverlayKeys reverts exactly the keys the previous render's
// sidecar attributes to the overlay, and never an agent edit) and the result
// is validated once more. A failure with NO overlay in play is the platform's
// own bug and fails the start loudly rather than shipping a config openclaw
// already said it will not run.
func (a *Adapter) ensureConfigAcceptable(ctx context.Context) error {
	firstErr := validateOpenclawConfig()
	if firstErr == nil {
		return nil
	}

	a.mu.RLock()
	rendered := a.rendered
	a.mu.RUnlock()
	if rendered == nil || len(bytes.TrimSpace(rendered.Framework)) == 0 {
		return fmt.Errorf("openclaw rejects the rendered config and no owner overlay is in force — platform bug, not booting on it: %w", firstErr)
	}

	logger.Logf("WARN openclaw rejected the rendered config (%v); withdrawing the owner's framework overlay and booting on the platform half — fix the overlay via the settings channel", firstErr)
	stripped := *rendered
	stripped.Framework = nil
	if err := a.RenderSettings(ctx, stripped); err != nil {
		return fmt.Errorf("re-render without the owner overlay: %w", err)
	}
	if err := validateOpenclawConfig(); err != nil {
		return fmt.Errorf("openclaw still rejects the config with the owner overlay withdrawn — platform bug: %w", err)
	}
	return nil
}
