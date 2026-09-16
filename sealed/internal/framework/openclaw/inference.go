package openclaw

import (
	"context"
	"encoding/json"

	"seal-verify/internal/inference"
	"seal-verify/internal/logger"
)

// Inference resolution helpers used at Start time to read provider+model
// out of openclaw.json (now that the path-driven model writes the file
// verbatim from chain plaintext, the persona config struct that used to
// hold these fields is gone). spawn.go calls these to set API-key env
// vars and to apply 0g-compute's models.providers augmentation if needed.

// inferencePick is the resolved provider+model pair parsed from
// `agents.defaults.model.primary` ("<provider>/<model>" string).
type inferencePick struct {
	Provider string
	Model    string
}

// resolveInferenceFromOpenclawJSON parses agents.defaults.model.primary
// from the on-disk openclaw.json and returns the provider+model pair.
// Returns zero-value inferencePick if any layer is missing — caller
// (Start) treats empty provider as "not configured" and logs a warning;
// sealed doesn't crash because openclaw itself will fail at first chat
// with a clearer message, and the failure reaches attestor via manager.
func resolveInferenceFromOpenclawJSON() (inferencePick, error) {
	cfg, err := loadOpenclawJSON()
	if err != nil {
		return inferencePick{}, err
	}
	return inferencePickFromConfig(cfg), nil
}

// inferencePickFromConfig is the pure-data variant of
// resolveInferenceFromOpenclawJSON. Useful when caller already has the
// parsed openclaw.json map.
func inferencePickFromConfig(cfg map[string]any) inferencePick {
	agents, _ := cfg["agents"].(map[string]any)
	if agents == nil {
		return inferencePick{}
	}
	defaults, _ := agents["defaults"].(map[string]any)
	if defaults == nil {
		return inferencePick{}
	}
	model, _ := defaults["model"].(map[string]any)
	if model == nil {
		return inferencePick{}
	}
	primary, _ := model["primary"].(string)
	provider, modelName := splitProviderModel(primary)
	return inferencePick{Provider: provider, Model: modelName}
}

// splitProviderModel parses "<provider>/<model>" into its parts. Anything
// before the FIRST slash is provider; the rest is model (model strings
// can contain further slashes — e.g. "anthropic/claude-3-5-sonnet-latest").
func splitProviderModel(combined string) (provider, model string) {
	for i := 0; i < len(combined); i++ {
		if combined[i] == '/' {
			return combined[:i], combined[i+1:]
		}
	}
	return combined, ""
}

// isZGComputeRouted reports whether the given provider triggers 0g-compute
// routing (provider name "0g-compute" triggers applyZGComputeAugmentation
// which rewrites openclaw.json to route through 0G's OpenAI-compatible
// endpoint). spawn.go uses this to populate RuntimeSnapshot.ZGComputeRouted
// for the agent's runtime context.
func isZGComputeRouted(provider string) bool {
	return provider == "0g-compute"
}

// applyZGComputeAugmentation rewrites openclaw.json in place to add the
// models.providers entry openclaw needs to route to the 0G router.
// No-op for any provider other than "0g-compute".
//
// The wire format comes from the route Start resolved once per boot
// (shared inference.ResolveZG — router catalog + heuristic fallback):
// claude-* models are served on the router's Anthropic-format endpoint
// ONLY — hardcoding the OpenAI format here is exactly what 400'd live
// ("model 'claude-sonnet-5' is not available on the openai API format").
// The same route also picks the exported key env name (spawn.go), so
// config dialect and key can't disagree.
//
// Called from Start AFTER Restore has written the owner's openclaw.json
// to disk. Treats this as runtime augmentation: owner specifies
// "0g-compute" as a provider name; sealed handles the protocol bridging
// transparently. The persisted file ends up with the providers entry too
// (next EvolutionFor will see it) but watcher's post-Start settle pass
// captures that as the new baseline so no spurious drift fires.
func applyZGComputeAugmentation(provider, model string, route *inference.Route) error {
	if provider != "0g-compute" || route == nil {
		return nil
	}
	return updateOpenclawJSON(func(cfg map[string]any) {
		applyZGComputeToConfig(cfg, model, *route)
	})
}

// applyZGComputeToConfig is the in-memory mutation 0g-compute requires.
// Encoded once here so callers don't have to memorise the openclaw model
// definition shape. Authoritative shape per openclaw's plugin-sdk type
// defs (ModelProviderConfig + ModelDefinitionConfig).
//
// The route decides the dialect:
//   - OpenAI wire: provider "openai", api "openai-completions".
//     compat.requiresStringContent is critical — 0G rejects OpenAI's
//     multimodal array form ({type:"text",...}) so content must
//     serialise as a plain string.
//   - Anthropic wire: provider "anthropic", api "anthropic-messages"
//     (claude-* on the router). No compat block — the anthropic client
//     path speaks string content natively.
func applyZGComputeToConfig(cfg map[string]any, model string, route inference.Route) {
	clawProvider := "openai"
	api := "openai-completions"
	if route.Format == inference.WireAnthropic {
		clawProvider = "anthropic"
		api = "anthropic-messages"
	}

	primary := clawProvider + "/" + model
	_ = setAgentsDefaults(cfg, "model", json.RawMessage(mustMarshal(map[string]any{
		"primary": primary,
	})))
	// Always-thinking models (glm-5.3) reason WITHOUT BOUND unless the request
	// carries reasoning_effort (Route.SupportsReasoningEffort documents the
	// measurement: 23k chars / 10min of reasoning, zero reply, upstream kill;
	// effort=low → full reply in ~2.5min). thinkingDefault supplies the level
	// when no /think directive is present; "low" because glm-5.3 accepts only
	// low/high/max (medium is a hard 400) and low is the portable
	// intersection. Only set when the catalog says the model takes the
	// parameter — for every other model the directive would be noise — and
	// only when absent, so an owner-set level (high / off) survives (review
	// F1).
	if route.SupportsReasoningEffort && !hasAgentsDefault(cfg, "thinkingDefault") {
		_ = setAgentsDefaults(cfg, "thinkingDefault", json.RawMessage(`"low"`))
	}

	modelDef := map[string]any{
		"id":            model,
		"name":          model,
		"reasoning":     route.SupportsReasoningEffort,
		"input":         []string{"text"},
		"cost":          map[string]any{"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
		"contextWindow": route.ContextWindow,
	}
	// Output budget: only a CATALOG-sourced value may be persisted (review
	// P1). During an outage the heuristic's 8192 would be written into the
	// chain-tracked config and — with reasoning and the reply SHARING the
	// budget — permanently starve replies. With the field absent openclaw
	// sends no max_tokens at all and the model's own ceiling applies.
	if route.CatalogSourced && route.MaxTokens > 0 {
		modelDef["maxTokens"] = route.MaxTokens
	}
	if route.Format == inference.WireOpenAI {
		modelDef["compat"] = map[string]any{
			"requiresStringContent":    true,
			"supportsStore":            false,
			"supportsDeveloperRole":    false,
			"supportsReasoningEffort":  route.SupportsReasoningEffort,
			"supportsUsageInStreaming": false,
			"supportsStrictMode":       false,
			"maxTokensField":           "max_tokens",
		}
	}
	providerEntry := map[string]any{
		"baseUrl": route.BaseURL,
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
			"id":       route.EnvKey,
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

	// auth.profiles[openai:api] + auth.order so openclaw picks the right
	// profile for inference requests.
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

// hasAgentsDefault reports whether agents.defaults carries the given key.
func hasAgentsDefault(cfg map[string]any, key string) bool {
	agents, _ := cfg["agents"].(map[string]any)
	defaults, _ := agents["defaults"].(map[string]any)
	_, ok := defaults[key]
	return ok
}

// healOpenclawConfig runs on EVERY Start (review P0). applyZGComputeAugmentation
// only runs on the FIRST Start of a fresh agent — and it rewrites the pin's
// provider from "0g-compute" to the resolved "openai"/"anthropic" form, which
// is what gets drift-committed. So an existing agent's chain-restored
// openclaw.json is already in resolved form, the augmentation never recognizes
// it again, and fixes shipped after mint (bounded reasoning, watchdog
// headroom, catalog budgets) never reach it. This healer recognizes the
// SHAPES sealed itself wrote — provider entries pinned to the 0g router's
// endpoints, and machine defaults that were absent — and updates only those:
//
//   - modelDef reasoning / compat.supportsReasoningEffort: false → true when
//     the catalog says the model takes reasoning_effort (the old machine
//     shape hard-coded false; an unbounded thinking model dies without it).
//   - modelDef maxTokens: absent or the heuristic's 8192 → the catalog value
//     (only CatalogSourced; absent otherwise so openclaw omits the parameter).
//     Any other value is treated as hand-set and left alone.
//   - provider timeoutSeconds: absent → 600 (pre-c2dd5f9 agents).
//   - agents.defaults.thinkingDefault: absent → "low" (owner-set levels stay).
//   - diagnostics.stuckSessionAbortMs: absent → 900s. Deliberately OUTSIDE
//     the router-shape gate (review F3): the watchdog-vs-slow-turns tuning is
//     orthogonal to routing, and a native-provider thinking model can also
//     legitimately show no progress for >6min.
//
// No-op (no write, no drift) when nothing needs healing.
func healOpenclawConfig(ctx context.Context) error {
	cfg, err := loadOpenclawJSON()
	if err != nil {
		return err
	}
	changed := false

	if diagnostics, _ := cfg["diagnostics"].(map[string]any); diagnostics == nil {
		cfg["diagnostics"] = map[string]any{"stuckSessionAbortMs": 900_000}
		changed = true
	} else if _, set := diagnostics["stuckSessionAbortMs"]; !set {
		// Stuck-session watchdog headroom: default 360s (warn 120s × 3) is
		// tuned for fast models; a thinking model legitimately shows no
		// "progress" for minutes (live: a PR-review run killed at 446s as
		// stalled_agent_run → owner saw "internal error"). 900s must stay
		// ABOVE the provider timeoutSeconds (600s): a single silent model
		// call dies to the idle timeout first, so 600–900s only ever catches
		// real deadlocks. Deliberate stops don't depend on it (Esc / cancel).
		diagnostics["stuckSessionAbortMs"] = 900_000
		changed = true
	}

	models, _ := cfg["models"].(map[string]any)
	providers, _ := models["providers"].(map[string]any)
	for _, pv := range providers {
		p, _ := pv.(map[string]any)
		baseURL, _ := p["baseUrl"].(string)
		if baseURL != inference.ZGOpenAIBaseURL && baseURL != inference.ZGAnthropicBaseURL {
			continue // not a sealed-written router pin — never touch
		}
		if _, set := p["timeoutSeconds"]; !set {
			p["timeoutSeconds"] = 600
			changed = true
		}
		modelList, _ := p["models"].([]any)
		for _, mv := range modelList {
			m, _ := mv.(map[string]any)
			id, _ := m["id"].(string)
			if m == nil || id == "" {
				continue
			}
			route := inference.ResolveZG(ctx, id)
			if route.SupportsReasoningEffort {
				if r, _ := m["reasoning"].(bool); !r {
					m["reasoning"] = true
					changed = true
				}
				if compat, _ := m["compat"].(map[string]any); compat != nil {
					if s, _ := compat["supportsReasoningEffort"].(bool); !s {
						compat["supportsReasoningEffort"] = true
						changed = true
					}
				}
				if !hasAgentsDefault(cfg, "thinkingDefault") {
					_ = setAgentsDefaults(cfg, "thinkingDefault", json.RawMessage(`"low"`))
					changed = true
				}
			}
			mt, _ := m["maxTokens"].(float64)
			machineValue := mt == 0 || int(mt) == inference.HeuristicOpenAIMaxTokens
			if machineValue {
				switch {
				case route.CatalogSourced && route.MaxTokens > 0 && int(mt) != route.MaxTokens:
					m["maxTokens"] = route.MaxTokens
					changed = true
				case !route.CatalogSourced && mt != 0:
					// Poisoned heuristic value and no catalog to correct it:
					// drop the field — openclaw then omits max_tokens and the
					// model's own ceiling applies.
					delete(m, "maxTokens")
					changed = true
				}
			}
		}
	}

	if !changed {
		return nil
	}
	logger.Logf("openclaw: config heal applied (bounded reasoning / budgets / watchdog — see healOpenclawConfig)")
	return saveOpenclawJSON(cfg)
}
