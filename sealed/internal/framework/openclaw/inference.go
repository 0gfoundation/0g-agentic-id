package openclaw

import (
	"encoding/json"
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
// models.providers entry openclaw needs to route to 0G's OpenAI-compatible
// endpoint. No-op for any provider other than "0g-compute".
//
// Called from Start AFTER Restore has written the owner's openclaw.json
// to disk. Treats this as runtime augmentation: owner specifies
// "0g-compute" as a provider name; sealed handles the protocol bridging
// transparently. The persisted file ends up with the providers entry too
// (next EvolutionFor will see it) but watcher's post-Start settle pass
// captures that as the new baseline so no spurious drift fires.
func applyZGComputeAugmentation(provider, model string) error {
	if provider != "0g-compute" {
		return nil
	}
	return updateOpenclawJSON(func(cfg map[string]any) {
		applyZGComputeToConfig(cfg, model)
	})
}

// applyZGComputeToConfig is the in-memory mutation 0g-compute requires.
// Encoded once here so callers don't have to memorise the openclaw model
// definition shape. Authoritative shape per openclaw's plugin-sdk type
// defs (ModelProviderConfig + ModelDefinitionConfig).
//
// Routing details:
//   - openclaw provider name is rewritten to "openai" because 0G is
//     OpenAI-protocol-compatible
//   - baseUrl forces the 0G router endpoint
//   - apiKey references env (the same OPENAI_API_KEY sealed exports)
//   - compat.requiresStringContent is critical: 0G rejects OpenAI's
//     multimodal array form ({type:"text",...}) so content must serialise
//     as a plain string
func applyZGComputeToConfig(cfg map[string]any, model string) {
	const clawProvider = "openai"
	const baseURL = "https://router-api.0g.ai/v1"

	primary := clawProvider + "/" + model
	_ = setAgentsDefaults(cfg, "model", json.RawMessage(mustMarshal(map[string]any{
		"primary": primary,
	})))

	modelDef := map[string]any{
		"id":            model,
		"name":          model,
		"reasoning":     false,
		"input":         []string{"text"},
		"cost":          map[string]any{"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
		"contextWindow": 128000,
		"maxTokens":     8192,
		"compat": map[string]any{
			"requiresStringContent":    true,
			"supportsStore":            false,
			"supportsDeveloperRole":    false,
			"supportsReasoningEffort":  false,
			"supportsUsageInStreaming": false,
			"supportsStrictMode":       false,
			"maxTokensField":           "max_tokens",
		},
	}
	providerEntry := map[string]any{
		"baseUrl": baseURL,
		"api":     "openai-completions",
		"apiKey": map[string]any{
			"source":   "env",
			"provider": "default",
			"id":       "OPENAI_API_KEY",
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
