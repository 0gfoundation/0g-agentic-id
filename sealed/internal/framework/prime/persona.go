package prime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"seal-verify/internal/logger"
)

// role="APPEND_SYSTEM.md" — the owner persona, and the mint-time `persona`
// seed's destination.
//
// Prime Agent's DefaultResourceLoader appends APPEND_SYSTEM.md from the agent
// dir onto the system prompt (see packages/coding-agent/examples/sdk/
// 03-custom-prompt.ts, whose `appendSystemPromptOverride: () => []` exists
// precisely to suppress that pickup). That makes it the framework-native
// owner-persona channel, exactly analogous to hermes's SOUL.md.
//
// It is NOT where sealed's own platform/doctrine text goes. That is injected
// in code by the HTTP bridge at session creation (agentsFilesOverride), from
// agentDocPath() outside primeHome — so platform text can never phantom-drift
// onto chain, and the agent's rlm.harness.delete_prompt_note (which operates
// on harness entries, a different mechanism entirely) cannot remove it.
// Consequence: this role needs no marker stripping, unlike the openclaw and
// hermes identity files.

// evoAppendSystem returns the persona file's bytes verbatim. Missing or empty
// file → nil, matching Defaults so an absent persona produces no chain entry.
func (a *Adapter) evoAppendSystem() ([]byte, error) {
	content, err := os.ReadFile(appendSystemPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("prime evoAppendSystem: read %s: %w", appendSystemPath(), err)
	}
	if len(content) == 0 {
		return nil, nil
	}
	return content, nil
}

// restoreAppendSystem writes the persona file verbatim. nil plaintext leaves an
// existing file alone (so a supervisor restart never clobbers an agent's own
// edits) and touches an empty one otherwise, so the framework never appends a
// stock template that would land on chain as first-boot drift.
func (a *Adapter) restoreAppendSystem(plaintext []byte) error {
	if err := os.MkdirAll(primeHome, 0o755); err != nil {
		return fmt.Errorf("prime.Restore[APPEND_SYSTEM.md]: mkdir %s: %w", primeHome, err)
	}
	if len(plaintext) == 0 {
		if _, err := os.Stat(appendSystemPath()); err == nil {
			return nil
		}
		if err := os.WriteFile(appendSystemPath(), nil, 0o644); err != nil {
			return fmt.Errorf("prime.Restore[APPEND_SYSTEM.md]: touch: %w", err)
		}
		return nil
	}
	if err := os.WriteFile(appendSystemPath(), plaintext, 0o644); err != nil {
		return fmt.Errorf("prime.Restore[APPEND_SYSTEM.md]: write: %w", err)
	}
	logger.Logf("prime.Restore[APPEND_SYSTEM.md]: %d bytes", len(plaintext))
	return nil
}

// personaSeed is the protocol seed role every adapter must ingest
// (FRAMEWORK_ADAPTER.md §5.4). The deploy client builds it; the attestor
// synthesizes nothing.
type personaSeed struct {
	SystemPrompt string `json:"system_prompt"`
	Inference    struct {
		Provider string `json:"provider"`
		Model    string `json:"model"`
	} `json:"inference"`
}

// HandleLegacy translates mint-only ingestion roles into this adapter's
// path-driven artifacts. Unknown roles are logged and ignored — never an
// error — because chains may carry experimental roles a given adapter version
// does not understand.
func (a *Adapter) HandleLegacy(ctx context.Context, role string, plaintext []byte) error {
	if role != "persona" {
		logger.Logf("prime.HandleLegacy: ignoring unknown role %q (%d bytes)", role, len(plaintext))
		return nil
	}
	if len(strings.TrimSpace(string(plaintext))) == 0 {
		logger.Logf("prime.HandleLegacy[persona]: empty seed, nothing to ingest")
		return nil
	}

	var seed personaSeed
	if err := json.Unmarshal(plaintext, &seed); err != nil {
		// A malformed seed must not stop the boot: log and keep defaults.
		logger.Logf("prime.HandleLegacy[persona]: WARN parse failed (%v); keeping defaults", err)
		return nil
	}

	if seed.SystemPrompt != "" {
		if err := a.restoreAppendSystem([]byte(seed.SystemPrompt)); err != nil {
			return fmt.Errorf("prime.HandleLegacy[persona]: %w", err)
		}
	}

	// Translate the inference pin into the tracked models.json role.
	//
	// This MUST be persisted, not merely remembered. `persona` is a mint-time
	// seed: the uploader drops chain entries outside Roles(), so it is gone from
	// chain at the first drift commit (§5.4). An earlier version of this adapter
	// kept the pin in memory only, and every boot after that first commit came up
	// with no model at all — found live, on agent 271.
	if seed.Inference.Provider != "" && seed.Inference.Model != "" {
		provider, api, baseURL := resolveInference(ctx, seed.Inference.Provider, seed.Inference.Model)
		if baseURL == "" {
			// A native provider is a built-in: nothing to register, and writing a
			// half-filled entry would shadow the built-in with a broken one.
			logger.Logf("prime.HandleLegacy[persona]: native provider %q — no models.json entry needed", provider)
		} else if err := writeModelsJSON(buildModelsConfig(provider, seed.Inference.Model, api, baseURL)); err != nil {
			return fmt.Errorf("prime.HandleLegacy[persona]: %w", err)
		}
	}
	a.mu.Lock()
	a.personaProvider, a.personaModel = seed.Inference.Provider, seed.Inference.Model
	a.mu.Unlock()
	logger.Logf("prime.HandleLegacy[persona]: system_prompt=%d bytes, inference=%s/%s",
		len(seed.SystemPrompt), seed.Inference.Provider, seed.Inference.Model)
	return nil
}
