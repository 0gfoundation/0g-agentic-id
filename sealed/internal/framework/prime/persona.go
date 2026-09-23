package prime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"seal-verify/internal/logger"
	"seal-verify/internal/settings"
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
	SystemPrompt string           `json:"system_prompt"`
	Inference    personaInference `json:"inference"`
}

// personaInference is the seed's inference pin: the owner's literal mint-time
// choice, in the spelling they made it ("0g-compute" for a platform-routed
// model), which is also the spelling the settings document uses.
type personaInference struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

// HandleLegacy handles every chain role this adapter no longer declares: the
// mint-only `persona` seed, and the retired "models.json" role an agent minted
// before the settings channel still carries its pin in (modelsjson.go).
// Unknown roles are logged and ignored — never an error — because chains may
// carry experimental roles a given adapter version does not understand.
func (a *Adapter) HandleLegacy(ctx context.Context, role string, plaintext []byte) error {
	switch role {
	case "persona":
		return a.handleLegacyPersona(plaintext)
	case legacyModelsRole:
		return a.handleLegacyModels(plaintext)
	}
	logger.Logf("prime.HandleLegacy: ignoring unknown role %q (%d bytes)", role, len(plaintext))
	return nil
}

// handleLegacyPersona ingests the protocol seed role every adapter must handle
// (FRAMEWORK_ADAPTER.md §5.4).
func (a *Adapter) handleLegacyPersona(plaintext []byte) error {
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

	// The pin BEFORE the disk write. It is the half only this boot can recover
	// — the watcher's first wholesale commit rebuilds the chain array from
	// Roles() and this entry is not in it — it cannot fail, and a disk that
	// refuses APPEND_SYSTEM.md must not also cost the owner their model.
	a.seedFromPersona(seed.Inference)

	if seed.SystemPrompt != "" {
		if err := a.restoreAppendSystem([]byte(seed.SystemPrompt)); err != nil {
			// Logged, never returned, matching the models.json branch. Phase C
			// propagates an error (main.go returns on it), so an unwritable
			// persona file would take the container OFFLINE — strictly worse
			// than an agent running on the stock system prompt, and worse than
			// what the code before this migration did with the same disk.
			logger.Logf("prime.HandleLegacy[persona]: WARN write APPEND_SYSTEM.md: %v", err)
		}
	}

	logger.Logf("prime.HandleLegacy[persona]: system_prompt=%d bytes", len(seed.SystemPrompt))
	return nil
}

// seedFromPersona REPORTS the mint-time pin to the platform, which persists it
// as the owner's settings document (framework.LegacySettingsSeeder →
// report.SeedSettings) when attestor holds none.
//
// It closes the one gap the settings migration left. attestor mints exactly
// two iData roles, `framework` and `persona`, so an agent minted before the
// channel that has never committed drift carries its pin HERE and nowhere
// else: the retired models.json role that modelsjson.go reads only exists on
// chain after a drift commit. For THIS adapter an unrecovered pin is not a
// degradation but an outage — Start hard-fails on a missing pin (spawn.go), so
// the container goes OFFLINE, and the code before the migration booted it
// fine. The same seed also covers the agent that pinned a framework BUILT-IN,
// which never produced a models.json entry at all (nothing to register).
//
// Reporting is ALL that happens; the pin is deliberately not translated into a
// models.json on disk any more. It used to be, and that was the original bug
// (found live, on agent 271): `persona` is a mint-time seed, the uploader
// drops chain entries outside Roles(), so the seed left the chain at the first
// drift commit and the in-memory pin died with it. RenderSettings owns that
// file now and rebuilds it from the owner's document before every Start, so a
// copy written here would be overwritten moments later — and a second source
// of truth for the model an agent runs is the ambiguity that bug was made of.
//
// This does NOT outrank the retired models.json role; legacySource
// (modelsjson.go) carries the rule and the reasoning.
//
// Both halves of the pin or nothing, exactly as the models.json branch: Start
// refuses an empty provider as flatly as an empty model, and what comes back
// from here is PERSISTED as the owner's document — so half a pin would not be
// a partial recovery, it would be a stored document that fails every future
// boot, outranking this recovery each time, until the owner notices.
//
// The provider is carried VERBATIM, and needs no rewrite of the kind
// pinProvider does for the registration: the seed records what the owner
// picked, so "0g-compute" is already the spelling settings.Resolve turns back
// into a router endpoint, and any other value is the framework built-in the
// owner named.
//
// No level is recovered, because persona has no field that could carry one —
// the owner's choice travelled in the deploy payload's env
// (SEAL_OWNER_THINKING), not in this seed. Unset lets Effort() derive a bound
// from the catalog, as it does for every other agent; inventing one here would
// configure the agent for the owner.
func (a *Adapter) seedFromPersona(inf personaInference) {
	provider := strings.TrimSpace(inf.Provider)
	model := strings.TrimSpace(inf.Model)
	if provider == "" || model == "" {
		if provider != "" || model != "" {
			logger.Logf("prime.HandleLegacy[persona]: seed pins provider=%q model=%q; half a pin is not a recovery",
				inf.Provider, inf.Model)
		}
		return
	}

	doc := settings.Doc{Provider: provider, Model: model}
	if !a.stashSeededPin(sourcePersona, doc) {
		logger.Logf("prime.HandleLegacy[persona]: the mint seed pins %s/%s, but the retired %s role already recovered this agent's later pin; keeping that one",
			provider, model, legacyModelsRole)
		return
	}
	logger.Logf("prime.HandleLegacy[persona]: recovered pin provider=%s model=%s from the mint seed; the platform will persist it as the owner's settings document",
		provider, model)
}
