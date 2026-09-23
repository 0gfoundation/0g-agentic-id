package dsh

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strconv"

	"seal-verify/internal/inference"
	"seal-verify/internal/logger"
	"seal-verify/internal/settings"
)

// The owner's configuration channel, dsh half (CONFIG_SURFACE.md §9).
//
// THIS FRAMEWORK HAS NO CONFIG FILE TO RENDER INTO, deliberately. DSH's own
// settings file ($DSH_HOME/settings.yaml) is served by
// `@deepseek-ai/dsh-settings-file`, and the bridge does NOT mount that plugin:
// it hot-reloads, so an agent edit of the file would inject an arbitrary
// baseURL/apiKeyEnv route into a live process. The file survived anyway as
// this adapter's own durable store for the inference pin — a chain-tracked
// `settings.yaml` role that Start read back at boot. With the owner's settings
// document as the pin's home that store has no remaining purpose, so it is
// gone: nothing writes the file, nothing reads it, and the bridge still does
// not mount the plugin that would. The security property is unchanged;
// nothing is left for it to protect. The one remaining trace is the CHAIN
// entry an agent minted while the role existed still carries, which
// HandleLegacy reads the pin out of exactly once (see the bottom of this
// file) before the watcher drops it.
//
// "Where this framework reads its settings" is therefore the bridge process's
// ENVIRONMENT. RenderSettings computes those variables once, deterministically,
// and Start hands them to the process it spawns (spawn.go).

// dshKnobs are the composition knobs the owner may set through the settings
// document's opaque `framework` section. They are the literals the bridge
// used to hardcode; an overlay that says nothing must reproduce exactly the
// composition that shipped.
//
// This set is an allowlist on purpose. The composition also carries the
// platform's OWN decisions — the sandbox policy mode, the spine invariant
// checks, the filesystem root, seal-tools/seal-guard — and those are not
// owner business: they are the part of the boundary the image hash attests.
//
// `workspaceContext` was in this set and is NOT any more. It mounts the
// spine's workspace-context extra, which reads ~/.dsh/AGENTS.md into every
// turn's system context — and that file is agent-writable (privsep hands the
// home to the agent user, which has bash and fs-local) and belongs to no
// role, so it is neither restored nor committed nor visible to anyone
// verifying the agent. Turning it on would give the agent an untracked
// channel into its own system prompt, which is a platform-boundary move, not
// a composition preference; an owner knob must not be able to make it. The
// knob is recognised and refused (see parseKnobs) rather than silently
// dropped. Making ~/.dsh/AGENTS.md a tracked role is the change that would
// let this become an owner option again; it is listed as deferred in
// README.md and needs the role, not a flag.
type dshKnobs struct {
	// ToolJobs mounts the spine's background-job tools.
	ToolJobs bool
	// MaxParallelToolCalls bounds how many tool calls one turn may run at
	// once. 1 = strictly serial.
	MaxParallelToolCalls int
}

// defaultKnobs is today's composition, i.e. what an empty overlay must yield.
func defaultKnobs() dshKnobs {
	return dshKnobs{ToolJobs: false, MaxParallelToolCalls: 1}
}

// parseKnobs reads the owner's opaque per-framework section, key by key. An
// absent key means "leave it as it ships", and keys this adapter does not know
// are ignored — being able to carry a key the platform has no opinion about is
// the whole point of an opaque section.
//
// NOTHING here is fatal, and that is one policy for every way an overlay can
// be wrong: a value out of range, a value of the wrong type, a section that is
// not an object at all. The first cut clamped the out-of-range case and
// errored on the wrongly-typed one, which is incoherent — RenderSettings runs
// from the manager's PreStart hook before EVERY spawn, so an error here is not
// a rejected push, it is an agent that will not boot, and it keeps not booting
// because the document that caused it is the one attestor stores. The overlay
// is owner-authored free text; a typo in it must cost the knob it is in, not
// the agent. Each rejected value falls back to the shipped default and says so
// in the log, and the knobs around it still apply.
func parseKnobs(raw json.RawMessage) dshKnobs {
	k := defaultKnobs()
	if len(bytes.TrimSpace(raw)) == 0 {
		return k
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		logger.Logf("dsh.RenderSettings: framework overlay is not a JSON object (%v); composing with the shipped defaults", err)
		return k
	}

	if v, ok := fields["toolJobs"]; ok {
		if err := json.Unmarshal(v, &k.ToolJobs); err != nil {
			logger.Logf("dsh.RenderSettings: toolJobs=%s is not a boolean (%v); using %v",
				v, err, defaultKnobs().ToolJobs)
			k.ToolJobs = defaultKnobs().ToolJobs
		}
	}

	if v, ok := fields["maxParallelToolCalls"]; ok {
		n := defaultKnobs().MaxParallelToolCalls
		switch err := json.Unmarshal(v, &n); {
		case err != nil:
			logger.Logf("dsh.RenderSettings: maxParallelToolCalls=%s is not a whole number (%v); using %d",
				v, err, defaultKnobs().MaxParallelToolCalls)
			n = defaultKnobs().MaxParallelToolCalls
		case n < 1:
			// A zero or negative bound would compose an agent that can run no
			// tool at all.
			logger.Logf("dsh.RenderSettings: maxParallelToolCalls=%d is out of range; using %d",
				n, defaultKnobs().MaxParallelToolCalls)
			n = defaultKnobs().MaxParallelToolCalls
		}
		k.MaxParallelToolCalls = n
	}

	if _, ok := fields["workspaceContext"]; ok {
		// Refused, loudly and in one place. See the type doc: the file it
		// would pull into the system prompt is agent-writable and tracked by
		// nothing, so this is not a knob an owner gets to turn.
		logger.Logf("dsh.RenderSettings: REFUSING framework.workspaceContext — it feeds ~/.dsh/AGENTS.md into the system prompt, and that file is agent-writable and belongs to no chain-tracked role, so this platform does not offer it as a setting (composing with it off)")
	}

	return k
}

// renderedSettings is what RenderSettings produced: the resolved document
// (Start reads the pin from it) and the bridge environment derived from it.
type renderedSettings struct {
	resolved settings.Resolved
	env      []string // KEY=VALUE, sorted; see settingsEnv
}

// RenderSettings implements framework.Framework.
//
// Successor to buildSettingsRoute + the settings.yaml writer + resolveInference.
// Two things the settings channel changed, both of which were bugs before:
//
//   - the pin is rebuilt from the owner's document at every boot instead of
//     being restored from a mint-time copy, so a fix shipped after an agent
//     was minted reaches it on the next boot;
//   - the reasoning bound no longer hangs off the provider check. It used to
//     live behind resolveInference's `provider != 0g-compute` early return, so
//     picking a native provider silently dropped it — and an always-thinking
//     model with no bound reasons forever (measured on glm-5.3: 100k+ chars of
//     reasoning, zero reply, stream killed upstream; effort=low converges in
//     minutes). s.Effort() is provider-independent and is applied for every
//     provider (settingsEnv). Only the ENDPOINT wiring stays behind
//     `s.Endpoint != nil`.
//
// It cannot fail on anything the owner wrote: the overlay is best-effort
// (parseKnobs) and the pin is checked by Start, not here. Two callers make
// that matter — the manager renders before every spawn, so an error is an
// agent that will not boot, and the owner's push path rolls the document back
// on one.
func (a *Adapter) RenderSettings(ctx context.Context, s settings.Resolved) error {
	knobs := parseKnobs(s.Others)
	env := settingsEnv(s, knobs)

	a.mu.Lock()
	a.rendered = &renderedSettings{resolved: s, env: env}
	a.mu.Unlock()

	level, decided := s.Effort()
	logger.Logf("dsh: rendered settings provider=%s model=%s effort=%q(decided=%t) routed=%v maxTokens=%d knobs=%+v",
		s.Provider, s.Model, level, decided, s.Endpoint != nil, s.PersistableMaxTokens(), knobs)
	return nil
}

// settingsEnv renders the settings-derived half of the bridge environment.
//
// Deterministic by construction: values are collected in a map and emitted
// sorted, so the same Resolved yields byte-identical output however the
// keys were inserted (the interface's idempotence rule).
//
// The inference credential is not one of these variables. It is not a secret
// this adapter can avoid holding — Start needs it at spawn and takes it from
// the resolved document stashed above (spawn.go) — but it stays out of THIS
// slice, which is the deterministic, logged, re-rendered-every-boot artifact
// the idempotence contract is about. Keeping the key out of it is what lets
// the rendered env be compared, logged and reasoned about without handling a
// secret.
func settingsEnv(s settings.Resolved, k dshKnobs) []string {
	env := map[string]string{}

	// Owner's knobs FIRST, platform-owned keys written over them. Today that
	// ordering is belt-and-braces — parseKnobs reads only the keys it knows
	// and renders each under a fixed name, so nothing an owner writes can
	// name a platform variable in the first place — but the ordering is what
	// keeps that true when a knob is added later, without anyone having to
	// maintain an exclusion list.
	env["SEAL_DSH_TOOL_JOBS"] = boolEnv(k.ToolJobs)
	env["SEAL_DSH_MAX_PARALLEL_TOOL_CALLS"] = strconv.Itoa(k.MaxParallelToolCalls)

	env["SEAL_MODEL_PROVIDER"] = s.Provider
	env["SEAL_MODEL_ID"] = s.Model

	if s.Endpoint != nil {
		// Endpoint wiring only when the PLATFORM routes this model: the 0g
		// router exists in no framework's built-in table, so we supply it. A
		// framework built-in ships its own and must not be re-pointed by us.
		env["SEAL_MODEL_BASE_URL"] = s.Endpoint.BaseURL
		env["SEAL_MODEL_API"] = wireAPI(s.Endpoint.Format)
	}

	// The reasoning bound, provider-independent (see RenderSettings). All
	// three of Effort()'s outcomes are handled, and two of them are NOT the
	// same decision even though they render the same way here:
	//
	//   level != ""      name it; the bridge declares the model
	//                    reasoning-capable and defaults the profile to it.
	//   decided, ""      the catalog says this model REJECTS
	//                    reasoning_effort. Naming a level would put the
	//                    parameter on the wire and earn a hard 400 on every
	//                    turn, so the variable is absent and the bridge
	//                    declares nothing.
	//   undecided, ""    the catalog was unreachable or silent. The platform
	//                    knows nothing, so it CLAIMS nothing: no variable, and
	//                    no invented floor either. There is no third rendering
	//                    available — this environment is built from scratch at
	//                    every spawn, so unlike openclaw's config file there is
	//                    no previous value here to leave standing — but there
	//                    is a third DECISION, and it is "do not state what we
	//                    cannot know". Inventing "low" out of an outage is the
	//                    400 above; the bridge's silence instead leaves the
	//                    judgement with pi-ai's own model metadata, which for a
	//                    framework built-in still knows the answer.
	//
	// The residual risk of that last case is real and is logged: an
	// always-thinking model on a platform-routed endpoint runs unbounded until
	// the catalog answers again. An owner who does not want to depend on the
	// catalog sets `thinking` in the document — a stated preference makes
	// Effort() decided even during an outage.
	switch level, decided := s.Effort(); {
	case level != "":
		env["SEAL_MODEL_EFFORT"] = level
	case decided:
		logger.Logf("dsh: %q takes no reasoning bound (catalog); the bridge will declare none", s.Model)
	default:
		logger.Logf("warn: dsh: the router catalog is silent on %q, so the platform states no reasoning bound for this boot; if this model always thinks it can reason unbounded until the catalog answers — set `thinking` in the settings document to pin a level regardless", s.Model)
	}

	// Only a catalog-sourced budget reaches the bridge (review P1): the name
	// heuristic's guess (8192) starves a reasoning model's shared
	// thinking+reply budget, and PersistableMaxTokens is 0 for it. With no
	// variable the bridge omits maxTokens and pi-ai's own default applies.
	if mt := s.PersistableMaxTokens(); mt > 0 {
		env["SEAL_MODEL_MAX_TOKENS"] = strconv.Itoa(mt)
	}

	out := make([]string, 0, len(env))
	for name, v := range env {
		out = append(out, name+"="+v)
	}
	sort.Strings(out)
	return out
}

// wireAPI maps a resolved wire format onto the pi-ai `api` id the bridge
// passes to the llm-pi-ai route.
func wireAPI(f inference.WireFormat) string {
	if f == inference.WireAnthropic {
		return "anthropic-messages"
	}
	return "openai-completions"
}

func boolEnv(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// ── the retired settings.yaml role ──────────────────────────────────────────

// legacySettingsRole is the chain role this adapter used to declare for the
// inference pin, before the owner's settings document existed. It is no longer
// in Roles(), so bootstrap hands whatever the chain still carries under that
// name to HandleLegacy — once, before the watcher's first tick rebuilds the
// entry list from Roles() and drops it.
//
// That drop is correct and is not worked around here: the pin's home is the
// owner's document now, and the platform persists what this recovery hands
// back (report.SeedSettings) before the entry goes. What only this package can
// do is READ the old entry, which is why the branch exists.
const legacySettingsRole = "settings.yaml"

// legacyLLMPluginID is the composition-entry key the retired role nested the
// route under — DSH's own settings-file shape, which this adapter wrote even
// though the bridge never mounted the plugin that reads it.
const legacyLLMPluginID = "llm-pi-ai"

// handleLegacySettings recovers the inference pin from the retired role's
// plaintext. Never an error: a legacy entry this adapter version cannot read
// must not stop a boot, it just leaves the agent on whatever document attestor
// already holds.
func (a *Adapter) handleLegacySettings(plaintext []byte) error {
	provider, model := legacyPin(plaintext)
	if model == "" {
		logger.Logf("dsh.HandleLegacy[%s]: no usable pin in the legacy entry (%d bytes); nothing to recover",
			legacySettingsRole, len(plaintext))
		return nil
	}
	doc := settings.Doc{Provider: provider, Model: model}

	// Top of the rank: this is the agent's LATER state — the seed's pin was
	// translated into this role once, and any re-pin lived here and nowhere
	// else — so it wins over the mint seed whichever order Phase C visits.
	a.stashSeededPin(sourceConfig, doc)

	logger.Logf("dsh.HandleLegacy[%s]: recovered pin provider=%s model=%s from the retired role; the platform will persist it as the owner's settings document",
		legacySettingsRole, provider, model)
	return nil
}

// legacySource ranks the retired chain roles a pin can be recovered from;
// higher wins. Phase C walks the chain entries in whatever order they arrived
// (main.go), so "whichever branch ran last" is a coin flip, not a rule.
//
// The retired settings.yaml role outranks the mint-time persona seed for the
// same reason as prime's models.json (modelsjson.go there carries the full
// argument): the seed is frozen at mint, while the role is what Start read on
// every boot after the first — a later re-pin exists only there. In practice
// the two never coexist on one chain (the first drift commit rebuilds the
// array from Roles() and persona is not in it); the rank makes that an
// invariant this code does not have to depend on.
type legacySource int

const (
	sourceNone legacySource = iota
	sourcePersona
	sourceConfig
)

// stashSeededPin records doc as what SeededSettings reports, unless a
// higher-ranked source already stashed one. Equal rank overwrites, so a later
// boot that still finds the same chain entry recovers the same document —
// HandleLegacy's idempotence rule — rather than depending on first-write-wins.
func (a *Adapter) stashSeededPin(src legacySource, doc settings.Doc) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.seededFrom > src {
		return false
	}
	a.seededPin = &doc
	a.seededFrom = src
	return true
}

// SeededSettings implements framework.LegacySettingsSeeder: hand the recovered
// document to the platform, which persists it to attestor and renders from it.
// Only consulted when the stored document names no model, so a real document
// always outranks this.
func (a *Adapter) SeededSettings() (settings.Doc, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.seededPin == nil {
		return settings.Doc{}, false
	}
	return *a.seededPin, true
}

// legacyPin digs provider + model out of the retired role's plaintext.
//
// The wire encoding is the canonical JSON the old writer produced (compact,
// sorted keys — YAML was the on-disk form, JSON the on-chain one), shaped
//
//	{"llm-pi-ai":{"providers":{"<provider>":{"models":[{"id":"<model>"}]}}}}
//
// Anything else — a blank entry, a parse failure, a file with no route — is
// "nothing to recover", reported by an empty model.
func legacyPin(plaintext []byte) (provider, model string) {
	if len(bytes.TrimSpace(plaintext)) == 0 {
		return "", ""
	}
	var cfg map[string]struct {
		Providers map[string]struct {
			Models []struct {
				ID string `json:"id"`
			} `json:"models"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(plaintext, &cfg); err != nil {
		logger.Logf("dsh.HandleLegacy[%s]: WARN parse failed (%v); nothing recovered", legacySettingsRole, err)
		return "", ""
	}
	providers := cfg[legacyLLMPluginID].Providers

	// Deterministic pick: sort the provider names, so a multi-provider file
	// (which this adapter never wrote, but a hand edit might have left)
	// recovers the same pin on every boot instead of a random one.
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, m := range providers[name].Models {
			if m.ID != "" {
				return name, m.ID
			}
		}
	}
	return "", ""
}
