package hermes

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"seal-verify/internal/framework"
	"seal-verify/internal/inference"
	"seal-verify/internal/logger"
	"seal-verify/internal/settings"
)

// Mint-only ingestion: attestor's default_i_data emits a semantic `persona`
// role at mint (`{system_prompt, inference}`) because attestor stays
// framework-agnostic. Sealed translates this on first boot into the
// path-driven disk artifacts — SOUL.md for the prompt — and reports its
// inference half to the platform as the owner's settings document, which is
// where the model pin lives now.
//
// persona is NOT in Roles() and NOT in Restore()'s dispatch: it's a
// one-shot bootstrap-time conversion. After the first uploader.Apply the
// wholesale chain.Update drops it and the path-driven invariant takes over.

// personaPlaintext mirrors the shape attestor's default_i_data emits.
type personaPlaintext struct {
	SystemPrompt string             `json:"system_prompt"`
	Inference    personaInferenceIn `json:"inference"`
}

type personaInferenceIn struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

// HandleLegacy implements framework.Framework. It handles the mint-only
// ingestion role and the role this adapter has RETIRED; unknown legacy roles
// are logged and ignored per the contract in framework.go.
//
//	persona      the mint seed: identity onto disk, and the owner's literal
//	             model pin into the seeded-pin stash (below)
//	config.yaml  the retired config role; its model pin is recovered into the
//	             same stash, at a lower rank (bottom of this file)
//
// Neither branch can fail a boot. main.go's Phase C turns a HandleLegacy error
// into an offline container, and nothing either branch reads is worth that:
// these are historical bytes this adapter version may simply not understand.
func (a *Adapter) HandleLegacy(ctx context.Context, role string, plaintext []byte) error {
	switch role {
	case "persona":
		return a.ingestPersona(ctx, plaintext)
	case legacyConfigRole:
		return a.handleLegacyConfig(plaintext)
	default:
		logger.Logf("hermes.HandleLegacy: unknown legacy role %q (%d bytes) — ignoring",
			role, len(plaintext))
		return nil
	}
}

// ingestPersona translates the mint-time persona plaintext:
//
//   - persona.SystemPrompt → ~/.hermes/SOUL.md
//   - persona.Inference    → the seeded-pin stash SeededSettings reports, and
//     config.yaml model.{provider,default}
//
// THE STASH IS THE HALF THAT KEEPS AN AGENT ROUTING. attestor mints exactly two
// iData roles, `framework` and `persona`, so an agent minted before the
// settings channel that has not drifted since has NO retired config role on
// chain: this seed is the only written record of its pin anywhere. Translating
// it to disk and not reporting it left that agent with an empty settings
// document — a modelless hermes whose first message fails, where the old code
// booted it fine. Reporting it costs one line and closes that window; the
// platform decides what to do with it (main.go consults SeededSettings only
// when the stored document names no model, so a real document still wins).
//
// The config.yaml write below is now belt-and-braces: RenderSettings owns that
// file's model section and rebuilds it from the document before every Start,
// and the document is seeded from the same stash in the same bootstrap.
//
// Idempotent: same plaintext → same disk state and same stash.
//
// Never fatal, for the same reason handleLegacyConfig is not (see there). A
// seed this adapter version cannot parse leaves the agent on the identity and
// document it already has; a disk write that fails costs SOUL.md, and neither
// is worth the offline container a returned error would produce. The failures
// are independent on purpose: an unwritable SOUL.md must not also cost the pin.
func (a *Adapter) ingestPersona(ctx context.Context, plaintext []byte) error {
	if len(strings.TrimSpace(string(plaintext))) == 0 {
		logger.Logf("hermes.HandleLegacy[persona]: empty entry; nothing to ingest")
		return nil
	}
	var p personaPlaintext
	if err := json.Unmarshal(plaintext, &p); err != nil {
		logger.Logf("hermes.HandleLegacy[persona]: WARN parse failed (%v); nothing ingested — the agent keeps the identity on disk and the document attestor holds", err)
		return nil
	}

	if err := os.MkdirAll(hermesHome, 0o755); err != nil {
		logger.Logf("hermes.HandleLegacy[persona]: WARN mkdir %s (%v); SOUL.md not written", hermesHome, err)
	} else if err := os.WriteFile(soulMDPath(), []byte(p.SystemPrompt), 0o644); err != nil {
		logger.Logf("hermes.HandleLegacy[persona]: WARN write SOUL.md (%v); the agent boots without this persona", err)
	}

	// The provider is taken VERBATIM here, unlike the retired role's (see
	// legacyPin). Nothing rewrote this one: attestor records what the owner
	// picked at deploy — "0g-compute" stays "0g-compute", which is the exact
	// spelling settings.Resolve needs to re-derive the router endpoint and
	// this boot's key.
	provider := strings.TrimSpace(p.Inference.Provider)
	model := strings.TrimSpace(p.Inference.Model)
	if model != "" {
		a.stashSeededPin(sourcePersonaSeed, settings.Doc{Provider: provider, Model: model})
		logger.Logf("hermes.HandleLegacy[persona]: recovered pin provider=%s model=%s from the mint seed; the platform will persist it as the owner's settings document",
			provider, model)
	}

	if provider != "" && model != "" {
		if err := updateConfigYAML(func(cfg map[string]any) {
			m, _ := cfg["model"].(map[string]any)
			if m == nil {
				m = map[string]any{}
			}
			m["provider"] = provider
			m["default"] = model
			cfg["model"] = m
		}); err != nil {
			logger.Logf("hermes.HandleLegacy[persona]: WARN update config.yaml (%v); RenderSettings rewrites this section from the settings document before Start anyway", err)
		}
	}

	logger.Logf("hermes.HandleLegacy[persona]: prompt=%dB inference=%s/%s",
		len(p.SystemPrompt), provider, model)
	return nil
}

// ── the retired config.yaml role ────────────────────────────────────────────

// legacyConfigRole is the chain role this adapter used to declare for
// ~/.hermes/config.yaml, before the owner's settings document existed. It is
// no longer in Roles(), so bootstrap hands whatever the chain still carries
// under that name to HandleLegacy — once, before the watcher's first tick
// rebuilds the entry list from Roles() and commits it wholesale, dropping it.
//
// That drop is correct and is not worked around here: the pin's home is the
// owner's document now, and the platform persists what this recovery hands
// back (report.SeedSettings) before the entry goes. What only this package
// can do is READ the old entry — canonical JSON of the owned top-level keys
// (approvals, model, terminal), api_key stripped — which is why the branch
// exists. Without it the window is one boot wide: an agent minted before the
// channel comes up with an empty document, hermes is rendered modelless, and
// the owner's first message fails.
//
// Purely transitional, exactly as framework.LegacySettingsSeeder says. Once no
// live agent carries a "config.yaml" iData entry, this section — the const,
// the dispatch branch, handleLegacyConfig, legacyPin, isRouterBaseURL — is
// deletable in one go. The stash and SeededSettings below are NOT part of that
// deletion: attestor still mints `persona`, so the seed half of the recovery
// outlives this role.
const legacyConfigRole = "config.yaml"

// handleLegacyConfig recovers the model pin from the retired role's plaintext.
//
// Never an error. main.go's Phase C treats a HandleLegacy failure as a failed
// boot, and a legacy entry this adapter version cannot parse is not worth an
// offline container: the agent stays on whatever document attestor already
// holds. Idempotent and side-effect-free apart from the stash — config.yaml
// itself is deliberately NOT written here, because RenderSettings rebuilds
// that file from the document before every Start, so a write would be a
// second source of truth that wins only on the boots where the document is
// empty.
func (a *Adapter) handleLegacyConfig(plaintext []byte) error {
	if len(strings.TrimSpace(string(plaintext))) == 0 {
		logger.Logf("hermes.HandleLegacy[%s]: empty entry; nothing to recover", legacyConfigRole)
		return nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(plaintext, &top); err != nil {
		logger.Logf("hermes.HandleLegacy[%s]: WARN parse failed (%v); nothing recovered — the agent keeps the document attestor holds",
			legacyConfigRole, err)
		return nil
	}

	// approvals and terminal rode this entry too, and are deliberately NOT
	// carried into the recovered document's opaque framework section. They
	// are owner knobs today (frameworkOverlay, spawn.go), but sealed never
	// WROTE them: evoConfigYAML photographed whatever the installer template
	// and the running framework happened to have left on disk at the last
	// drift commit. Promoting that photograph into the owner's document would
	// make one hermes release's defaults outrank every later release's,
	// forever, in a section the platform does not parse and never revisits —
	// the same shape of bug as the 8192 max-tokens guess that got frozen into
	// a config and starved every reply. The pin is the only key in this entry
	// whose loss takes the agent down, so it is the only one this recovery
	// claims; the knobs are named in the log instead, so an owner who did
	// hand-tune one can push it back in a single command.
	var knobs []string
	for _, k := range []string{"approvals", "terminal"} {
		if _, ok := top[k]; ok {
			knobs = append(knobs, k)
		}
	}
	if len(knobs) > 0 {
		logger.Logf("hermes.HandleLegacy[%s]: the legacy entry also carries %s — not recovered; these are per-framework knobs now and ride the settings document's `framework` section if you want them",
			legacyConfigRole, strings.Join(knobs, "+"))
	}

	provider, model := legacyPin(top)
	if model == "" {
		logger.Logf("hermes.HandleLegacy[%s]: no usable pin in the legacy entry (%d bytes); nothing to recover",
			legacyConfigRole, len(plaintext))
		return nil
	}

	// Thinking is left unset, and that is a reading of the entry rather than
	// a gap in it. The retired role's key allowlist was {approvals, model,
	// terminal}; `agent` was never in it, so agent.reasoning_effort —
	// hermes's one reasoning chokepoint and the only reasoning key sealed
	// ever wrote — never reached the chain. There is nothing here to read.
	// Unset is also what REPRODUCES the old behaviour: the boot-time rewrite
	// defaulted the bound to "low" for a catalog-flagged thinking model, and
	// an unset Thinking is exactly what makes Effort() apply that same "low"
	// floor. Inventing a level to fill the field would instead pin a choice
	// the owner never made, on every future boot.
	// Lower-ranked than the mint seed, and the RANK decides — not the order
	// Phase C happened to reach the two entries in (see stashSeededPin).
	if !a.stashSeededPin(sourceLegacyConfig, settings.Doc{Provider: provider, Model: model}) {
		logger.Logf("hermes.HandleLegacy[%s]: the retired role pins %s/%s, but the mint seed's pin outranks it and is already recovered; keeping that one",
			legacyConfigRole, provider, model)
		return nil
	}
	logger.Logf("hermes.HandleLegacy[%s]: recovered pin provider=%s model=%s from the retired role; the platform will persist it as the owner's settings document",
		legacyConfigRole, provider, model)
	return nil
}

// legacyPin digs the pin out of the retired entry's `model` section, which
// evoConfigYAML captured verbatim from config.yaml:
//
//	{"model":{"base_url":"https://router-api.0g.ai/v1","default":"<model>","provider":"custom"}}
//
// Anything else — no model section, a section that is not an object, no
// `default` — is "nothing to recover", reported by an empty model.
//
// THE PROVIDER IS NOT TAKEN VERBATIM, and model.base_url is what decides.
// Every boot before the settings channel rewrote an owner's "0g-compute" into
// hermes's resolved custom-endpoint form (provider=custom + base_url=<0G
// router> + api_key) because hermes has no 0g-compute provider of its own,
// and the next drift commit uploaded THAT — keyless, since stripSecrets kept
// api_key off the chain. So a config that has been through a drift commit
// records the mechanism, not the choice. Recovering "custom" verbatim would
// be an outage, not a migration: settings.Resolve treats every provider but
// 0g-compute as a framework built-in and leaves Endpoint nil, whereupon
// RenderSettings deletes base_url and api_key and leaves hermes in custom
// mode with no endpoint to dial and no key to dial it with — a worse version
// of the keyless-custom 401 the old applyZGComputeAugmentation had to
// special-case.
//
// Hence:
//
//	base_url is a 0G    the PLATFORM wrote that endpoint, so the owner chose
//	router endpoint     0g-compute and that is what the document records —
//	                    which is also the only spelling that makes the
//	                    platform re-derive base_url and the key next boot.
//	any other base_url  the OWNER wired their own OpenAI-compatible endpoint
//	                    (hermes's custom mode dials whatever is in that key).
//	                    Reading "some base_url is set" as 0g-compute — which
//	                    this did until a review caught it — hands that agent
//	                    the 0G router and the platform's key, i.e. re-points
//	                    inference at a service the owner did not pick and
//	                    bills someone else for it. The settings document has
//	                    no vocabulary for a third-party endpoint, so nothing
//	                    about it is recoverable; the entry is treated exactly
//	                    like the no-base_url case below, which keeps the model
//	                    and leaves the endpoint to the owner's next push.
//	base_url absent     the provider names a framework built-in that brings
//	                    its own wiring ("anthropic", "openai", or a mint-time
//	                    "0g-compute" seed the rewrite never got to) and is
//	                    recovered verbatim. Except "custom": that is not a
//	                    provider an owner can have chosen, only hermes's
//	                    marker for "dial model.base_url", and with no base_url
//	                    left to dial it is dropped rather than written into
//	                    the owner's document. The pin still carries the model,
//	                    which is what keeps the document valid and the agent
//	                    one owner push away from correct.
func legacyPin(top map[string]json.RawMessage) (provider, model string) {
	raw, ok := top["model"]
	if !ok {
		return "", ""
	}
	var m struct {
		Provider string `json:"provider"`
		Default  string `json:"default"`
		BaseURL  string `json:"base_url"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		logger.Logf("hermes.HandleLegacy[%s]: WARN model section is not an object (%v); nothing recovered",
			legacyConfigRole, err)
		return "", ""
	}
	model = strings.TrimSpace(m.Default)
	if model == "" {
		return "", ""
	}
	provider = strings.TrimSpace(m.Provider)
	switch baseURL := strings.TrimSpace(m.BaseURL); {
	case isRouterBaseURL(baseURL):
		provider = inference.ZGComputeProvider
	default:
		if baseURL != "" {
			logger.Logf("hermes.HandleLegacy[%s]: WARN the legacy entry dials %s, which is not a 0G router endpoint — that is the owner's own endpoint and the settings document cannot express one, so only the model is recovered; re-point it with a settings push",
				legacyConfigRole, baseURL)
		}
		if provider == legacyCustomProvider {
			provider = ""
		}
	}
	return provider, model
}

// isRouterBaseURL reports whether a legacy entry's model.base_url is one the
// PLATFORM put there, which is the whole evidence that the owner chose
// 0g-compute.
//
// Exact match against the two constants, deliberately: sealed wrote
// route.BaseURL verbatim from them and nothing else ever wrote this key, so an
// exact match covers every entry this adapter produced, and anything it does
// not cover is by definition an endpoint sealed did not write. Both formats are
// listed even though hermes rejects anthropic-wire models (RenderSettings), so
// a hand-edited entry cannot slip through on the wire format alone.
func isRouterBaseURL(baseURL string) bool {
	switch baseURL {
	case inference.ZGOpenAIBaseURL, inference.ZGAnthropicBaseURL:
		return true
	}
	return false
}

// legacyCustomProvider is hermes's own marker for "dial model.base_url" —
// the value the pre-channel rewrite wrote next to the router endpoint, and
// never a provider name an owner selected. See legacyPin.
const legacyCustomProvider = "custom"

// ── which recovery wins ─────────────────────────────────────────────────────

// Two chain entries can carry a pre-channel agent's model pin — the mint-time
// `persona` seed and the retired `config.yaml` role — and bootstrap's Phase C
// walks the chain's iData entries in whatever order they appear (sealed/main.go).
// "Whichever HandleLegacy call ran last wins" is therefore not a rule, it is a
// coin flip, so the answer is ranked here instead:
//
//	THE PERSONA SEED WINS.
//
// Not because it is newer — it is the older of the two — but because it is the
// pin the container was ACTUALLY DIALING before this upgrade, and the only one
// of the two that records the owner's provider instead of an inference about it:
//
//   - What the old boot did with both entries present is on the record in this
//     file. Phase A restored the config.yaml role onto disk; Phase C then ran
//     ingestPersona, which wrote model.provider + model.default straight over
//     it (HandleLegacy runs after every Restore, by contract); and Start read
//     the pin back off that file (resolveInferenceFromConfigYAML, before
//     RenderSettings replaced it). So on a chain carrying both, the seed's pin
//     is the one that reached the router. Recovering it is what makes the
//     migrated document route the way the agent already routed — which is the
//     entire job of this migration.
//   - The seed says "0g-compute", the literal value the owner picked at deploy
//     and the exact spelling settings.Resolve needs to re-derive the router
//     endpoint and this boot's key. The retired role carries the resolved form
//     the pre-channel rewrite left behind (provider=custom + base_url, key
//     stripped), out of which legacyPin can only INFER the owner's choice — and
//     that inference has a floor: a base_url the platform did not write is an
//     endpoint the settings document cannot express at all, so the same entry
//     that is "later" is also the one that can come back with no provider.
//
// What the seed is NOT better at is being current: it is the mint-time model,
// so this ranking would lose a later pin — if a later pin could reach the chain
// alongside it. It cannot. The drift commit that first writes a config.yaml
// entry rebuilds the whole iData array from Roles() and drops persona in the
// same transaction, and a clone re-seals the source's live array, so a chain
// carries one or the other. The ranking is here so that the day something does
// carry both — a hand-assembled chain, a half-finished migration — the answer
// is a decision in the code rather than an accident of iteration order.
type legacySource int

const (
	// sourceLegacyConfig is the retired config.yaml role: the agent's later
	// state, but only ever an inference about the owner's provider.
	sourceLegacyConfig legacySource = iota
	// sourcePersonaSeed is the mint seed: the owner's literal choice, and the
	// pin the pre-channel boot dialed with. Highest rank.
	sourcePersonaSeed
)

// stashSeededPin records a recovered document unless something higher-ranked
// is already recorded, and reports whether it took. Equal rank overwrites,
// which is what keeps a repeat HandleLegacy call on a later boot idempotent
// instead of order-sensitive.
func (a *Adapter) stashSeededPin(src legacySource, doc settings.Doc) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.seededPin != nil && src < a.seededFrom {
		return false
	}
	a.seededPin = &doc
	a.seededFrom = src
	return true
}

// Asserted at compile time because the platform side is a type assertion
// (main.go): a signature that drifts would not fail the build, it would make
// the recovery silently stop happening, which looks exactly like an agent
// that had nothing to recover.
var _ framework.LegacySettingsSeeder = (*Adapter)(nil)

// SeededSettings implements framework.LegacySettingsSeeder: hand the recovered
// document to the platform, which persists it to attestor and renders from it.
// Only consulted when the stored document names no model, so a real document
// always outranks either recovery.
func (a *Adapter) SeededSettings() (settings.Doc, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.seededPin == nil {
		return settings.Doc{}, false
	}
	return *a.seededPin, true
}
