package prime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"seal-verify/internal/framework"
	"seal-verify/internal/inference"
	"seal-verify/internal/logger"
	"seal-verify/internal/settings"
)

// models.json — Prime Agent's native model registration, RENDERED from the
// owner's settings document at every Start. Not a chain role any more.
//
// It was one, for a reason that has been dissolved rather than dismissed. The
// inference pin arrived in the mint-time `persona` seed; the uploader drops
// every chain entry outside Roles(), so the seed left the chain at the first
// drift commit and every later boot came up with no model at all (found live,
// agent 271). Making the FILE a tracked role gave the pin a durable home. The
// settings document is a better one: the owner owns it, it is not conveyed on
// transfer, and — because this file is rebuilt from it on every boot — a fix
// shipped after an agent was minted actually reaches that agent instead of
// losing to a mint-time copy restored over it.
//
// The one trace the change leaves behind is on CHAIN: an agent minted while
// this was a role still carries that entry, and it holds the only copy of its
// pin. HandleLegacy reads the pin out of it exactly once, at the bottom of
// this file, before the watcher's first tick drops the entry.
//
// That is what killed backfillMaxTokens. It existed to heal machine-written
// values inside a restored copy: entries minted before modelEntry.MaxTokens
// existed, and budgets poisoned by the heuristic's 8192 during a catalog
// outage (which starves a reasoning model's shared thinking+reply budget into
// permanently empty replies — live on agent 404, three ~6min turns, textLen=0).
// Nothing is restored now, so there is nothing to heal: the budget below is
// recomputed from the live catalog every boot, and gated on
// Resolved.PersistableMaxTokens so a guess made during an outage is omitted
// rather than written down.
//
// The file itself still has to exist, and that is not a leftover:
//
//   - the SDK's ModelRegistry reads it out of the agent dir, and it is the
//     ONLY way to register a provider the SDK has no built-in for. The 0G
//     router is exactly that — no environment variable redirects a built-in
//     provider at another endpoint; setting OPENAI_BASE_URL is ignored, the
//     request goes to api.openai.com with the router's key and returns 401
//     "incorrect API key", which reads like a credential problem and hides the
//     real cause (verified live on 0G Galileo, 2026-08-13);
//   - it carries the flags that let the SDK put reasoning_effort on the wire
//     at all (see modelEntry.Reasoning).
//
// A built-in provider needs neither, so unless the owner's overlay has
// something to say about it, the render writes no file for one.
//
// The PLATFORM writes no secret into it: the apiKey it renders holds the NAME
// of an environment variable (apiKeyEnvRef), which the framework resolves at
// use time. That is a statement about the platform's half only. The owner's
// overlay is opaque bytes and can put a literal key in a provider entry of its
// own; nothing here strips one. What bounds that is this file not being a
// tracked role (paths.go) — a secret an owner pastes into it stays in the
// container and never reaches chain.

// apiKeyEnvRef is the env var the models.json entry points at, rather than a
// literal key. Must match what bridgeEnv.environ exports.
const apiKeyEnvRef = "SEAL_MODEL_API_KEY"

type modelEntry struct {
	ID string `json:"id"`
	// MaxTokens is the model's OUTPUT budget per call (the SDK sends it as
	// max_tokens). Filled from Resolved.PersistableMaxTokens (the router
	// catalog's max_completion_tokens); omitted — SDK default 16384 — for a
	// budget the catalog did not supply.
	MaxTokens int `json:"maxTokens,omitempty"`
	// Reasoning marks the model as a thinking model. Required for the SDK to
	// send reasoning_effort at all (its gate is reasoning && compat
	// supportsReasoningEffort && a session thinking level) — and glm-5.3
	// without that parameter reasons unboundedly and never writes a reply
	// (see inference.ModelFacts.SupportsReasoningEffort).
	//
	// The gate reads the RESOLVED MODEL's registry entry, which is this one
	// only for a provider registered in this file. For a framework built-in
	// the same gate reads the SDK's own tables, which this adapter neither
	// writes nor can see — so for a built-in the platform supplies the level
	// and the framework decides whether it goes on the wire.
	Reasoning bool `json:"reasoning,omitempty"`
	// ThinkingLevelMap declares this model's accepted levels and their wire
	// spellings, so the SDK validates against OUR set instead of clamping to
	// its own (which silently rewrites levels — lab-measured). Every entry
	// resolves to a level the 0g router can actually finish: low and high
	// verbatim; medium (router 400s it) and max (measured-unusable there:
	// reasoning out-runs the ~600s stream kill) both land on safe values, so
	// even an agent that sets its own session level never dials a lethal one.
	ThinkingLevelMap map[string]string `json:"thinkingLevelMap,omitempty"`
}

// portableThinkingLevels is the level set written for catalog-flagged
// thinking models — see modelEntry.ThinkingLevelMap.
func portableThinkingLevels() map[string]string {
	return map[string]string{"low": "low", "medium": "low", "high": "high", "max": "max"}
}

type providerCfg struct {
	BaseURL    string          `json:"baseUrl"`
	API        string          `json:"api"`
	APIKey     string          `json:"apiKey"`
	AuthHeader bool            `json:"authHeader"`
	Compat     map[string]bool `json:"compat,omitempty"`
	Models     []modelEntry    `json:"models"`
}

type modelsConfig struct {
	Providers map[string]providerCfg `json:"providers"`
}

// RenderSettings implements framework.Framework: it puts the owner's settings
// where Prime Agent reads them.
//
// Prime Agent reads them in two places, so this writes to two:
//
//   - models.json, for a provider the SDK has no built-in for (see the file
//     comment above);
//   - the Resolved value itself, stashed for Start, which turns it into the
//     bridge's SEAL_MODEL_* environment. The reasoning LEVEL travels that way
//     and only that way — models.json never holds one — which is why a
//     built-in provider, for which no file may be written at all, still gets
//     a level. Whether the level reaches the wire is a separate question the
//     framework answers from the model's registry entry (modelEntry.Reasoning).
//
// Idempotent: the bytes are a pure function of Resolved (Go sorts map keys, so
// the generic-JSON merge below is deterministic), and the stash is a plain
// overwrite. Nothing checks the rendered bytes afterwards — the watcher does
// not hash this file (it is not a tracked role) and Start reads the stash, not
// the file.
func (a *Adapter) RenderSettings(ctx context.Context, s settings.Resolved) error {
	blob, err := renderModelsJSON(s)
	if err != nil {
		return fmt.Errorf("prime.RenderSettings: %w", err)
	}
	if blob == nil {
		// Built-in provider and no overlay: nothing to register. Remove any
		// file an earlier render left — an owner who moves from the router to
		// a built-in must not keep a registration aimed at the old endpoint,
		// and this file is an artifact, so there is no agent state to lose.
		if err := os.Remove(modelsJSONPath()); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("prime.RenderSettings: remove stale %s: %w", modelsJSONPath(), err)
		}
	} else {
		if err := ensureDir(primeHome); err != nil {
			return fmt.Errorf("prime.RenderSettings: %w", err)
		}
		if err := os.WriteFile(modelsJSONPath(), blob, 0o644); err != nil {
			return fmt.Errorf("prime.RenderSettings: write %s: %w", modelsJSONPath(), err)
		}
	}

	a.mu.Lock()
	a.settings = &s
	a.mu.Unlock()

	claim := reasoningClaimFor(s)
	logger.Logf("prime.RenderSettings: %s/%s effort=%q decided=%v registered=%v maxTokens=%d",
		s.Provider, s.Model, claim.level, claim.decided, blob != nil, s.PersistableMaxTokens())
	if !claim.decided {
		logger.Logf("prime.RenderSettings: WARN the router catalog did not say whether %s takes a reasoning bound, so the registration claims nothing about it; if this model always thinks and nothing else marks it, it can reason unbounded — set a thinking level to pin one",
			s.Model)
	}
	return nil
}

// renderModelsJSON builds the registration bytes, or nil when this agent needs
// no registration at all.
//
// Order is the contract (framework.Framework.RenderSettings): the owner's
// opaque overlay goes down FIRST and the platform's keys are written over it.
// Ordering rather than an exclusion list is what lets an overlay add whatever
// the framework understands while never disabling bounded reasoning or pinning
// a base URL the catalog has since moved.
//
// That holds on BOTH paths, which is a hole this function shipped with: the
// built-in-provider path emitted the overlay verbatim, with zero platform keys
// over it. An overlay that redefined the PINNED provider — say
// providers.anthropic.baseUrl — therefore sent the agent's inference, and the
// credential the bridge exports for it, wherever the document said, and could
// clear the very reasoning flags the bound depends on.
//
// The paths differ only in what the platform is in a position to state:
//
//   - platform-routed (s.Endpoint != nil): the platform knows the whole
//     wiring and registers the provider outright.
//   - framework built-in (s.Endpoint == nil): the framework owns the wiring,
//     so the platform's value for every wiring key is ABSENT. It corrects a
//     pinned-provider entry the overlay declared — model entry and reasoning
//     flags written over it, wiring deleted — and writes nothing otherwise,
//     leaving the framework's built-in table to do its job.
//
// Consequence, deliberate: an overlay can no longer point the PINNED model at
// an endpoint of its own. Registering some other provider still works, and
// pointing the pinned model somewhere is what settings.Doc.Provider =
// inference.ZGComputeProvider is for.
func renderModelsJSON(s settings.Resolved) ([]byte, error) {
	doc := map[string]any{}
	if len(bytes.TrimSpace(s.Others)) > 0 {
		// Opaque by contract: decoded as generic JSON, never interpreted.
		// UseNumber so an owner's integer never round-trips into 1e+06.
		dec := json.NewDecoder(bytes.NewReader(s.Others))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			// A malformed overlay is the owner's mistake and must not take the
			// boot down with it — the platform half still renders.
			logger.Logf("prime.RenderSettings: ignoring the framework overlay, not a JSON object: %v", err)
			doc = map[string]any{}
		}
		if doc == nil { // a literal `null` leaves the map untouched
			doc = map[string]any{}
		}
	}

	claim := reasoningClaimFor(s)
	switch {
	case s.Endpoint != nil:
		owned, err := jsonObject(modelsConfig{Providers: map[string]providerCfg{s.Provider: routedProvider(s, claim)}})
		if err != nil {
			return nil, err
		}
		doc = mergeJSONObjects(doc, owned)
	case declaresProvider(doc, s.Provider):
		owned, err := jsonObject(map[string]any{"providers": map[string]any{
			s.Provider: builtinOverride{Compat: claim.compat(nil), Models: []modelEntry{platformModel(s, claim)}},
		}})
		if err != nil {
			return nil, err
		}
		doc = mergeJSONObjects(doc, owned)
		dropBuiltinWiring(doc, s.Provider)
	}
	if len(doc) == 0 {
		return nil, nil
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal models.json: %w", err)
	}
	return out, nil
}

// builtinOverride is the platform's half of a provider entry the FRAMEWORK
// wires itself. No endpoint, no credential, no auth scheme — those are exactly
// what the built-in supplies — just the two things the platform knows about
// the pinned model regardless of who serves it.
type builtinOverride struct {
	Compat map[string]bool `json:"compat,omitempty"`
	Models []modelEntry    `json:"models"`
}

// builtinWiringKeys name WHERE a request goes and what it carries. On the
// built-in path the platform's value for each is "absent", and absence is the
// one value a key-by-key merge cannot write — hence an explicit delete.
var builtinWiringKeys = []string{"baseUrl", "api", "apiKey", "authHeader"}

// dropBuiltinWiring removes owner-supplied wiring from the pinned provider's
// entry. Loud, because it changes where the agent's inference goes relative to
// what the owner wrote, and a silent strip would read as the SDK misbehaving.
func dropBuiltinWiring(doc map[string]any, provider string) {
	providers, _ := doc["providers"].(map[string]any)
	entry, _ := providers[provider].(map[string]any)
	if entry == nil {
		return
	}
	var dropped []string
	for _, k := range builtinWiringKeys {
		if _, present := entry[k]; !present {
			continue
		}
		delete(entry, k)
		dropped = append(dropped, k)
	}
	if len(dropped) > 0 {
		logger.Logf("prime.RenderSettings: dropped %v from the overlay's providers.%s — that provider serves the pinned model as a framework built-in, so the framework supplies its own wiring; pin an endpoint by routing the model through the platform (provider %q) instead",
			dropped, provider, inference.ZGComputeProvider)
	}
}

// declaresProvider reports whether the overlay has anything to say about this
// provider. The built-in path only writes over an entry the owner created:
// inventing one for a provider the SDK already knows would replace a working
// built-in registration with a half-filled one.
func declaresProvider(doc map[string]any, provider string) bool {
	providers, _ := doc["providers"].(map[string]any)
	if providers == nil {
		return false
	}
	_, ok := providers[provider]
	return ok
}

// reasoningClaim is what the platform can honestly say about this model's
// reasoning bound on this boot: the three outcomes of
// settings.Resolved.Effort, kept apart instead of collapsed into one string.
//
//	{"high", true}   the model takes a bound — write the flags and the level
//	{"",     true}   the catalog says this model REJECTS reasoning_effort;
//	                 say so, because sending it is a hard 400
//	{"",     false}  the catalog was unreachable or silent about this model.
//	                 The platform states NOTHING — no reasoning flag, no
//	                 compat key — because both available claims are wrong:
//	                 false strips the bound from an always-thinking model
//	                 (unbounded reasoning, empty replies, the failure this
//	                 whole mechanism exists to prevent), true earns a 400 from
//	                 a model that takes no bound. Saying nothing leaves the
//	                 judgement with the framework's own model metadata, which
//	                 is the only party that still knows anything.
type reasoningClaim struct {
	level   string
	decided bool
	// carried marks a claim recovered from the previous render rather than
	// from the catalog. Logged, so an outage boot that keeps a bound says so.
	carried bool
}

func reasoningClaimFor(s settings.Resolved) reasoningClaim {
	level, decided := s.Effort()
	c := reasoningClaim{level: level, decided: decided}
	if decided {
		return c
	}
	// Undecided means the router catalog was unreachable or silent about this
	// model — we know nothing, so we must not ASSERT anything. But this
	// renderer rebuilds the whole document each boot, so contributing nothing
	// is not neutral here the way it is for a merging renderer: it drops the
	// claim a previous, catalog-backed boot already established, and an
	// always-thinking model with no bound reasons without end and never
	// replies. Carry the previous claim forward instead.
	if prev, ok := previousReasoning(s.Provider, s.Model); ok {
		prev.carried = true
		return prev
	}
	return c
}

// previousReasoning recovers the reasoning claim the last render wrote for
// this provider+model, so an outage boot can keep it rather than silently
// retracting it. Absent file, absent entry or a different model all mean
// "nothing to carry".
func previousReasoning(provider, model string) (reasoningClaim, bool) {
	raw, err := os.ReadFile(modelsJSONPath())
	if err != nil {
		return reasoningClaim{}, false
	}
	var cfg struct {
		Providers map[string]struct {
			Compat map[string]bool `json:"compat"`
			Models []struct {
				ID               string            `json:"id"`
				Reasoning        bool              `json:"reasoning"`
				ThinkingLevelMap map[string]string `json:"thinkingLevelMap"`
			} `json:"models"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return reasoningClaim{}, false
	}
	p, ok := cfg.Providers[provider]
	if !ok {
		return reasoningClaim{}, false
	}
	for _, m := range p.Models {
		if m.ID != model {
			continue
		}
		if !m.Reasoning {
			// A previous boot decided this model takes no bound. That is a
			// claim too, and retracting it would start sending a parameter
			// the model hard-400s on.
			return reasoningClaim{level: "", decided: true}, true
		}
		lvl := "low"
		if _, ok := m.ThinkingLevelMap["high"]; ok && len(m.ThinkingLevelMap) > 0 {
			// The map records the offered set, not the chosen level; the
			// chosen one lives in the owner document and is re-applied by the
			// bridge. Any non-empty level keeps Reasoning true, which is the
			// bit that matters here.
			lvl = "low"
		}
		return reasoningClaim{level: lvl, decided: true}, true
	}
	return reasoningClaim{}, false
}

// compat renders the claim into the provider's compat block, on top of
// whatever else the platform owns there. An undecided claim contributes no
// key at all.
func (c reasoningClaim) compat(base map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k, v := range base {
		out[k] = v
	}
	if c.decided {
		out["supportsReasoningEffort"] = c.level != ""
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// platformModel is the pinned model's entry. Provider-independent by
// construction: a model that takes a reasoning bound takes it wherever it is
// served, so nothing here consults s.Endpoint — endpoint wiring is the only
// thing a provider check may decide.
func platformModel(s settings.Resolved, c reasoningClaim) modelEntry {
	e := modelEntry{
		ID: s.Model,
		// Catalog-sourced only: a heuristic guess written here during an
		// outage is worse than the SDK's own default (see the file comment's
		// agent-404 incident).
		MaxTokens: s.PersistableMaxTokens(),
	}
	if c.decided && c.level != "" {
		e.Reasoning = true
		e.ThinkingLevelMap = portableThinkingLevels()
	}
	return e
}

// routedProvider is the provider entry the PLATFORM owns when it routes the
// model itself: endpoint, wire API, credential reference, output budget and
// the reasoning flags. Whatever the overlay said about these keys, this wins.
func routedProvider(s settings.Resolved, c reasoningClaim) providerCfg {
	return providerCfg{
		BaseURL:    s.Endpoint.BaseURL,
		API:        wireAPI(s.Endpoint.Format),
		APIKey:     apiKeyEnvRef,
		AuthHeader: true,
		// supportsDeveloperRole is off because a third-party
		// OpenAI-compatible endpoint generally does not understand the
		// `developer` role. It is the platform's to state here and only here:
		// this endpoint is one the platform wired.
		Compat: c.compat(map[string]bool{"supportsDeveloperRole": false}),
		Models: []modelEntry{platformModel(s, c)},
	}
}

// wireAPI is the framework's name for a wire format. Used by BOTH the
// registration file and the bridge environment (SEAL_MODEL_API), which have to
// agree — they describe one endpoint.
func wireAPI(f inference.WireFormat) string {
	if f == inference.WireAnthropic {
		return "anthropic-messages"
	}
	return "openai-completions"
}

// jsonObject re-encodes a typed value as generic JSON so it can be merged with
// the owner's opaque overlay. UseNumber for the same reason as above.
func jsonObject(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal models.json: %w", err)
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("marshal models.json: %w", err)
	}
	return m, nil
}

// mergeJSONObjects writes `over` on top of `base`: objects merge key by key,
// recursively; every other value replaces outright — so the platform's models
// array IS the models array rather than an append to the owner's.
func mergeJSONObjects(base, over map[string]any) map[string]any {
	if base == nil {
		base = map[string]any{}
	}
	for k, ov := range over {
		bm, baseIsObj := base[k].(map[string]any)
		om, overIsObj := ov.(map[string]any)
		if baseIsObj && overIsObj {
			base[k] = mergeJSONObjects(bm, om)
			continue
		}
		base[k] = ov
	}
	return base
}

// ── the retired models.json role ────────────────────────────────────────────

// legacyModelsRole is the chain role this adapter used to declare for the
// model registration, before the owner's settings document existed. It is no
// longer in Roles(), so bootstrap hands whatever the chain still carries under
// that name to HandleLegacy — once, before the watcher's first tick rebuilds
// the entry list from Roles() and drops it.
//
// That drop is correct and is not worked around here: the pin's home is the
// owner's document now, and the platform persists what this recovery hands
// back (report.SeedSettings) before the entry goes. What only this package can
// do is READ the old entry, which is why the branch exists. For THIS adapter
// the stakes are the highest of the four: Start hard-fails without a pin
// (spawn.go), so an unrecovered agent does not degrade, it goes offline.
//
// Transitional by construction (see framework.LegacySettingsSeeder): once no
// live agent carries this role, everything below this line can be deleted.
const legacyModelsRole = "models.json"

// legacySource ranks the retired chain roles a pin can be recovered from.
// Higher wins. The rank exists because bootstrap's Phase C walks the chain
// entries in whatever order they arrived (main.go), so "whichever branch ran
// last" is a coin flip, not a rule — and two branches stash now.
//
// THE RETIRED models.json ROLE OUTRANKS THE MINT-TIME persona SEED. Both
// describe the same agent, so the only question is which of the two documents
// routes the way the agent was routing on its last boot before this upgrade.
//
//   - persona is frozen at mint. It is the ONLY record for an agent that never
//     committed drift — exactly the gap it is here to fill — but for an agent
//     that did drift it is a snapshot of a route that may have been replaced
//     many boots ago. models.json is what the SDK read at every boot after the
//     first: the seed's pin was translated into it once, and any later re-pin
//     (that file was chain-tracked AND agent-writable) exists there and nowhere
//     else. Preferring the seed would roll such an agent back to a model it
//     stopped using, which is the opposite of routing the way it was.
//   - The one field the seed is strictly more faithful about — the provider,
//     which it names as the OWNER picked it ("0g-compute") where the
//     registration carries the label the platform resolved it into — is
//     already recovered from the registration: pinProvider un-resolves that
//     label from the router baseUrl sealed itself wrote beside the pin. So
//     preferring persona buys no provider fidelity and costs model fidelity.
//
// In practice the two never coexist — the first drift commit rebuilds the
// chain array from Roles() wholesale and persona is not in it, so an agent
// carries the registration or the mint seed, never both. The rank is what
// makes that an invariant this code does not have to depend on.
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
	if a.seededFrom > src {
		return false
	}
	a.seededPin = &doc
	a.seededFrom = src
	return true
}

// handleLegacyModels recovers the inference pin from the retired role's
// plaintext. Never an error: a legacy entry this adapter version cannot read
// must not stop a boot, it just leaves the agent on whatever document attestor
// already holds.
//
// Side-effect-free apart from the stash — nothing is written to disk, so a
// later boot that still finds the chain entry recovers the same pin again.
func (a *Adapter) handleLegacyModels(plaintext []byte) error {
	provider, model := legacyPin(plaintext)
	if provider == "" || model == "" {
		// BOTH halves or nothing. Start refuses an empty provider exactly as
		// it refuses an empty model, and what comes back from here is
		// persisted as the owner's document — so a half-pin would not be a
		// partial recovery, it would be a stored document that fails every
		// future boot until the owner notices.
		logger.Logf("prime.HandleLegacy[%s]: no usable pin in the legacy entry (%d bytes); nothing to recover",
			legacyModelsRole, len(plaintext))
		return nil
	}

	// Provider + model, and deliberately nothing else. Everything else the old
	// entry carries — baseUrl, api, apiKey, authHeader, compat, maxTokens — is
	// platform-derived and is recomputed from the catalog at every render now.
	// Carrying a stale copy forward is precisely the 8192-max-tokens incident
	// (see the file comment: agent 404, three ~6min turns, empty replies).
	//
	// `thinking` stays UNSET, and that is a recovery, not an omission: the old
	// entry's `reasoning` / `thinkingLevelMap` record that the model TAKES a
	// bound and which levels are offered — portableThinkingLevels writes the
	// same map whatever level is in force — never which level the owner chose.
	// That choice travelled in the deploy payload's env (SEAL_OWNER_THINKING),
	// not in this file, so there is nothing here to read. Deriving a level from
	// these flags would invent a configuration the owner never made; unset lets
	// Effort() decide it from the catalog as it does for every other agent.
	doc := settings.Doc{Provider: provider, Model: model}

	// Top of the rank (legacySource): this wins over a mint seed recovered by
	// the persona branch, whichever of the two Phase C reached first.
	a.stashSeededPin(sourceConfig, doc)

	logger.Logf("prime.HandleLegacy[%s]: recovered pin provider=%s model=%s from the retired role; the platform will persist it as the owner's settings document",
		legacyModelsRole, provider, model)
	return nil
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

// Transitional, like the rest of this section (see legacyModelsRole): the
// assertion goes when the implementation does. It is load-bearing until then —
// bootstrap reaches this method through a type assertion (main.go), so an
// adapter that stopped satisfying the interface would not fail to compile, it
// would silently skip the recovery, and for THIS adapter a skipped recovery is
// an offline container rather than a degraded one.
var _ framework.LegacySettingsSeeder = (*Adapter)(nil)

// legacyPin digs provider + model out of the retired role's plaintext.
//
// The wire encoding is the framework's own model registration, canonical JSON
// (buildModelsConfig's output), shaped
//
//	{"providers":{"<provider>":{"baseUrl":…,"api":…,"apiKey":"SEAL_MODEL_API_KEY",
//	 "models":[{"id":"<model>",…}]}}}
//
// Anything else — a blank entry, a parse failure, a file with no model — is
// "nothing to recover", reported by an empty result. An agent that pinned a
// framework built-in never had such an entry at all (nothing to register), and
// neither did one that promoted nothing to chain; that is the normal case, not
// an error. Neither of those agents is left unrecovered: their pin is still in
// the mint seed, and the persona branch reads it out (persona.go).
func legacyPin(plaintext []byte) (provider, model string) {
	if len(bytes.TrimSpace(plaintext)) == 0 {
		return "", ""
	}
	// Parsed through a shape of its own rather than through modelsConfig: this
	// describes bytes already written on chain, which no later change to the
	// renderer's structs may retroactively reinterpret.
	var cfg struct {
		Providers map[string]struct {
			BaseURL string `json:"baseUrl"`
			Models  []struct {
				ID string `json:"id"`
			} `json:"models"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(plaintext, &cfg); err != nil {
		logger.Logf("prime.HandleLegacy[%s]: WARN parse failed (%v); nothing recovered", legacyModelsRole, err)
		return "", ""
	}

	// One candidate per provider that names a model, in sorted order, so a
	// multi-provider file (which this adapter never wrote, but the file was
	// agent-writable AND chain-tracked, so an agent edit could have left one)
	// recovers the same pin on every boot instead of one picked by map order.
	names := make([]string, 0, len(cfg.Providers))
	for name := range cfg.Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	type candidate struct{ name, baseURL, model string }
	cands := make([]candidate, 0, len(names))
	for _, name := range names {
		entry := cfg.Providers[name]
		for _, m := range entry.Models {
			if m.ID != "" {
				cands = append(cands, candidate{name: name, baseURL: entry.BaseURL, model: m.ID})
				break
			}
		}
	}
	if len(cands) == 0 {
		return "", ""
	}

	// Sorted order alone is deterministic but not RIGHT when several providers
	// are registered: it recovers whichever name sorts first, which for
	// {"anthropic", "openai"@router} is the built-in the agent was not running
	// — a pin that names a provider the SDK will send somewhere else entirely.
	// The platform's own entry is the one the agent was routing through, so it
	// wins; sorted order only breaks ties among the rest.
	pick := cands[0]
	for _, c := range cands {
		if isPlatformRoute(c.name, c.baseURL) {
			pick = c
			break
		}
	}
	if pick != cands[0] {
		logger.Logf("prime.HandleLegacy[%s]: the legacy entry registers %d providers; recovering the platform-routed one (%s/%s) rather than %q, which the agent was not running",
			legacyModelsRole, len(cands), pick.name, pick.model, cands[0].name)
	}
	return pinProvider(pick.name, pick.baseURL), pick.model
}

// isPlatformRoute reports whether a legacy provider entry is the one the
// PLATFORM routed: it points at the 0g router, or it is keyed by the provider
// name that means "the platform routes this" (which is how this adapter's own
// writer keyed it, and which pinProvider keeps verbatim).
//
// Only consulted to choose between several entries — a file naming one
// provider recovers that one whatever this says.
func isPlatformRoute(name, baseURL string) bool {
	return isZGRouterURL(baseURL) || name == inference.ZGComputeProvider
}

// pinProvider spells the recovered provider the way the SETTINGS DOCUMENT
// spells it, which is not always the way the old entry did.
//
// The document's provider field is a routing decision: inference.Resolve hands
// back an endpoint for inference.ZGComputeProvider and for nothing else, so a
// pin recovered under any other name is treated as a framework built-in and
// the SDK sends it to that provider's own endpoint — with the router's
// credential, earning the 401 "incorrect API key" the file comment above
// records. The old entry's baseUrl is what settles which it was.
//
// This adapter's own writer keyed the entry "0g-compute" for a routed model,
// so the rewrite is usually a no-op. It is here for the entry the adapter did
// not write: models.json was agent-writable and chain-tracked at the same
// time, so the bytes on chain may name the router under any key at all.
func pinProvider(name, baseURL string) string {
	if !isZGRouterURL(baseURL) {
		// A built-in, or an endpoint someone set by hand. Either way the name
		// stands. A hand-set endpoint itself is NOT carried: settings.Doc has
		// no field for one, by design — the platform computes endpoints.
		return name
	}
	if name != inference.ZGComputeProvider {
		logger.Logf("prime.HandleLegacy[%s]: the legacy entry registers %q at the 0g router; recovering it as provider %q, which is how the settings document asks the platform to route (recovering it verbatim would send inference to %s's own endpoint with the router's key)",
			legacyModelsRole, name, inference.ZGComputeProvider, name)
	}
	return inference.ZGComputeProvider
}

// isZGRouterURL reports whether a legacy entry's baseUrl points at the 0g
// router.
//
// Compared by HOSTNAME, not by prefix: the two router constants differ only in
// the path (the OpenAI one appends /v1), and a prefix test would also accept a
// look-alike host like router-api.0g.ai.example.com — which would rewrite that
// pin to "the platform routes this" and silently move the agent's inference.
//
// The PORT is deliberately outside the comparison. It used to be inside it
// (u.Host carries one), so a baseUrl written "https://router-api.0g.ai:443/v1"
// — the same endpoint as the constant, spelled explicitly — did not match, and
// the pin was recovered as a framework built-in: the exact misroute this
// rewrite exists to prevent. The two mistakes are not symmetric, which is what
// settles the rule. Failing to recognise the router sends the agent's
// inference, and the router credential the bridge exports, to some other
// provider's own endpoint (401 "incorrect API key", which reads like a
// credential problem). Recognising it on an unusual port only asks the
// platform to route the pin — and the platform then computes the endpoint
// itself, because settings.Doc carries no URL, so no address an owner typed is
// ever followed. Prefer the recoverable error.
func isZGRouterURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return false
	}
	router, err := url.Parse(inference.ZGAnthropicBaseURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), router.Hostname())
}
