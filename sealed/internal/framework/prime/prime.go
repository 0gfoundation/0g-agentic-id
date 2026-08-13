// Package prime is the framework adapter for Prime Agent (Prime Intellect) —
// a self-improving RLM harness whose durable identity is its Continual
// Harness state.
//
// Role set:
//
//	framework            Leaf — 3-field binding JSON (package_version = the
//	                     Prime Agent RELEASE version, e.g. 0.7.2 — not the npm
//	                     version, which is a different series; see whitelist.go)
//	harness_state.json   Leaf — the GLOBAL half of ~/.prime/agent/harness/
//	                     harness_state.json, canonical JSON, `refinements`
//	                     dropped (harness.go)
//	APPEND_SYSTEM.md     Leaf — owner persona, verbatim bytes (persona.go)
//	skills/              DirectoryManifest — agent-installed Python skill
//	                     packages under ~/.prime/agent/skills/ (skills.go)
//
// What makes this adapter unusual: Prime Agent rewrites its own prompts,
// memories and skills MID-TASK, not just between tasks. That would be a
// drift nightmare except the framework already splits its state into a
// per-session ("local") file and a cross-session ("global") one, and only an
// explicit promote crosses over. Tracking the global half alone gives us
// "durable identity" for free, with no drift-rate tuning — see paths.go.
//
// File map:
//   - prime.go        Adapter struct + framework.Framework interface methods
//   - paths.go        on-disk paths (+ the do-not-track list and why)
//   - whitelist.go    validated release version set (and why not npm)
//   - harness.go      harness_state.json canonicalization (the identity anchor)
//   - skills.go       the skills/ manifest role
//   - persona.go      APPEND_SYSTEM.md + HandleLegacy persona ingestion
//   - platformtext.go FrameworkFacts (this framework's blanks in the agent doc)
//   - spawn.go        Start/Stop/probes + version pin + bridge supervision
//   - bridge/bridge.mjs  the go:embed'ed HTTP bridge (see spawn.go)
//
// Prime Agent has no HTTP surface of its own — its daemon speaks JSONL over a
// local socket — so sealed ships its own bridge, which embeds the SDK and
// exposes exactly one OpenAI-shaped chat endpoint. That inverts the usual
// exposure problem: instead of auditing a framework's built-in dashboard for
// shell/file/exec reach, the public surface here is a whitelist by
// construction.
package prime

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/manifest"
)

// frameworkName is the adapter id and the `name` field of the framework
// binding. Selection at boot matches on this exact string.
const frameworkName = "prime-agent"

// Adapter is the Prime Agent implementation of framework.Framework.
type Adapter struct {
	mu sync.RWMutex

	// binding is the composed framework-role state (name + pinned version).
	binding frameworkBinding

	// persona* hold the mint-time inference pin from the `persona` seed. Prime
	// Agent is model-agnostic, so the pin becomes a session setting at Start
	// rather than a config-file rewrite.
	personaProvider string
	personaModel    string

	// cmd is the running bridge process; nil before Start / after Stop.
	cmd *exec.Cmd

	// bridgeToken gates the bridge's /v1/* surface and is what AuthResponse
	// hands a verified owner. Minted once per container, memory-only.
	bridgeToken string

	// initialized flips after the first successful Start. Subsequent Starts
	// (supervisor restarts, Reload) skip the install so agent
	// self-modifications survive restart untouched.
	initialized bool
}

// frameworkBinding is the protocol-reserved "framework" role's plaintext.
// Field order is the marshal order.
type frameworkBinding struct {
	Name           string `json:"name"`
	PackageVersion string `json:"package_version"`
	SchemaVersion  int    `json:"schema_version"`
}

// New builds the adapter and self-registers it under frameworkName.
//
// NOTE: main.go does not call this yet — see the STATUS note in the package
// doc. Registration lives here so wiring it up later is one line there.
func New() *Adapter {
	a := &Adapter{
		binding: frameworkBinding{
			Name:           frameworkName,
			PackageVersion: whitelistMax(),
			SchemaVersion:  1,
		},
	}
	framework.Register(frameworkName, a)
	return a
}

func (a *Adapter) Name() string { return frameworkName }

// probePrimeVersion reports the installed framework version. A swappable
// package var because any external probe that can feed canonical plaintext
// must be stubbable in tests (FRAMEWORK_ADAPTER.md §10) — a real install on a
// dev machine must never leak into round-trip results.
//
// Returns "" until Start exists to install a pinned version; EvolutionFor
// deliberately does NOT consult it yet, so the framework role's plaintext is a
// pure function of what was restored.
var probePrimeVersion = func(ctx context.Context) string { return "" }

// Version is a best-effort runtime probe. Not consumed by core code today
// (FRAMEWORK_ADAPTER.md §2.2).
func (a *Adapter) Version(ctx context.Context) (string, error) {
	if v := probePrimeVersion(ctx); v != "" {
		return v, nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.binding.PackageVersion, nil
}

func (a *Adapter) Roles() []framework.RoleSpec {
	return []framework.RoleSpec{
		{Name: "framework", Shape: framework.Leaf},
		{Name: "harness_state.json", Shape: framework.Leaf},
		{Name: "APPEND_SYSTEM.md", Shape: framework.Leaf},
		{Name: "models.json", Shape: framework.Leaf},
		{Name: "skills/", Shape: framework.DirectoryManifest},
	}
}

// Defaults returns the canonical "empty/zero" plaintext for a role.
//
//   - "framework": adapter name + whitelistMax + schema 1
//   - "harness_state.json": nil — an agent that has promoted nothing to global
//     scope has no durable harness identity, so no chain entry
//   - "APPEND_SYSTEM.md": nil — an absent persona is "no content"
//   - "skills/": empty Manifest
func (a *Adapter) Defaults(role string) []byte {
	switch role {
	case "framework":
		b, err := json.Marshal(&frameworkBinding{
			Name:           frameworkName,
			PackageVersion: whitelistMax(),
			SchemaVersion:  1,
		})
		if err != nil {
			return nil
		}
		return b
	case "harness_state.json", "APPEND_SYSTEM.md", "models.json":
		return nil
	case "skills/":
		b, err := manifest.New().Marshal()
		if err != nil {
			return nil
		}
		return b
	}
	return nil
}

// Restore applies one role's plaintext to disk / composed state. Calls
// commute across roles and are idempotent per role.
func (a *Adapter) Restore(ctx context.Context, role string, plaintext []byte) error {
	switch role {
	case "framework":
		return a.restoreFramework(plaintext)
	case "harness_state.json":
		return a.restoreHarnessState(plaintext)
	case "APPEND_SYSTEM.md":
		return a.restoreAppendSystem(plaintext)
	case "models.json":
		return a.restoreModelsJSON(plaintext)
	case "skills/":
		return a.restoreManifestDir(plaintext)
	}
	// Unknown roles are not an error: bootstrap routes them to HandleLegacy.
	logger.Logf("prime.Restore: ignoring unknown role %q", role)
	return nil
}

// restoreFramework composes the binding. A binding naming a DIFFERENT
// framework fails loud: selection and adapter disagree about what this agent
// is, and booting anyway would forge identity (FRAMEWORK_ADAPTER.md §3).
// An empty/absent package_version resolves to whitelistMax, because version
// knowledge lives with the code that validates versions, not with attestor.
func (a *Adapter) restoreFramework(plaintext []byte) error {
	next := frameworkBinding{Name: frameworkName, PackageVersion: whitelistMax(), SchemaVersion: 1}
	if len(plaintext) > 0 {
		var got frameworkBinding
		if err := json.Unmarshal(plaintext, &got); err != nil {
			return fmt.Errorf("prime.Restore[framework]: parse: %w", err)
		}
		if got.Name != "" && got.Name != frameworkName {
			return fmt.Errorf("prime.Restore[framework]: binding names %q, this adapter is %q — refusing to forge identity", got.Name, frameworkName)
		}
		if got.SchemaVersion != 0 {
			next.SchemaVersion = got.SchemaVersion
		}
		next.PackageVersion = coerceWhitelisted(got.PackageVersion)
		if got.PackageVersion != "" && got.PackageVersion != next.PackageVersion {
			logger.Logf("prime.Restore[framework]: pinned version %q is not whitelisted; coerced to %q",
				got.PackageVersion, next.PackageVersion)
		}
	}
	a.mu.Lock()
	a.binding = next
	a.mu.Unlock()
	return nil
}

// restoreManifestDir validates the manifest parses and ensures the role's
// directory exists. Entry content arrives via RestoreEntry.
func (a *Adapter) restoreManifestDir(plaintext []byte) error {
	count := 0
	if len(plaintext) > 0 {
		m, err := manifest.Unmarshal(plaintext)
		if err != nil {
			return fmt.Errorf("prime.Restore[skills/]: %w", err)
		}
		count = len(m.Entries)
	}
	if err := ensureDir(skillsDir()); err != nil {
		return fmt.Errorf("prime.Restore[skills/]: %w", err)
	}
	logger.Logf("prime.Restore[skills/]: parsed manifest (%d entries)", count)
	return nil
}

// EvolutionFor returns the role's canonical plaintext for drift detection.
func (a *Adapter) EvolutionFor(ctx context.Context, role string) ([]byte, error) {
	switch role {
	case "framework":
		a.mu.RLock()
		b := a.binding
		a.mu.RUnlock()
		out, err := json.Marshal(&b)
		if err != nil {
			return nil, fmt.Errorf("prime evoFramework: marshal: %w", err)
		}
		return out, nil
	case "harness_state.json":
		return a.evoHarnessState()
	case "APPEND_SYSTEM.md":
		return a.evoAppendSystem()
	case "models.json":
		return a.evoModelsJSON()
	case "skills/":
		return a.evoSkills()
	}
	return nil, framework.ErrUnsupportedDim
}

// LoadEntry returns one manifest entry's plaintext. Must hash to exactly the
// content_hash EvolutionFor declared for that path.
func (a *Adapter) LoadEntry(ctx context.Context, role, path string) ([]byte, error) {
	if role == "skills/" {
		return a.loadEntrySkills(path)
	}
	return nil, framework.ErrUnsupportedDim
}

// RestoreEntry writes one manifest entry under the role's disk location.
func (a *Adapter) RestoreEntry(ctx context.Context, role, path string, plaintext []byte) error {
	if role == "skills/" {
		return a.restoreEntrySkills(path, plaintext)
	}
	return framework.ErrUnsupportedDim
}

// FrameworkRoutes implements framework.RouteProvider.
//
// ONE route, and it is the bridge's: Prime Agent's daemon speaks JSONL over a
// local socket, so the only HTTP surface in the container is the sealed-owned
// bridge, which exposes exactly one OpenAI-shaped chat endpoint. Nothing of
// the framework's own is reachable — there is no web dashboard, no file or
// exec endpoint to audit (FRAMEWORK_ADAPTER.md §11 step 10), and because we
// author the bridge, the exposed surface is a whitelist by construction
// rather than something we have to fence off.
//
// Signed is false: this is the owner↔agent steering channel. The proxy
// enforces that for every framework route regardless; false here keeps the
// declaration honest.
func (a *Adapter) FrameworkRoutes() []framework.Route {
	return []framework.Route{
		{
			Prefix:      "/v1/",
			Kind:        "chat",
			Auth:        "bearer",
			Signed:      false,
			Backend:     fmt.Sprintf("http://127.0.0.1:%d", bridgePort),
			Description: "OpenAI-compatible chat/completions API (sealed bridge onto the Prime Agent daemon).",
		},
	}
}

// bridgePort is the loopback port the sealed-owned HTTP bridge binds. Not the
// framework's own port: Prime Agent has none.
const bridgePort = 8791

// Compile-time interface assertions — silent non-implementation of an optional
// capability is a feature quietly off (FRAMEWORK_ADAPTER.md §2.2).
//
// Two are deliberately absent:
//
//   - VersionReconciler. Reconciling means installing, and this framework is
//     provisioned at image build time so its bytes ride the image hash that
//     goes into on-chain validFrameworkHashes. Downloading a different version
//     into an attested container at drift time would defeat that, so a drifted
//     `framework` role is committed as-is and Start verifies instead (see
//     verifyInstalled).
//   - SettleDelayer. Prime Agent writes harness state lazily, on the first
//     refine, not as a first-boot config rewrite, so the conservative 5s
//     bootstrap default is right and a custom value would be noise.
//
// framework.Reloadable is absent because nothing consumes it.
var (
	_ framework.Framework             = (*Adapter)(nil)
	_ framework.RouteProvider         = (*Adapter)(nil)
	_ framework.SubprocessLogProvider = (*Adapter)(nil)
)
