// Package harness is the framework adapter for 0g-harness
// (github.com/0gfoundation/0g-harness): the platform's agent harness, composed
// from DeepSeek Harness (DSH, @deepseek-ai/dsh) plugin packages, where every
// capability (model, tools, skills, sessions, storage, system prompt) is an
// independently swappable plugin.
//
// STATUS: complete adapter. The state half — Roles(), Defaults(),
// Restore/EvolutionFor, FrameworkFacts — is conformance-tested. The process
// half (spawn.go) runs 0g-harness, which the image installs at build time, and
// New() self-registers so an on-chain "0g-harness" binding selects it. The
// harness composes the DSH plugin tree in its own code (not a
// loader/profile/cordis.yml and not any $DSH_HOME patch layer), so the plugin
// SET rides the image hash and an agent editing its home cannot alter what
// mounts next boot. Four composition options are the owner's (README.md),
// delivered as env at spawn. Like prime-agent, the process half wants a
// live-boot pass to confirm on first deploy (model streams end-to-end,
// bash/skills work de-privileged); the state half needed no such loop
// (FRAMEWORK_ADAPTER.md §13 point 5).
//
// The old name: an agent minted before 0g-harness carries a "dsh" binding.
// It still selects this adapter, and its binding is rewritten to "0g-harness"
// at its first commit (legacyFrameworkName).
//
// Role set:
//
//	framework       Leaf — 3-field binding JSON (package_version = the
//	                0g-harness version; see whitelist.go)
//	APPEND_SYSTEM.md Leaf — owner persona, verbatim bytes (persona.go).
//	                Injected by the harness into ctx.systemPrompt at boot,
//	                NOT through any DSH-native config file — DSH's own
//	                `persona` config key lives in the plugin composition
//	                (cordis.yml), which is per-boot platform structure, not
//	                agent-owned state we track.
//	skills/         DirectoryManifest — agent-installed skills under
//	                $DSH_HOME/skills/ (skills.go)
//
// There is no config role: the inference pin is not chain state but the
// owner's settings document, rendered into the harness's environment at every
// Start (RenderSettings in settings.go). So a routing fix reaches an
// already-minted agent on its next boot instead of only at mint time, and
// $DSH_HOME/settings.yaml — which DSH itself never read, see settings.go —
// is gone entirely.
//
// What makes this adapter unusual among the shipped set: 0g-harness is the
// only framework here whose composition is not fixed by the adapter but
// assembled per-boot from ~50 independently versioned DSH plugin packages.
// There is no single "the framework's config file" the way openclaw and hermes
// each have one — the composition itself (which plugins, which order, which
// config) is platform structure, authored in the harness package the image
// carries.
//
// File map:
//
//	harness.go      Adapter struct + framework.Framework interface methods
//	paths.go        on-disk paths this adapter manages (+ what it does not)
//	whitelist.go    validated 0g-harness version set
//	persona.go      APPEND_SYSTEM.md + HandleLegacy persona ingestion
//	settings.go     RenderSettings: the owner's settings → harness env (no config
//	                file), plus recovery of the retired settings.yaml role
//	skills.go       the skills/ manifest role
//	platformtext.go FrameworkFacts (this framework's blanks in the agent doc)
//	spawn.go        Start/Stop/probes + the harness lifecycle and the routes
//	                it advertises
//
// The harness itself, with its platform plugins (seal-tools, seal-guard,
// subagent-guard), lives in github.com/0gfoundation/0g-harness; the image
// installs a pinned version of it (images/harness/Dockerfile).
package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/manifest"
	"seal-verify/internal/privsep"
	"seal-verify/internal/settings"
)

// frameworkName is the adapter id and the `name` field of the framework
// binding. Selection at boot matches on this exact string.
const frameworkName = "0g-harness"

// legacyFrameworkName is the name this framework had before 0g-harness, which
// agents minted then carry in their binding. It selects this adapter too, and
// restoreFramework composes a binding that names frameworkName, so the drift
// watcher commits the new name at the agent's first commit. Remove once no
// agent on any chain carries it.
const legacyFrameworkName = "dsh"

// Adapter is the 0g-harness implementation of framework.Framework.
type Adapter struct {
	mu sync.RWMutex

	// binding is the composed framework-role state (name + pinned version).
	binding frameworkBinding

	// cmd is the running harness process (nil before first Start / after Stop).
	cmd *exec.Cmd

	// bridgeToken gates the harness's /v1/* surface; AuthResponse hands it to a
	// verified owner. Minted once per container (memory-only), so a reset
	// rotates it.
	bridgeToken string

	// rendered is what RenderSettings last produced from the owner's settings
	// document: the resolved pin Start boots on, plus the harness environment
	// derived from it. nil means RenderSettings has not run — a programming
	// error Start refuses to paper over, because there is no file left to
	// recover a pin from (settings.go).
	rendered *renderedSettings

	// seededPin is the inference pin recovered from the retired
	// "settings.yaml" role by HandleLegacy, handed back to the platform
	// through SeededSettings so it can be persisted as the owner's settings
	// document. nil for any agent minted after the settings channel shipped,
	// which is every new one — this is transitional (settings.go).
	seededPin *settings.Doc
	// seededFrom ranks where seededPin came from, because two retired chain
	// roles can carry a pin and bootstrap's Phase C walks them in arrival
	// order — see stashSeededPin (settings.go).
	seededFrom legacySource

	// initialized flips after the first successful Start. A supervisor restart
	// reuses the installed framework + token and never rewrites agent state.
	initialized bool
}

// frameworkBinding is the protocol-reserved "framework" role's plaintext.
// Field order is the marshal order.
type frameworkBinding struct {
	Name           string `json:"name"`
	PackageVersion string `json:"package_version"`
	SchemaVersion  int    `json:"schema_version"`
}

// New builds the adapter and self-registers it (side-effect, like every other
// bundled adapter's New()), under its name and its old one.
func New() *Adapter {
	a := &Adapter{
		binding: frameworkBinding{
			Name:           frameworkName,
			PackageVersion: whitelistMax(),
			SchemaVersion:  1,
		},
	}
	framework.Register(frameworkName, a)
	framework.Register(legacyFrameworkName, a)
	// The tree spawnBridge hands to the agent user (privsep.DeclareTree:
	// Harden leaves it in root's home although the agent owns it).
	privsep.DeclareTree(dshHome)
	return a
}

func (a *Adapter) Name() string { return frameworkName }

// Version is a best-effort runtime probe. Not consumed by core code today
// (FRAMEWORK_ADAPTER.md §2.2).
func (a *Adapter) Version(ctx context.Context) (string, error) {
	return a.binding.PackageVersion, nil
}

func (a *Adapter) Roles() []framework.RoleSpec {
	return []framework.RoleSpec{
		{Name: "framework", Shape: framework.Leaf},
		{Name: "APPEND_SYSTEM.md", Shape: framework.Leaf},
		{Name: "skills/", Shape: framework.DirectoryManifest},
	}
}

// Defaults returns the canonical "empty/zero" plaintext for a role.
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
	case "APPEND_SYSTEM.md":
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
	case "APPEND_SYSTEM.md":
		return a.restoreAppendSystem(plaintext)
	case "skills/":
		return a.restoreManifestDir(plaintext)
	}
	// Unknown roles are not an error: bootstrap routes them to HandleLegacy.
	logger.Logf("harness.Restore: ignoring unknown role %q", role)
	return nil
}

// restoreFramework composes the binding. A binding naming a DIFFERENT
// framework fails loud: selection and adapter disagree about what this agent
// is, and booting anyway would forge identity (FRAMEWORK_ADAPTER.md §3). The
// old name is this framework (legacyFrameworkName): the composed binding names
// frameworkName, and the drift watcher commits it. An empty/absent
// package_version resolves to whitelistMax, because version knowledge lives
// with the code that validates versions, not with attestor.
func (a *Adapter) restoreFramework(plaintext []byte) error {
	next := frameworkBinding{Name: frameworkName, PackageVersion: whitelistMax(), SchemaVersion: 1}
	if len(plaintext) > 0 {
		var got frameworkBinding
		if err := json.Unmarshal(plaintext, &got); err != nil {
			return fmt.Errorf("harness.Restore[framework]: parse: %w", err)
		}
		switch got.Name {
		case "", frameworkName:
		case legacyFrameworkName:
			logger.Logf("harness.Restore[framework]: binding names %q, the old name of %q; the next commit rewrites it",
				got.Name, frameworkName)
		default:
			return fmt.Errorf("harness.Restore[framework]: binding names %q, this adapter is %q — refusing to forge identity", got.Name, frameworkName)
		}
		if got.SchemaVersion != 0 {
			next.SchemaVersion = got.SchemaVersion
		}
		next.PackageVersion = coerceWhitelisted(got.PackageVersion)
		if got.PackageVersion != "" && got.PackageVersion != next.PackageVersion {
			logger.Logf("harness.Restore[framework]: pinned version %q is not whitelisted; coerced to %q",
				got.PackageVersion, next.PackageVersion)
		}
	}
	a.binding = next
	return nil
}

// restoreManifestDir validates the manifest parses and ensures the role's
// directory exists. Entry content arrives via RestoreEntry.
func (a *Adapter) restoreManifestDir(plaintext []byte) error {
	count := 0
	if len(plaintext) > 0 {
		m, err := manifest.Unmarshal(plaintext)
		if err != nil {
			return fmt.Errorf("harness.Restore[skills/]: %w", err)
		}
		count = len(m.Entries)
	}
	if err := ensureRoleDir(skillsDir()); err != nil {
		return fmt.Errorf("harness.Restore[skills/]: %w", err)
	}
	logger.Logf("harness.Restore[skills/]: parsed manifest (%d entries)", count)
	return nil
}

// EvolutionFor returns the role's canonical plaintext for drift detection.
func (a *Adapter) EvolutionFor(ctx context.Context, role string) ([]byte, error) {
	switch role {
	case "framework":
		out, err := json.Marshal(&a.binding)
		if err != nil {
			return nil, fmt.Errorf("harness evoFramework: marshal: %w", err)
		}
		return out, nil
	case "APPEND_SYSTEM.md":
		return a.evoAppendSystem()
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

// Compile-time interface assertions — silent non-implementation of an
// optional capability is a feature quietly off (FRAMEWORK_ADAPTER.md §2.2).
//
// VersionReconciler is deliberately absent, for the same reason as
// prime-agent: 0g-harness is installed at image build time
// (images/harness/Dockerfile), so its bytes ride the image hash in on-chain
// validFrameworkHashes; a drifted `framework` role is committed as-is rather
// than installing a different version into an attested container.
var (
	_ framework.Framework = (*Adapter)(nil)
	// Transitional: recovers the pin from the retired "settings.yaml" role
	// for agents minted before the settings channel (settings.go).
	_ framework.LegacySettingsSeeder = (*Adapter)(nil)
)
