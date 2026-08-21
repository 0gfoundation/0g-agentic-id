// Package dsh is the framework adapter for DeepSeek Harness (DSH,
// @deepseek-ai/dsh) — a Cordis-plugin-composed harness whose every capability
// (model, tools, skills, sessions, storage, system prompt) is an independently
// swappable plugin.
//
// STATUS: state half only. Roles(), Defaults(), Restore/EvolutionFor and
// FrameworkFacts are real and conformance-tested. Start/Stop/Liveness/
// Readiness/AuthResponse are stubs that return a clear "not implemented"
// error, and New() does not self-register (see spawn.go) — so this package
// compiles and its invariants are checked, but no on-chain binding can select
// it yet. This mirrors the prime-agent port's own documented strategy
// (FRAMEWORK_ADAPTER.md §13 point 5): the roles/canonicalization half is a
// pure function of disk state and can be finished and reviewed before the
// process half exists. The process half needs a live sandbox loop to get
// right — composing a working DSH plugin tree, wiring an HTTP bridge into it,
// and confirming the model actually streams — the same kind of iteration the
// prime-agent port needed (see its port report's "left to verify on first
// live boot" and the npm-vs-tarball mistake it documents).
//
// Role set:
//
//	framework       Leaf — 3-field binding JSON (package_version = the DSH
//	                npm/release version — the two series match for DSH,
//	                unlike prime-agent; see whitelist.go)
//	APPEND_SYSTEM.md Leaf — owner persona, verbatim bytes (persona.go).
//	                Injected by the bridge into ctx.systemPrompt at boot,
//	                NOT through any DSH-native config file — DSH's own
//	                `persona` config key lives in the plugin composition
//	                (cordis.yml), which is per-boot platform structure, not
//	                agent-owned state we track.
//	settings.yaml   Leaf — the inference route pin, in DSH's own hot-reloaded
//	                settings-file format (settingsyaml.go)
//	skills/         DirectoryManifest — agent-installed skills under
//	                $DSH_HOME/skills/ (skills.go)
//
// What makes this adapter unusual among the shipped set: DSH is the only
// framework here whose composition is not fixed by the adapter but assembled
// per-boot from ~50 independently versioned plugin packages. There is no
// single "the framework's config file" the way openclaw and hermes each have
// one — the composition itself (which plugins, which order, which config) is
// platform structure this adapter authors and materializes at Start, exactly
// like the sealed-owned HTTP bridge it also ships.
//
// File map:
//
//	dsh.go          Adapter struct + framework.Framework interface methods
//	paths.go        on-disk paths this adapter manages (+ what it does not)
//	whitelist.go    validated DSH version set
//	persona.go      APPEND_SYSTEM.md + HandleLegacy persona ingestion
//	settingsyaml.go the settings.yaml role (inference pin, YAML on disk / canonical JSON on chain)
//	skills.go       the skills/ manifest role
//	platformtext.go FrameworkFacts (this framework's blanks in the agent doc)
//	spawn.go        Start/Stop/probes — STUBBED, see the package doc above
package dsh

import (
	"context"
	"encoding/json"
	"fmt"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/manifest"
)

// frameworkName is the adapter id and the `name` field of the framework
// binding. Selection at boot matches on this exact string.
const frameworkName = "dsh"

// Adapter is the DSH implementation of framework.Framework.
type Adapter struct {
	// binding is the composed framework-role state (name + pinned version).
	binding frameworkBinding
}

// frameworkBinding is the protocol-reserved "framework" role's plaintext.
// Field order is the marshal order.
type frameworkBinding struct {
	Name           string `json:"name"`
	PackageVersion string `json:"package_version"`
	SchemaVersion  int    `json:"schema_version"`
}

// New builds the adapter. It does NOT self-register (unlike every other
// bundled adapter's New()) — see the package doc for why: the process half
// is not implemented yet, and an on-chain binding must never be able to
// select a framework whose Start always fails. Wiring it up is one call to
// framework.Register(frameworkName, New()) here, plus the registration line
// in main.go, once spawn.go is real.
func New() *Adapter {
	return &Adapter{
		binding: frameworkBinding{
			Name:           frameworkName,
			PackageVersion: whitelistMax(),
			SchemaVersion:  1,
		},
	}
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
		{Name: "settings.yaml", Shape: framework.Leaf},
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
	case "APPEND_SYSTEM.md", "settings.yaml":
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
	case "settings.yaml":
		return a.restoreSettingsYAML(plaintext)
	case "skills/":
		return a.restoreManifestDir(plaintext)
	}
	// Unknown roles are not an error: bootstrap routes them to HandleLegacy.
	logger.Logf("dsh.Restore: ignoring unknown role %q", role)
	return nil
}

// restoreFramework composes the binding. A binding naming a DIFFERENT
// framework fails loud: selection and adapter disagree about what this agent
// is, and booting anyway would forge identity (FRAMEWORK_ADAPTER.md §3). An
// empty/absent package_version resolves to whitelistMax, because version
// knowledge lives with the code that validates versions, not with attestor.
func (a *Adapter) restoreFramework(plaintext []byte) error {
	next := frameworkBinding{Name: frameworkName, PackageVersion: whitelistMax(), SchemaVersion: 1}
	if len(plaintext) > 0 {
		var got frameworkBinding
		if err := json.Unmarshal(plaintext, &got); err != nil {
			return fmt.Errorf("dsh.Restore[framework]: parse: %w", err)
		}
		if got.Name != "" && got.Name != frameworkName {
			return fmt.Errorf("dsh.Restore[framework]: binding names %q, this adapter is %q — refusing to forge identity", got.Name, frameworkName)
		}
		if got.SchemaVersion != 0 {
			next.SchemaVersion = got.SchemaVersion
		}
		next.PackageVersion = coerceWhitelisted(got.PackageVersion)
		if got.PackageVersion != "" && got.PackageVersion != next.PackageVersion {
			logger.Logf("dsh.Restore[framework]: pinned version %q is not whitelisted; coerced to %q",
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
			return fmt.Errorf("dsh.Restore[skills/]: %w", err)
		}
		count = len(m.Entries)
	}
	if err := ensureDir(skillsDir()); err != nil {
		return fmt.Errorf("dsh.Restore[skills/]: %w", err)
	}
	logger.Logf("dsh.Restore[skills/]: parsed manifest (%d entries)", count)
	return nil
}

// EvolutionFor returns the role's canonical plaintext for drift detection.
func (a *Adapter) EvolutionFor(ctx context.Context, role string) ([]byte, error) {
	switch role {
	case "framework":
		out, err := json.Marshal(&a.binding)
		if err != nil {
			return nil, fmt.Errorf("dsh evoFramework: marshal: %w", err)
		}
		return out, nil
	case "APPEND_SYSTEM.md":
		return a.evoAppendSystem()
	case "settings.yaml":
		return a.evoSettingsYAML()
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
// prime-agent: DSH is provisioned at image build time so its bytes ride the
// image hash in on-chain validFrameworkHashes; a drifted `framework` role is
// committed as-is rather than downloading a different version into an
// attested container (see spawn.go once it is real).
var (
	_ framework.Framework = (*Adapter)(nil)
)
