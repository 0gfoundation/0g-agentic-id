package openclaw

import (
	"context"
	"encoding/json"

	"seal-verify/internal/framework"
)

// EvolutionFor produces canonical iData plaintext bytes for `role` by
// reading the live state from disk: the workspace markdown files + skills
// / canvas subtrees. Reading from disk (rather than a stale in-memory cfg)
// is what makes evolution detection correct — when the agent self-modifies
// its state (new skill, MEMORY.md write), the watcher's next tick observes
// those changes.
//
// openclaw.json is deliberately absent: its platform-owned half is
// re-rendered from the owner's settings at every Start (RenderSettings) and
// the remainder is openclaw's own per-boot bookkeeping, so tracking the file
// would anchor a derived artifact and hand a mint-time copy back to an agent
// whose settings have since changed. Nothing in it reaches chain — including
// any edit the agent makes there, which is what the agent doc tells it.
//
// Output MUST be deterministic: same on-disk state → byte-identical
// output. Per-role helpers in evolution_paths.go enforce this through
// stable JSON marshalling and determinism-tar.
func (a *Adapter) EvolutionFor(ctx context.Context, role string) ([]byte, error) {
	switch role {
	case "framework":
		return a.evoFramework(ctx)
	case "workspace/":
		return a.evoWorkspace()
	case "workspace/skills/":
		return a.evoWorkspaceSkills()
	case "workspace/canvas/":
		return a.evoWorkspaceCanvas()
	}
	return nil, framework.ErrUnsupportedDim
}

// evoFramework returns the framework binding plaintext (current openclaw
// name + npm package version + protocol schema version). Lives on the
// path-driven side because every role's evolution shares the same iData
// schema — see evolution_paths.go for the other four.
func (a *Adapter) evoFramework(ctx context.Context) ([]byte, error) {
	a.mu.RLock()
	fb := frameworkBinding{}
	if a.cfg != nil {
		fb = a.cfg.framework
	}
	a.mu.RUnlock()
	// Live-probe the installed openclaw npm version so a dashboard upgrade
	// is observable as drift on this role. Empty result means probe failed
	// (binary not installed yet — happens during pre-Start seed) so we
	// keep the cfg value.
	if v := probeOpenclawVersion(ctx); v != "" {
		fb.PackageVersion = v
	}
	return json.Marshal(&fb)
}
