package openclaw

import (
	"context"
	"encoding/json"
	"fmt"

	"seal-verify/internal/logger"
)

// Restore applies a role's plaintext to disk + the small in-memory state
// the adapter retains (framework binding). Path-driven roles' restore
// implementations live in restore_paths.go; this file owns dispatch +
// the framework leaf.
//
// Multiple Restore calls must commute and be idempotent (see
// sealed/ARCHITECTURE.zh.md §3 on Restore commutativity): each role
// owns its disk slice, no cross-role merging happens here.
func (a *Adapter) Restore(ctx context.Context, role string, plaintext []byte) error {
	a.mu.Lock()
	if a.cfg == nil {
		a.cfg = &config{}
	}
	a.mu.Unlock()

	switch role {
	case "framework":
		return a.restoreFramework(plaintext)
	case "openclaw.json":
		return a.restoreOpenclawJSON(plaintext)
	case "workspace/":
		return a.restoreWorkspace(plaintext)
	case "workspace/skills/":
		return a.restoreWorkspaceSkills(plaintext)
	case "workspace/canvas/":
		return a.restoreWorkspaceCanvas(plaintext)
	default:
		logger.Logf("openclaw.Restore[%s]: unknown role, ignoring (%d bytes)", role, len(plaintext))
		return nil
	}
}

// restoreFramework parses + validates the framework binding. nil plaintext
// is interpreted as "chain has no entry"; in that case the binding falls
// back to adapter-derived defaults (current name + whitelistMax version +
// schema_version=1). Present-but-malformed plaintext fails loud.
//
// An empty/absent package_version in a present binding also resolves to
// whitelistMax: version knowledge lives with the code that validates
// versions (this adapter), so attestor can mint a version-less binding
// {"name","schema_version"} without speaking any framework's release
// scheme. The first watcher tick then pins the concrete installed
// version on chain (one expected drift-commit for version-less mints).
//
// A pinned version OUTSIDE the whitelist is coerced to the nearest
// validated version (logged) rather than installed as-is: sealed only
// ever runs releases it has been validated against, at install exactly
// like on drift-reconcile (which always pulls to whitelistMax). Same
// convergence as the version-less case — the first watcher tick commits
// the version actually running on chain. Whitelisted pins, including
// ones below whitelistMax, are honored.
func (a *Adapter) restoreFramework(plaintext []byte) error {
	var fb frameworkBinding
	if len(plaintext) == 0 {
		fb = frameworkBinding{
			Name:           "openclaw",
			PackageVersion: whitelistMax(),
			SchemaVersion:  1,
		}
	} else {
		if err := json.Unmarshal(plaintext, &fb); err != nil {
			return fmt.Errorf("parse framework: %w", err)
		}
		if fb.Name != "openclaw" {
			return fmt.Errorf("framework.name = %q; openclaw adapter expected", fb.Name)
		}
		if fb.SchemaVersion != 1 {
			return fmt.Errorf("unsupported schema_version: %d (this reader supports 1)", fb.SchemaVersion)
		}
		if fb.PackageVersion == "" {
			fb.PackageVersion = whitelistMax()
		} else if !isWhitelisted(fb.PackageVersion) {
			nearest := nearestWhitelisted(fb.PackageVersion)
			logger.Logf("openclaw.Restore[framework]: pinned package_version %q is not a validated release; installing nearest validated %q instead (chain record converges on the next drift commit)",
				fb.PackageVersion, nearest)
			fb.PackageVersion = nearest
		}
	}
	a.mu.Lock()
	a.cfg.framework = fb
	a.mu.Unlock()
	logger.Logf("openclaw.Restore[framework]: name=%s package_version=%s schema=%d",
		fb.Name, fb.PackageVersion, fb.SchemaVersion)
	return nil
}

// ── small utilities (shared with inference.go) ──────────────────────────────

// mustMarshal is shorthand for json.Marshal that panics on programmer
// error. Used only with map[string]any inputs of primitive values where
// failure is impossible in practice; documented panic vs returning error
// keeps the call sites in inference.go readable.
func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
