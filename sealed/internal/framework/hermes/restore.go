package hermes

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
// Multiple Restore calls must commute and be idempotent: each role owns
// its disk slice, no cross-role merging happens here.
func (a *Adapter) Restore(ctx context.Context, role string, plaintext []byte) error {
	a.mu.Lock()
	if a.cfg == nil {
		a.cfg = &config{}
	}
	a.mu.Unlock()

	switch role {
	case "framework":
		return a.restoreFramework(plaintext)
	case "config.yaml":
		return a.restoreConfigYAML(plaintext)
	case "SOUL.md":
		return a.restoreSoulMD(plaintext)
	case "memories/":
		return a.restoreManifestDir(plaintext, memoriesDir(), "memories/")
	case "skills/":
		return a.restoreManifestDir(plaintext, skillsDir(), "skills/")
	default:
		logger.Logf("hermes.Restore[%s]: unknown role, ignoring (%d bytes)", role, len(plaintext))
		return nil
	}
}

// restoreFramework parses + validates the framework binding. nil plaintext
// falls back to adapter-derived defaults (name + whitelistMax + schema 1).
// A version-less binding ({"name","schema_version"}) is legal — attestor
// doesn't speak release schemes — and resolves to whitelistMax; the first
// watcher tick then pins the concrete tag on chain. A pinned tag OUTSIDE
// the whitelist is coerced to the nearest validated tag (logged): sealed
// only ever checks out releases it has been validated against.
func (a *Adapter) restoreFramework(plaintext []byte) error {
	var fb frameworkBinding
	if len(plaintext) == 0 {
		fb = frameworkBinding{
			Name:           "hermes",
			PackageVersion: whitelistMax(),
			SchemaVersion:  1,
		}
	} else {
		if err := json.Unmarshal(plaintext, &fb); err != nil {
			return fmt.Errorf("parse framework: %w", err)
		}
		if fb.Name != "hermes" {
			return fmt.Errorf("framework.name = %q; hermes adapter expected", fb.Name)
		}
		if fb.SchemaVersion != 1 {
			return fmt.Errorf("unsupported schema_version: %d (this reader supports 1)", fb.SchemaVersion)
		}
		if fb.PackageVersion == "" {
			fb.PackageVersion = whitelistMax()
		} else if !isWhitelisted(fb.PackageVersion) {
			nearest := nearestWhitelisted(fb.PackageVersion)
			logger.Logf("hermes.Restore[framework]: pinned package_version %q is not a validated release; installing nearest validated %q instead (chain record converges on the next drift commit)",
				fb.PackageVersion, nearest)
			fb.PackageVersion = nearest
		}
	}
	a.mu.Lock()
	a.cfg.framework = fb
	a.mu.Unlock()
	logger.Logf("hermes.Restore[framework]: name=%s package_version=%s schema=%d",
		fb.Name, fb.PackageVersion, fb.SchemaVersion)
	return nil
}
