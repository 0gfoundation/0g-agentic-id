// Package claudecode is the framework adapter for Claude Code agents —
// the second adapter after openclaw, and the one whose port drove the
// optional-capability split in internal/framework (VersionReconciler,
// SubprocessLogProvider, SettleDelayer).
//
// Claude Code differs from openclaw in two structural ways this adapter
// has to absorb:
//
//  1. It is a CLI, not a server. The long-running upstream process sealed
//     supervises is an HTTP bridge (images/claudecode/bridge/server.js)
//     that execs `claude -p` per request with session continuity. Claude
//     Code itself starts and exits inside each bridge call.
//  2. It has one context file (CLAUDE.md) rather than openclaw's
//     SOUL/IDENTITY/TOOLS split, so the entire platform injection lands
//     as a single marker section in CLAUDE.md.
//
// Declared role set (path-driven):
//
//	framework       Leaf — 3-field binding JSON
//	settings.json   Leaf — ~/.claude/settings.json, allowlist-filtered
//	workspace/      DirectoryManifest — workspace root .md files (CLAUDE.md …)
//	agents/         DirectoryManifest — ~/.claude/agents/*.md (subagent defs)
//	skills/         DirectoryManifest — ~/.claude/skills/<slug>/ (tar.gz each)
//
// File map mirrors the openclaw adapter so the two stay reviewable
// side-by-side: claudecode.go (adapter + lifecycle), restore.go,
// evolution.go, spawn.go (bridge), claudemd.go (injection), paths.go,
// whitelist.go.
package claudecode

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
)

const (
	// upstreamPort is the localhost-only port the bridge binds to. The
	// outer proxy on :8080 reverse-proxies to this.
	upstreamPort = 3285

	// startTimeout bounds Start's wait for the bridge to bind
	// upstreamPort. First boot includes an npm install of claude-code
	// (~30-60s on a fresh container).
	startTimeout = 120 * time.Second

	// npmPackage is the Claude Code distribution package.
	npmPackage = "@anthropic-ai/claude-code"
)

// Compile-time contract checks: the full Framework interface plus every
// optional capability this adapter opts into. Deliberately NOT
// framework.ServicesManifestProvider — /hello advertises PUBLIC serve
// endpoints, and this framework exposes none yet: /v1/query is the
// owner's control surface (gated), not a public serve endpoint (which
// would need per-call payment/rate-limiting/ephemeral sessions). So
// /hello omits the services field, the intended degradation.
var (
	_ framework.Framework             = (*Adapter)(nil)
	_ framework.VersionReconciler     = (*Adapter)(nil)
	_ framework.SubprocessLogProvider = (*Adapter)(nil)
	_ framework.SettleDelayer         = (*Adapter)(nil)
)

// frameworkBinding is the plaintext of role="framework". Same 3-field
// protocol shape as every adapter (see FRAMEWORK_ADAPTER.md §3).
type frameworkBinding struct {
	Name           string `json:"name"`
	PackageVersion string `json:"package_version"`
	SchemaVersion  int    `json:"schema_version"`
}

// Adapter is the Claude Code implementation of framework.Framework.
type Adapter struct {
	mu         sync.RWMutex
	binding    *frameworkBinding // composed by Restore("framework", …); nil before
	adminToken string            // bridge admin token; generated on first Start, stable across restarts
	cmd        *exec.Cmd         // running bridge process; nil before Start / after exit

	// initialized flips after the first successful Start. Restarts skip
	// npm install + token generation so agent self-modifications survive
	// (same platform principle as openclaw: sealed keeps the agent alive,
	// it doesn't interfere with what the agent did to itself).
	initialized bool
}

// New returns a fresh Adapter and registers it as "claude-code".
func New() *Adapter {
	a := &Adapter{}
	framework.Register("claude-code", a)
	return a
}

// Name implements framework.Framework. Matches the binding JSON's `name`.
func (a *Adapter) Name() string { return "claude-code" }

// probeVersion returns the installed Claude Code version, "" on any
// failure (binary not installed yet — normal during pre-Start seeding).
// CLI output "2.1.12 (Claude Code)" → "2.1.12".
//
// Package var so tests can stub it out: unlike openclaw, a developer
// machine plausibly HAS `claude` on PATH, and a live probe leaking into
// round-trip tests makes them environment-dependent.
var probeVersion = func(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "claude", "--version").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// Version implements framework.Framework (best-effort CLI probe).
func (a *Adapter) Version(ctx context.Context) (string, error) {
	if v := probeVersion(ctx); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("claude-code: version probe failed (binary not installed?)")
}

// Roles implements framework.Framework. Five path-driven roles; trailing
// "/" marks the manifest-shaped ones per convention.
func (a *Adapter) Roles() []framework.RoleSpec {
	return []framework.RoleSpec{
		{Name: "framework", Shape: framework.Leaf},
		{Name: "settings.json", Shape: framework.Leaf},
		{Name: "workspace/", Shape: framework.DirectoryManifest},
		{Name: "agents/", Shape: framework.DirectoryManifest},
		{Name: "skills/", Shape: framework.DirectoryManifest},
	}
}

// Defaults implements framework.Framework: the canonical empty plaintext
// per role (see FRAMEWORK_ADAPTER.md §3.1 for the absent-on-chain
// invariant these bytes anchor).
func (a *Adapter) Defaults(role string) []byte {
	switch role {
	case "framework":
		return marshalBinding(frameworkBinding{
			Name:           "claude-code",
			PackageVersion: whitelistMax(),
			SchemaVersion:  1,
		})
	case "settings.json":
		return []byte("{}")
	case "workspace/", "agents/", "skills/":
		return emptyManifestBytes()
	}
	return nil
}

// AuthResponse implements framework.Framework. Owner auth grants the
// bridge's owner token; the console opens the chat control console at
// dashboard_url with the token in the fragment — same shape openclaw
// returns, so the attestor console's owner-manage entry is uniform
// across frameworks. That token gates /v1/query + /admin/* on the bridge.
//
// Caller (proxy.handleAuth) has already verified the requester is the
// on-chain owner.
func (a *Adapter) AuthResponse(ctx context.Context) (any, error) {
	a.mu.RLock()
	token := a.adminToken
	a.mu.RUnlock()
	if token == "" {
		return nil, fmt.Errorf("claude-code: owner token not provisioned (Start has not run successfully)")
	}
	return map[string]any{
		"token":         token,
		"dashboard_url": "/#token=" + token,
	}, nil
}

// Stop SIGTERMs the bridge, waits up to gracefulTimeout, then SIGKILLs.
// Afterwards sweeps any `claude` CLI children the bridge was running when
// it died — an orphaned claude process doesn't hold the upstream port,
// but it does hold a session lock in the workspace and burns tokens.
func (a *Adapter) Stop(ctx context.Context, gracefulTimeout time.Duration) error {
	a.mu.Lock()
	cmd := a.cmd
	a.cmd = nil
	a.mu.Unlock()

	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(gracefulTimeout):
			_ = cmd.Process.Kill()
			<-done
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			<-done
			return ctx.Err()
		}
	}

	sweepOrphans()
	return nil
}

// sweepOrphans SIGKILLs any leftover bridge or headless-claude process.
// pkill exit 1 = "no process matched", the happy path.
func sweepOrphans() {
	for _, pattern := range []string{bridgeScriptPath, "claude -p"} {
		out, err := exec.Command("pkill", "-9", "-f", pattern).CombinedOutput()
		if err == nil {
			logger.Logf("claude-code: swept orphan processes matching %q", pattern)
			continue
		}
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			continue // none matched
		}
		logger.Logf("claude-code: pkill %q sweep failed: %v: %s", pattern, err, strings.TrimSpace(string(out)))
	}
}

// Liveness reports nil if the bridge is accepting TCP connections.
func (a *Adapter) Liveness(ctx context.Context) error {
	addr := fmt.Sprintf("127.0.0.1:%d", upstreamPort)
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// Readiness today is the same as Liveness: the bridge accepts requests as
// soon as it binds; per-request claude spawns have their own timeout.
func (a *Adapter) Readiness(ctx context.Context) error { return a.Liveness(ctx) }

// ReconcileFramework implements framework.VersionReconciler: collapse any
// framework dim drift back onto whitelistMax via npm, updating the
// in-memory binding. Caller follows up with manager.Reload so the new
// binary actually serves (bridge respawn re-execs the new claude).
func (a *Adapter) ReconcileFramework(ctx context.Context) error {
	target := whitelistMax()
	if target == "" {
		return fmt.Errorf("no supported claude-code versions configured")
	}
	if running := probeVersion(ctx); running == target {
		return nil
	}
	logger.Logf("claude-code: reconciling framework version -> %q (whitelistMax)", target)
	if err := installClaudeCode(target); err != nil {
		return fmt.Errorf("install %s: %w", target, err)
	}
	a.mu.Lock()
	if a.binding != nil {
		a.binding.PackageVersion = target
	}
	a.mu.Unlock()
	return nil
}

// MonitorExit implements manager.Adapter's supervision hook: runs onExit
// (in a goroutine) once when the bridge process exits.
func (a *Adapter) MonitorExit(onExit func(err error)) {
	a.mu.RLock()
	cmd := a.cmd
	a.mu.RUnlock()
	if cmd == nil {
		return
	}
	go func() {
		err := cmd.Wait()
		if err != nil {
			logger.Logf("claude-code bridge exited: %v", err)
		} else {
			logger.Logf("claude-code bridge exited cleanly")
		}
		onExit(err)
	}()
}

// SubprocessLogPath implements framework.SubprocessLogProvider.
func (a *Adapter) SubprocessLogPath() string { return subprocessLogPath }

// SettleDelay implements framework.SettleDelayer. Claude Code doesn't
// rewrite settings.json on first boot the way openclaw rewrites its
// config, and the bridge touches nothing chain-tracked; a short delay
// only covers filesystem sync.
func (a *Adapter) SettleDelay() time.Duration { return 1 * time.Second }

func installClaudeCode(version string) error {
	spec := npmPackage
	if v := strings.TrimSpace(version); v != "" {
		spec = npmPackage + "@" + v
	}
	logger.Logf("installing %s (this may take ~30s)...", spec)
	if out, err := exec.Command("npm", "install", "-g", "--no-audit", "--no-fund", spec).CombinedOutput(); err != nil {
		return fmt.Errorf("npm install %s: %v: %s", spec, err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("claude", "--version").Output(); err == nil {
		logger.Logf("OK   installed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
