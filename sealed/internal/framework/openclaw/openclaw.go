// Package openclaw is the framework adapter for openclaw agents.
//
// 5-dim iData layout (EVOLUTION_DESIGN.md §3.1):
//
//	framework  → JSON FrameworkBinding (name + package_version + schema_version)
//	persona    → tar.gz: persona.md + inference.json + ui.json + talk.json
//	knowledge  → tar.gz: memory.md / dreams.md / user.md / agents.md +
//	             memory.json / session.json + manifest.json
//	skills     → JSON: { plugins, tools, web, approvals, audio, commands,
//	             agent_defaults_skills }  — each section opaque RawMessage
//	ops        → JSON: { channels, mcp, hooks, cron, browser, bindings,
//	             surfaces, broadcast, media, messages, accessGroups,
//	             commitments, secrets, acp, rate_limits, safety }
//
// File map:
//   - openclaw.go    Adapter struct + framework.Framework interface methods
//   - config.go      private config types
//   - paths.go       on-disk path constants
//   - disk.go        tar.gz helpers + openclaw.json read/merge/write +
//                    workspace I/O
//   - restore.go     Restore: parse iData → cfg → write openclaw.json +
//                    workspace files
//   - evolution.go   EvolutionFor: read openclaw.json + workspace → pack
//                    iData plaintext (this is the "reverse mapping" the
//                    uploader needs to publish actual current state)
//   - spawn.go       Start: install + spawn openclaw + runtime config
//                    sections (gateway.token, controlUi)
//   - toolsmd.go     platform-injected TOOLS.md upsert
package openclaw

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
	// upstreamPort is the localhost-only port openclaw binds to. The outer
	// proxy on :8080 reverse-proxies to this.
	upstreamPort = 3284

	// startTimeout is how long Start will wait for openclaw to bind upstreamPort
	// before giving up. With a fresh container this includes 30-60s of npm install.
	startTimeout = 120 * time.Second
)

// Adapter is the openclaw implementation of framework.Framework.
type Adapter struct {
	mu        sync.RWMutex
	cfg       *config   // composed from the 5 dim Restore calls
	authToken string    // gateway auth token; generated on first Start, reused on every restart
	cmd       *exec.Cmd // running gateway process; nil before Start / after exit

	// initialized flips after the first successful Start. Subsequent Start
	// calls (i.e. supervisor restarts) skip the npm install + token
	// generation steps so agent self-modifications (dashboard upgrade,
	// plugin install, config edits) are not silently overwritten.
	// EVOLUTION_DESIGN principle: outer framework does not interfere with
	// agent self-modification; it only keeps the agent alive.
	initialized bool
}

// New returns a fresh Adapter and registers it as "openclaw".
func New() *Adapter {
	a := &Adapter{}
	framework.Register("openclaw", a)
	return a
}

// Name implements framework.Framework.
func (a *Adapter) Name() string { return "openclaw" }

// Version probes the installed openclaw CLI. Best-effort; returns "" on error.
func (a *Adapter) Version(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "openclaw", "--version").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// Dimensions returns the adapter-owned dim labels — NOT including the
// protocol-reserved "framework" entry (EVOLUTION_DESIGN §7.1). Bootstrap
// handles framework separately (validates schema_version, picks adapter)
// and then iterates these for restore + snapshot seeding.
func (a *Adapter) Dimensions() []string {
	return []string{"persona", "knowledge", "skills", "ops"}
}

// AuthResponse implements framework.Framework. Returns the openclaw
// control-UI payload: gateway token + dashboard URL fragment that loads it.
//
// Caller (proxy.handleAuth) is responsible for verifying the requester is
// the on-chain owner before invoking; adapter assumes the call is authorised.
func (a *Adapter) AuthResponse(ctx context.Context) (any, error) {
	a.mu.RLock()
	token := a.authToken
	a.mu.RUnlock()
	if token == "" {
		return nil, fmt.Errorf("openclaw: auth token not provisioned (Start has not run successfully)")
	}
	return map[string]any{
		"token":         token,
		"dashboard_url": "/#token=" + token,
	}, nil
}

// Stop SIGTERMs the tracked process, waits up to gracefulTimeout, then
// SIGKILLs. Afterwards SIGKILLs any leftover `openclaw gateway run`
// processes — openclaw 5.x's self-restart fork-execs a child gateway we
// don't track via a.cmd, and a leftover child holding :3284 would race
// the next Start.
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

	sweepOrphanGateways()
	return nil
}

// sweepOrphanGateways SIGKILLs any `openclaw gateway run` process. Used by
// Stop to clean up children left behind by openclaw's internal self-restart.
// pkill exit 1 = "no process matched" which is the happy-path; only louder
// errors get logged.
func sweepOrphanGateways() {
	out, err := exec.Command("pkill", "-9", "-f", "openclaw gateway run").CombinedOutput()
	if err == nil {
		logger.Logf("openclaw: swept orphan gateway processes")
		return
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		return // none matched, nothing to do
	}
	logger.Logf("openclaw: pkill orphan sweep failed: %v: %s", err, strings.TrimSpace(string(out)))
}

// Liveness reports nil if the openclaw gateway is accepting TCP connections.
func (a *Adapter) Liveness(ctx context.Context) error {
	addr := fmt.Sprintf("127.0.0.1:%d", upstreamPort)
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// Readiness today is the same as Liveness.
func (a *Adapter) Readiness(ctx context.Context) error { return a.Liveness(ctx) }

// ReconcileFramework collapses any framework dim drift back onto the
// version sealed has been validated against (whitelistMax). Behaviour:
//
//   - If openclaw on disk already == whitelistMax: no-op.
//   - Otherwise: npm-install whitelistMax, update in-memory cfg's
//     package_version, return. Caller is expected to follow up with a
//     manager.Reload to spawn the new binary.
//
// Caller signals: "user (or openclaw self-upgrade) brought a non-target
// version onto disk; bring it back to the target." Same path handles
// both "user picked something out of whitelist" and "user picked a
// whitelisted version below max" — sealed always targets max.
//
// iData chain sync (uploader.Push for framework dim) is the caller's
// responsibility, separate from reconciliation.
func (a *Adapter) ReconcileFramework(ctx context.Context) error {
	target := whitelistMax()
	if target == "" {
		return fmt.Errorf("no supported openclaw versions configured")
	}
	running := probeOpenclawVersion(ctx)
	if running == target {
		return nil
	}
	logger.Logf("openclaw: reconciling framework version %q -> %q (whitelistMax)", running, target)
	if err := installOpenclaw(target); err != nil {
		return fmt.Errorf("install %s: %w", target, err)
	}
	a.mu.Lock()
	if a.cfg != nil {
		a.cfg.framework.PackageVersion = target
	}
	a.mu.Unlock()
	return nil
}

// MonitorExit runs the supplied onExit callback after the spawned process
// exits. Wraps cmd.Wait so the manager can be notified without polling.
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
			logger.Logf("openclaw gateway exited: %v", err)
		} else {
			logger.Logf("openclaw gateway exited cleanly")
		}
		if onExit != nil {
			onExit(err)
		}
	}()
}
