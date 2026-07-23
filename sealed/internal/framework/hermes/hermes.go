// Package hermes is the framework adapter for Hermes Agent (Nous Research).
//
// Current path-driven role set (mirrors the openclaw adapter's shape;
// designed 2026-07 from the live spike against hermes v0.19.0):
//
//	framework    Leaf — 3-field binding JSON (package_version = git tag)
//	config.yaml  Leaf — owned-keys subset of ~/.hermes/config.yaml,
//	             canonical JSON on chain, YAML on disk, api_key stripped
//	SOUL.md      Leaf — identity/persona file, verbatim bytes
//	memories/    DirectoryManifest — ~/.hermes/memories/*.md (hermes caps
//	             these small: MEMORY.md ~2200 chars, USER.md ~1375)
//	skills/      DirectoryManifest — each agent-created skill dir is one
//	             tar.gz entry; install-bundled skills (listed in
//	             skills/.bundled_manifest) are EXCLUDED — they are
//	             reproducible from the pinned framework version
//
// File map:
//   - hermes.go      Adapter struct + framework.Framework interface methods
//   - config.go      private config types
//   - paths.go       on-disk path constants (+ the do-not-track list)
//   - yamlio.go      config.yaml read/update + secret strip
//   - restore.go     Restore dispatch + framework leaf
//   - restore_paths.go  path-driven Restore/LoadEntry/RestoreEntry
//   - evolution.go   EvolutionFor dispatch + framework live probe
//   - evolution_paths.go  per-role canonical plaintext builders
//   - ingest.go      HandleLegacy: mint-only persona translation
//   - spawn.go       Start: version pin (git tag + uv sync) + gateway spawn
package hermes

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/manifest"
)

const (
	// upstreamPort is hermes's OpenAI-compatible API server (loopback-only;
	// enabled via API_SERVER_ENABLED at spawn). The outer proxy on :8080
	// reverse-proxies to this. Chosen over the gateway's own WebSocket
	// control plane because the HTTP surface is the documented headless
	// path (/v1/chat/completions, /v1/health).
	upstreamPort = 8642

	// startTimeout is how long Start will wait for the API server to bind.
	// First boot includes a `uv sync --locked` (seconds against the baked
	// warm cache, minutes if the image cache is cold).
	startTimeout = 180 * time.Second
)

// Adapter is the hermes implementation of framework.Framework.
type Adapter struct {
	mu           sync.RWMutex
	cfg          *config   // composed from Restore calls
	apiServerKey string    // API server bearer key; generated on first Start, reused on restarts
	cmd          *exec.Cmd // running gateway process; nil before Start / after exit

	// initialized flips after the first successful Start. Subsequent Start
	// calls (supervisor restarts) skip install + config rewrites so agent
	// self-modifications survive restart untouched.
	initialized bool
}

// New returns a fresh Adapter and registers it as "hermes".
func New() *Adapter {
	a := &Adapter{}
	framework.Register("hermes", a)
	return a
}

// Name implements framework.Framework.
func (a *Adapter) Name() string { return "hermes" }

// ── Optional capability interfaces (framework.go) ───────────────────────────

// SubprocessLogPath implements framework.SubprocessLogProvider. spawn.go
// pipes the gateway's stdout/stderr here; proxy serves it on /log/agent.
func (a *Adapter) SubprocessLogPath() string { return "/tmp/hermes.log" }

// SettleDelay implements framework.SettleDelayer. Hermes's first boot
// seeds bundled skills into ~/.hermes/skills/ and may rewrite config.yaml
// defaults; 10s lets those writes land before the watcher baseline is
// captured (seeding is file-copy bound, not network bound).
func (a *Adapter) SettleDelay() time.Duration { return 10 * time.Second }

// Version probes the installed hermes CLI. Best-effort; "" on error.
func (a *Adapter) Version(ctx context.Context) (string, error) {
	v := probeHermesVersion(ctx)
	if v == "" {
		return "", fmt.Errorf("hermes: version probe failed")
	}
	return v, nil
}

// Roles returns the path-driven role set this adapter declares.
// Path-suffix convention: trailing "/" means manifest, no trailing slash
// means leaf. None are sealed-required; missing roles fall back to
// Defaults() / nil-plaintext Restore.
func (a *Adapter) Roles() []framework.RoleSpec {
	return []framework.RoleSpec{
		{Name: "framework", Shape: framework.Leaf},
		{Name: "config.yaml", Shape: framework.Leaf},
		{Name: "SOUL.md", Shape: framework.Leaf},
		{Name: "memories/", Shape: framework.DirectoryManifest},
		{Name: "skills/", Shape: framework.DirectoryManifest},
	}
}

// Defaults returns the canonical "empty/zero" plaintext for a role.
//
//   - "framework": current adapter name + whitelistMax tag + schema 1
//   - "config.yaml": empty JSON object (canonical wire encoding is JSON)
//   - "SOUL.md": nil — an absent/empty identity file is "no content"
//   - manifest roles: empty Manifest
func (a *Adapter) Defaults(role string) []byte {
	switch role {
	case "framework":
		fb := frameworkBinding{
			Name:           "hermes",
			PackageVersion: whitelistMax(),
			SchemaVersion:  1,
		}
		b, err := json.Marshal(&fb)
		if err != nil {
			return nil
		}
		return b
	case "config.yaml":
		return []byte("{}")
	case "SOUL.md":
		return nil
	case "memories/", "skills/":
		b, err := manifest.New().Marshal()
		if err != nil {
			return nil
		}
		return b
	}
	return nil
}

// AuthResponse implements framework.Framework. Returns the hermes headless
// credentials: the API server bearer key plus the chat path, so a verified
// owner can drive /v1/chat/completions through the sealed proxy.
//
// Caller (proxy.handleAuth) is responsible for verifying the requester is
// the on-chain owner before invoking.
func (a *Adapter) AuthResponse(ctx context.Context) (any, error) {
	a.mu.RLock()
	key := a.apiServerKey
	a.mu.RUnlock()
	if key == "" {
		return nil, fmt.Errorf("hermes: api server key not provisioned (Start has not run successfully)")
	}
	return map[string]any{
		"api_server_key": key,
		"chat_path":      "/v1/chat/completions",
	}, nil
}

// Stop SIGTERMs the tracked process, waits up to gracefulTimeout, then
// SIGKILLs. Afterwards sweeps any leftover `hermes gateway run` processes
// so a stale child can't hold :8642 against the next Start.
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

// sweepOrphanGateways SIGKILLs any `hermes gateway run` process. pkill
// exit 1 = "no process matched" which is the happy path.
func sweepOrphanGateways() {
	out, err := exec.Command("pkill", "-9", "-f", "hermes gateway run").CombinedOutput()
	if err == nil {
		logger.Logf("hermes: swept orphan gateway processes")
		return
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		return // none matched
	}
	logger.Logf("hermes: pkill orphan sweep failed: %v: %s", err, strings.TrimSpace(string(out)))
}

// Liveness reports nil if the hermes API server is accepting TCP
// connections. The API server rides inside the gateway process, so this
// covers both "process up" and "HTTP surface bound".
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

// ReconcileFramework collapses any framework dim drift back onto
// whitelistMax: checkout the tag + uv sync. Mirrors the openclaw twin;
// the only difference is the package manager (git tag vs npm).
func (a *Adapter) ReconcileFramework(ctx context.Context) error {
	target := whitelistMax()
	if target == "" {
		return fmt.Errorf("no supported hermes versions configured")
	}
	running := probeHermesVersion(ctx)
	if running == target {
		return nil
	}
	logger.Logf("hermes: reconciling framework version %q -> %q (whitelistMax)", running, target)
	if err := installHermes(target); err != nil {
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
			logger.Logf("hermes gateway exited: %v", err)
		} else {
			logger.Logf("hermes gateway exited cleanly")
		}
		if onExit != nil {
			onExit(err)
		}
	}()
}
