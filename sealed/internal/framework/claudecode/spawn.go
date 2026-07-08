package claudecode

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/platform"
)

// bridgeServerJS is the HTTP bridge source, compiled into the sealed
// binary and materialized to bridgeScriptPath at every Start. Embedding
// (rather than baking the file into the container image) keeps the
// bridge version pinned to the measured sealed binary and lets one
// universal image (see images/sealed/) run any bundled framework.
//
//go:embed bridge/server.js
var bridgeServerJS []byte

// materializeBridge writes the embedded bridge to bridgeScriptPath.
// Unconditional overwrite: the bridge is platform infrastructure (like
// the marker sections), not agent state — it must always match the
// running sealed binary, and it lives outside every chain-tracked role.
func materializeBridge() error {
	if err := os.MkdirAll(filepath.Dir(bridgeScriptPath), 0o755); err != nil {
		return fmt.Errorf("mkdir bridge dir: %w", err)
	}
	if err := os.WriteFile(bridgeScriptPath, bridgeServerJS, 0o755); err != nil {
		return fmt.Errorf("write bridge: %w", err)
	}
	return nil
}

// Start brings the Claude Code agent up:
//
//   - First call (initialized=false): npm-install the version pinned by
//     the framework binding, generate the bridge admin token, inject the
//     platform section into CLAUDE.md, spawn the bridge.
//   - Restart (supervisor / Reload): verify the binary, re-inject
//     CLAUDE.md (idempotent marker upsert), spawn. No install, no token
//     regeneration — agent self-modifications survive untouched.
//
// The upstream sealed proxies to is the bridge, not claude itself: Claude
// Code is a per-invocation CLI, and the bridge (see
// images/claudecode/bridge/server.js) owns session continuity.
func (a *Adapter) Start(ctx context.Context, rt framework.RuntimeContext) (framework.StartResult, error) {
	a.mu.RLock()
	binding := a.binding
	cachedToken := a.adminToken
	initialized := a.initialized
	a.mu.RUnlock()
	if binding == nil {
		return framework.StartResult{}, fmt.Errorf("claude-code: no framework binding restored before Start")
	}

	// Inference routing comes from settings.json (the chain-tracked
	// config), not from RuntimeContext — claude reads model + env itself;
	// we only surface the resolved picture in the injected runtime
	// snapshot. env.ANTHROPIC_BASE_URL pointing at the 0G router means
	// inference runs inside 0g-compute's TEE (Anthropic-compatible
	// endpoint), completing the verifiable-inference trust layer.
	provider, model, zgRouted := readInferenceFromSettings()

	adminToken := cachedToken
	if !initialized {
		newToken, err := randomTokenHex(32)
		if err != nil {
			return framework.StartResult{}, fmt.Errorf("generate bridge admin token: %w", err)
		}
		adminToken = newToken
		if err := installClaudeCode(binding.PackageVersion); err != nil {
			return framework.StartResult{}, err
		}
	} else {
		if _, err := exec.Command("claude", "--version").Output(); err != nil {
			return framework.StartResult{}, fmt.Errorf("claude binary missing on restart: %w", err)
		}
		logger.Logf("claude-code restart: skipping npm install + token regeneration (preserving agent self-modifications)")
	}

	// Assemble the platform injection from the shared content builder and
	// deliver it as CLAUDE.md's single marker section.
	rs := platform.RuntimeSnapshot{
		SealedVersion:    rt.SealedVersion,
		FrameworkVersion: probeVersion(ctx),
		AgentSeal:        rt.AgentSeal,
		AgentID:          rt.AgentID,
		Owner:            rt.Owner,
		ChainRPC:         rt.ChainRPC,
		ContractAddr:     rt.ContractAddr,
		AttestorURL:      rt.AttestorURL,
		PublicURL:        rt.PublicURL,
		SealSignSock:     rt.SealSignSock,
		Provider:         provider,
		Model:            model,
		ZGComputeRouted:  zgRouted,
		BootTime:         time.Now(),
	}
	rs.Whitelist = make([]platform.WhitelistEntry, len(supportedClaudeCodeVersions))
	for i, v := range supportedClaudeCodeVersions {
		rs.Whitelist[i] = platform.WhitelistEntry{Version: v}
	}
	rs.WhitelistMax = whitelistMax()

	// Platform identity + doctrine go to claude's AUTHORITATIVE channel
	// (--append-system-prompt via the bridge), not CLAUDE.md — CLAUDE.md
	// is memory, and content there is treated as advisory/injection. See
	// claudemd.go.
	systemPrompt := composeSystemPrompt(platform.Build(rs))

	cmd, err := spawnBridge(rt, adminToken, systemPrompt)
	if err != nil {
		return framework.StartResult{}, err
	}
	a.mu.Lock()
	a.cmd = cmd
	a.adminToken = adminToken
	a.initialized = true
	a.mu.Unlock()

	addr := fmt.Sprintf("127.0.0.1:%d", upstreamPort)
	if err := waitForListen(ctx, addr, startTimeout); err != nil {
		return framework.StartResult{}, fmt.Errorf("claude-code bridge not listening: %w", err)
	}

	return framework.StartResult{
		Upstream: fmt.Sprintf("http://%s", addr),
		PID:      cmd.Process.Pid,
	}, nil
}

// readInferenceFromSettings best-effort extracts the resolved inference
// routing from settings.json: the model pin plus whether
// env.ANTHROPIC_BASE_URL routes to 0g-compute's Anthropic endpoint.
// Zero values on any failure — claude falls back to its own defaults and
// the injected runtime snapshot says "unknown".
func readInferenceFromSettings() (provider, model string, zgRouted bool) {
	provider = "anthropic"
	data, err := os.ReadFile(settingsJSONPath())
	if err != nil {
		return provider, "", false
	}
	var cfg struct {
		Model string            `json:"model"`
		Env   map[string]string `json:"env"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return provider, "", false
	}
	if cfg.Env["ANTHROPIC_BASE_URL"] == zgComputeAnthropicBaseURL {
		return "0g-compute", cfg.Model, true
	}
	return provider, cfg.Model, false
}

// spawnBridge launches the node bridge with a strict env whitelist — the
// bridge (and every claude it execs) must never see SANDBOX_SEAL_KEY or
// the other bootstrap env vars.
func spawnBridge(rt framework.RuntimeContext, adminToken, systemPrompt string) (*exec.Cmd, error) {
	if err := materializeBridge(); err != nil {
		return nil, err
	}
	logFile, err := os.OpenFile(subprocessLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", subprocessLogPath, err)
	}
	if err := os.MkdirAll(workspaceDir(), 0o755); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("mkdir workspace: %w", err)
	}

	cmd := exec.Command("node", bridgeScriptPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		fmt.Sprintf("BRIDGE_PORT=%d", upstreamPort),
		"BRIDGE_WORKDIR=" + workspaceDir(),
		"BRIDGE_ADMIN_TOKEN=" + adminToken,
	}
	// The authoritative system-prompt channel: the bridge passes this to
	// every `claude -p` via --append-system-prompt, so the AgenticID
	// identity + doctrine bind as instruction, not advisory memory.
	if systemPrompt != "" {
		env = append(env, "BRIDGE_APPEND_SYSTEM_PROMPT="+systemPrompt)
	}
	if rt.APIKey != "" {
		env = append(env, "ANTHROPIC_API_KEY="+rt.APIKey)
	}
	if rt.PublicURL != "" {
		env = append(env, "AGENT_PUBLIC_URL="+rt.PublicURL)
	}
	if rt.SealSignSock != "" {
		env = append(env, "SEAL_SIGN_SOCK="+rt.SealSignSock)
	}
	if rt.AgentSeal != "" {
		env = append(env, "AGENT_SEAL="+rt.AgentSeal)
	}
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("start claude-code bridge: %w", err)
	}
	logger.Logf("OK   claude-code bridge spawned, pid=%d (log: %s)", cmd.Process.Pid, subprocessLogPath)
	return cmd, nil
}

// waitForListen polls TCP-connect to addr until success or timeout.
func waitForListen(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	backoff := 200 * time.Millisecond
	logger.Logf("waitForListen %s (up to %s)...", addr, timeout)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err == nil {
			_ = conn.Close()
			logger.Logf("OK   %s accepting connections", addr)
			return nil
		}
		time.Sleep(backoff)
		if backoff < 2*time.Second {
			backoff *= 2
		}
	}
	return fmt.Errorf("%s did not accept connections within %s", addr, timeout)
}

func randomTokenHex(nbytes int) (string, error) {
	buf := make([]byte, nbytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
