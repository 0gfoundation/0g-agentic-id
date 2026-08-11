package prime

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/inference"
	"seal-verify/internal/logger"
	"seal-verify/internal/platform"
)

// Start: version pin → materialize the bridge → write the agent doc → spawn.
//
// Unlike the other adapters there is no framework daemon to supervise: the
// bridge embeds the SDK (createAgentSession) in its own node process, so the
// bridge IS the framework process. Prime Agent's own daemon-backed CLI is the
// human-facing path and is deliberately unused — it would add a JSONL socket
// hop and a second process tree for nothing.

//go:embed bridge/bridge.mjs
var bridgeFS embed.FS

const (
	// bridgeScriptDir is where the embedded bridge is materialized at Start.
	// Deliberately not baked into the image: the bridge ships inside the
	// sealed binary, so its measurement is covered by the sealed image hash
	// and it can never drift out of sync with the adapter that spawns it.
	bridgeScriptDir = "/usr/local/lib/seal-prime-bridge"

	// npmPackage is the SDK the bridge imports; the version whitelist pins it.
	npmPackage = "@earendil-works/pi-coding-agent"

	// agentLogPath receives the bridge's stdout/stderr, served on /log/agent.
	agentLogPath = "/tmp/prime-agent.log"

	// startTimeout bounds the wait for the bridge to bind. First boot may
	// include a global npm install against a cold cache.
	startTimeout = 180 * time.Second
)

func bridgeScriptPath() string { return filepath.Join(bridgeScriptDir, "bridge.mjs") }

func (a *Adapter) Start(ctx context.Context, rt framework.RuntimeContext) (framework.StartResult, error) {
	a.mu.RLock()
	initialized, token, version := a.initialized, a.bridgeToken, a.binding.PackageVersion
	provider, model := a.personaProvider, a.personaModel
	a.mu.RUnlock()

	if !initialized {
		if err := installPinned(ctx, version); err != nil {
			return framework.StartResult{}, fmt.Errorf("prime.Start: %w", err)
		}
		if token == "" {
			var err error
			if token, err = randomTokenHex(); err != nil {
				return framework.StartResult{}, fmt.Errorf("prime.Start: generate bridge token: %w", err)
			}
		}
	} else {
		// Restart: never redo install or rewrite agent-owned state — the
		// platform keeps the agent alive without interfering with what the
		// agent did to itself.
		logger.Logf("prime restart: skipping install (preserving agent self-modifications)")
	}

	if err := materializeBridge(); err != nil {
		return framework.StartResult{}, fmt.Errorf("prime.Start: %w", err)
	}

	sdkProvider, baseURLEnv, baseURL := resolveInference(ctx, provider, model)

	// The agent doc goes to a standalone file OUTSIDE the framework home; the
	// bridge injects it as a virtual context file at session creation. No
	// markers, no stripping, and nothing for the agent's harness API to delete.
	pc := platform.Build(platform.RuntimeSnapshot{
		SealedVersion:    rt.SealedVersion,
		FrameworkVersion: version,
		WhitelistMax:     whitelistMax(),
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
		ZGComputeRouted:  provider == zgComputeProvider,
		BootTime:         time.Now(),
	})
	if err := os.WriteFile(agentDocPath(), []byte(platform.AssembleAgentDoc(pc, a.FrameworkFacts())), 0o644); err != nil {
		// Serving without the platform doc means an agent that doesn't know its
		// own identity or the sign-refusal doctrine. Fail rather than degrade.
		return framework.StartResult{}, fmt.Errorf("prime.Start: write agent doc %s: %w", agentDocPath(), err)
	}

	cmd, err := spawnBridge(bridgeEnv{
		token:       token,
		apiKey:      rt.APIKey,
		sdkProvider: sdkProvider,
		model:       model,
		baseURLEnv:  baseURLEnv,
		baseURL:     baseURL,
		rt:          rt,
	})
	if err != nil {
		return framework.StartResult{}, fmt.Errorf("prime.Start: %w", err)
	}

	a.mu.Lock()
	a.cmd = cmd
	a.bridgeToken = token
	a.initialized = true
	a.mu.Unlock()

	addr := fmt.Sprintf("127.0.0.1:%d", bridgePort)
	if err := waitForListen(ctx, addr, startTimeout); err != nil {
		return framework.StartResult{}, fmt.Errorf("prime.Start: bridge not listening: %w", err)
	}
	return framework.StartResult{Upstream: "http://" + addr, PID: cmd.Process.Pid}, nil
}

// zgComputeProvider is the persona-seed provider name that means "route through
// the 0G compute router".
const zgComputeProvider = "0g-compute"

// resolveInference translates the persona seed's inference pin into the shape
// the bridge needs: the SDK provider id, plus the base-URL env var to set when
// the request has to go through the 0G router.
//
// Provider knowledge lives in internal/inference, never here — the openclaw
// adapter learned that the hard way when the router added Anthropic-format
// models and a hardcoded OpenAI assumption turned every first inference into a
// 400 (FRAMEWORK_ADAPTER.md §12, item 19). This function only decides HOW the
// framework is told about a resolved route.
func resolveInference(ctx context.Context, provider, model string) (sdkProvider, baseURLEnv, baseURL string) {
	if provider != zgComputeProvider {
		// A native provider ("anthropic", "openai", …) needs no rewriting: the
		// SDK's own registry knows it and reads its standard base URL.
		return provider, "", ""
	}
	route := inference.ResolveZG(ctx, model)
	switch route.Format {
	case inference.WireAnthropic:
		return "anthropic", "ANTHROPIC_BASE_URL", route.BaseURL
	default:
		return "openai", "OPENAI_BASE_URL", route.BaseURL
	}
}

// installPinned installs the whitelisted SDK version globally. npm is the only
// pinnable channel the project offers (the public `curl | sh` installer fetches
// an unversioned-by-default release), and the bridge imports the package by
// name, so a global install is exactly what it needs.
func installPinned(ctx context.Context, version string) error {
	spec := npmPackage + "@" + coerceWhitelisted(version)
	logger.Logf("prime: installing %s", spec)
	cmd := exec.CommandContext(ctx, "npm", "install", "-g", "--no-fund", "--no-audit", spec)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("npm install %s: %w: %s", spec, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ReconcileFramework implements framework.VersionReconciler: on `framework`
// role drift, force the install back to the whitelist ceiling before the
// manager reloads the process.
func (a *Adapter) ReconcileFramework(ctx context.Context) error {
	return installPinned(ctx, whitelistMax())
}

// materializeBridge writes the embedded bridge script to disk. Rewritten on
// every Start so a sealed upgrade always ships its own bridge.
func materializeBridge() error {
	src, err := bridgeFS.ReadFile("bridge/bridge.mjs")
	if err != nil {
		return fmt.Errorf("read embedded bridge: %w", err)
	}
	if err := ensureDir(bridgeScriptDir); err != nil {
		return err
	}
	if err := os.WriteFile(bridgeScriptPath(), src, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", bridgeScriptPath(), err)
	}
	return nil
}

type bridgeEnv struct {
	token       string
	apiKey      string
	sdkProvider string
	model       string
	baseURLEnv  string
	baseURL     string
	rt          framework.RuntimeContext
}

// spawnBridge starts the node bridge with a strict environment allowlist.
//
// Bootstrap's own env is NOT inherited: a leaked SANDBOX_SEAL_KEY would
// otherwise be readable from inside the agent process via `env` or
// /proc/self/environ. Same rule as the openclaw and hermes adapters.
func spawnBridge(be bridgeEnv) (*exec.Cmd, error) {
	logFile, err := os.OpenFile(agentLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", agentLogPath, err)
	}

	nodePath, err := npmGlobalRoot()
	if err != nil {
		logFile.Close()
		return nil, err
	}

	cmd := exec.Command("node", bridgeScriptPath())
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// The agent's own working directory: keep it inside the framework home so
	// cwd-relative discovery (project skills, context files) stays within the
	// paths this adapter manages.
	cmd.Dir = primeHome

	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"NODE_PATH=" + nodePath,
		"PRIME_AGENT_CODING_AGENT_DIR=" + primeHome,
		fmt.Sprintf("SEAL_BRIDGE_PORT=%d", bridgePort),
		"SEAL_BRIDGE_TOKEN=" + be.token,
		"SEAL_AGENT_DOC=" + agentDocPath(),
	}
	if be.sdkProvider != "" {
		env = append(env, "SEAL_MODEL_PROVIDER="+be.sdkProvider)
	}
	if be.model != "" {
		env = append(env, "SEAL_MODEL_ID="+be.model)
	}
	if be.apiKey != "" {
		// Handed to the SDK via authStorage.setRuntimeApiKey (never persisted),
		// so the inference key touches no tracked path.
		env = append(env, "SEAL_MODEL_API_KEY="+be.apiKey)
	}
	if be.baseURLEnv != "" && be.baseURL != "" {
		env = append(env, be.baseURLEnv+"="+be.baseURL)
	}
	// Public on-chain facts the agent benefits from knowing directly, mirroring
	// the openclaw allowlist. The authoritative copy is the injected doc.
	if be.rt.PublicURL != "" {
		env = append(env, "AGENT_PUBLIC_URL="+be.rt.PublicURL)
	}
	if be.rt.SealSignSock != "" {
		env = append(env, "SEAL_SIGN_SOCK="+be.rt.SealSignSock)
	}
	if be.rt.AgentSeal != "" {
		env = append(env, "AGENT_SEAL="+be.rt.AgentSeal)
	}
	cmd.Env = env

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("start bridge: %w", err)
	}
	logger.Logf("prime: bridge started (pid %d, port %d, provider %s/%s)",
		cmd.Process.Pid, bridgePort, be.sdkProvider, be.model)
	return cmd, nil
}

// npmGlobalRoot resolves the global node_modules path so the bridge can import
// the SDK it was installed with.
func npmGlobalRoot() (string, error) {
	out, err := exec.Command("npm", "root", "-g").Output()
	if err != nil {
		return "", fmt.Errorf("npm root -g: %w", err)
	}
	root := strings.TrimSpace(string(out))
	if root == "" {
		return "", fmt.Errorf("npm root -g returned nothing")
	}
	return root, nil
}

// randomTokenHex mints the bridge bearer token: 32 random bytes, hex-encoded.
// Regenerated per container (memory-only until AuthResponse hands it to a
// verified owner), so a reset rotates it — which the SDK's lazy re-auth
// handles transparently.
func randomTokenHex() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// waitForListen polls a TCP address until it accepts a connection.
//
// (This, randomTokenHex and the install helper are near-duplicates of the
// openclaw and hermes equivalents. FRAMEWORK_ADAPTER.md §12 item 9 calls for a
// shared spawn-util package at the third port; kept local here so this change
// does not touch two shipping adapters, but that refactor is now due.)
func waitForListen(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s not accepting connections after %s", addr, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// Stop terminates the bridge: SIGTERM, wait, SIGKILL.
func (a *Adapter) Stop(ctx context.Context, gracefulTimeout time.Duration) error {
	a.mu.Lock()
	cmd := a.cmd
	a.cmd = nil
	a.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}
	_ = cmd.Process.Signal(os.Interrupt)

	done := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(gracefulTimeout):
		_ = cmd.Process.Kill()
	}

	// The bridge hosts the agent in-process, but an IPython kernel it spawned
	// can outlive it and hold state; sweep any stray child so the next Start
	// gets a clean port and kernel.
	_ = exec.Command("pkill", "-f", bridgeScriptPath()).Run()
	return nil
}

// Liveness: the bridge's port is open. Cheap enough for the 5s probe loop.
func (a *Adapter) Liveness(ctx context.Context) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", bridgePort), 2*time.Second)
	if err != nil {
		return fmt.Errorf("prime.Liveness: %w", err)
	}
	conn.Close()
	return nil
}

// Readiness: the bridge answers its loopback health route. Distinct from
// Liveness because the first session build (model resolution, skill discovery)
// happens lazily and can lag the port being open.
func (a *Adapter) Readiness(ctx context.Context) error {
	url := fmt.Sprintf("http://127.0.0.1:%d/healthz", bridgePort)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("prime.Readiness: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("prime.Readiness: /healthz returned %d", resp.StatusCode)
	}
	return nil
}

// AuthResponse hands the verified owner the bridge bearer token. The proxy has
// already checked the EIP-191 signature against the live on-chain owner; this
// only decides what a verified owner receives.
func (a *Adapter) AuthResponse(ctx context.Context) (any, error) {
	a.mu.RLock()
	token := a.bridgeToken
	a.mu.RUnlock()
	if token == "" {
		return nil, fmt.Errorf("prime.AuthResponse: bridge not started yet")
	}
	return map[string]any{"token": token}, nil
}

// MonitorExit satisfies manager.Adapter: invoke onExit exactly once when the
// spawned process exits, with cmd.Wait's error. A non-nil error is a crash the
// manager restarts immediately; nil defers to the liveness verdict.
func (a *Adapter) MonitorExit(onExit func(err error)) {
	a.mu.RLock()
	cmd := a.cmd
	a.mu.RUnlock()
	if cmd == nil {
		return
	}
	go func() { onExit(cmd.Wait()) }()
}

// SubprocessLogPath implements framework.SubprocessLogProvider: the bridge log
// is what /log/agent serves.
func (a *Adapter) SubprocessLogPath() string { return agentLogPath }
