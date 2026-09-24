package prime

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/platform"
	"seal-verify/internal/privsep"
	"seal-verify/internal/settings"
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

	// releasePackage is the global npm package name the release tarball installs
	// under. The bridge imports it, and Start verifies the installed version
	// against the binding rather than installing anything — the framework is
	// provisioned at image build time (images/prime/Dockerfile), so its bytes
	// are covered by the image hash that goes into on-chain
	// validFrameworkHashes. A first-Start download would leave the running
	// framework outside that measurement.
	releasePackage = "prime-agent"

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
	cfg := a.settings
	a.mu.RUnlock()

	// The inference pin comes from the owner's settings, rendered by
	// RenderSettings before every Start. Nothing on disk backs it up any more,
	// so a nil here is a bootstrap-sequence bug rather than an owner mistake —
	// and guessing would run a model the owner never chose, which this adapter
	// has always refused to do (see the bridge's resolveModel).
	if cfg == nil {
		return framework.StartResult{}, fmt.Errorf(
			"prime.Start: RenderSettings has not run — the owner's settings must be rendered before the bridge is spawned")
	}
	provider, model := cfg.Provider, cfg.Model
	if provider == "" || model == "" {
		return framework.StartResult{}, fmt.Errorf(
			"prime.Start: settings carry no inference pin (provider=%q model=%q)", provider, model)
	}

	if !initialized {
		if err := verifyInstalled(ctx, version); err != nil {
			return framework.StartResult{}, fmt.Errorf("prime.Start: %w", err)
		}
		if token == "" {
			var err error
			if token, err = randomTokenHex(); err != nil {
				return framework.StartResult{}, fmt.Errorf("prime.Start: generate bridge token: %w", err)
			}
		}
	} else {
		// Restart: never rewrite agent-owned state — the platform keeps the
		// agent alive without interfering with what the agent did to itself.
		logger.Logf("prime restart: reusing the installed framework and bridge token")
	}

	if err := materializeBridge(); err != nil {
		return framework.StartResult{}, fmt.Errorf("prime.Start: %w", err)
	}
	if err := ensureDir(sessionStateDir()); err != nil {
		return framework.StartResult{}, fmt.Errorf("prime.Start: %w", err)
	}

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
		ZGComputeRouted:  cfg.Endpoint != nil,
		BootTime:         time.Now(),
	})
	if err := os.WriteFile(agentDocPath(), []byte(platform.AssembleAgentDoc(pc, a.FrameworkFacts())), 0o644); err != nil {
		// Serving without the platform doc means an agent that doesn't know its
		// own identity or the sign-refusal doctrine. Fail rather than degrade.
		return framework.StartResult{}, fmt.Errorf("prime.Start: write agent doc %s: %w", agentDocPath(), err)
	}

	cmd, err := spawnBridge(bridgeEnvFor(*cfg, token, rt))
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

// verifyInstalled checks that the framework baked into this image is the one
// the agent's binding asks for, and fails Start loudly when it is not.
//
// This adapter deliberately does NOT install at runtime, so there is no
// framework.VersionReconciler: a drifted `framework` role is committed on chain
// as-is (the documented degradation, FRAMEWORK_ADAPTER.md §2.2) rather than
// silently downloading a different framework into an attested container. The
// consequence is a hard constraint on releases: the version whitelist and the
// image must move together, and this check is what turns a mismatch into a
// clear boot failure instead of an agent running something nobody validated.
func verifyInstalled(ctx context.Context, version string) error {
	want := coerceWhitelisted(version)

	root, err := npmGlobalRoot()
	if err != nil {
		return fmt.Errorf("locate the global install: %w", err)
	}
	pkgDir := filepath.Join(root, releasePackage)

	// Read package.json directly rather than asking node: a bare
	// require("prime-agent/package.json") fails twice over — the global
	// node_modules is not on node's default resolution path, and the package's
	// `exports` map does not expose ./package.json.
	raw, err := os.ReadFile(filepath.Join(pkgDir, "package.json"))
	if err != nil {
		return fmt.Errorf("%s is not installed in this image (expected %s): %w — a prime-agent binding needs the prime-agent image; check the deploy's sealedImage", releasePackage, want, err)
	}
	var meta struct{ Version string }
	if err := json.Unmarshal(raw, &meta); err != nil {
		return fmt.Errorf("parse %s/package.json: %w", pkgDir, err)
	}
	if meta.Version != want {
		return fmt.Errorf("image carries %s@%s but this agent's binding resolves to %s; the version whitelist and the image are out of sync", releasePackage, meta.Version, want)
	}

	// The Python half is what makes this framework hostable at all — the harness
	// state this adapter anchors on chain is written by it, in the kernel. Assert
	// the provisioned interpreter can import BOTH halves.
	//
	// Checking for .py files in the install tree is not enough: the runtime
	// sources ship inside the release tarball, so that check passes on an image
	// where the kernel venv was never provisioned. An agent there looks perfectly
	// healthy and never persists a thing.
	if out, err := exec.CommandContext(ctx, kernelVenvPython(), "-c", "import ipykernel, rlm.harness").CombinedOutput(); err != nil {
		return fmt.Errorf("kernel venv at %s cannot import ipykernel + rlm.harness: %w: %s — the image's kernel bootstrap did not complete, so the harness state would never be written",
			kernelVenvPython(), err, strings.TrimSpace(string(out)))
	}

	logger.Logf("prime: %s@%s present with a working kernel venv (binding resolved to %s)", releasePackage, meta.Version, want)
	return nil
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

// bridgeEnv is everything the bridge is told about this boot. The settings
// half of it is built by bridgeEnvFor.
type bridgeEnv struct {
	token    string
	apiKey   string
	provider string // registration name the bridge resolves the model under
	model    string
	modelAPI string // wire API name; empty for a framework built-in
	baseURL  string // endpoint to register; empty for a framework built-in
	effort   string // reasoning level for the session; "" = the platform names none
	rt       framework.RuntimeContext
}

// bridgeEnvFor maps the owner's resolved settings onto the bridge's
// environment. A separate function from spawnBridge because this mapping is
// the whole of the configuration channel for this adapter and has to be
// testable without an installed framework.
//
// The inference credential comes from the RESOLVED SETTINGS, not from
// RuntimeContext: the resolved document is where the platform decides what
// this boot runs and what it authenticates with, and the two drifting apart
// once dialed a platform-routed endpoint keyless and 401'd.
//
// Note what is NOT behind the endpoint check: the effort bound. Only the
// wiring (base URL, wire API) depends on who serves the model — a model that
// takes a reasoning bound takes it wherever it is served.
//
// SEAL_OWNER_THINKING carries the LEVEL, and it is the only thing that does:
// models.json never holds one (its thinkingLevelMap is a spelling table, not
// a choice). It is NOT what makes the level reach the wire. The SDK gates
// that on the resolved model's own reasoning flag and its provider's compat
// block — rendered into models.json by this adapter for a provider registered
// there, and read from the SDK's built-in tables for a framework built-in,
// which this adapter neither writes nor can see (bridge.mjs, buildSession).
//
// Both of Effort's empty outcomes pass no level, deliberately: this variable
// names a level, and neither "the catalog says this model takes no bound" nor
// "the catalog said nothing" gives the platform one to name. Where the two
// differ they are kept apart — in the rendered flags, see reasoningClaim in
// modelsjson.go. The bridge floors an unset variable at "low", so a thinking
// model the framework knows about stays bounded either way.
func bridgeEnvFor(cfg settings.Resolved, token string, rt framework.RuntimeContext) bridgeEnv {
	level, _ := cfg.Effort()
	be := bridgeEnv{
		token:    token,
		apiKey:   cfg.APIKey,
		provider: cfg.Provider,
		model:    cfg.Model,
		effort:   level,
		rt:       rt,
	}
	if cfg.Endpoint != nil {
		be.baseURL = cfg.Endpoint.BaseURL
		be.modelAPI = wireAPI(cfg.Endpoint.Format)
	}
	return be
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

	// The bridge imports `prime-agent` by bare specifier. That resolves because
	// the bridge is materialized under /usr/local/lib/, whose sibling
	// /usr/local/lib/node_modules IS npm's global root, so node's ordinary
	// walk-up finds it — verified in the built image. NODE_PATH is set anyway
	// for anything CommonJS in the dependency graph; it would NOT be enough on
	// its own, since NODE_PATH is ignored by ESM resolution.
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
	cmd.Env = be.environ(nodePath)

	// Run the bridge (and the IPython kernel it spawns) as the low-privilege
	// agent user when the image provides one (no-op otherwise — see
	// internal/privsep). Restore wrote the home as root, so hand it over
	// now; $HOME itself must also accept new dotfiles. sessionStateDir is
	// under /tmp (world-writable), no handover needed.
	if privsep.Drop(cmd) {
		privsep.OwnPath(os.Getenv("HOME"))
		privsep.OwnTree(primeHome)
	}

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("start bridge: %w", err)
	}
	logger.Logf("prime: bridge started (pid %d, port %d, provider %s/%s)",
		cmd.Process.Pid, bridgePort, be.provider, be.model)
	return cmd, nil
}

// environ is the bridge's whole environment: a strict allowlist, built as a
// pure function of bridgeEnv so what the framework is told can be asserted in
// a test without spawning anything.
func (be bridgeEnv) environ(nodePath string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"NODE_PATH=" + nodePath,
		"PRIME_AGENT_CODING_AGENT_DIR=" + primeHome,
		// Read by harness.py inside the IPython kernel, which the SDK spawns as
		// a child of this bridge and which therefore inherits this env. See
		// sessionStateDir for why leaving it unset is not an option.
		"RLM_SESSION_DIR=" + sessionStateDir(),
		fmt.Sprintf("SEAL_BRIDGE_PORT=%d", bridgePort),
		"SEAL_BRIDGE_TOKEN=" + be.token,
		"SEAL_AGENT_DOC=" + agentDocPath(),
	}
	if be.provider != "" {
		env = append(env, "SEAL_MODEL_PROVIDER="+be.provider)
	}
	if be.model != "" {
		env = append(env, "SEAL_MODEL_ID="+be.model)
	}
	if be.apiKey != "" {
		// Handed to the SDK via authStorage.setRuntimeApiKey (never persisted),
		// so the inference key touches no tracked path.
		env = append(env, "SEAL_MODEL_API_KEY="+be.apiKey)
	}
	// A non-empty base URL tells the bridge to register the model as a custom
	// provider (models.json) rather than expecting a built-in. The API key is
	// referenced there BY ENV VAR NAME, so it stays out of the file.
	if be.baseURL != "" {
		env = append(env, "SEAL_MODEL_BASE_URL="+be.baseURL)
		if be.modelAPI != "" {
			env = append(env, "SEAL_MODEL_API="+be.modelAPI)
		}
	}
	if be.effort != "" {
		// The reasoning level: the owner's choice, or the platform's low floor
		// for a model the catalog flags as thinking whose owner expressed no
		// preference (see settings.Resolved.Effort — an always-thinking model
		// with no bound reasons forever and never writes a reply). The bridge
		// uses it as the session level and as the baseline a per-message
		// override restores to.
		//
		// SEAL_OWNER_THINKING keeps its name because it is the bridge's
		// contract (bridge.mjs), which ships inside this binary; only the
		// SOURCE of the value changed, from the deploy-time env to the owner's
		// settings document.
		env = append(env, "SEAL_OWNER_THINKING="+be.effort)
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
	return env
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
