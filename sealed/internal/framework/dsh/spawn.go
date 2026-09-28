package dsh

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
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/platform"
	"seal-verify/internal/privsep"
)

// The bridge and its two platform plugins ship inside the sealed binary and
// are materialized at Start — so their bytes are covered by the sealed image
// hash and can never drift out of sync with the adapter that spawns them,
// exactly like the prime bridge.
//
//go:embed bridge/bridge.mjs bridge/seal-tools.mjs bridge/seal-guard.mjs
var bridgeFS embed.FS

const (
	// bridgePort is the bridge's loopback upstream. Distinct from openclaw
	// (3284), hermes (8642), prime (8791).
	bridgePort = 8794

	// bridgeScriptDir is where the embedded bridge is materialized. Chosen as
	// a SIBLING of the image's global node_modules (/usr/local/lib/node_modules)
	// so the bridge's bare `@deepseek-ai/*` ESM imports resolve by Node's
	// ancestor node_modules walk — the ESM loader does not consult NODE_PATH.
	// Same mechanism the prime bridge relies on.
	bridgeScriptDir = "/usr/local/lib/seal-dsh-bridge"

	// agentLogPath receives the bridge's stdout/stderr, served on /log/agent.
	agentLogPath = "/tmp/dsh-agent.log"

	// startTimeout bounds the wait for the bridge to bind. First boot composes
	// the whole plugin tree and the first model resolution.
	startTimeout = 180 * time.Second

	// versionPackage is the installed npm package whose version we check against
	// the whitelist. The DSH family releases lockstep (whitelist.go), so the
	// spine package's version equals the `@deepseek-ai/dsh` version the
	// whitelist names.
	versionPackage = "@deepseek-ai/dsh-agent-spine-demo"
)

func bridgeScriptPath() string { return filepath.Join(bridgeScriptDir, "bridge.mjs") }

// Start: take the pin RenderSettings resolved → verify the framework is the
// one the binding asks for → write the agent doc → materialize the bridge →
// spawn it de-privileged → wait for it to listen.
func (a *Adapter) Start(ctx context.Context, rt framework.RuntimeContext) (framework.StartResult, error) {
	a.mu.RLock()
	initialized, token, version := a.initialized, a.bridgeToken, a.binding.PackageVersion
	rendered := a.rendered
	a.mu.RUnlock()

	// The pin comes from the owner's settings document, not from parsing a
	// file: settings.yaml stopped being a role and stopped existing, so there
	// is nothing on disk to read back and nothing an agent edit could
	// re-point (settings.go). A missing render is a bootstrap bug — not
	// something an owner can cause — so it fails before anything is spawned.
	if rendered == nil {
		return framework.StartResult{}, fmt.Errorf("dsh.Start: RenderSettings has not run before Start (bootstrap must render the owner's settings first)")
	}
	provider, model := rendered.resolved.Provider, rendered.resolved.Model
	if provider == "" || model == "" {
		return framework.StartResult{}, fmt.Errorf(
			"dsh.Start: no inference pin — the owner's settings name provider=%q model=%q; substituting a model the owner never picked is not an option", provider, model)
	}

	// The credential comes from the RESOLVED SETTINGS, never from
	// RuntimeContext: RuntimeContext is captured at the first Start and
	// replayed verbatim on every restart (so a key rotated at runtime would be
	// silently reverted), it is losing these fields, and reading the key from
	// it is what dialled a platform-routed endpoint keyless and 401'd live.
	//
	// Missing and platform-routed is fatal here rather than at the first turn:
	// the 0G router answers an unauthenticated call with a 401, so the
	// container would come up healthy, serve /hello, and fail every single
	// chat with an error the owner cannot place.
	apiKey := rendered.resolved.APIKey
	if apiKey == "" {
		if ep := rendered.resolved.Endpoint; ep != nil {
			return framework.StartResult{}, fmt.Errorf(
				"dsh.Start: the platform routes %s to %s but this boot has no inference key — the bridge would dial it unauthenticated and 401 on the first turn (check API_KEY in the container's environment)", model, ep.BaseURL)
		}
		// A framework built-in supplies its own endpoint, and only its own
		// provider knows whether that endpoint needs a key at all. Say so and
		// keep booting.
		logger.Logf("warn: dsh.Start: no inference key for this boot; provider %q must serve %s unauthenticated or the first turn fails", provider, model)
	}

	if !initialized {
		if err := verifyInstalled(version); err != nil {
			return framework.StartResult{}, fmt.Errorf("dsh.Start: %w", err)
		}
		if token == "" {
			var err error
			if token, err = randomTokenHex(); err != nil {
				return framework.StartResult{}, fmt.Errorf("dsh.Start: mint bridge token: %w", err)
			}
		}
	} else {
		logger.Logf("dsh restart: reusing installed framework + bridge token")
	}

	// Agent doc → a file OUTSIDE the framework home; the bridge injects it as a
	// system-prompt section (the authoritative channel). No markers, nothing a
	// tracked role carries.
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
		ZGComputeRouted:  rendered.resolved.Endpoint != nil,
		BootTime:         time.Now(),
	})
	if err := os.WriteFile(agentDocPath(), []byte(platform.AssembleAgentDoc(pc, a.FrameworkFacts())), 0o644); err != nil {
		// Serving without the platform doc means an agent that doesn't know its
		// identity or the sign-refusal doctrine. Fail rather than degrade.
		return framework.StartResult{}, fmt.Errorf("dsh.Start: write agent doc %s: %w", agentDocPath(), err)
	}

	if err := materializeBridge(); err != nil {
		return framework.StartResult{}, fmt.Errorf("dsh.Start: %w", err)
	}

	cmd, err := spawnBridge(bridgeEnv{
		token:       token,
		apiKey:      apiKey,
		settingsEnv: rendered.env,
		rt:          rt,
	})
	if err != nil {
		return framework.StartResult{}, fmt.Errorf("dsh.Start: %w", err)
	}

	a.mu.Lock()
	a.cmd = cmd
	a.bridgeToken = token
	a.initialized = true
	a.mu.Unlock()

	addr := fmt.Sprintf("127.0.0.1:%d", bridgePort)
	if err := waitForListen(ctx, addr, startTimeout); err != nil {
		return framework.StartResult{}, fmt.Errorf("dsh.Start: bridge not listening: %w", err)
	}
	return framework.StartResult{Upstream: "http://" + addr, PID: cmd.Process.Pid}, nil
}

// verifyInstalled checks the framework baked into this image matches the
// binding, and fails Start loudly otherwise. Like prime, this adapter does NOT
// install at runtime (no framework.VersionReconciler): a drifted `framework`
// role is committed on chain as-is rather than pulling a different framework
// into an attested container. The whitelist and the image must move together.
func verifyInstalled(version string) error {
	want := coerceWhitelisted(version)

	root, err := npmGlobalRoot()
	if err != nil {
		return fmt.Errorf("locate the global install: %w", err)
	}
	// Read package.json directly: the global node_modules is not on Node's
	// default resolution path and the package's exports map need not expose
	// ./package.json.
	raw, err := os.ReadFile(filepath.Join(root, versionPackage, "package.json"))
	if err != nil {
		return fmt.Errorf("%s is not installed in this image (expected %s): %w — a dsh binding needs the dsh image; check the deploy's sealedImage", versionPackage, want, err)
	}
	var meta struct{ Version string }
	if err := json.Unmarshal(raw, &meta); err != nil {
		return fmt.Errorf("parse %s/package.json: %w", versionPackage, err)
	}
	if meta.Version != want {
		return fmt.Errorf("image carries %s@%s but this agent's binding resolves to %s; the version whitelist and the image are out of sync", versionPackage, meta.Version, want)
	}
	logger.Logf("dsh: %s@%s present (binding resolved to %s)", versionPackage, meta.Version, want)
	return nil
}

// materializeBridge writes the embedded bridge + platform plugins to disk.
// Rewritten on every Start so a sealed upgrade always ships its own bridge.
func materializeBridge() error {
	if err := ensureDir(bridgeScriptDir); err != nil {
		return err
	}
	for _, name := range []string{"bridge.mjs", "seal-tools.mjs", "seal-guard.mjs"} {
		src, err := bridgeFS.ReadFile("bridge/" + name)
		if err != nil {
			return fmt.Errorf("read embedded %s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(bridgeScriptDir, name), src, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

// bridgeEnv carries the per-Start values the bridge process needs.
type bridgeEnv struct {
	token string
	// apiKey is settings.Resolved.APIKey — the credential the platform
	// resolved for THIS boot. Never framework.RuntimeContext.APIKey: that
	// field is going away, and it is frozen at the first Start, so a key that
	// changed since would be silently reverted by the next restart.
	apiKey string
	// settingsEnv is what RenderSettings produced (settings.go): the model
	// pin, the endpoint wiring, the reasoning bound and the owner's
	// composition knobs, already rendered as sorted KEY=VALUE entries.
	settingsEnv []string
	rt          framework.RuntimeContext
}

// environ builds the bridge process's whole environment.
//
// A strict whitelist, NOT the inherited env: a leaked SANDBOX_SEAL_KEY must
// not be readable via /proc/self/environ (or plain `env`) from inside the
// agent process, which runs arbitrary model-authored bash.
func (be bridgeEnv) environ(nodePath string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"NODE_PATH=" + nodePath, // belt for any CJS child; ESM resolves by ancestor walk
		"DSH_HOME=" + dshHome,
		fmt.Sprintf("SEAL_BRIDGE_PORT=%d", bridgePort),
		"SEAL_BRIDGE_TOKEN=" + be.token,
		"SEAL_AGENT_DOC=" + agentDocPath(),
		"SEAL_PERSONA_PATH=" + appendSystemPath(),
	}
	// Everything the owner's settings decide (pin, endpoint, reasoning bound,
	// composition knobs) — rendered once, deterministically, before Start.
	env = append(env, be.settingsEnv...)
	if be.apiKey != "" {
		// Resolved by ctx.credentials from the process env (top, read-only
		// layer), so the key never touches a credentials file.
		env = append(env, "SEAL_MODEL_API_KEY="+be.apiKey)
	}
	// Public on-chain facts the agent (and seal-tools) benefit from knowing.
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
	cmd.Dir = dshHome
	cmd.Env = be.environ(nodePath)

	// Run the bridge (and every tool subprocess it spawns) as the low-privilege
	// agent user when the image provides one (no-op otherwise — internal/privsep).
	// Restore wrote the home as root, so hand it over now; $HOME must also accept
	// new dotfiles. bridgeScriptDir stays root-owned read-only, which is fine.
	if privsep.Drop(cmd) {
		privsep.OwnPath(os.Getenv("HOME"))
		privsep.OwnTree(dshHome)
	}

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("start bridge: %w", err)
	}
	logger.Logf("dsh: bridge started (pid %d, port %d)", cmd.Process.Pid, bridgePort)
	return cmd, nil
}

// npmGlobalRoot resolves the global node_modules path.
func npmGlobalRoot() (string, error) {
	out, err := exec.Command("npm", "root", "-g").Output()
	if err != nil {
		return "", fmt.Errorf("npm root -g: %w", err)
	}
	root := string(out)
	for len(root) > 0 && (root[len(root)-1] == '\n' || root[len(root)-1] == ' ') {
		root = root[:len(root)-1]
	}
	if root == "" {
		return "", fmt.Errorf("npm root -g returned nothing")
	}
	return root, nil
}

// randomTokenHex mints the bridge bearer token: 32 random bytes, hex-encoded.
func randomTokenHex() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// waitForListen polls a TCP address until it accepts a connection.
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

// Stop terminates the bridge: SIGTERM, wait, SIGKILL, then sweep strays.
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

	// A tool subprocess the bridge spawned can outlive it; sweep any stray so
	// the next Start gets a clean port.
	_ = exec.Command("pkill", "-f", bridgeScriptPath()).Run()
	return nil
}

// Liveness: the bridge's port is open.
func (a *Adapter) Liveness(ctx context.Context) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", bridgePort), 2*time.Second)
	if err != nil {
		return fmt.Errorf("dsh.Liveness: %w", err)
	}
	conn.Close()
	return nil
}

// Readiness: the bridge answers its loopback health route. Distinct from
// Liveness because the first composition + model resolution happens lazily and
// can lag the port being open.
func (a *Adapter) Readiness(ctx context.Context) error {
	url := fmt.Sprintf("http://127.0.0.1:%d/healthz", bridgePort)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("dsh.Readiness: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dsh.Readiness: /healthz returned %d", resp.StatusCode)
	}
	return nil
}

// AuthResponse hands the verified owner the bridge bearer token. The proxy has
// already checked the EIP-191 signature against the live on-chain owner.
func (a *Adapter) AuthResponse(ctx context.Context) (any, error) {
	a.mu.RLock()
	token := a.bridgeToken
	a.mu.RUnlock()
	if token == "" {
		return nil, fmt.Errorf("dsh.AuthResponse: bridge not started yet")
	}
	return map[string]any{"token": token}, nil
}

// MonitorExit satisfies manager.Adapter: invoke onExit once when the bridge
// exits, with cmd.Wait's error.
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

// FrameworkRoutes declares the one public surface: the OpenAI-shaped chat API.
func (a *Adapter) FrameworkRoutes() []framework.Route {
	backend := fmt.Sprintf("http://127.0.0.1:%d", bridgePort)
	return []framework.Route{
		{
			Prefix:  "/v1/",
			Kind:    "chat",
			Auth:    "bearer",
			Signed:  false,
			Backend: backend,
			// STATEFUL, like prime: the conversation lives in the bridge's
			// in-memory DSH session and only the last user message of `messages`
			// is read, so re-sending an edited history does not rewind it.
			Description: "OpenAI-compatible chat/completions API (sealed bridge). STATEFUL: the conversation lives in a server-side session and only the last user message is read. Turns are serialized.",
		},
		{
			Prefix:  "/v1/responses",
			Kind:    "responses",
			Auth:    "bearer",
			Signed:  false,
			Backend: backend,
			// Same upstream as /v1/ (longest-prefix wins is a no-op here); the
			// separate entry exists so /hello ADVERTISES the capability — the SDK
			// picks Responses over chat/completions when it sees this kind (the
			// long-task surface: the turn is owned by a server-side response id,
			// not by the HTTP connection).
			Description: "OpenAI Responses API subset (sealed bridge): POST /v1/responses {input, stream} → events with sequence_number; GET /{id} polls; GET /{id}?stream=true&starting_after=N resumes; POST /{id}/cancel stops the turn. Same stateful session as the chat route.",
		},
	}
}
