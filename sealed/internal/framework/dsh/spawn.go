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
	"seal-verify/internal/inference"
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

	// zgComputeProvider is the persona-seed provider name meaning "route
	// through the 0G compute router".
	zgComputeProvider = "0g-compute"
)

func bridgeScriptPath() string { return filepath.Join(bridgeScriptDir, "bridge.mjs") }

// Start: verify the framework is the one the binding asks for → resolve the
// inference pin → write the agent doc → materialize the bridge → spawn it
// de-privileged → wait for it to listen.
func (a *Adapter) Start(ctx context.Context, rt framework.RuntimeContext) (framework.StartResult, error) {
	a.mu.RLock()
	initialized, token, version := a.initialized, a.bridgeToken, a.binding.PackageVersion
	a.mu.RUnlock()

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

	// The inference pin's durable home is the tracked settings.yaml (readPin).
	// `persona` is a mint-time seed gone from chain at the first drift commit,
	// so later boots have only the file — same fix prime made with models.json.
	provider, model := readPin()
	if provider == "" || model == "" {
		return framework.StartResult{}, fmt.Errorf(
			"dsh.Start: no inference pin — neither %s nor the persona seed named a provider/model", settingsYAMLPath())
	}
	sdkProvider, api, baseURL := resolveInference(ctx, provider, model)

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
		ZGComputeRouted:  provider == zgComputeProvider,
		Deprivileged:     privsep.Active(),
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
		apiKey:      rt.APIKey,
		sdkProvider: sdkProvider,
		model:       model,
		modelAPI:    api,
		baseURL:     baseURL,
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

// resolveInference translates the pin into what the bridge's llm-pi-ai route
// needs: the provider name to register under, the wire API, and the endpoint.
// A native provider is a catalog built-in (empty baseURL); 0g-compute resolves
// to the router endpoint for the model's wire format. Provider knowledge lives
// in internal/inference (the openclaw hardcoded-OpenAI regression, §12/19).
func resolveInference(ctx context.Context, provider, model string) (sdkProvider, api, baseURL string) {
	if provider != zgComputeProvider {
		return provider, "", ""
	}
	route := inference.ResolveZG(ctx, model)
	if route.Format == inference.WireAnthropic {
		return provider, "anthropic-messages", route.BaseURL
	}
	return provider, "openai-completions", route.BaseURL
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
	token       string
	apiKey      string
	sdkProvider string
	model       string
	modelAPI    string
	baseURL     string
	rt          framework.RuntimeContext
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

	// Strict env whitelist — do NOT inherit bootstrap's env so a leaked
	// SANDBOX_SEAL_KEY can't be read via /proc/self/environ from inside the
	// agent process.
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"NODE_PATH=" + nodePath, // belt for any CJS child; ESM resolves by ancestor walk
		"DSH_HOME=" + dshHome,
		fmt.Sprintf("SEAL_BRIDGE_PORT=%d", bridgePort),
		"SEAL_BRIDGE_TOKEN=" + be.token,
		"SEAL_AGENT_DOC=" + agentDocPath(),
		"SEAL_PERSONA_PATH=" + appendSystemPath(),
		"SEAL_MODEL_PROVIDER=" + be.sdkProvider,
		"SEAL_MODEL_ID=" + be.model,
	}
	if be.apiKey != "" {
		// Resolved by ctx.credentials from the process env (top, read-only
		// layer), so the key never touches a credentials file.
		env = append(env, "SEAL_MODEL_API_KEY="+be.apiKey)
	}
	if be.baseURL != "" {
		env = append(env, "SEAL_MODEL_BASE_URL="+be.baseURL)
		if be.modelAPI != "" {
			env = append(env, "SEAL_MODEL_API="+be.modelAPI)
		}
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
	cmd.Env = env

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
	logger.Logf("dsh: bridge started (pid %d, port %d, provider %s/%s)",
		cmd.Process.Pid, bridgePort, be.sdkProvider, be.model)
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
	}
}
