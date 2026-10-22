package openclaw

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
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

// Start does the heavy lifting of bringing openclaw up, in two flavours:
//
//   - First call (initialized=false): npm-install the version pinned by the
//     framework dim, write the runtime sections of openclaw.json (gateway
//     token, controlUi flags, `gateway.mode = local`), then spawn.
//     The chain-restored workspace files were already written by Restore and
//     the inference sections by RenderSettings -- Start re-composes neither.
//
//   - Subsequent calls (supervisor restart): just spawn. We don't re-install
//     openclaw -- agent self-modifications survive restart untouched (see
//     ARCHITECTURE.zh.md §6: platform doesn't interfere with agent's own
//     evolution). The one exception is a restart after RenderSettings had to
//     rebuild a corrupt openclaw.json: the gateway section went with the old
//     file, so it is written again (same token).
//
// RenderSettings must have run first, both times: it owns the inference
// half of openclaw.json and hands Start the provider/model pin.
//
// The auth token is generated on first init and cached in a.authToken; the
// dashboard stays signed in across restarts because the token is stable.
func (a *Adapter) Start(ctx context.Context, rt framework.RuntimeContext) (framework.StartResult, error) {
	a.mu.RLock()
	cfg := a.cfg
	rendered := a.rendered
	cachedToken := a.authToken
	initialized := a.initialized
	configRebuilt := a.configRebuilt
	a.mu.RUnlock()
	if cfg == nil {
		return framework.StartResult{}, fmt.Errorf("openclaw: no config restored before Start")
	}
	// The pin comes from the settings document, not from parsing
	// openclaw.json: that file is an OUTPUT of RenderSettings now. A missing
	// render is a platform sequencing bug, not an owner mistake — fail loud
	// rather than spawning a gateway with no model wired up.
	if rendered == nil {
		return framework.StartResult{}, fmt.Errorf("openclaw: Start called before RenderSettings (programming error: the platform must render the owner's settings before every Start)")
	}
	resolved := *rendered
	provider := resolved.Provider
	model := resolved.Model
	if provider == "" || model == "" {
		logger.Logf("warn: settings carry no provider/model pin; openclaw will fail at first chat")
	}

	// What keeps the root-run install (npm and the package's own install
	// scripts) out of the agent's tree is its environment, installEnv:
	// OPENCLAW_HOME under framework.StateDir, the plugin-registry migration
	// off, and RootCommand's root-only TMPDIR. Installing before the
	// handover (prepareTree) only matters on a container's first boot; on a
	// restarted container the tree is already agent-owned, and
	// ReconcileFramework installs while the gateway runs.
	if !initialized {
		if err := installOpenclaw(cfg.framework.PackageVersion); err != nil {
			return framework.StartResult{}, err
		}
	}

	authToken, err := a.prepareTree(ctx, initialized, configRebuilt, cachedToken)
	if err != nil {
		return framework.StartResult{}, err
	}

	if initialized {
		// Restart: verify the binary is still installed, otherwise the spawn
		// will fail confusingly later. A static read, not a CLI run: root
		// runs no framework CLI.
		if probeOpenclawVersion(ctx) == "" {
			return framework.StartResult{}, fmt.Errorf("openclaw binary missing on restart (no openclaw package resolvable through the trusted PATH)")
		}
		logger.Logf("openclaw restart: skipping npm install (preserving agent self-modifications)")
	}

	// The inference credential goes into the gateway's environment
	// allowlist (gatewayEnv) and nowhere else — never into sealed's own
	// environment. The env NAME follows the wire format, not the provider
	// label: on 0g-compute a claude-* model rides the Anthropic-format
	// endpoint and openclaw's anthropic client reads ANTHROPIC_API_KEY. It
	// comes from the same resolved Endpoint the render wrote into the
	// config, so the config dialect and the key's env name can't disagree
	// (they once did, across a catalog flap, and openclaw went keyless at
	// inference).
	//
	// Both halves come from the RESOLVED SETTINGS, never from
	// RuntimeContext: the credential belongs to the inference document the
	// platform resolved for this boot (RuntimeContext is losing the field),
	// and reading it from the other struct is how a platform-routed
	// endpoint once got dialled keyless and 401'd live.
	apiKeyEnv, apiKey := inferenceCredential(resolved)
	if apiKey != "" && apiKeyEnv != "" {
		logger.Logf("OK   %s from the resolved settings goes to the gateway environment", apiKeyEnv)
	}

	// Build the single PlatformContext from RuntimeContext + config.
	// This is the one place where all platform-injection content is
	// assembled. The adapter's upsert functions only handle file I/O.
	// See internal/platform/context.go for content generation.
	fwVersion := probeOpenclawVersion(ctx)
	rs := platform.RuntimeSnapshot{
		SealedVersion:    rt.SealedVersion,
		FrameworkVersion: fwVersion,
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
		ZGComputeRouted:  isZGComputeRouted(provider),
		BootTime:         time.Now(),
	}
	rs.WhitelistMax = whitelistMax()

	pc := platform.Build(rs)

	// Deliver: adapter maps PlatformContext sections to framework files.
	// IDENTITY.md ← pc.Identity, SOUL.md ← pc.Sovereignty,
	// TOOLS.md ← pc.Capabilities + pc.Constraints + pc.Runtime.
	if err := upsertIdentityMD(identityMDPath(), pc.Identity); err != nil {
		logger.Logf("warn: upsert IDENTITY.md sealed section: %v", err)
	}
	if err := upsertSoulMD(soulMDPath(), pc.Sovereignty); err != nil {
		logger.Logf("warn: upsert SOUL.md sealed section: %v", err)
	}
	if err := upsertToolsMD(toolsMDPath(), pc, platform.RenderFrameworkFacts(a.FrameworkFacts())); err != nil {
		logger.Logf("warn: upsert TOOLS.md sealed section: %v", err)
	}
	if rt.AgentSeal != "" || rt.PublicURL != "" || rt.SealSignSock != "" {
		logger.Logf("OK   injected sealed sections (identity/soul/tools) for agent=%q public_url=%q sign_sock=%q",
			rt.AgentSeal, rt.PublicURL, rt.SealSignSock)
	}

	cmd, err := spawnGateway(apiKeyEnv, apiKey, rt)
	if err != nil {
		return framework.StartResult{}, err
	}
	a.mu.Lock()
	a.cmd = cmd
	a.authToken = authToken
	a.initialized = true
	a.configRebuilt = false
	a.mu.Unlock()

	addr := fmt.Sprintf("127.0.0.1:%d", upstreamPort)
	if err := waitForListen(ctx, addr, startTimeout); err != nil {
		// A blind TCP timeout hides the real reason — openclaw usually
		// crashed on startup (bad model/provider config, OOM, …) and never
		// bound. Surface the tail of its own log so the failure is
		// actionable instead of a mystery "not listening within 2m".
		return framework.StartResult{}, fmt.Errorf("openclaw not listening: %w\n--- %s (tail) ---\n%s", err, framework.LogPath(logName), tailOpenclawLog(40))
	}

	return framework.StartResult{
		Upstream: fmt.Sprintf("http://%s", addr),
		PID:      cmd.Process.Pid,
	}, nil
}

// prepareTree is Start's work between the install and the spawn, in the
// order it depends on: hand the tree over and link it, write the gateway
// section, then validate the config. It returns the gateway's auth token
// (cachedToken, or one minted on the first Start).
//
// The validator runs as the agent user, so the handover must come before
// it: on a first boot RenderSettings wrote openclaw.json as root, mode
// 0600, and a validator that cannot read the file exits non-zero — which
// ensureConfigAcceptable would take as a rejection, withdrawing the owner's
// overlay and then failing the start as a platform bug.
func (a *Adapter) prepareTree(ctx context.Context, initialized, configRebuilt bool, cachedToken string) (string, error) {
	authToken := cachedToken

	// Hand the framework tree to the agent user: the validator below runs
	// as that user and must be able to read what Restore and RenderSettings
	// wrote as root, and from here on every file root writes into the tree
	// takes the tree's owner (privsep.WriteFile). The agent's own HOME is
	// elsewhere (privsep.AgentHome). openclaw is told where its tree is
	// (OPENCLAW_STATE_DIR and OPENCLAW_HOME, stateEnv) rather than left to
	// find it from HOME; the tree is also linked at ~/.openclaw so the
	// paths the agent is told about resolve. sealed itself keeps using
	// openclawHome and never resolves the link.
	privsep.OwnTree(openclawHome)
	privsep.LinkAgentHome(".openclaw", openclawHome)

	// The gateway subtree lives in openclaw.json, which RenderSettings
	// rebuilds from scratch when it finds the file corrupt. Re-write it
	// after such a rebuild even on a restart: the token this adapter still
	// hands owners via /_seal/auth is only good if the gateway has it too.
	if !initialized || configRebuilt {
		if !initialized {
			newToken, err := randomTokenHex(32)
			if err != nil {
				return "", fmt.Errorf("generate openclaw auth token: %w", err)
			}
			authToken = newToken
		} else {
			logger.Logf("openclaw: openclaw.json was rebuilt from the owner's settings; re-writing the gateway section with the existing token")
		}
		if err := writeRuntimeSections(authToken); err != nil {
			return "", err
		}
	}

	// openclaw validates its config STRICTLY — an unknown key at the root is
	// "<root>: Invalid input" and the gateway refuses to run. The owner's
	// opaque overlay is merged into that same file, so a single junk key in it
	// used to take the agent OFFLINE (live: agent 411, overlay {"备注": …},
	// caught by the T2 drill). The platform cannot know openclaw's schema —
	// that is the whole point of the overlay being opaque — so it uses
	// openclaw's own judgment instead: validate, and if the file is rejected
	// while an overlay is present, strip the overlay, re-render, and boot on
	// the platform half alone. The owner's junk costs the owner their knobs,
	// never their agent; the log and the settings channel are how they learn.
	if err := a.ensureConfigAcceptable(ctx); err != nil {
		return "", err
	}
	return authToken, nil
}

// writeRuntimeSections merges per-boot config (gateway.token, controlUi
// flags) into openclaw.json. RenderSettings already wrote the inference
// sections; this function only touches the gateway subtree, which carries
// a credential minted for this boot and therefore never comes from the
// owner's settings overlay.
//
// `gateway.mode = local` used to be set by running `openclaw config set` as
// root after the first validation; it is written here instead, with the
// rest of the subtree, so root never runs the framework CLI.
//
// `gateway.controlUi.*` flags relax openclaw's CORS / device-auth checks
// because the sealed sandbox proxy at :8080 is the trust boundary --
// openclaw doesn't need its own.
//
// `gateway.http.endpoints.chatCompletions` is openclaw's OpenAI-compatible
// HTTP surface (/v1/chat/completions etc.), disabled by default upstream.
// It's gated behind the same gateway.auth token as the control UI -- a
// valid token is already an owner/operator credential there (per
// openclaw's own docs), so enabling it doesn't raise the trust bar we've
// already accepted for authenticate()'s dashboard handshake. This is what
// lets a caller without a browser actually talk to the agent.
func writeRuntimeSections(authToken string) error {
	return updateOpenclawJSON(func(cfg map[string]any) {
		cfg["gateway"] = map[string]any{
			"mode": "local",
			"auth": map[string]any{
				"mode":  "token",
				"token": authToken,
			},
			"controlUi": map[string]any{
				"dangerouslyAllowHostHeaderOriginFallback": true,
				"dangerouslyDisableDeviceAuth":             true,
				"allowInsecureAuth":                        true,
			},
			"http": map[string]any{
				"endpoints": map[string]any{
					"chatCompletions": map[string]any{
						"enabled": true,
					},
				},
			},
		}
	})
}

// probeOpenclawVersion returns the installed openclaw version, e.g.
// "2026.7.1", or "" when none is installed (the pre-Start seed in main.go
// runs before the install).
//
// A static read, not `openclaw --version`: root runs no framework CLI, and
// EvolutionFor("framework") calls this on every watcher tick. It resolves
// `openclaw` through the trusted PATH (privsep.LookPath — root-only
// directories, resolved to the real file) and reads "version" from the
// nearest package.json above it whose "name" is "openclaw": npm's global
// bin entry is a link into the package directory, so that is the package
// the binary belongs to.
//
// Package var, not func: EvolutionFor("framework") layers this live probe
// over the restored binding, so a real openclaw on the test machine's PATH
// makes round-trip results environment-dependent unless tests stub it.
// The conformance suite caught exactly that on a dev machine with a local
// openclaw install.
var probeOpenclawVersion = func(ctx context.Context) string {
	bin, err := privsep.LookPath("openclaw")
	if err != nil {
		return ""
	}
	return packageVersionAbove(bin, "openclaw")
}

// packageVersionAbove walks up from the file at bin and returns the version
// of the nearest package.json whose name is pkg ("" if none within a few
// levels).
func packageVersionAbove(bin, pkg string) string {
	dir := filepath.Dir(bin)
	for i := 0; i < 8 && dir != "/"; i++ {
		raw, err := privsep.ReadFile(filepath.Join(dir, "package.json"), privsep.LimitConfig)
		if err == nil {
			var meta struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}
			if json.Unmarshal(raw, &meta) == nil && meta.Name == pkg {
				return strings.TrimSpace(meta.Version)
			}
		}
		dir = filepath.Dir(dir)
	}
	return ""
}

// inferenceCredential is the (env var, value) pair openclaw's client needs
// for this boot. Both halves come from the resolved settings document —
// the credential is settings.Resolved.APIKey, NOT
// framework.RuntimeContext.APIKey, which is going away and which was never
// the thing settings.Resolve authenticated the endpoint with.
func inferenceCredential(s settings.Resolved) (envName, apiKey string) {
	return apiKeyEnvName(s), s.APIKey
}

// apiKeyEnvName resolves which env var openclaw's client will read the
// inference key from. A platform-routed model takes the name off its
// resolved Endpoint (the wire format decides: ANTHROPIC_API_KEY for the
// router's anthropic endpoint, OPENAI_API_KEY for the openai one); a
// framework built-in maps by provider name, matching openclaw's own table.
func apiKeyEnvName(s settings.Resolved) string {
	if s.Endpoint != nil {
		return s.Endpoint.EnvKey
	}
	switch s.Provider {
	case "anthropic":
		return "ANTHROPIC_API_KEY"
	case "openai":
		return "OPENAI_API_KEY"
	}
	return ""
}

// installOpenclaw installs the pinned version into the global prefix. npm
// writes root-owned directories, so it runs as root — through
// privsep.RootCommand, which resolves npm only in root-only PATH
// directories and gives it a fixed environment (root-only HOME and TMPDIR).
//
// openclaw's install script resolves its state directory from
// OPENCLAW_HOME (else HOME): it prunes plugin runtime state there and, unless
// disabled, migrates the plugin registry into a state database. Run as root
// against the agent's ~/.openclaw, that would leave root-owned state in the
// agent's tree and act on whatever the agent keeps there. installEnv points
// it at a root-only directory under framework.StateDir and disables the
// migration — the gateway, running as the agent, creates its own state — so
// the install touches nothing the agent can write. That also makes it safe
// while the gateway is running (ReconcileFramework).
func installOpenclaw(packageVersion string) error {
	spec := "openclaw"
	if v := strings.TrimSpace(packageVersion); v != "" {
		spec = "openclaw@" + v
	}
	logger.Logf("installing %s (this may take ~30s)...", spec)
	cmd, err := installCommand(spec)
	if err != nil {
		return fmt.Errorf("npm install %s: %w", spec, err)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("npm install %s: %v: %s", spec, err, strings.TrimSpace(string(out)))
	}
	if v := probeOpenclawVersion(context.Background()); v != "" {
		logger.Logf("OK   installed: openclaw %s", v)
	}
	return nil
}

// installCommand builds the root-run `npm install -g <spec>`: RootCommand's
// fixed environment plus installEnv. Separate from installOpenclaw so a test
// can check the environment the install really gets without running it.
func installCommand(spec string) (*exec.Cmd, error) {
	home, err := framework.StateSubdir(installHomeName)
	if err != nil {
		return nil, fmt.Errorf("install home: %w", err)
	}
	cmd, err := privsep.RootCommand(context.Background(), "npm", "install", "-g", "--no-audit", "--no-fund", spec)
	if err != nil {
		return nil, err
	}
	cmd.Env = append(cmd.Env, installEnv(home)...)
	return cmd, nil
}

// installHomeName is the framework.StateDir subdirectory installEnv gives
// openclaw's install script as OPENCLAW_HOME.
const installHomeName = "openclaw-install"

// installEnv is what installOpenclaw adds to RootCommand's environment:
// npm's prompts off, and openclaw's install script kept out of the agent's
// tree (see installOpenclaw).
func installEnv(home string) []string {
	return []string{
		"npm_config_update_notifier=false",
		"npm_config_fund=false",
		"npm_config_audit=false",
		"OPENCLAW_HOME=" + home,
		"OPENCLAW_DISABLE_PLUGIN_REGISTRY_MIGRATION=1",
	}
}

// gatewayEnv is the strict environment the openclaw subprocess gets.
//
// A whitelist, not the inherited env: a leaked SANDBOX_SEAL_KEY must not be
// readable via "env" or /proc/self/environ from inside the agent process.
//
// apiKey is the credential from the resolved settings document; passing
// rt.APIKey here instead is the defect that dialled a platform-routed
// endpoint keyless.
func gatewayEnv(apiKeyEnv, apiKey string, rt framework.RuntimeContext) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		// The agent's own home (privsep.AgentHome): its tools' caches and
		// config live there, and ~/.openclaw links to openclawHome.
		"HOME=" + privsep.AgentHome(),
	}
	env = append(env, stateEnv()...)
	if apiKey != "" && apiKeyEnv != "" {
		env = append(env, apiKeyEnv+"="+apiKey)
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
	return env
}

// stateEnv tells openclaw where its tree is, so that it never finds it
// through the ~/.openclaw link LinkAgentHome makes in the agent's home.
// openclaw resolves its own paths from two variables, and every
// whitelisted version gets both:
//
//   - OPENCLAW_STATE_DIR, the state directory: config, sessions, other
//     agents' workspaces (workspace-<id>), and in 2026.7.1 the exec tool's
//     approvals file;
//   - OPENCLAW_HOME, which openclaw takes as its home instead of HOME for
//     the paths it derives as ~/.openclaw/...: the default agent's
//     workspace and, in 2026.5.x, the exec tool's approvals file. It is the
//     directory holding the tree, so ~/.openclaw is the tree itself, as it
//     was when HOME was root's home. openclaw core also expands "~" from it
//     — in its config's path-valued keys (openclaw.json), in the paths its
//     media tools are given, and for files it keeps beside the tree
//     (~/.config/openclaw/gateway.env) — so those name root's home, where
//     the agent can create nothing outside the tree. The render rewrites
//     the owner's "~/..." and "/root/..." agent paths
//     (homeRelativeOverlayPaths), and the agent doc tells the agent
//     (QUIRKS.md).
//
// openclaw refuses to run its exec tool, and to append under the
// workspace, through a path with a symbolic link in it (QUIRKS.md), and a
// link the agent removed or replaced would silently point the gateway, the
// config validator and every openclaw CLI the agent runs at another tree —
// one without the config and token sealed renders. With both variables
// openclaw core no longer goes through the link. A few bundled plugins
// still do: they take their default locations from os.homedir(), which is
// HOME (memory-wiki's vault, the file-transfer audit log, memory-lancedb,
// voice-call). On 2026.7.1 memory-wiki's and the audit log's appends refuse
// the link, so the render gives an enabled memory-wiki an absolute vault
// path in the tree (applyMemoryWikiVault); the audit log has no setting
// and is not written (QUIRKS.md). HOME stays the agent's own home:
// openclaw's read/write/edit tools, and every program its exec tool runs,
// expand "~" from HOME, not OPENCLAW_HOME. Processes the gateway starts
// (its exec tool, the agent's shell, an openclaw CLI the agent runs)
// inherit both variables.
func stateEnv() []string {
	return []string{
		"OPENCLAW_STATE_DIR=" + openclawHome,
		"OPENCLAW_HOME=" + filepath.Dir(openclawHome),
	}
}

// logName names the gateway's log under framework.StateDir/log.
const logName = "openclaw"

// spawnGateway starts the gateway as the agent user (privsep.AgentCommand;
// a plain spawn when the image has no agent account), in the agent's own
// home. The tree it works in was handed over, and linked into that home,
// earlier in Start (prepareTree).
func spawnGateway(apiKeyEnv, apiKey string, rt framework.RuntimeContext) (*exec.Cmd, error) {
	logFile, err := framework.OpenLog(logName)
	if err != nil {
		return nil, fmt.Errorf("open openclaw log: %w", err)
	}
	// Background, not Start's ctx: the gateway outlives the call that
	// spawned it; Stop ends it.
	cmd, err := privsep.AgentCommand(context.Background(), "openclaw", "gateway", "run",
		"--allow-unconfigured", "--bind", "loopback",
		"--port", fmt.Sprintf("%d", upstreamPort))
	if err != nil {
		logFile.Close()
		return nil, fmt.Errorf("start openclaw gateway: %w", err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = gatewayEnv(apiKeyEnv, apiKey, rt)

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("start openclaw gateway: %w", err)
	}
	logger.Logf("OK   openclaw gateway spawned, pid=%d (log: %s)", cmd.Process.Pid, framework.LogPath(logName))
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

// tailOpenclawLog returns the last n lines of openclaw's log (best-effort).
// waitForListen only observes "no TCP", never why; on a startup failure this
// makes openclaw's own error (the real cause) legible to the attestor.
func tailOpenclawLog(n int) string {
	b, err := privsep.ReadTail(framework.LogPath(logName), 64<<10)
	if err != nil {
		return fmt.Sprintf("(no openclaw log: %v)", err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func randomTokenHex(nbytes int) (string, error) {
	buf := make([]byte, nbytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
