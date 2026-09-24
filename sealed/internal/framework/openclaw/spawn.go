package openclaw

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
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
//     token, controlUi flags), refresh `gateway.mode = local`, then spawn.
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

	authToken := cachedToken

	// The gateway subtree lives in openclaw.json, which RenderSettings
	// rebuilds from scratch when it finds the file corrupt. Re-write it
	// after such a rebuild even on a restart: the token this adapter still
	// hands owners via /_seal/auth is only good if the gateway has it too.
	if !initialized || configRebuilt {
		if !initialized {
			newToken, err := randomTokenHex(32)
			if err != nil {
				return framework.StartResult{}, fmt.Errorf("generate openclaw auth token: %w", err)
			}
			authToken = newToken
		} else {
			logger.Logf("openclaw: openclaw.json was rebuilt from the owner's settings; re-writing the gateway section with the existing token")
		}
		if err := writeRuntimeSections(authToken); err != nil {
			return framework.StartResult{}, err
		}
	}

	if !initialized {
		if err := installOpenclaw(cfg.framework.PackageVersion); err != nil {
			return framework.StartResult{}, err
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
		return framework.StartResult{}, err
	}

	if !initialized {
		if out, err := exec.Command("openclaw", "config", "set", "gateway.mode", "local").CombinedOutput(); err != nil {
			return framework.StartResult{}, fmt.Errorf("openclaw config set: %v: %s", err, strings.TrimSpace(string(out)))
		}
	} else {
		// Restart: verify the binary is still installed, otherwise the spawn
		// will fail confusingly later.
		if _, err := exec.Command("openclaw", "--version").Output(); err != nil {
			return framework.StartResult{}, fmt.Errorf("openclaw binary missing on restart: %w", err)
		}
		logger.Logf("openclaw restart: skipping npm install (preserving agent self-modifications)")
	}

	// Always export the inference provider API key into bootstrap's env so
	// spawnGateway's whitelist can pass it to the new openclaw subprocess.
	// The env NAME follows the wire format, not the provider label: on
	// 0g-compute a claude-* model rides the Anthropic-format endpoint and
	// openclaw's anthropic client reads ANTHROPIC_API_KEY. It comes from the
	// same resolved Endpoint the render wrote into the config, so the config
	// dialect and the exported key can't disagree (they once did, across a
	// catalog flap, and openclaw went keyless at inference).
	//
	// Both halves come from the RESOLVED SETTINGS, never from
	// RuntimeContext: the credential belongs to the inference document the
	// platform resolved for this boot (RuntimeContext is losing the field),
	// and reading it from the other struct is how a platform-routed
	// endpoint once got dialled keyless and 401'd live.
	apiKeyEnv, apiKey := inferenceCredential(resolved)
	if err := exportAPIKey(apiKeyEnv, apiKey); err != nil {
		return framework.StartResult{}, err
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
		return framework.StartResult{}, fmt.Errorf("openclaw not listening: %w\n--- /tmp/openclaw.log (tail) ---\n%s", err, tailOpenclawLog(40))
	}

	return framework.StartResult{
		Upstream: fmt.Sprintf("http://%s", addr),
		PID:      cmd.Process.Pid,
	}, nil
}

// writeRuntimeSections merges per-boot config (gateway.token, controlUi
// flags) into openclaw.json. RenderSettings already wrote the inference
// sections; this function only touches the gateway subtree, which carries
// a credential minted for this boot and therefore never comes from the
// owner's settings overlay.
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

// probeOpenclawVersion returns just the version number from
// `openclaw --version`. CLI output: "OpenClaw 2026.4.26 (be8c246)" -> "2026.4.26".
// Empty on probe error (binary not installed yet -- happens during pre-Start
// seed in main.go).
//
// Package var, not func: EvolutionFor("framework") layers this live probe
// over the restored binding, so a real openclaw on the test machine's PATH
// makes round-trip results environment-dependent unless tests stub it.
// The conformance suite caught exactly that on a dev machine with a local
// openclaw install.
var probeOpenclawVersion = func(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "openclaw", "--version").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 2 {
		return ""
	}
	return fields[1]
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

func exportAPIKey(envName, apiKey string) error {
	if apiKey == "" || envName == "" {
		return nil
	}
	if err := os.Setenv(envName, apiKey); err != nil {
		return fmt.Errorf("set %s: %w", envName, err)
	}
	logger.Logf("OK   exported %s from the resolved settings", envName)
	return nil
}

func installOpenclaw(packageVersion string) error {
	spec := "openclaw"
	if v := strings.TrimSpace(packageVersion); v != "" {
		spec = "openclaw@" + v
	}
	logger.Logf("installing %s (this may take ~30s)...", spec)
	if out, err := exec.Command("npm", "install", "-g", "--no-audit", "--no-fund", spec).CombinedOutput(); err != nil {
		return fmt.Errorf("npm install %s: %v: %s", spec, err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("openclaw", "--version").Output(); err == nil {
		logger.Logf("OK   installed: %s", strings.TrimSpace(string(out)))
	}
	return nil
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
		"HOME=" + os.Getenv("HOME"),
	}
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

func spawnGateway(apiKeyEnv, apiKey string, rt framework.RuntimeContext) (*exec.Cmd, error) {
	logFile, err := os.OpenFile("/tmp/openclaw.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open openclaw.log: %w", err)
	}
	cmd := exec.Command("openclaw", "gateway", "run",
		"--allow-unconfigured", "--bind", "loopback",
		"--port", fmt.Sprintf("%d", upstreamPort))
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	cmd.Env = gatewayEnv(apiKeyEnv, apiKey, rt)

	// Run the framework as the low-privilege agent user when the image
	// provides one (no-op otherwise — see internal/privsep). Restore wrote
	// the home as root, so hand it over now; $HOME itself must also accept
	// new dotfiles (npm/openclaw caches).
	if privsep.Drop(cmd) {
		privsep.OwnPath(os.Getenv("HOME"))
		privsep.OwnTree(openclawHome)
	}

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("start openclaw gateway: %w", err)
	}
	logger.Logf("OK   openclaw gateway spawned, pid=%d (log: /tmp/openclaw.log)", cmd.Process.Pid)
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
	b, err := os.ReadFile("/tmp/openclaw.log")
	if err != nil {
		return fmt.Sprintf("(no openclaw.log: %v)", err)
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
