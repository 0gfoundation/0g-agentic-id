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
)

// Start does the heavy lifting of bringing openclaw up, in two flavours:
//
//   - First call (initialized=false): npm-install the version pinned by the
//     framework dim, write the runtime sections of openclaw.json (gateway
//     token, controlUi flags), refresh `gateway.mode = local`, then spawn.
//     iData-derived sections were already written by Restore -- Start does
//     NOT re-compose them.
//
//   - Subsequent calls (supervisor restart): just spawn. We don't re-install
//     openclaw or re-write any config -- agent self-modifications survive
//     restart untouched (see ARCHITECTURE.zh.md §6: platform doesn't
//     interfere with agent's own evolution).
//
// The auth token is generated on first init and cached in a.authToken; the
// dashboard stays signed in across restarts because the token is stable.
func (a *Adapter) Start(ctx context.Context, rt framework.RuntimeContext) (framework.StartResult, error) {
	a.mu.RLock()
	cfg := a.cfg
	cachedToken := a.authToken
	initialized := a.initialized
	a.mu.RUnlock()
	if cfg == nil {
		return framework.StartResult{}, fmt.Errorf("openclaw: no config restored before Start")
	}

	// Resolve inference provider+model from the on-disk openclaw.json
	// that path-driven Restore just wrote. Empty values are not a hard
	// fail here — openclaw will report the missing config more clearly
	// at first inference, and the manager will surface that to attestor.
	pick, err := resolveInferenceFromOpenclawJSON()
	if err != nil {
		return framework.StartResult{}, fmt.Errorf("read openclaw.json: %w", err)
	}
	provider := pick.Provider
	model := pick.Model
	if provider == "" || model == "" {
		logger.Logf("warn: openclaw.json has no agents.defaults.model.primary; openclaw will fail at first chat")
	}

	authToken := cachedToken

	if !initialized {
		newToken, err := randomTokenHex(32)
		if err != nil {
			return framework.StartResult{}, fmt.Errorf("generate openclaw auth token: %w", err)
		}
		authToken = newToken

		if err := writeRuntimeSections(authToken); err != nil {
			return framework.StartResult{}, err
		}

		// 0g-compute runtime augmentation: owner specifies "0g-compute"
		// as a provider name; sealed rewrites that to "openai" with the
		// 0G router endpoint + compat flags so openclaw can dial it.
		// No-op for any other provider name.
		if err := applyZGComputeAugmentation(provider, model); err != nil {
			return framework.StartResult{}, fmt.Errorf("0g-compute augmentation: %w", err)
		}

		if err := installOpenclaw(cfg.framework.PackageVersion); err != nil {
			return framework.StartResult{}, err
		}

		if out, err := exec.Command("openclaw", "config", "set", "gateway.mode", "local").CombinedOutput(); err != nil {
			return framework.StartResult{}, fmt.Errorf("openclaw config set: %v: %s", err, strings.TrimSpace(string(out)))
		}
	} else {
		// Restart: verify the binary is still installed, otherwise the spawn
		// will fail confusingly later.
		if _, err := exec.Command("openclaw", "--version").Output(); err != nil {
			return framework.StartResult{}, fmt.Errorf("openclaw binary missing on restart: %w", err)
		}
		logger.Logf("openclaw restart: skipping npm install + config rewrite (preserving agent self-modifications)")
	}

	// Always export the inference provider API key into bootstrap's env so
	// spawnGateway's whitelist can pass it to the new openclaw subprocess.
	if err := exportAPIKey(provider, rt.APIKey); err != nil {
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
	rs.Whitelist = make([]platform.WhitelistEntry, len(supportedOpenclawVersions))
	for i, v := range supportedOpenclawVersions {
		rs.Whitelist[i] = platform.WhitelistEntry{Version: v}
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
	if err := upsertToolsMD(toolsMDPath(), pc); err != nil {
		logger.Logf("warn: upsert TOOLS.md sealed section: %v", err)
	}
	if rt.AgentSeal != "" || rt.PublicURL != "" || rt.SealSignSock != "" {
		logger.Logf("OK   injected sealed sections (identity/soul/tools) for agent=%q public_url=%q sign_sock=%q",
			rt.AgentSeal, rt.PublicURL, rt.SealSignSock)
	}

	cmd, err := spawnGateway(provider, rt)
	if err != nil {
		return framework.StartResult{}, err
	}
	a.mu.Lock()
	a.cmd = cmd
	a.authToken = authToken
	a.initialized = true
	a.mu.Unlock()

	addr := fmt.Sprintf("127.0.0.1:%d", upstreamPort)
	if err := waitForListen(ctx, addr, startTimeout); err != nil {
		return framework.StartResult{}, fmt.Errorf("openclaw not listening: %w", err)
	}

	return framework.StartResult{
		Upstream: fmt.Sprintf("http://%s", addr),
		PID:      cmd.Process.Pid,
	}, nil
}

// writeRuntimeSections merges per-boot config (gateway.token, controlUi
// flags) into openclaw.json. Restore already wrote the iData-derived
// sections; this function only touches keys that aren't on chain.
//
// `gateway.controlUi.*` flags relax openclaw's CORS / device-auth checks
// because the sealed sandbox proxy at :8080 is the trust boundary --
// openclaw doesn't need its own.
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

func exportAPIKey(provider, apiKey string) error {
	if apiKey == "" {
		return nil
	}
	envName := ""
	switch provider {
	case "anthropic":
		envName = "ANTHROPIC_API_KEY"
	case "openai", "0g-compute":
		// 0G Compute is OpenAI-protocol-compatible; the endpoint switch
		// happens in openclaw config (models.providers.openai.baseUrl),
		// not via env. The same OPENAI_API_KEY carries the credential.
		envName = "OPENAI_API_KEY"
	}
	if envName == "" {
		return nil
	}
	if err := os.Setenv(envName, apiKey); err != nil {
		return fmt.Errorf("set %s: %w", envName, err)
	}
	logger.Logf("OK   exported %s from API_KEY", envName)
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

func spawnGateway(provider string, rt framework.RuntimeContext) (*exec.Cmd, error) {
	logFile, err := os.OpenFile("/tmp/openclaw.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open openclaw.log: %w", err)
	}
	cmd := exec.Command("openclaw", "gateway", "run",
		"--allow-unconfigured", "--bind", "loopback",
		"--port", fmt.Sprintf("%d", upstreamPort))
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// Strict env whitelist -- do NOT inherit bootstrap's env so a leaked
	// SANDBOX_SEAL_KEY can't be read via "env" or /proc/self/environ from
	// inside the agent process.
	envWhitelist := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
	}
	if rt.APIKey != "" {
		switch provider {
		case "anthropic":
			envWhitelist = append(envWhitelist, "ANTHROPIC_API_KEY="+rt.APIKey)
		case "openai", "0g-compute":
			// Same env name for both. Endpoint routing for 0g lives in
			// openclaw config (models.providers.openai.baseUrl), not env.
			envWhitelist = append(envWhitelist, "OPENAI_API_KEY="+rt.APIKey)
		}
	}
	if rt.PublicURL != "" {
		envWhitelist = append(envWhitelist, "AGENT_PUBLIC_URL="+rt.PublicURL)
	}
	if rt.SealSignSock != "" {
		envWhitelist = append(envWhitelist, "SEAL_SIGN_SOCK="+rt.SealSignSock)
	}
	if rt.AgentSeal != "" {
		envWhitelist = append(envWhitelist, "AGENT_SEAL="+rt.AgentSeal)
	}
	cmd.Env = envWhitelist
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

func randomTokenHex(nbytes int) (string, error) {
	buf := make([]byte, nbytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

