package hermes

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
	"seal-verify/internal/inference"
	"seal-verify/internal/logger"
	"seal-verify/internal/platform"
	"seal-verify/internal/privsep"
)

// Start brings hermes up, in two flavours (mirrors the openclaw twin):
//
//   - First call (initialized=false): pin the framework version from the
//     framework dim (git checkout + uv sync against the image's warm
//     checkout), apply the 0g-compute → custom-endpoint rewrite, generate
//     the API server key, then spawn. iData-derived config was already
//     written by Restore — Start does NOT re-compose it.
//
//   - Subsequent calls (supervisor restart): just spawn. No re-install, no
//     config rewrite — agent self-modifications survive restart untouched.
//
// The API server key is generated on first init and cached in
// a.apiServerKey; AuthResponse hands it to a verified owner.
//
// Before spawning, Start injects the platform context (identity +
// sovereignty + capabilities, incl. how to expose a service via
// $SEAL_SIGN_SOCK/services) into SOUL.md — the reliable HERMES_HOME
// context file the agent reads every turn. See platformtext.go.
func (a *Adapter) Start(ctx context.Context, rt framework.RuntimeContext) (framework.StartResult, error) {
	a.mu.RLock()
	cfg := a.cfg
	cachedKey := a.apiServerKey
	initialized := a.initialized
	a.mu.RUnlock()
	if cfg == nil {
		return framework.StartResult{}, fmt.Errorf("hermes: no config restored before Start")
	}

	// Resolve inference provider+model from the on-disk config.yaml that
	// path-driven Restore just wrote. Empty values are not a hard fail —
	// hermes reports missing model config clearly at first inference.
	provider, model, err := resolveInferenceFromConfigYAML()
	if err != nil {
		return framework.StartResult{}, fmt.Errorf("read config.yaml: %w", err)
	}
	if provider == "" || model == "" {
		logger.Logf("warn: config.yaml has no model.provider/model.default; hermes will fail at first chat")
	}

	// Resolve the 0g-compute route ONCE per boot — the config rewrite and
	// the exported key env name below must come from the same answer.
	var zgRoute *inference.Route
	if provider == "0g-compute" {
		r := inference.ResolveZG(ctx, model)
		zgRoute = &r
	}

	apiServerKey := cachedKey
	if !initialized {
		newKey, err := randomTokenHex(32)
		if err != nil {
			return framework.StartResult{}, fmt.Errorf("generate hermes api server key: %w", err)
		}
		apiServerKey = newKey

		// 0g-compute runtime rewrite: owner specifies "0g-compute" as the
		// provider; sealed rewrites that to hermes's custom-endpoint form
		// (provider=custom + base_url + api_key) so hermes can dial the 0G
		// router. No-op for any other provider name.
		if err := applyZGComputeAugmentation(provider, model, rt.APIKey, zgRoute); err != nil {
			return framework.StartResult{}, fmt.Errorf("0g-compute augmentation: %w", err)
		}

		if err := installHermes(cfg.framework.PackageVersion); err != nil {
			return framework.StartResult{}, err
		}
	} else {
		if _, err := exec.Command("hermes", "--version").Output(); err != nil {
			return framework.StartResult{}, fmt.Errorf("hermes binary missing on restart: %w", err)
		}
		logger.Logf("hermes restart: skipping install + config rewrite (preserving agent self-modifications)")
	}

	apiKeyEnv := apiKeyEnvName(provider)

	// Inject the platform context into SOUL.md before spawning, so the
	// agent's first turn already knows its identity, sovereignty, and — the
	// v1 gap — how to expose a service (register at $SEAL_SIGN_SOCK/services).
	// Marker-delimited; evoSoulMD strips it so only the persona reaches chain.
	pc := platform.Build(platform.RuntimeSnapshot{
		SealedVersion:    rt.SealedVersion,
		FrameworkVersion: probeHermesVersion(ctx),
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
		ZGComputeRouted:  provider == "0g-compute",
		BootTime:         time.Now(),
		Deprivileged:     privsep.Active(),
	})
	if err := upsertSoulMD(pc, a.FrameworkFacts()); err != nil {
		logger.Logf("warn: inject platform context into SOUL.md: %v", err)
	}

	cmd, err := spawnGateway(apiKeyEnv, apiServerKey, rt)
	if err != nil {
		return framework.StartResult{}, err
	}

	// The web dashboard (:9119) is intentionally NOT started — see
	// FrameworkRoutes: it embeds a terminal + file browser and is never
	// exposed through the proxy, so running it would only add attack surface
	// and RAM for nothing. Owner interaction is the chat API only.

	a.mu.Lock()
	a.cmd = cmd
	a.apiServerKey = apiServerKey
	a.initialized = true
	a.mu.Unlock()

	addr := fmt.Sprintf("127.0.0.1:%d", upstreamPort)
	if err := waitForListen(ctx, addr, startTimeout); err != nil {
		return framework.StartResult{}, fmt.Errorf("hermes api server not listening: %w", err)
	}

	return framework.StartResult{
		Upstream: fmt.Sprintf("http://%s", addr),
		PID:      cmd.Process.Pid,
	}, nil
}

// resolveInferenceFromConfigYAML reads model.provider + model.default from
// the on-disk config.yaml.
func resolveInferenceFromConfigYAML() (provider, model string, err error) {
	cfg, err := loadConfigYAML()
	if err != nil {
		return "", "", err
	}
	m, _ := cfg["model"].(map[string]any)
	if m == nil {
		return "", "", nil
	}
	provider, _ = m["provider"].(string)
	model, _ = m["default"].(string)
	return provider, model, nil
}

// applyZGComputeAugmentation rewrites config.yaml for the 0g-compute
// provider: hermes has no native 0g-compute provider, but its custom
// endpoint mode ("when base_url is set, hermes calls that endpoint
// directly") speaks OpenAI wire format — which is what the 0G router's
// /v1 base serves. The rewrite lands in the owned "model" subtree, so the
// first watcher tick commits the resolved form on chain (one expected
// drift-commit, same convergence pattern as the version-less binding);
// subsequent boots restore the already-resolved config and this becomes
// a no-op.
//
// The inference key goes into model.api_key HERE, on disk, NOT via an env
// var: hermes's `custom` provider declares env_vars=() (verified in
// plugins/model-providers/custom) — it reads the key ONLY from
// model.api_key, ignoring OPENAI_API_KEY entirely (that fallback is for
// the native `openai` provider). Injecting via env produced a live 401
// from the router: hermes dialed it keyless. Writing the key to config on
// disk inside the TEE container is where it must live for hermes to use
// it; it never reaches chain because evoConfigYAML's stripSecrets removes
// api_key on the capture path (deterministically, so no phantom drift).
//
// Anthropic-format-only models (route.Format != openai) cannot ride the
// custom endpoint; fail loud at deploy time rather than 400 at first chat.
func applyZGComputeAugmentation(provider, model, apiKey string, route *inference.Route) error {
	if provider != "0g-compute" {
		return nil
	}
	if route == nil {
		return fmt.Errorf("0g-compute provider with no resolved route")
	}
	if route.Format != inference.WireOpenAI {
		return fmt.Errorf("model %q routes %s-format on 0g-compute; the hermes adapter supports openai-format models only (pick an openai-format model)", model, route.Format)
	}
	return updateConfigYAML(func(cfg map[string]any) {
		m, _ := cfg["model"].(map[string]any)
		if m == nil {
			m = map[string]any{}
		}
		m["provider"] = "custom"
		m["base_url"] = route.BaseURL
		m["default"] = model
		if apiKey != "" {
			m["api_key"] = apiKey
		}
		cfg["model"] = m
	})
}

// apiKeyEnvName resolves which env var hermes's client reads the inference
// key from, for the NATIVE providers that honour one. 0g-compute is NOT
// here: it maps to the `custom` provider, whose env_vars=() means it reads
// the key only from config.yaml model.api_key — so that path delivers the
// key via applyZGComputeAugmentation, not env (this returns "", so no env
// var is set). Returns "" for any provider without a fixed env key.
func apiKeyEnvName(provider string) string {
	switch provider {
	case "anthropic":
		return "ANTHROPIC_API_KEY"
	case "openai":
		return "OPENAI_API_KEY"
	}
	return ""
}

// uvSyncArgs is the exact dependency set the adapter (and the image bake —
// keep images/hermes/Dockerfile in lockstep) syncs. `uv sync` is an exact
// sync: a package not covered by these args gets REMOVED, so the two call
// sites diverging silently strips dependencies at first boot.
//
// --extra sms is not about SMS: upstream has no dedicated extra for the
// API server, whose HTTP layer needs aiohttp ("API Server: aiohttp not
// installed" → :8642 never binds — first live T2 failure). aiohttp ships
// only inside platform extras, and sms's payload is exactly aiohttp and
// nothing else, so it's the minimal way to say "core + aiohttp" while
// staying inside the uv.lock pin set.
var uvSyncArgs = []string{"sync", "--locked", "--extra", "sms"}

// installHermes pins the framework to a git release tag: checkout + uv
// sync inside the image's warm checkout. Hermes has no npm/pip package;
// this IS its version-pinning mechanism (`hermes update` is just a
// friendlier `git pull` + sync). `uv sync --locked` hash-verifies against
// uv.lock, so the dependency tree is pinned by the same tag.
func installHermes(tag string) error {
	if _, err := os.Stat(hermesInstallDir); err != nil {
		return fmt.Errorf("hermes checkout missing at %s (not baked into this image?): %w", hermesInstallDir, err)
	}
	if v := strings.TrimSpace(tag); v != "" {
		logger.Logf("pinning hermes to %s...", v)
		if out, err := exec.Command("git", "-C", hermesInstallDir, "checkout", "--quiet", v).CombinedOutput(); err != nil {
			// Tag may postdate the baked checkout: fetch tags once and retry.
			logger.Logf("hermes: local checkout lacks %s, fetching tags: %s", v, strings.TrimSpace(string(out)))
			if out, err := exec.Command("git", "-C", hermesInstallDir, "fetch", "--tags", "--quiet", "origin").CombinedOutput(); err != nil {
				return fmt.Errorf("git fetch --tags: %v: %s", err, strings.TrimSpace(string(out)))
			}
			if out, err := exec.Command("git", "-C", hermesInstallDir, "checkout", "--quiet", v).CombinedOutput(); err != nil {
				return fmt.Errorf("git checkout %s: %v: %s", v, err, strings.TrimSpace(string(out)))
			}
		}
	}
	logger.Logf("uv %s (fast against the baked cache)...", strings.Join(uvSyncArgs, " "))
	sync := exec.Command("uv", uvSyncArgs...)
	sync.Dir = hermesInstallDir
	if out, err := sync.CombinedOutput(); err != nil {
		return fmt.Errorf("uv %s: %v: %s", strings.Join(uvSyncArgs, " "), err, tail(string(out), 400))
	}
	if out, err := exec.Command("hermes", "--version").Output(); err == nil {
		logger.Logf("OK   installed: %s", firstLine(string(out)))
	}
	return nil
}

// probeHermesVersion returns the CalVer release tag from `hermes
// --version`. CLI output double-names the release: "Hermes Agent v0.19.0
// (2026.7.20) · upstream 8fc27820" — the parenthesized token is the git
// tag minus its "v" (the "v0.19.0" is a marketing name with NO
// corresponding tag), so this returns "v2026.7.20". Empty on probe error
// or unrecognized output — empty keeps the binding's value, which is
// strictly safer than returning the un-checkout-able semantic name (that
// would wedge the watcher in a permanent drift↔reconcile loop).
//
// Package var, not func: EvolutionFor("framework") layers this live probe
// over the restored binding, so tests must stub it (a real hermes on the
// dev machine's PATH would make round-trips environment-dependent).
var probeHermesVersion = func(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "hermes", "--version").Output()
	if err != nil {
		return ""
	}
	for _, f := range strings.Fields(firstLine(string(out))) {
		inner := strings.TrimSuffix(strings.TrimPrefix(f, "("), ")")
		if inner != f && inner != "" && inner[0] >= '0' && inner[0] <= '9' && strings.Contains(inner, ".") {
			return "v" + inner
		}
	}
	return ""
}

func spawnGateway(apiKeyEnv, apiServerKey string, rt framework.RuntimeContext) (*exec.Cmd, error) {
	logFile, err := os.OpenFile("/tmp/hermes.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open hermes.log: %w", err)
	}
	cmd := exec.Command("hermes", "gateway", "run")
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// Strict env whitelist — do NOT inherit bootstrap's env so a leaked
	// SANDBOX_SEAL_KEY can't be read from inside the agent process. The
	// API server settings are env-only in hermes v0.19 (config.yaml
	// support upstream-pending), which suits us: they never touch disk.
	//
	// API_SERVER_CORS_ORIGINS=* is load-bearing, not permissive sloppiness:
	// the sealed proxy sets `Origin: http://127.0.0.1:8642` on every
	// forwarded request (it's how openclaw's controlUi accepts them), and
	// hermes's API server 403s any request that carries an Origin absent
	// from this allow-list — BEFORE auth, empty body, every path incl.
	// /v1/health (verified live: agent 138, and reproduced in a local
	// container). CORS is not the trust boundary here — the Bearer
	// API_SERVER_KEY check is (hermes api_server.py says as much), and it
	// still runs after CORS, so `*` opens the browser-origin gate without
	// weakening auth (verified: wrong key → 401 even with Origin + `*`).
	envWhitelist := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"API_SERVER_ENABLED=true",
		"API_SERVER_KEY=" + apiServerKey,
		"API_SERVER_CORS_ORIGINS=*",
	}
	if rt.APIKey != "" && apiKeyEnv != "" {
		envWhitelist = append(envWhitelist, apiKeyEnv+"="+rt.APIKey)
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

	// Run the framework as the low-privilege agent user when the image
	// provides one (no-op otherwise — see internal/privsep). Restore wrote
	// the home as root, so hand it over now; $HOME itself must also accept
	// new dotfiles. The checkout under hermesInstallDir stays root-owned
	// read-only, which is fine (python skips __pycache__ writes silently).
	if privsep.Drop(cmd) {
		privsep.OwnPath(os.Getenv("HOME"))
		privsep.OwnTree(hermesHome)
	}

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("start hermes gateway: %w", err)
	}
	logger.Logf("OK   hermes gateway spawned, pid=%d (log: /tmp/hermes.log)", cmd.Process.Pid)
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

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(line)
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
