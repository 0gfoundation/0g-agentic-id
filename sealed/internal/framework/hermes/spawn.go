package hermes

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
	"regexp"
	"strings"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/inference"
	"seal-verify/internal/logger"
	"seal-verify/internal/platform"
	"seal-verify/internal/privsep"
	"seal-verify/internal/settings"
)

// Start brings hermes up, in two flavours (mirrors the openclaw twin):
//
//   - First call (initialized=false): pin the framework version from the
//     framework dim (git checkout + uv sync against the image's warm
//     checkout), generate the API server key, then spawn.
//
//   - Subsequent calls (supervisor restart): just spawn, no re-install.
//
// config.yaml is NOT composed here in either flavour: RenderSettings owns
// that file and the bootstrap calls it before every Start.
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
	rs := a.resolved
	a.mu.RUnlock()
	if cfg == nil {
		return framework.StartResult{}, fmt.Errorf("hermes: no config restored before Start")
	}
	// The pin comes from the settings document, not from re-reading
	// config.yaml: that file stopped being a chain-tracked role and is now an
	// artifact RenderSettings produces, so reading it back would let an agent
	// edit re-point inference. A missing render is a bootstrap bug, not
	// something an owner can cause — fail loudly rather than boot modelless.
	if rs == nil {
		return framework.StartResult{}, fmt.Errorf("hermes: RenderSettings has not run before Start (bootstrap must render the owner's settings first)")
	}
	provider, model := rs.Provider, rs.Model

	apiServerKey := cachedKey
	if !initialized {
		newKey, err := randomTokenHex(32)
		if err != nil {
			return framework.StartResult{}, fmt.Errorf("generate hermes api server key: %w", err)
		}
		apiServerKey = newKey

		if err := installHermes(cfg.framework.PackageVersion); err != nil {
			return framework.StartResult{}, err
		}
	} else {
		if err := checkoutPresent(); err != nil {
			return framework.StartResult{}, err
		}
		logger.Logf("hermes restart: skipping install (framework already pinned)")
	}

	apiKeyEnv := apiKeyEnvName(provider)

	// Inject the platform context into SOUL.md before spawning, so the
	// agent's first turn already knows its identity, sovereignty, and — the
	// v1 gap — how to expose a service (register at $SEAL_SIGN_SOCK/services).
	// Marker-delimited; evoSoulMD strips it so only the persona reaches chain.
	pc := platform.Build(platform.RuntimeSnapshot{
		SealedVersion:       rt.SealedVersion,
		FrameworkVersion:    probeHermesVersion(ctx),
		WhitelistMax:        whitelistMax(),
		AgentSeal:           rt.AgentSeal,
		AgentID:             rt.AgentID,
		Owner:               rt.Owner,
		ChainRPC:            rt.ChainRPC,
		ContractAddr:        rt.ContractAddr,
		ServeProofValidator: rt.VerifiedFeedbackAddr,
		AttestorURL:         rt.AttestorURL,
		PublicURL:           rt.PublicURL,
		SealSignSock:        rt.SealSignSock,
		Provider:            provider,
		Model:               model,
		ZGComputeRouted:     rs.Endpoint != nil,
		BootTime:            time.Now(),
	})
	if err := upsertSoulMD(pc, a.FrameworkFacts()); err != nil {
		logger.Logf("warn: inject platform context into SOUL.md: %v", err)
	}

	// The inference credential comes from the resolved settings document,
	// never from RuntimeContext: the settings channel owns it now, and a
	// platform-routed endpoint dialed with the wrong one is a live 401.
	cmd, err := spawnGateway(apiKeyEnv, rs.APIKey, apiServerKey, rt)
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

// RenderSettings implements framework.Framework: it renders the owner's
// settings document into ~/.hermes/config.yaml, the only place hermes reads
// its model wiring from.
//
// It replaces the old boot-time 0g-compute config rewrite. Two things the
// settings channel changed, both of which were bugs before:
//
//   - config.yaml is no longer a chain-tracked role, so it is rebuilt from
//     the document at every Start instead of being restored from a mint-time
//     copy. A fix shipped after an agent was minted now reaches it on the
//     next boot, and there is no longer a first-boot "rewrite then let the
//     watcher commit the resolved form" convergence dance.
//   - the reasoning bound no longer hangs off the provider check. It used to
//     sit inside the 0g-compute branch, so picking a native provider silently
//     dropped it — and an always-thinking model with no bound reasons
//     forever (measured on glm-5.3: 100k+ chars of reasoning, zero reply,
//     stream killed upstream). s.Effort() is provider-independent.
//
// The keys this render owns are model.{default,provider,base_url,api_key}
// and agent.reasoning_effort, plus model.max_tokens whenever the catalog
// gives the model's budget. The three that carry endpoint wiring
// (provider/base_url/api_key) are also CLEARED when the document stops
// supplying them — a leftover value aims hermes at the previous boot's
// endpoint, or hands it the previous boot's key. Everything else in the file
// — hermes's own sections, and whatever the owner's overlay carries — is
// merged or left alone: the file is edited, not regenerated. (FrameworkFacts
// tells the agent the same thing; keep the two in step.)
//
// The inference key goes into model.api_key HERE, on disk, NOT via an env
// var: hermes's `custom` provider declares env_vars=() (verified in
// plugins/model-providers/custom) — it reads the key ONLY from
// model.api_key, ignoring OPENAI_API_KEY entirely (that fallback is for the
// native `openai` provider). Injecting via env produced a live 401 from the
// router: hermes dialed it keyless. Writing it every render is what keeps an
// evolved agent authenticated across resets; nothing captures this file any
// more, so the key cannot ride to chain and needs no strip on the way out.
//
// Anthropic-format-only models cannot ride hermes's custom endpoint (it
// speaks OpenAI wire format); fail loud here rather than 400 at first chat.
func (a *Adapter) RenderSettings(ctx context.Context, s settings.Resolved) error {
	if s.Endpoint != nil {
		if s.Endpoint.Format != inference.WireOpenAI {
			return fmt.Errorf("model %q routes %s-format on %s; the hermes adapter supports openai-format models only (pick an openai-format model)",
				s.Model, s.Endpoint.Format, s.Provider)
		}
		if s.APIKey == "" {
			return fmt.Errorf("platform-routed endpoint but no API key for this boot — hermes would dial %s unauthenticated", s.Endpoint.BaseURL)
		}
	}
	overlay, err := frameworkOverlay(s.Others)
	if err != nil {
		return err
	}
	effort, effortDecided := s.Effort()

	if err := updateConfigYAML(func(cfg map[string]any) {
		// Which model the on-disk model.max_tokens was written for — read
		// before anything below touches the section.
		budgetWrittenFor := modelIdentity(cfg)

		// Owner's overlay FIRST, platform-owned keys over it. Ordering, not
		// an exclusion list, is what stops an overlay from pinning a stale
		// base_url or disabling the reasoning bound.
		mergeInto(cfg, overlay)

		m, _ := cfg["model"].(map[string]any)
		if m == nil {
			m = map[string]any{}
		}
		if s.Model != "" {
			m["default"] = s.Model
		}
		if s.Endpoint != nil {
			// hermes has no 0g-compute provider; its custom-endpoint mode
			// ("when base_url is set, hermes calls that endpoint directly")
			// speaks the OpenAI wire format the 0G router's /v1 base serves.
			m["provider"] = "custom"
			m["base_url"] = s.Endpoint.BaseURL
		} else {
			if s.Provider != "" {
				m["provider"] = s.Provider
			} else if m["provider"] == "custom" {
				// "custom" is purely hermes's marker for "dial model.base_url",
				// which the next line removes — left behind it points hermes at
				// an endpoint that is no longer in the file. Any other provider
				// value (a mint-time seed, hermes's own default) names a
				// built-in that brings its own wiring, so it stays.
				delete(m, "provider")
			}
			// A framework built-in supplies its own endpoint. Drop any
			// base_url a previous render (or the overlay) left behind, or
			// hermes would keep dialing the old custom endpoint.
			delete(m, "base_url")
		}
		// model.api_key is THIS boot's credential, not durable configuration,
		// so its lifecycle matches base_url's: written when the platform has
		// one, removed when it does not. Without the removal, a boot that
		// switches to a framework built-in keeps the previous boot's 0G router
		// key on disk and hands it to whichever provider now owns the section.
		if s.APIKey != "" {
			m["api_key"] = s.APIKey
		} else {
			delete(m, "api_key")
		}
		cfg["model"] = m
		// model.max_tokens is the per-request output budget hermes sends as
		// max_tokens (gateway/run.py reads it, over any provider's own cap).
		// Absent, the custom provider profile's default applies — captured on
		// the wire as 65536 on every main-loop request (why that is capped:
		// settings.RequestMaxTokens). Like the reasoning bound below, the
		// outcomes must not be collapsed:
		//   budget known (catalog)       write it, capped (RequestMaxTokens)
		//   unknown, overlay names one   the owner's value stands
		//   unknown, same model          leave it: a catalog outage must not
		//                                drop the cap; a guess is never written
		//   unknown, model changed       remove it: it is the previous model's
		//                                budget, and a value above the new
		//                                model's limit fails every request
		switch mt := s.RequestMaxTokens(); {
		case mt > 0:
			m["max_tokens"] = mt
		case overlayNamesMaxTokens(overlay):
		case s.Facts.CatalogSourced || modelIdentity(cfg) != budgetWrittenFor:
			delete(m, "max_tokens")
		}

		// agent.reasoning_effort is hermes's single chokepoint for reasoning
		// depth (hermes_constants.resolve_reasoning_config: per-model override
		// > global agent.reasoning_effort; every surface reads it). Applied
		// for every provider, not just the routed one.
		//
		// Effort() has three outcomes and collapsing any two is a live bug:
		//   level, true   write it
		//   "",    true   the catalog says this model rejects the parameter
		//                 (hard 400) — clear whatever a previous model's
		//                 render left behind
		//   "",    false  the catalog is unreachable or silent: we know
		//                 nothing, so leave the on-disk value alone. Deleting
		//                 here would strip the bound from an always-thinking
		//                 model during an outage, and it then reasons without
		//                 end and never writes a reply.
		agent, _ := cfg["agent"].(map[string]any)
		if agent == nil {
			agent = map[string]any{}
		}
		if effortDecided {
			if effort != "" {
				agent["reasoning_effort"] = effort
			} else {
				delete(agent, "reasoning_effort")
			}
		}
		if len(agent) > 0 {
			cfg["agent"] = agent
		} else {
			delete(cfg, "agent")
		}
	}); err != nil {
		return fmt.Errorf("hermes.RenderSettings: %w", err)
	}

	if s.Model == "" {
		logger.Logf("warn: settings carry no model; hermes will fail at first chat")
	}
	logger.Logf("hermes: rendered settings provider=%s model=%s effort=%q effort_decided=%v routed=%v",
		s.Provider, s.Model, effort, effortDecided, s.Endpoint != nil)

	a.mu.Lock()
	a.resolved = &s
	a.mu.Unlock()
	return nil
}

// modelIdentity names the model config.yaml's model section points at: the
// model, the provider and the endpoint.
func modelIdentity(cfg map[string]any) string {
	m, _ := cfg["model"].(map[string]any)
	return fmt.Sprintf("%v|%v|%v", m["default"], m["provider"], m["base_url"])
}

// overlayNamesMaxTokens reports whether the owner's overlay sets
// model.max_tokens itself.
func overlayNamesMaxTokens(overlay map[string]any) bool {
	m, _ := overlay["model"].(map[string]any)
	_, ok := m["max_tokens"]
	return ok
}

// frameworkOverlay decodes the owner's opaque per-framework section as the
// top-level shape hermes's config.yaml already has. It is merged (see
// mergeInto), never interpreted: the platform makes no promise about what
// hermes accepts there, and a key it does not know is exactly the point of
// the overlay.
//
// This is also where `approvals` and `terminal` now live. They were iData
// roles labelled "agent self-tuning", but nothing in sealed ever wrote them
// and an unattended TEE has nobody for an approval policy to ask — they are
// owner knobs, so they ride the overlay like any other hermes key.
func frameworkOverlay(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	overlay := map[string]any{}
	if err := json.Unmarshal(raw, &overlay); err != nil {
		return nil, fmt.Errorf("hermes.RenderSettings: framework overlay is not a JSON object: %w", err)
	}
	return overlay, nil
}

// mergeInto deep-merges src into dst: where both sides hold a mapping the
// merge recurses, otherwise src's value is assigned.
//
// The depth matters. A shallow top-level assignment made an overlay that
// carries `model: {temperature: 0.2}` REPLACE the whole model section, so a
// pin already on disk (a mint-time seed, or a previous render whose document
// no longer names a model) was blanked by a knob that has nothing to do with
// it. Overlay values still win over what is on disk — the platform's own keys
// are written after this and win over both.
func mergeInto(dst, src map[string]any) {
	for k, v := range src {
		if sub, ok := v.(map[string]any); ok {
			if cur, ok := dst[k].(map[string]any); ok {
				mergeInto(cur, sub)
				continue
			}
		}
		dst[k] = v
	}
}

// apiKeyEnvName resolves which env var hermes's client reads the inference
// key from, for the NATIVE providers that honour one. 0g-compute is NOT
// here: it maps to the `custom` provider, whose env_vars=() means it reads
// the key only from config.yaml model.api_key — so that path delivers the
// key through RenderSettings, not env (this returns "", so no env var is
// set). Returns "" for any provider without a fixed env key.
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
//
// The checkout is root-owned, so git and uv run as root — through
// privsep.RootCommand (root-only PATH resolution, fixed environment), in
// the checkout directory (privsep.RootDir, which refuses one another uid
// could write: git and uv read their configuration from it), with git's
// credential prompt disabled.
func installHermes(tag string) error {
	if _, err := privsep.Lstat(hermesInstallDir); err != nil {
		return fmt.Errorf("hermes checkout missing at %s (not baked into this image?): %w", hermesInstallDir, err)
	}
	// run takes RootCommand's result directly, so every call site names its
	// toolchain binary as a literal (TestRootRunsOnlyPinnedToolchainCommands
	// pins which binaries root runs).
	run := func(cmd *exec.Cmd, err error) ([]byte, error) {
		if err != nil {
			return nil, err
		}
		if err := privsep.RootDir(cmd, hermesInstallDir); err != nil {
			return nil, err
		}
		cmd.Env = append(cmd.Env, "GIT_TERMINAL_PROMPT=0")
		return cmd.CombinedOutput()
	}
	ctx := context.Background()
	if v := strings.TrimSpace(tag); v != "" {
		logger.Logf("pinning hermes to %s...", v)
		if out, err := run(privsep.RootCommand(ctx, "git", "-C", hermesInstallDir, "checkout", "--quiet", v)); err != nil {
			// Tag may postdate the baked checkout: fetch tags once and retry.
			logger.Logf("hermes: local checkout lacks %s, fetching tags: %v %s", v, err, strings.TrimSpace(string(out)))
			if out, err := run(privsep.RootCommand(ctx, "git", "-C", hermesInstallDir, "fetch", "--tags", "--quiet", "origin")); err != nil {
				return fmt.Errorf("git fetch --tags: %v: %s", err, strings.TrimSpace(string(out)))
			}
			if out, err := run(privsep.RootCommand(ctx, "git", "-C", hermesInstallDir, "checkout", "--quiet", v)); err != nil {
				return fmt.Errorf("git checkout %s: %v: %s", v, err, strings.TrimSpace(string(out)))
			}
		}
	}
	logger.Logf("uv %s (fast against the baked cache)...", strings.Join(uvSyncArgs, " "))
	if out, err := run(privsep.RootCommand(ctx, "uv", uvSyncArgs...)); err != nil {
		return fmt.Errorf("uv %s: %v: %s", strings.Join(uvSyncArgs, " "), err, tail(string(out), 400))
	}
	if v := probeHermesVersion(context.Background()); v != "" {
		logger.Logf("OK   installed: hermes %s", v)
	}
	return nil
}

// probeHermesVersion returns the CalVer release tag of the checked-out
// hermes, e.g. "v2026.7.20", or "" when the checkout is missing or
// unrecognized — empty keeps the binding's value.
//
// A static read, not `hermes --version`: root runs no framework CLI, and
// EvolutionFor("framework") calls this on every watcher tick. It reads
// __release_date__ from hermes_cli/__init__.py in the root-owned checkout —
// the value `hermes --version` prints in parentheses ("Hermes Agent v0.19.0
// (2026.7.20)"), which is the git tag minus its "v". The semantic
// __version__ ("0.19.0") is a marketing name with NO corresponding tag, and
// returning it would wedge the watcher in a permanent drift↔reconcile loop.
//
// Package var, not func: EvolutionFor("framework") layers this live probe
// over the restored binding, so tests must stub it (a real hermes checkout
// on the dev machine would make round-trips environment-dependent).
var probeHermesVersion = func(ctx context.Context) string {
	raw, err := privsep.ReadFile(hermesVersionFile(), privsep.LimitConfig)
	if err != nil {
		return ""
	}
	return parseReleaseDate(raw)
}

// checkoutPresent is the restart check: the checkout must still be there.
// A static check, not `hermes --version`, because root runs no framework
// CLI. Presence, not the version parse: a release whose __init__.py the
// parser does not recognize must restart just as it booted (the first
// Start and evoFramework treat an unparsed version as benign too).
func checkoutPresent() error {
	if _, err := privsep.Lstat(hermesVersionFile()); err != nil {
		return fmt.Errorf("hermes checkout missing or unreadable on restart (%s): %w", hermesInstallDir, err)
	}
	return nil
}

// hermesVersionFile is the checkout file the version is read from; its
// presence is what a restart checks.
func hermesVersionFile() string {
	return filepath.Join(hermesInstallDir, "hermes_cli", "__init__.py")
}

var releaseDateRE = regexp.MustCompile(`(?m)^__release_date__\s*=\s*["']([^"']+)["']`)

// parseReleaseDate extracts __release_date__ and returns it as a tag ("v" +
// value), or "" when absent or not CalVer-shaped.
func parseReleaseDate(src []byte) string {
	m := releaseDateRE.FindSubmatch(src)
	if m == nil {
		return ""
	}
	v := strings.TrimSpace(string(m[1]))
	if v == "" || v[0] < '0' || v[0] > '9' || !strings.Contains(v, ".") {
		return ""
	}
	return "v" + v
}

// logName names the gateway's log under framework.StateDir/log.
const logName = "hermes"

func spawnGateway(apiKeyEnv, inferenceKey, apiServerKey string, rt framework.RuntimeContext) (*exec.Cmd, error) {
	logFile, err := framework.OpenLog(logName)
	if err != nil {
		return nil, fmt.Errorf("open hermes log: %w", err)
	}
	// Run the framework as the low-privilege agent user when the image
	// provides one (a plain spawn otherwise — see internal/privsep).
	// Background, not Start's ctx: the gateway outlives the call that
	// spawned it; Stop ends it.
	cmd, err := privsep.AgentCommand(context.Background(), "hermes", "gateway", "run")
	if err != nil {
		logFile.Close()
		return nil, fmt.Errorf("start hermes gateway: %w", err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = gatewayEnv(apiKeyEnv, inferenceKey, apiServerKey, rt)

	// Restore wrote the home as root; hand the framework tree over now, and
	// link it into the agent's own home so ~/.hermes (the path the agent is
	// told about) still names it. Root's home stays root's
	// (privsep.SecureHome). The checkout under hermesInstallDir stays
	// root-owned read-only, which is fine (python skips __pycache__ writes
	// silently).
	privsep.OwnTree(hermesHome)
	privsep.LinkAgentHome(".hermes", hermesHome)

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("start hermes gateway: %w", err)
	}
	logger.Logf("OK   hermes gateway spawned, pid=%d (log: %s)", cmd.Process.Pid, framework.LogPath(logName))
	return cmd, nil
}

// gatewayEnv builds the gateway process's environment.
//
// inferenceKey is the credential for THIS boot, taken from the resolved
// settings document — not from RuntimeContext. The two used to be assumed
// identical; they are not, and dialing a platform-routed endpoint with the
// wrong (or empty) one produced a live 401.
func gatewayEnv(apiKeyEnv, inferenceKey, apiServerKey string, rt framework.RuntimeContext) []string {
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
	//
	// HOME is the agent's own home (privsep.AgentHome): its tools' caches
	// and config go there, and it is hermes's default working directory —
	// the terminal tool, relative paths in the file tools and execute_code
	// start there unless the owner's overlay sets terminal.cwd, which this
	// environment leaves to config.yaml. HERMES_HOME names the framework
	// tree explicitly, so hermes does not depend on the ~/.hermes link.
	envWhitelist := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + privsep.AgentHome(),
		"HERMES_HOME=" + hermesHome,
		"API_SERVER_ENABLED=true",
		"API_SERVER_KEY=" + apiServerKey,
		"API_SERVER_CORS_ORIGINS=*",
	}
	if inferenceKey != "" && apiKeyEnv != "" {
		envWhitelist = append(envWhitelist, apiKeyEnv+"="+inferenceKey)
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
	return envWhitelist
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
