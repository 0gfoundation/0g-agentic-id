package dsh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/platform"
	"seal-verify/internal/privsep"
)

// The process this adapter runs is 0g-harness (github.com/0gfoundation/0g-harness):
// it composes the DSH plugin tree, keeps the one agent, routes each turn's
// output to whoever opened the turn, and serves the owner's /v1/ surface. The
// image installs it at build time with its whole dependency tree locked
// (images/dsh/Dockerfile), so its bytes ride the image hash; the build also
// fails unless the DSH version it locks is the one whitelist.go records in
// the framework role. Its environment contract is what environ() builds.
// Identifiers keep the word "bridge" for the loopback process this adapter
// talks to.
const (
	// bridgePort is the harness's loopback upstream. Distinct from openclaw
	// (3284), hermes (8642), prime (8791).
	bridgePort = 8794

	// harnessEntry is the harness's entry script in the image's global
	// node_modules (node is installed under /usr/local, see the Dockerfile).
	// It resolves its @deepseek-ai/* imports from its own node_modules.
	harnessEntry = "/usr/local/lib/node_modules/@0gfoundation/0g-harness/bin/0g-harness.mjs"

	// logName names the harness's stdout/stderr log under
	// framework.StateDir/log, served on /log/agent.
	logName = "dsh-agent"

	// startTimeout bounds the wait for the harness to bind. First boot
	// composes the whole plugin tree and the first model resolution.
	startTimeout = 180 * time.Second
)

// Start: take the pin RenderSettings resolved → write the agent doc → spawn
// the harness de-privileged → wait for it to listen.
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
				"dsh.Start: the platform routes %s to %s but this boot has no inference key — the harness would dial it unauthenticated and 401 on the first turn (check API_KEY in the container's environment)", model, ep.BaseURL)
		}
		// A framework built-in supplies its own endpoint, and only its own
		// provider knows whether that endpoint needs a key at all. Say so and
		// keep booting.
		logger.Logf("warn: dsh.Start: no inference key for this boot; provider %q must serve %s unauthenticated or the first turn fails", provider, model)
	}

	if !initialized {
		if token == "" {
			var err error
			if token, err = randomTokenHex(); err != nil {
				return framework.StartResult{}, fmt.Errorf("dsh.Start: mint harness token: %w", err)
			}
		}
	} else {
		logger.Logf("dsh restart: reusing the harness token")
	}

	// Agent doc → a file OUTSIDE the framework home; the harness injects it as
	// a system-prompt section (the authoritative channel). No markers, nothing
	// a tracked role carries.
	pc := platform.Build(platform.RuntimeSnapshot{
		SealedVersion:       rt.SealedVersion,
		FrameworkVersion:    version,
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
		ZGComputeRouted:     rendered.resolved.Endpoint != nil && provider == "0g-compute",
		BootTime:            time.Now(),
	})
	if err := privsep.WriteFile(agentDocPath(), []byte(platform.AssembleAgentDoc(pc, a.FrameworkFacts())), 0o644); err != nil {
		// Serving without the platform doc means an agent that doesn't know its
		// identity or the sign-refusal doctrine. Fail rather than degrade.
		return framework.StartResult{}, fmt.Errorf("dsh.Start: write agent doc %s: %w", agentDocPath(), err)
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
		return framework.StartResult{}, fmt.Errorf("dsh.Start: harness not listening: %w", err)
	}
	return framework.StartResult{Upstream: "http://" + addr, PID: cmd.Process.Pid}, nil
}

// bridgeEnv carries the per-Start values the harness process needs.
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

// environ builds the harness process's whole environment.
//
// A strict whitelist, NOT the inherited env: a leaked SANDBOX_SEAL_KEY must
// not be readable via /proc/self/environ (or plain `env`) from inside the
// agent process, which runs arbitrary model-authored bash.
func (be bridgeEnv) environ() []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		// The agent's own home (privsep.AgentHome): its tools' caches and
		// config go there. DSH_HOME names the framework tree explicitly;
		// ~/.dsh links to the same tree for the paths the agent is told.
		"HOME=" + privsep.AgentHome(),
		"DSH_HOME=" + dshHome,
		fmt.Sprintf("SEAL_BRIDGE_PORT=%d", bridgePort),
		"SEAL_BRIDGE_TOKEN=" + be.token,
		"SEAL_AGENT_DOC=" + agentDocPath(),
		"SEAL_PERSONA_PATH=" + appendSystemPath(),
		// The harness persists the conversation here and re-seeds the session
		// from it on a process restart (CONVERSATION.md); its turn records sit
		// next to it as <file>.records.jsonl, so ClearSession clears both.
		"SEAL_CONVERSATION_FILE=" + conversationPath(),
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
	logFile, err := framework.OpenLog(logName)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", framework.LogPath(logName), err)
	}

	// Run the harness (and every tool subprocess it spawns) as the
	// low-privilege agent user when the image provides one (a plain spawn
	// otherwise — internal/privsep). Background, not Start's ctx: the harness
	// outlives the call that spawned it; Stop ends it.
	cmd, err := privsep.AgentCommand(context.Background(), "node", harnessEntry)
	if err != nil {
		logFile.Close()
		return nil, fmt.Errorf("start harness: %w", err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Dir = dshHome
	cmd.Env = be.environ()

	// Restore wrote $DSH_HOME as root, so hand it over now, and link it into
	// the agent's own home as ~/.dsh; root's home stays root's
	// (privsep.SecureHome). The harness package stays root-owned read-only.
	privsep.OwnTree(dshHome)
	privsep.LinkAgentHome(".dsh", dshHome)

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("start harness: %w", err)
	}
	logger.Logf("dsh: harness started (pid %d, port %d)", cmd.Process.Pid, bridgePort)
	return cmd, nil
}

// randomTokenHex mints the harness bearer token: 32 random bytes, hex-encoded.
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

// Stop terminates the harness: SIGTERM, wait, SIGKILL — then SIGKILLs any
// stray process whose command line names the harness entry (privsep.Sweep,
// which runs pkill as the agent user, so it reaches only agent processes),
// so the next Start gets a clean port.
func (a *Adapter) Stop(ctx context.Context, gracefulTimeout time.Duration) error {
	a.mu.Lock()
	cmd := a.cmd
	a.cmd = nil
	a.mu.Unlock()

	if cmd != nil && cmd.Process != nil {
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
	}

	privsep.Sweep(harnessEntry)
	return nil
}

// Liveness: the harness's port is open.
func (a *Adapter) Liveness(ctx context.Context) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", bridgePort), 2*time.Second)
	if err != nil {
		return fmt.Errorf("dsh.Liveness: %w", err)
	}
	conn.Close()
	return nil
}

// Readiness: the harness answers its loopback health route. Distinct from
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

// AuthResponse hands the verified owner the harness bearer token. The proxy has
// already checked the EIP-191 signature against the live on-chain owner.
func (a *Adapter) AuthResponse(ctx context.Context) (any, error) {
	a.mu.RLock()
	token := a.bridgeToken
	a.mu.RUnlock()
	if token == "" {
		return nil, fmt.Errorf("dsh.AuthResponse: harness not started yet")
	}
	return map[string]any{"token": token}, nil
}

// MonitorExit satisfies manager.Adapter: invoke onExit once when the harness
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

// SubprocessLogPath implements framework.SubprocessLogProvider: the harness
// log is what /log/agent serves.
func (a *Adapter) SubprocessLogPath() string { return framework.LogPath(logName) }

// FrameworkRoutes declares the owner surface the harness serves. Every route
// has the same upstream, so routing is the /v1/ prefix's either way; the
// separate entries exist so /hello ADVERTISES each capability by its kind —
// a client enables a feature only when the agent declares it, and other
// frameworks, which declare none of these kinds, are left exactly as they are.
// docs/PROTOCOL.md in 0g-harness is the contract.
func (a *Adapter) FrameworkRoutes() []framework.Route {
	backend := fmt.Sprintf("http://127.0.0.1:%d", bridgePort)
	route := func(prefix, kind, description string) framework.Route {
		return framework.Route{Prefix: prefix, Kind: kind, Auth: "bearer", Signed: false, Backend: backend, Description: description}
	}
	return []framework.Route{
		// STATEFUL, like prime: the conversation lives in the harness's DSH
		// session and only the last user message of `messages` is read, so
		// re-sending an edited history does not rewind it.
		route("/v1/", "chat", "OpenAI-compatible chat/completions API (0g-harness). STATEFUL: the conversation lives in a server-side session and only the last user message is read. Owner turns run one at a time."),
		// The SDK picks Responses over chat/completions when it sees this kind
		// (the long-task surface: the turn is owned by a server-side response
		// id, not by the HTTP connection).
		route("/v1/responses", "responses", "OpenAI Responses API subset (0g-harness): POST /v1/responses {input, stream} → events with sequence_number; GET /{id} polls; GET /{id}?stream=true&starting_after=N resumes; POST /{id}/cancel stops the turn. Same stateful session as the chat route."),
		route("/v1/inbox", "inbox", "Messages from turns the agent opened itself — a background job finishing, a reminder coming due: GET /v1/inbox?after=N, POST /v1/inbox/ack {through}."),
		route("/v1/events", "events", "Server-sent feed of turn, inbox, task and schedule changes, resumable from a cursor: GET /v1/events?after=N."),
		route("/v1/tasks", "tasks", "Turns, background commands and subagents, with who did each: GET /v1/tasks, GET /v1/tasks/{id}, POST /v1/tasks/{id}/cancel (id `all` cancels everything running)."),
		route("/v1/schedules", "schedules", "Reminders the agent set for itself: GET /v1/schedules (enabled:false unless the owner's `schedule` knob is on)."),
	}
}
