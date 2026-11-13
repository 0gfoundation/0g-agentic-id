package harness

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
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
	"seal-verify/internal/inferproxy"
	"seal-verify/internal/logger"
	"seal-verify/internal/platform"
	"seal-verify/internal/privsep"
	"seal-verify/internal/settings"
)

// The process this adapter runs is 0g-harness (github.com/0gfoundation/0g-harness):
// it composes the DSH plugin tree, keeps the one agent, routes each turn's
// output to whoever opened the turn, and serves the owner's /v1/ surface. It
// runs only from an official version package (sealed/LAYERS.md §5): the
// image ships none; sealed installs the one the trust registry lists and
// picks which package Start runs (UseHarness). A package holds the harness
// with its whole dependency tree, locked and built when the package is built
// (images/harness/Dockerfile), and that build fails unless the package's
// version is the one whitelist.go records in the framework role. Its
// environment contract is what environ() builds. Identifiers keep the word
// "bridge" for the loopback process this adapter talks to.
const (
	// bridgePort is the harness's loopback upstream. Distinct from openclaw
	// (3284), hermes (8642), prime (8791).
	bridgePort = 8794

	// packageEntry is the harness's entry script inside a package. It
	// resolves its @deepseek-ai/* imports from the package's node_modules.
	packageEntry = "bin/0g-harness.mjs"

	// logName names the harness's stdout/stderr log under
	// framework.StateDir/log, served on /log/agent.
	logName = "harness-agent"

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
	entry, pkgHash := a.entryLocked(), a.pkgHash
	a.mu.RUnlock()

	// The pin comes from the owner's settings document, not from parsing a
	// file: settings.yaml stopped being a role and stopped existing, so there
	// is nothing on disk to read back and nothing an agent edit could
	// re-point (settings.go). A missing render is a bootstrap bug — not
	// something an owner can cause — so it fails before anything is spawned.
	if rendered == nil {
		return framework.StartResult{}, fmt.Errorf("harness.Start: RenderSettings has not run before Start (bootstrap must render the owner's settings first)")
	}
	provider, model := rendered.resolved.Provider, rendered.resolved.Model
	if provider == "" || model == "" {
		return framework.StartResult{}, fmt.Errorf(
			"harness.Start: no inference pin — the owner's settings name provider=%q model=%q; substituting a model the owner never picked is not an option", provider, model)
	}

	// The credential comes from the RESOLVED SETTINGS, never from
	// RuntimeContext: RuntimeContext is captured at the first Start and
	// replayed verbatim on every restart (so a key rotated at runtime would be
	// silently reverted), it is losing these fields, and reading the key from
	// it is what dialled a platform-routed endpoint keyless and 401'd live.
	//
	ep := modelEndpoint(rendered.resolved)

	// No key is a state the owner sees and fixes: the agent's credential view
	// says no model key is in use, and `cred <agent> set model` applies one
	// to the running agent. So the harness starts, and its model calls fail
	// until then.
	apiKey := rendered.resolved.APIKey
	if apiKey == "" {
		logger.Logf("warn: harness.Start: no model key for %s on %s; model calls fail until the owner sets one (cred <agent> set model)", model, provider)
	}

	// The key stays in sealed: the credential proxy fills it in on the
	// endpoint's host only, and the harness and every tool it runs see a
	// placeholder, never the key.
	apiKey, modelBaseURL := holdInferenceKey(ep, apiKey, rt)

	ownerToken := ""
	if !initialized {
		if token == "" {
			var err error
			if token, err = randomTokenHex(); err != nil {
				return framework.StartResult{}, fmt.Errorf("harness.Start: mint harness token: %w", err)
			}
			if ownerToken, err = randomTokenHex(); err != nil {
				return framework.StartResult{}, fmt.Errorf("harness.Start: mint the owner's token: %w", err)
			}
		}
	} else {
		logger.Logf("harness restart: reusing the harness token")
	}

	// The agent doc: the platform text the model reads (identity, doctrine,
	// environment). No markers, nothing a tracked role carries.
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
		CredSock:            rt.CredSock,
		CredRevealSock:      rt.CredRevealSock,
		Provider:            provider,
		Model:               model,
		ZGComputeRouted:     rendered.resolved.Endpoint != nil && provider == "0g-compute",
		BootTime:            time.Now(),
		RefuseExport:        true,
		// The harness lists the runtime's tools from the sockets and
		// registers them (its seal-tools plugin); the sign socket applies the
		// runtime's signing rules (AppliesSigningRules).
		SealTools:    rt.SealSignSock != "",
		SigningRules: true,
	})
	doc := platform.AssembleAgentDoc(pc, a.FrameworkFacts())
	be := bridgeEnv{
		token:        token,
		apiKey:       apiKey,
		modelBaseURL: modelBaseURL,
		settingsEnv:  rendered.env,
		rt:           rt,
	}
	// The model is called through sealed's inference route (sealed/LAYERS.md
	// §4.2): every request goes to the endpoint above, names the owner's
	// model and carries the agent doc at the end of its system prompt, which
	// the harness code therefore cannot leave out; the route sets the key's
	// placeholder, which the credential proxy fills, and the harness holds
	// none. Only for a provider sealed knows no endpoint of does the harness
	// dial its own, and the doc is then a file OUTSIDE the framework home
	// that the harness puts into its system prompt itself.
	inferURL := ""
	if ep != nil {
		route, err := a.inferenceRoute()
		if err != nil {
			return framework.StartResult{}, fmt.Errorf("harness.Start: inference route: %w", err)
		}
		upstream := modelBaseURL
		if upstream == "" {
			upstream = ep.BaseURL
		}
		route.SetRoute(inferproxy.Route{Upstream: upstream, Headers: inferenceHeaders(ep.Format, apiKey), Model: model, System: doc})
		be.apiKey, be.modelBaseURL, be.modelAPI = routedKeyPlaceholder, route.BaseURL(), wireAPI(ep.Format)
		inferURL = ep.BaseURL
	} else {
		if err := privsep.WriteFile(agentDocPath(), []byte(doc), 0o644); err != nil {
			// Serving without the platform doc means an agent that doesn't know
			// its identity or the sign-refusal doctrine. Fail rather than
			// degrade.
			return framework.StartResult{}, fmt.Errorf("harness.Start: write agent doc %s: %w", agentDocPath(), err)
		}
		be.agentDoc = agentDocPath()
	}

	if entry == "" {
		return framework.StartResult{}, fmt.Errorf("harness.Start: no harness package chosen (UseHarness): the harness runs only from an official version package, which sealed installs under the layered flow (sealed/LAYERS.md §5)")
	}
	if !initialized {
		// A harness an earlier sealed in this container left running (one
		// that exited without stopping it) would hold the port, and the
		// listen check below would find it instead of the process spawned
		// here. Any package's entry matches.
		privsep.Sweep(packageEntry)
	}
	cmd, err := spawnBridge(be, entry)
	if err != nil {
		return framework.StartResult{}, fmt.Errorf("harness.Start: %w: %w", framework.ErrHarnessDidNotStart, err)
	}
	proc := watchProc(cmd, entry)

	a.mu.Lock()
	a.proc = proc
	a.runHash = pkgHash
	a.inferURL, a.inferModel = inferURL, model
	a.bridgeToken = token
	if ownerToken != "" {
		a.ownerToken = ownerToken
	}
	a.initialized = true
	a.mu.Unlock()

	addr := fmt.Sprintf("127.0.0.1:%d", bridgePort)
	if err := waitForListen(ctx, addr, startTimeout, proc.done); err != nil {
		return framework.StartResult{}, fmt.Errorf("harness.Start: %w: harness not listening: %w", framework.ErrHarnessDidNotStart, err)
	}
	return framework.StartResult{Upstream: "http://" + addr, PID: cmd.Process.Pid}, nil
}

// entryLocked is the entry script Start runs: the chosen package's, "" when
// none was chosen. a.mu must be held.
func (a *Adapter) entryLocked() string {
	if a.pkgDir == "" {
		return ""
	}
	return filepath.Join(a.pkgDir, packageEntry)
}

// harnessProc is one spawned harness process. Exactly one goroutine waits
// for it (watchProc), and Stop and MonitorExit both learn of its exit from
// done: a second wait on the same process would find it already reaped.
type harnessProc struct {
	cmd   *exec.Cmd
	entry string
	done  chan struct{}
	err   error // cmd.Wait's result, set before done closes
}

func watchProc(cmd *exec.Cmd, entry string) *harnessProc {
	p := &harnessProc{cmd: cmd, entry: entry, done: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	return p
}

// bridgeEnv carries the per-Start values the harness process needs.
type bridgeEnv struct {
	token string
	// apiKey is the model key the harness is given: routedKeyPlaceholder
	// when sealed's inference route sets the key, otherwise
	// settings.Resolved.APIKey — the credential the platform resolved for
	// THIS boot. Never framework.RuntimeContext.APIKey: that field is going
	// away, and it is frozen at the first Start, so a key that changed since
	// would be silently reverted by the next restart.
	apiKey string
	// modelBaseURL, when set, replaces the rendered SEAL_MODEL_BASE_URL:
	// sealed's inference route.
	modelBaseURL string
	// settingsEnv is what RenderSettings produced (settings.go): the model
	// pin, the endpoint wiring, the reasoning bound and the owner's
	// composition knobs, already rendered as sorted KEY=VALUE entries.
	settingsEnv []string
	rt          framework.RuntimeContext
	// agentDoc is the path of the agent doc file, "" when the doc rides the
	// inference route instead.
	agentDoc string
	// modelAPI, when set, replaces the rendered SEAL_MODEL_API: the wire
	// protocol of the endpoint the inference route forwards to.
	modelAPI string
}

// modelEndpoint is the endpoint sealed's inference route forwards the
// harness's model calls to: a platform-routed model's from the provider
// registry, a native provider's official one fixed in sealed
// (inference.NativeEndpoint). nil only for a provider sealed knows no
// endpoint of.
func modelEndpoint(s settings.Resolved) *inference.Endpoint {
	if s.Endpoint != nil {
		return s.Endpoint
	}
	ep, _ := inference.NativeEndpoint(s.Provider)
	return ep
}

// routedKeyPlaceholder is what the harness is given as its model key when
// sealed's inference route sets the real one: the harness's SDK wants a
// non-empty key, and the route drops whatever the harness sends.
const routedKeyPlaceholder = "sealed-inference-route"

// inferenceRoute is the adapter's inference proxy, started on first use and
// kept for the life of the process.
func (a *Adapter) inferenceRoute() (*inferproxy.Server, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.infer == nil {
		s, err := inferproxy.Start()
		if err != nil {
			return nil, err
		}
		a.infer = s
	}
	return a.infer, nil
}

// inferenceHeaders carries the key the way each wire takes it: the OpenAI
// wire's bearer token, the Anthropic wire's x-api-key.
func inferenceHeaders(f inference.WireFormat, key string) map[string]string {
	if f == inference.WireAnthropic {
		return map[string]string{"x-api-key": key}
	}
	return map[string]string{"Authorization": "Bearer " + key}
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
		"SEAL_PERSONA_PATH=" + appendSystemPath(),
		// The harness persists the conversation here and re-seeds the session
		// from it on a process restart (CONVERSATION.md); its turn records sit
		// next to it as <file>.records.jsonl, so ClearSession clears both.
		"SEAL_CONVERSATION_FILE=" + conversationPath(),
	}
	if be.agentDoc != "" {
		env = append(env, "SEAL_AGENT_DOC="+be.agentDoc)
	}
	// Everything the owner's settings decide (pin, endpoint, reasoning bound,
	// composition knobs) — rendered once, deterministically, before Start.
	for _, kv := range be.settingsEnv {
		if be.modelBaseURL != "" && strings.HasPrefix(kv, "SEAL_MODEL_BASE_URL=") {
			continue
		}
		if be.modelAPI != "" && strings.HasPrefix(kv, "SEAL_MODEL_API=") {
			continue
		}
		env = append(env, kv)
	}
	if be.modelBaseURL != "" {
		env = append(env, "SEAL_MODEL_BASE_URL="+be.modelBaseURL)
	}
	if be.modelAPI != "" {
		env = append(env, "SEAL_MODEL_API="+be.modelAPI)
	}
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
	return append(env, be.rt.CredentialEnv()...)
}

// holdInferenceKey has the credential proxy hold the key for the endpoint and
// returns what the inference route sends instead: the placeholder, and the
// endpoint's base URL through the credential proxy, which fills the key in
// on that host only. Otherwise (no proxy, no endpoint, no key, or the proxy
// could not hold it) the key and no base URL come back, and the inference
// route sets the key itself; either way the harness never gets it. After
// the owner changed there is no key at all (the new owner resets the agent).
func holdInferenceKey(ep *inference.Endpoint, apiKey string, rt framework.RuntimeContext) (key, baseURL string) {
	if ep == nil || apiKey == "" || rt.CredHold == nil {
		return apiKey, ""
	}
	base, placeholder, err := rt.CredHold("inference", ep.BaseURL, inferenceKeyHeaders, []byte(apiKey))
	if errors.Is(err, framework.ErrCredHoldRefused) {
		logger.Logf("warn: harness.Start: %v; the harness starts without the inference key", err)
		return "", ""
	}
	if err != nil {
		logger.Logf("warn: harness.Start: the credential proxy could not hold the inference key (%v); the inference route sets it itself", err)
		return apiKey, ""
	}
	return placeholder, base
}

// inferenceKeyHeaders are where the inference key may be filled in: the
// OpenAI wire's bearer token and the Anthropic wire's x-api-key.
var inferenceKeyHeaders = map[string]string{"Authorization": "Bearer {v}", "x-api-key": "{v}"}

func spawnBridge(be bridgeEnv, entry string) (*exec.Cmd, error) {
	logFile, err := framework.OpenLog(logName)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", framework.LogPath(logName), err)
	}

	// Run the harness (and every tool subprocess it spawns) as the
	// low-privilege agent user when the image provides one (a plain spawn
	// otherwise — internal/privsep). Background, not Start's ctx: the harness
	// outlives the call that spawned it; Stop ends it. entry is in a package
	// directory root owns and the agent can only read (sealed/LAYERS.md
	// §5.2).
	cmd, err := privsep.AgentCommand(context.Background(), "node", entry)
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
	logger.Logf("harness: harness started (pid %d, port %d, %s)", cmd.Process.Pid, bridgePort, entry)
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

// waitForListen polls a TCP address until it accepts a connection, and gives
// up as soon as exited closes (the process that was to listen is gone).
func waitForListen(ctx context.Context, addr string, timeout time.Duration, exited <-chan struct{}) error {
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
		case <-exited:
			return fmt.Errorf("the process exited before %s accepted connections", addr)
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
	proc := a.proc
	a.proc = nil
	entry := a.entryLocked()
	a.mu.Unlock()

	if proc != nil {
		entry = proc.entry
		_ = proc.cmd.Process.Signal(os.Interrupt)
		select {
		case <-proc.done:
		case <-time.After(gracefulTimeout):
			_ = proc.cmd.Process.Kill()
			<-proc.done
		}
	}

	if entry != "" {
		privsep.Sweep(entry)
	}
	return nil
}

// Liveness: the harness's port is open.
func (a *Adapter) Liveness(ctx context.Context) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", bridgePort), 2*time.Second)
	if err != nil {
		return fmt.Errorf("harness.Liveness: %w", err)
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
		return fmt.Errorf("harness.Readiness: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("harness.Readiness: /healthz returned %d", resp.StatusCode)
	}
	return nil
}

// AuthResponse hands the verified owner its bearer token for /v1/*. The proxy
// has already checked the EIP-191 signature against the live on-chain owner.
// It is not the token the harness checks: the proxy swaps it for that one
// (TranslateBearer).
func (a *Adapter) AuthResponse(ctx context.Context) (any, error) {
	a.mu.RLock()
	token := a.ownerToken
	a.mu.RUnlock()
	if token == "" {
		return nil, fmt.Errorf("harness.AuthResponse: harness not started yet")
	}
	return map[string]any{"token": token}, nil
}

// TranslateBearer implements framework.BearerTranslator: the owner's token
// in, the harness's own out.
func (a *Adapter) TranslateBearer(token string) (string, bool) {
	a.mu.RLock()
	owner, bridge := a.ownerToken, a.bridgeToken
	a.mu.RUnlock()
	if owner == "" || bridge == "" || subtle.ConstantTimeCompare([]byte(token), []byte(owner)) != 1 {
		return "", false
	}
	return bridge, true
}

// Bounds of an agent service registration's text (ServiceFieldLimits): one
// short sentence of description, one small example body.
const (
	serviceDescriptionMax  = 280
	serviceInputExampleMax = 2048
)

// ServiceFieldLimits implements framework.ServiceFieldLimiter.
func (a *Adapter) ServiceFieldLimits() (description, inputExample int) {
	return serviceDescriptionMax, serviceInputExampleMax
}

// AppliesSigningRules implements framework.SigningRules: the sign socket
// refuses AgenticID iData writes and records every signature for the owner.
func (a *Adapter) AppliesSigningRules() bool { return true }

// ServesRuntimeTools implements framework.RuntimeTools: the harness's
// seal-tools plugin registers the tools the sockets list.
func (a *Adapter) ServesRuntimeTools() bool { return true }

// MonitorExit satisfies manager.Adapter: invoke onExit once when the harness
// exits, with cmd.Wait's error.
func (a *Adapter) MonitorExit(onExit func(err error)) {
	a.mu.RLock()
	proc := a.proc
	a.mu.RUnlock()
	if proc == nil {
		return
	}
	go func() {
		<-proc.done
		onExit(proc.err)
	}()
}

// SubprocessLogPath implements framework.SubprocessLogProvider: the harness
// log is what /log/agent serves.
func (a *Adapter) SubprocessLogPath() string { return framework.LogPath(logName) }

// FrameworkRoutes declares the owner surface the harness serves. Every route
// has the same upstream, so routing is the /v1/ prefix's either way; the
// separate entries exist so /hello ADVERTISES each capability by its kind —
// a client enables a feature only when the agent declares it, and other
// frameworks, which declare none of these kinds, are left exactly as they are.
// docs/PROTOCOL.md in 0g-harness (protocol 1) is the contract, and each
// route lists its endpoints from it: the proxy forwards those requests only
// (sealed/LAYERS.md §4.3), so an endpoint the harness's code adds is not
// reachable from outside until sealed lists it.
func (a *Adapter) FrameworkRoutes() []framework.Route {
	backend := fmt.Sprintf("http://127.0.0.1:%d", bridgePort)
	route := func(prefix, kind, description string, endpoints ...framework.Endpoint) framework.Route {
		return framework.Route{Prefix: prefix, Kind: kind, Auth: "bearer", Signed: false, Backend: backend, Description: description, Endpoints: endpoints}
	}
	get := func(path string) framework.Endpoint { return framework.Endpoint{Method: http.MethodGet, Path: path} }
	post := func(path string) framework.Endpoint { return framework.Endpoint{Method: http.MethodPost, Path: path} }
	return []framework.Route{
		// STATEFUL, like prime: the conversation lives in the harness's DSH
		// session and only the last user message of `messages` is read, so
		// re-sending an edited history does not rewind it.
		route("/v1/", "chat", "OpenAI-compatible chat/completions API (0g-harness). STATEFUL: the conversation lives in a server-side session and only the last user message is read. Owner turns run one at a time.",
			get("/v1/harness"), post("/v1/chat/completions"), post("/v1/interrupt"), post("/v1/compact")),
		// The SDK picks Responses over chat/completions when it sees this kind
		// (the long-task surface: the turn is owned by a server-side response
		// id, not by the HTTP connection).
		route("/v1/responses", "responses", "OpenAI Responses API subset (0g-harness): POST /v1/responses {input, stream} → events with sequence_number; GET /{id} polls; GET /{id}?stream=true&starting_after=N resumes; POST /{id}/cancel stops the turn. Same stateful session as the chat route.",
			post("/v1/responses"), get("/v1/responses/{id}"), post("/v1/responses/{id}/cancel")),
		route("/v1/inbox", "inbox", "Messages from turns the agent opened itself — a background job finishing, a reminder coming due: GET /v1/inbox?after=N, POST /v1/inbox/ack {through}.",
			get("/v1/inbox"), post("/v1/inbox/ack")),
		route("/v1/events", "events", "Server-sent feed of turn, inbox, task and schedule changes, resumable from a cursor: GET /v1/events?after=N.",
			get("/v1/events")),
		route("/v1/tasks", "tasks", "Turns, background commands and subagents, with who did each: GET /v1/tasks, GET /v1/tasks/{id}, POST /v1/tasks/{id}/cancel (id `all` cancels everything running).",
			get("/v1/tasks"), get("/v1/tasks/{id}"), post("/v1/tasks/{id}/cancel")),
		route("/v1/schedules", "schedules", "Reminders the agent set for itself: GET /v1/schedules (enabled:false unless the owner's `schedule` knob is on).",
			get("/v1/schedules"), framework.Endpoint{Method: http.MethodDelete, Path: "/v1/schedules/{id}"}),
	}
}
