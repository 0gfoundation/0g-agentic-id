package servicehost

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"seal-verify/internal/credproxy"
	"seal-verify/internal/privsep"
	"seal-verify/internal/serviceidentity"
	"seal-verify/internal/servicesandbox"
)

type Status struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	Path        string `json:"path"`
	Description string `json:"description,omitempty"`
	State       string `json:"state"`
	Desired     bool   `json:"desired"`
	Error       string `json:"error,omitempty"`
}

type entry struct {
	Manifest Manifest `json:"manifest"`
	Status
	ControllerUID uint32 `json:"controller_uid,omitempty"`
	controller    *coordinator
	generation    uint64
}

type Manager struct {
	mu                         sync.Mutex
	base                       string
	programs                   string
	binding                    string
	entries                    map[string]*entry
	closed                     bool
	workers                    map[uint32]*worker
	executions                 map[string]*execution
	executionKeys              map[string]string
	outputBytes                int
	stopGC                     chan struct{}
	pendingInputs              map[string]pendingInput
	egressDial                 func(context.Context, string, string) (net.Conn, error)
	attestor                   ExecutionAttestor
	runtime                    func(context.Context) (RuntimeLease, error)
	model                      func(context.Context) (ModelRoute, error)
	watcher                    *resourceWatcher
	probeMu                    sync.Mutex
	probeAt                    time.Time
	probeErr                   error
	skipResourceLimitsForTests bool
}

// Options is trusted Go wiring, never owner-controlled manifest configuration.
// A test may supply a dialer to a local model/facilitator fixture. Production
// uses New, whose dialer always rejects private and loopback destinations.
type Options struct {
	EgressDial     func(context.Context, string, string) (net.Conn, error)
	AcquireRuntime func(context.Context) (RuntimeLease, error)
	ModelRoute     func(context.Context) (ModelRoute, error)
	// Only Go test fixtures may bypass the confinement probe and runtime pin.
	// No HTTP, env or manifest field can enable this; production leaves it false.
	SkipResourceLimitsForTests bool
}

// New binds durable service state to this container's owner and identity.
// A reset with another binding cannot resume programs from the old owner.
// base must be a sealed-owned directory, never a path supplied by a tool.
func New(base, binding string) (*Manager, error) {
	return NewWithOptions(base, binding, Options{})
}

func NewWithOptions(base, binding string, opts Options) (*Manager, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("service hosting requires sealed root privilege separation")
	}
	if binding == "" {
		return nil, fmt.Errorf("service binding is required")
	}
	if err := privsep.MkdirAll(base, 0700); err != nil {
		return nil, err
	}
	fi, err := privsep.Lstat(base)
	if err != nil {
		return nil, err
	}
	st := fi.Sys().(*unix.Stat_t)
	if st.Uid != 0 || st.Mode&077 != 0 {
		return nil, fmt.Errorf("service state must be root-owned 0700")
	}
	m := &Manager{base: base, binding: binding, entries: map[string]*entry{}, workers: map[uint32]*worker{}, executions: map[string]*execution{}, executionKeys: map[string]string{}, stopGC: make(chan struct{}), pendingInputs: map[string]pendingInput{}}
	m.runtime = opts.AcquireRuntime
	m.model = opts.ModelRoute
	m.skipResourceLimitsForTests = opts.SkipResourceLimitsForTests
	m.egressDial = opts.EgressDial
	if m.egressDial == nil {
		m.egressDial = credproxy.SafeDial
	}
	// Only immutable owner-authored source is shared; requests have private temporary state.
	programID := sha256.Sum256([]byte(base))
	m.programs = fmt.Sprintf("/var/lib/sealed-service-programs/%x", programID[:8])
	if err := privsep.MkdirAll(m.programs, 0755); err != nil {
		return nil, err
	}
	m.watcher = newResourceWatcher(m.stopGC, m.programs)
	// A previous sealed in this container may have left service processes
	// (the loader kills its descendants only when it runs as PID 1, and the
	// runner starts sandboxes with --init). They hold identities and may still
	// write their old directories, so none may survive into this manager.
	if err := reapLeftoverIdentities(); err != nil {
		return nil, err
	}
	// Never resume a request or any caller-provided runtime input after reboot.
	if err := privsep.RemoveAll(filepath.Join(m.programs, taskDirName)); err != nil {
		return nil, err
	}
	if err := privsep.MkdirAll(filepath.Join(m.programs, taskDirName), 0755); err != nil {
		return nil, err
	}
	b, err := privsep.ReadFile(filepath.Join(base, "registry.json"), privsep.LimitConfig)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if len(b) > 0 {
		var saved struct {
			Binding string   `json:"binding"`
			Entries []*entry `json:"entries"`
		}
		if err = json.Unmarshal(b, &saved); err != nil {
			return nil, err
		}
		if saved.Binding != binding {
			return nil, fmt.Errorf("saved services belong to another owner or identity")
		}
		if len(saved.Entries) > MaxServices {
			return nil, fmt.Errorf("too many saved services")
		}
		for _, e := range saved.Entries {
			v, err := e.Manifest.normalize()
			if err != nil || v != e.Version || e.ID != e.Manifest.ID {
				return nil, fmt.Errorf("invalid saved service")
			}
			if m.entries[e.ID] != nil {
				return nil, fmt.Errorf("duplicate saved service")
			}
			if e.Manifest.Worker != nil && !serviceidentity.Valid(int(e.ControllerUID)) {
				return nil, fmt.Errorf("invalid saved coordinator identity")
			}
			if e.ControllerUID != 0 {
				for _, prior := range m.entries {
					if prior.ControllerUID == e.ControllerUID {
						return nil, fmt.Errorf("duplicate coordinator identity")
					}
				}
			}
			e.Path = "/api/mcp/" + e.ID
			e.State = "stopped"
			e.Error = ""
			m.entries[e.ID] = e
		}
	}
	if err := m.restoreExecutions(); err != nil {
		return nil, err
	}
	go m.collectExecutions()
	return m, nil
}

func (m *Manager) persistLocked() error {
	entries := make([]*entry, 0, len(m.entries))
	for _, e := range m.entries {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	b, err := json.Marshal(struct {
		Binding string   `json:"binding"`
		Entries []*entry `json:"entries"`
	}{m.binding, entries})
	if err != nil {
		return err
	}
	if len(b) > int(privsep.LimitConfig) {
		return fmt.Errorf("service registry exceeds durable state limit")
	}
	return privsep.WriteFile(filepath.Join(m.base, "registry.json"), b, 0600)
}

func (m *Manager) Publish(man Manifest) (Status, error) {
	v, err := man.normalize()
	if err != nil {
		return Status{}, err
	}
	// Decode and bound the bundle before touching durable state.
	files := map[string][]byte{}
	total := 0
	for _, f := range man.Files {
		b, err := base64.StdEncoding.DecodeString(f.Data)
		if err != nil {
			return Status{}, fmt.Errorf("%s: invalid base64", f.Path)
		}
		total += len(b)
		if total > MaxBundleBytes {
			return Status{}, fmt.Errorf("bundle exceeds %d bytes", MaxBundleBytes)
		}
		files[f.Path] = b
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return Status{}, fmt.Errorf("service manager closed")
	}
	old := m.entries[man.ID]
	if old != nil && old.Desired {
		return Status{}, fmt.Errorf("stop the service before publishing an update")
	}
	if old != nil && old.controller != nil {
		// The new entry keeps the coordinator identity; its old processes
		// must be gone before anything can start under it again.
		return Status{}, fmt.Errorf("the previous coordinator is still being cleaned up; retry")
	}
	if old == nil {
		if len(m.entries) >= MaxServices {
			return Status{}, fmt.Errorf("service limit reached")
		}
	}
	base := filepath.Join(m.programs, man.ID)
	if err := privsep.MkdirAll(filepath.Join(base, "versions"), 0755); err != nil {
		return Status{}, err
	}
	dest := filepath.Join(base, "versions", v)
	if _, err := privsep.Lstat(dest); os.IsNotExist(err) {
		stage, err := os.MkdirTemp(filepath.Join(base, "versions"), ".publish-")
		if err != nil {
			return Status{}, err
		}
		defer privsep.RemoveAll(stage)
		for p, b := range files {
			f := filepath.Join(stage, p)
			if err := privsep.MkdirAll(filepath.Dir(f), 0755); err != nil {
				return Status{}, err
			}
			if err := privsep.WriteFile(f, b, 0444); err != nil {
				return Status{}, err
			}
		}
		if err := privsep.Chmod(stage, 0755); err != nil {
			return Status{}, err
		}
		if err := privsep.Rename(stage, dest); err != nil {
			return Status{}, err
		}
	} else if err != nil {
		return Status{}, err
	}
	e := &entry{Manifest: man, Status: Status{ID: man.ID, Version: v, Path: "/api/mcp/" + man.ID, Description: man.Description, State: "stopped"}}
	if old != nil {
		e.ControllerUID = old.ControllerUID
	}
	if man.Worker != nil {
		if e.ControllerUID == 0 {
			uid, err := m.allocateIdentityLocked()
			if err != nil {
				return Status{}, err
			}
			e.ControllerUID = uid
		}
		if err := m.prepareCoordinatorWork(e); err != nil {
			return Status{}, err
		}
	}
	m.entries[man.ID] = e
	if err := m.persistLocked(); err != nil {
		if old == nil {
			delete(m.entries, man.ID)
		} else {
			m.entries[man.ID] = old
		}
		return Status{}, err
	}
	// Bound retained source releases. Only root writes this directory.
	if dirs, err := privsep.ReadDir(filepath.Join(base, "versions")); err == nil && len(dirs) > 8 {
		sort.Slice(dirs, func(i, j int) bool {
			a, ea := dirs[i].Info()
			b, eb := dirs[j].Info()
			if ea != nil || eb != nil {
				return dirs[i].Name() < dirs[j].Name()
			}
			return a.ModTime().Before(b.ModTime())
		})
		count := len(dirs)
		for _, d := range dirs {
			if count <= 8 {
				break
			}
			if d.Name() != v {
				_ = privsep.RemoveAll(filepath.Join(base, "versions", d.Name()))
				count--
			}
		}
	}
	return e.Status, nil
}

func (m *Manager) List() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.entries))
	for _, e := range m.entries {
		out = append(out, e.Status)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Start enables a published endpoint. A program with a worker entrypoint runs
// a separately confined service coordinator; business execution uses fresh
// worker identities. Plain one-shot MCP programs retain request isolation.
// The confinement probe and runtime pin run without the manager lock.
func (m *Manager) Start(id string) (Status, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return Status{}, fmt.Errorf("service manager closed")
	}
	e := m.entries[id]
	if e == nil {
		m.mu.Unlock()
		return Status{}, fmt.Errorf("unknown service")
	}
	if e.Desired && (e.State == "running" || e.State == "starting" || e.State == "restarting") {
		out := e.Status
		m.mu.Unlock()
		return out, nil
	}
	if e.controller != nil {
		m.mu.Unlock()
		return Status{}, fmt.Errorf("the previous coordinator is still being cleaned up; retry")
	}
	previousDesired := e.Desired
	e.Desired = true
	e.Error = ""
	if err := m.persistLocked(); err != nil {
		e.Desired = previousDesired
		m.mu.Unlock()
		return Status{}, err
	}
	e.State = "starting"
	coordinated := e.Manifest.Worker != nil
	m.mu.Unlock()
	if coordinated {
		err := m.startCoordinator(id)
		m.mu.Lock()
		defer m.mu.Unlock()
		return e.Status, err
	}
	err := m.admission(context.Background())
	m.mu.Lock()
	defer m.mu.Unlock()
	if !e.Desired || m.closed {
		return e.Status, nil
	}
	if err != nil {
		setAdmissionFailure(e, err)
		return e.Status, err
	}
	e.State = "running"
	return e.Status, nil
}

func setAdmissionFailure(e *entry, err error) {
	e.State, e.Error = "failed", err.Error()
	if errors.Is(err, ErrIsolationUnavailable) {
		e.State = "unsupported"
	}
}

// allocateIdentityLocked draws an unused service identity at random:
// identities of different sandboxes then meet only by chance (serviceidentity).
func (m *Manager) allocateIdentityLocked() (uint32, error) {
	for i := 0; i < 64; i++ {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		uid := serviceidentity.Draw(binary.BigEndian.Uint32(b[:]))
		if m.workers[uid] != nil || m.controllerLocked(uid) {
			continue
		}
		return uid, nil
	}
	return 0, fmt.Errorf("no free service identity")
}

func (m *Manager) controllerLocked(uid uint32) bool {
	for _, e := range m.entries {
		if e.ControllerUID == uid {
			return true
		}
	}
	return false
}

// privateDir creates dir as root (so a service cannot place it first) and
// hands it to the service identity alone.
func privateDir(dir string, uid uint32) error {
	if err := privsep.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chown(dir, int(uid), int(uid)); err != nil {
		return err
	}
	return privsep.Chmod(dir, 0700)
}

type commandKind int

const (
	requestCommand     commandKind = iota // one anonymous MCP request
	coordinatorCommand                    // a service's long-running coordinator
	executionCommand                      // a detached execution its coordinator started
)

// command builds the confined launch of one service process (servicesandbox):
// the trusted launcher confines itself to the identity, sets the rlimits and
// execs the interpreter. It owns lease from here: released on failure,
// otherwise once the identity has been reaped.
func (m *Manager) command(ctx context.Context, e *entry, uid uint32, taskDir string, kind commandKind, lease RuntimeLease) (_ *isolatedCommand, err error) {
	defer func() {
		if err != nil && lease.Release != nil {
			lease.Release()
		}
	}()
	sys := imageSystem()
	interpreter, err := privsep.LookPath(e.Manifest.Command)
	if err != nil {
		return nil, err
	}
	if real, rerr := filepath.EvalSymlinks(interpreter); rerr == nil {
		interpreter = real
	}
	if !withinAny(interpreter, sys.readExec) {
		return nil, fmt.Errorf("interpreter %s is outside the image's system directories", e.Manifest.Command)
	}
	program := filepath.Join(m.programs, e.ID, "versions", e.Version)
	run := filepath.Join(taskDir, "run")
	work := filepath.Join(taskDir, "work")
	tmp := filepath.Join(taskDir, "tmp")
	if kind != coordinatorCommand {
		if err = privateDir(work, uid); err != nil {
			return nil, err
		}
	}
	if err = discardDir(tmp); err != nil {
		return nil, err
	}
	if err = privateDir(tmp, uid); err != nil {
		return nil, err
	}
	p := servicesandbox.Policy{
		UID:        uid,
		ReadExec:   append(append([]string(nil), sys.readExec...), program),
		ReadOnly:   sys.readOnly,
		Devices:    sys.devices,
		SocketDirs: []string{run},
		ReadWrite:  []string{work, tmp},
		Dir:        program,
		Program:    interpreter,
	}
	env := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + work, "TMPDIR=" + tmp, "MCP_SOCKET=" + filepath.Join(run, "service.sock"),
		"SEAL_SERVICE_ID=" + e.ID, "SEAL_SERVICE_VERSION=" + e.Version}
	if kind == coordinatorCommand {
		env = append(env, "SEAL_EXEC_SOCKET="+filepath.Join(run, "control.sock"))
	}
	var networkBootstrap string
	if lease.Dir != "" {
		p.ReadExec = append(p.ReadExec, lease.Dir)
		env = append(env, "HARNESS_RUNTIME_ROOT="+lease.Dir)
		networkBootstrap = filepath.Join(lease.Dir, "src", "service-network.mjs")
	}
	bridged := false
	if e.Manifest.Network == "egress" {
		if err = m.startEgress(ctx, e.Manifest.EgressHosts, uid, filepath.Join(run, "egress.sock")); err != nil {
			return nil, err
		}
		env = append(env, "SEAL_EGRESS_SOCKET="+filepath.Join(run, "egress.sock"))
		bridged = true
	}
	// Temporary workers (requests and executions) may spend the published
	// budget on the owner's model; the coordinator never receives the route.
	if kind != coordinatorCommand && e.Manifest.InferenceBudget != nil {
		route, rerr := m.startModel(ctx, *e.Manifest.InferenceBudget, uid, filepath.Join(run, "model.sock"))
		if rerr != nil {
			return nil, rerr
		}
		env = append(env, "SEAL_MODEL_SOCKET="+filepath.Join(run, "model.sock"), "SEAL_MODEL_ID="+route.Route.Model, "SEAL_MODEL_API="+route.API)
		bridged = true
	}
	keys := make([]string, 0, len(e.Manifest.Env))
	for k := range e.Manifest.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		env = append(env, k+"="+e.Manifest.Env[k])
	}
	p.Env = env
	if bridged && e.Manifest.Command == "node" {
		if networkBootstrap == "" {
			return nil, fmt.Errorf("immutable Node egress bridge unavailable")
		}
		p.Args = append(p.Args, "--import", networkBootstrap)
	}
	p.Args = append(p.Args, e.Manifest.Args...)
	p.Limits = servicesandbox.Limits{AddressSpace: uint64(e.Manifest.MemoryMB) << 20, Processes: uint64(e.Manifest.Processes), Files: 256, FileSize: 64 << 20}
	if err = p.Validate(); err != nil {
		return nil, err
	}
	// Only the trusted launcher executes as root; it drops to the service
	// identity, then sets the rlimits, before the interpreter runs.
	cmd, err := privsep.RootCommand(ctx, "sealed-service-launcher", p.LauncherArgs()...)
	if err != nil {
		return nil, err
	}
	c := &isolatedCommand{Cmd: cmd, uid: uid, runtimeHash: lease.Hash, release: lease.Release, watcher: m.watcher,
		limits: limits{residentBytes: int64(e.Manifest.ResidentMemoryMB) << 20, diskDirs: []string{work, tmp}, diskBytes: 2 * temporaryFilesystemBytes}}
	if kind == coordinatorCommand {
		// The coordinator's work directory is its durable business state.
		c.limits.diskBytes = coordinatorStateBytes + temporaryFilesystemBytes
	}
	return c, nil
}

func (m *Manager) Stop(id string) (Status, error) {
	m.mu.Lock()
	e := m.entries[id]
	if e == nil {
		m.mu.Unlock()
		return Status{}, fmt.Errorf("unknown service")
	}
	prev := e.Desired
	e.Desired = false
	if err := m.persistLocked(); err != nil {
		e.Desired = prev
		m.mu.Unlock()
		return Status{}, err
	}
	var taskWaits []chan struct{}
	e.generation++
	if e.controller != nil {
		e.controller.cancel()
		taskWaits = append(taskWaits, e.controller.done)
	}
	for _, w := range m.workers {
		if w.service == id {
			w.cancel()
			taskWaits = append(taskWaits, w.done)
		}
	}
	e.State = "stopped"
	out := e.Status
	m.mu.Unlock()
	// Processes are killed at once; only an identity whose reap keeps failing
	// stays pinned. Report that instead of blocking the caller indefinitely.
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for _, d := range taskWaits {
		select {
		case <-d:
		case <-deadline.C:
			m.mu.Lock()
			if !e.Desired {
				e.State, e.Error = "stopping", "processes are still being cleaned up"
			}
			out = e.Status
			m.mu.Unlock()
			return out, nil
		}
	}
	return out, nil
}

// Resume is called only after chain bootstrap has confirmed the identity and
// owner binding. Published versions and desired states survive a reboot.
func (m *Manager) Resume() {
	m.mu.Lock()
	var coordinated, plain []string
	for id, e := range m.entries {
		if !e.Desired {
			continue
		}
		e.State = "starting"
		if e.Manifest.Worker != nil {
			coordinated = append(coordinated, id)
		} else {
			plain = append(plain, id)
		}
	}
	m.mu.Unlock()
	probeErr := m.admission(context.Background())
	m.mu.Lock()
	for _, id := range plain {
		if e := m.entries[id]; e != nil && e.Desired && !m.closed {
			if probeErr != nil {
				setAdmissionFailure(e, probeErr)
			} else {
				e.State = "running"
			}
		}
	}
	m.mu.Unlock()
	for _, id := range coordinated {
		_ = m.startCoordinator(id)
	}
}

// Close stops every sandbox without changing persisted desired states. A
// transfer permanently closes this manager; a normal reboot may resume it.
func (m *Manager) Close() {
	m.mu.Lock()
	if !m.closed {
		close(m.stopGC)
	}
	m.closed = true
	var waits []chan struct{}
	for _, w := range m.workers {
		w.cancel()
		waits = append(waits, w.done)
	}
	for _, e := range m.entries {
		e.generation++
		if e.controller != nil {
			e.controller.cancel()
			waits = append(waits, e.controller.done)
		}
		e.State = "stopped"
	}
	m.mu.Unlock()
	for _, d := range waits {
		select {
		case <-d:
		case <-time.After(5 * time.Second):
		}
	}
}

func (m *Manager) Logs(id string) (string, error) {
	m.mu.Lock()
	_, ok := m.entries[id]
	m.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("unknown service")
	}
	// Request stdout/stderr is discarded, never retained in an owner-readable log.
	return "", nil
}

// Match identifies a published service; Start controls request admission.
func (m *Manager) Match(path string) (Status, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.Path == path {
			return e.Status, true
		}
	}
	return Status{}, false
}

// Client talks to one service's private Unix socket. Service sessions and
// headers pass through unchanged; HTTP proxy environment variables are ignored.
func Client(socket string) *http.Client {
	return &http.Client{Transport: &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}, DisableCompression: true, ResponseHeaderTimeout: 30 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
