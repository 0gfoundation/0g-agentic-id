package servicehost

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"seal-verify/internal/privsep"
)

type Status struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	Path        string `json:"path"`
	Description string `json:"description,omitempty"`
	State       string `json:"state"`
	Desired     bool   `json:"desired"`
	Error       string `json:"error,omitempty"`
	UID         uint32 `json:"uid"`
}

type entry struct {
	Manifest Manifest `json:"manifest"`
	Status
	cmd        *exec.Cmd
	done       chan struct{}
	cancel     context.CancelFunc
	generation uint64
}

type Manager struct {
	mu       sync.Mutex
	base     string
	programs string
	binding  string
	entries  map[string]*entry
	closed   bool
}

// New binds durable service state to this container's owner and identity.
// A reset with another binding cannot resume programs from the old owner.
// base must be a sealed-owned directory, never a path supplied by a tool.
func New(base, binding string) (*Manager, error) {
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
	m := &Manager{base: base, binding: binding, entries: map[string]*entry{}}
	// Source releases are public owner-authored code; work/run remain private to each service UID.
	programID := sha256.Sum256([]byte(base))
	m.programs = fmt.Sprintf("/var/lib/sealed-service-programs/%x", programID[:8])
	if err := privsep.MkdirAll(m.programs, 0755); err != nil {
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
			if err != nil || v != e.Version || e.ID != e.Manifest.ID || e.UID < 200000 || e.UID >= 200000+MaxServices {
				return nil, fmt.Errorf("invalid saved service")
			}
			for _, prior := range m.entries {
				if prior.UID == e.UID {
					return nil, fmt.Errorf("duplicate service uid")
				}
			}
			if m.entries[e.ID] != nil {
				return nil, fmt.Errorf("duplicate saved service")
			}
			e.Path = "/api/mcp/" + e.ID
			e.State = "stopped"
			e.Error = ""
			m.entries[e.ID] = e
		}
	}
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
	uid := uint32(200000)
	if old == nil {
		if len(m.entries) >= MaxServices {
			return Status{}, fmt.Errorf("service limit reached")
		}
		used := map[uint32]bool{}
		for _, e := range m.entries {
			used[e.UID] = true
		}
		for used[uid] {
			uid++
		}
	} else {
		uid = old.UID
	}
	base := filepath.Join(m.programs, man.ID)
	if err := privsep.MkdirAll(filepath.Join(m.base, man.ID), 0700); err != nil {
		return Status{}, err
	}
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
	for _, d := range []string{"work", "run"} {
		p := filepath.Join(base, d)
		if err := privsep.MkdirAll(p, 0700); err != nil {
			return Status{}, err
		}
		if err := os.Chown(p, int(uid), int(uid)); err != nil {
			return Status{}, err
		}
	}
	e := &entry{Manifest: man, Status: Status{ID: man.ID, Version: v, Path: "/api/mcp/" + man.ID, Description: man.Description, State: "stopped", UID: uid}}
	m.entries[man.ID] = e
	if err := m.persistLocked(); err != nil {
		if old == nil {
			delete(m.entries, man.ID)
		} else {
			m.entries[man.ID] = old
		}
		return Status{}, err
	}
	// Bound retained source releases. Only root writes this directory; work
	// is a separate service-owned directory and is never pruned here.
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

// Start persists the desired state before creating a process. Status remains
// starting until its private Unix socket accepts HTTP; no loopback port is
// registered or entrusted to an arbitrary process.
func (m *Manager) Start(id string) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return Status{}, fmt.Errorf("service manager closed")
	}
	e := m.entries[id]
	if e == nil {
		return Status{}, fmt.Errorf("unknown service")
	}
	if e.Desired {
		return e.Status, nil
	}
	e.Desired = true
	e.Error = ""
	if err := m.persistLocked(); err != nil {
		e.Desired = false
		return Status{}, err
	}
	if err := m.spawnLocked(e); err != nil {
		e.State = "failed"
		e.Error = err.Error()
		return e.Status, err
	}
	return e.Status, nil
}

func (m *Manager) socket(id string) string {
	return filepath.Join(m.programs, id, "run", "service.sock")
}

func (m *Manager) spawnLocked(e *entry) error {
	ctx, cancel := context.WithCancel(context.Background())
	cmd, err := m.command(ctx, e)
	if err != nil {
		cancel()
		return err
	}
	if err := privsep.Remove(m.socket(e.ID)); err != nil && !os.IsNotExist(err) {
		cancel()
		return err
	}
	cmd.Stdout = &logTail{path: filepath.Join(m.base, e.ID, "log")}
	cmd.Stderr = cmd.Stdout
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		cancel()
		return err
	}
	e.generation++
	gen := e.generation
	e.cmd = cmd
	e.cancel = cancel
	e.done = make(chan struct{})
	e.State = "starting"
	go m.supervise(e, gen, cmd, e.done)
	return nil
}

func (m *Manager) command(ctx context.Context, e *entry) (*exec.Cmd, error) {
	bwrap, err := privsep.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("isolation unavailable: %w", err)
	}
	interpreter, err := privsep.LookPath(e.Manifest.Command)
	if err != nil {
		return nil, err
	}
	launcher, err := privsep.LookPath("sealed-service-launcher")
	if err != nil {
		return nil, err
	}
	base := filepath.Join(m.programs, e.ID)
	args := []string{fmt.Sprintf("--as=%d", int64(e.Manifest.MemoryMB)<<20), fmt.Sprintf("--nproc=%d", e.Manifest.Processes), "--nofile=256", "--fsize=67108864", "--", launcher, fmt.Sprint(e.UID), bwrap,
		"--die-with-parent", "--new-session", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try",
		"--unshare-user",
		"--cap-drop", "ALL", "--uid", fmt.Sprint(e.UID), "--gid", fmt.Sprint(e.UID),
		"--clearenv", "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin", "--setenv", "HOME", "/work", "--setenv", "TMPDIR", "/tmp", "--setenv", "MCP_SOCKET", "/run/service.sock",
		"--ro-bind", "/usr", "/usr", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/etc", "--dir", "/run",
		"--ro-bind", filepath.Join(base, "versions", e.Version), "/app", "--bind", filepath.Join(base, "work"), "/work", "--bind", filepath.Join(base, "run"), "/run", "--chdir", "/app"}
	if e.Manifest.Network == "none" {
		args = append(args, "--unshare-net")
	}
	for _, p := range []string{"/bin", "/sbin", "/lib", "/lib64"} {
		if _, err := privsep.Lstat(p); err == nil {
			args = append(args, "--ro-bind", p, p)
		}
	}
	for _, p := range []string{"/etc/resolv.conf", "/etc/hosts", "/etc/ssl/certs"} {
		if _, err := privsep.Lstat(p); err == nil {
			args = append(args, "--ro-bind", p, p)
		}
	}
	keys := make([]string, 0, len(e.Manifest.Env))
	for k := range e.Manifest.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "--setenv", k, e.Manifest.Env[k])
	}
	args = append(args, "--", interpreter)
	args = append(args, e.Manifest.Args...)
	// Only the trusted image's resource limiter and sandbox launcher execute
	// as root. bwrap drops all capabilities before the service interpreter.
	cmd, err := privsep.RootCommand(ctx, "prlimit", args...)
	if err != nil {
		return nil, err
	}
	return cmd, nil
}

func (m *Manager) supervise(e *entry, gen uint64, cmd *exec.Cmd, done chan struct{}) {
	readyDone := make(chan struct{})
	go func() {
		defer close(readyDone)
		deadline := time.NewTimer(15 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-deadline.C:
				_ = cmd.Process.Kill()
				return
			case <-tick.C:
			}
			conn, err := net.DialTimeout("unix", m.socket(e.ID), 50*time.Millisecond)
			if err != nil {
				continue
			}
			conn.Close()
			m.mu.Lock()
			if e.generation == gen && e.Desired {
				e.State = "running"
			}
			m.mu.Unlock()
			return
		}
	}()
	err := cmd.Wait()
	close(done)
	<-readyDone
	m.mu.Lock()
	if e.generation != gen {
		m.mu.Unlock()
		return
	}
	e.cmd = nil
	e.cancel = nil
	e.State = "stopped"
	if err != nil {
		e.Error = err.Error()
	}
	restart := e.Desired && !m.closed
	if restart {
		e.State = "restarting"
	}
	m.mu.Unlock()
	if !restart {
		return
	}
	// A fixed bounded rate prevents a crash loop from consuming CPU. Stop
	// changes Desired/generation, so this cannot resurrect a stopped service.
	time.Sleep(2 * time.Second)
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.generation != gen || !e.Desired || m.closed {
		return
	}
	if err := m.spawnLocked(e); err != nil {
		e.State = "failed"
		e.Error = err.Error()
	}
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
	e.generation++
	cancel, done := e.cancel, e.done
	e.cancel = nil
	e.cmd = nil
	e.State = "stopped"
	if cancel != nil {
		cancel()
	}
	out := e.Status
	m.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			return out, fmt.Errorf("service stop timed out")
		}
	}
	return out, nil
}

// Resume is called only after chain bootstrap has confirmed the identity and
// owner binding. Published versions and desired states survive a reboot.
func (m *Manager) Resume() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.Desired {
			if err := m.spawnLocked(e); err != nil {
				e.State = "failed"
				e.Error = err.Error()
			}
		}
	}
}

// Close stops every sandbox without changing persisted desired states. A
// transfer permanently closes this manager; a normal reboot may resume it.
func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	var waits []chan struct{}
	for _, e := range m.entries {
		e.generation++
		if e.cancel != nil {
			e.cancel()
		}
		if e.done != nil {
			waits = append(waits, e.done)
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
	b, err := privsep.ReadTail(filepath.Join(m.base, id, "log"), 64<<10)
	if os.IsNotExist(err) {
		return "", nil
	}
	return string(b), err
}

// Match returns only a ready managed endpoint, never a user-provided port.
func (m *Manager) Match(path string) (Status, string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.Path == path {
			return e.Status, m.socket(e.ID), true
		}
	}
	return Status{}, "", false
}

// Client talks to one service's private Unix socket. Service sessions and
// headers pass through unchanged; HTTP proxy environment variables are ignored.
func Client(socket string) *http.Client {
	return &http.Client{Transport: &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}, DisableCompression: true, ResponseHeaderTimeout: 30 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type logTail struct {
	mu   sync.Mutex
	path string
	buf  []byte
}

func (l *logTail) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, p...)
	if len(l.buf) > 64<<10 {
		l.buf = append([]byte(nil), l.buf[len(l.buf)-(64<<10):]...)
	}
	err := privsep.WriteFile(l.path, l.buf, 0600)
	return len(p), err
}

var _ io.Writer = (*logTail)(nil)
