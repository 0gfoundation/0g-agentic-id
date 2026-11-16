package proxy

// Agent interfaces that outlive a restart.
//
// An agent interface is a backend the agent runs itself, inside its own
// sandbox, which sealed fronts and signs (services.go). Its registration
// lives in sealed, so sealed keeps it: the registered list is written to
// sealed's root-only state directory, bound to the owner and the agent's seal,
// and restored when sealed starts again (container stop/start, a sealed
// upgrade). A saved entry that no longer passes registration is dropped on
// its own; the others are restored.
//
// A registration can name a start command; sealed then runs that backend
// itself, as the agent user, and starts it again whenever it exits. One
// backend address has one start command, however many paths it serves. The
// backend runs in a process group of its own, which sealed kills when the
// entry is removed or changed and when sealed stops, so a server the command
// forks is stopped with it; a server that leaves the group (setsid, a daemon
// manager) is out of sealed's reach. Its output and how it last ended are
// kept for the agent (GET /services). Without a start command the agent keeps
// its backend running, and after a restart the path answers 502 until it
// does.
//
// Nothing here survives a reset (a new sandbox) or a transfer (the container
// closes), as for hosted programs: a backend that must outlive those keeps
// its code in the agent's tracked data and registers again.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"seal-verify/internal/logger"
	"seal-verify/internal/privsep"
)

// ServiceStart is how sealed runs an agent interface's backend: a system
// command by name or a program by absolute path, in a directory below the
// agent's home.
type ServiceStart struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Dir     string   `json:"dir,omitempty"` // absolute, below the agent's home; default the home
}

const (
	maxStartCommand   = 256
	maxStartArgs      = 32
	maxStartArg       = 1024
	backendOutputTail = 4096 // bytes of a backend's output kept for the agent
)

// validateStart refuses a start command sealed could not run, so the agent
// learns it at registration: a name must be a system command (the PATH
// sealed runs the agent's commands with), anything else an absolute path.
func validateStart(s *ServiceStart) error {
	if s == nil {
		return nil
	}
	if s.Command == "" || len(s.Command) > maxStartCommand || strings.ContainsRune(s.Command, 0) {
		return fmt.Errorf("start.command must be 1..%d bytes", maxStartCommand)
	}
	if strings.ContainsRune(s.Command, '/') {
		if !filepath.IsAbs(s.Command) || filepath.Clean(s.Command) != s.Command {
			return fmt.Errorf("start.command %q: a path must be absolute and clean", s.Command)
		}
	} else if _, err := privsep.LookPath(s.Command); err != nil {
		return fmt.Errorf("start.command %q is not a system command; for a program of your own give its absolute path", s.Command)
	}
	if len(s.Args) > maxStartArgs {
		return fmt.Errorf("start.args holds at most %d arguments", maxStartArgs)
	}
	for _, a := range s.Args {
		if len(a) > maxStartArg || strings.ContainsRune(a, 0) {
			return fmt.Errorf("start.args: an argument is over %d bytes or holds NUL", maxStartArg)
		}
	}
	if s.Dir != "" && !privsep.BelowAgentHome(s.Dir) {
		return fmt.Errorf("start.dir must be an absolute, clean path below %s", privsep.AgentHome())
	}
	return nil
}

// backendAddr names a backend by its loopback port: entries on one port share
// one backend, whether they write localhost or 127.0.0.1.
func backendAddr(backend string) string {
	u, err := url.Parse(backend)
	if err != nil {
		return backend
	}
	return "127.0.0.1:" + u.Port()
}

func startKey(s *ServiceStart) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// checkSharedStarts refuses two start commands for one backend.
func checkSharedStarts(entries []ServiceEntry) error {
	starts := map[string]*ServiceStart{}
	for i, e := range entries {
		if e.Start == nil {
			continue
		}
		addr := backendAddr(e.Backend)
		if prev, ok := starts[addr]; ok && startKey(prev) != startKey(e.Start) {
			return fmt.Errorf("services[%d].start differs from another entry's on backend %s: one backend has one start command", i, addr)
		}
		starts[addr] = e.Start
	}
	return nil
}

// AgentServiceRuntime is what sealed needs to keep the agent's interfaces:
// where to write them, whose they are, and the environment a backend it
// starts gets on top of PATH and HOME (main.go: the credential proxy's
// settings and the agent's public facts, not the framework's own variables).
type AgentServiceRuntime struct {
	StateFile string
	Binding   string // "<owner>:<sealID>"; a file written for another binding is dropped
	Env       []string
}

// agentServiceFile is the registered list as sealed writes it.
type agentServiceFile struct {
	V        int            `json:"v"`
	Binding  string         `json:"binding"`
	Services []ServiceEntry `json:"services"`
}

type agentServiceKeeper struct {
	post sync.Mutex // one registration at a time (handleServices)
	mu   sync.Mutex
	rt   *AgentServiceRuntime
	sups map[string]*backendSupervisor // by backend address
}

// RestoreAgentServices hands the server what it needs to keep the agent's
// interfaces and brings back the ones registered before this start, starting
// the backends that name a start command. Call it once the owner and the
// agent's seal are confirmed, before the framework starts.
func (s *Server) RestoreAgentServices(rt AgentServiceRuntime) {
	s.keeper.mu.Lock()
	s.keeper.rt = &rt
	s.keeper.mu.Unlock()
	b, err := privsep.ReadFile(rt.StateFile, privsep.LimitConfig)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Logf("services: cannot read the agent's interfaces (%v); starting with none", err)
		}
		return
	}
	var saved agentServiceFile
	if err := json.Unmarshal(b, &saved); err != nil || saved.V != 1 {
		logger.Logf("services: the saved agent interfaces are unreadable; starting with none")
		_ = privsep.Remove(rt.StateFile)
		return
	}
	if saved.Binding != rt.Binding {
		logger.Logf("services: the saved agent interfaces belong to another owner or agent; dropped")
		_ = privsep.Remove(rt.StateFile)
		return
	}
	entries := s.restorable(saved.Services)
	if len(entries) < len(saved.Services) {
		if err := writeAgentServices(&rt, entries); err != nil {
			logger.Logf("services: cannot rewrite the agent's interfaces: %v", err)
		}
	}
	s.mu.Lock()
	s.services = entries
	s.mu.Unlock()
	s.syncBackends(entries)
	logger.Logf("services: restored %d agent interface(s)", len(entries))
}

// restorable is the saved list as this runtime accepts it: an entry that no
// longer passes registration (a rule an upgrade tightened) is dropped, and
// the rest kept.
func (s *Server) restorable(saved []ServiceEntry) []ServiceEntry {
	limits := s.serviceLimits()
	if entries, err := validateServices(saved, limits); err == nil {
		return entries
	}
	var kept []ServiceEntry
	for _, e := range saved {
		if _, err := validateServices(append(append([]ServiceEntry(nil), kept...), e), limits); err != nil {
			logger.Logf("services: the saved agent interface %s no longer passes registration (%v); dropped", e.Path, err)
			continue
		}
		kept = append(kept, e)
	}
	entries, _ := validateServices(kept, limits)
	return entries
}

func writeAgentServices(rt *AgentServiceRuntime, entries []ServiceEntry) error {
	b, err := json.Marshal(agentServiceFile{V: 1, Binding: rt.Binding, Services: entries})
	if err != nil {
		return err
	}
	return privsep.WriteFileSync(rt.StateFile, b, 0600)
}

// keepAgentServices brings the backends in line with the registered list and
// writes it. Before RestoreAgentServices nothing is kept.
func (s *Server) keepAgentServices(entries []ServiceEntry) error {
	s.keeper.mu.Lock()
	rt := s.keeper.rt
	s.keeper.mu.Unlock()
	if rt == nil {
		return nil
	}
	s.syncBackends(entries)
	return writeAgentServices(rt, entries)
}

// syncBackends stops the supervisors of backends that are gone or whose start
// command changed and starts one for every backend with a start command that
// has none.
func (s *Server) syncBackends(entries []ServiceEntry) {
	k := &s.keeper
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.rt == nil {
		return
	}
	if k.sups == nil {
		k.sups = map[string]*backendSupervisor{}
	}
	type wanted struct {
		entry ServiceEntry // the first entry on the backend
		paths []string
	}
	want := map[string]*wanted{}
	for _, e := range entries {
		if e.Start == nil {
			continue
		}
		addr := backendAddr(e.Backend)
		if w, ok := want[addr]; ok {
			w.paths = append(w.paths, e.Path)
			continue
		}
		want[addr] = &wanted{entry: e, paths: []string{e.Path}}
	}
	for addr, sup := range k.sups {
		if w, ok := want[addr]; !ok || startKey(w.entry.Start) != sup.key {
			sup.stop()
			delete(k.sups, addr)
		}
	}
	for addr, w := range want {
		if sup, ok := k.sups[addr]; ok {
			sup.status.setPaths(w.paths)
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		sup := &backendSupervisor{
			key:    startKey(w.entry.Start),
			cancel: cancel,
			done:   make(chan struct{}),
			status: &backendStatus{addr: addr, paths: w.paths},
			pipes:  map[*os.File]bool{},
		}
		k.sups[addr] = sup
		go sup.run(ctx, w.entry, append([]string(nil), k.rt.Env...))
	}
}

// StopAgentServices stops every backend sealed started (shutdown).
func (s *Server) StopAgentServices() {
	k := &s.keeper
	k.mu.Lock()
	defer k.mu.Unlock()
	for addr, sup := range k.sups {
		sup.stop()
		delete(k.sups, addr)
	}
}

// BackendStatus is how a backend sealed runs for the agent is doing.
type BackendStatus struct {
	Backend  string   `json:"backend"`
	Paths    []string `json:"paths"`
	State    string   `json:"state"` // running | answering | restarting
	Starts   int      `json:"starts"`
	LastExit string   `json:"last_exit,omitempty"`
	Output   string   `json:"output,omitempty"` // the last bytes it wrote to stdout and stderr
}

const (
	backendRunning    = "running"    // the process sealed started is running
	backendAnswering  = "answering"  // something answers on the address, so sealed starts nothing
	backendRestarting = "restarting" // the process ended; sealed starts it again shortly
)

// backendStatuses lists the backends sealed runs, for GET /services.
func (s *Server) backendStatuses() []BackendStatus {
	k := &s.keeper
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]BackendStatus, 0, len(k.sups))
	for _, sup := range k.sups {
		out = append(out, sup.status.snapshot())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Backend < out[j].Backend })
	return out
}

type backendStatus struct {
	mu       sync.Mutex
	addr     string
	paths    []string
	state    string
	starts   int
	lastExit string
	out      []byte // the last backendOutputTail bytes written
}

// Write keeps the tail of the backend's output.
func (b *backendStatus) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.out = append(b.out, p...)
	if over := len(b.out) - backendOutputTail; over > 0 {
		b.out = append(b.out[:0], b.out[over:]...)
	}
	return len(p), nil
}

func (b *backendStatus) setPaths(paths []string) {
	b.mu.Lock()
	b.paths = paths
	b.mu.Unlock()
}

func (b *backendStatus) setState(state string) {
	b.mu.Lock()
	b.state = state
	b.mu.Unlock()
}

func (b *backendStatus) started() {
	b.mu.Lock()
	b.state = backendRunning
	b.starts++
	b.mu.Unlock()
}

func (b *backendStatus) ended(err error) {
	b.mu.Lock()
	b.state = backendRestarting
	b.lastExit = "exit status 0"
	if err != nil {
		b.lastExit = err.Error()
	}
	b.mu.Unlock()
}

func (b *backendStatus) snapshot() BackendStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	return BackendStatus{
		Backend: b.addr, Paths: append([]string(nil), b.paths...), State: b.state,
		Starts: b.starts, LastExit: b.lastExit, Output: strings.ToValidUTF8(string(b.out), "�"),
	}
}

// backendSupervisor keeps one backend's start command running until stopped.
type backendSupervisor struct {
	key    string // the start command; a change means a new supervisor
	cancel context.CancelFunc
	done   chan struct{}
	status *backendStatus

	mu    sync.Mutex
	pgid  int               // the process group of the last start while anything is left in it
	pipes map[*os.File]bool // read ends of the output pipes still open
}

func (sup *backendSupervisor) stop() {
	sup.cancel()
	<-sup.done
}

// Supervision pace (variables for tests).
var (
	backendCheckEvery = 10 * time.Second
	backendFirstDelay = 2 * time.Second
	backendMaxDelay   = time.Minute
)

// run keeps one backend running: while something answers on its address (the
// agent's own process, or one sealed started) it waits; otherwise it ends
// what is left of the last start, starts the command as the agent and waits
// for it to exit, backing off from 2 s to a minute while it keeps failing
// within a minute.
func (sup *backendSupervisor) run(ctx context.Context, e ServiceEntry, env []string) {
	defer close(sup.done)
	defer sup.endGroup(true)
	u, err := url.Parse(e.Backend)
	if err != nil {
		return
	}
	delay := backendFirstDelay
	for {
		if backendAnswers(u.Host) {
			sup.status.setState(backendAnswering)
			if !sleepCtx(ctx, backendCheckEvery) {
				return
			}
			sup.forgetEndedGroup()
			continue
		}
		sup.endGroup(false)
		sup.status.started()
		started := time.Now()
		err := sup.runOnce(ctx, e.Start, env)
		if ctx.Err() != nil {
			return
		}
		sup.forgetEndedGroup()
		sup.status.ended(err)
		if time.Since(started) > backendMaxDelay {
			delay = backendFirstDelay
		}
		logger.Logf("services: backend %s ended (%v); starting it again in %s if nothing answers", sup.status.addr, err, delay)
		if !sleepCtx(ctx, delay) {
			return
		}
		if delay *= 2; delay > backendMaxDelay {
			delay = backendMaxDelay
		}
	}
}

// runOnce runs the start command as the agent, in its own process group, with
// its output kept in the status, and returns when the command exits. A
// server it forked runs on in the group, which endGroup kills.
func (sup *backendSupervisor) runOnce(ctx context.Context, st *ServiceStart, env []string) error {
	cmd, err := privsep.AgentBackground(ctx, st.Dir, env, st.Command, st.Args...)
	if err != nil {
		return err
	}
	// A pipe sealed reads itself, not one exec copies: Wait then returns when
	// the command exits, even while a server it forked holds the pipe open.
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = w, w
	err = cmd.Start()
	w.Close()
	if err != nil {
		r.Close()
		return err
	}
	sup.mu.Lock()
	sup.pgid = cmd.Process.Pid
	sup.pipes[r] = true
	sup.mu.Unlock()
	go func() {
		_, _ = io.Copy(sup.status, r)
		sup.mu.Lock()
		delete(sup.pipes, r)
		sup.mu.Unlock()
		r.Close()
	}()
	return cmd.Wait()
}

// endGroup kills what is left of the last start: its process group, whose
// leader may have exited while a server it forked runs on. final also
// closes the output pipes, which a process that left the group may hold.
func (sup *backendSupervisor) endGroup(final bool) {
	sup.mu.Lock()
	defer sup.mu.Unlock()
	if sup.pgid != 0 {
		_ = unix.Kill(-sup.pgid, unix.SIGKILL)
		sup.pgid = 0
	}
	if final {
		for r := range sup.pipes {
			r.Close()
			delete(sup.pipes, r)
		}
	}
}

// forgetEndedGroup drops the last start's process group once nothing is left
// in it, so a later kill cannot reach another group that reuses the number.
func (sup *backendSupervisor) forgetEndedGroup() {
	sup.mu.Lock()
	defer sup.mu.Unlock()
	if sup.pgid != 0 && unix.Kill(-sup.pgid, 0) == unix.ESRCH {
		sup.pgid = 0
	}
}

func backendAnswers(hostport string) bool {
	c, err := net.DialTimeout("tcp", hostport, 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
