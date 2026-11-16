package proxy

// Agent interfaces that outlive a restart.
//
// An agent interface is a backend the agent runs itself, inside its own
// sandbox, which sealed fronts and signs (services.go). Its registration
// lives in sealed, so sealed keeps it: the registered list is written to
// sealed's root-only state directory, bound to the owner and the agent's seal,
// and restored when sealed starts again (container stop/start, a sealed
// upgrade). A registration can name a start command; sealed then runs that
// backend itself, as the agent user with the agent's environment, and starts
// it again whenever it exits. Without one the agent keeps its backend
// running, and after a restart the path answers 502 until it does.
//
// Nothing here survives a reset (a new sandbox) or a transfer (the container
// closes), as for hosted programs: a backend that must outlive those keeps
// its code in the agent's tracked data and registers again.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"seal-verify/internal/logger"
	"seal-verify/internal/privsep"
)

// ServiceStart is how sealed runs an agent interface's backend: a command,
// resolved as the agent resolves it, in a directory below the agent's home.
type ServiceStart struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Dir     string   `json:"dir,omitempty"` // absolute, below the agent's home; default the home
}

const (
	maxStartCommand = 256
	maxStartArgs    = 32
	maxStartArg     = 1024
)

func validateStart(s *ServiceStart) error {
	if s == nil {
		return nil
	}
	if s.Command == "" || len(s.Command) > maxStartCommand || strings.ContainsRune(s.Command, 0) {
		return fmt.Errorf("start.command must be 1..%d bytes", maxStartCommand)
	}
	if len(s.Args) > maxStartArgs {
		return fmt.Errorf("start.args holds at most %d arguments", maxStartArgs)
	}
	for _, a := range s.Args {
		if len(a) > maxStartArg || strings.ContainsRune(a, 0) {
			return fmt.Errorf("start.args: an argument is over %d bytes or holds NUL", maxStartArg)
		}
	}
	if s.Dir != "" {
		home := privsep.AgentHome()
		if !filepath.IsAbs(s.Dir) || filepath.Clean(s.Dir) != s.Dir || (s.Dir != home && !strings.HasPrefix(s.Dir, home+"/")) {
			return fmt.Errorf("start.dir must be an absolute, clean path below %s", home)
		}
	}
	return nil
}

// AgentServiceRuntime is what sealed needs to keep the agent's interfaces:
// where to write them, whose they are, and the environment a backend it
// starts gets (on top of the agent's PATH and HOME).
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

// backendSupervisor runs one interface's backend until stopped.
type backendSupervisor struct {
	key    string // the entry's backend and start command; a change means a new supervisor
	cancel context.CancelFunc
	done   chan struct{}
}

type agentServiceKeeper struct {
	post sync.Mutex // one registration at a time (handleServices)
	mu   sync.Mutex
	rt   *AgentServiceRuntime
	sups map[string]*backendSupervisor // by path
}

func supervisorKey(e ServiceEntry) string {
	b, _ := json.Marshal(struct {
		Backend string
		Start   *ServiceStart
	}{e.Backend, e.Start})
	return string(b)
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
	entries, err := validateServices(saved.Services, s.serviceLimits())
	if err != nil {
		logger.Logf("services: the saved agent interfaces no longer pass registration (%v); dropped", err)
		_ = privsep.Remove(rt.StateFile)
		return
	}
	s.mu.Lock()
	s.services = entries
	s.mu.Unlock()
	s.syncBackends(entries)
	logger.Logf("services: restored %d agent interface(s)", len(entries))
}

// keepAgentServices writes the registered list and brings the backends in
// line with it. Before RestoreAgentServices nothing is kept.
func (s *Server) keepAgentServices(entries []ServiceEntry) error {
	s.keeper.mu.Lock()
	rt := s.keeper.rt
	s.keeper.mu.Unlock()
	if rt == nil {
		return nil
	}
	b, err := json.Marshal(agentServiceFile{V: 1, Binding: rt.Binding, Services: entries})
	if err != nil {
		return err
	}
	if err := privsep.WriteFileSync(rt.StateFile, b, 0600); err != nil {
		return err
	}
	s.syncBackends(entries)
	return nil
}

// syncBackends stops the supervisors of entries that are gone or changed and
// starts one for every entry with a start command that has none.
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
	want := map[string]ServiceEntry{}
	for _, e := range entries {
		if e.Start != nil {
			want[e.Path] = e
		}
	}
	for path, sup := range k.sups {
		if e, ok := want[path]; !ok || supervisorKey(e) != sup.key {
			sup.cancel()
			<-sup.done
			delete(k.sups, path)
		}
	}
	for path, e := range want {
		if _, ok := k.sups[path]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		sup := &backendSupervisor{key: supervisorKey(e), cancel: cancel, done: make(chan struct{})}
		k.sups[path] = sup
		go func(e ServiceEntry, env []string) {
			defer close(sup.done)
			superviseBackend(ctx, e, env)
		}(e, append([]string(nil), k.rt.Env...))
	}
}

// StopAgentServices stops every backend sealed started (shutdown).
func (s *Server) StopAgentServices() {
	k := &s.keeper
	k.mu.Lock()
	defer k.mu.Unlock()
	for path, sup := range k.sups {
		sup.cancel()
		<-sup.done
		delete(k.sups, path)
	}
}

// Supervision pace (variables for tests).
var (
	backendCheckEvery = 10 * time.Second
	backendFirstDelay = 2 * time.Second
	backendMaxDelay   = time.Minute
)

// superviseBackend keeps one backend running: while something answers on
// its port (the agent's own process, or the one sealed started) it waits;
// otherwise it starts the command as the agent and waits for it to end,
// backing off from 2 s to a minute while it keeps failing within a minute.
func superviseBackend(ctx context.Context, e ServiceEntry, env []string) {
	u, err := url.Parse(e.Backend)
	if err != nil {
		return
	}
	delay := backendFirstDelay
	for {
		if backendAnswers(u.Host) {
			if !sleepCtx(ctx, backendCheckEvery) {
				return
			}
			continue
		}
		started := time.Now()
		err := runBackend(ctx, e.Start, env)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > backendMaxDelay {
			delay = backendFirstDelay
		}
		logger.Logf("services: backend of %s ended (%v); starting it again in %s", e.Path, err, delay)
		if !sleepCtx(ctx, delay) {
			return
		}
		if delay *= 2; delay > backendMaxDelay {
			delay = backendMaxDelay
		}
	}
}

// runBackend runs the start command as the agent, in its own process group so
// a stop ends everything it started, and returns when it exits.
func runBackend(ctx context.Context, st *ServiceStart, env []string) error {
	cmd, err := privsep.AgentBackground(ctx, st.Dir, env, st.Command, st.Args...)
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Wait()
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
