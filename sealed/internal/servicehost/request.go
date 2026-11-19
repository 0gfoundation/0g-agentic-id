package servicehost

// Request workers are an execution primitive, not a credential store. Runtime
// input exists only in the caller's request and an anonymous stdin pipe to the
// selected sandbox. There is no reveal tool, writeback, restart or key registry.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"seal-verify/internal/privsep"
)

// This is an optional HTTP extension, not an MCP protocol field. HTTPS callers
// opt in to sharing the values with the published task program (including its
// tools), never the resident owner harness. Standard MCP requests still work.
const RuntimeInputHeader = "X-Seal-Runtime-Input"
const ServiceVersionHeader = "X-Seal-Service-Version"
const MaxRuntimeInput = 16 << 10
const MaxWorkers = 32
const taskDirName = ".tasks"            // cannot collide with a valid published service id
const runDirName = ".run"               // coordinator sockets; cannot collide with a service id either
const serviceNetDirName = ".servicenet" // network adapters (servicenet); no service id either

// MaxServiceProcesses bounds the processes and threads of all service
// processes together: each running request, execution and coordinator holds
// its manifest's processes limit (its RLIMIT_NPROC) against this budget.
const MaxServiceProcesses = 2048

// ErrProcessBudget refuses a service process the budget cannot hold.
var ErrProcessBudget = errors.New("service process budget reached; retry later")

// One-shot request workers serve anonymous POSTs to plain services. They may
// hold at most MaxRequestWorkers of the MaxWorkers slots and
// MaxRequestProcesses of the process budget, so executions a coordinator
// spawns (paid jobs among them) always have room.
const (
	MaxRequestWorkers   = MaxWorkers / 2
	MaxRequestProcesses = MaxServiceProcesses / 2
)

type worker struct {
	service   string
	cancel    context.CancelFunc
	done      chan struct{}
	processes int
	request   bool // a one-shot request worker
}

// requestWorkersLocked counts the running one-shot request workers and the
// processes they hold.
func (m *Manager) requestWorkersLocked() (n, processes int) {
	for _, w := range m.workers {
		if w.request {
			n, processes = n+1, processes+w.processes
		}
	}
	return n, processes
}

// serviceHasWorkersLocked reports whether any request or execution worker of
// the service is still running or being cleaned up.
func (m *Manager) serviceHasWorkersLocked(id string) bool {
	for _, w := range m.workers {
		if w.service == id {
			return true
		}
	}
	return false
}

// processesInUseLocked sums the processes limits of every running request,
// execution and coordinator (including ones still being cleaned up).
func (m *Manager) processesInUseLocked() int {
	n := 0
	for _, w := range m.workers {
		n += w.processes
	}
	for _, e := range m.entries {
		if e.controller != nil {
			n += e.Manifest.Processes
		}
	}
	return n
}

type taskTransport struct {
	manager *Manager
	id      string
}

// HTTPClient selects a fresh isolated process for every managed MCP POST.
func (m *Manager) HTTPClient(id string) *http.Client {
	return &http.Client{Transport: &taskTransport{m, id}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func response(req *http.Request, code int, message string) *http.Response {
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(message)), Request: req}
}

// Private input is consent to one audited immutable release, never whichever
// code happens to be current by the time a request reaches this container.
func checkPrivateInputVersion(req *http.Request, version string) (int, string) {
	versions := req.Header.Values(ServiceVersionHeader)
	if len(versions) == 0 && len(req.Header.Values(RuntimeInputHeader)) == 0 {
		return 0, ""
	}
	if len(versions) != 1 || !runtimeDigest.MatchString(versions[0]) {
		return http.StatusBadRequest, "runtime input requires one X-Seal-Service-Version release hash"
	}
	if versions[0] != version {
		return http.StatusConflict, "service release changed; audit the current release before sending runtime input"
	}
	return 0, ""
}

func (t *taskTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m := t.manager
	m.mu.Lock()
	e := m.entries[t.id]
	if e == nil || !e.Desired || m.closed {
		m.mu.Unlock()
		return response(req, 503, "service unavailable"), nil
	}
	man, status := e.Manifest, e.Status
	m.mu.Unlock()
	if code, message := checkPrivateInputVersion(req, status.Version); code != 0 {
		return response(req, code, message), nil
	}
	if man.Worker != nil {
		return t.coordinatorRoundTrip(req)
	}
	if req.Method != http.MethodPost {
		r := response(req, 405, "stateless request services accept POST only")
		r.Header.Set("Allow", "POST")
		return r, nil
	}
	if req.Header.Get("Mcp-Session-Id") != "" {
		return response(req, 400, "request services do not resume MCP sessions"), nil
	}
	values := req.Header.Values(RuntimeInputHeader)
	var input []byte
	if len(values) > 0 {
		if len(values) != 1 || len(values[0]) > base64.StdEncoding.EncodedLen(MaxRuntimeInput) {
			return response(req, 400, "invalid runtime input"), nil
		}
		var err error
		input, err = base64.StdEncoding.Strict().DecodeString(values[0])
		var fields map[string]string
		if err != nil || len(input) > MaxRuntimeInput || json.Unmarshal(input, &fields) != nil || fields == nil {
			return response(req, 400, "runtime input must encode a JSON string map"), nil
		}
	} else {
		input = []byte("{}")
	}
	// Do not forward this header into the MCP server's HTTP handling or logs.
	req = req.Clone(req.Context())
	req.Header.Del(RuntimeInputHeader)
	req.Header.Del(ServiceVersionHeader)
	req.Header.Del(InputHandleHeader)
	ctx, cancel := context.WithTimeout(req.Context(), time.Duration(man.RequestTimeoutSeconds)*time.Second)
	w := &worker{service: t.id, cancel: cancel, done: make(chan struct{}), processes: man.Processes, request: true}
	m.mu.Lock()
	// Recheck after parsing; Stop must not race admission and miss this worker.
	e = m.entries[t.id]
	if m.closed || e == nil || !e.Desired || e.Version != status.Version {
		m.mu.Unlock()
		cancel()
		return response(req, 503, "service unavailable"), nil
	}
	if len(m.workers) >= MaxWorkers {
		m.mu.Unlock()
		cancel()
		return response(req, 503, "request worker limit reached"), nil
	}
	if m.processesInUseLocked()+man.Processes > MaxServiceProcesses {
		m.mu.Unlock()
		cancel()
		return response(req, 503, ErrProcessBudget.Error()), nil
	}
	if n, procs := m.requestWorkersLocked(); n >= MaxRequestWorkers || procs+man.Processes > MaxRequestProcesses {
		m.mu.Unlock()
		cancel()
		return response(req, 503, "request worker limit reached"), nil
	}
	uid, err := m.allocateIdentityLocked()
	if err != nil {
		m.mu.Unlock()
		cancel()
		return response(req, 503, "request worker limit reached"), nil
	}
	m.workers[uid] = w
	m.mu.Unlock()
	var dir string
	var exited chan struct{}
	var command *isolatedCommand
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			cancel()
			if exited != nil {
				<-exited
			} else if command != nil {
				command.beginCleanup()
				<-command.cleanupDone
			}
			if dir != "" {
				_ = privsep.RemoveAll(dir)
			}
			m.mu.Lock()
			delete(m.workers, uid)
			close(w.done)
			m.mu.Unlock()
		})
	}
	ok := false
	defer func() {
		if !ok {
			cleanup()
		}
	}()
	dir, err = os.MkdirTemp(filepath.Join(m.programs, taskDirName), "t-")
	if err != nil {
		return nil, fmt.Errorf("prepare request sandbox")
	}
	// Only root can replace the task directory; the worker owns its run inode.
	if err = privsep.Chmod(dir, 0755); err != nil {
		return nil, fmt.Errorf("prepare request sandbox")
	}
	run := filepath.Join(dir, "run")
	if err = privateDir(run, uid); err != nil {
		return nil, fmt.Errorf("prepare request sandbox")
	}
	lease, err := m.prepareLaunch(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare request interpreter: %w", err)
	}
	job := &entry{Manifest: man, Status: status}
	cmd, err := m.command(ctx, job, uid, dir, requestCommand, lease)
	if err != nil {
		return nil, fmt.Errorf("prepare request interpreter")
	}
	command = cmd
	// os/exec creates an anonymous pipe; values never appear in argv, the
	// published manifest, environment of a launcher, or a filesystem file.
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.WaitDelay = 250 * time.Millisecond
	if err = cmd.Start(); err != nil {
		return nil, fmt.Errorf("start request sandbox")
	}
	exited = make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	socket := filepath.Join(run, "service.sock")
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	ready := false
	for !ready {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("request cancelled or timed out")
		case <-exited:
			return nil, fmt.Errorf("request sandbox exited before readiness")
		case <-timer.C:
			return nil, fmt.Errorf("request sandbox readiness timed out")
		case <-tick.C:
			conn, err := net.DialTimeout("unix", socket, 20*time.Millisecond)
			if err == nil {
				conn.Close()
				ready = true
			}
		}
	}
	client := Client(socket)
	transport := client.Transport.(*http.Transport)
	transport.ResponseHeaderTimeout = 0 // the request context owns the whole deadline
	resp, err := transport.RoundTrip(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("request sandbox exchange failed")
	}
	resp.Body = &taskBody{ReadCloser: resp.Body, cleanup: cleanup}
	// Deadline/Stop must release the worker even if a caller never closes an
	// already-returned body. EOF also releases it before the public response is
	// signed or written to a potentially slow client.
	go func() { <-ctx.Done(); cleanup() }()
	ok = true
	return resp, nil
}

type taskBody struct {
	io.ReadCloser
	cleanup func()
}

func (b *taskBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.cleanup()
	}
	return n, err
}

func (b *taskBody) Close() error { err := b.ReadCloser.Close(); b.cleanup(); return err }
