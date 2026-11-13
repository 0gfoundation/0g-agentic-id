package servicehost

// Detached execution is a process primitive, not a business task or payment
// ledger. Only bounded process metadata survives restart. Input and output are
// never written to this registry; the service owns its durable business state.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"seal-verify/internal/privsep"
)

const MaxExecutionInput = 512 << 10
const MaxExecutionOutput = 1 << 20
const MaxExecutionChunk = 64 << 10
const MaxExecutionRecords = 1024
const MaxRetainedExecutionOutput = 32 << 20
const executionRetention = 10 * time.Minute

// A dated nonce allows bounded deduplication without ever rerunning an old
// key after its tombstone is collected. SDKs generate <unix-ms>-<random>.
var validExecutionKey = regexp.MustCompile(`^[0-9]{13}-[a-zA-Z0-9_-]{16,48}$`)
var validExecutionHandle = regexp.MustCompile(`^[0-9a-f]{64}$`)

var ErrExecutionNotFound = errors.New("execution not found")
var ErrExecutionConflict = errors.New("execution key already used for different input or code")

// ExecutionStatus contains process facts only. It does not identify an employer
// or describe business progress, payment, result entitlement or task success.
type ExecutionStatus struct {
	Handle          string `json:"handle"`
	Service         string `json:"service"`
	Key             string `json:"key"`
	Version         string `json:"version"`
	InputHash       string `json:"input_hash"`
	State           string `json:"state"`
	StartedAt       int64  `json:"started_at"`
	Deadline        int64  `json:"deadline"`
	FinishedAt      int64  `json:"finished_at,omitempty"`
	ExitCode        *int   `json:"exit_code,omitempty"`
	Reason          string `json:"reason,omitempty"`
	OutputBytes     int    `json:"output_bytes"`
	OutputHash      string `json:"output_hash,omitempty"`
	OutputAvailable bool   `json:"output_available"`
	UID             uint32 `json:"uid"`
	Receipt         string `json:"receipt,omitempty"`
}

// IsolationProfile describes enforced mechanisms, not a claim that programs
// have a separate kernel or that their business output is correct.
type IsolationProfile struct {
	Driver            string   `json:"driver"`
	WorkerRuntimeHash string   `json:"worker_runtime_hash,omitempty"`
	PrivatePID        bool     `json:"private_pid"`
	PrivateMounts     bool     `json:"private_mounts"`
	PrivateNetwork    bool     `json:"private_network"`
	ReadOnlyCode      bool     `json:"readonly_code"`
	TemporaryWork     bool     `json:"temporary_work"`
	OwnerInterfaces   bool     `json:"owner_interfaces"`
	Network           string   `json:"network"`
	EgressHosts       []string `json:"egress_hosts,omitempty"`
	VirtualMemoryMB   int      `json:"virtual_memory_mb"`
	Processes         int      `json:"processes"`
	TimeoutSeconds    int      `json:"timeout_seconds"`
}

type ExecutionAttestor func(ExecutionStatus, IsolationProfile) (string, error)

type execution struct {
	ExecutionStatus
	Isolation IsolationProfile
	output    []byte
	done      chan struct{}
	cancel    context.CancelFunc
	limit     bool
	failure   string
}

type executionRecord struct {
	Binding string `json:"binding"`
	ExecutionStatus
	Isolation IsolationProfile `json:"isolation"`
}

func executionKey(service, key string) string { return service + ":" + key }

func (m *Manager) persistExecutionLocked(e *execution) error {
	b, err := json.Marshal(executionRecord{m.binding, e.ExecutionStatus, e.Isolation})
	if err != nil {
		return err
	}
	return privsep.WriteFile(filepath.Join(m.base, "executions", e.Handle+".json"), b, 0600)
}

func (m *Manager) restoreExecutions() error {
	dir := filepath.Join(m.base, "executions")
	if err := privsep.MkdirAll(dir, 0700); err != nil {
		return err
	}
	files, err := privsep.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(files) > MaxExecutionRecords {
		return fmt.Errorf("too many execution records")
	}
	for _, f := range files {
		handle := strings.TrimSuffix(f.Name(), ".json")
		if f.Name() != handle+".json" || !validExecutionHandle.MatchString(handle) || !f.Type().IsRegular() {
			return fmt.Errorf("invalid execution record")
		}
		b, err := privsep.ReadFile(filepath.Join(dir, f.Name()), 16<<10)
		if err != nil {
			return err
		}
		var r executionRecord
		if err := json.Unmarshal(b, &r); err != nil || r.Binding != m.binding || r.Handle != handle || !validID.MatchString(r.Service) || !validExecutionKey.MatchString(r.Key) {
			return fmt.Errorf("invalid or foreign execution record")
		}
		e := &execution{ExecutionStatus: r.ExecutionStatus, Isolation: r.Isolation, done: make(chan struct{})}
		if e.FinishedAt == 0 {
			e.State, e.Reason, e.FinishedAt = "interrupted", "sealed_restarted", time.Now().UnixMilli()
			if err := m.persistExecutionLocked(e); err != nil {
				return err
			}
		}
		close(e.done)
		k := executionKey(e.Service, e.Key)
		if m.executionKeys[k] != "" {
			return fmt.Errorf("duplicate execution key")
		}
		m.executions[handle], m.executionKeys[k] = e, handle
	}
	m.pruneExecutionsLocked()
	return nil
}

func (m *Manager) pruneExecutionsLocked() {
	cutoff := time.Now().Add(-executionRetention).UnixMilli()
	for h, e := range m.executions {
		if e.FinishedAt == 0 || e.FinishedAt >= cutoff {
			continue
		}
		if err := privsep.Remove(filepath.Join(m.base, "executions", h+".json")); err != nil && !os.IsNotExist(err) {
			continue
		}
		m.outputBytes -= len(e.output)
		delete(m.executionKeys, executionKey(e.Service, e.Key))
		delete(m.executions, h)
	}
}

func (m *Manager) collectExecutions() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-m.stopGC:
			return
		case <-tick.C:
			m.mu.Lock()
			m.pruneExecutionsLocked()
			m.mu.Unlock()
		}
	}
}

// SpawnExecution returns after the isolated interpreter starts. Its lifetime
// belongs to Manager, never to the submitting HTTP request. key is scoped to the
// authorized service and prevents concurrent/retried submission from rerunning
// code. Opaque public input and private runtime input share a bounded framed
// stdin stream; neither goes through the resident owner Harness or the disk.
func (m *Manager) SpawnExecution(service, key string, input, runtimeInput []byte) (ExecutionStatus, error) {
	runtimeInput = bytes.Clone(runtimeInput)
	return m.spawnExecution(service, key, input, func() ([]byte, error) { return runtimeInput, nil })
}

func (m *Manager) spawnExecution(service, key string, input []byte, privateInput func() ([]byte, error)) (ExecutionStatus, error) {
	if !validExecutionKey.MatchString(key) || len(input) > MaxExecutionInput {
		return ExecutionStatus{}, fmt.Errorf("invalid execution input or key")
	}
	input = bytes.Clone(input)
	digest := sha256.Sum256(input)
	inputHash := hex.EncodeToString(digest[:])
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExecutionsLocked()
	entry := m.entries[service]
	if m.closed || entry == nil || !entry.Desired || entry.Manifest.Worker == nil {
		return ExecutionStatus{}, fmt.Errorf("service execution unavailable")
	}
	k := executionKey(service, key)
	if h := m.executionKeys[k]; h != "" {
		e := m.executions[h]
		if e.InputHash != inputHash || e.Version != entry.Version {
			return ExecutionStatus{}, ErrExecutionConflict
		}
		return e.ExecutionStatus, nil
	}
	issued, _ := strconv.ParseInt(strings.SplitN(key, "-", 2)[0], 10, 64)
	if issued < time.Now().Add(-executionRetention).UnixMilli() || issued > time.Now().Add(30*time.Second).UnixMilli() {
		return ExecutionStatus{}, fmt.Errorf("execution key expired or issued in the future")
	}
	if len(m.executions) >= MaxExecutionRecords {
		return ExecutionStatus{}, fmt.Errorf("execution record limit reached; acknowledge completed output")
	}
	uid := uint32(210000)
	for m.workers[uid] != nil && uid < 210000+MaxWorkers {
		uid++
	}
	if uid == 210000+MaxWorkers {
		return ExecutionStatus{}, fmt.Errorf("worker limit reached")
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return ExecutionStatus{}, err
	}
	runtimeInput, err := privateInput()
	if err != nil {
		return ExecutionStatus{}, err
	}
	if len(runtimeInput) == 0 {
		runtimeInput = []byte("{}")
	}
	var fields map[string]string
	if len(runtimeInput) > MaxRuntimeInput || json.Unmarshal(runtimeInput, &fields) != nil || fields == nil {
		return ExecutionStatus{}, fmt.Errorf("runtime input must be a bounded JSON string map")
	}
	now := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(entry.Manifest.RequestTimeoutSeconds)*time.Second)
	e := &execution{ExecutionStatus: ExecutionStatus{
		Handle: hex.EncodeToString(token[:]), Service: service, Key: key, Version: entry.Version,
		InputHash: inputHash, State: "starting", StartedAt: now.UnixMilli(), Deadline: now.Add(time.Duration(entry.Manifest.RequestTimeoutSeconds) * time.Second).UnixMilli(), UID: uid,
	}, done: make(chan struct{}), cancel: cancel}
	e.Isolation = IsolationProfile{Driver: "bubblewrap-v1", PrivatePID: true, PrivateMounts: true, PrivateNetwork: true, ReadOnlyCode: true, TemporaryWork: true, OwnerInterfaces: false,
		WorkerRuntimeHash: m.runtimeHash,
		Network:           entry.Manifest.Network, EgressHosts: append([]string(nil), entry.Manifest.EgressHosts...), VirtualMemoryMB: entry.Manifest.MemoryMB, Processes: entry.Manifest.Processes, TimeoutSeconds: entry.Manifest.RequestTimeoutSeconds}
	// Reserve durably before spawning. If sealed crashes in the start window,
	// the next boot reports interrupted and never silently re-executes input.
	if err := m.persistExecutionLocked(e); err != nil {
		cancel()
		return ExecutionStatus{}, err
	}
	m.executions[e.Handle], m.executionKeys[k] = e, e.Handle
	w := &worker{service: service, cancel: cancel, done: e.done}
	m.workers[uid] = w
	dir, cmd, err := m.prepareExecution(ctx, entry, uid, input, runtimeInput)
	if err == nil {
		cmd.Stdout, cmd.Stderr = &executionOutput{manager: m, execution: e}, io.Discard
		cmd.WaitDelay = 250 * time.Millisecond
		err = cmd.Start()
	}
	if err != nil {
		cancel()
		if dir != "" {
			_ = privsep.RemoveAll(dir)
		}
		delete(m.workers, uid)
		e.State, e.Reason, e.FinishedAt = "failed", "start_failed", time.Now().UnixMilli()
		_ = m.persistExecutionLocked(e)
		close(e.done)
		return e.ExecutionStatus, fmt.Errorf("start isolated execution")
	}
	e.State = "running"
	if err := m.persistExecutionLocked(e); err != nil {
		e.failure = "metadata_write_failed"
		cancel()
		go m.waitExecution(ctx, e, cmd, dir)
		return e.ExecutionStatus, fmt.Errorf("persist execution state")
	}
	go m.waitExecution(ctx, e, cmd, dir)
	return e.ExecutionStatus, nil
}

func (m *Manager) prepareExecution(ctx context.Context, source *entry, uid uint32, input, runtimeInput []byte) (string, *exec.Cmd, error) {
	dir, err := os.MkdirTemp(filepath.Join(m.programs, taskDirName), "e-")
	if err != nil {
		return "", nil, err
	}
	if err = privsep.Chmod(dir, 0755); err != nil {
		return dir, nil, err
	}
	run := filepath.Join(dir, "run")
	if err = privsep.MkdirAll(run, 0700); err != nil {
		return dir, nil, err
	}
	if err = os.Chown(run, int(uid), int(uid)); err != nil {
		return dir, nil, err
	}
	job := *source
	job.Manifest.Command, job.Manifest.Args = source.Manifest.Worker.Command, source.Manifest.Worker.Args
	cmd, err := m.command(ctx, &job, uid, dir, false)
	if err != nil {
		return dir, nil, err
	}
	// Framing keeps private input distinct from public task input without
	// depending on inherited descriptors that the sandbox correctly closes.
	header := make([]byte, 16)
	copy(header, "SEALRUN1")
	binary.BigEndian.PutUint32(header[8:12], uint32(len(runtimeInput)))
	binary.BigEndian.PutUint32(header[12:16], uint32(len(input)))
	cmd.Stdin = io.MultiReader(bytes.NewReader(header), bytes.NewReader(runtimeInput), bytes.NewReader(input))
	return dir, cmd, nil
}

type executionOutput struct {
	manager   *Manager
	execution *execution
}

func (o *executionOutput) Write(p []byte) (int, error) {
	m, e := o.manager, o.execution
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(e.output)+len(p) > MaxExecutionOutput || m.outputBytes+len(p) > MaxRetainedExecutionOutput {
		e.limit = true
		e.cancel()
		return 0, fmt.Errorf("execution output limit exceeded")
	}
	e.output = append(e.output, p...)
	m.outputBytes += len(p)
	e.OutputBytes = len(e.output)
	return len(p), nil
}

func (m *Manager) waitExecution(ctx context.Context, e *execution, cmd *exec.Cmd, dir string) {
	err := cmd.Wait()
	cause := ctx.Err()
	e.cancel()
	cleanupErr := privsep.RemoveAll(dir)
	m.mu.Lock()
	defer m.mu.Unlock()
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	e.ExitCode, e.FinishedAt = &code, time.Now().UnixMilli()
	e.State = "exited"
	switch {
	case e.failure != "":
		e.State, e.Reason = "failed", e.failure
	case e.limit:
		e.State, e.Reason = "failed", "output_limit"
	case errors.Is(cause, context.DeadlineExceeded):
		e.State, e.Reason = "timed_out", "deadline"
	case cause != nil:
		e.State, e.Reason = "cancelled", "terminated"
	case err != nil:
		e.State, e.Reason = "failed", "process_exit"
	}
	if cleanupErr != nil {
		e.State, e.Reason = "failed", "cleanup_failed"
	}
	hash := sha256.Sum256(e.output)
	e.OutputHash = hex.EncodeToString(hash[:])
	m.attestExecutionLocked(e)
	if err := m.persistExecutionLocked(e); err != nil {
		e.State, e.Reason = "failed", "metadata_write_failed"
	}
	delete(m.workers, e.UID)
	close(e.done)
}

// Execution only resolves a handle inside its authorized service. Output is
// opaque, bounded and transient. A service must copy it into its own result
// store before acknowledging or before the execution retention expires.
func (m *Manager) Execution(service, handle string, offset int) (ExecutionStatus, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.executions[handle]
	if e == nil || e.Service != service {
		return ExecutionStatus{}, nil, ErrExecutionNotFound
	}
	if offset < 0 || offset > len(e.output) {
		return ExecutionStatus{}, nil, fmt.Errorf("invalid output offset")
	}
	m.attestExecutionLocked(e)
	status := e.ExecutionStatus
	status.OutputAvailable = len(e.output) == e.OutputBytes
	end := min(len(e.output), offset+MaxExecutionChunk)
	return status, bytes.Clone(e.output[offset:end]), nil
}

// The attestor is trusted runtime wiring. No API accepts a caller-supplied
// profile, digest or arbitrary signing preimage.
func (m *Manager) SetExecutionAttestor(attest ExecutionAttestor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attestor = attest
}

func (m *Manager) attestExecutionLocked(e *execution) {
	if m.attestor == nil || e.Receipt != "" || e.State != "exited" || e.ExitCode == nil || *e.ExitCode != 0 || e.FinishedAt == 0 {
		return
	}
	if receipt, err := m.attestor(e.ExecutionStatus, e.Isolation); err == nil {
		e.Receipt = receipt
	}
}

func (m *Manager) WaitExecution(ctx context.Context, service, handle string) (ExecutionStatus, error) {
	m.mu.Lock()
	e := m.executions[handle]
	if e == nil || e.Service != service {
		m.mu.Unlock()
		return ExecutionStatus{}, ErrExecutionNotFound
	}
	done := e.done
	m.mu.Unlock()
	select {
	case <-ctx.Done():
		return ExecutionStatus{}, ctx.Err()
	case <-done:
		status, _, err := m.Execution(service, handle, 0)
		return status, err
	}
}

func (m *Manager) TerminateExecution(service, handle string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.executions[handle]
	if e == nil || e.Service != service {
		return ErrExecutionNotFound
	}
	if e.FinishedAt == 0 && e.cancel != nil {
		e.cancel()
	}
	return nil
}

// FindExecution resolves a lost start acknowledgement without creating a new
// process or asking the caller to supply runtime credentials again.
func (m *Manager) FindExecution(service, key string) (ExecutionStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.executionKeys[executionKey(service, key)]
	e := m.executions[h]
	if e == nil || e.Service != service {
		return ExecutionStatus{}, ErrExecutionNotFound
	}
	m.attestExecutionLocked(e)
	return e.ExecutionStatus, nil
}

// ReleaseExecution only drops captured output after the service has stored
// it. Keep the metadata/key tombstone so a retried start cannot run twice.
func (m *Manager) ReleaseExecution(service, handle string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.executions[handle]
	if e == nil || e.Service != service {
		return ErrExecutionNotFound
	}
	if e.FinishedAt == 0 {
		return fmt.Errorf("execution still running")
	}
	m.outputBytes -= len(e.output)
	e.output = nil
	return nil
}

var _ io.Writer = (*executionOutput)(nil)
