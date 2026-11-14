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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"seal-verify/internal/inferproxy"
	"seal-verify/internal/logger"
	"seal-verify/internal/privsep"
	"seal-verify/internal/servicesandbox"
)

const MaxExecutionInput = 512 << 10
const MaxExecutionOutput = 1 << 20
const MaxExecutionChunk = 64 << 10
const MaxExecutionRecords = 1024
const MaxRetainedExecutionOutput = 32 << 20
const executionRetention = 10 * time.Minute

// maxExecutionRecordBytes bounds one saved execution record. The largest one
// (32 egress hosts of maxHostLength, a signed receipt carrying them again)
// fits with room to spare (TestLargestExecutionRecordFits).
const maxExecutionRecordBytes = 64 << 10

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
// have a separate kernel or that their business output is correct. Driver
// "landlock-v1" is servicesandbox: one identity per process tree, Landlock
// (filesystem allowlist, no /proc, TCP refused, abstract sockets and signals
// scoped to the domain) and a seccomp filter allowing only AF_UNIX sockets.
// Memory and disk are watched by sealed, which kills the identity over its
// limit; processes are bounded by RLIMIT_NPROC on the identity.
type IsolationProfile struct {
	Driver               string                 `json:"driver"`
	WorkerRuntimeHash    string                 `json:"worker_runtime_hash,omitempty"`
	LandlockABI          int                    `json:"landlock_abi"`
	FilesystemAllowlist  bool                   `json:"filesystem_allowlist"`
	ProcHidden           bool                   `json:"proc_hidden"`
	SignalScoped         bool                   `json:"signal_scoped"`
	AbstractSocketScoped bool                   `json:"abstract_socket_scoped"`
	DirectNetwork        bool                   `json:"direct_network"`
	ReadOnlyCode         bool                   `json:"readonly_code"`
	TemporaryWork        bool                   `json:"temporary_work"`
	OwnerInterfaces      bool                   `json:"owner_interfaces"`
	Network              string                 `json:"network"`
	EgressHosts          []string               `json:"egress_hosts,omitempty"`
	VirtualMemoryMB      int                    `json:"virtual_memory_mb"`
	ResidentMemoryMB     int                    `json:"resident_memory_mb"`
	Processes            int                    `json:"processes"`
	TimeoutSeconds       int                    `json:"timeout_seconds"`
	InferenceBudget      *inferproxy.TaskLimits `json:"inference_budget,omitempty"`
}

var (
	abiOnce  sync.Once
	abiValue int
)

func landlockABI() int {
	abiOnce.Do(func() { abiValue, _ = servicesandbox.ABI() })
	return abiValue
}

// landlockProfile is the receipt's description of what servicesandbox enforced.
func landlockProfile(man Manifest) IsolationProfile {
	p := IsolationProfile{Driver: "landlock-v1", LandlockABI: landlockABI(), FilesystemAllowlist: true, ProcHidden: true, SignalScoped: true,
		AbstractSocketScoped: true, DirectNetwork: false, ReadOnlyCode: true, TemporaryWork: true, OwnerInterfaces: false,
		Network: man.Network, EgressHosts: append([]string(nil), man.EgressHosts...), VirtualMemoryMB: man.MemoryMB,
		ResidentMemoryMB: man.ResidentMemoryMB, Processes: man.Processes, TimeoutSeconds: man.RequestTimeoutSeconds}
	if man.InferenceBudget != nil {
		budget := *man.InferenceBudget
		p.InferenceBudget = &budget
	}
	return p
}

type ExecutionAttestor func(ExecutionStatus, IsolationProfile) (string, error)

type execution struct {
	ExecutionStatus
	Isolation IsolationProfile
	output    []byte
	done      chan struct{}
	ctx       context.Context
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

func (m *Manager) executionRecordPath(handle string) string {
	return filepath.Join(m.base, "executions", handle+".json")
}

func (m *Manager) executionRecordLocked(e *execution) ([]byte, error) {
	return json.Marshal(executionRecord{m.binding, e.ExecutionStatus, e.Isolation})
}

// persistExecutionLocked records a status change. It is not synced: losing it
// to a crash leaves the synced reservation, which restores as interrupted and
// never runs again (reserveDurably).
func (m *Manager) persistExecutionLocked(e *execution) error {
	b, err := m.executionRecordLocked(e)
	if err != nil {
		return err
	}
	return privsep.WriteFile(m.executionRecordPath(e.Handle), b, 0600)
}

// reserveDurably syncs a new reservation record before anything can run under
// its key, without the manager lock (fsync can take seconds on a busy disk).
// A crash before it completes leaves no record, and nothing has run.
func (m *Manager) reserveDurably(handle string, record []byte) error {
	return syncRecord(m.executionRecordPath(handle), record, 0600)
}

// syncRecord is privsep.WriteFileSync, replaceable in tests.
var syncRecord = privsep.WriteFileSync

// restoreExecutions loads the records a previous sealed left. A file that
// cannot be a record (a temporary file a crash left between write and rename,
// a corrupt, oversized or foreign record) never disables hosting: temporary
// files are removed, anything else is set aside as .bad-<name> and logged, and
// its key is not restored.
func (m *Manager) restoreExecutions() error {
	dir := filepath.Join(m.base, "executions")
	if err := privsep.MkdirAll(dir, 0700); err != nil {
		return err
	}
	files, err := privsep.ReadDir(dir)
	if err != nil {
		return err
	}
	setAside := func(name, why string) {
		logger.Logf("service execution record %s set aside: %s", name, why)
		if err := privsep.Rename(filepath.Join(dir, name), filepath.Join(dir, ".bad-"+name)); err != nil {
			_ = privsep.Remove(filepath.Join(dir, name))
		}
	}
	for _, f := range files {
		name := f.Name()
		if strings.HasPrefix(name, ".") {
			if strings.Contains(name, ".sealed-tmp-") {
				_ = privsep.Remove(filepath.Join(dir, name))
			}
			continue // set aside earlier
		}
		handle := strings.TrimSuffix(name, ".json")
		if name != handle+".json" || !validExecutionHandle.MatchString(handle) || !f.Type().IsRegular() {
			setAside(name, "not an execution record")
			continue
		}
		if len(m.executions) >= MaxExecutionRecords {
			setAside(name, "too many execution records")
			continue
		}
		b, err := privsep.ReadFile(filepath.Join(dir, name), maxExecutionRecordBytes)
		if err != nil {
			setAside(name, err.Error())
			continue
		}
		var r executionRecord
		if err := json.Unmarshal(b, &r); err != nil || r.Binding != m.binding || r.Handle != handle || !validID.MatchString(r.Service) || !validExecutionKey.MatchString(r.Key) {
			setAside(name, "invalid or foreign record")
			continue
		}
		k := executionKey(r.Service, r.Key)
		if m.executionKeys[k] != "" {
			setAside(name, "duplicate execution key")
			continue
		}
		e := &execution{ExecutionStatus: r.ExecutionStatus, Isolation: r.Isolation, done: make(chan struct{})}
		if e.FinishedAt == 0 {
			e.State, e.Reason, e.FinishedAt = "interrupted", "sealed_restarted", time.Now().UnixMilli()
			_ = m.persistExecutionLocked(e)
		}
		close(e.done)
		m.executions[handle], m.executionKeys[k] = e, handle
	}
	m.pruneExecutionsLocked()
	return nil
}

// keyAcceptedUntil is the last moment reserveExecution would accept key: a key
// is accepted from 30 s before its issue time until executionRetention after it.
func keyAcceptedUntil(key string) int64 {
	issued, _ := strconv.ParseInt(strings.SplitN(key, "-", 2)[0], 10, 64)
	return issued + executionRetention.Milliseconds()
}

// pruneExecutionsLocked deletes a finished record executionRetention after it
// finished, but never while its key could still be accepted: the record is the
// key's tombstone, and without it a retry of the key would run again.
func (m *Manager) pruneExecutionsLocked() {
	now := time.Now().UnixMilli()
	cutoff := now - executionRetention.Milliseconds()
	for h, e := range m.executions {
		if e.FinishedAt == 0 || e.FinishedAt >= cutoff || keyAcceptedUntil(e.Key) >= now {
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
	return m.spawnExecution(service, key, input, func() ([]byte, error) { return runtimeInput, nil }, nil)
}

func (m *Manager) spawnExecution(service, key string, input []byte, privateInput func() ([]byte, error), consumeInput func()) (ExecutionStatus, error) {
	if !validExecutionKey.MatchString(key) || len(input) > MaxExecutionInput {
		return ExecutionStatus{}, fmt.Errorf("invalid execution input or key")
	}
	input = bytes.Clone(input)
	digest := sha256.Sum256(input)
	inputHash := hex.EncodeToString(digest[:])
	e, job, runtimeInput, record, status, err := m.reserveExecution(service, key, inputHash, privateInput, consumeInput)
	if e == nil {
		return status, err
	}
	ctx, cancel := e.ctx, e.cancel
	if err := m.reserveDurably(e.Handle, record); err != nil {
		// Nothing ran. The in-memory record stays the key's tombstone, so a
		// retry of the key sees start_failed (never ran) rather than running.
		m.mu.Lock()
		cancel()
		e.State, e.Reason, e.FinishedAt = "failed", "start_failed", time.Now().UnixMilli()
		_ = m.persistExecutionLocked(e)
		delete(m.workers, e.UID)
		close(e.done)
		m.mu.Unlock()
		return e.ExecutionStatus, fmt.Errorf("reserve execution: %w", err)
	}
	// The slow part runs without the manager lock, so /hello and other
	// services' requests never wait on a probe, a chain read or a process
	// start. Stop cancels ctx, which fails the start below.
	lease, err := m.prepareLaunch(ctx)
	var dir string
	var cmd *isolatedCommand
	if err == nil {
		dir, cmd, err = m.prepareExecution(ctx, job, e.UID, input, runtimeInput, lease)
	}
	if err == nil {
		cmd.onCleanupFailure = func() {
			m.mu.Lock()
			e.failure, e.State, e.Reason = "resource_cleanup_failed", "quarantined", "resource_cleanup_failed"
			_ = m.persistExecutionLocked(e)
			m.mu.Unlock()
		}
		cmd.onLimit = func(reason string) {
			m.mu.Lock()
			if e.failure == "" {
				e.failure = reason
			}
			m.mu.Unlock()
		}
		cmd.Stdout, cmd.Stderr = &executionOutput{manager: m, execution: e}, io.Discard
		cmd.WaitDelay = 250 * time.Millisecond
		err = cmd.Start()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		cancel()
		if dir != "" {
			_ = discardDir(dir) // under the manager lock: never a slow removal
		}
		e.State, e.Reason, e.FinishedAt = "failed", "start_failed", time.Now().UnixMilli()
		_ = m.persistExecutionLocked(e)
		m.finishFailedExecutionStart(e, cmd)
		return e.ExecutionStatus, fmt.Errorf("start isolated execution: %w", err)
	}
	e.Isolation.WorkerRuntimeHash = cmd.runtimeHash
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

// reserveExecution validates and reserves an execution under the manager lock,
// in memory: a duplicate spawn of the key from then on returns this execution.
// It returns the record the caller must sync (reserveDurably) before starting
// anything. It returns a nil execution with the status or error to report when
// nothing is to be started (a duplicate key returns the original).
func (m *Manager) reserveExecution(service, key, inputHash string, privateInput func() ([]byte, error), consumeInput func()) (*execution, *entry, []byte, []byte, ExecutionStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExecutionsLocked()
	entry := m.entries[service]
	if m.closed || entry == nil || !entry.Desired || entry.Manifest.Worker == nil {
		return nil, nil, nil, nil, ExecutionStatus{}, fmt.Errorf("service execution unavailable")
	}
	k := executionKey(service, key)
	if h := m.executionKeys[k]; h != "" {
		e := m.executions[h]
		if e.InputHash != inputHash || e.Version != entry.Version {
			return nil, nil, nil, nil, ExecutionStatus{}, ErrExecutionConflict
		}
		return nil, nil, nil, nil, e.ExecutionStatus, nil
	}
	issued, _ := strconv.ParseInt(strings.SplitN(key, "-", 2)[0], 10, 64)
	if issued < time.Now().Add(-executionRetention).UnixMilli() || issued > time.Now().Add(30*time.Second).UnixMilli() {
		return nil, nil, nil, nil, ExecutionStatus{}, fmt.Errorf("execution key expired or issued in the future")
	}
	if len(m.executions) >= MaxExecutionRecords {
		return nil, nil, nil, nil, ExecutionStatus{}, fmt.Errorf("execution record limit reached; acknowledge completed output")
	}
	if len(m.workers) >= MaxWorkers {
		return nil, nil, nil, nil, ExecutionStatus{}, fmt.Errorf("worker limit reached")
	}
	if m.processesInUseLocked()+entry.Manifest.Processes > MaxServiceProcesses {
		return nil, nil, nil, nil, ExecutionStatus{}, ErrProcessBudget
	}
	uid, err := m.allocateIdentityLocked()
	if err != nil {
		return nil, nil, nil, nil, ExecutionStatus{}, err
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, nil, nil, nil, ExecutionStatus{}, err
	}
	runtimeInput, err := privateInput()
	if err != nil {
		return nil, nil, nil, nil, ExecutionStatus{}, err
	}
	if len(runtimeInput) == 0 {
		runtimeInput = []byte("{}")
	}
	var fields map[string]string
	if len(runtimeInput) > MaxRuntimeInput || json.Unmarshal(runtimeInput, &fields) != nil || fields == nil {
		return nil, nil, nil, nil, ExecutionStatus{}, fmt.Errorf("runtime input must be a bounded JSON string map")
	}
	now := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(entry.Manifest.RequestTimeoutSeconds)*time.Second)
	e := &execution{ExecutionStatus: ExecutionStatus{
		Handle: hex.EncodeToString(token[:]), Service: service, Key: key, Version: entry.Version,
		InputHash: inputHash, State: "starting", StartedAt: now.UnixMilli(), Deadline: now.Add(time.Duration(entry.Manifest.RequestTimeoutSeconds) * time.Second).UnixMilli(), UID: uid,
	}, done: make(chan struct{}), ctx: ctx, cancel: cancel}
	e.Isolation = landlockProfile(entry.Manifest)
	// The caller syncs this record before spawning. If sealed crashes in the
	// start window, the next boot reports interrupted and never silently
	// re-executes input; with no record yet, nothing has run.
	record, err := m.executionRecordLocked(e)
	if err != nil {
		cancel()
		return nil, nil, nil, nil, ExecutionStatus{}, err
	}
	if consumeInput != nil {
		consumeInput()
	}
	m.executions[e.Handle], m.executionKeys[k] = e, e.Handle
	m.workers[uid] = &worker{service: service, cancel: cancel, done: e.done, processes: entry.Manifest.Processes}
	job := *entry
	return e, &job, runtimeInput, record, ExecutionStatus{}, nil
}

// Called with m.mu held after Start failed. The identity remains reserved
// while cleanup cannot prove it has no process left, even though exec failed.
// The reason stays start_failed: the worker never ran, whatever the cleanup.
func (m *Manager) finishFailedExecutionStart(e *execution, cmd *isolatedCommand) {
	if cmd != nil && !cmd.resourcesReleased() {
		e.State = "quarantined"
		go func() {
			<-cmd.cleanupDone
			m.mu.Lock()
			delete(m.workers, e.UID)
			e.State = "failed"
			_ = m.persistExecutionLocked(e)
			close(e.done)
			m.mu.Unlock()
		}()
		return
	}
	delete(m.workers, e.UID)
	close(e.done)
}

// prepareExecution owns lease: command takes it over, and it is released here
// if preparation fails first.
func (m *Manager) prepareExecution(ctx context.Context, source *entry, uid uint32, input, runtimeInput []byte, lease RuntimeLease) (string, *isolatedCommand, error) {
	dir, err := os.MkdirTemp(filepath.Join(m.programs, taskDirName), "e-")
	if err != nil {
		lease.Release()
		return "", nil, err
	}
	if err = privsep.Chmod(dir, 0755); err == nil {
		err = privateDir(filepath.Join(dir, "run"), uid)
	}
	if err != nil {
		lease.Release()
		return dir, nil, err
	}
	job := *source
	job.Manifest.Command, job.Manifest.Args = source.Manifest.Worker.Command, source.Manifest.Worker.Args
	cmd, err := m.command(ctx, &job, uid, dir, executionCommand, lease)
	if err != nil {
		return dir, nil, err
	}
	// Framing keeps private input distinct from public task input on the one
	// stdin pipe: the launcher passes the worker no other descriptor.
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

func (m *Manager) waitExecution(ctx context.Context, e *execution, cmd *isolatedCommand, dir string) {
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

// SetReceiptCapability is trusted runtime wiring beside the attestor: ready
// reports, without signing, whether the attestor can sign a receipt now.
func (m *Manager) SetReceiptCapability(ready func() bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.receiptsReady = ready
}

// ReceiptsAvailable reports whether an execution that exits 0 now would
// receive a signed receipt. A paid coordinator asks before charging.
func (m *Manager) ReceiptsAvailable() bool {
	m.mu.Lock()
	attest, ready := m.attestor, m.receiptsReady
	m.mu.Unlock()
	return attest != nil && ready != nil && ready()
}

// launchProbeTimeout bounds LaunchAvailable.
const launchProbeTimeout = 5 * time.Second

// LaunchAvailable reports whether sealed's own preparation for a service
// process succeeds now: the confinement probe (cached), free space, and the
// verified runtime's listing and pin, whose lease it releases at once. It runs
// without the manager lock. A paid coordinator asks before charging.
func (m *Manager) LaunchAvailable() bool {
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), launchProbeTimeout)
	defer cancel()
	lease, err := m.prepareLaunch(ctx)
	if err != nil {
		return false
	}
	if lease.Release != nil {
		lease.Release()
	}
	return true
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
