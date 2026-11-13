//go:build linux

// Package servicecgroup admits service processes only into a provider-delegated
// cgroup-v2 subtree inside the billed sandbox. It never creates that delegation,
// moves the supervisor, relaxes seccomp, or substitutes process RSS polling.
package servicecgroup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	MountPath      = "/sys/fs/cgroup"
	SupervisorName = "0g-supervisor"
	PoolName       = "0g-service-jobs"
)

var ErrUnsupported = errors.New("provider cgroup delegation unavailable")
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$`)

// Pool pins a root-owned delegated directory. Its aggregate limits also bound
// simultaneous coordinators and jobs; each Lease adds its own descendant limits.
type Pool struct {
	mu           sync.Mutex
	fd           int
	kernel       kernel
	memory       int64
	pids         int
	parentMemory int64
	parentPIDs   int
	leases       map[string]*Lease
}

// Lease owns one per-process-tree cgroup. ProcsFile is borrowed by the trusted
// launcher, which must write its own PID before dropping UID or running code.
type Lease struct {
	mu      sync.Mutex
	pool    *Pool
	name    string
	fd      int
	procs   *os.File
	memory  int64
	pids    int
	removed bool
}

// kernel is private: tests emulate kernel-created control files, but production
// New always checks the real cgroup2 filesystem and uses real cgroup operations.
type kernel struct {
	checkFS    func(int) error
	mkdir      func(int, string) error
	remove     func(int, string) error
	afterWrite func(int, string, string) error
}

func systemKernel() kernel {
	return kernel{
		checkFS: func(fd int) error {
			var st unix.Statfs_t
			if err := unix.Fstatfs(fd, &st); err != nil {
				return err
			}
			if st.Type != unix.CGROUP2_SUPER_MAGIC {
				return errors.New("not a cgroup-v2 filesystem")
			}
			return nil
		},
		mkdir:  func(fd int, name string) error { return unix.Mkdirat(fd, name, 0700) },
		remove: func(fd int, name string) error { return unix.Unlinkat(fd, name, unix.AT_REMOVEDIR) },
	}
}

// New recognizes exactly the provider's preconfigured sibling layout below the
// process's billed parent. Ordinary Docker cgroup mounts do not satisfy it.
func New() (*Pool, error) { return newAt(MountPath, "/proc/self/cgroup", systemKernel()) }

func unsupported(err error) error { return fmt.Errorf("%w: %v", ErrUnsupported, err) }
func newAt(mount, membership string, k kernel) (_ *Pool, retErr error) {
	data, err := os.ReadFile(membership)
	if err != nil {
		return nil, unsupported(err)
	}
	current, err := unifiedPath(string(data))
	if err != nil {
		return nil, unsupported(err)
	}
	root, err := unix.Open(mount, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, unsupported(err)
	}
	defer unix.Close(root)
	if err = checkDir(root, k); err != nil {
		return nil, unsupported(err)
	}
	parent, err := walk(root, path.Dir(current), k)
	if err != nil {
		return nil, unsupported(err)
	}
	defer unix.Close(parent)
	if err = requireText(parent, "cgroup.type", "domain", k); err != nil {
		return nil, unsupported(err)
	}
	parentMemory, err := readLimit(parent, "memory.max", k)
	if err != nil {
		return nil, unsupported(err)
	}
	parentPIDs, err := readLimit(parent, "pids.max", k)
	if err != nil || parentPIDs > int64(int(^uint(0)>>1)) {
		return nil, unsupported(fmt.Errorf("finite parent pids.max required: %v", err))
	}
	if err = requireControllers(parent, k); err != nil {
		return nil, unsupported(err)
	}
	supervisor, err := openDir(parent, SupervisorName, k)
	if err != nil {
		return nil, unsupported(err)
	}
	defer unix.Close(supervisor)
	procs, err := readControl(supervisor, "cgroup.procs", k)
	if err != nil {
		return nil, unsupported(err)
	}
	present := false
	for _, pid := range strings.Fields(procs) {
		if pid == strconv.Itoa(os.Getpid()) {
			present = true
		}
	}
	if !present {
		return nil, unsupported(errors.New("current PID is not in the claimed supervisor cgroup"))
	}
	poolfd, err := openDir(parent, PoolName, k)
	if err != nil {
		return nil, unsupported(err)
	}
	defer func() {
		if retErr != nil {
			unix.Close(poolfd)
		}
	}()
	if err = requireText(poolfd, "cgroup.type", "domain", k); err != nil {
		return nil, unsupported(err)
	}
	if err = requireText(poolfd, "cgroup.procs", "", k); err != nil {
		return nil, unsupported(errors.New("delegated pool must contain no direct processes"))
	}
	if err = requireControllers(poolfd, k); err != nil {
		return nil, unsupported(err)
	}
	memory, err := readLimit(poolfd, "memory.max", k)
	if err != nil {
		return nil, unsupported(err)
	}
	pids, err := readLimit(poolfd, "pids.max", k)
	if err != nil || pids > int64(int(^uint(0)>>1)) {
		return nil, unsupported(fmt.Errorf("finite pool pids.max required: %v", err))
	}
	if memory >= parentMemory || pids >= parentPIDs {
		return nil, unsupported(errors.New("pool memory.max and pids.max must leave bounded supervisor headroom below the billed parent"))
	}
	p := &Pool{fd: poolfd, kernel: k, memory: memory, pids: int(pids), parentMemory: parentMemory, parentPIDs: int(parentPIDs), leases: map[string]*Lease{}}
	// Read-back alone is insufficient: prove child creation, every controller
	// write, writable migration FD, subtree kill, empty observation and removal.
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, unsupported(err)
	}
	probeMemory := int64(16 << 20)
	if memory < probeMemory {
		probeMemory = memory
	}
	lease, err := p.Acquire("probe-"+hex.EncodeToString(nonce[:]), probeMemory, 1)
	if err != nil {
		return nil, unsupported(err)
	}
	cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = lease.KillAndRemove(cleanup); err != nil {
		return nil, unsupported(fmt.Errorf("controller probe cleanup: %w", err))
	}
	return p, nil
}

func unifiedPath(text string) (string, error) {
	var current string
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || fields[0] != "0" || fields[1] != "" || current != "" {
			return "", errors.New("one unified cgroup-v2 membership required")
		}
		current = fields[2]
	}
	if !strings.HasPrefix(current, "/") || path.Clean(current) != current || strings.ContainsAny(current, "\x00\\") || path.Base(current) != SupervisorName {
		return "", errors.New("current cgroup must be the fixed 0g-supervisor leaf")
	}
	return current, nil
}

func openBelow(fd int, name string, flags int) (int, error) {
	return unix.Openat2(fd, name, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
}
func checkDir(fd int, k kernel) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 {
		return errors.New("cgroup directory must be root-owned and not group/other writable")
	}
	return k.checkFS(fd)
}
func openDir(fd int, name string, k kernel) (int, error) {
	child, err := openBelow(fd, name, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return -1, err
	}
	if err = checkDir(child, k); err != nil {
		unix.Close(child)
		return -1, err
	}
	return child, nil
}
func walk(root int, p string, k kernel) (int, error) {
	fd, err := unix.FcntlInt(uintptr(root), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := openDir(fd, part, k)
		unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
	}
	return fd, nil
}
func openControl(fd int, name string, flags int, k kernel) (*os.File, error) {
	child, err := openBelow(fd, name, flags)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	err = unix.Fstat(child, &st)
	if err == nil && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0022 != 0) {
		err = errors.New("cgroup control must be root-owned and not group/other writable")
	}
	if err == nil {
		err = k.checkFS(child)
	}
	if err != nil {
		unix.Close(child)
		return nil, err
	}
	return os.NewFile(uintptr(child), name), nil
}
func readControl(fd int, name string, k kernel) (string, error) {
	f, err := openControl(fd, name, unix.O_RDONLY, k)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return "", err
	}
	if len(buf) > 65536 {
		return "", errors.New("cgroup control too large")
	}
	return strings.TrimSpace(string(buf)), nil
}
func writeControl(fd int, name, value string, k kernel) error {
	f, err := openControl(fd, name, unix.O_WRONLY|unix.O_TRUNC, k)
	if err != nil {
		return err
	}
	_, writeErr := f.WriteString(value)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if k.afterWrite != nil {
		return k.afterWrite(fd, name, value)
	}
	return nil
}
func requireText(fd int, name, want string, k kernel) error {
	value, err := readControl(fd, name, k)
	if err != nil {
		return err
	}
	if value != want {
		return fmt.Errorf("%s must be %q (got %q)", name, want, value)
	}
	return nil
}
func readLimit(fd int, name string, k kernel) (int64, error) {
	value, err := readControl(fd, name, k)
	if err != nil {
		return 0, err
	}
	limit, err := strconv.ParseInt(value, 10, 64)
	if err != nil || limit <= 0 {
		return 0, fmt.Errorf("%s must be a finite positive integer", name)
	}
	return limit, nil
}
func requireControllers(fd int, k kernel) error {
	for _, name := range []string{"cgroup.controllers", "cgroup.subtree_control"} {
		value, err := readControl(fd, name, k)
		if err != nil {
			return err
		}
		present := map[string]bool{}
		for _, item := range strings.Fields(value) {
			present[item] = true
		}
		if !present["memory"] || !present["pids"] {
			return fmt.Errorf("provider must pre-enable memory and pids in %s", name)
		}
	}
	return nil
}

// Acquire creates a fresh cgroup for a sealed-generated identity, never a name
// supplied by an employer. It never joins or reuses an existing cgroup.
func (p *Pool) Acquire(key string, memoryBytes int64, pids int) (*Lease, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fd < 0 {
		return nil, errors.New("cgroup pool closed")
	}
	if !keyPattern.MatchString(key) || memoryBytes <= 0 || memoryBytes > p.memory || pids < 1 || pids > p.pids {
		return nil, errors.New("invalid cgroup key or limits outside the delegated pool")
	}
	name := "job-" + key
	if err := p.kernel.mkdir(p.fd, name); err != nil {
		return nil, fmt.Errorf("create cgroup: %w", err)
	}
	fd, err := openDir(p.fd, name, p.kernel)
	if err != nil {
		_ = p.kernel.remove(p.fd, name)
		return nil, err
	}
	fail := func(cause error) (*Lease, error) { unix.Close(fd); _ = p.kernel.remove(p.fd, name); return nil, cause }
	if err = requireText(fd, "cgroup.type", "domain", p.kernel); err != nil {
		return fail(err)
	}
	for _, item := range [][2]string{{"memory.max", strconv.FormatInt(memoryBytes, 10)}, {"memory.swap.max", "0"}, {"pids.max", strconv.Itoa(pids)}, {"memory.oom.group", "1"}} {
		if err = writeControl(fd, item[0], item[1], p.kernel); err != nil {
			return fail(fmt.Errorf("%s: %w", item[0], err))
		}
		if err = requireText(fd, item[0], item[1], p.kernel); err != nil {
			return fail(err)
		}
	}
	procs, err := openControl(fd, "cgroup.procs", unix.O_WRONLY, p.kernel)
	if err != nil {
		return fail(err)
	}
	// The kernel's atomic subtree kill operation is mandatory, including for
	// descendants that changed process group/session or double-forked.
	kill, err := openControl(fd, "cgroup.kill", unix.O_WRONLY, p.kernel)
	if err != nil {
		procs.Close()
		return fail(err)
	}
	kill.Close()
	lease := &Lease{pool: p, name: name, fd: fd, procs: procs, memory: memoryBytes, pids: pids}
	p.leases[name] = lease
	return lease, nil
}

func (p *Pool) MemoryLimitBytes() int64       { return p.memory }
func (p *Pool) PIDsLimit() int                { return p.pids }
func (p *Pool) ParentMemoryLimitBytes() int64 { return p.parentMemory }
func (p *Pool) ParentPIDsLimit() int          { return p.parentPIDs }
func (l *Lease) MemoryLimitBytes() int64      { return l.memory }
func (l *Lease) PIDsLimit() int               { return l.pids }
func (l *Lease) ProcsFile() *os.File          { return l.procs }

// KillAndRemove kills every descendant and waits for the kernel to report the
// subtree empty before removal. Cancellation leaves the lease pinned for retry;
// it never treats a best-effort signal or RSS sample as completed cleanup.
func (l *Lease) KillAndRemove(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.removed {
		return nil
	}
	if err := writeControl(l.fd, "cgroup.kill", "1", l.pool.kernel); err != nil {
		return fmt.Errorf("cgroup.kill: %w", err)
	}
	for {
		events, err := readControl(l.fd, "cgroup.events", l.pool.kernel)
		if err != nil {
			return err
		}
		populated, err := populated(events)
		if err != nil {
			return err
		}
		if !populated {
			break
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	l.pool.mu.Lock()
	defer l.pool.mu.Unlock()
	if err := l.pool.kernel.remove(l.pool.fd, l.name); err != nil {
		return err
	}
	l.removed = true
	delete(l.pool.leases, l.name)
	procsErr := l.procs.Close()
	dirErr := unix.Close(l.fd)
	l.fd = -1
	return errors.Join(procsErr, dirErr)
}
func populated(events string) (bool, error) {
	found := false
	value := false
	for _, line := range strings.Split(events, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "populated" {
			if found || f[1] != "0" && f[1] != "1" {
				return false, errors.New("invalid cgroup populated state")
			}
			found = true
			value = f[1] == "1"
		}
	}
	if !found {
		return false, errors.New("missing cgroup populated state")
	}
	return value, nil
}

// Close refuses to release the pool while a descendant lease still exists.
func (p *Pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fd < 0 {
		return nil
	}
	if len(p.leases) > 0 {
		return errors.New("cgroup pool still has leases")
	}
	err := unix.Close(p.fd)
	p.fd = -1
	return err
}
