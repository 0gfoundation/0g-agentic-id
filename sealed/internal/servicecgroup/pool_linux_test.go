//go:build linux

package servicecgroup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type fixture struct {
	mount, proc, parent, pool string
	k                         kernel
	killed                    []string
}

func put(t *testing.T, p, value string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}
func controls(t *testing.T, dir string, memory int64, pids int) {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"cgroup.type": "domain", "cgroup.controllers": "memory pids", "cgroup.subtree_control": "memory pids", "cgroup.procs": "", "cgroup.kill": "0", "cgroup.events": "populated 0\nfrozen 0", "memory.max": strconv.FormatInt(memory, 10), "memory.swap.max": "max", "pids.max": strconv.Itoa(pids), "memory.oom.group": "0"} {
		put(t, filepath.Join(dir, name), value)
	}
}
func fake(t *testing.T) *fixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned cgroup fixtures require root")
	}
	base := t.TempDir()
	f := &fixture{mount: filepath.Join(base, "cgroup"), proc: filepath.Join(base, "membership")}
	f.parent = filepath.Join(f.mount, "sandbox")
	f.pool = filepath.Join(f.parent, PoolName)
	controls(t, f.mount, 2<<30, 2048)
	controls(t, f.parent, 1<<30, 1024)
	controls(t, f.pool, 512<<20, 256)
	supervisor := filepath.Join(f.parent, SupervisorName)
	controls(t, supervisor, 512<<20, 256)
	put(t, filepath.Join(supervisor, "cgroup.procs"), strconv.Itoa(os.Getpid())+"\n")
	put(t, f.proc, "0::/sandbox/"+SupervisorName+"\n")
	f.k = systemKernel()
	f.k.checkFS = func(int) error { return nil }
	f.k.mkdir = func(fd int, name string) error {
		p := filepath.Join(fmt.Sprintf("/proc/self/fd/%d", fd), name)
		if err := os.Mkdir(p, 0700); err != nil {
			return err
		}
		controls(t, p, 512<<20, 256)
		return nil
	}
	f.k.remove = func(fd int, name string) error {
		return os.RemoveAll(filepath.Join(fmt.Sprintf("/proc/self/fd/%d", fd), name))
	}
	f.k.afterWrite = func(fd int, name, value string) error {
		if name == "cgroup.kill" {
			dir := fmt.Sprintf("/proc/self/fd/%d", fd)
			f.killed = append(f.killed, dir)
			return os.WriteFile(filepath.Join(dir, "cgroup.events"), []byte("populated 0\nfrozen 0"), 0600)
		}
		return nil
	}
	return f
}
func (f *fixture) open(t *testing.T) *Pool {
	t.Helper()
	p, err := newAt(f.mount, f.proc, f.k)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p
}

func TestNewProvesControllerWritesAndAcquirePinsMigrationFD(t *testing.T) {
	f := fake(t)
	p := f.open(t)
	if p.MemoryLimitBytes() != 512<<20 || p.PIDsLimit() != 256 || p.ParentMemoryLimitBytes() != 1<<30 || p.ParentPIDsLimit() != 1024 {
		t.Fatal("wrong aggregate limits")
	}
	if len(f.killed) != 1 {
		t.Fatal("startup did not exercise subtree kill")
	}
	entries, err := os.ReadDir(f.pool)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "job-") {
			t.Fatal("startup probe leaked a child")
		}
	}
	lease, err := p.Acquire("sealed-uid-500001", 128<<20, 32)
	if err != nil {
		t.Fatal(err)
	}
	if lease.MemoryLimitBytes() != 128<<20 || lease.PIDsLimit() != 32 || lease.ProcsFile() == nil {
		t.Fatal("missing lease facts")
	}
	for name, want := range map[string]string{"memory.max": "134217728", "memory.swap.max": "0", "pids.max": "32", "memory.oom.group": "1"} {
		got, err := os.ReadFile(filepath.Join(f.pool, "job-sealed-uid-500001", name))
		if err != nil || string(got) != want {
			t.Fatalf("%s: got %q: %v", name, got, err)
		}
	}
	if _, err = p.Acquire("sealed-uid-500001", 128<<20, 32); err == nil {
		t.Fatal("reused an existing cgroup")
	}
	if err = p.Close(); err == nil {
		t.Fatal("closed a pool with a lease")
	}
	if err = lease.KillAndRemove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = lease.KillAndRemove(context.Background()); err != nil {
		t.Fatal("cleanup not idempotent:", err)
	}
	if _, err = lease.ProcsFile().WriteString("0"); err == nil {
		t.Fatal("cleanup left migration FD open")
	}
}

func TestNewRejectsUnboundedOrUnsafeDelegation(t *testing.T) {
	cases := []struct {
		name   string
		change func(*testing.T, *fixture)
	}{
		{"not-cgroup2", func(t *testing.T, f *fixture) { f.k.checkFS = func(int) error { return errors.New("not cgroup2") } }},
		{"wrong-membership", func(t *testing.T, f *fixture) { put(t, f.proc, "0::/sandbox/owner\n") }},
		{"escaped-membership", func(t *testing.T, f *fixture) { put(t, f.proc, "0::/sandbox/../"+SupervisorName+"\n") }},
		{"duplicate-membership", func(t *testing.T, f *fixture) {
			put(t, f.proc, "0::/sandbox/"+SupervisorName+"\n0::/sandbox/"+SupervisorName+"\n")
		}},
		{"wrong-current-pid", func(t *testing.T, f *fixture) {
			put(t, filepath.Join(f.parent, SupervisorName, "cgroup.procs"), "99999999\n")
		}},
		{"parent-unbounded-memory", func(t *testing.T, f *fixture) { put(t, filepath.Join(f.parent, "memory.max"), "max") }},
		{"parent-unbounded-pids", func(t *testing.T, f *fixture) { put(t, filepath.Join(f.parent, "pids.max"), "max") }},
		{"pool-unbounded", func(t *testing.T, f *fixture) { put(t, filepath.Join(f.pool, "memory.max"), "max") }},
		{"no-supervisor-headroom", func(t *testing.T, f *fixture) { put(t, filepath.Join(f.pool, "memory.max"), strconv.Itoa(1<<30)) }},
		{"pool-has-process", func(t *testing.T, f *fixture) { put(t, filepath.Join(f.pool, "cgroup.procs"), "123\n") }},
		{"controllers-disabled", func(t *testing.T, f *fixture) { put(t, filepath.Join(f.pool, "cgroup.subtree_control"), "pids") }},
		{"threaded-pool", func(t *testing.T, f *fixture) { put(t, filepath.Join(f.pool, "cgroup.type"), "threaded") }},
		{"writable-ancestor", func(t *testing.T, f *fixture) {
			if err := os.Chmod(f.parent, 0777); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable-control", func(t *testing.T, f *fixture) {
			if err := os.Chmod(filepath.Join(f.pool, "memory.max"), 0666); err != nil {
				t.Fatal(err)
			}
		}},
		{"foreign-owner", func(t *testing.T, f *fixture) {
			if err := os.Chown(f.pool, 65534, 65534); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink-pool", func(t *testing.T, f *fixture) {
			os.Rename(f.pool, f.pool+"-real")
			if err := os.Symlink(f.pool+"-real", f.pool); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink-control", func(t *testing.T, f *fixture) {
			name := filepath.Join(f.pool, "memory.max")
			os.Remove(name)
			if err := os.Symlink(filepath.Join(f.parent, "memory.max"), name); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing-kill", func(t *testing.T, f *fixture) {
			original := f.k.mkdir
			f.k.mkdir = func(fd int, name string) error {
				if err := original(fd, name); err != nil {
					return err
				}
				return os.Remove(filepath.Join(fmt.Sprintf("/proc/self/fd/%d", fd), name, "cgroup.kill"))
			}
		}},
		{"controller-write-denied", func(t *testing.T, f *fixture) {
			f.k.afterWrite = func(_ int, name, _ string) error {
				if name == "memory.swap.max" {
					return unix.EPERM
				}
				return nil
			}
		}},
		{"controller-write-not-effective", func(t *testing.T, f *fixture) {
			f.k.afterWrite = func(fd int, name, _ string) error {
				if name == "memory.max" {
					return os.WriteFile(filepath.Join(fmt.Sprintf("/proc/self/fd/%d", fd), name), []byte("max"), 0600)
				}
				return nil
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := fake(t)
			tc.change(t, f)
			p, err := newAt(f.mount, f.proc, f.k)
			if !errors.Is(err, ErrUnsupported) {
				if p != nil {
					p.Close()
				}
				t.Fatalf("wanted ErrUnsupported, got %v", err)
			}
		})
	}
}

func TestAcquireRejectsCallerPathsAndLimits(t *testing.T) {
	f := fake(t)
	p := f.open(t)
	for _, key := range []string{"", "../escape", "/outside", "x/y", "x.y", strings.Repeat("x", 81)} {
		if _, err := p.Acquire(key, 128<<20, 8); err == nil {
			t.Errorf("accepted key %q", key)
		}
	}
	for _, limits := range [][2]int64{{0, 8}, {-1, 8}, {513 << 20, 8}, {128 << 20, 0}, {128 << 20, 257}} {
		if _, err := p.Acquire("limits", limits[0], int(limits[1])); err == nil {
			t.Errorf("accepted limits %v", limits)
		}
	}
}

func TestCleanupWaitsForWholeSubtreeAndKeepsLeaseOnTimeout(t *testing.T) {
	f := fake(t)
	p := f.open(t)
	lease, err := p.Acquire("waiting", 128<<20, 8)
	if err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(f.pool, "job-waiting", "cgroup.events")
	put(t, events, "populated 1\nfrozen 0")
	// Simulate a descendant still running after the kill request. No signal/RSS
	// observation may stand in for the kernel's populated=0 acknowledgement.
	p.kernel.afterWrite = func(int, string, string) error { return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Millisecond)
	defer cancel()
	if err = lease.KillAndRemove(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected timeout, got %v", err)
	}
	if _, err = os.Stat(filepath.Join(f.pool, "job-waiting")); err != nil {
		t.Fatal("removed populated cgroup")
	}
	put(t, events, "populated 0\nfrozen 0")
	if err = lease.KillAndRemove(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestProductionNewDoesNotAcceptAnOrdinaryFilesystem(t *testing.T) {
	f := fake(t)
	if p, err := newAt(f.mount, f.proc, systemKernel()); !errors.Is(err, ErrUnsupported) {
		if p != nil {
			p.Close()
		}
		t.Fatalf("ordinary fs accepted: %v", err)
	}
}

func TestPinnedDescriptorsAreCloseOnExec(t *testing.T) {
	f := fake(t)
	root, err := unix.Open(f.mount, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(root)
	fd, err := walk(root, "/", f.k)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("parent descriptor can leak across concurrent exec: flags=%d, err=%v", flags, err)
	}
	p := f.open(t)
	lease, err := p.Acquire("cloexec", 128<<20, 8)
	if err != nil {
		t.Fatal(err)
	}
	flags, err = unix.FcntlInt(lease.ProcsFile().Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("migration descriptor can leak outside explicit ExtraFiles: flags=%d, err=%v", flags, err)
	}
	if err = lease.KillAndRemove(context.Background()); err != nil {
		t.Fatal(err)
	}
}
