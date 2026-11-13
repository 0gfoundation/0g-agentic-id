package servicehost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"seal-verify/internal/privsep"
	"seal-verify/internal/serviceidentity"
)

const coordinatorUIDBase = serviceidentity.CoordinatorBase
const workerUIDBase = serviceidentity.WorkerBase
const temporaryFilesystemBytes = 64 << 20

var ErrIsolationUnavailable = errors.New("isolation unavailable")

// mappedIdentity checks the namespace's inside IDs, not its host UID offset.
// An unmapped ID makes setuid/chown fail even when sealed has SETUID/CHOWN.
func mappedIdentity(mapping []byte, first, count uint64) bool {
	end := first + count
	if count == 0 || end < first {
		return false
	}
	for _, line := range strings.Split(string(mapping), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		inside, e1 := strconv.ParseUint(f[0], 10, 64)
		_, e2 := strconv.ParseUint(f[1], 10, 64)
		n, e3 := strconv.ParseUint(f[2], 10, 64)
		if e1 == nil && e2 == nil && e3 == nil && n > 0 && inside+n >= inside && first >= inside && end <= inside+n {
			return true
		}
	}
	return false
}

func checkServiceIdentityMaps() error {
	for _, name := range []string{"uid_map", "gid_map"} {
		mapping, err := os.ReadFile("/proc/self/" + name)
		if err != nil || !mappedIdentity(mapping, coordinatorUIDBase, serviceidentity.CoordinatorCount) || !mappedIdentity(mapping, workerUIDBase, serviceidentity.WorkerCount) {
			return fmt.Errorf("%w: provider %s must map reserved service IDs %d..%d and %d..%d", ErrIsolationUnavailable, name, coordinatorUIDBase, coordinatorUIDBase+serviceidentity.CoordinatorCount-1, workerUIDBase, workerUIDBase+serviceidentity.WorkerCount-1)
		}
	}
	return nil
}

func imageSystemArguments() []string {
	var args []string
	for _, p := range []string{"/bin", "/sbin", "/lib", "/lib64", "/etc/resolv.conf", "/etc/hosts", "/etc/ssl/certs"} {
		if _, err := privsep.Lstat(p); err == nil {
			args = append(args, "--ro-bind", p, p)
		}
	}
	return args
}

// namespaceArguments always creates the full isolation boundary. /proc stays
// empty: mounting a fresh procfs is forbidden below Docker's masked proc mounts,
// and binding the parent's procfs would reveal the owner's processes.
func namespaceArguments(uid uint32) []string {
	return []string{
		"--die-with-parent", "--new-session", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try", "--unshare-user", "--unshare-net",
		"--cap-drop", "ALL", "--uid", fmt.Sprint(uid), "--gid", fmt.Sprint(uid),
		"--clearenv", "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin", "--setenv", "HOME", "/work", "--setenv", "TMPDIR", "/tmp",
		"--ro-bind", "/usr", "/usr", "--dir", "/proc", "--dev", "/dev", "--remount-ro", "/dev",
		"--size", strconv.Itoa(temporaryFilesystemBytes), "--tmpfs", "/tmp", "--dir", "/etc", "--dir", "/run",
	}
}

// ProbeIsolation verifies the actual provider policy before admitting service
// code. It never relaxes namespaces, proc masks, capabilities or seccomp.
func ProbeIsolation(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkServiceIdentityMaps(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	bwrap, err := privsep.LookPath("bwrap")
	if err != nil {
		return fmt.Errorf("%w: trusted bubblewrap is required: %v", ErrIsolationUnavailable, err)
	}
	args := append([]string{strconv.Itoa(workerUIDBase), bwrap}, namespaceArguments(workerUIDBase)...)
	args = append(args, imageSystemArguments()...)
	args = append(args, "--remount-ro", "/", "--", "/usr/bin/true")
	cmd, err := privsep.RootCommand(ctx, "sealed-service-launcher", args...)
	if err != nil {
		return fmt.Errorf("%w: trusted service launcher is required: %v", ErrIsolationUnavailable, err)
	}
	// Probe diagnostics are bounded by this fixed trusted command and contain
	// no owner state or task input. Keep the concrete denial actionable.
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("isolation probe: %w", ctx.Err())
		}
		detail := strings.TrimSpace(string(out))
		if len(detail) > 512 {
			detail = detail[:512]
		}
		return fmt.Errorf("%w: provider must enable the constrained bubblewrap namespace seccomp/AppArmor policy (six capabilities and masked proc retained): %s: %v", ErrIsolationUnavailable, detail, err)
	}
	return nil
}
