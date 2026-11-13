//go:build linux

// Trusted bootstrap for untrusted service sandboxes. Drop the host identity
// before bwrap creates namespaces. Only its read-only release and private
// work/run directories are mounted; sealed's state and sockets stay outside.
package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"seal-verify/internal/serviceidentity"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "service-launcher:", err)
		os.Exit(1)
	}
}
func run() error {
	args := os.Args[1:]
	if os.Geteuid() != 0 || len(args) < 3 {
		return fmt.Errorf("requires sealed root, uid and a trusted sandbox command")
	}
	if args[0] == "--cgroup-fd=3" {
		var fs unix.Statfs_t
		if err := unix.Fstatfs(3, &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
			return fmt.Errorf("requires verified cgroup-v2 descriptor")
		}
		if n, err := unix.Write(3, []byte("0")); err != nil || n != 1 {
			return fmt.Errorf("enter process-tree cgroup: %v", err)
		}
		if err := unix.Close(3); err != nil {
			return err
		}
		if err := os.WriteFile("/proc/self/oom_score_adj", []byte("0"), 0600); err != nil {
			return fmt.Errorf("reset worker OOM protection: %w", err)
		}
		args = args[1:]
	}
	if len(args) < 3 {
		return fmt.Errorf("requires uid and trusted sandbox command")
	}
	uid, err := strconv.Atoi(args[0])
	if err != nil || !serviceidentity.Valid(uid) {
		return fmt.Errorf("invalid service identity")
	}
	if err = syscall.Setgroups([]int{}); err != nil {
		return err
	}
	if err = syscall.Setgid(uid); err != nil {
		return err
	}
	if err = syscall.Setuid(uid); err != nil {
		return err
	}
	// Restore ordinary procfs ownership only after dropping to the unique
	// host UID; no sealed/root process is exposed.
	if err = unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err != nil {
		return err
	}
	if err = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	return syscall.Exec(args[1], args[1:], os.Environ())
}
