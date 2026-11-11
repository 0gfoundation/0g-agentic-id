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
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "service-launcher:", err)
		os.Exit(1)
	}
}
func run() error {
	if os.Geteuid() != 0 || len(os.Args) < 4 {
		return fmt.Errorf("requires sealed root, uid and a trusted sandbox command")
	}
	uid, err := strconv.Atoi(os.Args[1])
	if err != nil || uid < 200000 || uid >= 200016 {
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
	return syscall.Exec(os.Args[2], os.Args[2:], os.Environ())
}
