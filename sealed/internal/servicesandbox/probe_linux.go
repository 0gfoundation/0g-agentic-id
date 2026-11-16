//go:build linux

package servicesandbox

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"

	"seal-verify/internal/serviceidentity"
)

// Probe confines the calling process (a fresh launcher run as root) with a
// minimal policy at the probe identity, then checks that the kernel
// enforces it: /proc unreadable; no socket but AF_UNIX and no System V IPC.
// The process must exit after.
func Probe() error {
	runtime.LockOSThread()
	p := Policy{UID: serviceidentity.Probe, ReadExec: existing("/usr", "/bin", "/lib", "/lib64"), Dir: "/", Program: "/bin/true"}
	if len(p.ReadExec) == 0 {
		return errors.New("no system directories")
	}
	if err := confine(p); err != nil {
		return err
	}
	if _, err := os.ReadFile("/proc/self/status"); err == nil {
		return errors.New("landlock did not refuse a path outside the policy")
	}
	// Every refusal must be the filter's EPERM: an address family the kernel
	// lacks would fail too, but with another error.
	for _, family := range []int{unix.AF_INET, unix.AF_SMC} {
		fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err == nil {
			unix.Close(fd)
			return fmt.Errorf("seccomp did not refuse a socket of family %d", family)
		}
		if !errors.Is(err, unix.EPERM) {
			return fmt.Errorf("socket of family %d: %w", family, err)
		}
	}
	if _, _, errno := unix.Syscall(unix.SYS_SHMGET, 0, 4096, 0o600); errno != unix.EPERM {
		return fmt.Errorf("shmget: %v, want the filter's EPERM", errno)
	}
	// No x32 call here: under Docker's default seccomp profile one kills the
	// calling thread before this filter's answer counts.
	return nil
}

func existing(paths ...string) []string {
	var out []string
	for _, p := range paths {
		if fi, err := os.Lstat(p); err == nil && fi.IsDir() {
			out = append(out, p)
		}
	}
	return out
}
