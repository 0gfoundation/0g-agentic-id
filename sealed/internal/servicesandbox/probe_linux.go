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
// minimal policy at the first service identity, then checks that the kernel
// enforces it: /proc unreadable, no inet socket. The process must exit after.
func Probe() error {
	runtime.LockOSThread()
	p := Policy{UID: serviceidentity.Base, ReadExec: existing("/usr", "/bin", "/lib", "/lib64"), Dir: "/", Program: "/bin/true"}
	if len(p.ReadExec) == 0 {
		return errors.New("no system directories")
	}
	if err := confine(p); err != nil {
		return err
	}
	if _, err := os.ReadFile("/proc/self/status"); err == nil {
		return errors.New("landlock did not refuse a path outside the policy")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		unix.Close(fd)
		return errors.New("seccomp did not refuse an inet socket")
	}
	if !errors.Is(err, unix.EPERM) {
		return fmt.Errorf("inet socket: %w", err)
	}
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
