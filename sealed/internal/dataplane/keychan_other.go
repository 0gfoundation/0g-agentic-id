//go:build unix && !linux

package dataplane

import "syscall"

// cloexecSocketpair returns a connected AF_UNIX stream socket pair with
// both ends close-on-exec. Without SOCK_CLOEXEC the flag is set after the
// call, under syscall.ForkLock so no exec can happen in between (as package
// net does). sealed ships on Linux; this keeps the package's tests running
// on other development machines.
func cloexecSocketpair() ([2]int, error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fds, err
	}
	syscall.CloseOnExec(fds[0])
	syscall.CloseOnExec(fds[1])
	return fds, nil
}
