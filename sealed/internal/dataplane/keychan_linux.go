//go:build linux

package dataplane

import "syscall"

// cloexecSocketpair returns a connected AF_UNIX stream socket pair with
// both ends created close-on-exec atomically.
func cloexecSocketpair() ([2]int, error) {
	return syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
}
