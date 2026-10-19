//go:build linux

package main

import "golang.org/x/sys/unix"

// hardenProcess marks the process non-dumpable, as sealed does for itself
// (internal/privsep.HardenSelf). execve resets the flag, so sealed's setting
// does not carry over to this child. While it is clear, processes without
// CAP_SYS_PTRACE cannot ptrace the helper or read its /proc/<pid>/mem,
// environ or fd entries, even when they run under the same uid. main calls
// it before anything else, in particular before the key is read from stdin.
func hardenProcess() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
