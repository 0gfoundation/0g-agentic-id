//go:build linux

package main

import "golang.org/x/sys/unix"

// hardenProcess marks the process non-dumpable, as sealed does for itself
// (internal/privsep.HardenSelf). execve resets the flag, so sealed's setting
// does not carry over to this child. From the call on, processes without
// CAP_SYS_PTRACE cannot start to ptrace the helper or open its
// /proc/<pid>/mem, environ or fd entries, even under the same uid; access
// gained before the call (the helper is dumpable from execve until run
// reaches it) is not revoked. run calls it before anything else, in
// particular before the key is read from stdin.
func hardenProcess() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
