//go:build linux

package main

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// harden does for the loader what privsep.HardenSelf does for sealed. The
// loader holds the same environment, container key included, so it is made
// non-dumpable: no other process can ptrace it or read its /proc/1/mem or
// /proc/1/environ. It also sets no_new_privs on every thread, so nothing it
// starts can gain privileges through a setuid binary or file capabilities.
// Failures are logged, not fatal: sealed sets both again for itself, and
// its provision gate refuses to run without no_new_privs.
func harden() {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		logf("PR_SET_DUMPABLE=0: %v", err)
	}
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		logf("PR_SET_NO_NEW_PRIVS=1: %v", errno)
	}
}
