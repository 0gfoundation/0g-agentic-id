//go:build !linux

package main

// hardenProcess is a no-op off Linux: the sealed images are Linux, and the
// non-dumpable flag (harden_linux.go) is Linux-specific. Kept so the
// helper builds and its tests run on a development machine.
func hardenProcess() error { return nil }
