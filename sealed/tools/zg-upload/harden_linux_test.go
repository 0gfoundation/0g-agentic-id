//go:build linux

package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestHardenProcess_ClearsDumpable(t *testing.T) {
	if err := hardenProcess(); err != nil {
		t.Fatalf("hardenProcess: %v", err)
	}
	v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("PR_GET_DUMPABLE: %v", err)
	}
	if v != 0 {
		t.Fatalf("dumpable = %d after hardenProcess, want 0", v)
	}
}
