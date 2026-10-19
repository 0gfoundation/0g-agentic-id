//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/sys/unix"
)

func dumpable(t *testing.T) int {
	t.Helper()
	v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("PR_GET_DUMPABLE: %v", err)
	}
	return v
}

// makeDumpable sets the flag again, so that finding it clear afterwards
// proves something: an earlier test in this process may have cleared it.
func makeDumpable(t *testing.T) {
	t.Helper()
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err != nil {
		t.Fatalf("PR_SET_DUMPABLE 1: %v", err)
	}
	if v := dumpable(t); v != 1 {
		t.Fatalf("dumpable = %d after setting it, want 1", v)
	}
}

func TestHardenProcess_ClearsDumpable(t *testing.T) {
	makeDumpable(t)
	if err := hardenProcess(); err != nil {
		t.Fatalf("hardenProcess: %v", err)
	}
	if v := dumpable(t); v != 0 {
		t.Fatalf("dumpable = %d after hardenProcess, want 0", v)
	}
}

// readerFunc adapts a function to io.Reader.
type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(b []byte) (int, error) { return f(b) }

// TestRun_NonDumpableWhenKeyIsRead runs run with the real harden and
// checks the kernel's view at the moment stdin is first read.
func TestRun_NonDumpableWhenKeyIsRead(t *testing.T) {
	makeDumpable(t)
	key := strings.NewReader(testKeyHex + "\n")
	reads := 0
	stdin := readerFunc(func(b []byte) (int, error) {
		if reads++; reads == 1 {
			if v := dumpable(t); v != 0 {
				t.Errorf("dumpable = %d when the key is read, want 0", v)
			}
		}
		return key.Read(b)
	})
	stub := func(context.Context, options, *ecdsa.PrivateKey) ([]common.Hash, error) {
		return []common.Hash{{1}}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), sealedArgs(t, "f"), stdin, &stdout, &stderr, stub); code != exitOK {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	if reads == 0 {
		t.Fatal("run never read stdin")
	}
}
