//go:build unix

package main

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

// TestReadKey_FromSocketpair reads the key the way sealed delivers it: on
// one end of an AF_UNIX stream socketpair, written in pieces, followed by
// a shutdown of the sending side.
func TestReadKey_FromSocketpair(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	local := os.NewFile(uintptr(fds[0]), "sealed-end")
	stdin := os.NewFile(uintptr(fds[1]), "helper-stdin")
	defer local.Close()
	defer stdin.Close()

	line := "0x" + testKeyHex + "\n"
	go func() {
		// Two writes with a pause, so the reader sees a short read first.
		if _, err := local.Write([]byte(line[:20])); err != nil {
			t.Error(err)
		}
		time.Sleep(20 * time.Millisecond)
		if _, err := local.Write([]byte(line[20:])); err != nil {
			t.Error(err)
		}
		if err := syscall.Shutdown(fds[0], syscall.SHUT_WR); err != nil {
			t.Error(err)
		}
	}()
	priv, err := readKey(stdin)
	if err != nil {
		t.Fatalf("readKey: %v", err)
	}
	if got, want := crypto.PubkeyToAddress(priv.PublicKey), testKeyAddress(t); got != want {
		t.Fatalf("address = %s, want %s", got, want)
	}
}
