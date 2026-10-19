package dataplane

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// keyChannel carries the signing key to the upload helper's stdin.
//
// The helper's stdin is one end of an AF_UNIX stream socketpair, never a
// pipe. A process allowed to inspect the helper (same uid, helper still
// dumpable) can open a pipe the helper holds again through
// /proc/<pid>/fd/0 and read what is buffered in it, and the helper is
// dumpable from execve until it hardens itself early in its own code. A
// socket cannot be opened through /proc at all (ENXIO), so the key sits in
// a buffer only the helper's own descriptor reaches.
//
// sealed writes the key as soon as the helper has started, without waiting
// for it to harden itself. What a same-uid process could still do in that
// window (attach with ptrace, or copy the descriptor with pidfd_getfd)
// keeps working after the helper turns non-dumpable, so a "hardened"
// handshake would not revoke it; against the agent, the uid split is the
// boundary (TRUST_MODEL.md).
//
// Both ends are close-on-exec in sealed, so no other child sealed starts
// (the framework subprocess included) inherits either; exec.Cmd dup2s the
// remote end onto the helper's fd 0, which clears the flag there only.
type keyChannel struct {
	local  *os.File // sealed's end: the key line is written here
	remote *os.File // the helper's stdin (cmd.Stdin)
	line   []byte   // bare hex key + "\n"
}

func newKeyChannel(signerPrivHex string) (*keyChannel, error) {
	fds, err := cloexecSocketpair()
	if err != nil {
		return nil, fmt.Errorf("upload key channel: %w", err)
	}
	return &keyChannel{
		local:  os.NewFile(uintptr(fds[0]), "zg-upload-key"),
		remote: os.NewFile(uintptr(fds[1]), "zg-upload-stdin"),
		line:   []byte(strings.TrimPrefix(signerPrivHex, "0x") + "\n"),
	}, nil
}

// started drops sealed's copy of the helper's end once the started helper
// holds its own, so the helper's exit is seen as a closed peer.
func (k *keyChannel) started() { _ = k.remote.Close() }

// aLongTimeAgo is a deadline that has already passed: setting it makes a
// pending or future write fail at once.
var aLongTimeAgo = time.Unix(1, 0)

// send writes the key line to the helper and shuts down sealed's sending
// side, so the helper reads the line followed by end-of-file. The write is
// bounded by ctx: its deadline, or its cancellation. send is one-shot: it
// closes sealed's end whatever happens, so a failed send leaves the helper
// at end-of-file (and failing for want of a key) instead of waiting on its
// stdin until the upload deadline.
func (k *keyChannel) send(ctx context.Context) error {
	defer clear(k.line)
	defer k.local.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	c, err := net.FileConn(k.local)
	if err != nil {
		return err
	}
	defer c.Close()
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("key channel is a %T, want a unix socket", c)
	}
	if dl, ok := ctx.Deadline(); ok {
		if err := uc.SetWriteDeadline(dl); err != nil {
			return err
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = uc.SetWriteDeadline(aLongTimeAgo) })
	defer stop()
	if _, err := uc.Write(k.line); err != nil {
		return err
	}
	return uc.CloseWrite()
}

// Close releases both ends and zeroes the buffered key line.
func (k *keyChannel) Close() {
	_ = k.local.Close()
	_ = k.remote.Close()
	clear(k.line)
}
