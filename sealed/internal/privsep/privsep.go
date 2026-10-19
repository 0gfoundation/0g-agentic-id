// Package privsep runs the framework subprocess as a dedicated low-privilege
// user ("agent") so the agent process cannot read sealed's memory
// (/proc/<pid>/mem, ptrace), sealed's bootstrap environment
// (/proc/1/environ), or any file outside the subtrees explicitly handed to
// it. sealed itself stays where it is (PID 1) — the split demotes the agent,
// it does not elevate sealed.
//
// Availability is probed once, lazily: the split engages only when sealed
// runs as root AND the image ships the agent user (created in the image's
// build Dockerfile). Without it every helper degrades to a no-op — but
// sealed refuses to provision agent_seal_priv (Required, checked in main),
// so a container that cannot keep the key from its framework never
// receives it. Unit tests and local runs without an attestor never
// provision, so they are unaffected.
//
// This turns the key-exfiltration half of the agent doctrine (refusals 2
// and 4: shell → read sealed's memory / bootstrap secrets) from a
// prompt-level request into a kernel-enforced boundary. The doctrine text
// stays as defence in depth; the sign-socket usage discipline (refusal 1)
// is unaffected — the socket is the agent's legitimate channel and is
// handed to the agent user here.
package privsep

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"seal-verify/internal/logger"
)

// agentUsername is the low-privilege account the framework subprocess runs
// as. Created by the runtime images; its home is /root (shared with sealed's
// $HOME on purpose — every framework home path is /root/.<framework> and
// those constants are chain- and doc-visible, so ownership moves to the
// agent user rather than the paths moving to a new home).
const agentUsername = "agent"

var (
	lookupOnce  sync.Once
	cred        *syscall.Credential
	unavailable string // why cred is nil; set together with it
)

// credential resolves the agent user once. nil = split unavailable, with
// the reason in unavailable.
func credential() *syscall.Credential {
	lookupOnce.Do(func() {
		if os.Geteuid() != 0 {
			unavailable = fmt.Sprintf("not root (euid=%d)", os.Geteuid())
		} else if u, err := user.Lookup(agentUsername); err != nil {
			unavailable = fmt.Sprintf("no %q user in this image", agentUsername)
		} else if uid, err1 := strconv.ParseUint(u.Uid, 10, 32); err1 != nil {
			unavailable = fmt.Sprintf("unparsable uid %q for %q", u.Uid, agentUsername)
		} else if gid, err2 := strconv.ParseUint(u.Gid, 10, 32); err2 != nil {
			unavailable = fmt.Sprintf("unparsable gid %q for %q", u.Gid, agentUsername)
		} else {
			// Groups: empty slice (not nil) so setgroups(0) actually drops
			// root's supplementary groups instead of inheriting them.
			cred = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}
			logger.Logf("privsep: framework subprocess will run as %s (uid=%d gid=%d)", agentUsername, uid, gid)
			return
		}
		logger.Logf("privsep: unavailable — %s", unavailable)
	})
	return cred
}

// Active reports whether the uid split is available in this container —
// i.e. whether the framework subprocess will run de-privileged.
func Active() bool {
	return credential() != nil
}

// Required returns nil when the framework subprocess will run as the agent
// user, else an error naming why it cannot. sealed checks it before
// provisioning and fails closed: without the split the framework would
// share sealed's uid and could read agent_seal_priv out of this process,
// and the doctrine injected into the agent states the kernel wall as fact
// (platform/context.go) — so the key is never fetched into such a
// container. Catches a mis-built image (an image whose build Dockerfile
// lost the useradd) that the on-chain image whitelist, which pins hashes
// rather than contents, cannot.
func Required() error {
	if credential() == nil {
		return fmt.Errorf("privsep unavailable: %s", unavailable)
	}
	return nil
}

// Drop configures cmd to spawn as the agent user. Returns false — leaving
// cmd untouched — when the split is unavailable.
func Drop(cmd *exec.Cmd) bool {
	c := credential()
	if c == nil {
		return false
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = c
	return true
}

// OwnPath chowns one path (non-recursive) to the agent user. Best-effort,
// no-op without the split. Used for $HOME itself: the agent must be able to
// create new dotfiles (npm/tool caches) next to the subtrees it owns, and
// for the sign socket file, which is the agent's one legitimate channel to
// its key.
func OwnPath(path string) {
	c := credential()
	if c == nil {
		return
	}
	if err := os.Lchown(path, int(c.Uid), int(c.Gid)); err != nil {
		logger.Logf("privsep: chown %s: %v", path, err)
	}
}

// OwnTree recursively chowns root to the agent user. Best-effort, no-op
// without the split. Called by adapters after Restore has written role
// plaintexts (as root) and immediately before Start, so everything the
// agent must be able to edit is its own. Uses Lchown throughout: an
// agent-planted symlink surviving from a previous run must never redirect
// a chown outside the tree.
func OwnTree(root string) {
	c := credential()
	if c == nil {
		return
	}
	_ = filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return nil // best-effort: skip unreadable entries, keep walking
		}
		if err := os.Lchown(p, int(c.Uid), int(c.Gid)); err != nil {
			logger.Logf("privsep: chown %s: %v", p, err)
		}
		return nil
	})
}

// HardenSelf makes the sealed process non-dumpable (PR_SET_DUMPABLE=0): even
// a same-uid process can then neither ptrace it nor read its /proc/<pid>/mem
// or environ. Defence in depth on top of the uid split (Required refuses to
// provision without it). Call once at startup.
func HardenSelf() {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		logger.Logf("privsep: PR_SET_DUMPABLE=0: %v", err)
	}
}
