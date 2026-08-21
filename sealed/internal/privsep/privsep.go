// Package privsep runs the framework subprocess as a dedicated low-privilege
// user ("agent") so the agent process cannot read sealed's memory
// (/proc/<pid>/mem, ptrace), sealed's bootstrap environment
// (/proc/1/environ), or any file outside the subtrees explicitly handed to
// it. sealed itself stays where it is (PID 1) — the split demotes the agent,
// it does not elevate sealed.
//
// Availability is probed once, lazily: the split engages only when sealed
// runs as root AND the image ships the agent user (created in
// images/*/Dockerfile). Everywhere else — unit tests, local dev, a legacy
// image — every function degrades to a logged no-op and the subprocess
// spawns with sealed's own identity, exactly the pre-split behaviour.
//
// This turns the key-exfiltration half of the agent doctrine (refusals 2
// and 4: shell → read sealed's memory / bootstrap secrets) from a
// prompt-level request into a kernel-enforced boundary. The doctrine text
// stays as defence in depth; the sign-socket usage discipline (refusal 1)
// is unaffected — the socket is the agent's legitimate channel and is
// handed to the agent user here.
package privsep

import (
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
	lookupOnce sync.Once
	cred       *syscall.Credential
)

// credential resolves the agent user once. nil = split unavailable.
func credential() *syscall.Credential {
	lookupOnce.Do(func() {
		if os.Geteuid() != 0 {
			logger.Logf("privsep: not root (euid=%d) — framework subprocess keeps current identity", os.Geteuid())
			return
		}
		u, err := user.Lookup(agentUsername)
		if err != nil {
			logger.Logf("privsep: no %q user in this image — framework subprocess keeps root (legacy image?)", agentUsername)
			return
		}
		uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
		gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
		if err1 != nil || err2 != nil {
			logger.Logf("privsep: unparsable uid/gid for %q (%q/%q) — framework subprocess keeps root", agentUsername, u.Uid, u.Gid)
			return
		}
		// Groups: empty slice (not nil) so setgroups(0) actually drops
		// root's supplementary groups instead of inheriting them.
		cred = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}
		logger.Logf("privsep: framework subprocess will run as %s (uid=%d gid=%d)", agentUsername, uid, gid)
	})
	return cred
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
// or environ. Defence in depth for images without the agent user, where the
// framework subprocess still shares root with sealed. Call once at startup.
func HardenSelf() {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		logger.Logf("privsep: PR_SET_DUMPABLE=0: %v", err)
	}
}
