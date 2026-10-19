// Package privsep runs the framework subprocess as a dedicated low-privilege
// user ("agent") so the agent process cannot read sealed's memory
// (/proc/<pid>/mem, ptrace), sealed's bootstrap environment
// (/proc/1/environ), or any file outside the subtrees explicitly handed to
// it. sealed itself stays where it is (PID 1) — the split demotes the agent,
// it does not elevate sealed.
//
// Availability is probed once, lazily: the split engages only when sealed
// runs as root AND the image ships an agent account with its own non-root
// uid and gid (created in the image's build Dockerfile). Without it every
// helper degrades to a no-op — but sealed then refuses to provision
// agent_seal_priv (Required, checked in main), so in a container that holds
// the key the framework never runs as sealed's uid. That is a necessary
// condition for the kernel wall described below, not a complete proof of
// isolation: how root-side code handles framework-owned files and framework
// CLIs is a separate hardening area. Unit tests and local runs without an
// attestor never provision, so they are unaffected.
//
// This turns the key-exfiltration half of the agent doctrine (refusals 2
// and 4: shell → read sealed's memory / bootstrap secrets) from a
// prompt-level request into a kernel-enforced boundary. The doctrine text
// stays as defence in depth; the sign-socket usage discipline (refusal 1)
// is unaffected — the socket is the agent's legitimate channel and is
// handed to the agent user here.
package privsep

import (
	"errors"
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

// agentUseradd is the Dockerfile line that creates the agent account, quoted
// verbatim in Required's error when the image lacks it. The id -u guard
// keeps it idempotent, so an image layered on a base that already has the
// user still builds.
const agentUseradd = "RUN id -u agent >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /root --shell /usr/sbin/nologin agent"

var (
	lookupOnce  sync.Once
	cred        *syscall.Credential
	unavailable string // why cred is nil and what fixes it; set together with it
)

// credential resolves the agent user once. nil = split unavailable, with
// the cause and its remediation in unavailable.
func credential() *syscall.Credential {
	lookupOnce.Do(func() {
		cred, unavailable = probe(os.Geteuid(), user.Lookup)
		if cred != nil {
			logger.Logf("privsep: framework subprocess will run as %s (uid=%d gid=%d)", agentUsername, cred.Uid, cred.Gid)
			return
		}
		logger.Logf("privsep: unavailable — %s", unavailable)
	})
	return cred
}

// probe is credential's decision with sealed's euid and the account lookup
// injected, so every cause is unit-testable. It returns either the
// credential to drop the framework to, or why there is none followed by the
// fix for that specific cause — an operator reading the refusal in /log
// must not be sent to the Dockerfile when the problem is how sealed runs.
func probe(euid int, lookup func(string) (*user.User, error)) (*syscall.Credential, string) {
	if euid != 0 {
		return nil, fmt.Sprintf("sealed runs as euid=%d, not root; run sealed as root so it can drop the framework to the %q user", euid, agentUsername)
	}
	u, err := lookup(agentUsername)
	var unknown user.UnknownUserError
	switch {
	case errors.As(err, &unknown):
		return nil, fmt.Sprintf("no %q user in this image; add to its Dockerfile: %s", agentUsername, agentUseradd)
	case err != nil:
		return nil, fmt.Sprintf("looking up the %q user: %v; fix the image's account database", agentUsername, err)
	}
	c, err := agentCredential(u.Uid, u.Gid, euid)
	if err != nil {
		return nil, fmt.Sprintf("%v; fix the image's %q account: it needs its own non-root uid and gid", err, agentUsername)
	}
	return c, ""
}

// agentCredential turns the agent account's uid/gid strings into the
// credential the framework spawns with, refusing any account that would
// not actually separate the framework from sealed: uid 0 or gid 0 (root's
// identity under another name), or a uid equal to sealed's own euid. Pure,
// so each rejection is unit-tested.
func agentCredential(uidStr, gidStr string, selfEUID int) (*syscall.Credential, error) {
	uid, err := strconv.ParseUint(uidStr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("%q has unparsable uid %q", agentUsername, uidStr)
	}
	gid, err := strconv.ParseUint(gidStr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("%q has unparsable gid %q", agentUsername, gidStr)
	}
	switch {
	case uid == 0:
		return nil, fmt.Errorf("%q maps to uid 0 (root)", agentUsername)
	case gid == 0:
		return nil, fmt.Errorf("%q maps to gid 0 (root's group)", agentUsername)
	case selfEUID >= 0 && uid == uint64(selfEUID):
		return nil, fmt.Errorf("%q maps to sealed's own uid %d", agentUsername, uid)
	}
	// Groups: empty slice (not nil) so setgroups(0) actually drops root's
	// supplementary groups instead of inheriting them.
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}, nil
}

// Active reports whether the uid split is available in this container —
// i.e. whether the framework subprocess will run de-privileged.
func Active() bool {
	return credential() != nil
}

// Required returns nil when the framework subprocess will run as the agent
// user, else an error naming the cause and the fix for it. sealed checks it
// before provisioning and fails closed: without the split the framework
// would share sealed's uid and could read agent_seal_priv out of this
// process, and the doctrine injected into the agent states the kernel wall
// as fact (platform/context.go). What the gate guarantees is deliberately
// narrow — in a container that holds the key, the framework never runs as
// sealed's uid. That is necessary for the wall, not sufficient for
// isolation; root-side handling of framework files and CLIs is a separate
// hardening area. It catches a mis-built image (a build Dockerfile that
// lost or broke the agent account) that the on-chain image whitelist, which
// pins hashes rather than contents, cannot.
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
