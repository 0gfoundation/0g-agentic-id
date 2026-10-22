//go:build linux

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
// the key the framework never runs as sealed's uid. Unit tests and local
// runs without an attestor never provision, so they are unaffected.
//
// The agent process is untrusted input to everything root does afterwards,
// so the package also owns root's side of the boundary. The invariants:
//
//   - Root's home stays root:root 0711 with no POSIX ACL (SecureHome, run
//     by Harden at boot), and holds nothing another uid could have changed
//     (ReclaimHome moves out what an earlier sealed let the agent leave
//     there, by owner, mode or ACL, sparing the trees adapters declare and
//     making root's a directory that only leads to one). The agent has a
//     home of its own, /home/agent
//     (PrepareAgentHome), which is HOME for everything it runs and
//     AgentCommand's default working directory; Required refuses until both
//     are in place. Inside root's
//     home the agent owns only the framework trees handed to it (OwnTree),
//     linked into its own home (LinkAgentHome); never root's home, "/", an
//     ancestor of anything root runs, or anything inside sealed's state
//     directory or a package root runs from (guardHandover).
//   - Root runs no framework CLI. Toolchain commands go through
//     RootCommand, which resolves binaries only in root-only PATH
//     directories and fixes the environment (only proxy endpoints come from
//     the container's), including a root-only TMPDIR, and sealed's own TLS
//     trusts only CA locations that name root-only files (ScrubTrustEnv);
//     framework CLIs that read agent-writable state run as the agent
//     (AgentCommand). A root-run install is given an environment that keeps
//     it out of the agent's trees, so it touches nothing the agent can
//     write even while the framework is running.
//   - Every root read, write, chown or removal inside an agent-writable
//     tree goes through the helpers in fs.go, which never follow a link and
//     never open a non-regular file for reading; ReadFile and ReadTail bound
//     what they read, and callers of Open bound it themselves.
//     They are safe against an agent process changing the tree at the same
//     time, so root-side work does not depend on the agent being stopped.
//     sealed's own files (state, logs, scratch space) live under StateDir,
//     which the agent cannot reach.
//
// sealed also sets no_new_privs on itself (HardenSelf), which every process
// it starts inherits, so no agent process regains privileges through a
// setuid binary in the image.
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
// as. Created by the runtime images. Its home is /home/agent, which sealed
// creates at boot (PrepareAgentHome); the framework trees stay under /root
// (their paths are chain- and doc-visible), which remains root's (root:root
// 0711, SecureHome) — the agent can traverse it but owns only the trees
// OwnTree hands over.
const agentUsername = "agent"

// agentUseradd is the Dockerfile line that creates the agent account, quoted
// verbatim in Required's error when the image lacks it. On a base that
// already has the user — whose home an earlier line made /root — it points
// the account's home at /home/agent instead (passwdHomeNote), so an image
// layered on such a base still builds and gets the right home.
const agentUseradd = "RUN if id -u agent >/dev/null 2>&1; then usermod --home /home/agent agent; else useradd --system --no-create-home --home-dir /home/agent --shell /usr/sbin/nologin agent; fi"

var (
	lookupOnce  sync.Once
	cred        *syscall.Credential
	unavailable string // why cred is nil and what fixes it; set together with it

	// testCred, when set, stands in for the agent account: tests use it to
	// exercise the split's code paths on machines without one. Production
	// code never sets it.
	testCred *syscall.Credential
)

// credential resolves the agent user once. nil = split unavailable, with
// the cause and its remediation in unavailable.
func credential() *syscall.Credential {
	if c := testCred; c != nil {
		return c
	}
	lookupOnce.Do(func() {
		cred, unavailable = probe(os.Geteuid(), user.Lookup)
		if cred != nil {
			logger.Logf("privsep: framework subprocess will run as %s (uid=%d gid=%d)", agentUsername, cred.Uid, cred.Gid)
			if note := passwdHomeNote(user.Lookup); note != "" {
				logger.Logf("privsep: %s", note)
			}
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

// passwdHomeNote returns a line for the boot log when the agent account's
// home in the image's account database is not agentHomeDir, which an image
// built on a base whose agent account an earlier Dockerfile line created
// (with /root as its home) can still have. The agent's HOME is agentHomeDir
// either way, so nothing sealed starts depends on it, but tools that take
// the home from the account database instead of HOME (OpenSSH's ssh, scp
// and ssh-keygen, and so git over ssh) look there — in /root, where the
// agent can create nothing. Logged, not refused: it breaks those tools for
// the agent, not the boundary.
func passwdHomeNote(lookup func(string) (*user.User, error)) string {
	u, err := lookup(agentUsername)
	if err != nil || u.HomeDir == "" || filepath.Clean(u.HomeDir) == agentHomeDir {
		return ""
	}
	return fmt.Sprintf("the %q account's home in the image's account database is %q, not %s; its processes still get HOME=%s, but tools that take the home from the account database (ssh, scp, ssh-keygen, git over ssh) use %q instead; fix the image: usermod --home %s %s (see %s)", agentUsername, u.HomeDir, agentHomeDir, agentHomeDir, u.HomeDir, agentHomeDir, agentUsername, agentUseradd)
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
// user, root's home has been made root-only (SecureHome) and holds nothing
// another uid could have changed (ReclaimHome), the agent's own home is
// in place (PrepareAgentHome), and no process sealed starts can gain
// privileges through an exec (HardenSelf's no_new_privs) — all done by
// Harden at boot — else an error
// naming the cause and the fix for it. sealed checks it
// before provisioning and fails closed: without the split the framework
// would share sealed's uid and could read agent_seal_priv out of this
// process, and the doctrine injected into the agent states the kernel wall
// as fact (platform/context.go). With the split, root's home must also be
// root-only, or the agent could replace the toolchains and configuration
// root uses from there, and the agent's home must exist, or nothing the
// agent runs can start. The rest of the boundary — how root runs commands
// and touches agent-writable files — is structural (RootCommand,
// AgentCommand, fs.go) rather than a boot check. It catches a mis-built
// image (a build Dockerfile that lost or broke the agent account) that the
// on-chain image whitelist, which pins hashes rather than contents, cannot.
func Required() error {
	if credential() == nil {
		return fmt.Errorf("privsep unavailable: %s", unavailable)
	}
	secured, secErr, ready, prepErr := homeState()
	switch {
	case secErr != nil:
		return fmt.Errorf("privsep: %s could not be made root-only (root:root 0711): %v; fix the image so sealed, running as root, can chown and chmod it", rootHome, secErr)
	case !secured:
		return fmt.Errorf("privsep: %s has not been made root-only (root:root 0711): SecureHome did not run before the provisioning check; sealed must call privsep.Harden at boot", rootHome)
	case prepErr != nil:
		return fmt.Errorf("privsep: the agent's home %s could not be prepared (agent:agent 0700): %v; fix the image so sealed, running as root, can create it (and neither it nor its parent is a symbolic link)", agentHomeDir, prepErr)
	case !ready:
		return fmt.Errorf("privsep: the agent's home %s has not been prepared: PrepareAgentHome did not run before the provisioning check; sealed must call privsep.Harden at boot", agentHomeDir)
	}
	switch done, err := reclaimState(); {
	case err != nil:
		return fmt.Errorf("privsep: %v", err)
	case !done:
		return fmt.Errorf("privsep: %s has not been checked for entries an earlier sealed let the agent leave there: ReclaimHome did not run before the provisioning check; sealed must call privsep.Harden at boot", rootHome)
	}
	switch set, err := selfState(); {
	case err != nil:
		return fmt.Errorf("privsep: no_new_privs could not be set (PR_SET_NO_NEW_PRIVS): %v; without it the agent user could regain root through a setuid binary in the image", err)
	case !set:
		return fmt.Errorf("privsep: no_new_privs has not been set: HardenSelf did not run before the provisioning check; sealed must call privsep.Harden at boot")
	}
	return nil
}

// Drop configures cmd to spawn as the agent user. Returns false — leaving
// cmd untouched — when the split is unavailable. Each command gets its own
// copy of the credential, so nothing done to one command's credential can
// change what another command, or a later one, runs as.
func Drop(cmd *exec.Cmd) bool {
	c := credential()
	if c == nil {
		return false
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	own := *c
	own.Groups = []uint32{}
	cmd.SysProcAttr.Credential = &own
	return true
}

// OwnPath chowns one socket (not following a link at it) to the agent user.
// Best-effort, no-op without the split. Used only for the sign socket, the
// agent's one legitimate channel to its key; it refuses anything that is
// not a socket, and the same paths OwnTree does (guardHandover).
func OwnPath(path string) {
	c := credential()
	if c == nil {
		return
	}
	if err := ownPath(path, c.Uid, c.Gid); err != nil {
		logger.Logf("privsep: chown %s: %v", path, err)
	}
}

// HardenSelf makes the sealed process non-dumpable (PR_SET_DUMPABLE=0): even
// a same-uid process can then neither ptrace it nor read its /proc/<pid>/mem
// or environ. Defence in depth on top of the uid split (Required refuses to
// provision without it).
//
// It also sets no_new_privs (PR_SET_NO_NEW_PRIVS), which every process
// sealed starts inherits and none can clear: an execve in them never
// grants privileges, so a setuid or setgid binary in the image (su, mount,
// passwd, ...) runs as whoever executed it, and file capabilities are not
// gained. The agent's processes therefore cannot climb back to root
// through such a binary, and the uid split does not depend on every one of
// them being free of a local privilege escalation. It changes nothing for
// root's own commands (setuid-root is a no-op for root; the credential
// drop to the agent user is a setuid call, not an exec, and still works).
//
// no_new_privs belongs to a thread, not to the process, and a child
// inherits it from the thread that forks it, which for os/exec is
// whichever thread the starting goroutine runs on. So it is set on every
// thread of the process at once (syscall.AllThreadsSyscall); threads the
// runtime starts later are cloned from those and inherit it. Go cannot do
// that in a binary that links cgo (ENOTSUP): the images build sealed with
// CGO_ENABLED=0, and a cgo build is refused by Required rather than run
// with some children able to gain privileges. Call once at startup.
func HardenSelf() {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		logger.Logf("privsep: PR_SET_DUMPABLE=0: %v", err)
	}
	var err error
	switch _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno {
	case 0:
	case syscall.ENOTSUP:
		err = errors.New("it cannot be set on every thread of a binary that links cgo; build sealed with CGO_ENABLED=0")
	default:
		err = errno
	}
	homeMu.Lock()
	noNewPrivs, noNewPrivsErr = err == nil, err
	homeMu.Unlock()
	if err != nil {
		logger.Logf("privsep: PR_SET_NO_NEW_PRIVS=1: %v", err)
	}
}

// selfState reports whether HardenSelf set no_new_privs, with its error.
func selfState() (bool, error) {
	homeMu.Lock()
	defer homeMu.Unlock()
	return noNewPrivs, noNewPrivsErr
}
