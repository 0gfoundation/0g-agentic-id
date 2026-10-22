//go:build linux

package privsep

// What root executes, and with what environment.
//
// sealed never runs a framework CLI as root. The only programs root runs
// are toolchain commands that must write root-owned prefixes (npm, git, uv,
// 0g-storage-client), and they go through RootCommand, which resolves the
// binary only in PATH directories that nothing but root can change, checks
// the binary's own path the same way, and gives it an environment fixed by
// sealed (the only values taken from the container's environment are proxy
// endpoints) whose temporary directory is root-only. Framework CLIs that
// read agent-writable state, and the process sweeps, run as the agent user
// through AgentCommand.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"seal-verify/internal/logger"
)

// rootHome is root's home directory. It stays root-owned (SecureHome); the
// agent owns only the framework trees inside it and has a home of its own
// (agentHomeDir, home.go).
const rootHome = "/root"

// StateDir holds sealed's own per-container state, root-owned 0700 and
// outside every tree handed to the agent user. framework.StateDir is a
// test-redirectable copy of it; RootCommand's temporary directory
// (rootTmpDir) and the bootstrap log (logger.LogPath) live under it.
const StateDir = "/var/lib/sealed"

// rootTmpDir is the TMPDIR every RootCommand gets: a root-only directory,
// so a toolchain (or a package lifecycle script it runs) that keeps fixed
// names under the temporary directory never works in one the agent user
// can also write, as the shared /tmp is. A var so tests can redirect it;
// production code never reassigns it.
var rootTmpDir = StateDir + "/tmp"

// netEnv is the network configuration RootCommand passes through from
// sealed's own environment when it is set: proxy endpoints, and nothing
// else. sealed's environment is the container's, which the deploy request
// sets, so it is not trusted to choose what root runs or trusts: package
// registry and index URLs (which pick the package whose install scripts
// root runs) and CA bundle locations (paths root's toolchains would open,
// and which could name an agent-writable file) are not passed. Those come
// only from the image (its trust store, and the toolchains' root-owned
// configuration). A proxy sees which hosts are contacted but cannot alter
// what is fetched over TLS, which the image's trust store still verifies.
// sealed's own connections follow the same rule (ScrubTrustEnv).
var netEnv = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "no_proxy",
}

// TrustedPATH returns the directories on sealed's PATH whose whole resolved
// path is owned by root and writable by nobody else, as resolved paths, in
// PATH order, without duplicates.
func TrustedPATH() []string {
	trusted, _ := trustedPATH(os.Getenv("PATH"))
	return trusted
}

// UntrustedPATH returns one line per PATH entry TrustedPATH leaves out and
// why, for the boot log.
func UntrustedPATH() []string {
	_, rejected := trustedPATH(os.Getenv("PATH"))
	return rejected
}

func trustedPATH(pathEnv string) (trusted, rejected []string) {
	seen := map[string]bool{}
	for _, d := range filepath.SplitList(pathEnv) {
		if d == "" {
			continue
		}
		if !filepath.IsAbs(d) {
			rejected = append(rejected, d+": relative entry")
			continue
		}
		real, err := filepath.EvalSymlinks(d)
		if err != nil {
			continue // a missing PATH entry is not worth a line
		}
		if err := rootOnly(real, unix.S_IFDIR); err != nil {
			rejected = append(rejected, fmt.Sprintf("%s: %v", d, err))
			continue
		}
		if !seen[real] {
			seen[real] = true
			trusted = append(trusted, real)
		}
	}
	return trusted, rejected
}

// rootOnly checks that the resolved path p has file type typ and that p and
// every directory above it are owned by root and not group- or
// other-writable. p must be absolute: a relative path has no directories
// above it to check (the walk would end at "." rather than "/"), so it is
// refused.
func rootOnly(p string, typ uint32) error {
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%q is not an absolute path", p)
	}
	p = filepath.Clean(p)
	for q := p; ; q = filepath.Dir(q) {
		var st unix.Stat_t
		if err := unix.Lstat(q, &st); err != nil {
			return err
		}
		if q == p && st.Mode&unix.S_IFMT != typ {
			return fmt.Errorf("%s has the wrong file type", q)
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			return fmt.Errorf("%s is a symbolic link", q)
		}
		if st.Uid != 0 {
			return fmt.Errorf("%s is owned by uid %d, not root", q, st.Uid)
		}
		if st.Mode&0o022 != 0 {
			return fmt.Errorf("%s is group- or other-writable (mode %#o)", q, st.Mode&0o7777)
		}
		if up := filepath.Dir(q); up == q {
			return nil // q is "/"
		}
	}
}

// LookPath resolves a bare command name in TrustedPATH and returns the
// binary's resolved path, which must itself be a root-owned executable
// regular file under root-only directories. Candidates that fail the check
// are skipped, not run.
func LookPath(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '/') {
		return "", fmt.Errorf("privsep: LookPath takes a bare command name, got %q", name)
	}
	trusted, rejected := trustedPATH(os.Getenv("PATH"))
	var skipped []string
	for _, dir := range trusted {
		real, err := filepath.EvalSymlinks(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if err := trustedExecutable(real); err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", filepath.Join(dir, name), err))
			continue
		}
		return real, nil
	}
	msg := fmt.Sprintf("%q not found in a root-only PATH directory", name)
	if len(skipped) > 0 {
		msg += "; skipped " + strings.Join(skipped, "; ")
	}
	if len(rejected) > 0 {
		msg += "; PATH entries not trusted: " + strings.Join(rejected, "; ")
	}
	return "", fmt.Errorf("privsep: %s: %w", msg, exec.ErrNotFound)
}

func trustedExecutable(real string) error {
	if err := rootOnly(real, unix.S_IFREG); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Stat(real, &st); err != nil {
		return err
	}
	if st.Mode&0o111 == 0 {
		return errors.New("not executable")
	}
	return nil
}

// RootCommand builds a command root runs: a toolchain binary resolved by
// LookPath (or an absolute path that passes the same check), with exactly
// PATH=<TrustedPATH>, HOME=/root and TMPDIR=<rootTmpDir> plus whichever of
// netEnv sealed has, and the root directory as its working directory.
// Callers may append fixed values to Env, none of which may name a path
// another uid can write (the root-side guard test admits only literals
// that name no path, or a listed helper's values: rootEnvHelpers), and
// change the working directory only through
// RootDir, which refuses one that is not root-only (a toolchain reads
// configuration from its working directory: .npmrc, .git/config). HOME
// stays /root on purpose: only root can write it (SecureHome), and it
// carries the toolchains' warm caches. It fails when the root-only
// temporary directory cannot be prepared, rather than falling back to the
// shared /tmp.
func RootCommand(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	path, err := resolveRoot(name)
	if err != nil {
		return nil, err
	}
	tmp, err := rootTemp()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Args[0] = name
	cmd.Env = rootEnv(tmp)
	cmd.Dir = "/"
	return cmd, nil
}

// RootDir sets the working directory of cmd, a RootCommand, to dir after
// checking that dir resolves to a directory which, with every directory
// above it, is owned by root and writable by nobody else.
func RootDir(cmd *exec.Cmd, dir string) error {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("privsep: resolve %s: %w", dir, err)
	}
	if err := rootOnly(real, unix.S_IFDIR); err != nil {
		return fmt.Errorf("privsep: %s is not a root-only directory: %w", dir, err)
	}
	cmd.Dir = real
	return nil
}

// rootTemp creates rootTmpDir if needed (without following links) and
// checks that it and every directory above it are root-only.
func rootTemp() (string, error) {
	if err := MkdirAll(rootTmpDir, 0o700); err != nil {
		return "", fmt.Errorf("privsep: preparing %s: %w", rootTmpDir, err)
	}
	if err := rootOnly(rootTmpDir, unix.S_IFDIR); err != nil {
		return "", fmt.Errorf("privsep: %s is not root-only: %w", rootTmpDir, err)
	}
	return rootTmpDir, nil
}

// TempDir creates a fresh directory under rootTmpDir for files root stages
// for, or receives from, a toolchain command (a storage download, an upload's
// input), and returns its path; the caller removes it. Nothing but root can
// enter it, so no other uid can create, replace or read a name inside it
// while the command runs, as it could in the shared /tmp.
func TempDir(pattern string) (string, error) {
	base, err := rootTemp()
	if err != nil {
		return "", err
	}
	return os.MkdirTemp(base, pattern)
}

func resolveRoot(name string) (string, error) {
	if !filepath.IsAbs(name) {
		return LookPath(name)
	}
	real, err := filepath.EvalSymlinks(name)
	if err != nil {
		return "", fmt.Errorf("privsep: resolve %s: %w", name, err)
	}
	if err := trustedExecutable(real); err != nil {
		return "", fmt.Errorf("privsep: %s is not a root-only executable: %w", name, err)
	}
	return real, nil
}

func rootEnv(tmp string) []string {
	env := []string{
		"PATH=" + strings.Join(TrustedPATH(), string(os.PathListSeparator)),
		"HOME=" + rootHome,
		"TMPDIR=" + tmp,
	}
	for _, k := range netEnv {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// AgentCommand builds a command that runs as the agent user (when the split
// is active): name is taken as-is when absolute, otherwise resolved by
// LookPath. The environment is minimal (PATH=<TrustedPATH>,
// HOME=<AgentHome>) and the working directory is the agent's home once
// PrepareAgentHome has made it (which Required demands before anything is
// provisioned), "/" otherwise; callers that spawn the framework replace the
// environment with their own allowlist, which carries the same HOME, and
// may set another directory the agent owns as Dir. Without the split the
// command runs as sealed.
func AgentCommand(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	path := name
	if !filepath.IsAbs(name) {
		p, err := LookPath(name)
		if err != nil {
			return nil, err
		}
		path = p
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Args[0] = name
	cmd.Env = []string{
		"PATH=" + strings.Join(TrustedPATH(), string(os.PathListSeparator)),
		"HOME=" + AgentHome(),
	}
	cmd.Dir = "/"
	if Drop(cmd) && agentHomeReady() {
		cmd.Dir = agentHomeDir
	}
	return cmd, nil
}

// Sweep SIGKILLs every process whose full command line matches pattern
// (pkill -9 -f, an extended regular expression). pkill runs as the agent
// user when the split is active, so it can reach only agent-uid processes,
// never root's; without it it runs as sealed. Adapters call it at the end
// of Stop for the framework's own processes (a self-restarted child the
// adapter does not track would otherwise hold the port against the next
// Start); the pattern must match the command line those processes actually
// have, which is not always the one they were started with (a framework
// may retitle itself, and an interpreter script runs under its
// interpreter). It does not end anything else the agent started, such as a
// backend it registered over the sign socket: those survive a framework
// restart. pkill's "no process matched" exit is the quiet case; other
// failures are logged.
func Sweep(pattern string) {
	ctx, cancel := context.WithTimeout(context.Background(), sweepTimeout)
	defer cancel()
	cmd, err := AgentCommand(ctx, "pkill", "-9", "-f", pattern)
	if err != nil {
		logger.Logf("privsep: sweep %q unavailable: %v", pattern, err)
		return
	}
	out, err := BoundedOutput(cmd, 4<<10)
	if err == nil {
		logger.Logf("privsep: swept leftover %q processes", pattern)
		return
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1 {
		return
	}
	logger.Logf("privsep: sweep %q: %v: %s", pattern, err, strings.TrimSpace(string(out)))
}

// sweepTimeout bounds one Sweep.
const sweepTimeout = 30 * time.Second

// BoundedOutput runs cmd to completion and returns its combined output,
// keeping at most the last max bytes of it. For commands whose output, or
// whose lifetime, depends on state the agent controls: cmd should come from
// AgentCommand or RootCommand built with a context that carries a deadline,
// and BoundedOutput sets a WaitDelay so that descendants left holding the
// output pipe cannot keep the call from returning once that deadline (or
// the command itself) ends.
func BoundedOutput(cmd *exec.Cmd, max int) ([]byte, error) {
	buf := &tailBuffer{max: max}
	cmd.Stdout = buf
	cmd.Stderr = buf
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = 5 * time.Second
	}
	err := cmd.Run()
	return buf.bytes(), err
}

// tailBuffer is an io.Writer that keeps only the last max bytes written.
type tailBuffer struct {
	mu   sync.Mutex
	max  int
	buf  []byte
	lost bool
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.max; over > 0 {
		t.buf = append(t.buf[:0], t.buf[over:]...)
		t.lost = true
	}
	return len(p), nil
}

func (t *tailBuffer) bytes() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.lost {
		return append([]byte("…"), t.buf...)
	}
	return append([]byte(nil), t.buf...)
}
