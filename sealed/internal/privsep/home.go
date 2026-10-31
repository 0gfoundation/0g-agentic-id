//go:build linux

package privsep

// The two homes.
//
// Root's home (/root) stays root:root 0711, with no POSIX ACL: the agent
// can traverse it to reach the framework trees handed to it, but cannot
// list it or create, rename or replace anything directly in it — in
// particular not the toolchain configuration and caches root's commands
// use from there. A container an earlier sealed ran may still hold entries
// the agent made there while that sealed let it own /root (or a default
// ACL it set on /root, which root's later entries inherited); ReclaimHome
// moves them out at boot (into the agent's home), so root's commands never
// pick them up.
//
// The agent has a home of its own, agentHomeDir (/home/agent, agent:agent
// 0700), which is HOME for everything it runs and the default working
// directory of AgentCommand. (The prime bridge and 0g-harness deliberately start
// in their framework tree instead, as their spawn.go explains, so relative
// paths of the tools they run resolve inside that tree.) Tools keep their
// per-user caches and configuration there (~/.npm, ~/.cache, ~/.config,
// ~/.local, ~/.gitconfig, ...) and the agent's own files go there. Root
// never reads anything under it. The
// framework trees stay where the platform keeps them (/root/.openclaw,
// /root/.hermes, ...: the paths are chain- and doc-visible), and each
// adapter links its tree into the agent's home (LinkAgentHome), so the
// paths the agent was told about ("~/.openclaw/workspace/...") keep naming
// the same files. An adapter whose framework locates its tree from HOME
// also names the tree in the framework's environment (HERMES_HOME,
// OPENCLAW_STATE_DIR and OPENCLAW_HOME, ...), so that the framework's
// config, state and workspace are never found through the link. (A few
// openclaw plugins take their default locations from HOME regardless and
// do reach the tree through it; the openclaw adapter and QUIRKS.md say how
// that is handled.) sealed itself never resolves the link.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"seal-verify/internal/logger"
)

// agentHomeDir is the agent user's home directory. A var so tests can
// redirect it; production code never reassigns it.
var agentHomeDir = "/home/agent"

// AgentHome is the HOME of everything started through AgentCommand: the
// agent's own home when the split is active, root's home otherwise (the
// framework then shares sealed's uid, and sealed never provisions).
// Adapters put the same value in their spawn environment.
func AgentHome() string {
	if credential() != nil {
		return agentHomeDir
	}
	return rootHome
}

var (
	homeMu      sync.Mutex
	homeSecured bool  // SecureHome succeeded
	homeErr     error // SecureHome's last error
	agentReady  bool  // PrepareAgentHome succeeded
	agentErr    error // PrepareAgentHome's last error
	reclaimed   bool  // ReclaimHome succeeded
	reclaimErr  error // ReclaimHome's last error

	noNewPrivs    bool  // HardenSelf set no_new_privs
	noNewPrivsErr error // its error
)

var (
	treesMu   sync.Mutex
	declared  []string          // DeclareTree
	relocated map[string]string // DeclareRelocation: name in root's home → destination
)

// DeclareTree records a tree an adapter hands to the agent user (OwnTree)
// inside root's home: ReclaimHome leaves it where it is, although the agent
// owns it. A directory between root's home and a tree declared deeper
// inside it (prime's /root/.prime, above /root/.prime/agent) stays too, but
// is root's: ReclaimHome makes it so if another uid could have changed it.
// Adapters declare their trees when they register (New), which main does
// before Harden.
func DeclareTree(p string) {
	treesMu.Lock()
	defer treesMu.Unlock()
	declared = append(declared, filepath.Clean(p))
}

// DeclareRelocation records where ReclaimHome moves the entry at from — a
// name directly in root's home that an earlier sealed let the agent make,
// and that the framework now expects elsewhere — instead of into the
// agent's home: to, an absolute path inside a tree the adapter declares
// (DeclareTree), whose parent directory must exist. The move is a rename
// that follows no link and replaces nothing (RenameNoReplace); when it
// cannot be made (nothing at the destination's parent, or something
// already at the destination), the entry goes into the agent's home like
// any other. Adapters declare relocations when they register (New), with
// their trees.
func DeclareRelocation(from, to string) {
	treesMu.Lock()
	defer treesMu.Unlock()
	if relocated == nil {
		relocated = map[string]string{}
	}
	relocated[filepath.Clean(from)] = filepath.Clean(to)
}

// relocations returns the declared relocations whose source is directly in
// home, by name.
func relocations(home string) map[string]string {
	treesMu.Lock()
	defer treesMu.Unlock()
	out := map[string]string{}
	for from, to := range relocated {
		if filepath.Dir(from) == home && filepath.IsAbs(to) {
			out[filepath.Base(from)] = to
		}
	}
	return out
}

// declaredTrees returns the declared trees inside home, as clean paths
// relative to it (".openclaw", ".prime/agent"), sorted.
func declaredTrees(home string) []string {
	treesMu.Lock()
	defer treesMu.Unlock()
	var out []string
	for _, p := range declared {
		rel, err := filepath.Rel(home, p)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
			continue
		}
		out = append(out, rel)
	}
	sort.Strings(out)
	return out
}

// SecureHome makes root's home owned by root:root with mode 0711 and no
// POSIX ACL: the agent user can traverse it to reach the framework trees
// handed to it, but cannot list it or create, rename or replace anything
// directly inside it — in particular not the toolchains root runs from
// there. The ACLs go because chown and chmod leave them in place: a default
// ACL an earlier owner set would hand every entry root later creates in
// the home to whoever it names (the umask does not apply under one), and an
// access ACL keeps its named entries. Harden calls it at boot when the
// split is active. Required refuses until it has succeeded, so a container
// whose home could not be secured, or in which it never ran, is never
// provisioned.
func SecureHome() error {
	err := secureHome(rootHome)
	homeMu.Lock()
	homeErr = err
	homeSecured = err == nil
	homeMu.Unlock()
	if err != nil {
		logger.Logf("privsep: securing %s: %v", rootHome, err)
	}
	return err
}

func secureHome(home string) error {
	return secureDir("securehome", home, 0o711)
}

// secureDir makes the directory at path (refused if it is a link, never
// followed) root's: no POSIX ACL, owner root:root, mode perm, each applied
// through the directory's own descriptor. A filesystem without ACL support
// has none to remove.
func secureDir(op, path string, perm uint32) error {
	pfd, base, err := openParent(op, path)
	if err != nil {
		return err
	}
	defer unix.Close(pfd)
	fd, err := openat(pfd, base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return classify(pfd, base, op, path, err)
	}
	defer unix.Close(fd)
	for _, attr := range []string{aclDefaultXattr, aclAccessXattr} {
		if err := unix.Fremovexattr(fd, attr); err != nil && err != unix.ENODATA && err != unix.EOPNOTSUPP {
			return pathErr(op, path, fmt.Errorf("removing %s: %w", attr, err))
		}
	}
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return pathErr(op, path, err)
	}
	if err := unix.Fchmod(fd, perm); err != nil {
		return pathErr(op, path, err)
	}
	return nil
}

// PrepareAgentHome makes the agent's home: its parent (/home) is created
// root:root 0755 if absent, and the home itself is created, or an existing
// one taken over, as agent:agent 0700. Neither may be a symbolic link
// (refused, never followed). Harden calls it at boot when the split is
// active; Required refuses until it has succeeded, because everything the
// agent runs starts in that directory.
func PrepareAgentHome() error {
	c := credential()
	if c == nil {
		return errors.New("privsep unavailable")
	}
	err := prepareAgentHome(agentHomeDir, c.Uid, c.Gid)
	homeMu.Lock()
	agentErr = err
	agentReady = err == nil
	homeMu.Unlock()
	if err != nil {
		logger.Logf("privsep: preparing the agent's home %s: %v", agentHomeDir, err)
	}
	return err
}

func prepareAgentHome(home string, uid, gid uint32) error {
	if err := checkLeaf("mkdir", home); err != nil {
		return err
	}
	if err := ensureDir(filepath.Dir(home), 0o755, 0, 0, false); err != nil {
		return err
	}
	return ensureDir(home, 0o700, uid, gid, true)
}

// ensureDir makes dir (whose parent must exist) a real directory: when
// absent it is created with mode perm and owner uid:gid; when present it
// must not be a link, and with fix set it is given that owner and mode too.
// Both are applied through the directory's own descriptor.
func ensureDir(dir string, perm, uid, gid uint32, fix bool) error {
	pfd, base, err := openParent("mkdir", dir)
	if err != nil {
		return err
	}
	defer unix.Close(pfd)
	created := false
	switch err := unix.Mkdirat(pfd, base, perm); err {
	case nil:
		created = true
	case unix.EEXIST:
	default:
		return pathErr("mkdir", dir, err)
	}
	fd, err := openat(pfd, base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return classify(pfd, base, "mkdir", dir, err)
	}
	defer unix.Close(fd)
	if !created && !fix {
		return nil
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return pathErr("mkdir", dir, err)
	}
	if st.Uid != uid || st.Gid != gid {
		if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
			return pathErr("mkdir", dir, err)
		}
	}
	if st.Mode&0o7777 != perm {
		if err := unix.Fchmod(fd, perm); err != nil {
			return pathErr("mkdir", dir, err)
		}
	}
	return nil
}

// LinkAgentHome makes name, relative to the agent's home, a symbolic link
// to target: an adapter links its framework tree (an absolute path under
// root's home) into the agent's home, so the paths the agent knows
// ("~/.openclaw/...") keep naming that tree. name may have several
// components (".prime/agent"); directories above the link are created
// agent-owned. An entry already at name is left as it is (and logged once)
// unless it is that same link: the agent's home is the agent's to arrange.
// Best-effort and a no-op without the split. Root never resolves these
// links; its own code uses the absolute paths.
func LinkAgentHome(name, target string) {
	if credential() == nil {
		return
	}
	if !agentHomeReady() {
		logger.Once("privsep.link:"+name, "privsep: not linking ~/%s: the agent's home was not prepared", name)
		return
	}
	if err := linkAgentHome(agentHomeDir, name, target); err != nil {
		logger.Once("privsep.link:"+name, "privsep: linking ~/%s to %s: %v", name, target, err)
	}
}

func linkAgentHome(home, name, target string) error {
	if name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") {
		return fmt.Errorf("link name %q must be a clean relative path", name)
	}
	if !filepath.IsAbs(target) {
		return fmt.Errorf("link target %q must be absolute", target)
	}
	p := filepath.Join(home, name)
	if dir := filepath.Dir(p); dir != home {
		// Created inside the agent's home, so they take its owner.
		if err := MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	pfd, base, err := openParent("symlink", p)
	if err != nil {
		return err
	}
	defer unix.Close(pfd)
	err = unix.Symlinkat(target, pfd, base)
	if err == nil {
		return nil
	}
	if err != unix.EEXIST {
		return pathErr("symlink", p, err)
	}
	buf := make([]byte, 4096)
	if n, rerr := unix.Readlinkat(pfd, base, buf); rerr == nil && string(buf[:n]) == target {
		return nil
	}
	return pathErr("symlink", p, errors.New("another entry is already there; left as it is"))
}

// ReclaimHome moves out of root's home every entry directly in it that
// another uid could have changed — one not owned by root, or (a link
// aside) writable by a group other than root's or by others, or carrying a
// POSIX ACL that lets another uid write it or, on a directory, what root
// later creates in it (otherWritable) — except an adapter's declared
// framework tree (DeclareTree), which is the agent's by design. Such
// entries exist only in a container an earlier sealed ran, which let the
// agent own /root: anything it made there (~/.npmrc, ~/.gitconfig,
// ~/.config, ~/.local, ...), and anything root made there under a default
// ACL the agent set on /root, would otherwise stay where root's commands
// read their configuration, caches and interpreters from, and stay
// writable by the agent through it. Each is moved, without following a
// link, into the agent's home under its own name (or name.from-root,
// name.from-root-2, ... when that is taken), so the agent keeps what it
// made — or, for an entry an adapter declared a relocation for
// (DeclareRelocation), to where its framework now expects it. A directory
// that only leads to a tree declared deeper inside root's home (prime's
// /root/.prime) is not the agent's: it stays where it is, made root's
// (root:root 0755, no ACL) if another uid could have changed it, so the
// agent cannot rename or replace the tree inside it, and what else it
// holds is reclaimed the same way. Harden runs it after SecureHome and
// PrepareAgentHome; Required refuses to provision while an entry could not
// be moved or made root's.
func ReclaimHome() error {
	if credential() == nil {
		return errors.New("privsep unavailable")
	}
	err := reclaimHome(rootHome, agentHomeDir, declaredTrees(rootHome), relocations(rootHome))
	homeMu.Lock()
	reclaimErr = err
	reclaimed = err == nil
	homeMu.Unlock()
	if err != nil {
		logger.Logf("privsep: %v", err)
	}
	return err
}

// maxReclaimNames bounds the alternative names tried for one moved entry.
const maxReclaimNames = 20

// reclaimHome is ReclaimHome on home, with trees the declared trees inside
// it (relative paths) and relocate the declared relocations by name.
func reclaimHome(home, agentHome string, trees []string, relocate map[string]string) error {
	var failed []string
	if err := reclaimDir(home, agentHome, trees, relocate, &failed); err != nil {
		return err
	}
	if len(failed) > 0 {
		return fmt.Errorf("%s holds entries another uid could have changed, which root's commands would pick up, and they could not be moved out or made root's: %s; remove them from the container (or recreate it)", home, strings.Join(failed, "; "))
	}
	return nil
}

// reclaimDir reclaims the entries of dir — root's home, or a directory in
// it that leads to a declared tree — with trees the declared trees below
// dir (relative to it) and relocate the relocations declared by name in
// dir. What could not be moved or secured is added to failed.
func reclaimDir(dir, agentHome string, trees []string, relocate map[string]string, failed *[]string) error {
	own := map[string]bool{}       // names that are declared trees
	below := map[string][]string{} // names that lead to trees declared deeper, with those trees relative to them
	for _, rel := range trees {
		if first, rest, nested := strings.Cut(rel, "/"); nested {
			below[first] = append(below[first], rest)
		} else {
			own[first] = true
		}
	}
	ents, err := ReadDir(dir)
	if err != nil {
		return fmt.Errorf("listing %s: %w", dir, err)
	}
	for _, e := range ents {
		name, st := e.Name(), e.st
		p := filepath.Join(dir, name)
		typ := st.Mode & unix.S_IFMT
		_, leads := below[name]
		if own[name] && typ == unix.S_IFDIR {
			continue // a declared tree: the agent's by design
		}
		foreign, why := otherWritable(p, &st)
		if leads && !own[name] && typ == unix.S_IFDIR {
			// Only leads to a declared tree: root's, like root's home, so
			// the agent cannot rename or replace the tree in it. Secured in
			// place rather than moved, which would take the tree (and what
			// the image baked into it) along.
			if foreign {
				if err := secureDir("reclaim", p, 0o755); err != nil {
					*failed = append(*failed, fmt.Sprintf("%q (uid %d, mode %#o%s): %v", p, st.Uid, st.Mode&0o7777, why, err))
					continue
				}
				logger.Logf("privsep: made %q (uid %d, mode %#o%s), which leads to a framework tree, root's (root:root 0755)", p, st.Uid, st.Mode&0o7777, why)
			}
			if err := reclaimDir(p, agentHome, below[name], nil, failed); err != nil {
				*failed = append(*failed, err.Error())
			}
			continue
		}
		if !foreign {
			continue
		}
		// An entry the framework now expects elsewhere goes there
		// (DeclareRelocation), when that can be done without replacing
		// anything.
		if to, ok := relocate[name]; ok && !own[name] && !leads {
			err := RenameNoReplace(p, to)
			if err == nil {
				logger.Logf("privsep: moved %q (uid %d, mode %#o%s), which an earlier sealed let the agent leave in root's home, to %q, where the framework now keeps it", p, st.Uid, st.Mode&0o7777, why, to)
				continue
			}
			logger.Logf("privsep: could not move %q to %q (%v); moving it into the agent's home instead", p, to, err)
		}
		// A declared name that is not a directory is moved too (restore
		// makes the tree anew), but not to its own name in the agent's
		// home, where LinkAgentHome puts the link to the tree.
		dest, err := moveInto(p, agentHome, name, own[name] || leads)
		if err != nil {
			*failed = append(*failed, fmt.Sprintf("%q (uid %d, mode %#o%s): %v", p, st.Uid, st.Mode&0o7777, why, err))
			continue
		}
		logger.Logf("privsep: moved %q (uid %d, mode %#o%s), which another uid could have changed, out of root's home to %q", p, st.Uid, st.Mode&0o7777, why, dest)
	}
	return nil
}

// foreignWritable reports whether an entry another uid than root could have
// made or changed, by its owner and mode: not owned by root, or (for
// anything but a link, whose mode means nothing) writable by others or by
// a group other than root's. ACLs are otherWritable's.
func foreignWritable(st *unix.Stat_t) bool {
	if st.Uid != 0 {
		return true
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return false
	}
	return st.Mode&0o002 != 0 || (st.Mode&0o020 != 0 && st.Gid != 0)
}

// otherWritable is foreignWritable extended to POSIX ACLs. With an access
// ACL, a mode's group bits are the ACL's mask, not the owning group's
// permissions, so a root:root entry whose group bits allow writing can
// still be writable by a user the ACL names; and a directory's default ACL
// is inherited by every entry created in it, with the umask ignored, so a
// root-only directory can still hand what root later creates in it to
// another uid. Either counts, as does an ACL that cannot be read (a link
// carries none). why describes an ACL found, for the log.
func otherWritable(p string, st *unix.Stat_t) (foreign bool, why string) {
	if foreignWritable(st) {
		return true, ""
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return false, ""
	}
	attr, err := foreignACL(p, st)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, ""
	case err != nil:
		return true, fmt.Sprintf(", ACL unreadable: %v", err)
	case attr != "":
		return true, ", its " + attr + " lets another uid write"
	}
	return false, ""
}

// POSIX ACLs as the kernel keeps them in extended attributes: a
// little-endian version word, then 8-byte entries (tag, permissions, id).
const (
	aclAccessXattr  = "system.posix_acl_access"
	aclDefaultXattr = "system.posix_acl_default"
	aclXattrVersion = 2
	aclTagUser      = 0x02
	aclTagGroupObj  = 0x04
	aclTagGroup     = 0x08
	aclTagMask      = 0x10
	aclTagOther     = 0x20
	aclPermWrite    = 0x02
	aclXattrMax     = 64 << 10 // XATTR_SIZE_MAX
)

// foreignACL returns the name of the ACL on p (not a link: the entry is
// opened O_PATH without following one, and its xattrs read through that
// descriptor) that lets another uid than root write — p itself, for its
// access ACL, or what is created in it, for a directory's default ACL — or
// "" when there is none.
func foreignACL(p string, st *unix.Stat_t) (string, error) {
	pfd, base, err := openParent("getxattr", p)
	if err != nil {
		return "", err
	}
	defer unix.Close(pfd)
	fd, err := openat(pfd, base, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", classify(pfd, base, "getxattr", p, err)
	}
	defer unix.Close(fd)
	var fst unix.Stat_t
	if err := unix.Fstat(fd, &fst); err != nil {
		return "", pathErr("getxattr", p, err)
	}
	if fst.Dev != st.Dev || fst.Ino != st.Ino {
		return "", pathErr("getxattr", p, errors.New("the entry changed while it was checked"))
	}
	proc := fmt.Sprintf("/proc/self/fd/%d", fd)
	buf := make([]byte, aclXattrMax)
	for _, attr := range []string{aclAccessXattr, aclDefaultXattr} {
		n, err := unix.Getxattr(proc, attr, buf)
		switch {
		case err == unix.ENODATA || err == unix.EOPNOTSUPP:
			continue
		case err != nil:
			// Not the entry's absence (that open succeeded): an ACL that
			// cannot be read counts as one that grants write.
			return "", pathErr("getxattr", p, fmt.Errorf("reading %s through %s: %v", attr, proc, err))
		}
		if aclGrantsWrite(buf[:n], fst.Gid) {
			return attr, nil
		}
	}
	return "", nil
}

// aclGrantsWrite reports whether an ACL in its extended-attribute form lets
// anyone but root write: a user or group it names other than root's, or
// the owning group (gid) when that is not root's — each only as far as the
// mask lets it — or others. One that does not parse counts as granting it.
func aclGrantsWrite(b []byte, gid uint32) bool {
	if len(b) < 4 || binary.LittleEndian.Uint32(b) != aclXattrVersion || (len(b)-4)%8 != 0 {
		return true
	}
	maskWrite := true // an ACL without a mask names no user or group
	for i := 4; i < len(b); i += 8 {
		if binary.LittleEndian.Uint16(b[i:]) == aclTagMask {
			maskWrite = binary.LittleEndian.Uint16(b[i+2:])&aclPermWrite != 0
		}
	}
	for i := 4; i < len(b); i += 8 {
		tag := binary.LittleEndian.Uint16(b[i:])
		write := binary.LittleEndian.Uint16(b[i+2:])&aclPermWrite != 0
		id := binary.LittleEndian.Uint32(b[i+4:])
		switch tag {
		case aclTagUser, aclTagGroup:
			if write && maskWrite && id != 0 {
				return true
			}
		case aclTagGroupObj:
			if write && maskWrite && gid != 0 {
				return true
			}
		case aclTagOther:
			if write {
				return true
			}
		}
	}
	return false
}

// moveInto renames src into dir under name (unless skipOwn), or the first
// free alternative name, without replacing anything there.
func moveInto(src, dir, name string, skipOwn bool) (string, error) {
	start := 0
	if skipOwn {
		start = 1
	}
	for i := start; i < maxReclaimNames; i++ {
		cand := name
		switch {
		case i == 1:
			cand = name + ".from-root"
		case i > 1:
			cand = fmt.Sprintf("%s.from-root-%d", name, i)
		}
		dest := filepath.Join(dir, cand)
		err := RenameNoReplace(src, dest)
		if err == nil {
			return dest, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	return "", fmt.Errorf("no free name for it in %s", dir)
}

// agentHomeReady reports whether PrepareAgentHome has succeeded.
func agentHomeReady() bool {
	homeMu.Lock()
	defer homeMu.Unlock()
	return agentReady
}

// homeState reports whether SecureHome and PrepareAgentHome have
// succeeded, with their last errors.
func homeState() (secured bool, secErr error, ready bool, prepErr error) {
	homeMu.Lock()
	defer homeMu.Unlock()
	return homeSecured, homeErr, agentReady, agentErr
}

// reclaimState reports whether ReclaimHome has succeeded, with its last
// error.
func reclaimState() (bool, error) {
	homeMu.Lock()
	defer homeMu.Unlock()
	return reclaimed, reclaimErr
}

// Harden is sealed's boot-time hardening, run once from main before
// anything else (after the adapters have registered, and so declared their
// trees): sealed's own CA locations are checked (ScrubTrustEnv), the
// process becomes non-dumpable (HardenSelf), and when the split is active
// root's home is made root-only (SecureHome), the agent's own home is
// prepared (PrepareAgentHome), what an earlier sealed let the agent leave
// in root's home is moved out (ReclaimHome) and the PATH entries
// RootCommand will not use are logged. A failure is recorded, not fatal
// here: Required, checked before provisioning, refuses until both homes
// are in place and root's home has been reclaimed, so a boot path that
// skips Harden fails closed.
func Harden() {
	harden(scrubOwnEnv, Active, HardenSelf, SecureHome, PrepareAgentHome, ReclaimHome, UntrustedPATH)
}

// scrubOwnEnv checks the path-valued variables of sealed's own environment
// that its own process reads: the time zone (ScrubTimeEnv), then the CA
// locations (ScrubTrustEnv). Neither logs, so both are done before the
// first log line, which is what first uses the time zone.
func scrubOwnEnv() []string {
	return append(ScrubTimeEnv(), ScrubTrustEnv()...)
}

// harden is Harden with its steps injected, so a test can check that each
// runs, in order. The environment checks run first, with or without the
// split: they are about sealed's own process, not the agent's, and the
// time zone must be settled before the first log line.
func harden(scrub func() []string, active func() bool, self func(), secure, prepare, reclaim func() error, untrusted func() []string) {
	for _, line := range scrub() {
		logger.Logf("privsep: %s", line)
	}
	self()
	if !active() {
		return
	}
	_ = secure()
	_ = prepare()
	_ = reclaim()
	for _, line := range untrusted() {
		logger.Logf("privsep: PATH entry not used for root-run commands: %s", line)
	}
}
