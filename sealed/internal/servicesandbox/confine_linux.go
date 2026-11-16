//go:build linux

package servicesandbox

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	fsReadExec = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	fsReadOnly = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	fsSocket   = unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE
	// Rights that may sit on a rule for a file rather than a directory.
	fsFileRights = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_TRUNCATE | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
)

// handledFS is every filesystem right the running kernel's ABI knows, so the
// domain refuses whatever no rule grants.
func handledFS(abi int) uint64 {
	fs := uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if abi >= 2 {
		fs |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		fs |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 {
		fs |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	return fs
}

// ABI returns the kernel's Landlock ABI, or an error when Landlock is not
// built in, disabled at boot or refused by the container's seccomp policy.
func ABI() (int, error) {
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0, fmt.Errorf("landlock unavailable: %w", errno)
	}
	return int(v), nil
}

type ruleset struct {
	fd  int
	abi int
}

func newRuleset(abi int) (*ruleset, error) {
	attr := unix.LandlockRulesetAttr{
		Access_fs:  handledFS(abi),
		Access_net: unix.LANDLOCK_ACCESS_NET_BIND_TCP | unix.LANDLOCK_ACCESS_NET_CONNECT_TCP,
		Scoped:     unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | unix.LANDLOCK_SCOPE_SIGNAL,
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return nil, fmt.Errorf("landlock ruleset: %w", errno)
	}
	return &ruleset{fd: int(fd), abi: abi}, nil
}

// allow grants access below path. The launcher runs as root here, so it opens
// even paths the service identity cannot traverse; O_NOFOLLOW keeps a final
// link from redirecting the rule.
func (r *ruleset) allow(path string, access uint64) error {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	access &= handledFS(r.abi)
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		access &= fsFileRights
	}
	attr := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(fd)}
	if _, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(r.fd), unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&attr)), 0, 0, 0); errno != 0 {
		return fmt.Errorf("landlock rule %s: %w", path, errno)
	}
	return nil
}

func (r *ruleset) restrictSelf() error {
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(r.fd), 0, 0); errno != 0 {
		return fmt.Errorf("landlock restrict: %w", errno)
	}
	return nil
}

func buildRuleset(p Policy, abi int) (*ruleset, error) {
	r, err := newRuleset(abi)
	if err != nil {
		return nil, err
	}
	all := handledFS(abi) &^ (unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK)
	device := uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_TRUNCATE)
	groups := []struct {
		paths  []string
		access uint64
	}{{p.ReadExec, fsReadExec}, {p.ReadOnly, fsReadOnly}, {p.Devices, device}, {p.SocketDirs, fsSocket}, {p.ReadWrite, all}}
	for _, g := range groups {
		for _, path := range g.paths {
			if err := r.allow(path, g.access); err != nil {
				unix.Close(r.fd)
				return nil, err
			}
		}
	}
	return r, nil
}

var auditArch = map[string]uint32{"amd64": unix.AUDIT_ARCH_X86_64, "arm64": unix.AUDIT_ARCH_AARCH64}

// x32Bit marks x32 system calls on amd64. They arrive with AUDIT_ARCH_X86_64
// but their own numbers, so the filter refuses the whole x32 range.
const x32Bit = 0x40000000

// refusedCalls fail with EPERM in a service process:
//   - io_uring, which could open sockets without socket(2);
//   - System V IPC and POSIX message queues, whose objects belong to the
//     whole sandbox and outlive the processes that created them;
//   - kernel keyrings, which belong to a UID and so would reach the next task
//     that draws the same identity.
var refusedCalls = []uint32{
	unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
	unix.SYS_SHMGET, unix.SYS_SHMAT, unix.SYS_SHMCTL, unix.SYS_SHMDT,
	unix.SYS_MSGGET, unix.SYS_MSGSND, unix.SYS_MSGRCV, unix.SYS_MSGCTL,
	unix.SYS_SEMGET, unix.SYS_SEMOP, unix.SYS_SEMCTL, unix.SYS_SEMTIMEDOP,
	unix.SYS_MQ_OPEN, unix.SYS_MQ_UNLINK, unix.SYS_MQ_TIMEDSEND, unix.SYS_MQ_TIMEDRECEIVE, unix.SYS_MQ_NOTIFY, unix.SYS_MQ_GETSETATTR,
	unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY, unix.SYS_KEYCTL,
}

// bpf assembles a classic BPF program with forward jumps to named labels.
type bpf struct {
	prog   []unix.SockFilter
	jumps  []bpfJump
	labels map[string]int
}

type bpfJump struct {
	at     int
	jt, jf string // "" falls through
}

func (b *bpf) stmt(code uint16, k uint32) {
	b.prog = append(b.prog, unix.SockFilter{Code: code, K: k})
}

func (b *bpf) jump(code uint16, k uint32, jt, jf string) {
	b.jumps = append(b.jumps, bpfJump{at: len(b.prog), jt: jt, jf: jf})
	b.stmt(code, k)
}

func (b *bpf) label(name string) { b.labels[name] = len(b.prog) }

func (b *bpf) assemble() ([]unix.SockFilter, error) {
	for _, j := range b.jumps {
		for _, t := range []struct {
			label string
			off   *uint8
		}{{j.jt, &b.prog[j.at].Jt}, {j.jf, &b.prog[j.at].Jf}} {
			if t.label == "" {
				continue
			}
			to, ok := b.labels[t.label]
			if !ok || to <= j.at || to-j.at-1 > 255 {
				return nil, fmt.Errorf("seccomp jump to %q", t.label)
			}
			*t.off = uint8(to - j.at - 1)
		}
	}
	return b.prog, nil
}

// serviceFilter allows sockets only of family AF_UNIX (the sockets sealed
// hands the service), refuses refusedCalls and every x32 call, and answers
// fallocate with EOPNOTSUPP: fallocate can reserve blocks past RLIMIT_FSIZE
// without growing the file, while callers such as glibc's posix_fallocate fall
// back to writes, which RLIMIT_FSIZE bounds. clone with CLONE_PARENT is
// refused: its child would be sealed's, which never waits for it, so once
// killed it would stay a zombie counting against the identity's
// RLIMIT_NPROC. clone3 answers ENOSYS (its flags are out of the filter's
// reach), so libc falls back to clone, as under Docker's default profile.
// Any other architecture is killed.
func serviceFilter() ([]unix.SockFilter, error) {
	arch, ok := auditArch[runtime.GOARCH]
	if !ok {
		return nil, fmt.Errorf("unsupported architecture %s", runtime.GOARCH)
	}
	const (
		ld   = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeq  = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		jge  = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
		jset = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
		ret  = unix.BPF_RET | unix.BPF_K
		nr   = 0  // offsetof(struct seccomp_data, nr)
		arc  = 4  // offsetof(struct seccomp_data, arch)
		arg0 = 16 // low word of args[0] (little endian)
	)
	b := &bpf{labels: map[string]int{}}
	b.stmt(ld, arc)
	b.jump(jeq, arch, "", "kill")
	b.stmt(ld, nr)
	if runtime.GOARCH == "amd64" {
		b.jump(jge, x32Bit, "deny", "")
	}
	for _, n := range refusedCalls {
		b.jump(jeq, n, "deny", "")
	}
	b.jump(jeq, unix.SYS_FALLOCATE, "unsupported", "")
	b.jump(jeq, unix.SYS_CLONE3, "nosys", "")
	b.jump(jeq, unix.SYS_CLONE, "clone", "")
	b.jump(jeq, unix.SYS_SOCKET, "family", "")
	b.jump(jeq, unix.SYS_SOCKETPAIR, "family", "allow")
	b.label("clone")
	b.stmt(ld, arg0) // clone's flags, on amd64 and arm64 alike
	b.jump(jset, unix.CLONE_PARENT, "deny", "allow")
	b.label("family")
	b.stmt(ld, arg0)
	b.jump(jeq, unix.AF_UNIX, "allow", "deny")
	b.label("allow")
	b.stmt(ret, unix.SECCOMP_RET_ALLOW)
	b.label("deny")
	b.stmt(ret, unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM))
	b.label("unsupported")
	b.stmt(ret, unix.SECCOMP_RET_ERRNO|uint32(unix.EOPNOTSUPP))
	b.label("nosys")
	b.stmt(ret, unix.SECCOMP_RET_ERRNO|uint32(unix.ENOSYS))
	b.label("kill")
	b.stmt(ret, unix.SECCOMP_RET_KILL_PROCESS)
	return b.assemble()
}

func installServiceFilter() error {
	filter, err := serviceFilter()
	if err != nil {
		return err
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&prog))); errno != 0 {
		return fmt.Errorf("seccomp: %w", errno)
	}
	return nil
}

// dropTo leaves root for uid with no supplementary groups. Go applies the
// credential calls to every thread.
func dropTo(uid uint32) error {
	if err := syscall.Setgroups(nil); err != nil {
		return err
	}
	if err := syscall.Setgid(int(uid)); err != nil {
		return err
	}
	if err := syscall.Setuid(int(uid)); err != nil {
		return err
	}
	if os.Getuid() != int(uid) || os.Geteuid() != int(uid) || os.Getgid() != int(uid) || os.Getegid() != int(uid) {
		return errors.New("identity did not change")
	}
	return nil
}

// applyLimits lowers the rlimits after the identity drop (lowering needs no
// privilege). RLIMIT_NPROC then counts only this identity's processes.
func applyLimits(l Limits) error {
	set := func(resource int, v uint64) error {
		if v == 0 {
			return nil
		}
		return unix.Setrlimit(resource, &unix.Rlimit{Cur: v, Max: v})
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return fmt.Errorf("rlimit core: %w", err)
	}
	for _, r := range []struct {
		resource int
		value    uint64
		name     string
	}{{unix.RLIMIT_AS, l.AddressSpace, "as"}, {unix.RLIMIT_NPROC, l.Processes, "nproc"}, {unix.RLIMIT_NOFILE, l.Files, "nofile"}, {unix.RLIMIT_FSIZE, l.FileSize, "fsize"}} {
		if err := set(r.resource, r.value); err != nil {
			return fmt.Errorf("rlimit %s: %w", r.name, err)
		}
	}
	return nil
}

// demote sets nice 19 on the calling thread, which execve keeps, and takes
// away the right to lower it again (RLIMIT_NICE 0). It orders service
// processes only where the kernel applies nice between them and sealed or the
// owner; on the dev runner (autogroup on, a CPU quota) a nice-19 process in
// its own session got as much CPU as a nice-0 one.
func demote() error {
	if err := unix.Setrlimit(unix.RLIMIT_NICE, &unix.Rlimit{}); err != nil {
		return fmt.Errorf("rlimit nice: %w", err)
	}
	if err := unix.Setpriority(unix.PRIO_PROCESS, 0, 19); err != nil {
		return fmt.Errorf("nice: %w", err)
	}
	return nil
}

// confine applies the whole policy to the calling thread and process. The
// caller must have locked the goroutine to its OS thread: no_new_privs,
// Landlock and seccomp attach to the thread that later calls execve.
func confine(p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	abi, err := ABI()
	if err != nil {
		return err
	}
	if abi < MinABI {
		return fmt.Errorf("landlock ABI %d, need %d (abstract socket and signal scoping)", abi, MinABI)
	}
	// Raise before dropping root, so the kernel's OOM killer picks a service
	// process before sealed. Landlock then keeps /proc out of reach, so the
	// service cannot lower it again.
	if err := os.WriteFile("/proc/self/oom_score_adj", []byte("1000"), 0); err != nil {
		return fmt.Errorf("oom_score_adj: %w", err)
	}
	r, err := buildRuleset(p, abi)
	if err != nil {
		return err
	}
	defer unix.Close(r.fd)
	if err := dropTo(p.UID); err != nil {
		return err
	}
	if err := applyLimits(p.Limits); err != nil {
		return err
	}
	if err := demote(); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	if err := r.restrictSelf(); err != nil {
		return err
	}
	if err := installServiceFilter(); err != nil {
		return err
	}
	if _, err := unix.Setsid(); err != nil {
		return err
	}
	return unix.Chdir(p.Dir)
}

// Run confines the calling process and executes the service program. It
// returns only on failure.
func Run(p Policy) error {
	runtime.LockOSThread()
	if err := confine(p); err != nil {
		return err
	}
	return syscall.Exec(p.Program, append([]string{p.Program}, p.Args...), p.Env)
}
