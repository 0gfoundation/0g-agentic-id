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

// networkFilter refuses inet, netlink and packet sockets and io_uring (which
// could open sockets without socket(2)). Any other architecture is killed.
func networkFilter() ([]unix.SockFilter, error) {
	arch, ok := auditArch[runtime.GOARCH]
	if !ok {
		return nil, fmt.Errorf("unsupported architecture %s", runtime.GOARCH)
	}
	const (
		ld   = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeq  = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		ret  = unix.BPF_RET | unix.BPF_K
		nr   = 0  // offsetof(struct seccomp_data, nr)
		arc  = 4  // offsetof(struct seccomp_data, arch)
		arg0 = 16 // low word of args[0] (little endian)
	)
	denyNR := []uint32{unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER}
	denyFamily := []uint32{unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK, unix.AF_PACKET}
	allow := 4 + len(denyNR) + 2 + len(denyFamily)
	deny := allow + 1
	var p []unix.SockFilter
	add := func(code uint16, k uint32, jt, jf int) {
		p = append(p, unix.SockFilter{Code: code, Jt: uint8(jt), Jf: uint8(jf), K: k})
	}
	add(ld, arc, 0, 0)
	add(jeq, arch, 1, 0)
	add(ret, unix.SECCOMP_RET_KILL_PROCESS, 0, 0)
	add(ld, nr, 0, 0)
	for _, n := range denyNR {
		add(jeq, n, deny-len(p)-1, 0)
	}
	add(jeq, unix.SYS_SOCKET, 0, allow-len(p)-1)
	add(ld, arg0, 0, 0)
	for _, f := range denyFamily {
		add(jeq, f, deny-len(p)-1, 0)
	}
	add(ret, unix.SECCOMP_RET_ALLOW, 0, 0)
	add(ret, unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM), 0, 0)
	if len(p) != deny+1 {
		return nil, fmt.Errorf("seccomp program layout")
	}
	return p, nil
}

func installNetworkFilter() error {
	filter, err := networkFilter()
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
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	if err := r.restrictSelf(); err != nil {
		return err
	}
	if err := installNetworkFilter(); err != nil {
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
