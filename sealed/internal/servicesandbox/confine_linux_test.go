//go:build linux

package servicesandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"seal-verify/internal/serviceidentity"
)

// runFilter interprets the subset of classic BPF the service filter uses.
func runFilter(t *testing.T, prog []unix.SockFilter, arch, nr uint32, arg0 uint32) uint32 {
	t.Helper()
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			switch in.K {
			case 0:
				acc = nr
			case 4:
				acc = arch
			case 16:
				acc = arg0
			default:
				t.Fatalf("unexpected load offset %d", in.K)
			}
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			var taken bool
			switch in.Code & 0xf0 {
			case unix.BPF_JEQ:
				taken = acc == in.K
			case unix.BPF_JGE:
				taken = acc >= in.K
			case unix.BPF_JSET:
				taken = acc&in.K != 0
			}
			if taken {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return in.K
		default:
			t.Fatalf("unexpected instruction %#x", in.Code)
		}
	}
	t.Fatal("filter fell off its end")
	return 0
}

func TestServiceFilterDecisions(t *testing.T) {
	prog, err := serviceFilter()
	if err != nil {
		t.Fatal(err)
	}
	arch := auditArch[runtime.GOARCH]
	allow := uint32(unix.SECCOMP_RET_ALLOW)
	deny := uint32(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM))
	unsupported := uint32(unix.SECCOMP_RET_ERRNO | uint32(unix.EOPNOTSUPP))
	// glibc's pthread_create flags.
	const threadClone = unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND | unix.CLONE_THREAD |
		unix.CLONE_SYSVSEM | unix.CLONE_SETTLS | unix.CLONE_PARENT_SETTID | unix.CLONE_CHILD_CLEARTID
	type decision struct {
		name string
		arch uint32
		nr   uint32
		arg0 uint32
		want uint32
	}
	cases := []decision{
		{"unix socket", arch, unix.SYS_SOCKET, unix.AF_UNIX, allow},
		{"unix socketpair", arch, unix.SYS_SOCKETPAIR, unix.AF_UNIX, allow},
		{"inet socket", arch, unix.SYS_SOCKET, unix.AF_INET, deny},
		{"inet6 socket", arch, unix.SYS_SOCKET, unix.AF_INET6, deny},
		{"netlink socket", arch, unix.SYS_SOCKET, unix.AF_NETLINK, deny},
		{"packet socket", arch, unix.SYS_SOCKET, unix.AF_PACKET, deny},
		{"smc socket", arch, unix.SYS_SOCKET, unix.AF_SMC, deny},
		{"vsock socket", arch, unix.SYS_SOCKET, unix.AF_VSOCK, deny},
		{"inet socketpair", arch, unix.SYS_SOCKETPAIR, unix.AF_INET, deny},
		{"fallocate", arch, unix.SYS_FALLOCATE, 3, unsupported},
		{"clone3", arch, unix.SYS_CLONE3, 0, uint32(unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS))},
		{"clone with CLONE_PARENT", arch, unix.SYS_CLONE, unix.CLONE_PARENT | uint32(unix.SIGCHLD), deny},
		{"thread clone with CLONE_PARENT", arch, unix.SYS_CLONE, threadClone | unix.CLONE_PARENT, deny},
		{"fork-style clone", arch, unix.SYS_CLONE, unix.CLONE_CHILD_SETTID | unix.CLONE_CHILD_CLEARTID | uint32(unix.SIGCHLD), allow},
		{"thread clone", arch, unix.SYS_CLONE, threadClone, allow},
		{"read", arch, unix.SYS_READ, unix.AF_INET, allow},
		{"connect", arch, unix.SYS_CONNECT, unix.AF_INET, allow},
		{"write", arch, unix.SYS_WRITE, 0, allow},
		{"foreign architecture", arch ^ 1, unix.SYS_READ, 0, unix.SECCOMP_RET_KILL_PROCESS},
	}
	for _, n := range refusedCalls {
		cases = append(cases, decision{fmt.Sprintf("refused call %d", n), arch, n, 0, deny})
	}
	if runtime.GOARCH == "amd64" {
		cases = append(cases,
			decision{"x32 socket", arch, x32Bit | unix.SYS_SOCKET, unix.AF_INET, deny},
			decision{"x32 read", arch, x32Bit | unix.SYS_READ, 0, deny},
			decision{"x32 sendmsg", arch, x32Bit | 518, 0, deny})
	}
	for _, c := range cases {
		if got := runFilter(t, prog, c.arch, c.nr, c.arg0); got != c.want {
			t.Errorf("%s: %#x, want %#x", c.name, got, c.want)
		}
	}
}

// The gated tests below need root, Landlock ABI 6 and a container that lets
// the launcher use it (the provider's sandbox). They re-run this test binary
// as the launcher: the child confines itself, then execs python3 with checks.
const confinedChecks = `import os,json,socket,signal,ctypes
def refused(f):
 try: f();return False
 except OSError: return True
libc=ctypes.CDLL(None,use_errno=True)
L=ctypes.c_long
def call_errno(nr,*args):
 ctypes.set_errno(0)
 return 0 if libc.syscall(L(nr),*args)>=0 else ctypes.get_errno()
def socket_errno(family):
 try: socket.socket(family,socket.SOCK_STREAM).close();return 0
 except OSError as e: return e.errno
calls=json.loads(os.environ['CALLS'])
home=os.environ['HOME']
fd=os.open(os.path.join(home,'prealloc'),os.O_CREAT|os.O_RDWR,0o600)
out={'uid':os.getuid(),
 'read_system':not refused(lambda:open('/usr/lib/os-release').read()),
 'read_outside':not refused(lambda:open(os.environ['OUTSIDE']).read()),
 'list_proc':not refused(lambda:os.listdir('/proc')),
 'lower_oom':not refused(lambda:open('/proc/self/oom_score_adj','w').write('0')),
 'write_home':not refused(lambda:open(os.path.join(home,'x'),'w').write('x')),
 'write_tmp_shared':not refused(lambda:open('/tmp/sealed-shared','w').write('x')),
 'write_release':not refused(lambda:open('release-file','w').write('x')),
 'symlink_in_run':not refused(lambda:os.symlink('/etc/hosts',os.path.join(os.environ['RUN'],'service.sock'))),
 'socket_in_run':not refused(lambda:socket.socket(socket.AF_UNIX).bind(os.path.join(os.environ['RUN'],'s.sock'))),
 'inet':not refused(lambda:socket.socket(socket.AF_INET,socket.SOCK_STREAM)),
 'udp':not refused(lambda:socket.socket(socket.AF_INET,socket.SOCK_DGRAM)),
 'signal_outside':not refused(lambda:os.kill(int(os.environ['OUTSIDE_PID']),0)),
 'abstract_outside':not refused(lambda:socket.socket(socket.AF_UNIX).connect('\0'+os.environ['ABSTRACT'])),
 'unix_pair':not refused(lambda:socket.socketpair(socket.AF_UNIX)),
 'smc_errno':socket_errno(43),
 'vsock_errno':socket_errno(40),
 'shmget_errno':call_errno(calls['shmget'],L(0),L(4096),L(0o1600)),
 'mq_open_errno':call_errno(calls['mq_open'],ctypes.c_char_p(b'/sealed-q'),L(0o102),L(0o600),None),
 'keyctl_errno':call_errno(calls['keyctl'],L(0),L(-4),L(1)),
 'fallocate_errno':call_errno(calls['fallocate'],L(fd),L(1),L(0),L(1<<30)),
 'clone_parent_errno':call_errno(calls['clone'],L(calls['clone_parent_sigchld']),L(0),L(0),L(0),L(0)),
 'nice':os.nice(0),
 'renice_refused':refused(lambda:os.nice(-1))}
print(json.dumps(out))
`

func TestMain(m *testing.M) {
	if os.Getenv("SERVICESANDBOX_HELPER") == "launcher" {
		var p Policy
		if err := json.Unmarshal([]byte(os.Getenv("SERVICESANDBOX_POLICY")), &p); err != nil {
			os.Exit(90)
		}
		if err := Run(p); err != nil {
			os.Stderr.WriteString(err.Error())
			os.Exit(91)
		}
	}
	if os.Getenv("SERVICESANDBOX_HELPER") == "spawn" {
		uid, _ := strconv.Atoi(os.Getenv("SERVICESANDBOX_UID"))
		runtime.LockOSThread()
		if err := dropTo(uint32(uid)); err != nil {
			os.Exit(92)
		}
		for range 4 {
			// Each child starts its own session and is re-parented: kill(-1)
			// as the identity must still reach it.
			cmd := exec.Command("/bin/sh", "-c", "sleep 300 & sleep 300")
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			_ = cmd.Start()
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func gate(t *testing.T) {
	t.Helper()
	if os.Getenv("SEALED_LANDLOCK_TESTS") != "1" {
		t.Skip("set SEALED_LANDLOCK_TESTS=1 as root on a kernel with Landlock ABI 6 (the provider's sandbox)")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	if abi, err := ABI(); err != nil || abi < MinABI {
		t.Fatalf("landlock ABI %d: %v", abi, err)
	}
}

func TestConfinedProcess(t *testing.T) {
	gate(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 required for the checks")
	}
	python, _ = filepath.EvalSymlinks(python)
	// t.TempDir's parent is private to root; the identity must traverse to
	// its directories, as it does to sealed's world-traversable task parent.
	base, err := os.MkdirTemp("", "servicesandbox-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	uid := uint32(serviceidentity.Base + 77)
	release, run, work, tmp := filepath.Join(base, "release"), filepath.Join(base, "run"), filepath.Join(base, "work"), filepath.Join(base, "tmp")
	for _, d := range []string{run, work, tmp} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(d, int(uid), int(uid)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(release, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, "checks.py"), []byte(confinedChecks), 0444); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside.txt")
	if err := os.WriteFile(outside, []byte("world-readable"), 0644); err != nil {
		t.Fatal(err)
	}
	abstract := "servicesandbox-test-" + strconv.Itoa(os.Getpid())
	ln, err := unixListenAbstract(abstract)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(ln)
	// A process of the same identity outside the domain: plain UID rules would
	// let the confined process signal it, Landlock's signal scope must not.
	outsider := exec.Command("/bin/sh", "-c", "sleep 30")
	outsider.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
	if err := outsider.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = outsider.Process.Kill(); _ = outsider.Wait() }()
	// x32 calls are covered by TestServiceFilterDecisions: under Docker's
	// default profile one kills the calling thread before this filter answers.
	calls, _ := json.Marshal(map[string]int{"shmget": unix.SYS_SHMGET, "mq_open": unix.SYS_MQ_OPEN, "keyctl": unix.SYS_KEYCTL, "fallocate": unix.SYS_FALLOCATE,
		"clone": unix.SYS_CLONE, "clone_parent_sigchld": unix.CLONE_PARENT | int(unix.SIGCHLD)})
	p := Policy{UID: uid, ReadExec: []string{"/usr", release}, SocketDirs: []string{run}, ReadWrite: []string{work, tmp}, Dir: release, Program: python,
		Env:  []string{"HOME=" + work, "TMPDIR=" + tmp, "RUN=" + run, "OUTSIDE=" + outside, "OUTSIDE_PID=" + strconv.Itoa(outsider.Process.Pid), "ABSTRACT=" + abstract, "CALLS=" + string(calls)},
		Args: []string{"checks.py"}}
	for _, d := range []string{"/lib", "/lib64", "/bin"} {
		if real, err := filepath.EvalSymlinks(d); err == nil && !strings.HasPrefix(real, "/usr") {
			p.ReadExec = append(p.ReadExec, real)
		}
	}
	policy, _ := json.Marshal(p)
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = []string{"SERVICESANDBOX_HELPER=launcher", "SERVICESANDBOX_POLICY=" + string(policy)}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("confined run: %v: %s", err, out)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("checks output: %q", out)
	}
	want := map[string]any{"uid": float64(uid), "read_system": true, "read_outside": false, "list_proc": false, "lower_oom": false,
		"write_home": true, "write_tmp_shared": false, "write_release": false, "symlink_in_run": false, "socket_in_run": true,
		"inet": false, "udp": false, "signal_outside": false, "abstract_outside": false, "unix_pair": true,
		"smc_errno": float64(unix.EPERM), "vsock_errno": float64(unix.EPERM), "shmget_errno": float64(unix.EPERM), "mq_open_errno": float64(unix.EPERM),
		"keyctl_errno": float64(unix.EPERM), "fallocate_errno": float64(unix.EOPNOTSUPP), "clone_parent_errno": float64(unix.EPERM),
		"nice": float64(19), "renice_refused": true}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v (%s)", k, got[k], v, out)
		}
	}
}

func unixListenAbstract(name string) (int, error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: "@" + name}); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, unix.Listen(fd, 4)
}

func TestReapKillsDetachedProcessesOfOneIdentity(t *testing.T) {
	gate(t)
	uid := uint32(serviceidentity.Base + 78)
	spawn := exec.Command(os.Args[0], "-test.run=^$")
	spawn.Env = []string{"SERVICESANDBOX_HELPER=spawn", "SERVICESANDBOX_UID=" + strconv.Itoa(int(uid)), "PATH=/usr/bin:/bin"}
	if out, err := spawn.CombinedOutput(); err != nil {
		t.Fatalf("spawn: %v %s", err, out)
	}
	time.Sleep(200 * time.Millisecond)
	if n := Scan(map[uint32]bool{uid: true})[uid].Processes; n < 4 {
		t.Fatalf("fixture started %d processes", n)
	}
	reaper := exec.Command(os.Args[0], "-test.run=^TestReapHelper$")
	reaper.Env = []string{"SERVICESANDBOX_REAP=" + strconv.Itoa(int(uid))}
	if out, err := reaper.CombinedOutput(); err != nil {
		t.Fatalf("reap: %v %s", err, out)
	}
	if n := Scan(map[uint32]bool{uid: true})[uid].Processes; n != 0 {
		t.Fatalf("%d processes survived the reap", n)
	}
}

// TestReapHelper is the reaper process of the test above (it drops to the
// identity, so it must not be the test process itself).
func TestReapHelper(t *testing.T) {
	v := os.Getenv("SERVICESANDBOX_REAP")
	if v == "" {
		t.Skip("helper")
	}
	uid, _ := strconv.Atoi(v)
	if err := Reap(uint32(uid), 2*time.Second); err != nil {
		t.Fatal(err)
	}
}
