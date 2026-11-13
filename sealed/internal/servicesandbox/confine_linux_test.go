//go:build linux

package servicesandbox

import (
	"encoding/json"
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

// runFilter interprets the subset of classic BPF the network filter uses.
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
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if acc == in.K {
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

func TestNetworkFilterDecisions(t *testing.T) {
	prog, err := networkFilter()
	if err != nil {
		t.Fatal(err)
	}
	arch := auditArch[runtime.GOARCH]
	deny := uint32(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM))
	for _, c := range []struct {
		name string
		arch uint32
		nr   uint32
		arg0 uint32
		want uint32
	}{
		{"inet socket", arch, unix.SYS_SOCKET, unix.AF_INET, deny},
		{"inet6 socket", arch, unix.SYS_SOCKET, unix.AF_INET6, deny},
		{"netlink socket", arch, unix.SYS_SOCKET, unix.AF_NETLINK, deny},
		{"packet socket", arch, unix.SYS_SOCKET, unix.AF_PACKET, deny},
		{"unix socket", arch, unix.SYS_SOCKET, unix.AF_UNIX, unix.SECCOMP_RET_ALLOW},
		{"io_uring_setup", arch, unix.SYS_IO_URING_SETUP, 0, deny},
		{"io_uring_enter", arch, unix.SYS_IO_URING_ENTER, 0, deny},
		{"io_uring_register", arch, unix.SYS_IO_URING_REGISTER, 0, deny},
		{"read", arch, unix.SYS_READ, unix.AF_INET, unix.SECCOMP_RET_ALLOW},
		{"connect", arch, unix.SYS_CONNECT, unix.AF_INET, unix.SECCOMP_RET_ALLOW},
		{"foreign architecture", arch ^ 1, unix.SYS_READ, 0, unix.SECCOMP_RET_KILL_PROCESS},
	} {
		if got := runFilter(t, prog, c.arch, c.nr, c.arg0); got != c.want {
			t.Errorf("%s: %#x, want %#x", c.name, got, c.want)
		}
	}
}

func TestScanSumsOneIdentity(t *testing.T) {
	dir := t.TempDir()
	write := func(pid, body string) {
		if err := os.MkdirAll(filepath.Join(dir, pid), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, pid, "status"), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("10", "State:\tS\nUid:\t20001\t20001\t20001\t20001\nThreads:\t2\nVmRSS:\t100 kB\n")
	write("11", "State:\tR\nUid:\t20001\t20001\t20001\t20001\nThreads:\t1\nVmRSS:\t50 kB\n")
	write("12", "State:\tZ\nUid:\t20001\t20001\t20001\t20001\n")
	write("13", "State:\tS\nUid:\t20002\t20002\t20002\t20002\nThreads:\t1\nVmRSS:\t999 kB\n")
	write("self", "State:\tS\nUid:\t20001\n")
	old := procRoot
	procRoot = dir
	defer func() { procRoot = old }()
	u := Scan(map[uint32]bool{20001: true})[20001]
	if u.Processes != 2 || u.Tasks != 3 || u.RSSBytes != 150<<10 {
		t.Fatalf("scan: %+v", u)
	}
}

// The gated tests below need root, Landlock ABI 6 and a container that lets
// the launcher use it (the provider's sandbox). They re-run this test binary
// as the launcher: the child confines itself, then execs python3 with checks.
const confinedChecks = `import os,json,socket,signal
def refused(f):
 try: f();return False
 except OSError: return True
home=os.environ['HOME']
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
 'abstract_outside':not refused(lambda:socket.socket(socket.AF_UNIX).connect('\0'+os.environ['ABSTRACT']))}
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
	base := t.TempDir()
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
	p := Policy{UID: uid, ReadExec: []string{"/usr", release}, SocketDirs: []string{run}, ReadWrite: []string{work, tmp}, Dir: release, Program: python,
		Env:  []string{"HOME=" + work, "TMPDIR=" + tmp, "RUN=" + run, "OUTSIDE=" + outside, "OUTSIDE_PID=" + strconv.Itoa(outsider.Process.Pid), "ABSTRACT=" + abstract},
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
		"inet": false, "udp": false, "signal_outside": false, "abstract_outside": false}
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
