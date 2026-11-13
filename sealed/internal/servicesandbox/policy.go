// Package servicesandbox confines one hosted service process inside the
// sandbox with no namespaces, no capability beyond the provider's six and no
// provider change: a service identity of its own, rlimits set once it has left
// root, oom_score_adj 1000, a Landlock domain and a seccomp filter. Landlock lets the process read only the system, its program and its
// runtime, write only its private directories, and keeps its abstract Unix
// sockets and signals inside its own domain; it also refuses TCP. The seccomp
// filter refuses inet, netlink and packet sockets and io_uring, so the only
// way out is a Unix socket sealed hands it. sealed/isolation/README.md records
// what was measured on the dev runner.
package servicesandbox

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"seal-verify/internal/serviceidentity"
)

// MinABI is the first Landlock ABI that scopes abstract Unix sockets and
// signals (Linux 6.12). Older kernels report the service runtime unsupported.
const MinABI = 6

// Policy is everything one confined process may use. Paths are absolute and
// already resolved by sealed; the launcher opens each one as root before it
// drops to UID, so a path the service controls can never widen the domain.
type Policy struct {
	UID uint32
	// ReadExec: read and execute below each path (system, program, runtime).
	ReadExec []string
	// ReadOnly: read below each path (a few /etc entries).
	ReadOnly []string
	// Devices: read and write one device node each (/dev/null and the like).
	Devices []string
	// SocketDirs: list the directory and create or remove sockets in it, and
	// nothing else; a socket sealed later dials cannot be swapped for a link.
	SocketDirs []string
	// ReadWrite: private work and temporary directories.
	ReadWrite []string
	Dir       string
	Env       []string
	Program   string
	Args      []string
	// Limits are set after the identity drop: inside a user namespace (Sysbox)
	// the container's root is not exempt from RLIMIT_NPROC, which would count
	// every root process of the runner against the launcher's own threads.
	Limits Limits
}

// Limits are the rlimits of the service process; zero leaves one unchanged.
// Core files are always disabled.
type Limits struct {
	AddressSpace uint64 // bytes
	Processes    uint64 // processes and threads of the identity
	Files        uint64 // open descriptors
	FileSize     uint64 // bytes per file
}

var validEnvEntry = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}=`)

func cleanAbs(p string) bool {
	return p != "" && filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsRune(p, 0)
}

// Validate refuses anything the launcher must not interpret: a foreign
// identity, a relative or unclean path, or a malformed environment entry.
func (p Policy) Validate() error {
	if !serviceidentity.Valid(int(p.UID)) {
		return fmt.Errorf("invalid service identity")
	}
	for _, group := range [][]string{p.ReadExec, p.ReadOnly, p.Devices, p.SocketDirs, p.ReadWrite} {
		for _, path := range group {
			if !cleanAbs(path) || path == "/" {
				return fmt.Errorf("invalid confinement path %q", path)
			}
		}
	}
	if !cleanAbs(p.Dir) || !cleanAbs(p.Program) {
		return fmt.Errorf("program and working directory must be absolute")
	}
	for _, kv := range p.Env {
		if !validEnvEntry.MatchString(kv) || strings.ContainsRune(kv, 0) {
			return fmt.Errorf("invalid environment entry")
		}
	}
	for _, a := range p.Args {
		if strings.ContainsRune(a, 0) {
			return fmt.Errorf("invalid argument")
		}
	}
	return nil
}

// LauncherArgs encodes the policy for the launcher's command line. Only sealed
// builds it; service input never reaches argv (it arrives on stdin).
func (p Policy) LauncherArgs() []string {
	args := []string{"run", "--uid=" + strconv.FormatUint(uint64(p.UID), 10)}
	for flag, v := range map[string]uint64{"--as": p.Limits.AddressSpace, "--nproc": p.Limits.Processes, "--nofile": p.Limits.Files, "--fsize": p.Limits.FileSize} {
		if v != 0 {
			args = append(args, flag+"="+strconv.FormatUint(v, 10))
		}
	}
	add := func(flag string, values []string) {
		for _, v := range values {
			args = append(args, flag+"="+v)
		}
	}
	add("--rx", p.ReadExec)
	add("--ro", p.ReadOnly)
	add("--dev", p.Devices)
	add("--sock", p.SocketDirs)
	add("--rw", p.ReadWrite)
	args = append(args, "--chdir="+p.Dir)
	add("--env", p.Env)
	args = append(args, "--", p.Program)
	return append(args, p.Args...)
}

// ParseRun decodes LauncherArgs (without the leading "run").
func ParseRun(args []string) (Policy, error) {
	var p Policy
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 >= len(args) {
				return Policy{}, fmt.Errorf("missing program")
			}
			p.Program, p.Args = args[i+1], append([]string(nil), args[i+2:]...)
			return p, p.Validate()
		}
		flag, value, ok := strings.Cut(a, "=")
		if !ok {
			return Policy{}, fmt.Errorf("unexpected argument %q", a)
		}
		switch flag {
		case "--uid":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return Policy{}, fmt.Errorf("invalid uid")
			}
			p.UID = uint32(n)
		case "--as", "--nproc", "--nofile", "--fsize":
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil || n == 0 {
				return Policy{}, fmt.Errorf("invalid %s", flag)
			}
			*map[string]*uint64{"--as": &p.Limits.AddressSpace, "--nproc": &p.Limits.Processes, "--nofile": &p.Limits.Files, "--fsize": &p.Limits.FileSize}[flag] = n
		case "--rx":
			p.ReadExec = append(p.ReadExec, value)
		case "--ro":
			p.ReadOnly = append(p.ReadOnly, value)
		case "--dev":
			p.Devices = append(p.Devices, value)
		case "--sock":
			p.SocketDirs = append(p.SocketDirs, value)
		case "--rw":
			p.ReadWrite = append(p.ReadWrite, value)
		case "--chdir":
			p.Dir = value
		case "--env":
			p.Env = append(p.Env, value)
		default:
			return Policy{}, fmt.Errorf("unknown flag %q", flag)
		}
	}
	return Policy{}, fmt.Errorf("missing program")
}
