// Package servicehost manages owner-authored service programs. It never runs
// their code, dependency installers or interpreters with sealed's privileges.
package servicehost

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"seal-verify/internal/inferproxy"
)

const MaxFiles = 512
const MaxBundleBytes = 16 << 20
const MaxServices = 16

var validID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
var validEnv = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// File is a regular file in a release. Base64 supports both source and
// vendored dependencies; archives, links, devices and executable modes are
// deliberately not interpreted by the root-side publisher.
type File struct {
	Path string `json:"path"`
	Data string `json:"data"` // standard base64
}

// Program selects code from the immutable service release, never a host path.
type Program struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

type Manifest struct {
	ID          string            `json:"id"`
	Command     string            `json:"command"` // trusted image interpreter, e.g. node
	Args        []string          `json:"args"`
	Env         map[string]string `json:"env,omitempty"`
	Files       []File            `json:"files"`
	Description string            `json:"description,omitempty"`
	// Worker is the separately isolated program a service may execute. The
	// service controls business workflow; sealed only manages its processes.
	Worker *Program `json:"worker,omitempty"`
	// Programs always have a private network namespace. egress grants only
	// public destinations explicitly named in EgressHosts through a Unix proxy.
	Network          string   `json:"network,omitempty"`
	EgressHosts      []string `json:"egress_hosts,omitempty"`
	MemoryMB         int      `json:"memory_mb,omitempty"`
	ResidentMemoryMB int      `json:"resident_memory_mb,omitempty"`
	Processes        int      `json:"processes,omitempty"`
	// Optional, counted separately for every temporary worker. The model key
	// stays in sealed; coordinators never receive this route.
	InferenceBudget *inferproxy.TaskLimits `json:"inference_budget,omitempty"`
	// Bounds temporary request/task workers, never the service coordinator.
	RequestTimeoutSeconds int `json:"request_timeout_seconds,omitempty"`
}

func (m *Manifest) normalize() (string, error) {
	if m.InferenceBudget != nil {
		if err := m.InferenceBudget.Validate(); err != nil {
			return "", err
		}
	}
	if !validID.MatchString(m.ID) {
		return "", fmt.Errorf("id: use a lowercase service name, up to 32 characters")
	}
	if m.Command == "" || strings.ContainsAny(m.Command, "/\\\x00") || len(m.Command) > 64 {
		return "", fmt.Errorf("command: name a trusted image interpreter")
	}
	if len(m.Args) > 64 || len(m.Description) > 1024 || len(m.Env) > 64 {
		return "", fmt.Errorf("manifest metadata too large")
	}
	for _, a := range m.Args {
		if len(a) > 8192 || strings.ContainsRune(a, 0) {
			return "", fmt.Errorf("invalid argument")
		}
	}
	if m.Worker != nil {
		if m.Worker.Command == "" || strings.ContainsAny(m.Worker.Command, "/\\\x00") || len(m.Worker.Command) > 64 || len(m.Worker.Args) > 64 {
			return "", fmt.Errorf("worker: name a trusted image interpreter")
		}
		for _, a := range m.Worker.Args {
			if len(a) > 8192 || strings.ContainsRune(a, 0) {
				return "", fmt.Errorf("invalid worker argument")
			}
		}
	}
	for k, v := range m.Env {
		if !validEnv.MatchString(k) || len(v) > 8192 || strings.ContainsRune(v, 0) || k == "PATH" || k == "HOME" || k == "TMPDIR" || k == "MCP_SOCKET" || k == "HARNESS_RUNTIME_ROOT" || strings.HasPrefix(k, "SEAL_") || strings.HasPrefix(k, "LD_") {
			return "", fmt.Errorf("env: reserved or invalid key %q", k)
		}
	}
	if m.RequestTimeoutSeconds == 0 {
		m.RequestTimeoutSeconds = 300
	}
	if m.RequestTimeoutSeconds < 1 || m.RequestTimeoutSeconds > 3600 {
		return "", fmt.Errorf("request_timeout_seconds must be 1..3600")
	}
	if m.Network == "" {
		m.Network = "none"
	}
	if m.Network != "none" && m.Network != "egress" {
		return "", fmt.Errorf("network must be none or egress")
	}
	if len(m.EgressHosts) > 32 || (m.Network == "none" && len(m.EgressHosts) != 0) || (m.Network == "egress" && len(m.EgressHosts) == 0) {
		return "", fmt.Errorf("egress requires 1..32 explicit host:port destinations")
	}
	for i, addr := range m.EgressHosts {
		h, p, err := net.SplitHostPort(addr)
		n, perr := strconv.Atoi(p)
		if err != nil || perr != nil || n < 1 || n > 65535 || h == "" || strings.ContainsAny(h, "\\/@?#%\x00\r\n\t ") {
			return "", fmt.Errorf("egress_hosts: use explicit host:port destinations")
		}
		for _, c := range h {
			if c > 127 {
				return "", fmt.Errorf("egress_hosts: use ASCII DNS names")
			}
		}
		m.EgressHosts[i] = net.JoinHostPort(strings.TrimSuffix(strings.ToLower(h), "."), strconv.Itoa(n))
	}
	sort.Strings(m.EgressHosts)
	if m.MemoryMB == 0 {
		m.MemoryMB = 8192
	}
	if m.Processes == 0 {
		m.Processes = 64
	}
	if m.ResidentMemoryMB == 0 {
		m.ResidentMemoryMB = 256
	}
	if m.ResidentMemoryMB < 64 || m.ResidentMemoryMB > 4096 {
		return "", fmt.Errorf("resident_memory_mb must be 64..4096")
	}
	if m.MemoryMB < 128 || m.MemoryMB > 16384 || m.Processes < 1 || m.Processes > 256 {
		return "", fmt.Errorf("resource limits out of range")
	}
	if len(m.Files) == 0 || len(m.Files) > MaxFiles {
		return "", fmt.Errorf("give 1..%d files", MaxFiles)
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		if f.Path == "" || len(f.Path) > 240 || path.IsAbs(f.Path) || path.Clean(f.Path) != f.Path || f.Path == "." || strings.HasPrefix(f.Path, "../") || strings.ContainsAny(f.Path, "\\\x00") || seen[f.Path] {
			return "", fmt.Errorf("invalid or duplicate file path %q", f.Path)
		}
		seen[f.Path] = true
	}
	for _, f := range m.Files {
		for p := path.Dir(f.Path); p != "."; p = path.Dir(p) {
			if seen[p] {
				return "", fmt.Errorf("file is also a directory: %s", p)
			}
		}
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	b, _ := json.Marshal(m)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
