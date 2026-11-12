// Package servicehost manages owner-authored service programs. It never runs
// their code, dependency installers or interpreters with sealed's privileges.
package servicehost

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
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

type Manifest struct {
	ID          string            `json:"id"`
	Command     string            `json:"command"` // trusted image interpreter, e.g. node
	Args        []string          `json:"args"`
	Env         map[string]string `json:"env,omitempty"`
	Files       []File            `json:"files"`
	Description string            `json:"description,omitempty"`
	// Network is "none" (default) or "host". Host is an explicit grant of
	// the container's network, including loopback; it is NOT tenant network
	// isolation. No credential proxy variables or sockets are inherited.
	Network   string `json:"network,omitempty"`
	MemoryMB  int    `json:"memory_mb,omitempty"`
	Processes int    `json:"processes,omitempty"`
	// request runs each stateless MCP POST in a fresh sandbox, including
	// discovery. The default keeps the existing supervised service process.
	Mode                  string `json:"mode,omitempty"`
	RequestTimeoutSeconds int    `json:"request_timeout_seconds,omitempty"`
}

func (m *Manifest) normalize() (string, error) {
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
	for k, v := range m.Env {
		if !validEnv.MatchString(k) || len(v) > 8192 || strings.ContainsRune(v, 0) || k == "PATH" || k == "HOME" || k == "TMPDIR" || k == "MCP_SOCKET" || k == "HARNESS_RUNTIME_ROOT" || strings.HasPrefix(k, "SEAL_") || strings.HasPrefix(k, "LD_") {
			return "", fmt.Errorf("env: reserved or invalid key %q", k)
		}
	}
	if m.Mode != "" && m.Mode != "daemon" && m.Mode != "request" {
		return "", fmt.Errorf("mode must be daemon or request")
	}
	if m.Mode == "request" {
		if m.RequestTimeoutSeconds == 0 {
			m.RequestTimeoutSeconds = 300
		}
		if m.RequestTimeoutSeconds < 1 || m.RequestTimeoutSeconds > 3600 {
			return "", fmt.Errorf("request_timeout_seconds must be 1..3600")
		}
	} else if m.RequestTimeoutSeconds != 0 {
		return "", fmt.Errorf("request_timeout_seconds requires request mode")
	}
	if m.Network == "" {
		m.Network = "none"
	}
	if m.Network != "none" && m.Network != "host" {
		return "", fmt.Errorf("network must be none or host")
	}
	if m.MemoryMB == 0 {
		m.MemoryMB = 8192
	}
	if m.Processes == 0 {
		m.Processes = 64
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
