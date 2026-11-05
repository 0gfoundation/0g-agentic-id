// Package credproxy is sealed's credential egress proxy. The harness writes a
// placeholder such as [[credential:github]] where a secret belongs; requests
// that leave the container through this proxy get the placeholder replaced
// with the real value, but only for a host and a request position the
// owner allowed for that entry. Responses are streamed back with every known
// value redacted to its placeholder.
//
// Two entry points share one loopback listener: an explicit form
// (http://127.0.0.1:<port>/<token>/https/<host>/<path>) and an intercepting
// form (HTTPS_PROXY + CONNECT), where hosts named by an entry are terminated
// with a per-boot CA and every other host is tunnelled untouched.
package credproxy

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Use is what an entry's value may be used for.
type Use string

const (
	// UseInject fills placeholders in outgoing requests (the default).
	UseInject Use = "inject"
	// UseTokenOnly is a value that may only feed a token request (a refresh
	// token); a placeholder for it in an ordinary request is refused.
	UseTokenOnly Use = "token_only"
	// UseSign is a signing key; the proxy never writes it into a request.
	UseSign Use = "sign"
)

// Position kinds an entry may allow.
const (
	PosHeader = "header"
	PosBasic  = "basic"
	PosQuery  = "query"
	PosPath   = "path"
	PosBody   = "body"
)

// Position is one place in a request where an entry's placeholder may stand.
type Position struct {
	Kind     string `json:"kind"`
	Name     string `json:"name,omitempty"`     // header: header name
	Template string `json:"template,omitempty"` // header: e.g. "Bearer {v}"
	Username string `json:"username,omitempty"` // basic: the fixed username
	Param    string `json:"param,omitempty"`    // query: parameter name
	Field    string `json:"field,omitempty"`    // body: top-level JSON or form field
}

// Entry is one credential the proxy can fill.
type Entry struct {
	Name      string
	Hosts     []string // normalized: lower case, no trailing dot, ":port" only when not 443
	Positions []Position
	Use       Use
	Signer    *Signer // Use == UseSign: how the value signs
	Value     []byte
	ExpiresAt time.Time // zero = no expiry
}

// namePattern is the grammar of an entry name inside a placeholder. Entries
// sealed derives from a token request carry the "derived:" prefix; values
// sealed itself supplies to the framework (its inference key) "sealed:".
const namePattern = `(?:derived:|sealed:)?[a-z0-9][a-z0-9._-]{0,62}`

var (
	placeholderRe = regexp.MustCompile(`\[\[credential:(` + namePattern + `)\]\]`)
	nameRe        = regexp.MustCompile(`^` + namePattern + `$`)
)

// Placeholder renders the placeholder for name.
func Placeholder(name string) string { return "[[credential:" + name + "]]" }

// ValidName reports whether name fits the placeholder grammar.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// placeholderNames returns the distinct entry names referenced in s.
func placeholderNames(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range placeholderRe.FindAllStringSubmatch(s, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// NormalizeHost lower-cases host, drops a trailing dot and the default port
// 443, and keeps any other port as host:port.
func NormalizeHost(hostport string) string {
	h := strings.ToLower(strings.TrimSpace(hostport))
	host, port, err := net.SplitHostPort(h)
	if err != nil {
		host, port = h, ""
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if port == "" || port == "443" {
		if strings.Contains(host, ":") { // bare IPv6
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, port)
}

// Registry holds the entries sealed currently serves. It is safe for
// concurrent use; the proxy reads it on every request.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]*Entry
	gen     uint64 // advances on every change to the entries
	now     func() time.Time
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{entries: map[string]*Entry{}, now: time.Now}
}

// Replace swaps the whole entry set, e.g. after a new credential set loads.
func (r *Registry) Replace(entries []*Entry) error {
	next := make(map[string]*Entry, len(entries))
	for _, e := range entries {
		if err := e.validate(); err != nil {
			return err
		}
		if _, dup := next[e.Name]; dup {
			return fmt.Errorf("credential %q listed twice", e.Name)
		}
		next[e.Name] = e
	}
	r.mu.Lock()
	r.entries = next
	r.gen++
	r.mu.Unlock()
	return nil
}

// Put adds or replaces one entry (derived entries from a token request).
func (r *Registry) Put(e *Entry) error {
	if err := e.validate(); err != nil {
		return err
	}
	r.mu.Lock()
	r.entries[e.Name] = e
	r.gen++
	r.mu.Unlock()
	return nil
}

// Delete removes one entry.
func (r *Registry) Delete(name string) {
	r.mu.Lock()
	delete(r.entries, name)
	r.gen++
	r.mu.Unlock()
}

// Get returns the entry named name, or nil.
func (r *Registry) Get(name string) *Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.entries[name]
}

// Names lists entry names, sorted.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.entries))
	for n := range r.entries {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// InterceptsHost reports whether any entry names host, i.e. whether a CONNECT
// to it is terminated rather than tunnelled.
func (r *Registry) InterceptsHost(host string) bool {
	host = NormalizeHost(host)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.entries {
		for _, h := range e.Hosts {
			if h == host {
				return true
			}
		}
	}
	return false
}

// inspectsBody reports whether requests to host have their bodies read: some
// entry for it may fill a body field, or signs requests to it (sigv4, hmac).
func (r *Registry) inspectsBody(host string) bool {
	host = NormalizeHost(host)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.entries {
		if !hostAllowed(e, host) {
			continue
		}
		if e.Use == UseSign && e.Signer != nil && (e.Signer.Method == SignSigV4 || e.Signer.Method == SignHMAC) {
			return true
		}
		for _, p := range e.Positions {
			if p.Kind == PosBody {
				return true
			}
		}
	}
	return false
}

// BasicFor names the first entry (by name) that may go to host as a Basic
// auth password, with the fixed username it goes with.
func (r *Registry) BasicFor(host string) (username, name string, ok bool) {
	host = NormalizeHost(host)
	for _, n := range r.Names() {
		e := r.Get(n)
		if e == nil || e.Use != UseInject || !hostAllowed(e, host) {
			continue
		}
		for _, p := range e.Positions {
			if p.Kind == PosBasic {
				return p.Username, n, true
			}
		}
	}
	return "", "", false
}

// secrets snapshots name → value for redaction.
func (r *Registry) secrets() map[string][]byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string][]byte, len(r.entries))
	for n, e := range r.entries {
		out[n] = e.Value
	}
	return out
}

// Validate reports whether e can be served (hosts, positions, use, signer);
// Replace refuses a set holding one that cannot.
func (e *Entry) Validate() error { return e.validate() }

func (e *Entry) validate() error {
	if !ValidName(e.Name) {
		return fmt.Errorf("credential name %q is not valid", e.Name)
	}
	switch e.Use {
	case UseInject, UseTokenOnly, UseSign:
	case "":
		e.Use = UseInject
	default:
		return fmt.Errorf("credential %q: unknown use %q", e.Name, e.Use)
	}
	for i, h := range e.Hosts {
		e.Hosts[i] = NormalizeHost(h)
		if e.Hosts[i] == "" {
			return fmt.Errorf("credential %q: empty host", e.Name)
		}
	}
	for _, p := range e.Positions {
		switch p.Kind {
		case PosHeader:
			if p.Name == "" || strings.Count(p.Template, "{v}") != 1 {
				return fmt.Errorf("credential %q: header position needs a name and a template with one {v}", e.Name)
			}
			if forbiddenHeader(p.Name) {
				return fmt.Errorf("credential %q: header %q may not carry a credential", e.Name, p.Name)
			}
		case PosBasic:
			if p.Username == "" || strings.Contains(p.Username, ":") {
				return fmt.Errorf("credential %q: basic position needs a username without ':'", e.Name)
			}
		case PosQuery:
			if p.Param == "" {
				return fmt.Errorf("credential %q: query position needs a param", e.Name)
			}
		case PosPath:
		case PosBody:
			if p.Field == "" {
				return fmt.Errorf("credential %q: body position needs a field", e.Name)
			}
		default:
			return fmt.Errorf("credential %q: unknown position kind %q", e.Name, p.Kind)
		}
	}
	return e.validateSigner()
}

// forbiddenHeader names headers a credential may never be written into.
func forbiddenHeader(name string) bool {
	n := strings.ToLower(name)
	switch n {
	case "host", "content-length", "transfer-encoding", "cookie":
		return true
	}
	return strings.HasPrefix(n, "proxy-")
}
