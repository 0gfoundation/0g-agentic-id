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
	"bytes"
	"fmt"
	"net"
	"regexp"
	"slices"
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
//
// Besides the entries it keeps values that are only scrubbed, never filled:
// every value sealed served earlier in this boot and no longer does (an entry
// replaced or removed, the previous owner's after a Clear), and the JWTs the
// proxy minted, until their exp. Redaction, Scrub and ScrubReader cover them
// under the placeholder of the entry they belonged to.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]*Entry
	// retired holds the values of owner and sealed entries, retiredDerived
	// those of derived entries; each oldest first (retireLocked).
	retired        []scrubValue
	retiredDerived []scrubValue
	minted         []scrubValue // oldest first, at most maxMinted
	gen            uint64       // advances on every change to the values Scrub covers
	now            func() time.Time

	// formsMu guards forms, the redaction forms of every value Scrub covers
	// as they stood at formsGen.
	formsMu  sync.Mutex
	forms    *formSet
	formsGen uint64
}

// scrubValue is a value kept only to be scrubbed, and the entry whose
// placeholder replaces it.
type scrubValue struct {
	name  string
	value []byte
	until time.Time // minted tokens: the token's exp
}

// The scrub-only sets are bounded; the oldest values go first.
const (
	maxRetired        = 1024 // values of owner and sealed entries
	maxRetiredDerived = 1024 // values of derived entries
	maxRetiredPerName = 32   // in either, the values of any one entry name
	maxMinted         = 256
)

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{entries: map[string]*Entry{}, now: time.Now}
}

// validated returns a validated copy of e. The registry never writes to an
// entry it is handed: callers pass entries they read back from it, which
// proxy goroutines may be reading at the same time.
func validated(e *Entry) (*Entry, error) {
	cp := *e
	cp.Hosts = append([]string(nil), e.Hosts...)
	if err := cp.validate(); err != nil {
		return nil, err
	}
	return &cp, nil
}

// Replace swaps the whole entry set, e.g. after a new credential set loads.
// A value the new set no longer holds is retired: scrubbed, never filled.
func (r *Registry) Replace(entries []*Entry) error {
	next := make(map[string]*Entry, len(entries))
	held := make(map[string]bool, len(entries))
	for _, e := range entries {
		v, err := validated(e)
		if err != nil {
			return err
		}
		if _, dup := next[v.Name]; dup {
			return fmt.Errorf("credential %q listed twice", v.Name)
		}
		next[v.Name] = v
		held[string(v.Value)] = true
	}
	r.mu.Lock()
	for _, n := range sortedNames(r.entries) {
		if old := r.entries[n]; !held[string(old.Value)] {
			r.retireLocked(old)
		}
	}
	r.entries = next
	r.gen++
	r.mu.Unlock()
	return nil
}

// Put adds or replaces one entry (derived entries from a token request). A
// value it replaces is retired.
func (r *Registry) Put(e *Entry) error {
	v, err := validated(e)
	if err != nil {
		return err
	}
	r.mu.Lock()
	if old, ok := r.entries[v.Name]; ok && !bytes.Equal(old.Value, v.Value) {
		r.retireLocked(old)
	}
	r.entries[v.Name] = v
	r.gen++
	r.mu.Unlock()
	return nil
}

// Delete removes one entry; its value is retired.
func (r *Registry) Delete(name string) {
	r.mu.Lock()
	if old, ok := r.entries[name]; ok {
		r.retireLocked(old)
	}
	delete(r.entries, name)
	r.gen++
	r.mu.Unlock()
}

// retireLocked keeps e's value to be scrubbed for the rest of the process.
// Values of derived entries, which every token request replaces, are kept
// apart from those of owner and sealed entries, so the one never pushes the
// other out; and a name keeps at most maxRetiredPerName values, so a value
// replaced again and again (a rotated refresh token) pushes out only its own
// earlier ones.
func (r *Registry) retireLocked(e *Entry) {
	if len(e.Value) == 0 {
		return
	}
	list, limit := &r.retired, maxRetired
	if strings.HasPrefix(e.Name, "derived:") {
		list, limit = &r.retiredDerived, maxRetiredDerived
	}
	kept := (*list)[:0]
	same := 0
	for _, v := range *list {
		if !bytes.Equal(v.value, e.Value) {
			kept = append(kept, v)
			if v.name == e.Name {
				same++
			}
		}
	}
	if same >= maxRetiredPerName {
		i := slices.IndexFunc(kept, func(v scrubValue) bool { return v.name == e.Name })
		kept = slices.Delete(kept, i, i+1)
	}
	kept = append(kept, scrubValue{name: e.Name, value: e.Value})
	if len(kept) > limit {
		kept = append([]scrubValue(nil), kept[len(kept)-limit:]...)
	}
	*list = kept
}

// holdMinted keeps a token minted for jwt entry name until its exp, so later
// responses and what sealed commits are scrubbed of it as well.
func (r *Registry) holdMinted(name string, tok []byte, until time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var kept []scrubValue
	for _, v := range r.minted {
		if now.Before(v.until) {
			kept = append(kept, v)
		}
	}
	kept = append(kept, scrubValue{name: name, value: tok, until: until})
	if len(kept) > maxMinted {
		kept = kept[len(kept)-maxMinted:]
	}
	r.minted = kept
	r.gen++
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
	return sortedNames(r.entries)
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

// scrubListLocked lists every value Scrub covers: the entries (by name),
// then the minted tokens not yet expired and the retired values, newest
// first. Where one value appears twice the first placeholder wins.
func (r *Registry) scrubListLocked() []secret {
	out := make([]secret, 0, len(r.entries)+len(r.minted)+len(r.retired)+len(r.retiredDerived))
	for _, n := range sortedNames(r.entries) {
		out = append(out, secret{name: n, value: r.entries[n].Value})
	}
	now := r.now()
	for i := len(r.minted) - 1; i >= 0; i-- {
		if v := r.minted[i]; now.Before(v.until) {
			out = append(out, secret{name: v.name, value: v.value})
		}
	}
	for _, list := range [][]scrubValue{r.retired, r.retiredDerived} {
		for i := len(list) - 1; i >= 0; i-- {
			out = append(out, secret{name: list[i].name, value: list[i].value})
		}
	}
	return out
}

// scrubForms returns the redaction forms of every value Scrub covers, built
// again only when those values changed.
func (r *Registry) scrubForms() *formSet {
	r.formsMu.Lock()
	defer r.formsMu.Unlock()
	r.mu.RLock()
	if r.forms != nil && r.formsGen == r.gen {
		r.mu.RUnlock()
		return r.forms
	}
	gen, list := r.gen, r.scrubListLocked()
	r.mu.RUnlock()
	r.forms, r.formsGen = newFormSet(list), gen
	return r.forms
}

func sortedNames(m map[string]*Entry) []string {
	out := make([]string, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// MaxValueLen bounds a value sealed holds: a key, a token or a login's
// access token. Each value is also kept in many encoded forms for redaction.
const MaxValueLen = 16 << 10

// Validate reports whether e can be served (hosts, positions, use, signer);
// Replace refuses a set holding one that cannot. It normalizes e's hosts and
// use in place, so it is for an entry the registry does not hold yet.
func (e *Entry) Validate() error { return e.validate() }

func (e *Entry) validate() error {
	if len(e.Value) > MaxValueLen {
		return fmt.Errorf("credential %q: a value of %d bytes is over the %d sealed holds", e.Name, len(e.Value), MaxValueLen)
	}
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
