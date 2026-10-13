// Package secrets holds the owner's business secrets (Stripe keys, bot
// tokens, …) so the agent can USE them without ever SEEING their values
// (SECRETS.md). Each secret is delivered encrypted to the agent's agentSeal
// key, carries its own narrow host allowlist, and lives only here, in sealed's
// memory — never on disk, never in the agent's env, never handed to the
// framework. The agent references a secret by a placeholder and the loopback
// egress proxy (proxy.go) substitutes the real value at the moment a request
// leaves for an allowed host.
//
// This is NOT the agentSeal identity key (environment-generated, /provision,
// local signing only); see TRUST_MODEL.md. It is the owner's own credentials,
// which the owner holds and which must only be hidden from the agent.
//
// Wire format mirrors secretenv (agent-seal-ecies-v1), extended from a
// name→value map to name→{value,hosts}:
//
//	{"v":1,"owner":"0x…","secrets":{"STRIPE":{"value":"sk_live_…","hosts":["api.stripe.com"]}}}
//
// `owner` is the sealing signer; Open requires it to equal the agent's live
// on-chain owner, so a ciphertext a previous owner sealed cannot be replayed
// into the next owner's container.
package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	eciesgo "github.com/ecies/go/v2"
	"github.com/ethereum/go-ethereum/common"
)

// Version is the only plaintext version this binary understands.
const Version = 1

// minRedactLen is the shortest value worth redacting from a response: a very
// short "secret" would match everywhere and is not a real credential anyway
// (mirrors openclaw's redaction floor).
const minRedactLen = 6

// Secret is one owner secret: its real value and the hosts it may be sent to.
type Secret struct {
	Value string
	Hosts []string
}

// placeholder is the token the agent uses to reference a secret by name.
func placeholder(name string) string { return "{{secret:" + name + "}}" }

// Store is the in-memory set of opened secrets. Safe for concurrent use; the
// proxy reads it per request while a settings/provision refresh may replace it.
type Store struct {
	mu sync.RWMutex
	m  map[string]Secret
}

// NewStore returns an empty store (no secrets configured).
func NewStore() *Store { return &Store{m: map[string]Secret{}} }

// Replace swaps the whole secret set (a fresh /provision delivery). A nil or
// empty map clears it.
func (s *Store) Replace(m map[string]Secret) {
	cp := make(map[string]Secret, len(m))
	for k, v := range m {
		hosts := append([]string(nil), v.Hosts...)
		cp[k] = Secret{Value: v.Value, Hosts: hosts}
	}
	s.mu.Lock()
	s.m = cp
	s.mu.Unlock()
}

// Len reports how many secrets are configured.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}

// get returns the secret by name.
func (s *Store) get(name string) (Secret, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[name]
	return v, ok
}

// hostAllowed reports whether `host` is in `secret`'s allowlist. Matching is
// case-insensitive on the host, and an entry may be an exact host
// (`api.stripe.com`) or a leading-wildcard suffix (`*.stripe.com`, matching
// any subdomain but not the apex). Port is ignored.
func hostAllowed(host string, allow []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	if host == "" {
		return false
	}
	for _, a := range allow {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, "*.") {
			if strings.HasSuffix(host, a[1:]) && len(host) > len(a)-1 {
				return true
			}
			continue
		}
		if host == a {
			return true
		}
	}
	return false
}

// substituteForHost replaces every {{secret:NAME}} in `in` with NAME's real
// value, but ONLY for secrets whose allowlist includes `host`. A placeholder
// whose secret does not allow this host (or is unknown) is left untouched, so
// the far end receives the useless placeholder, never the value. It returns
// the result and the names of any placeholders deliberately left unresolved
// because the host was not allowed (for a warning log; never values).
func (s *Store) substituteForHost(in, host string) (out string, blocked []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out = in
	for name, sec := range s.m {
		ph := placeholder(name)
		if !strings.Contains(out, ph) {
			continue
		}
		if hostAllowed(host, sec.Hosts) {
			out = strings.ReplaceAll(out, ph, sec.Value)
		} else {
			blocked = append(blocked, name)
		}
	}
	sort.Strings(blocked)
	return out, blocked
}

// redact swaps every real secret value in `in` back to its placeholder, so a
// value echoed in a response never reaches the agent. All known values are
// redacted (not only ones used this turn), above the length floor.
func (s *Store) redact(in string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Longest value first (review #171 nit): if one secret's value is a
	// substring of another's, redacting the shorter first could leave a
	// fragment of the longer exposed. Deterministic, longest-match-wins.
	type kv struct {
		name string
		val  string
	}
	vals := make([]kv, 0, len(s.m))
	for name, sec := range s.m {
		if len(sec.Value) >= minRedactLen {
			vals = append(vals, kv{name, sec.Value})
		}
	}
	sort.Slice(vals, func(i, j int) bool { return len(vals[i].val) > len(vals[j].val) })
	out := in
	for _, v := range vals {
		if strings.Contains(out, v.val) {
			out = strings.ReplaceAll(out, v.val, placeholder(v.name))
		}
	}
	return out
}

// ── delivery (decrypt + validate) ────────────────────────────────────────

type secretIn struct {
	Value string   `json:"value"`
	Hosts []string `json:"hosts"`
}

type payload struct {
	V       int                 `json:"v"`
	Owner   string              `json:"owner"`
	Secrets map[string]secretIn `json:"secrets"`
}

// Reason classes for an Open failure — a cause, never a value.
const (
	ReasonMalformed          = "malformed"
	ReasonUnsupportedVersion = "unsupported_version"
	ReasonNotSealedToAgent   = "not_sealed_to_this_agent"
	ReasonOwnerUnknown       = "owner_unknown"
	ReasonOwnerMismatch      = "owner_mismatch"
	ReasonInternal           = "internal"
)

// Error is an Open failure with its reason class.
type Error struct {
	Reason string
	err    error
}

func (e *Error) Error() string            { return e.err.Error() }
func (e *Error) Unwrap() error            { return e.err }
func fail(reason string, err error) error { return &Error{Reason: reason, err: err} }

// Reason returns the reason class of an Open error.
func Reason(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ReasonMalformed
}

// Open decodes, decrypts and validates a delivered secrets document, returning
// the name→Secret map. Owner-bound exactly like secretenv: an empty or
// mismatched chainOwner fails closed. Errors never include values. A secret
// with an empty value, an empty host allowlist, or a bad placeholder-unsafe
// name is rejected — an unusable secret must not silently disable protection.
func Open(encoded string, agentSealPriv []byte, chainOwner string) (map[string]Secret, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return map[string]Secret{}, nil // nothing configured
	}
	ct, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fail(ReasonMalformed, fmt.Errorf("base64: %w", err))
	}
	if len(agentSealPriv) != 32 {
		return nil, fail(ReasonInternal, fmt.Errorf("agentSeal key must be 32 bytes, got %d", len(agentSealPriv)))
	}
	pt, err := eciesgo.Decrypt(eciesgo.NewPrivateKeyFromBytes(agentSealPriv), ct)
	if err != nil {
		return nil, fail(ReasonNotSealedToAgent, fmt.Errorf("ecies decrypt: %w", err))
	}
	var p payload
	dec := json.NewDecoder(bytes.NewReader(pt))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fail(ReasonMalformed, errors.New("plaintext is not a v1 secrets document"))
	}
	if p.V != Version {
		return nil, fail(ReasonUnsupportedVersion, fmt.Errorf("unsupported version %d (want %d)", p.V, Version))
	}
	if !common.IsHexAddress(p.Owner) {
		return nil, fail(ReasonMalformed, errors.New("owner is not an address"))
	}
	if !common.IsHexAddress(chainOwner) {
		return nil, fail(ReasonOwnerUnknown, errors.New("on-chain owner unknown; refusing owner-bound secrets"))
	}
	if common.HexToAddress(p.Owner) != common.HexToAddress(chainOwner) {
		return nil, fail(ReasonOwnerMismatch, fmt.Errorf("sealed for %s, agent owner is %s",
			common.HexToAddress(p.Owner).Hex(), common.HexToAddress(chainOwner).Hex()))
	}
	out := make(map[string]Secret, len(p.Secrets))
	for name, in := range p.Secrets {
		if name == "" || strings.ContainsAny(name, "{}: \t\r\n") {
			return nil, fail(ReasonMalformed, fmt.Errorf("invalid secret name %q", name))
		}
		if in.Value == "" || strings.ContainsRune(in.Value, 0) {
			return nil, fail(ReasonMalformed, fmt.Errorf("%s: empty or invalid value", name))
		}
		// Symmetric with the redaction floor (review #171 F3): a value too short
		// to redact is too short to be a secret — it would be substituted at
		// egress but echoed back to the agent unredacted. Reject it here.
		if len(in.Value) < minRedactLen {
			return nil, fail(ReasonMalformed, fmt.Errorf("%s: value shorter than %d chars cannot be protected", name, minRedactLen))
		}
		hosts := make([]string, 0, len(in.Hosts))
		for _, h := range in.Hosts {
			if h = strings.TrimSpace(h); h != "" {
				hosts = append(hosts, h)
			}
		}
		if len(hosts) == 0 {
			// Invariant 3: a secret with no allowlist is unusable, not a
			// free-for-all. Reject the whole document so the owner fixes it.
			return nil, fail(ReasonMalformed, fmt.Errorf("%s: no hosts — a secret must name the hosts it may be sent to", name))
		}
		out[name] = Secret{Value: in.Value, Hosts: hosts}
	}
	return out, nil
}
