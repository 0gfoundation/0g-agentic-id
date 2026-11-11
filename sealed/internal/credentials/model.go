package credentials

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"seal-verify/internal/credproxy"
	"seal-verify/internal/inference"
)

// ModelKeyPrefix starts the name of a model key entry: "model.<provider>".
const ModelKeyPrefix = "model."

// UseModel is a model key entry's use. The proxy knows no such use, so an
// image from before model keys skips the entry instead of serving it.
const UseModel credproxy.Use = "model"

// InferenceSpec makes an entry the agent's model key for one provider of the
// platform's provider registry. sealed hands the value to the framework for
// that provider's model calls and for nothing else: the entry has no hosts
// or positions of the owner's, no placeholder, and is never revealed or
// listed to the harness. Which provider the agent uses is its settings'
// choice; the set may hold keys for several.
//
// RouteHash and Registry bind the key to where that provider was when the
// owner signed, as the key handed over at create/reset is bound
// (internal/secretenv): with no RouteHash the image's built-in route,
// otherwise the provider's route in that accepted registry version.
type InferenceSpec struct {
	Provider  string                 `json:"provider"`
	RouteHash string                 `json:"route_hash,omitempty"`
	Registry  *inference.RegistryPin `json:"registry,omitempty"`
}

// ModelKey is the owner's model key for one provider.
type ModelKey struct {
	Name      string
	Provider  string
	Value     []byte
	ValueHash string
	RouteHash string
	Registry  *inference.RegistryPin
}

// ModelInUse says which model key the framework runs on, for the owner.
type ModelInUse struct {
	Provider string `json:"provider,omitempty"`
	// Source is "credentials" (an entry of the set), "deploy" (the key
	// handed over at create/reset) or "none".
	Source string `json:"source"`
	// ValueHash is the entry's value hash when Source is "credentials".
	ValueHash string `json:"value_hash,omitempty"`
	// Issue says why a key the owner set is not the one in use.
	Issue string `json:"issue,omitempty"`
}

var (
	modelProviderRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	routeHashRe     = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
)

// maxSafeInteger is the largest registry version the SDK signs exactly.
const maxSafeInteger = 1<<53 - 1

// checkModelEntry checks a model key entry and its value. The owner's
// definition carries nothing but the binding: whatever else it could say
// (hosts, a template, reveal, writeback) would reach the key past sealed.
func checkModelEntry(d *Definition, value []byte) error {
	m := d.Inference
	if !modelProviderRe.MatchString(m.Provider) || d.Name != ModelKeyPrefix+m.Provider {
		return errors.New("a model key is named model.<provider>")
	}
	if len(d.Hosts) > 0 || len(d.Positions) > 0 || d.Use != UseModel ||
		d.AllowReveal || d.Writeback || d.ExpiresAt != 0 || d.TokenRequest != nil || d.Signer != nil || d.MCP != nil {
		return errors.New("a model key carries only its provider binding")
	}
	switch {
	case m.RouteHash == "" && m.Registry == nil:
	case m.RouteHash == "" || m.Registry == nil:
		return errors.New("a model key's route and registry version go together")
	case !routeHashRe.MatchString(m.RouteHash):
		return errors.New("a model key's route hash is not valid")
	case m.Registry.Version < 0 || m.Registry.Version > maxSafeInteger ||
		(m.Registry.Version == 0 && m.Registry.Digest != "") ||
		(m.Registry.Version > 0 && !routeHashRe.MatchString(m.Registry.Digest)):
		return errors.New("a model key's registry version is not valid")
	}
	if len(value) == 0 || len(value) > credproxy.MaxValueLen {
		return fmt.Errorf("a model key is 1 to %d bytes", credproxy.MaxValueLen)
	}
	for _, b := range value {
		// It is sent in a header or written into the framework's config.
		if b < 0x20 || b == 0x7f {
			return errors.New("a model key has no control characters")
		}
	}
	return nil
}

// modelKeysOf splits the model keys out of an opened set's entries.
func modelKeysOf(defs map[string]*Definition, values map[string][]byte) (rest map[string]*Definition, restValues map[string][]byte, keys map[string]ModelKey) {
	rest, restValues, keys = map[string]*Definition{}, map[string][]byte{}, map[string]ModelKey{}
	for name, d := range defs {
		if d.Inference == nil {
			rest[name], restValues[name] = d, values[name]
			continue
		}
		keys[d.Inference.Provider] = ModelKey{Name: name, Provider: d.Inference.Provider, Value: values[name],
			ValueHash: strings.ToLower(d.ValueHash), RouteHash: d.Inference.RouteHash, Registry: d.Inference.Registry}
	}
	return rest, restValues, keys
}

func sameModelKey(a, b ModelKey) bool {
	return a.Provider == b.Provider && bytes.Equal(a.Value, b.Value) && a.RouteHash == b.RouteHash && samePin(a.Registry, b.Registry)
}

func samePin(a, b *inference.RegistryPin) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

// ModelKey returns the owner's model key for provider.
func (s *Store) ModelKey(provider string) (ModelKey, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.models[provider]
	return k, ok
}

// ModelProviders lists the providers the set holds a model key for.
func (s *Store) ModelProviders() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.models))
	for p := range s.models {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// OnModelKeys sets what runs (on its own goroutine) after a load changed
// the model keys.
func (s *Store) OnModelKeys(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onModels = f
}

// SetModelInUse records which key the framework runs on.
func (s *Store) SetModelInUse(m ModelInUse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.Source == "" {
		m.Source = "none"
	}
	s.inUse = m
}

// ModelInUse says which key the framework runs on.
func (s *Store) ModelInUse() ModelInUse {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inUse
}

// SwapSystemValue gives a value sealed holds for the framework (HoldSystem)
// a new value, filled in where the old one was. It reports false when no
// such value is held for host alone, or after the owner changed.
func (s *Store) SwapSystemValue(name, host string, value []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.system[name]
	if s.retired || e == nil || len(e.Hosts) != 1 || e.Hosts[0] != credproxy.NormalizeHost(host) {
		return false
	}
	next := *e
	next.Value = append([]byte(nil), value...)
	if next.Validate() != nil {
		return false
	}
	s.system[name] = &next
	s.syncRegistryLocked()
	return true
}

// ReleaseSystem drops a value sealed holds for the framework: the framework
// is about to start, and holds it again if it still needs it.
func (s *Store) ReleaseSystem(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.system[name]; ok {
		delete(s.system, name)
		s.syncRegistryLocked()
	}
}

// swapModelsLocked installs the model keys of a newly loaded set, notes the
// changes in the owner's audit log (when audit), and reports whether any
// changed.
func (s *Store) swapModelsLocked(keys map[string]ModelKey, audit bool) bool {
	changed := false
	for p, k := range keys {
		old, ok := s.models[p]
		if !ok || !sameModelKey(old, k) {
			changed = true
			if audit {
				s.audit("model", k.Name, "", "model key set")
			}
			continue
		}
		// The same key sealed again: what the owner reads names the entry
		// now stored.
		if s.inUse.Source == "credentials" && s.inUse.Provider == p && s.inUse.ValueHash == old.ValueHash {
			s.inUse.ValueHash = k.ValueHash
		}
	}
	for p, old := range s.models {
		if _, ok := keys[p]; !ok {
			changed = true
			if audit {
				s.audit("model", old.Name, "", "model key removed")
			}
		}
	}
	s.models = keys
	if changed {
		// Applied anew (or refused anew) by the framework's side.
		s.inUse.Issue = ""
	}
	return changed
}
