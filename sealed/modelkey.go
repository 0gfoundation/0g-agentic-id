package main

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"seal-verify/internal/credentials"
	"seal-verify/internal/inference"
	"seal-verify/internal/settings"
)

// modelKeys chooses the model (inference) key for a settings document: the
// owner's key for its provider from the credential set (cred set model),
// else the key handed over at create/reset. With no provider in the
// settings, a set holding a key for exactly one provider means that one.
type modelKeys struct {
	boot  inference.ProviderCredential
	store modelKeySource // nil when credentials are off
	// loadPinned reads the registry version a key is bound to.
	loadPinned func(ctx context.Context, c inference.ProviderCredential) (*inference.Registry, error)

	mu     sync.Mutex
	pinned map[string]*inference.Registry
}

// modelKeySource is the credential store's side of it.
type modelKeySource interface {
	ModelKey(provider string) (credentials.ModelKey, bool)
	ModelProviders() []string
}

// modelChoice is a document with the key it runs on.
type modelChoice struct {
	doc        settings.Doc // the provider filled in when it was implied
	credential inference.ProviderCredential
	source     string // "credentials", "deploy" or "none"
	valueHash  string
	issue      string
}

func (m *modelKeys) choose(doc settings.Doc) modelChoice {
	if m.store != nil {
		eff := doc
		var issue string
		if eff.Provider == "" {
			switch providers := m.store.ModelProviders(); len(providers) {
			case 0:
			case 1:
				eff.Provider = providers[0]
			default:
				issue = fmt.Sprintf("the settings name no provider and the credential set holds model keys for %s: choose one with settings provider=…", strings.Join(providers, ", "))
			}
		}
		if eff.Provider != "" {
			if k, ok := m.store.ModelKey(eff.Provider); ok {
				return modelChoice{doc: eff, source: "credentials", valueHash: k.ValueHash, credential: inference.ProviderCredential{
					Provider: k.Provider, APIKey: string(k.Value), RouteHash: k.RouteHash, Registry: k.Registry, Bound: true}}
			}
		}
		if issue != "" {
			return modelChoice{doc: doc, credential: m.boot, source: "none", issue: issue}
		}
	}
	source := "deploy"
	// A document with no provider is given no key (settings.ResolveForRegistry).
	if doc.Provider == "" || m.boot.APIKey == "" {
		source = "none"
	}
	return modelChoice{doc: doc, credential: m.boot, source: source}
}

// resolve resolves the choice against the registry its key is bound to.
func (m *modelKeys) resolve(ctx context.Context, c modelChoice) (settings.Resolved, error) {
	registry := inference.DefaultRegistry
	if c.credential.RouteHash != "" {
		var err error
		if registry, err = m.registry(ctx, c.credential); err != nil {
			return settings.Resolved{}, fmt.Errorf("load provider registry: %w", err)
		}
	}
	return settings.ResolveForRegistry(ctx, c.doc, c.credential, registry)
}

// registry reads the pinned registry once per binding.
func (m *modelKeys) registry(ctx context.Context, c inference.ProviderCredential) (*inference.Registry, error) {
	key := c.Provider + "\n" + c.RouteHash
	if c.Registry != nil {
		key += fmt.Sprintf("\n%d\n%s", c.Registry.Version, c.Registry.Digest)
	}
	m.mu.Lock()
	r := m.pinned[key]
	m.mu.Unlock()
	if r != nil {
		return r, nil
	}
	if m.loadPinned == nil {
		return nil, fmt.Errorf("dynamic provider registry requires chain bootstrap")
	}
	r, err := m.loadPinned(ctx, c)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	if m.pinned == nil {
		m.pinned = map[string]*inference.Registry{}
	}
	m.pinned[key] = r
	m.mu.Unlock()
	return r, nil
}

// inUse is what the owner reads about the choice.
func (c modelChoice) inUse() credentials.ModelInUse {
	return credentials.ModelInUse{Provider: c.doc.Provider, Source: c.source, ValueHash: c.valueHash, Issue: c.issue}
}

// sameRoute reports whether a and b differ in the key alone: the same
// provider at the same registry binding, so the same endpoint and facts.
func sameRoute(a, b inference.ProviderCredential) bool {
	if a.Provider != b.Provider || a.RouteHash != b.RouteHash || (a.Registry == nil) != (b.Registry == nil) {
		return false
	}
	return a.Registry == nil || *a.Registry == *b.Registry
}

// modelApply is what applying a pushed model key needs from the running
// sealed (startAgent).
type modelApply struct {
	keys    *modelKeys
	current func() settings.Doc
	applied func() modelChoice
	// setApplied records what the framework runs on (render records it too).
	setApplied func(modelChoice)
	// render renders the framework's settings and records the choice.
	render func(ctx context.Context, c modelChoice, resolved settings.Resolved) error
	// swap replaces the key sealed holds for the framework on host; false
	// when it holds none there.
	swap func(host string, value []byte) bool
	// reload restarts the framework on the current choice (its PreStart
	// renders it); while that cannot be rendered, the framework stays stopped.
	reload func(ctx context.Context) error
	// busy reports a framework (re)start under way.
	busy     func() bool
	setInUse func(credentials.ModelInUse)
}

// stoppedChoice is what the framework runs on after apply stopped it.
var stoppedChoice = modelChoice{source: "stopped"}

// apply makes the key the settings now choose the one in use: in place
// when sealed holds it for the framework and only the key changed,
// otherwise by restarting the framework on it. A key that cannot be used
// stops the framework rather than leave it on a key the owner's state no
// longer chooses. It returns what it did: "unchanged", "deferred" (a
// (re)start is under way: try again), "in_place", "restarted" or "stopped".
func (a modelApply) apply(ctx context.Context) string {
	choice := a.keys.choose(a.current())
	prev := a.applied()
	if choice.source == prev.source && choice.issue == prev.issue && choice.doc.Provider == prev.doc.Provider &&
		choice.credential.APIKey == prev.credential.APIKey && sameRoute(choice.credential, prev.credential) {
		return "unchanged"
	}
	// A (re)start under way renders what it read before this change, and a
	// reload asked for meanwhile is skipped.
	if a.busy() {
		return "deferred"
	}
	resolved, err := a.keys.resolve(ctx, choice)
	if err == nil {
		inPlace := choice.doc.Provider == prev.doc.Provider && sameRoute(choice.credential, prev.credential) && resolved.Endpoint != nil
		if err = a.render(ctx, choice, resolved); err == nil {
			if inPlace && a.swap(endpointHost(resolved.Endpoint), []byte(resolved.APIKey)) {
				return "in_place"
			}
		} else {
			err = fmt.Errorf("render: %w", err)
		}
	}
	// The restart renders the current choice again: a passing failure
	// clears, otherwise the framework stays stopped.
	if rerr := a.reload(ctx); rerr == nil {
		return "restarted"
	} else if err == nil {
		err = rerr
	}
	a.setApplied(stoppedChoice)
	a.setInUse(credentials.ModelInUse{Provider: choice.doc.Provider, Source: "none",
		Issue: "the model key the settings choose cannot be used (" + err.Error() + "); the framework is stopped until it can"})
	return "stopped"
}

func endpointHost(ep *inference.Endpoint) string {
	u, err := url.Parse(ep.BaseURL)
	if err != nil {
		return ""
	}
	return u.Host
}
