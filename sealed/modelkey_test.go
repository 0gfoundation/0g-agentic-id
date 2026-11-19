package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"seal-verify/internal/credentials"
	"seal-verify/internal/inference"
	"seal-verify/internal/settings"
)

type fakeModelKeys map[string]credentials.ModelKey

func (f fakeModelKeys) ModelKey(p string) (credentials.ModelKey, bool) {
	k, ok := f[p]
	return k, ok
}

func (f fakeModelKeys) ModelProviders() []string {
	var out []string
	for p := range f {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func stubCatalog(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "m", "supported_formats": []string{"openai"}}}})
	}))
	restore := inference.SetCatalogURLForTest(srv.URL)
	t.Cleanup(func() { restore(); srv.Close() })
}

var bootKey = inference.ProviderCredential{Provider: "0g-compute", APIKey: "sk-boot"}

// zgRoute is the built-in 0g-compute route, as a registry version binds it.
func zgRoute(t *testing.T) string {
	t.Helper()
	h, err := inference.DefaultRegistry.RouteHash("0g-compute")
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// The settings' provider picks the key: the owner's from the set when it
// holds one, else the one handed over at create/reset.
func TestModelKeyChoice(t *testing.T) {
	keys := &modelKeys{boot: bootKey}
	if c := keys.choose(settings.Doc{Provider: "0g-compute", Model: "m"}); c.source != "deploy" || c.credential.APIKey != "sk-boot" {
		t.Fatalf("credentials off: %+v", c)
	}
	keys.store = fakeModelKeys{
		"0g-compute": {Provider: "0g-compute", Value: []byte("sk-cred"), ValueHash: "0xaa"},
		"anthropic":  {Provider: "anthropic", Value: []byte("sk-ant")},
	}
	c := keys.choose(settings.Doc{Provider: "0g-compute", Model: "m"})
	if c.source != "credentials" || c.credential.APIKey != "sk-cred" || !c.credential.Bound || c.valueHash != "0xaa" {
		t.Fatalf("set key: %+v", c)
	}
	// The owner learns which provider the create/reset key serves, if usable.
	if c.inUse().DeployProvider != "0g-compute" {
		t.Fatalf("deploy provider: %+v", c.inUse())
	}
	if (&modelKeys{boot: inference.ProviderCredential{Invalid: true}}).choose(settings.Doc{Provider: "0g-compute"}).deployProvider != "" {
		t.Fatal("an unusable create/reset key named as usable")
	}
	if c := keys.choose(settings.Doc{Provider: "openai", Model: "m"}); c.source != "deploy" || c.credential.APIKey != "sk-boot" {
		t.Fatalf("no key for the provider: %+v", c)
	}
	// No provider, keys for two: none chosen, and the owner is told.
	c = keys.choose(settings.Doc{Model: "m"})
	if c.source != "none" || c.doc.Provider != "" || !strings.Contains(c.issue, "0g-compute, anthropic") {
		t.Fatalf("ambiguous: %+v", c)
	}
	// No provider, a key for one: that one.
	keys.store = fakeModelKeys{"anthropic": {Provider: "anthropic", Value: []byte("sk-ant")}}
	if c := keys.choose(settings.Doc{Model: "m"}); c.doc.Provider != "anthropic" || c.credential.APIKey != "sk-ant" || c.issue != "" {
		t.Fatalf("implied: %+v", c)
	}
	// No provider, no key: as before, no key at all.
	keys.store = fakeModelKeys{}
	if c := keys.choose(settings.Doc{Model: "m"}); c.source != "none" || c.issue != "" {
		t.Fatalf("nothing: %+v", c)
	}
}

// A key bound to a registry version is resolved against that version, read
// once per binding; one with no binding uses the image's built-in routes.
func TestModelKeyResolveReadsPinnedRegistryOnce(t *testing.T) {
	stubCatalog(t)
	pin := &inference.RegistryPin{Version: 3, Digest: "0x" + strings.Repeat("cd", 32)}
	keys := &modelKeys{boot: bootKey, store: fakeModelKeys{"0g-compute": {Provider: "0g-compute", Value: []byte("sk-cred"),
		RouteHash: zgRoute(t), Registry: pin}}}
	ctx := context.Background()
	doc := settings.Doc{Provider: "0g-compute", Model: "m"}
	if _, err := keys.resolve(ctx, keys.choose(doc)); err == nil || !strings.Contains(err.Error(), "chain bootstrap") {
		t.Fatalf("no loader: %v", err)
	}
	loads := 0
	keys.loadPinned = func(_ context.Context, c inference.ProviderCredential) (*inference.Registry, error) {
		loads++
		if c.Registry != pin {
			t.Fatalf("loaded %+v", c.Registry)
		}
		return inference.DefaultRegistry, nil
	}
	for i := 0; i < 2; i++ {
		r, err := keys.resolve(ctx, keys.choose(doc))
		if err != nil || r.APIKey != "sk-cred" {
			t.Fatalf("resolve: %v %q", err, r.APIKey)
		}
	}
	if loads != 1 {
		t.Fatalf("registry read %d times", loads)
	}
}

// What a pushed key does: nothing when the key in use did not change; a
// swap in place when sealed holds it on that host and only the key changed;
// otherwise a restart on it; and a key that cannot be used stops the
// framework rather than leave it on one the owner's state no longer chooses.
func TestModelKeyApply(t *testing.T) {
	stubCatalog(t)
	store := fakeModelKeys{}
	keys := &modelKeys{boot: bootKey, store: store}
	doc := settings.Doc{Provider: "0g-compute", Model: "m"}
	applied := keys.choose(doc)
	var rendered []string
	var swapped []string
	reloads, busy, failed := 0, false, false
	heldHost := "router-api.0g.ai"
	var reloadErr error
	var inUse credentials.ModelInUse
	a := modelApply{
		keys: keys, current: func() settings.Doc { return doc },
		applied:    func() modelChoice { return applied },
		setApplied: func(c modelChoice) { applied = c },
		render: func(_ context.Context, c modelChoice, r settings.Resolved) error {
			rendered = append(rendered, r.APIKey)
			applied = c
			return nil
		},
		swap: func(host string, v []byte) bool {
			if host != heldHost {
				return false
			}
			swapped = append(swapped, string(v))
			return true
		},
		reload:   func(context.Context) error { reloads++; return reloadErr },
		busy:     func() bool { return busy },
		failed:   func() bool { return failed },
		setInUse: func(m credentials.ModelInUse) { inUse = m },
	}
	ctx := context.Background()
	if got := a.apply(ctx); got != "unchanged" {
		t.Fatalf("nothing pushed: %s", got)
	}
	// A key for a provider the settings do not use is only kept.
	store["anthropic"] = credentials.ModelKey{Provider: "anthropic", Value: []byte("sk-ant")}
	if got := a.apply(ctx); got != "unchanged" || len(rendered) != 0 {
		t.Fatalf("other provider: %s", got)
	}
	// A (re)start under way: tried again later, nothing touched.
	store["0g-compute"] = credentials.ModelKey{Provider: "0g-compute", Value: []byte("sk-1")}
	busy = true
	if got := a.apply(ctx); got != "deferred" || len(rendered) != 0 {
		t.Fatalf("busy: %s", got)
	}
	// Even with the choice already rendered: the restart may yet give up.
	if got := (modelApply{keys: keys, current: a.current, applied: func() modelChoice { return keys.choose(doc) },
		busy: func() bool { return true }, failed: func() bool { return false }}).apply(ctx); got != "deferred" {
		t.Fatalf("busy, choice rendered: %s", got)
	}
	busy = false
	// The provider's key, same route: swapped in place where sealed holds it.
	if got := a.apply(ctx); got != "in_place" || reloads != 0 || swapped[0] != "sk-1" || rendered[0] != "sk-1" {
		t.Fatalf("in place: %s reloads=%d", got, reloads)
	}
	// In use once swapped: the framework already runs on it.
	if inUse.Source != "credentials" || inUse.Provider != "0g-compute" {
		t.Fatalf("in use after the swap: %+v", inUse)
	}
	// Held for another host (or not held: the framework has the key itself): restarted.
	heldHost = "elsewhere.example"
	store["0g-compute"] = credentials.ModelKey{Provider: "0g-compute", Value: []byte("sk-2")}
	if got := a.apply(ctx); got != "restarted" || reloads != 1 || len(swapped) != 1 {
		t.Fatalf("restart: %s", got)
	}
	// Another route (a pinned registry version): never in place.
	heldHost = "router-api.0g.ai"
	keys.loadPinned = func(context.Context, inference.ProviderCredential) (*inference.Registry, error) {
		return inference.DefaultRegistry, nil
	}
	store["0g-compute"] = credentials.ModelKey{Provider: "0g-compute", Value: []byte("sk-3"),
		RouteHash: zgRoute(t), Registry: &inference.RegistryPin{Version: 2, Digest: "0x" + strings.Repeat("cd", 32)}}
	if got := a.apply(ctx); got != "restarted" || reloads != 2 {
		t.Fatalf("new route: %s", got)
	}
	// A key that cannot be used: the framework restarts on it, which stops
	// it while that fails; the owner is told why.
	keys.loadPinned = func(context.Context, inference.ProviderCredential) (*inference.Registry, error) {
		return nil, errors.New("attestor down")
	}
	reloadErr = errors.New("pre-start: attestor down")
	store["0g-compute"] = credentials.ModelKey{Provider: "0g-compute", Value: []byte("sk-4"),
		RouteHash: zgRoute(t), Registry: &inference.RegistryPin{Version: 5, Digest: "0x" + strings.Repeat("cd", 32)}}
	if got := a.apply(ctx); got != "stopped" || reloads != 3 || applied.source != "stopped" ||
		inUse.Source != "none" || !strings.Contains(inUse.Issue, "attestor down") {
		t.Fatalf("unusable: %s %+v", got, inUse)
	}
	// The choice fails, yet the restart passes (a passing failure, or a
	// restart that began meanwhile): looked at again, not taken as applied.
	reloadErr = nil
	if got := a.apply(ctx); got != "deferred" {
		t.Fatalf("restart passed after a failure: %s", got)
	}
	reloadErr = errors.New("pre-start: attestor down")
	if got := a.apply(ctx); got != "stopped" {
		t.Fatalf("still unusable: %s", got)
	}
	// Tried again once it can be used.
	keys.loadPinned = func(context.Context, inference.ProviderCredential) (*inference.Registry, error) {
		return inference.DefaultRegistry, nil
	}
	reloadErr = nil
	if got := a.apply(ctx); got != "restarted" || applied.credential.APIKey != "sk-4" {
		t.Fatalf("recovered: %s", got)
	}
	// The key renders but the framework does not start: not the key's fault,
	// and tried again.
	store["0g-compute"] = credentials.ModelKey{Provider: "0g-compute", Value: []byte("sk-5"),
		RouteHash: zgRoute(t), Registry: &inference.RegistryPin{Version: 6, Digest: "0x" + strings.Repeat("cd", 32)}}
	reloadErr = errors.New("start: port in use")
	if got := a.apply(ctx); got != "restart_failed" || applied.source != "stopped" || !strings.Contains(inUse.Issue, "did not restart") {
		t.Fatalf("restart failed: %s %+v", got, inUse)
	}
	// The supervisor's own restart rendered the key (recorded as applied)
	// and gave up: the retry starts the framework again.
	applied = keys.choose(doc)
	failed = true
	before := reloads
	if got := a.apply(ctx); got != "restart_failed" || reloads != before+1 {
		t.Fatalf("given up, still failing: %s reloads=%d", got, reloads-before)
	}
	applied = keys.choose(doc)
	reloadErr = nil
	if got := a.apply(ctx); got != "restarted" || reloads != before+2 || len(rendered) == 0 {
		t.Fatalf("given up, then started: %s reloads=%d", got, reloads-before)
	}
	failed = false
	reloadErr = nil
	if got := a.apply(ctx); got != "unchanged" {
		t.Fatalf("running: %s", got)
	}
	// The key removed: back to the one handed over at create/reset.
	delete(store, "0g-compute")
	if got := a.apply(ctx); got != "restarted" || applied.source != "deploy" || rendered[len(rendered)-1] != "sk-boot" {
		t.Fatalf("removed: %s %+v", got, applied)
	}
}

// Removing the key in use with no other key for the provider stops the
// framework: it does not keep the removed key.
func TestRemovedKeyInUseStopsTheFramework(t *testing.T) {
	stubCatalog(t)
	store := fakeModelKeys{"anthropic": {Provider: "anthropic", Value: []byte("sk-ant")}}
	keys := &modelKeys{boot: bootKey, store: store}
	doc := settings.Doc{Provider: "anthropic", Model: "m"}
	applied := keys.choose(doc)
	if applied.credential.APIKey != "sk-ant" {
		t.Fatalf("in use %+v", applied)
	}
	var inUse credentials.ModelInUse
	a := modelApply{
		keys: keys, current: func() settings.Doc { return doc },
		applied:    func() modelChoice { return applied },
		setApplied: func(c modelChoice) { applied = c },
		render: func(context.Context, modelChoice, settings.Resolved) error {
			t.Fatal("rendered without a key")
			return nil
		},
		swap: func(string, []byte) bool { t.Fatal("swapped"); return false },
		// The restart renders the current choice, which fails: stopped.
		reload: func(ctx context.Context) error {
			_, err := keys.resolve(ctx, keys.choose(doc))
			return err
		},
		busy:     func() bool { return false },
		failed:   func() bool { return false },
		setInUse: func(m credentials.ModelInUse) { inUse = m },
	}
	delete(store, "anthropic")
	if got := a.apply(context.Background()); got != "stopped" || applied.credential.APIKey != "" || !strings.Contains(inUse.Issue, "CREDENTIAL_PROVIDER_MISMATCH") {
		t.Fatalf("removed in use: %s %+v %+v", got, applied, inUse)
	}
}
