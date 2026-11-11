package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/credproxy"
	"seal-verify/internal/inference"
)

// defsDoc builds a signed document holding each definition with its value.
func (f *fixture) defsDoc(t *testing.T, version uint64, defs []Definition, values []string) Document {
	t.Helper()
	d := Document{Defs: map[string]string{}, Values: map[string]string{}}
	d.Set = CredentialSet{SealID: testSeal, OwnerEpoch: 7, Version: version}
	for i, def := range defs {
		ct, err := SealValue(f.sealECIES.PublicKey, crypto.PubkeyToAddress(f.owner.PublicKey), testSeal, f.domain.ChainID, def.Name, []byte(values[i]))
		if err != nil {
			t.Fatal(err)
		}
		def.V, def.ValueHash = 1, crypto.Keccak256Hash(ct).Hex()
		raw, _ := json.Marshal(def)
		d.Defs[def.Name] = base64.StdEncoding.EncodeToString(raw)
		d.Values[def.Name] = base64.StdEncoding.EncodeToString(ct)
		d.Set.Entries = append(d.Set.Entries, SetEntry{Name: def.Name, DefHash: crypto.Keccak256Hash(raw).Hex()})
	}
	digest, err := d.Set.Digest(f.domain)
	if err != nil {
		t.Fatal(err)
	}
	d.Signature = f.sign(t, digest, f.owner)
	return d
}

func modelDef(provider string) Definition {
	return Definition{Name: ModelKeyPrefix + provider, Use: UseModel, Inference: &InferenceSpec{Provider: provider}}
}

func githubDef() Definition {
	return Definition{Name: "github", Hosts: []string{"api.github.com"}, Use: credproxy.UseInject,
		Positions: []credproxy.Position{{Kind: credproxy.PosHeader, Name: "Authorization", Template: "Bearer {v}"}}}
}

// A model key is sealed's own: kept for the framework, never served by the
// proxy, listed to the harness, or revealed.
func TestModelKeyKeptApartFromEntries(t *testing.T) {
	f := newFixture(t)
	s, reg, _ := f.store(t, nil, nil)
	ctx := context.Background()
	calls := make(chan struct{}, 4)
	s.OnModelKeys(func() { calls <- struct{}{} })
	pinned := modelDef("acme")
	pinned.Inference.RouteHash = "0x" + strings.Repeat("ab", 32)
	pinned.Inference.Registry = &inference.RegistryPin{Version: 4, Digest: "0x" + strings.Repeat("cd", 32)}
	doc := f.defsDoc(t, 1, []Definition{githubDef(), modelDef("0g-compute"), pinned}, []string{"ghp_x", "sk-zg-1", "sk-acme"})
	o, err := s.Load(ctx, doc, 0)
	if err != nil || len(o.Skipped) != 0 {
		t.Fatalf("load: %v %+v", err, o.Skipped)
	}
	k, ok := s.ModelKey("0g-compute")
	if !ok || string(k.Value) != "sk-zg-1" || k.Name != "model.0g-compute" || k.RouteHash != "" || k.Registry != nil {
		t.Fatalf("model key %+v %v", k, ok)
	}
	if k, _ := s.ModelKey("acme"); k.RouteHash != pinned.Inference.RouteHash || k.Registry == nil || k.Registry.Version != 4 {
		t.Fatalf("pinned key %+v", k)
	}
	if got := s.ModelProviders(); len(got) != 2 || got[0] != "0g-compute" || got[1] != "acme" {
		t.Fatalf("providers %v", got)
	}
	if reg.Get("model.0g-compute") != nil || reg.Get("github") == nil {
		t.Fatalf("registry %v", reg.Names())
	}
	for _, e := range s.List() {
		if strings.HasPrefix(e.Name, ModelKeyPrefix) {
			t.Fatalf("the harness is shown %s", e.Name)
		}
	}
	if _, cerr := s.Reveal(ctx, "model.0g-compute", "why"); cerr == nil {
		t.Fatal("a model key was revealed")
	}
	<-calls
	// Another entry changes, the keys do not: nothing to apply.
	doc = f.defsDoc(t, 2, []Definition{modelDef("0g-compute"), pinned}, []string{"sk-zg-1", "sk-acme"})
	if _, err := s.Load(ctx, doc, 0); err != nil {
		t.Fatal(err)
	}
	// A new key is applied; a removed one is gone.
	doc = f.defsDoc(t, 3, []Definition{modelDef("0g-compute")}, []string{"sk-zg-2"})
	if _, err := s.Load(ctx, doc, 0); err != nil {
		t.Fatal(err)
	}
	<-calls
	if len(calls) != 0 {
		t.Fatal("an unchanged key was applied again")
	}
	if k, _ := s.ModelKey("0g-compute"); string(k.Value) != "sk-zg-2" {
		t.Fatalf("key %q", k.Value)
	}
	if _, ok := s.ModelKey("acme"); ok {
		t.Fatal("a removed key is kept")
	}
	audit, _ := json.Marshal(s.AuditSince(0))
	if !strings.Contains(string(audit), "model key set") || !strings.Contains(string(audit), "model key removed") || strings.Contains(string(audit), "sk-zg") {
		t.Fatalf("audit %s", audit)
	}
	// The owner changes: the keys go with everything else.
	s.Clear()
	if _, ok := s.ModelKey("0g-compute"); ok || s.ModelInUse().Source != "none" {
		t.Fatal("a model key outlived its owner")
	}
}

// A model key definition says nothing but its binding; anything that would
// let the key reach elsewhere skips it.
func TestModelKeyRefusals(t *testing.T) {
	f := newFixture(t)
	cases := map[string]func(d *Definition) string{
		"misnamed": func(d *Definition) string { d.Name = "model.other"; return "sk" },
		"hosts":    func(d *Definition) string { d.Hosts = []string{"evil.example"}; return "sk" },
		"position": func(d *Definition) string {
			d.Positions = []credproxy.Position{{Kind: credproxy.PosHeader, Name: "X", Template: "{v}"}}
			return "sk"
		},
		"reveal":    func(d *Definition) string { d.AllowReveal = true; return "sk" },
		"writeback": func(d *Definition) string { d.Writeback = true; return "sk" },
		"sign":      func(d *Definition) string { d.Use = credproxy.UseSign; return "sk" },
		"inject":    func(d *Definition) string { d.Use = credproxy.UseInject; return "sk" },
		"expires":   func(d *Definition) string { d.ExpiresAt = 1; return "sk" },
		"route only": func(d *Definition) string {
			d.Inference.RouteHash = "0x" + strings.Repeat("ab", 32)
			return "sk"
		},
		"bad route": func(d *Definition) string {
			d.Inference.RouteHash, d.Inference.Registry = "0xAB", &inference.RegistryPin{Version: 1, Digest: "0x" + strings.Repeat("cd", 32)}
			return "sk"
		},
		"v0 digest": func(d *Definition) string {
			d.Inference.RouteHash, d.Inference.Registry = "0x"+strings.Repeat("ab", 32), &inference.RegistryPin{Version: 0, Digest: "0x" + strings.Repeat("cd", 32)}
			return "sk"
		},
		"newline": func(d *Definition) string { return "sk\nX-Evil: 1" },
	}
	for name, edit := range cases {
		d := modelDef("0g-compute")
		value := edit(&d)
		o, err := Open(f.defsDoc(t, 1, []Definition{d}, []string{value}), f.check())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, ok := o.Skipped[d.Name]; !ok || o.Defs[d.Name] != nil {
			t.Fatalf("%s: taken (%+v)", name, o.Skipped)
		}
	}
}

// A value sealed holds for the framework is replaced where it is filled in,
// only on the host it is held for, and released before the framework starts.
func TestSwapAndReleaseSystemValue(t *testing.T) {
	f := newFixture(t)
	s, reg, _ := f.store(t, nil, nil)
	if s.SwapSystemValue("sealed:inference", "router-api.0g.ai", []byte("k2")) {
		t.Fatal("swapped a value never held")
	}
	e := &credproxy.Entry{Name: "sealed:inference", Hosts: []string{"router-api.0g.ai"}, Use: credproxy.UseInject, Value: []byte("k1"),
		Positions: []credproxy.Position{{Kind: credproxy.PosHeader, Name: "Authorization", Template: "Bearer {v}"}}}
	if err := s.HoldSystem(e); err != nil {
		t.Fatal(err)
	}
	if s.SwapSystemValue("sealed:inference", "other.example", []byte("k2")) {
		t.Fatal("swapped a value held for another host")
	}
	if !s.SwapSystemValue("sealed:inference", "router-api.0g.ai", []byte("k2")) {
		t.Fatal("not swapped")
	}
	got := reg.Get("sealed:inference")
	if got == nil || string(got.Value) != "k2" || got.Hosts[0] != "router-api.0g.ai" || string(e.Value) != "k1" {
		t.Fatalf("held %+v", got)
	}
	s.ReleaseSystem("sealed:inference")
	if reg.Get("sealed:inference") != nil {
		t.Fatal("a released value is still filled in")
	}
	if err := s.HoldSystem(e); err != nil {
		t.Fatal(err)
	}
	s.Clear()
	if s.SwapSystemValue("sealed:inference", "router-api.0g.ai", []byte("k3")) {
		t.Fatal("swapped after the owner changed")
	}
}

// The same key sealed again (a new ciphertext) is not applied again, but
// what the owner reads names the entry now stored; a changed key clears an
// earlier issue until the framework's side applies or refuses it.
func TestModelInUseFollowsTheStoredEntry(t *testing.T) {
	f := newFixture(t)
	s, _, _ := f.store(t, nil, nil)
	ctx := context.Background()
	calls := make(chan struct{}, 4)
	s.OnModelKeys(func() { calls <- struct{}{} })
	if _, err := s.Load(ctx, f.defsDoc(t, 1, []Definition{modelDef("0g-compute")}, []string{"sk-1"}), 0); err != nil {
		t.Fatal(err)
	}
	<-calls
	k, _ := s.ModelKey("0g-compute")
	s.SetModelInUse(ModelInUse{Provider: "0g-compute", Source: "credentials", ValueHash: k.ValueHash, Issue: "x"})
	if _, err := s.Load(ctx, f.defsDoc(t, 2, []Definition{modelDef("0g-compute")}, []string{"sk-1"}), 0); err != nil {
		t.Fatal(err)
	}
	k2, _ := s.ModelKey("0g-compute")
	if k2.ValueHash == k.ValueHash || s.ModelInUse().ValueHash != k2.ValueHash || len(calls) != 0 {
		t.Fatalf("in use %+v, calls %d", s.ModelInUse(), len(calls))
	}
	if _, err := s.Load(ctx, f.defsDoc(t, 3, []Definition{modelDef("0g-compute")}, []string{"sk-2"}), 0); err != nil {
		t.Fatal(err)
	}
	<-calls
	if s.ModelInUse().Issue != "" {
		t.Fatalf("an earlier issue outlived a new key: %+v", s.ModelInUse())
	}
}
