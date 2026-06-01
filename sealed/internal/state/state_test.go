package state

import (
	"testing"
)

// SeedChainSnapshot installs only the chain side of a dim's snapshot —
// currentSnapshot is left empty until the bootstrap's first
// UpdateCurrentSnapshot call. This separation is what lets reconciliation
// detect "disk diverges from chain" after Apply failures.
func TestSeedChainSnapshot_OnlyTouchesChain(t *testing.T) {
	a := New()
	a.SeedChainSnapshot("config", "abc123", "0xdeadbeef")

	// chainSnapshot has the seeded value
	if got, want := a.ChainDataHashes(), []string{"abc123"}; !equal(got, want) {
		t.Errorf("chain = %v; want %v", got, want)
	}
	// currentSnapshot is empty — phase 1 seed hasn't run yet
	if got := a.CurrentDataHashes(); len(got) != 0 {
		t.Errorf("current = %v; want empty (UpdateCurrentSnapshot hasn't been called)", got)
	}
}

// UpdateCurrentSnapshot returns false when current matches chain (no drift)
// even if content changed since last poll.
func TestUpdateCurrentSnapshot_InSyncWithChain(t *testing.T) {
	a := New()
	a.SeedChainSnapshot("config", "v1", "0xroot1")
	drifted := a.UpdateCurrentSnapshot("config", "v1")
	if drifted {
		t.Errorf("drift = true when current == chain; want false")
	}
	if a.HasChanges() {
		t.Errorf("HasChanges() = true after in-sync update; want false")
	}
}

// UpdateCurrentSnapshot returns true when current diverges from chain —
// the signal driving uploader.Apply.
func TestUpdateCurrentSnapshot_DriftFromChain(t *testing.T) {
	a := New()
	a.SeedChainSnapshot("config", "v1", "0xroot1")
	drifted := a.UpdateCurrentSnapshot("config", "v2")

	if !drifted {
		t.Errorf("drift = false when current != chain; want true")
	}
	if got, want := a.CurrentDataHashes(), []string{"v2"}; !equal(got, want) {
		t.Errorf("current after update = %v; want %v", got, want)
	}
	if got, want := a.ChainDataHashes(), []string{"v1"}; !equal(got, want) {
		t.Errorf("chain after update = %v; want %v (chain must not move)", got, want)
	}
	if !a.HasChanges() {
		t.Errorf("HasChanges() = false after drift; want true")
	}
}

// Reconciliation semantics: a failed Apply leaves chainSnapshot stale; the
// next tick's UpdateCurrentSnapshot still sees current != chain and
// returns drifted=true, naturally re-triggering Apply. This is the key
// behavioral difference from the old "current changed since last poll"
// model.
func TestUpdateCurrentSnapshot_RetriesAcrossTicks(t *testing.T) {
	a := New()
	a.SeedChainSnapshot("config", "v1", "0xroot1")

	// Tick 1: user edited config → disk hash v2; drift fires.
	if !a.UpdateCurrentSnapshot("config", "v2") {
		t.Fatal("tick 1: expected drift on first divergence")
	}
	// Apply fails (gas etc.) — chainSnapshot unchanged.

	// Tick 2: disk still v2; chain still v1; drift must fire again.
	if !a.UpdateCurrentSnapshot("config", "v2") {
		t.Errorf("tick 2: expected drift to persist when chainSnapshot stale; got false")
	}

	// Tick 3: still drifted.
	if !a.UpdateCurrentSnapshot("config", "v2") {
		t.Errorf("tick 3: expected drift to persist; got false")
	}
}

// First-tick reconciliation: when local plaintext already equals chain and
// the agent has no own-upload record, currentSnapshot adopts chain's
// DataHash so serve-proof reports a non-empty data_hash for the role.
// Without this, a role that never drifts produces a serve-proof envelope
// that the verifier judges ✗ (declared data_hash="" ≠ chain root).
func TestUpdateCurrentSnapshot_AdoptsChainDataHashWhenInSync(t *testing.T) {
	a := New()
	a.SeedChainSnapshot("framework", "h1", "0xroot1")

	if drifted := a.UpdateCurrentSnapshot("framework", "h1"); drifted {
		t.Fatalf("drift = true when current == chain; want false")
	}

	_, _, _, _, dh := a.Snapshot()
	got := dh["framework"]
	if got.ContentHash != "h1" || got.DataHash != "0xroot1" {
		t.Errorf("snapshot[framework] = %+v; want {content=h1, data=0xroot1}", got)
	}
}

// Fallback never overwrites an existing DataHash (e.g. one set by a prior
// RecordChainUpload). After upload-then-tick the carried-forward DataHash
// must stay authoritative.
func TestUpdateCurrentSnapshot_PrevDataHashWins(t *testing.T) {
	a := New()
	a.SeedChainSnapshot("framework", "h1", "0xroot1")
	a.UpdateCurrentSnapshot("framework", "h2")           // drift
	a.RecordChainUpload("framework", "h2", "0xroot2")    // own upload
	a.UpdateCurrentSnapshot("framework", "h2")           // tick

	_, _, _, _, dh := a.Snapshot()
	if got := dh["framework"].DataHash; got != "0xroot2" {
		t.Errorf("DataHash = %q; want 0xroot2 (RecordChainUpload value, not chain fallback)", got)
	}
}

// Fallback only fires when chain has a non-empty DataHash. Placeholder
// chain entries (role absent on chain) must not produce a fake data_hash.
func TestUpdateCurrentSnapshot_NoFallbackForPlaceholder(t *testing.T) {
	a := New()
	a.SeedChainSnapshot("workspace/skills/", "defaultHash", "") // placeholder
	a.UpdateCurrentSnapshot("workspace/skills/", "defaultHash")

	_, _, _, _, dh := a.Snapshot()
	if got := dh["workspace/skills/"].DataHash; got != "" {
		t.Errorf("DataHash = %q; want empty for chain-placeholder role", got)
	}
}

func TestRecordChainUpload_ClearsDrift(t *testing.T) {
	a := New()
	a.SeedChainSnapshot("config", "v1", "0xroot1")
	a.UpdateCurrentSnapshot("config", "v2")
	if !a.HasChanges() {
		t.Fatal("setup: expected drift after update")
	}
	a.RecordChainUpload("config", "v2", "0xroot2")
	if a.HasChanges() {
		t.Errorf("HasChanges() = true after upload sync; want false")
	}
	// Subsequent tick with same content should NOT fire drift.
	if a.UpdateCurrentSnapshot("config", "v2") {
		t.Errorf("drift = true after RecordChainUpload; want false")
	}
}

func TestMultiDim_Independent(t *testing.T) {
	a := New()
	a.SeedChainSnapshot("config", "c1", "0xc")
	a.SeedChainSnapshot("knowledge", "k1", "0xk")
	a.UpdateCurrentSnapshot("config", "c1")    // in sync
	a.UpdateCurrentSnapshot("knowledge", "k2") // drifted

	if !a.HasChanges() {
		t.Errorf("HasChanges() = false with one dim drifted; want true")
	}
	chain := a.ChainDataHashes()
	if !contains(chain, "c1") || !contains(chain, "k1") {
		t.Errorf("chain %v should still be c1 and k1", chain)
	}
}

func TestClear_ResetsSnapshots(t *testing.T) {
	a := New()
	a.SeedChainSnapshot("config", "v1", "0xroot1")
	a.UpdateCurrentSnapshot("config", "v1")
	a.Clear()
	if got := a.CurrentDataHashes(); len(got) != 0 {
		t.Errorf("current after Clear = %v; want empty", got)
	}
	if got := a.ChainDataHashes(); len(got) != 0 {
		t.Errorf("chain after Clear = %v; want empty", got)
	}
}

func TestSnapshot_ReturnsCurrentHashes(t *testing.T) {
	a := New()
	a.Set([]byte("priv"), "http://up", "sid", "owner")
	a.SeedChainSnapshot("config", "h1", "0xr1")
	a.UpdateCurrentSnapshot("config", "h2")

	_, _, _, _, dh := a.Snapshot()
	got, ok := dh["config"]
	// UpdateCurrentSnapshot carries forward the prior DataHash (empty in
	// currentSnapshot until RecordChainUpload bumps it). ChainSnapshot's
	// DataHash is 0xr1 but that's a separate accessor.
	if len(dh) != 1 || !ok || got.ContentHash != "h2" {
		t.Errorf("Snapshot dataHashes = %v; want {config: {content=h2, ...}}", dh)
	}
}

// helpers
func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}
