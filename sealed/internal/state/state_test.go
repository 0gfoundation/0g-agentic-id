package state

import (
	"testing"
)

func TestSeedSnapshots_BothEqual(t *testing.T) {
	a := New()
	a.SeedSnapshots("config", "abc123", "0xdeadbeef")

	if got, want := a.CurrentDataHashes(), []string{"abc123"}; !equal(got, want) {
		t.Errorf("current = %v; want %v", got, want)
	}
	if got, want := a.ChainDataHashes(), []string{"abc123"}; !equal(got, want) {
		t.Errorf("chain = %v; want %v", got, want)
	}
	if a.HasChanges() {
		t.Errorf("HasChanges() = true after seed; want false")
	}
}

func TestUpdateCurrent_DoesNotTouchChain(t *testing.T) {
	a := New()
	a.SeedSnapshots("config", "v1", "0xroot1")
	a.UpdateCurrent("config", "v2")

	if got, want := a.CurrentDataHashes(), []string{"v2"}; !equal(got, want) {
		t.Errorf("current after update = %v; want %v", got, want)
	}
	if got, want := a.ChainDataHashes(), []string{"v1"}; !equal(got, want) {
		t.Errorf("chain after update = %v; want %v (chain must not move)", got, want)
	}
	if !a.HasChanges() {
		t.Errorf("HasChanges() = false after update; want true")
	}
}

func TestUpdateCurrent_NoOpWhenSame(t *testing.T) {
	a := New()
	a.SeedSnapshots("config", "v1", "0xroot1")
	a.UpdateCurrent("config", "v1") // same content
	if a.HasChanges() {
		t.Errorf("HasChanges() = true after no-op update; want false")
	}
}

func TestRecordChainUpload_ResyncsBoth(t *testing.T) {
	a := New()
	a.SeedSnapshots("config", "v1", "0xroot1")
	a.UpdateCurrent("config", "v2")
	if !a.HasChanges() {
		t.Fatal("setup: expected drift after update")
	}
	a.RecordChainUpload("config", "v2", "0xroot2")
	if a.HasChanges() {
		t.Errorf("HasChanges() = true after upload sync; want false")
	}
	if got, want := a.CurrentDataHashes(), []string{"v2"}; !equal(got, want) {
		t.Errorf("current after upload = %v; want %v", got, want)
	}
	if got, want := a.ChainDataHashes(), []string{"v2"}; !equal(got, want) {
		t.Errorf("chain after upload = %v; want %v", got, want)
	}
}

func TestMultiDim_Independent(t *testing.T) {
	a := New()
	a.SeedSnapshots("config", "c1", "0xc")
	a.SeedSnapshots("knowledge", "k1", "0xk")
	a.UpdateCurrent("knowledge", "k2") // only knowledge changed

	if !a.HasChanges() {
		t.Errorf("HasChanges() = false with one dim drifted; want true")
	}
	cur := a.CurrentDataHashes()
	if !contains(cur, "c1") || !contains(cur, "k2") {
		t.Errorf("current %v should contain c1 and k2", cur)
	}
	chain := a.ChainDataHashes()
	if !contains(chain, "c1") || !contains(chain, "k1") {
		t.Errorf("chain %v should still be c1 and k1", chain)
	}
}

func TestClear_ResetsSnapshots(t *testing.T) {
	a := New()
	a.SeedSnapshots("config", "v1", "0xroot1")
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
	a.SeedSnapshots("config", "h1", "0xr1")
	a.UpdateCurrent("config", "h2")

	_, _, _, _, dh := a.Snapshot()
	// Snapshot returns DimHashes for every dim the agent is tracking,
	// with the latest ContentHash and the (carry-forward) DataHash.
	// UpdateCurrent must move ContentHash but leave DataHash on the
	// prior chain pin until a new tx confirms.
	got, ok := dh["config"]
	if len(dh) != 1 || !ok || got.ContentHash != "h2" || got.DataHash != "0xr1" {
		t.Errorf("Snapshot dataHashes = %v; want {config: {content=h2, data=0xr1}}", dh)
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
