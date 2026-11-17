package uploader

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"seal-verify/internal/chain"
	"seal-verify/internal/dataplane"
	"seal-verify/internal/framework"
)

// failingStorage fails the uploads whose 1-based number is in failOn, the
// way an unfunded seal wallet fails a storage submit.
type failingStorage struct {
	*mockStorage
	failOn map[int]bool
	calls  int
}

func (f *failingStorage) Upload(ctx context.Context, ct []byte) ([32]byte, error) {
	f.calls++
	if f.failOn[f.calls] {
		return [32]byte{}, fmt.Errorf("0g-storage upload: insufficient funds for gas * price + value")
	}
	return f.mockStorage.Upload(ctx, ct)
}

// failingChain fails the first failUpdates update transactions.
type failingChain struct {
	*mockChain
	failUpdates int
}

func (f *failingChain) Update(ctx context.Context, id *big.Int, d []chain.IntelligentData, k [][]byte, p []byte) (common.Hash, error) {
	if f.failUpdates > 0 {
		f.failUpdates--
		return common.Hash{}, fmt.Errorf("execution reverted")
	}
	return f.mockChain.Update(ctx, id, d, k, p)
}

// with rebuilds h.up on storage (and, when set, on c) with the same
// seal key.
func (h *uploadHarness) with(t *testing.T, storage StorageClient, c ChainClient) {
	t.Helper()
	if c == nil {
		c = h.chain
	}
	h.up = newWith(h.adapter, h.state, c, storage, big.NewInt(42), h.up.agentSealPriv, h.up.agentSealPub, "https://indexer.example")
}

// committedPlaintext decrypts a leaf role's committed blob with the key
// sealed on chain: it proves the blob and the sealed key belong together.
func (h *uploadHarness) committedPlaintext(t *testing.T, role string) []byte {
	t.Helper()
	e := h.findRoleOnChain(t, role)
	key, err := dataplane.UnsealDataKey(h.chain.keys[e.DataHash], h.up.agentSealPriv)
	if err != nil {
		t.Fatalf("unseal %s key: %v", role, err)
	}
	root, err := rootOf(e.DataDescription)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := dataplane.Decrypt(h.storage.blobs[root], key)
	if err != nil {
		t.Fatalf("decrypt %s with the key sealed on chain: %v", role, err)
	}
	return pt
}

// The dev failure (2026-11-17): a tick uploaded the framework role, then
// failed on the next role, and every retry uploaded the framework role again.
// Now the retry uploads only what is missing and sends one update.
func TestApply_RetryReusesWhatAFailedAttemptUploaded(t *testing.T) {
	h := newHarness(t, []framework.RoleSpec{
		{Name: "framework", Shape: framework.Leaf},
		{Name: "APPEND_SYSTEM.md", Shape: framework.Leaf},
	})
	h.stubLeafRole("framework", []byte(`{"name":"0g-harness","version":"0.2.0"}`))
	h.stubLeafRole("APPEND_SYSTEM.md", []byte("be brief"))
	fs := &failingStorage{mockStorage: h.storage, failOn: map[int]bool{2: true}}
	h.with(t, fs, nil)

	if err := h.up.Apply(context.Background(), h.plaintexts()); err == nil {
		t.Fatal("the attempt whose second upload failed succeeded")
	}
	if h.storage.uploadCount != 1 || h.chain.updateCount != 0 {
		t.Fatalf("after the failed attempt: %d uploads, %d updates; want 1, 0", h.storage.uploadCount, h.chain.updateCount)
	}
	var first [32]byte
	for root := range h.storage.blobs {
		first = root
	}

	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if h.storage.uploadCount != 2 {
		t.Errorf("uploads after the retry = %d; want 2 (the framework blob is not uploaded again)", h.storage.uploadCount)
	}
	if h.chain.updateCount != 1 {
		t.Errorf("updates = %d; want 1", h.chain.updateCount)
	}
	if got := h.findRoleOnChain(t, "framework").DataHash; got != first {
		t.Errorf("framework committed as 0x%x; want the blob the failed attempt uploaded, 0x%x", got, first)
	}
	// The reused blob was encrypted with the key minted in the failed
	// attempt: the update must seal that same key.
	if pt := h.committedPlaintext(t, "framework"); !bytes.Equal(pt, h.adapter.evo["framework"]) {
		t.Errorf("framework decrypts to %q", pt)
	}
	if pt := h.committedPlaintext(t, "APPEND_SYSTEM.md"); string(pt) != "be brief" {
		t.Errorf("APPEND_SYSTEM.md decrypts to %q", pt)
	}

	// In sync now: nothing more.
	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatal(err)
	}
	if h.storage.uploadCount != 2 || h.chain.updateCount != 1 {
		t.Errorf("in sync: %d uploads, %d updates; want 2, 1", h.storage.uploadCount, h.chain.updateCount)
	}
}

// A manifest role's entry blobs are kept the same way: a retry uploads the
// entries that are missing and the manifest, not the ones already up.
func TestApply_RetryReusesManifestEntryBlobs(t *testing.T) {
	h := newHarness(t, []framework.RoleSpec{{Name: "memory/", Shape: framework.DirectoryManifest}})
	h.stubManifestRole(t, "memory/", map[string][]byte{
		"a.md": []byte("---\nname: a\n---\nfirst"),
		"b.md": []byte("---\nname: b\n---\nsecond"),
	})
	fs := &failingStorage{mockStorage: h.storage, failOn: map[int]bool{2: true}}
	h.with(t, fs, nil)

	if err := h.up.Apply(context.Background(), h.plaintexts()); err == nil {
		t.Fatal("the attempt whose second upload failed succeeded")
	}
	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	// 1 entry blob, then the other entry blob and the manifest blob.
	if h.storage.uploadCount != 3 {
		t.Errorf("uploads = %d; want 3 (no entry blob uploaded twice)", h.storage.uploadCount)
	}
	// The entry uploaded in the failed attempt is not read again; the one
	// whose upload failed is.
	loads := map[string]int{}
	for _, l := range h.adapter.loadLog {
		loads[l]++
	}
	if len(h.adapter.loadLog) != 3 || len(loads) != 2 {
		t.Errorf("entries read %v; want the uploaded one once and the failed one twice", loads)
	}
	// The manifest and both entries decrypt with the key sealed on chain.
	e := h.findRoleOnChain(t, "memory/")
	key, err := dataplane.UnsealDataKey(h.chain.keys[e.DataHash], h.up.agentSealPriv)
	if err != nil {
		t.Fatal(err)
	}
	m, err := h.up.fetchOldManifest(context.Background(), &e, key)
	if err != nil {
		t.Fatalf("committed manifest: %v", err)
	}
	for _, me := range m.Entries {
		root, err := rootOf(`{"storage_ptr":{"root_hash":"` + me.StoragePtr.RootHash + `"}}`)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := dataplane.Decrypt(h.storage.blobs[root], key)
		if err != nil || !bytes.Equal(pt, h.adapter.entries["memory/"][me.Path]) {
			t.Errorf("%s decrypts to %q (%v)", me.Path, pt, err)
		}
	}
}

// When only the update failed, the retry sends the update and uploads
// nothing; when the content changed in between, the new content is uploaded
// and the stale blob is not used.
func TestApply_RetryAfterAFailedUpdate(t *testing.T) {
	h := newHarness(t, []framework.RoleSpec{{Name: "framework", Shape: framework.Leaf}})
	h.stubLeafRole("framework", []byte(`{"v":1}`))
	fc := &failingChain{mockChain: h.chain, failUpdates: 2}
	h.with(t, h.storage, fc)

	if err := h.up.Apply(context.Background(), h.plaintexts()); err == nil {
		t.Fatal("a failed update reported success")
	}
	if err := h.up.Apply(context.Background(), h.plaintexts()); err == nil {
		t.Fatal("a failed update reported success")
	}
	if h.storage.uploadCount != 1 {
		t.Fatalf("uploads after two failed updates = %d; want 1", h.storage.uploadCount)
	}

	h.stubLeafRole("framework", []byte(`{"v":2}`))
	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if h.storage.uploadCount != 2 || h.chain.updateCount != 1 {
		t.Errorf("%d uploads, %d updates; want 2, 1", h.storage.uploadCount, h.chain.updateCount)
	}
	if pt := h.committedPlaintext(t, "framework"); string(pt) != `{"v":2}` {
		t.Errorf("committed %q; want the new content", pt)
	}
}

// Commits that stop (an owner change refuses them at the gate) drop what
// was kept: nothing uploaded for this owner is reused for another.
func TestApply_CommitGateDropsWhatWasKept(t *testing.T) {
	h := newHarness(t, []framework.RoleSpec{{Name: "framework", Shape: framework.Leaf}})
	h.stubLeafRole("framework", []byte(`{"v":1}`))
	refuse := true
	h.up.SetCommitGate(func() error {
		if refuse {
			return fmt.Errorf("the agent belongs to another owner")
		}
		return nil
	})
	if err := h.up.Apply(context.Background(), h.plaintexts()); err == nil {
		t.Fatal("the gate did not stop the commit")
	}
	refuse = false
	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatal(err)
	}
	if h.storage.uploadCount != 2 {
		t.Errorf("uploads = %d; want 2 (nothing kept past the gate)", h.storage.uploadCount)
	}
}
