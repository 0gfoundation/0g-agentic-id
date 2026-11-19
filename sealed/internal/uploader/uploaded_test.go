package uploader

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"seal-verify/internal/dataplane"
	"seal-verify/internal/framework"
	"seal-verify/internal/manifest"
)

// apply runs one commit and returns how many blobs it uploaded.
func (h *uploadHarness) apply(t *testing.T) int {
	t.Helper()
	before := h.storage.uploadCount
	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return h.storage.uploadCount - before
}

// committedEntries decrypts every entry of a manifest role's committed
// manifest with the key sealed on chain.
func (h *uploadHarness) committedEntries(t *testing.T, role string) map[string][]byte {
	t.Helper()
	e := h.findRoleOnChain(t, role)
	key, err := dataplane.UnsealDataKey(h.chain.keys[e.DataHash], h.up.agentSealPriv)
	if err != nil {
		t.Fatal(err)
	}
	m, err := h.up.fetchOldManifest(context.Background(), &e, key)
	if err != nil {
		t.Fatalf("committed manifest: %v", err)
	}
	out := map[string][]byte{}
	for _, me := range m.Entries {
		root, err := rootOf(`{"storage_ptr":{"root_hash":"` + me.StoragePtr.RootHash + `"}}`)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := dataplane.Decrypt(h.storage.blobs[root], key)
		if err != nil {
			t.Fatalf("%s: %v", me.Path, err)
		}
		out[me.Path] = pt
	}
	return out
}

// Dev agent 625 (2026-11-18): memory/ went back to the content committed two
// commits earlier, and its entry and manifest blobs were uploaded again. A
// commit that comes back to content uploaded earlier in this boot now
// uploads nothing and commits the earlier manifest blob.
func TestApply_ManifestContentThatComesBackIsNotUploadedAgain(t *testing.T) {
	const role = "memory/"
	h := newHarness(t, []framework.RoleSpec{{Name: role, Shape: framework.DirectoryManifest}})
	v1 := map[string][]byte{"MEMORY.md": []byte("- a\n- b\n"), "a.md": []byte("alpha"), "b.md": []byte("beta")}
	h.stubManifestRole(t, role, v1)
	if n := h.apply(t); n != 4 {
		t.Fatalf("first commit uploaded %d blobs; want 4 (three entries and the manifest)", n)
	}
	first := h.findRoleOnChain(t, role).DataHash

	// A memory added, the index rewritten.
	h.stubManifestRole(t, role, map[string][]byte{"MEMORY.md": []byte("- a\n- b\n- c\n"), "a.md": []byte("alpha"), "b.md": []byte("beta"), "c.md": []byte("gamma")})
	if n := h.apply(t); n != 3 {
		t.Fatalf("second commit uploaded %d blobs; want 3 (c.md, MEMORY.md, the manifest)", n)
	}

	// And removed again: the role is as the first commit had it.
	h.stubManifestRole(t, role, v1)
	if n := h.apply(t); n != 0 {
		t.Errorf("the commit back to the first content uploaded %d blobs; want 0", n)
	}
	if h.chain.updateCount != 3 {
		t.Errorf("updates = %d; want 3 (the chain still has to point back)", h.chain.updateCount)
	}
	if got := h.findRoleOnChain(t, role).DataHash; got != first {
		t.Errorf("committed manifest 0x%x; want the first commit's, 0x%x", got, first)
	}
	got := h.committedEntries(t, role)
	if len(got) != len(v1) {
		t.Fatalf("committed %d entries; want %d", len(got), len(v1))
	}
	for p, want := range v1 {
		if !bytes.Equal(got[p], want) {
			t.Errorf("%s decrypts to %q; want %q", p, got[p], want)
		}
	}
}

// An entry blob is reused by content, whatever path holds it: a memory
// renamed costs the manifest only.
func TestApply_ManifestEntryMovedToAnotherPathIsNotUploadedAgain(t *testing.T) {
	const role = "memory/"
	h := newHarness(t, []framework.RoleSpec{{Name: role, Shape: framework.DirectoryManifest}})
	h.stubManifestRole(t, role, map[string][]byte{"a.md": []byte("alpha"), "b.md": []byte("beta")})
	h.apply(t)
	h.stubManifestRole(t, role, map[string][]byte{"renamed.md": []byte("alpha"), "b.md": []byte("beta")})
	if n := h.apply(t); n != 1 {
		t.Errorf("the rename uploaded %d blobs; want 1 (the manifest)", n)
	}
	if got := h.committedEntries(t, role)["renamed.md"]; string(got) != "alpha" {
		t.Errorf("renamed.md decrypts to %q", got)
	}
}

// A leaf role that comes back to content committed earlier commits that
// blob again.
func TestApply_LeafContentThatComesBackIsNotUploadedAgain(t *testing.T) {
	h := newHarness(t, []framework.RoleSpec{{Name: "APPEND_SYSTEM.md", Shape: framework.Leaf}})
	h.stubLeafRole("APPEND_SYSTEM.md", []byte("be brief"))
	h.apply(t)
	first := h.findRoleOnChain(t, "APPEND_SYSTEM.md").DataHash
	h.stubLeafRole("APPEND_SYSTEM.md", []byte("be thorough"))
	if n := h.apply(t); n != 1 {
		t.Fatalf("the change uploaded %d blobs; want 1", n)
	}
	h.stubLeafRole("APPEND_SYSTEM.md", []byte("be brief"))
	if n := h.apply(t); n != 0 {
		t.Errorf("the commit back uploaded %d blobs; want 0", n)
	}
	if got := h.findRoleOnChain(t, "APPEND_SYSTEM.md").DataHash; got != first {
		t.Errorf("committed 0x%x; want the first blob 0x%x", got, first)
	}
	if pt := h.committedPlaintext(t, "APPEND_SYSTEM.md"); string(pt) != "be brief" {
		t.Errorf("decrypts to %q", pt)
	}
}

// A blob is reused only under the key that encrypted it: a role dropped (its
// content back to the default) and added again gets a new key, and its
// content is uploaded again under it.
func TestApply_ARoleWithANewKeyUploadsAgain(t *testing.T) {
	h := newHarness(t, []framework.RoleSpec{{Name: "APPEND_SYSTEM.md", Shape: framework.Leaf}})
	h.stubLeafRole("APPEND_SYSTEM.md", []byte("be brief"))
	h.apply(t)
	h.stubLeafRole("APPEND_SYSTEM.md", []byte("{}")) // the default: dropped
	h.apply(t)
	if len(h.chain.entries) != 0 {
		t.Fatalf("the default content left %d entries on chain", len(h.chain.entries))
	}
	h.stubLeafRole("APPEND_SYSTEM.md", []byte("be brief"))
	if n := h.apply(t); n != 1 {
		t.Errorf("the role added again uploaded %d blobs; want 1 (a new key)", n)
	}
	if pt := h.committedPlaintext(t, "APPEND_SYSTEM.md"); string(pt) != "be brief" {
		t.Errorf("decrypts to %q", pt)
	}
}

// Commits that stop (an owner change) drop what was remembered too.
func TestApply_CommitGateDropsWhatWasUploaded(t *testing.T) {
	h := newHarness(t, []framework.RoleSpec{{Name: "APPEND_SYSTEM.md", Shape: framework.Leaf}})
	h.stubLeafRole("APPEND_SYSTEM.md", []byte("be brief"))
	h.apply(t)
	h.stubLeafRole("APPEND_SYSTEM.md", []byte("be thorough"))
	h.apply(t)
	refuse := true
	h.up.SetCommitGate(func() error {
		if refuse {
			return fmt.Errorf("the agent belongs to another owner")
		}
		return nil
	})
	h.stubLeafRole("APPEND_SYSTEM.md", []byte("be brief"))
	if err := h.up.Apply(context.Background(), h.plaintexts()); err == nil {
		t.Fatal("the gate did not stop the commit")
	}
	refuse = false
	before := h.storage.uploadCount
	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatal(err)
	}
	if n := h.storage.uploadCount - before; n != 1 {
		t.Errorf("after the gate: %d uploads; want 1 (nothing remembered past it)", n)
	}
}

// The remembered items are per role and per key, and bounded.
func TestUploadedBlobs(t *testing.T) {
	var u uploadedBlobs
	k1, k2 := keyID([]byte("key one")), keyID([]byte("key two"))
	p := manifest.StoragePtr{RootHash: "0x01", Size: 1}
	u.keepEntry("memory/", k1, "h", p)
	if got, ok := u.entry("memory/", k1, "h"); !ok || got != p {
		t.Fatalf("entry under its key: %+v %v", got, ok)
	}
	if _, ok := u.entry("memory/", k2, "h"); ok {
		t.Error("an entry found under another key")
	}
	if _, ok := u.entry("skills/", k1, "h"); ok {
		t.Error("an entry found under another role")
	}
	u.keepEntry("memory/", k2, "h2", p) // the role's key changed: it starts over
	if _, ok := u.entry("memory/", k1, "h"); ok {
		t.Error("an entry under the old key kept after the key changed")
	}
	for i := 0; i < maxRememberedPerRole+5; i++ {
		u.keepEntry("memory/", k2, fmt.Sprint(i), p)
	}
	u.mu.Lock()
	n := len(u.roles["memory/"].entries)
	u.mu.Unlock()
	if n > maxRememberedPerRole {
		t.Errorf("%d items kept; want at most %d", n, maxRememberedPerRole)
	}
}
