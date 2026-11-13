package uploader

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"seal-verify/internal/dataplane"
	"seal-verify/internal/framework"
	"seal-verify/internal/manifest"
	"seal-verify/internal/state"
)

// Known-answer vectors for the commitments (sealed/LAYERS.md §7.1),
// computed independently with Python's hmac and hashlib: data key 0x01…01;
// the leaf role APPEND_SYSTEM.md holding "persona" under storage root
// 0x22…22; the directory role skills/ with entries a.md ("A", root 0x33…33),
// b/ ("B", 0x44…44) and c.md ("C", 0x55…55), in that order.
const (
	katLeafCommitment = "d25091d7acf158c645c5390af06aeb6830cf8f910e97020e4fbdd88bb1695c7d"
	katDirCommitment  = "a4692720eb4dfa39999900d687e669812b29eee3c359f1b02c7a78a3d3c63078"
	katDirLeafA       = "c43348dbaeb3a05e292f6d4d63e2e964e5ec40aefca15c8e19400cd27d6a474c"
)

func fill(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func hexOf(b [32]byte) string { return "0x" + hex.EncodeToString(b[:]) }

func katManifest() *manifest.Manifest {
	m := manifest.New()
	for _, e := range []struct {
		path, content string
		root          byte
	}{{"a.md", "A", 0x33}, {"b/", "B", 0x44}, {"c.md", "C", 0x55}} {
		sum := sha256.Sum256([]byte(e.content))
		m.Entries = append(m.Entries, manifest.Entry{Path: e.path, Kind: manifest.EntryFile, ContentHash: hexOf(sum), Size: len(e.content),
			StoragePtr: manifest.StoragePtr{RootHash: hexOf(fill(e.root))}})
	}
	return m
}

func TestCommitmentsKnownAnswers(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	if got := leafCommitment(key, "APPEND_SYSTEM.md", fill(0x22), []byte("persona")); hex.EncodeToString(got[:]) != katLeafCommitment {
		t.Fatalf("leaf commitment 0x%x, want 0x%s", got, katLeafCommitment)
	}
	got, err := manifestCommitment(key, "skills/", katManifest())
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != katDirCommitment {
		t.Fatalf("directory commitment 0x%x, want 0x%s", got, katDirCommitment)
	}
	// One entry alone: its leaf is the root, the vector for a single-file proof.
	one := katManifest()
	one.Entries = one.Entries[:1]
	if got, _ := manifestCommitment(key, "skills/", one); hex.EncodeToString(got[:]) != katDirLeafA {
		t.Fatalf("single-entry commitment 0x%x, want 0x%s", got, katDirLeafA)
	}
}

// The commitment hides the plaintext behind a salt only the data key gives,
// and changes with the role, the root and the content.
func TestCommitmentsBindEveryInput(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	base := leafCommitment(key, "APPEND_SYSTEM.md", fill(0x22), []byte("persona"))
	for name, other := range map[string][32]byte{
		"key":     leafCommitment(bytes.Repeat([]byte{2}, 32), "APPEND_SYSTEM.md", fill(0x22), []byte("persona")),
		"role":    leafCommitment(key, "skills/", fill(0x22), []byte("persona")),
		"root":    leafCommitment(key, "APPEND_SYSTEM.md", fill(0x23), []byte("persona")),
		"content": leafCommitment(key, "APPEND_SYSTEM.md", fill(0x22), []byte("persona!")),
	} {
		if other == base {
			t.Errorf("a different %s gives the same commitment", name)
		}
	}
	if unsalted := sha256.Sum256([]byte("persona")); base == unsalted {
		t.Error("the commitment is the plain hash")
	}
}

func decryptManifest(ct, key []byte) (*manifest.Manifest, error) {
	pt, err := dataplane.Decrypt(ct, key)
	if err != nil {
		return nil, err
	}
	return manifest.Unmarshal(pt)
}

func description(t *testing.T, d string) onChainDescription {
	t.Helper()
	var out onChainDescription
	if err := json.Unmarshal([]byte(d), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Entries carry commitments only when they are turned on, and then the
// ones the definitions above give for what was uploaded.
func TestUploadsCarryCommitments(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	contents := map[string][]byte{"a.md": []byte("A"), "b.md": []byte("B")}
	adapter := &mockAdapter{
		roles:   []framework.RoleSpec{{Name: "APPEND_SYSTEM.md", Shape: framework.Leaf}, {Name: "skills/", Shape: framework.DirectoryManifest}},
		entries: map[string]map[string][]byte{"skills/": contents},
	}
	m := manifest.New()
	for _, p := range []string{"a.md", "b.md"} {
		sum := sha256.Sum256(contents[p])
		m.Entries = append(m.Entries, manifest.Entry{Path: p, Kind: manifest.EntryFile, ContentHash: hexOf(sum), Size: len(contents[p])})
	}
	plain, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	for _, on := range []bool{false, true} {
		u := newWith(adapter, state.New(), newMockChain(), newMockStorage(), nil, nil, nil, "https://indexer.example")
		u.SetPlaintextCommitments(on)

		leaf, err := u.pushLeaf(context.Background(), "APPEND_SYSTEM.md", []byte("persona"), key)
		if err != nil {
			t.Fatal(err)
		}
		d := description(t, leaf.DataDescription)
		if !on {
			if d.Commitments != nil {
				t.Fatalf("commitments off, but the leaf entry carries %+v", d.Commitments)
			}
		} else if want := commitmentsOf(leafCommitment(key, "APPEND_SYSTEM.md", leaf.DataHash, []byte("persona"))); d.Commitments == nil || *d.Commitments != *want {
			t.Fatalf("leaf commitments %+v, want %+v", d.Commitments, want)
		}

		dir, err := u.pushManifest(context.Background(), "skills/", plain, key, nil)
		if err != nil {
			t.Fatal(err)
		}
		d = description(t, dir.DataDescription)
		if !on {
			if d.Commitments != nil {
				t.Fatalf("commitments off, but the manifest entry carries %+v", d.Commitments)
			}
			continue
		}
		// Rebuild the filled manifest from storage to recompute the commitment.
		ct, err := u.storage.(*mockStorage).Download(context.Background(), dir.DataHash)
		if err != nil {
			t.Fatal(err)
		}
		filled, err := decryptManifest(ct, key)
		if err != nil {
			t.Fatal(err)
		}
		c, err := manifestCommitment(key, "skills/", filled)
		if err != nil {
			t.Fatal(err)
		}
		if d.Commitments == nil || d.Commitments.SHA256 != hexOf(c) {
			t.Fatalf("manifest commitments %+v, want %s", d.Commitments, hexOf(c))
		}
	}
}
