package manifest

import (
	"bytes"
	"strings"
	"testing"
)

func TestMarshal_DeterministicSortedByPath(t *testing.T) {
	// Build same logical manifest with entries in two different orders.
	a := &Manifest{
		Entries: []Entry{
			{Path: "zebra", Kind: EntryFile, ContentHash: "0x1", Size: 1,
				StoragePtr: StoragePtr{RootHash: "0xa1", Size: 1}},
			{Path: "apple", Kind: EntryFile, ContentHash: "0x2", Size: 2,
				StoragePtr: StoragePtr{RootHash: "0xa2", Size: 2}},
			{Path: "mango", Kind: EntryFile, ContentHash: "0x3", Size: 3,
				StoragePtr: StoragePtr{RootHash: "0xa3", Size: 3}},
		},
	}
	b := &Manifest{
		Entries: []Entry{
			{Path: "apple", Kind: EntryFile, ContentHash: "0x2", Size: 2,
				StoragePtr: StoragePtr{RootHash: "0xa2", Size: 2}},
			{Path: "mango", Kind: EntryFile, ContentHash: "0x3", Size: 3,
				StoragePtr: StoragePtr{RootHash: "0xa3", Size: 3}},
			{Path: "zebra", Kind: EntryFile, ContentHash: "0x1", Size: 1,
				StoragePtr: StoragePtr{RootHash: "0xa1", Size: 1}},
		},
	}
	aBytes, err := a.Marshal()
	if err != nil {
		t.Fatalf("a.Marshal: %v", err)
	}
	bBytes, err := b.Marshal()
	if err != nil {
		t.Fatalf("b.Marshal: %v", err)
	}
	if !bytes.Equal(aBytes, bBytes) {
		t.Errorf("identical manifests marshaled to different bytes:\na = %s\nb = %s", aBytes, bBytes)
	}
	// Sanity: entries should be sorted ascending.
	idxApple := bytes.Index(aBytes, []byte(`"path":"apple"`))
	idxMango := bytes.Index(aBytes, []byte(`"path":"mango"`))
	idxZebra := bytes.Index(aBytes, []byte(`"path":"zebra"`))
	if !(idxApple < idxMango && idxMango < idxZebra) {
		t.Errorf("entries not in lex order: apple=%d mango=%d zebra=%d", idxApple, idxMango, idxZebra)
	}
}

func TestMarshal_DefaultsAppliedWhenZero(t *testing.T) {
	m := &Manifest{} // schema_version=0, kind=""
	b, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(b), `"schema_version":1`) {
		t.Errorf("schema_version not auto-filled: %s", b)
	}
	if !strings.Contains(string(b), `"kind":"directory_manifest"`) {
		t.Errorf("kind not auto-filled: %s", b)
	}
	if !strings.Contains(string(b), `"entries":[]`) {
		t.Errorf("nil entries not normalised to []: %s", b)
	}
}

func TestRoundtrip(t *testing.T) {
	original := New()
	original.Entries = []Entry{
		{Path: "SOUL.md", Kind: EntryFile, ContentHash: "0xabc", Size: 26,
			StoragePtr: StoragePtr{RootHash: "0xcafe", Size: 298}},
		{Path: "airdrop-hunter/", Kind: EntryDir, ContentHash: "0xdef", Size: 42100,
			StoragePtr: StoragePtr{RootHash: "0xbeef", Size: 42376}},
	}
	bytesOut, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := Unmarshal(bytesOut)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(parsed.Entries) != 2 {
		t.Fatalf("entry count = %d; want 2", len(parsed.Entries))
	}
	// Re-marshal should produce identical bytes (idempotent).
	bytesOut2, err := parsed.Marshal()
	if err != nil {
		t.Fatalf("Marshal #2: %v", err)
	}
	if !bytes.Equal(bytesOut, bytesOut2) {
		t.Errorf("round-trip not byte-stable:\nfirst:  %s\nsecond: %s", bytesOut, bytesOut2)
	}
}

func TestUnmarshal_RejectsWrongSchemaVersion(t *testing.T) {
	in := []byte(`{"schema_version":99,"kind":"directory_manifest","entries":[]}`)
	if _, err := Unmarshal(in); err == nil {
		t.Errorf("expected error on schema_version=99, got nil")
	}
}

func TestUnmarshal_RejectsWrongKind(t *testing.T) {
	in := []byte(`{"schema_version":1,"kind":"some_other_kind","entries":[]}`)
	if _, err := Unmarshal(in); err == nil {
		t.Errorf("expected error on wrong kind, got nil")
	}
}

func TestUnmarshal_AcceptsEmptyManifest(t *testing.T) {
	in := []byte(`{"schema_version":1,"kind":"directory_manifest","entries":[]}`)
	m, err := Unmarshal(in)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(m.Entries) != 0 {
		t.Errorf("entries should be empty, got %d", len(m.Entries))
	}
}

func TestEntryByPath(t *testing.T) {
	m := New()
	m.Entries = []Entry{
		{Path: "foo", Kind: EntryFile},
		{Path: "bar", Kind: EntryDir},
	}
	if e := m.EntryByPath("foo"); e == nil || e.Kind != EntryFile {
		t.Errorf("EntryByPath(foo) = %+v; want file entry", e)
	}
	if e := m.EntryByPath("baz"); e != nil {
		t.Errorf("EntryByPath(baz) = %+v; want nil", e)
	}
}

func TestHashHex_FormatAndDeterminism(t *testing.T) {
	h1 := HashHex([]byte("hello"))
	h2 := HashHex([]byte("hello"))
	if h1 != h2 {
		t.Errorf("HashHex not deterministic: %s vs %s", h1, h2)
	}
	if !strings.HasPrefix(h1, "0x") {
		t.Errorf("HashHex result missing 0x prefix: %s", h1)
	}
	// sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	want := "0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if h1 != want {
		t.Errorf("HashHex(hello) = %s; want %s", h1, want)
	}
}
