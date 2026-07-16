package uploader

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/chain"
	"seal-verify/internal/dataplane"
	"seal-verify/internal/framework"
	"seal-verify/internal/manifest"
	"seal-verify/internal/state"
)

// ── mocks ───────────────────────────────────────────────────────────────────

type mockStorage struct {
	mu            sync.Mutex
	blobs         map[[32]byte][]byte
	uploadCount   int
	downloadCount int
}

func newMockStorage() *mockStorage {
	return &mockStorage{blobs: map[[32]byte][]byte{}}
}

func (m *mockStorage) Upload(_ context.Context, ct []byte) ([32]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uploadCount++
	root := sha256.Sum256(ct)
	m.blobs[root] = append([]byte(nil), ct...)
	return root, nil
}

func (m *mockStorage) Download(_ context.Context, root [32]byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.downloadCount++
	ct, ok := m.blobs[root]
	if !ok {
		return nil, fmt.Errorf("mockStorage: blob 0x%x not found", root)
	}
	return ct, nil
}

type mockChain struct {
	mu          sync.Mutex
	entries     []chain.IntelligentData
	keys        map[[32]byte][]byte
	updateCount int
}

func newMockChain() *mockChain {
	return &mockChain{keys: map[[32]byte][]byte{}}
}

func (m *mockChain) IntelligentDatasOf(_ context.Context, _ *big.Int) ([]chain.IntelligentData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]chain.IntelligentData, len(m.entries))
	copy(out, m.entries)
	return out, nil
}

func (m *mockChain) SealedKeysOf(_ context.Context, _ *big.Int) (map[[32]byte][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[[32]byte][]byte, len(m.keys))
	for k, v := range m.keys {
		out[k] = append([]byte(nil), v...)
	}
	return out, nil
}

func (m *mockChain) Update(
	_ context.Context,
	_ *big.Int,
	newDatas []chain.IntelligentData,
	sealedKeys [][]byte,
	_ []byte,
) (common.Hash, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateCount++
	m.entries = append(m.entries[:0:0], newDatas...)
	m.keys = make(map[[32]byte][]byte, len(newDatas))
	for i, e := range newDatas {
		m.keys[e.DataHash] = append([]byte(nil), sealedKeys[i]...)
	}
	return common.Hash{}, nil
}

// mockAdapter implements the uploader.Adapter contract. Tests stub
// Roles/Defaults/EvolutionFor per role and per-entry LoadEntry content.
type mockAdapter struct {
	roles    []framework.RoleSpec
	defaults map[string][]byte
	evo      map[string][]byte
	entries  map[string]map[string][]byte
	loadLog  []string
}

func (m *mockAdapter) Roles() []framework.RoleSpec { return m.roles }
func (m *mockAdapter) Defaults(role string) []byte {
	v, ok := m.defaults[role]
	if !ok {
		// Sensible defaults so tests don't have to stub every role:
		// leaf → "{}" (matches openclaw.json's actual default);
		// manifest → empty manifest bytes.
		for _, r := range m.roles {
			if r.Name == role && r.Shape == framework.DirectoryManifest {
				b, _ := manifest.New().Marshal()
				return b
			}
		}
		return []byte("{}")
	}
	return v
}
func (m *mockAdapter) EvolutionFor(_ context.Context, role string) ([]byte, error) {
	v, ok := m.evo[role]
	if !ok {
		return nil, fmt.Errorf("mockAdapter: no EvolutionFor stub for %q", role)
	}
	return v, nil
}
func (m *mockAdapter) LoadEntry(_ context.Context, role, path string) ([]byte, error) {
	m.loadLog = append(m.loadLog, role+":"+path)
	r, ok := m.entries[role]
	if !ok {
		return nil, fmt.Errorf("mockAdapter: no LoadEntry stub for role %q", role)
	}
	v, ok := r[path]
	if !ok {
		return nil, fmt.Errorf("mockAdapter: no LoadEntry stub for %q/%q", role, path)
	}
	return v, nil
}

// ── fixtures ────────────────────────────────────────────────────────────────

type uploadHarness struct {
	storage *mockStorage
	chain   *mockChain
	adapter *mockAdapter
	state   *state.Agent
	up      *Uploader
}

func newHarness(t *testing.T, roles []framework.RoleSpec) *uploadHarness {
	t.Helper()
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	privBytes := crypto.FromECDSA(priv)
	pubBytes := crypto.CompressPubkey(&priv.PublicKey)

	adapter := &mockAdapter{
		roles:    roles,
		defaults: map[string][]byte{},
		evo:      map[string][]byte{},
		entries:  map[string]map[string][]byte{},
	}
	storage := newMockStorage()
	chn := newMockChain()
	agent := state.New()

	up := newWith(
		adapter, agent, chn, storage,
		big.NewInt(42), privBytes, pubBytes, "https://indexer.example",
	)
	return &uploadHarness{
		storage: storage,
		chain:   chn,
		adapter: adapter,
		state:   agent,
		up:      up,
	}
}

// stubManifestRole installs an EvolutionFor result + per-entry LoadEntry
// content for a DirectoryManifest role. Entry content_hashes inside the
// manifest are derived from the provided payloads so push diffing works.
func (h *uploadHarness) stubManifestRole(t *testing.T, role string, entries map[string][]byte) {
	t.Helper()
	m := manifest.New()
	for path, content := range entries {
		kind := manifest.EntryFile
		if path != "" && path[len(path)-1] == '/' {
			kind = manifest.EntryDir
		}
		m.Entries = append(m.Entries, manifest.Entry{
			Path:        path,
			Kind:        kind,
			ContentHash: manifest.HashHex(content),
			Size:        len(content),
		})
	}
	pt, err := m.Marshal()
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	h.adapter.evo[role] = pt
	roleMap := map[string][]byte{}
	for k, v := range entries {
		roleMap[k] = v
	}
	h.adapter.entries[role] = roleMap
}

func (h *uploadHarness) stubLeafRole(role string, plaintext []byte) {
	h.adapter.evo[role] = plaintext
}

func (h *uploadHarness) plaintexts() map[string][]byte {
	out := make(map[string][]byte, len(h.adapter.evo))
	for k, v := range h.adapter.evo {
		out[k] = v
	}
	return out
}

func (h *uploadHarness) findRoleOnChain(t *testing.T, role string) chain.IntelligentData {
	t.Helper()
	for _, e := range h.chain.entries {
		if roleOf(e.DataDescription) == role {
			return e
		}
	}
	t.Fatalf("role %q absent from chain after Apply", role)
	panic("unreachable")
}

// ── Apply tests ─────────────────────────────────────────────────────────────

// First Apply with empty chain + non-default disk for a leaf role:
// encrypts + uploads, submits one chain.Update.
func TestApply_LeafRole_FirstAddUploadsAndPushes(t *testing.T) {
	h := newHarness(t, []framework.RoleSpec{
		{Name: "framework", Shape: framework.Leaf},
	})
	h.stubLeafRole("framework", []byte(`{"name":"openclaw","schema_version":1}`))

	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if h.storage.uploadCount != 1 {
		t.Errorf("uploadCount = %d; want 1", h.storage.uploadCount)
	}
	if h.chain.updateCount != 1 {
		t.Errorf("updateCount = %d; want 1", h.chain.updateCount)
	}
	if len(h.chain.entries) != 1 || roleOf(h.chain.entries[0].DataDescription) != "framework" {
		t.Errorf("chain entries = %v; want one framework entry", h.chain.entries)
	}
}

// Apply when chain already matches disk: no encryption, no upload, no tx.
func TestApply_AllRolesInSync_SkipsTx(t *testing.T) {
	h := newHarness(t, []framework.RoleSpec{
		{Name: "framework", Shape: framework.Leaf},
	})
	h.stubLeafRole("framework", []byte(`{"name":"openclaw","schema_version":1}`))

	// First Apply lands the entry on chain.
	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatalf("Apply (initial): %v", err)
	}
	beforeUploads := h.storage.uploadCount
	beforeUpdates := h.chain.updateCount

	// Second Apply with identical disk content: should be a no-op.
	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatalf("Apply (no-op): %v", err)
	}
	if h.storage.uploadCount != beforeUploads {
		t.Errorf("uploadCount changed on no-op Apply: %d -> %d", beforeUploads, h.storage.uploadCount)
	}
	if h.chain.updateCount != beforeUpdates {
		t.Errorf("chain.Update fired on no-op Apply: %d -> %d", beforeUpdates, h.chain.updateCount)
	}
}

// findEntry returns the chain entry for a role, or nil. Test helper.
func findEntry(entries []chain.IntelligentData, role string) *chain.IntelligentData {
	for i := range entries {
		if roleOf(entries[i].DataDescription) == role {
			return &entries[i]
		}
	}
	return nil
}

// Disk equals adapter Defaults: a CONTENT role is omitted from newDatas.
// If chain had it, the entry gets dropped on the next Apply. §16.10.
// (Uses a content role, not "framework" — the framework binding is the
// identity anchor and is exempt from omit; see the next test.)
func TestApply_DiskEqualsDefaults_OmitsFromChain(t *testing.T) {
	h := newHarness(t, []framework.RoleSpec{
		{Name: "framework", Shape: framework.Leaf},
		{Name: "config", Shape: framework.Leaf},
	})
	h.adapter.defaults["framework"] = []byte(`{"name":"openclaw","schema_version":1}`)
	h.stubLeafRole("framework", []byte(`{"name":"openclaw","schema_version":1}`))
	h.adapter.defaults["config"] = []byte("default-cfg")
	// Put something non-default on chain via first Apply.
	h.stubLeafRole("config", []byte("active-cfg"))
	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatalf("Apply (seed chain): %v", err)
	}
	if findEntry(h.chain.entries, "config") == nil {
		t.Fatalf("expected chain to have config entry after seed")
	}

	// config drifts back to defaults — Apply should drop its chain entry.
	h.stubLeafRole("config", []byte("default-cfg"))
	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatalf("Apply (drop to default): %v", err)
	}
	if findEntry(h.chain.entries, "config") != nil {
		t.Errorf("config still on chain after reverting to default; want dropped")
	}
}

// The framework binding is the on-chain identity selector — it MUST stay
// on chain even when it equals the adapter default. Regression guard for
// the bug where a version-less binding resolving to whitelistMax equalled
// Defaults("framework"), got omitted, and a recreated claude-code
// container fell back to openclaw because its binding had vanished.
func TestApply_FrameworkRole_NeverOmittedAsDefault(t *testing.T) {
	h := newHarness(t, []framework.RoleSpec{
		{Name: "framework", Shape: framework.Leaf},
	})
	// Disk content is byte-equal to Defaults("framework").
	binding := []byte(`{"name":"claude-code","package_version":"2.1.198","schema_version":1}`)
	h.adapter.defaults["framework"] = binding
	h.stubLeafRole("framework", binding)
	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if findEntry(h.chain.entries, "framework") == nil {
		t.Fatal("framework binding omitted from chain — identity anchor lost; a recreated agent would fall back to the default framework")
	}
}

// Legacy chain entry (role outside adapter.Roles()): wholesale replacement
// naturally drops it on the next Apply. This is the persona → path-driven
// migration path.
func TestApply_DropsLegacyChainEntries(t *testing.T) {
	h := newHarness(t, []framework.RoleSpec{
		{Name: "framework", Shape: framework.Leaf},
	})
	// Seed framework normally.
	h.stubLeafRole("framework", []byte(`fw-content`))
	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatalf("Apply (seed): %v", err)
	}
	// Inject a "legacy" persona entry directly into the mock chain (as if
	// attestor minted it). Apply must drop it on the next call.
	personaDH := [32]byte{0xDE, 0xAD}
	personaDesc, _ := json.Marshal(onChainDescription{
		Role: "persona",
		StoragePtr: storagePtr{
			RootHash: "0xdead",
			Indexer:  "https://indexer.example",
			Size:     1,
		},
		Encryption: "AES-GCM-256",
	})
	h.chain.mu.Lock()
	h.chain.entries = append(h.chain.entries, chain.IntelligentData{
		DataDescription: string(personaDesc),
		DataHash:        personaDH,
	})
	h.chain.keys[personaDH] = []byte("fake-sealed-key")
	h.chain.mu.Unlock()

	// Re-apply. framework still in sync with chain → reuse; persona not in
	// declared roles → omitted; new array has only framework.
	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatalf("Apply (drop persona): %v", err)
	}
	if len(h.chain.entries) != 1 || roleOf(h.chain.entries[0].DataDescription) != "framework" {
		t.Errorf("after Apply chain = %v; want only [framework]", h.chain.entries)
	}
}

// Apply with two declared roles + one drifted: only the drifted role
// re-uploads; the in-sync role's chain entry is reused verbatim.
func TestApply_ReusesInSyncRoles(t *testing.T) {
	h := newHarness(t, []framework.RoleSpec{
		{Name: "framework", Shape: framework.Leaf},
		{Name: "openclaw.json", Shape: framework.Leaf},
	})
	h.stubLeafRole("framework", []byte("fw"))
	h.stubLeafRole("openclaw.json", []byte("oc-v1"))

	// First Apply seeds both on chain.
	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatalf("Apply (seed): %v", err)
	}
	uploadsAfterSeed := h.storage.uploadCount
	frameworkBefore := h.findRoleOnChain(t, "framework").DataHash

	// Drift only openclaw.json.
	h.stubLeafRole("openclaw.json", []byte("oc-v2-CHANGED"))
	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatalf("Apply (drift): %v", err)
	}

	// Exactly one new upload (the changed openclaw.json blob).
	if delta := h.storage.uploadCount - uploadsAfterSeed; delta != 1 {
		t.Errorf("upload delta after partial drift = %d; want 1 (only openclaw.json)", delta)
	}
	// framework entry must be unchanged (same DataHash, same sealedKey).
	frameworkAfter := h.findRoleOnChain(t, "framework").DataHash
	if frameworkBefore != frameworkAfter {
		t.Errorf("framework dataHash changed during partial drift: %x -> %x", frameworkBefore, frameworkAfter)
	}
}

// Manifest role: incremental upload — only changed entries re-encrypt.
func TestApply_Manifest_IncrementalOnlyChangedEntryReuploads(t *testing.T) {
	h := newHarness(t, []framework.RoleSpec{
		{Name: "workspace/skills/", Shape: framework.DirectoryManifest},
	})
	h.stubManifestRole(t, "workspace/skills/", map[string][]byte{
		"airdrop-hunter/": []byte("ah-v1"),
		"weather/":        []byte("weather-v1"),
	})
	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatalf("Apply v1: %v", err)
	}
	uploadsAfterFirst := h.storage.uploadCount
	loadsAfterFirst := len(h.adapter.loadLog)

	// Only modify airdrop-hunter.
	h.stubManifestRole(t, "workspace/skills/", map[string][]byte{
		"airdrop-hunter/": []byte("ah-v2-NEW"),
		"weather/":        []byte("weather-v1"),
	})
	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatalf("Apply v2: %v", err)
	}

	uploadsDelta := h.storage.uploadCount - uploadsAfterFirst
	loadsDelta := len(h.adapter.loadLog) - loadsAfterFirst
	// Expected: 1 new entry blob (airdrop-hunter) + 1 new manifest blob.
	if uploadsDelta != 2 {
		t.Errorf("incremental uploadDelta = %d; want 2 (changed entry + manifest)", uploadsDelta)
	}
	if loadsDelta != 1 {
		t.Errorf("incremental LoadEntry delta = %d; want 1 (only changed entry)", loadsDelta)
	}
}

// chainSnapshot moves forward after Apply succeeds: RecordChainUpload
// installs sha256(plaintext) so next tick sees in-sync. This is what
// makes "failed Apply re-tries automatically" work — chainSnapshot only
// advances on success.
func TestApply_AdvancesChainSnapshotOnSuccess(t *testing.T) {
	h := newHarness(t, []framework.RoleSpec{
		{Name: "framework", Shape: framework.Leaf},
	})
	plaintext := []byte("fw-payload")
	h.stubLeafRole("framework", plaintext)

	if err := h.up.Apply(context.Background(), h.plaintexts()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// chainSnapshot.ContentHash should be sha256(plaintext).
	contentSum := sha256.Sum256(plaintext)
	want := hex.EncodeToString(contentSum[:])
	got := h.state.ChainEntry("framework").ContentHash
	if got != want {
		t.Errorf("chainSnapshot.ContentHash = %q; want %q", got, want)
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

// (decryptViaTestKey kept for future tests that want to inspect what
// actually landed in the mock storage. Not used by the trimmed test set
// yet; left as a utility.)
func decryptViaTestKey(t *testing.T, h *uploadHarness, e chain.IntelligentData) []byte {
	t.Helper()
	sealedKey := h.chain.keys[e.DataHash]
	dk, err := dataplane.UnsealDataKey(sealedKey, h.up.agentSealPriv)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	var desc onChainDescription
	if err := json.Unmarshal([]byte(e.DataDescription), &desc); err != nil {
		t.Fatalf("parse dataDescription: %v", err)
	}
	rootHex := desc.StoragePtr.RootHash
	if len(rootHex) >= 2 && rootHex[:2] == "0x" {
		rootHex = rootHex[2:]
	}
	rb, _ := hex.DecodeString(rootHex)
	var root [32]byte
	copy(root[:], rb)
	ct, err := h.storage.Download(context.Background(), root)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	pt, err := dataplane.Decrypt(ct, dk)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return pt
}
