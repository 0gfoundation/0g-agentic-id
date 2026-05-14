package uploader

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"seal-verify/internal/chain"
	"seal-verify/internal/dataplane"
	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
)

// Apply is the canonical "sync chain to disk" entry point. Called once per
// watcher tick. Wholesale-replacement semantics: constructs newDatas
// strictly from the adapter's declared roles' disk content, so any chain
// entry whose role is outside adapter.Roles() (legacy mint-only roles like
// openclaw's `persona`) gets dropped automatically.
//
// Per declared role, comparing the plaintext on disk to chainSnapshot:
//
//   - disk == sha256(Defaults(role)): omit from newDatas. §16.10
//     invariant: "plaintext = defaults ↔ no chain entry".
//   - disk == chain plaintext (cached chainSnapshot.ContentHash): reuse
//     the existing chain.IntelligentData verbatim — no encryption, no
//     0g-storage upload, no new sealedKey. Bandwidth + storage savings
//     compound to ~zero waste on every all-stable tick.
//   - disk != chain: encrypt with reused (or fresh) data_key, upload
//     ciphertext to 0g-storage, build fresh chain.IntelligentData.
//
// data_key reuse: if a role is already on chain we unseal the existing
// data_key (essential for manifest mode, where child blobs reference
// each other via storage_ptr encoded with the role-level key). New roles
// generate a fresh key.
//
// If the constructed newDatas array exactly equals current chainEntries
// (same set of role → DataHash bindings), the tx is skipped — saves gas
// when watcher polls find no actual change.
//
// Failure handling: any error (encrypt, 0g-storage upload, chain.Update)
// returns immediately without mutating state. The next tick will re-
// compute and retry — because chainSnapshot is unchanged on failure, the
// drift signal persists and Apply is naturally re-invoked.
//
// plaintexts: caller (watcher tick) has already invoked adapter.EvolutionFor
// for every declared role this tick to seed currentSnapshot for /hello.
// It passes that same map in here so Apply doesn't re-read disk.
func (u *Uploader) Apply(ctx context.Context, plaintexts map[string][]byte) error {
	chainEntries, err := u.chain.IntelligentDatasOf(ctx, u.tokenID)
	if err != nil {
		return fmt.Errorf("uploader.Apply: read chain entries: %w", err)
	}
	chainSealedKeys, err := u.chain.SealedKeysOf(ctx, u.tokenID)
	if err != nil {
		return fmt.Errorf("uploader.Apply: read sealedKeysOf: %w", err)
	}

	// Lock every declared role for the duration so a concurrent Apply
	// (e.g. a future caller besides the watcher tick) can't race.
	for _, r := range u.adapter.Roles() {
		lock := u.lockFor(r.Name)
		lock.Lock()
		defer lock.Unlock()
	}

	type outcome struct {
		role        string
		contentHash string
		dataHash    string // 0x... when on chain after this tx; "" when role was dropped
	}
	var outcomes []outcome

	newEntries := make([]chain.IntelligentData, 0, len(u.adapter.Roles()))
	newSealedKeys := make([][]byte, 0, len(u.adapter.Roles()))

	for _, r := range u.adapter.Roles() {
		plaintext, ok := plaintexts[r.Name]
		if !ok {
			// Caller didn't compute plaintext for this role (EvolutionFor
			// likely failed this tick). Conservatively preserve chain
			// entry if it exists — otherwise omit.
			if chainEntry := findChainEntry(chainEntries, r.Name); chainEntry != nil {
				sk, ok := chainSealedKeys[chainEntry.DataHash]
				if !ok {
					return fmt.Errorf("uploader.Apply: role %q has iData but no sealedKey", r.Name)
				}
				newEntries = append(newEntries, *chainEntry)
				newSealedKeys = append(newSealedKeys, sk)
			}
			continue
		}

		contentSum := sha256.Sum256(plaintext)
		contentHashHex := hex.EncodeToString(contentSum[:])
		defaultSum := sha256.Sum256(u.adapter.Defaults(r.Name))
		isDefault := contentSum == defaultSum

		chainEntry := findChainEntry(chainEntries, r.Name)
		cachedChainHash := u.agent.ChainEntry(r.Name).ContentHash

		switch {
		case isDefault:
			// §16.10: defaults plaintext → no chain entry. Omit. If chain
			// did have it, the omission drops it on the next chain.Update.
			if chainEntry != nil {
				outcomes = append(outcomes, outcome{r.Name, contentHashHex, ""})
			}

		case chainEntry != nil && cachedChainHash == contentHashHex:
			// In sync with chain. Reuse the existing entry verbatim — no
			// new encryption, no new storage upload, sealedKey unchanged.
			sk, ok := chainSealedKeys[chainEntry.DataHash]
			if !ok {
				return fmt.Errorf("uploader.Apply: role %q has iData but no sealedKey", r.Name)
			}
			newEntries = append(newEntries, *chainEntry)
			newSealedKeys = append(newSealedKeys, sk)

		default:
			// Diverged from chain. Encrypt + upload + build fresh entry.
			dataKey, sealedKey, err := u.resolveKey(chainEntry, chainSealedKeys)
			if err != nil {
				return err
			}
			var newEntry chain.IntelligentData
			switch u.shapeOf(r.Name) {
			case framework.DirectoryManifest:
				newEntry, err = u.pushManifest(ctx, r.Name, plaintext, dataKey, chainEntry)
			default:
				newEntry, err = u.pushLeaf(ctx, r.Name, plaintext, dataKey)
			}
			if err != nil {
				return err
			}
			newEntries = append(newEntries, newEntry)
			newSealedKeys = append(newSealedKeys, sealedKey)
			outcomes = append(outcomes, outcome{
				role:        r.Name,
				contentHash: contentHashHex,
				dataHash:    "0x" + hex.EncodeToString(newEntry.DataHash[:]),
			})
		}
	}

	// Any chain entry whose role isn't declared in adapter.Roles() is
	// naturally absent from newEntries (the loop above never visits it).
	// Log the drops so the audit trail is legible.
	for _, e := range chainEntries {
		role := roleOf(e.DataDescription)
		if !u.isDeclared(role) {
			logger.Logf("uploader.Apply: dropping legacy chain role %q", role)
		}
	}

	// Skip the tx if computed state equals current chain state.
	if entriesEqual(newEntries, chainEntries) {
		return nil
	}

	logger.Logf("uploader.Apply: submitting wholesale update tx (%d entries, %d state changes)",
		len(newEntries), len(outcomes))
	if _, err = u.chain.Update(ctx, u.tokenID, newEntries, newSealedKeys, u.agentSealPriv); err != nil {
		return fmt.Errorf("uploader.Apply: chain.Update: %w", err)
	}

	// Sync chainSnapshot for every role whose state changed (added,
	// rebuilt, or dropped).
	for _, o := range outcomes {
		u.agent.RecordChainUpload(o.role, o.contentHash, o.dataHash)
	}
	return nil
}

// resolveKey decides whether to reuse the chain entry's existing data_key
// (essential for manifest mode child-blob continuity) or mint a fresh one.
// Returns (dataKey, sealedKey, err).
func (u *Uploader) resolveKey(
	chainEntry *chain.IntelligentData,
	chainSealedKeys map[[32]byte][]byte,
) ([]byte, []byte, error) {
	if chainEntry != nil {
		sealedKey, ok := chainSealedKeys[chainEntry.DataHash]
		if !ok {
			return nil, nil, fmt.Errorf("uploader.Apply: chain inconsistency (no sealedKey for existing iData)")
		}
		dataKey, err := dataplane.UnsealDataKey(sealedKey, u.agentSealPriv)
		if err != nil {
			return nil, nil, fmt.Errorf("uploader.Apply: unseal data_key: %w", err)
		}
		return dataKey, sealedKey, nil
	}
	dataKey, err := dataplane.NewDataKey()
	if err != nil {
		return nil, nil, fmt.Errorf("uploader.Apply: new data_key: %w", err)
	}
	sealedKey, err := dataplane.SealDataKey(dataKey, u.agentSealPub)
	if err != nil {
		return nil, nil, fmt.Errorf("uploader.Apply: seal data_key: %w", err)
	}
	return dataKey, sealedKey, nil
}

// isDeclared returns true if role is one of adapter.Roles().
func (u *Uploader) isDeclared(role string) bool {
	for _, r := range u.adapter.Roles() {
		if r.Name == role {
			return true
		}
	}
	return false
}

// findChainEntry returns a pointer to the chainEntries element matching
// role, or nil. Linear scan; chain typically has <10 entries so this is
// cheap relative to chain RPC.
func findChainEntry(entries []chain.IntelligentData, role string) *chain.IntelligentData {
	for i := range entries {
		if roleOf(entries[i].DataDescription) == role {
			return &entries[i]
		}
	}
	return nil
}

// entriesEqual reports whether two iData arrays are pairwise identical in
// role + DataHash (order-insensitive). Used as the no-op short-circuit
// inside Apply to skip identical chain.Update txs.
func entriesEqual(a, b []chain.IntelligentData) bool {
	if len(a) != len(b) {
		return false
	}
	indexed := make(map[string][32]byte, len(a))
	for _, e := range a {
		indexed[roleOf(e.DataDescription)] = e.DataHash
	}
	for _, e := range b {
		bh, ok := indexed[roleOf(e.DataDescription)]
		if !ok || !bytes.Equal(bh[:], e.DataHash[:]) {
			return false
		}
	}
	return true
}
