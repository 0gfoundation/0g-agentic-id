// Package uploader syncs the agent's on-chain iData state to its on-disk
// state via a single wholesale-replacement primitive: Apply.
//
// Per-tick flow (watcher → Apply):
//
//  1. Caller (watcher) has already invoked adapter.EvolutionFor for every
//     declared role and passes the (role → plaintext) map to Apply.
//  2. Apply reads current chain entries + sealedKeys.
//  3. For each declared role:
//       - plaintext == sha256(Defaults): omit from newDatas. §16.10
//         "plaintext = defaults ↔ no chain entry".
//       - plaintext == chainSnapshot.ContentHash: reuse chain entry
//         verbatim (no re-encrypt, no upload).
//       - otherwise: encrypt + upload to 0g-storage, build fresh entry;
//         reuse data_key when chain has prior entry (so manifest child
//         blobs stay decipherable), mint fresh otherwise.
//  4. Anything on chain whose role is outside adapter.Roles() (e.g. mint-
//     only `persona` after bootstrap translation) is dropped — never
//     visited in the per-role loop, never written into newDatas.
//  5. If newDatas equals current chainEntries → skip the tx.
//  6. Otherwise chain.Update once with the full new arrays.
//  7. agent.RecordChainUpload for every role whose state changed.
//
// Failures: any error (encrypt, 0g-storage upload, chain.Update) returns
// without mutating state. The next watcher tick re-detects divergence
// (chainSnapshot stays stale, current still differs) and Apply re-runs
// naturally — no special retry path needed.
package uploader

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/chain"
	"seal-verify/internal/framework"
	"seal-verify/internal/state"
)

// onChainDescription mirrors the JSON layout the attestor writes into
// IntelligentData.dataDescription at mint time (see attestor crate
// worker/src/jobs.rs build of `on_chain_description`). Sealed reads only
// role + storage_ptr; extra fields are kept verbatim so we don't lose
// metadata attestor may surface later. size is the ciphertext length in
// bytes; encryption is fixed to AES-GCM-256 to match attestor.
type onChainDescription struct {
	Role       string     `json:"role"`
	StoragePtr storagePtr `json:"storage_ptr"`
	Encryption string     `json:"encryption"`
}

type storagePtr struct {
	RootHash string `json:"root_hash"`
	Indexer  string `json:"indexer"`
	Size     int    `json:"size"`
}

// roleOf returns the role tag inside a JSON-wrapped dataDescription.
// Falls back to the raw string if the description doesn't parse as JSON
// (e.g. legacy bare-role entries written by an older uploader build).
func roleOf(desc string) string {
	var d struct {
		Role string `json:"role"`
	}
	if err := json.Unmarshal([]byte(desc), &d); err == nil && d.Role != "" {
		return d.Role
	}
	return desc
}

// rootOf returns the 0g-storage root referenced by an iData entry's
// dataDescription. Used by manifest mode to download the prior manifest
// blob for incremental diffing.
func rootOf(desc string) ([32]byte, error) {
	var d onChainDescription
	if err := json.Unmarshal([]byte(desc), &d); err != nil {
		return [32]byte{}, fmt.Errorf("parse dataDescription: %w", err)
	}
	hexStr := d.StoragePtr.RootHash
	if len(hexStr) >= 2 && hexStr[:2] == "0x" {
		hexStr = hexStr[2:]
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(b) != 32 {
		return [32]byte{}, fmt.Errorf("invalid storage_ptr.root_hash %q", d.StoragePtr.RootHash)
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

// Uploader bundles the deps + identity material Apply needs. Constructed
// once at startAgent time after bootstrap has resolved agentID + the chain
// client is dialed; subsequent watcher ticks reuse it.
type Uploader struct {
	adapter       Adapter
	agent         *state.Agent
	chain         ChainClient
	storage       StorageClient
	tokenID       *big.Int
	agentSealPriv []byte
	agentSealPub  []byte // 33-byte compressed secp256k1 pubkey

	indexerURL string // recorded into dataDescription.storage_ptr.indexer

	// roleLocks serializes Apply's per-role work in case any future code
	// path invokes Apply outside the single watcher goroutine (today only
	// the watcher tick fires it, so contention is theoretical — the locks
	// are belt-and-braces).
	locksMu   sync.Mutex
	roleLocks map[string]*sync.Mutex
}

// New constructs a production Uploader wired to a concrete chain.Client
// and the dataplane CLI-shelling storage backend. Returns an error if
// agent_seal_priv can't be parsed (would block every Push otherwise).
func New(
	adapter Adapter,
	agent *state.Agent,
	chainClient *chain.Client,
	tokenID *big.Int,
	agentSealPriv []byte,
	rpcURL, indexerURL string,
) (*Uploader, error) {
	priv, err := crypto.ToECDSA(agentSealPriv)
	if err != nil {
		return nil, fmt.Errorf("parse agent_seal_priv: %w", err)
	}
	pub := crypto.CompressPubkey(&priv.PublicKey)
	storage := &dataplaneStorage{
		indexerURL:    indexerURL,
		rpcURL:        rpcURL,
		signerPrivHex: hex.EncodeToString(agentSealPriv),
	}
	return newWith(adapter, agent, chainClient, storage, tokenID, agentSealPriv, pub, indexerURL), nil
}

// newWith builds an Uploader from already-validated dependencies. Used by
// New (production path) and by tests that inject mock chain / storage.
// Not exported to keep the unit-test seam narrow.
func newWith(
	adapter Adapter,
	agent *state.Agent,
	chainClient ChainClient,
	storage StorageClient,
	tokenID *big.Int,
	agentSealPriv []byte,
	agentSealPub []byte,
	indexerURL string,
) *Uploader {
	return &Uploader{
		adapter:       adapter,
		agent:         agent,
		chain:         chainClient,
		storage:       storage,
		tokenID:       tokenID,
		agentSealPriv: agentSealPriv,
		agentSealPub:  agentSealPub,
		indexerURL:    indexerURL,
		roleLocks:     make(map[string]*sync.Mutex),
	}
}

// lockFor returns the per-role mutex, lazily creating it on first use.
func (u *Uploader) lockFor(role string) *sync.Mutex {
	u.locksMu.Lock()
	defer u.locksMu.Unlock()
	m, ok := u.roleLocks[role]
	if !ok {
		m = &sync.Mutex{}
		u.roleLocks[role] = m
	}
	return m
}

// shapeOf returns the declared shape for a role, or Leaf as the fallback
// for unknown roles (so legacy labels coexisting with declared ones during
// migration behave like leaves).
func (u *Uploader) shapeOf(role string) framework.Shape {
	for _, r := range u.adapter.Roles() {
		if r.Name == role {
			return r.Shape
		}
	}
	return framework.Leaf
}
