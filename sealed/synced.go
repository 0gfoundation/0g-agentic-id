package main

// What this container last had in sync with the chain, per role, kept on its
// own disk (framework.StateDir: root-only, never handed to the agent). It
// lets the next boot of the same container tell an edit the agent made after
// its last commit, which a stop or a crash cut off before the watcher
// committed it, from a change on chain: bootstrap keeps the first and
// restores the second (framework.UncommittedKeeper, startAgent Phase A).
//
// The record is rewritten after every boot's restore and after every
// confirmed commit (state.Agent.SetChainUploadHook). A reset starts a new
// container without it, so its boot restores the chain version as before.

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"sync"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
)

// syncedStateFile is the record's file name under framework.StateDir.
const syncedStateFile = "synced.json"

// syncedRecord is the record. SealID and Owner say whose state it describes:
// a record written for another agent, or for the owner before a transfer,
// keeps nothing.
type syncedRecord struct {
	SealID string `json:"seal_id"`
	Owner  string `json:"owner"`
	// Roles maps a role to the content hash (state.DimEntry.ContentHash)
	// the container last had in sync with the chain.
	Roles map[string]string `json:"roles"`
}

// loadSynced reads the record. ok is false when there is none or it cannot
// be read; the boot then restores the chain version of every role.
func loadSynced() (rec syncedRecord, ok bool) {
	b, err := framework.ReadState(syncedStateFile)
	if errors.Is(err, fs.ErrNotExist) {
		return syncedRecord{}, false
	}
	if err != nil {
		logger.Logf("synced: read the record: %v; every role is restored from chain", err)
		return syncedRecord{}, false
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		logger.Logf("synced: parse the record: %v; every role is restored from chain", err)
		return syncedRecord{}, false
	}
	return rec, true
}

// keepsUncommitted reports whether bootstrap leaves a role's disk content in
// place instead of restoring the chain version over it: the record is this
// agent's under the same owner, the role's chain version is still the one
// the container last had in sync, and the disk differs from it. diskHash ""
// means the disk could not be read, and the chain version is restored.
func keepsUncommitted(rec syncedRecord, ok bool, sealID, owner, role, chainHash, diskHash string) bool {
	if !ok || owner == "" || !strings.EqualFold(rec.SealID, sealID) || !strings.EqualFold(rec.Owner, owner) {
		return false
	}
	synced, has := rec.Roles[role]
	return has && synced == chainHash && diskHash != "" && diskHash != chainHash
}

// diskContentHash is the content hash the watcher would compute for role
// from the disk now, or "" when the disk cannot be read for it.
func diskContentHash(ctx context.Context, idata framework.Framework, role string) string {
	b, err := idata.EvolutionFor(ctx, role)
	if err != nil {
		logger.Logf("synced: EvolutionFor[%s]: %v; the role is restored from chain", role, err)
		return ""
	}
	return sha256Hex(b)
}

// shortHex is the first 8 hex digits of h, as the watcher's tick lines show
// a content hash; "(none)" for "".
func shortHex(h string) string {
	if h == "" {
		return "(none)"
	}
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

// syncedStore is the record in memory, written through on every change.
type syncedStore struct {
	mu  sync.Mutex
	rec syncedRecord
}

// newSyncedStore starts a record for this agent and owner.
func newSyncedStore(sealID, owner string) *syncedStore {
	return &syncedStore{rec: syncedRecord{SealID: sealID, Owner: owner, Roles: map[string]string{}}}
}

// set records role's content hash as the one in sync with the chain and
// writes the record. A failed write leaves the previous file; its entries
// then match the chain no more, so the next boot restores from chain.
func (s *syncedStore) set(role, contentHash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rec.Roles[role] = contentHash
	s.saveLocked()
}

// setAll records every role at once (after a boot's restore) and writes the
// record.
func (s *syncedStore) setAll(roles map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for role, h := range roles {
		s.rec.Roles[role] = h
	}
	s.saveLocked()
}

func (s *syncedStore) saveLocked() {
	b, err := json.Marshal(&s.rec)
	if err == nil {
		err = framework.WriteState(syncedStateFile, b)
	}
	if err != nil {
		logger.Logf("synced: write the record: %v", err)
	}
}
