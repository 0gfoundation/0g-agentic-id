package main

import (
	"context"
	"errors"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/state"
)

func TestKeepsUncommitted(t *testing.T) {
	const (
		seal  = "0x5ea1"
		owner = "0x00000000000000000000000000000000000000C1"
		role  = "APPEND_SYSTEM.md"
		chain = "c0ffee"
		disk  = "d15c"
	)
	rec := syncedRecord{SealID: seal, Owner: owner, Roles: map[string]string{role: chain}}
	cases := []struct {
		name  string
		rec   syncedRecord
		ok    bool
		owner string
		chain string
		disk  string
		want  bool
	}{
		{"edited after the last commit, chain unchanged", rec, true, owner, chain, disk, true},
		{"owner address in another case", rec, true, "0x00000000000000000000000000000000000000c1", chain, disk, true},
		{"disk as on chain", rec, true, owner, chain, chain, false},
		{"chain moved since", rec, true, owner, "beef", disk, false},
		{"no record", syncedRecord{}, false, owner, chain, disk, false},
		{"record of another agent", syncedRecord{SealID: "0x0bad", Owner: owner, Roles: rec.Roles}, true, owner, chain, disk, false},
		{"record from before a transfer", rec, true, "0x00000000000000000000000000000000000000D2", chain, disk, false},
		{"owner unknown", rec, true, "", chain, disk, false},
		{"role not in the record", syncedRecord{SealID: seal, Owner: owner, Roles: map[string]string{}}, true, owner, chain, disk, false},
		{"disk unreadable", rec, true, owner, chain, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := keepsUncommitted(c.rec, c.ok, seal, c.owner, role, c.chain, c.disk); got != c.want {
				t.Fatalf("keepsUncommitted = %v, want %v", got, c.want)
			}
		})
	}
}

func TestSyncedRecordRoundTrip(t *testing.T) {
	old := framework.StateDir
	framework.StateDir = t.TempDir()
	defer func() { framework.StateDir = old }()

	if _, ok := loadSynced(); ok {
		t.Fatal("loadSynced found a record in an empty state dir")
	}
	s := newSyncedStore("0x5ea1", "0xC1")
	s.setAll(map[string]string{"framework": "f1", "APPEND_SYSTEM.md": "p1"})
	s.set("APPEND_SYSTEM.md", "p2")

	rec, ok := loadSynced()
	if !ok {
		t.Fatal("loadSynced found no record after a write")
	}
	if rec.SealID != "0x5ea1" || rec.Owner != "0xC1" {
		t.Fatalf("record names %q / %q", rec.SealID, rec.Owner)
	}
	if rec.Roles["framework"] != "f1" || rec.Roles["APPEND_SYSTEM.md"] != "p2" {
		t.Fatalf("record roles %v, want framework=f1 APPEND_SYSTEM.md=p2", rec.Roles)
	}
}

func TestSyncedRecordUnparseableKeepsNothing(t *testing.T) {
	old := framework.StateDir
	framework.StateDir = t.TempDir()
	defer func() { framework.StateDir = old }()

	if err := framework.WriteState(syncedStateFile, []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadSynced(); ok {
		t.Fatal("an unparseable record was accepted")
	}
}

// A confirmed commit moves the record to the committed content (the hook
// state.RecordChainUpload calls).
func TestSyncedRecordFollowsCommits(t *testing.T) {
	old := framework.StateDir
	framework.StateDir = t.TempDir()
	defer func() { framework.StateDir = old }()

	agent := state.New()
	agent.SeedChainSnapshot("APPEND_SYSTEM.md", "p1", "0xroot1")
	s := newSyncedStore("0x5ea1", "0xC1")
	s.setAll(map[string]string{"APPEND_SYSTEM.md": agent.ChainEntry("APPEND_SYSTEM.md").ContentHash})
	agent.SetChainUploadHook(s.set)

	agent.RecordChainUpload("APPEND_SYSTEM.md", "p2", "0xroot2")
	rec, ok := loadSynced()
	if !ok || rec.Roles["APPEND_SYSTEM.md"] != "p2" {
		t.Fatalf("record after a commit = %v (ok=%v), want APPEND_SYSTEM.md=p2", rec.Roles, ok)
	}
}

// evoFake answers EvolutionFor for diskContentHash.
type evoFake struct {
	framework.Framework
	b   []byte
	err error
}

func (f evoFake) EvolutionFor(context.Context, string) ([]byte, error) { return f.b, f.err }

func TestDiskContentHash(t *testing.T) {
	if got, want := diskContentHash(context.Background(), evoFake{b: []byte("persona")}, "APPEND_SYSTEM.md"), sha256Hex([]byte("persona")); got != want {
		t.Fatalf("diskContentHash = %q, want %q", got, want)
	}
	if got := diskContentHash(context.Background(), evoFake{err: errors.New("busy")}, "APPEND_SYSTEM.md"); got != "" {
		t.Fatalf("diskContentHash on a read error = %q, want \"\"", got)
	}
}

// A role a boot restores from chain leaves the record before the restore
// begins: a boot that dies part-way keeps nothing of it.
func TestForgetSyncedDropsTheRolesRestored(t *testing.T) {
	old := framework.StateDir
	framework.StateDir = t.TempDir()
	defer func() { framework.StateDir = old }()

	s := newSyncedStore("0xseal", "0xowner")
	s.setAll(map[string]string{"APPEND_SYSTEM.md": "aaaa", "skills/": "bbbb"})
	rec, ok := loadSynced()
	if !ok {
		t.Fatal("no record")
	}
	forgetSynced(rec, []string{"skills/"})
	rec, ok = loadSynced()
	if !ok || rec.Roles["APPEND_SYSTEM.md"] != "aaaa" {
		t.Fatalf("record %+v", rec)
	}
	if _, has := rec.Roles["skills/"]; has {
		t.Fatalf("restored role still recorded: %+v", rec)
	}
	// So the next boot does not keep a partial skills/ copy.
	if keepsUncommitted(rec, ok, "0xseal", "0xowner", "skills/", "bbbb", "partial") {
		t.Fatal("a role being restored would be kept")
	}
}
