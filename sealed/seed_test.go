package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/privsep"
	"seal-verify/internal/state"
)

// seedStub is a framework whose EvolutionFor answers from a table; the
// other methods are never called by seedCurrentSnapshots.
type seedStub struct {
	framework.Framework
	roles []framework.RoleSpec
	out   map[string][]byte
	errs  map[string]error
}

func (s seedStub) Roles() []framework.RoleSpec { return s.roles }

func (s seedStub) EvolutionFor(_ context.Context, role string) ([]byte, error) {
	if err := s.errs[role]; err != nil {
		return nil, err
	}
	return s.out[role], nil
}

// A leaf role whose file is over its size limit (which an older sealed could
// commit, and restore writes back) keeps its committed version at boot
// instead of failing it: no error, and no drift against the chain entry.
// Any other EvolutionFor error still fails the seed.
func TestSeedKeepsAnOversizedLeafAtItsCommittedVersion(t *testing.T) {
	agent := state.New()
	const committed = "c0ffee"
	agent.SeedChainSnapshot("SOUL.md", committed, "0xdata")
	agent.SeedChainSnapshot("USER.md", "other", "0xdata2")
	stub := seedStub{
		roles: []framework.RoleSpec{{Name: "SOUL.md", Shape: framework.Leaf}, {Name: "USER.md", Shape: framework.Leaf}},
		out:   map[string][]byte{"USER.md": []byte("user")},
		errs:  map[string]error{"SOUL.md": fmt.Errorf("adapter.EvolutionFor[SOUL.md]: %w", privsep.ErrTooLarge)},
	}
	if err := seedCurrentSnapshots(context.Background(), stub, agent); err != nil {
		t.Fatalf("seedCurrentSnapshots = %v; an oversized leaf must not fail the boot", err)
	}
	if got := agent.CurrentEntry("SOUL.md").ContentHash; got != committed {
		t.Fatalf("SOUL.md current = %q, want the committed %q (no drift)", got, committed)
	}
	if got, want := agent.CurrentEntry("USER.md").ContentHash, sha256Hex([]byte("user")); got != want {
		t.Fatalf("USER.md current = %q, want %q", got, want)
	}

	stub.errs["SOUL.md"] = errors.New("disk on fire")
	if err := seedCurrentSnapshots(context.Background(), stub, agent); err == nil {
		t.Fatal("seedCurrentSnapshots ignored an EvolutionFor error that is not ErrTooLarge or ErrBusy")
	}
}

// A role whose file is leased by its owner (an agent process, once the
// framework runs: phase 2) cannot be read for now; the read says nothing
// about its content, so the role keeps its committed version and the boot
// goes on, as the watcher skips the role for a pass.
func TestSeedKeepsALeasedRoleAtItsCommittedVersion(t *testing.T) {
	agent := state.New()
	const committed = "c0ffee"
	agent.SeedChainSnapshot("SOUL.md", committed, "0xdata")
	agent.UpdateCurrentSnapshot("SOUL.md", "stale")
	stub := seedStub{
		roles: []framework.RoleSpec{{Name: "SOUL.md", Shape: framework.Leaf}},
		errs:  map[string]error{"SOUL.md": fmt.Errorf("adapter.EvolutionFor[SOUL.md]: read: %w", privsep.ErrBusy)},
	}
	if err := seedCurrentSnapshots(context.Background(), stub, agent); err != nil {
		t.Fatalf("seedCurrentSnapshots = %v; a leased file must not fail the boot", err)
	}
	if got := agent.CurrentEntry("SOUL.md").ContentHash; got != committed {
		t.Fatalf("SOUL.md current = %q, want the committed %q (no drift)", got, committed)
	}
}
