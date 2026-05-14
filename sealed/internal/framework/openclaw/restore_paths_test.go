package openclaw

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"seal-verify/internal/manifest"
)

// roundtripManifest exercises the round-trip property for a manifest role:
//
//	EvolutionFor(role)           → pt_before
//	for each entry in pt_before: capture via LoadEntry
//	wipe role's disk source
//	Restore(role, pt_before)
//	for each captured entry: RestoreEntry(role, path, captured)
//	EvolutionFor(role)           → pt_after
//	assert pt_before == pt_after (byte-equal)
//
// This is the property that makes watcher drift detection stable across
// transfers: a sandbox boots from chain plaintext, hashes its restored
// disk state, and the hash matches what was uploaded.
func roundtripManifest(t *testing.T, role, diskRoot string) {
	t.Helper()
	a := &Adapter{}
	ctx := context.Background()

	ptBefore, err := a.EvolutionFor(ctx, role)
	if err != nil {
		t.Fatalf("EvolutionFor %s (before): %v", role, err)
	}
	m, err := manifest.Unmarshal(ptBefore)
	if err != nil {
		t.Fatalf("Unmarshal %s: %v", role, err)
	}
	captured := make(map[string][]byte, len(m.Entries))
	for _, e := range m.Entries {
		b, err := a.LoadEntry(ctx, role, e.Path)
		if err != nil {
			t.Fatalf("LoadEntry %s/%s: %v", role, e.Path, err)
		}
		captured[e.Path] = b
		if got := manifest.HashHex(b); got != e.ContentHash {
			t.Fatalf("LoadEntry hash mismatch for %s/%s:\n have %s\n want %s (from manifest)",
				role, e.Path, got, e.ContentHash)
		}
	}

	// Wipe the role's disk root so restore is starting from scratch.
	if err := os.RemoveAll(diskRoot); err != nil {
		t.Fatalf("wipe %s: %v", diskRoot, err)
	}

	if err := a.Restore(ctx, role, ptBefore); err != nil {
		t.Fatalf("Restore %s: %v", role, err)
	}
	for path, content := range captured {
		if err := a.RestoreEntry(ctx, role, path, content); err != nil {
			t.Fatalf("RestoreEntry %s/%s: %v", role, path, err)
		}
	}

	ptAfter, err := a.EvolutionFor(ctx, role)
	if err != nil {
		t.Fatalf("EvolutionFor %s (after): %v", role, err)
	}
	if !bytes.Equal(ptBefore, ptAfter) {
		t.Errorf("round-trip mismatch for %s:\n before: %s\n  after: %s", role, ptBefore, ptAfter)
	}
}

// ── workspace/ ──────────────────────────────────────────────────────────────

func TestRoundtrip_Workspace(t *testing.T) {
	useTempHome(t)
	writeMd(t, "SOUL.md", "You are Sage. DeFi helper.\n")
	writeMd(t, "IDENTITY.md", "name: Sage\nstyle: friendly\n")
	writeMd(t, "AGENTS.md", "Be helpful; follow user instructions.\n")
	roundtripManifest(t, "workspace/", workspaceDir())
}

func TestRoundtrip_Workspace_WithToolsMdPlatformSection(t *testing.T) {
	useTempHome(t)
	writeMd(t, "SOUL.md", "agent core\n")
	// TOOLS.md gets an injected platform section. Round-trip must hash the
	// stripped content, restore the stripped content (the platform section
	// gets re-added at spawn time, not at restore time).
	rawTools := "# TOOLS\nowner content here.\n\n" +
		platformMarkerStart + "\n" +
		"## Environment\ninjected per-boot\n" +
		platformMarkerEnd + "\n"
	writeMd(t, "TOOLS.md", rawTools)
	roundtripManifest(t, "workspace/", workspaceDir())
}

func TestRestore_Workspace_TouchesEmptyMdsForTemplateDefense(t *testing.T) {
	useTempHome(t)
	// Manifest with only SOUL.md — Restore should touch empty defenses
	// for the remaining required md names.
	m := manifest.New()
	m.Entries = []manifest.Entry{
		{Path: "SOUL.md", Kind: manifest.EntryFile, ContentHash: "0x0", Size: 0,
			StoragePtr: manifest.StoragePtr{RootHash: "0x0", Size: 0}},
	}
	pt, _ := m.Marshal()

	if err := (&Adapter{}).Restore(context.Background(), "workspace/", pt); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	// SOUL.md not yet written (would come via RestoreEntry), but every
	// other required md should exist as an empty file.
	for _, name := range workspaceRequiredMDs {
		if name == "SOUL.md" {
			continue
		}
		p := filepath.Join(workspaceDir(), name)
		fi, err := os.Stat(p)
		if err != nil {
			t.Errorf("required md not touched: %s (%v)", name, err)
			continue
		}
		if fi.Size() != 0 {
			t.Errorf("touched md %s has size %d; want 0 (template defense)", name, fi.Size())
		}
	}
}

func TestRestore_Workspace_NilPlaintextTouchesAllDefenses(t *testing.T) {
	useTempHome(t)
	if err := (&Adapter{}).Restore(context.Background(), "workspace/", nil); err != nil {
		t.Fatalf("Restore(nil): %v", err)
	}
	for _, name := range workspaceRequiredMDs {
		p := filepath.Join(workspaceDir(), name)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("required md not touched on nil restore: %s (%v)", name, err)
		}
	}
}

// ── workspace/skills/ ───────────────────────────────────────────────────────

func TestRoundtrip_WorkspaceSkills(t *testing.T) {
	useTempHome(t)
	writeSkillFile(t, "airdrop-hunter", "SKILL.md", "---\nname: airdrop-hunter\n---\nbody\n")
	writeSkillFile(t, "airdrop-hunter", "scripts/sweep.ts", "console.log('sweep')\n")
	writeSkillFile(t, "weather", "SKILL.md", "---\nname: weather\n---\n")
	roundtripManifest(t, "workspace/skills/", workspaceDir()+"/skills")
}

func TestRestoreEntry_WorkspaceSkills_RemovesStaleFiles(t *testing.T) {
	useTempHome(t)
	a := &Adapter{}
	ctx := context.Background()

	// Start: airdrop-hunter has scripts/sweep.ts + data/whitelist.json
	writeSkillFile(t, "airdrop-hunter", "SKILL.md", "v1")
	writeSkillFile(t, "airdrop-hunter", "scripts/sweep.ts", "old")
	writeSkillFile(t, "airdrop-hunter", "data/whitelist.json", "[]")

	// Capture original via LoadEntry.
	originalTar, err := a.LoadEntry(ctx, "workspace/skills/", "airdrop-hunter/")
	if err != nil {
		t.Fatalf("LoadEntry: %v", err)
	}

	// Now simulate an "evolved" version: only SKILL.md (other files deleted).
	if err := os.RemoveAll(filepath.Join(workspaceDir(), "skills", "airdrop-hunter")); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	writeSkillFile(t, "airdrop-hunter", "SKILL.md", "v2")
	evolvedTar, err := a.LoadEntry(ctx, "workspace/skills/", "airdrop-hunter/")
	if err != nil {
		t.Fatalf("LoadEntry evolved: %v", err)
	}

	// RestoreEntry with the original — should NOT leave the v2 SKILL.md
	// behind, AND should restore the data/whitelist.json that v2 didn't have.
	if err := a.RestoreEntry(ctx, "workspace/skills/", "airdrop-hunter/", originalTar); err != nil {
		t.Fatalf("RestoreEntry: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(workspaceDir(), "skills", "airdrop-hunter", "SKILL.md"))
	if err != nil {
		t.Fatalf("read SKILL.md: %v", err)
	}
	if string(body) != "v1" {
		t.Errorf("SKILL.md not restored to v1: got %q", body)
	}
	if _, err := os.Stat(filepath.Join(workspaceDir(), "skills", "airdrop-hunter", "data", "whitelist.json")); err != nil {
		t.Errorf("data/whitelist.json not restored: %v", err)
	}
	// Sanity: original and evolved must differ so this test actually covers
	// something interesting.
	if bytes.Equal(originalTar, evolvedTar) {
		t.Errorf("test setup broken: original and evolved skills produce identical tars")
	}
}

// ── workspace/canvas/ ───────────────────────────────────────────────────────

func TestRoundtrip_WorkspaceCanvas(t *testing.T) {
	useTempHome(t)
	canvasDir := workspaceDir() + "/canvas"
	if err := os.MkdirAll(canvasDir+"/scripts", 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(canvasDir+"/index.html", []byte("<html></html>\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(canvasDir+"/scripts/main.js", []byte("console.log(1)\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	roundtripManifest(t, "workspace/canvas/", canvasDir)
}

// ── openclaw.json (leaf) ────────────────────────────────────────────────────

func TestRoundtrip_OpenclawJSON(t *testing.T) {
	useTempHome(t)
	writeJSONConfig(t, map[string]any{
		"agents": map[string]any{
			"defaults": map[string]any{
				"model": map[string]any{"primary": "anthropic/claude-opus-4-6"},
			},
		},
		"auth": map[string]any{
			"order":    map[string]any{"anthropic": []any{"anthropic:api"}},
			"profiles": map[string]any{"anthropic:api": map[string]any{"provider": "anthropic", "mode": "api_key"}},
		},
		"gateway": map[string]any{"auth": map[string]any{"token": "should-be-stripped"}},
	})

	a := &Adapter{}
	ctx := context.Background()

	ptBefore, err := a.EvolutionFor(ctx, "openclaw.json")
	if err != nil {
		t.Fatalf("EvolutionFor: %v", err)
	}
	// Sanity: gateway should be absent.
	if bytes.Contains(ptBefore, []byte("should-be-stripped")) {
		t.Fatalf("gateway token leaked into evolution output: %s", ptBefore)
	}

	// Wipe and restore.
	if err := os.Remove(openclawJSONPath()); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := a.Restore(ctx, "openclaw.json", ptBefore); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	ptAfter, err := a.EvolutionFor(ctx, "openclaw.json")
	if err != nil {
		t.Fatalf("EvolutionFor after: %v", err)
	}
	if !bytes.Equal(ptBefore, ptAfter) {
		t.Errorf("openclaw.json round-trip mismatch:\n before: %s\n  after: %s", ptBefore, ptAfter)
	}
}

// ── LoadEntry error paths ──────────────────────────────────────────────────

func TestLoadEntry_RejectsLeafRoles(t *testing.T) {
	a := &Adapter{}
	if _, err := a.LoadEntry(context.Background(), "framework", "anything"); err == nil {
		t.Errorf("LoadEntry on leaf role 'framework' should error, got nil")
	}
	if _, err := a.LoadEntry(context.Background(), "openclaw.json", "anything"); err == nil {
		t.Errorf("LoadEntry on leaf role 'openclaw.json' should error, got nil")
	}
}

func TestLoadEntry_WorkspaceSkills_RejectsNonDirPath(t *testing.T) {
	a := &Adapter{}
	if _, err := a.LoadEntry(context.Background(), "workspace/skills/", "no-trailing-slash"); err == nil {
		t.Errorf("expected error for skills entry without trailing /, got nil")
	}
}
