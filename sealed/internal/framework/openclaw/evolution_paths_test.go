package openclaw

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/manifest"
)

// ── Roles() / Defaults() ────────────────────────────────────────────────────

func TestRoles_ExpectedSet(t *testing.T) {
	a := &Adapter{}
	got := a.Roles()
	wantNames := []string{"framework", "openclaw.json", "workspace/", "workspace/skills/", "workspace/canvas/"}
	if len(got) != len(wantNames) {
		t.Fatalf("Roles count = %d; want %d", len(got), len(wantNames))
	}
	for i, want := range wantNames {
		if got[i].Name != want {
			t.Errorf("Roles[%d].Name = %q; want %q", i, got[i].Name, want)
		}
	}
	// framework + openclaw.json are Leaf; rest are DirectoryManifest.
	for _, r := range got {
		switch r.Name {
		case "framework", "openclaw.json":
			if r.Shape != framework.Leaf {
				t.Errorf("role %q shape = %q; want Leaf", r.Name, r.Shape)
			}
		default:
			if r.Shape != framework.DirectoryManifest {
				t.Errorf("role %q shape = %q; want DirectoryManifest", r.Name, r.Shape)
			}
		}
	}
}

func TestDefaults_RealValuesForLeafRoles(t *testing.T) {
	a := &Adapter{}
	// framework: should be a valid frameworkBinding JSON with current
	// adapter name + whitelistMax version + schema 1.
	d := a.Defaults("framework")
	if len(d) == 0 {
		t.Fatalf("Defaults(framework) is empty")
	}
	var fb frameworkBinding
	if err := json.Unmarshal(d, &fb); err != nil {
		t.Fatalf("Defaults(framework) not valid JSON: %v", err)
	}
	if fb.Name != "openclaw" {
		t.Errorf("Defaults(framework).Name = %q; want openclaw", fb.Name)
	}
	if fb.SchemaVersion != 1 {
		t.Errorf("Defaults(framework).SchemaVersion = %d; want 1", fb.SchemaVersion)
	}
	// openclaw.json: empty JSON object so spawn can read it without error.
	if got := string(a.Defaults("openclaw.json")); got != "{}" {
		t.Errorf("Defaults(openclaw.json) = %q; want {}", got)
	}
}

func TestDefaults_EmptyManifestForDirectoryRoles(t *testing.T) {
	a := &Adapter{}
	for _, role := range []string{"workspace/", "workspace/skills/", "workspace/canvas/"} {
		d := a.Defaults(role)
		if d == nil {
			t.Errorf("Defaults(%s) = nil; want empty manifest bytes", role)
			continue
		}
		m, err := manifest.Unmarshal(d)
		if err != nil {
			t.Errorf("Defaults(%s) not a valid manifest: %v", role, err)
			continue
		}
		if len(m.Entries) != 0 {
			t.Errorf("Defaults(%s) has %d entries; want 0", role, len(m.Entries))
		}
	}
}

// ── EvolutionFor("openclaw.json") ───────────────────────────────────────────

func TestEvoOpenclawJSON_StripsGateway(t *testing.T) {
	useTempHome(t)
	// Write an openclaw.json with both kept and stripped sections.
	cfg := map[string]any{
		"agents": map[string]any{
			"defaults": map[string]any{
				"model": map[string]any{"primary": "anthropic/claude-opus-4-6"},
			},
		},
		"gateway": map[string]any{
			"auth": map[string]any{"token": "secret-per-boot-token"},
		},
	}
	writeJSONConfig(t, cfg)

	out, err := (&Adapter{}).EvolutionFor(context.Background(), "openclaw.json")
	if err != nil {
		t.Fatalf("EvolutionFor: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("parse output: %v", err)
	}
	if _, present := parsed["gateway"]; present {
		t.Errorf("gateway key not stripped from output: %s", out)
	}
	if _, present := parsed["agents"]; !present {
		t.Errorf("agents key wrongly stripped: %s", out)
	}
}

func TestEvoOpenclawJSON_DeterministicAcrossRuns(t *testing.T) {
	useTempHome(t)
	cfg := map[string]any{
		"agents": map[string]any{"defaults": map[string]any{"model": map[string]any{"primary": "x/y"}}},
		"tools":  []any{},
	}
	writeJSONConfig(t, cfg)

	a := &Adapter{}
	out1, err := a.EvolutionFor(context.Background(), "openclaw.json")
	if err != nil {
		t.Fatalf("EvolutionFor 1: %v", err)
	}
	out2, err := a.EvolutionFor(context.Background(), "openclaw.json")
	if err != nil {
		t.Fatalf("EvolutionFor 2: %v", err)
	}
	if string(out1) != string(out2) {
		t.Errorf("not deterministic: %s vs %s", out1, out2)
	}
}

func TestEvoOpenclawJSON_MissingFileReturnsEmpty(t *testing.T) {
	useTempHome(t)
	// Don't write openclaw.json — loadOpenclawJSON returns empty map.
	out, err := (&Adapter{}).EvolutionFor(context.Background(), "openclaw.json")
	if err != nil {
		t.Fatalf("EvolutionFor: %v", err)
	}
	if string(out) != "{}" {
		t.Errorf("expected '{}' for missing config, got %s", out)
	}
}

// ── EvolutionFor("workspace/") ──────────────────────────────────────────────

func TestEvoWorkspace_EnumeratesMdFiles(t *testing.T) {
	useTempHome(t)
	writeMd(t, "SOUL.md", "You are Sage.\n")
	writeMd(t, "IDENTITY.md", "name: Sage\n")
	writeMd(t, "AGENTS.md", "") // empty — should be skipped (no content)
	// Non-.md file should be ignored.
	writeMd(t, "notes.txt", "ignored")

	out, err := (&Adapter{}).EvolutionFor(context.Background(), "workspace/")
	if err != nil {
		t.Fatalf("EvolutionFor: %v", err)
	}
	m, err := manifest.Unmarshal(out)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(m.Entries) != 2 {
		t.Fatalf("entries = %d; want 2 (non-empty .md only, empty AGENTS.md skipped)", len(m.Entries))
	}
	// Sorted by path: IDENTITY.md, SOUL.md (AGENTS.md skipped as empty).
	want := []string{"IDENTITY.md", "SOUL.md"}
	for i, e := range m.Entries {
		if e.Path != want[i] {
			t.Errorf("entries[%d].Path = %q; want %q", i, e.Path, want[i])
		}
		if e.Kind != manifest.EntryFile {
			t.Errorf("entries[%d].Kind = %q; want file", i, e.Kind)
		}
	}
	// Content hash should be stable + match raw bytes.
	for _, e := range m.Entries {
		raw, err := os.ReadFile(filepath.Join(workspaceDir(), e.Path))
		if err != nil {
			t.Fatalf("read %s: %v", e.Path, err)
		}
		if e.ContentHash != manifest.HashHex(raw) {
			t.Errorf("entry %s content_hash mismatch", e.Path)
		}
		if e.Size != len(raw) {
			t.Errorf("entry %s size = %d; want %d", e.Path, e.Size, len(raw))
		}
	}
}

func TestEvoWorkspace_EmptyDirReturnsEmptyManifest(t *testing.T) {
	useTempHome(t)
	// workspaceDir doesn't exist yet — should still produce empty manifest.
	out, err := (&Adapter{}).EvolutionFor(context.Background(), "workspace/")
	if err != nil {
		t.Fatalf("EvolutionFor: %v", err)
	}
	m, err := manifest.Unmarshal(out)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(m.Entries) != 0 {
		t.Errorf("expected empty manifest, got %d entries", len(m.Entries))
	}
}

func TestEvoWorkspace_StripsToolsMdPlatformSection(t *testing.T) {
	useTempHome(t)
	rawTools := "# TOOLS\n\nOwner part.\n\n" +
		platformMarkerStart + "\n" +
		"## Environment\n" +
		"injected per-boot stuff\n" +
		platformMarkerEnd + "\n"
	writeMd(t, "TOOLS.md", rawTools)

	out, err := (&Adapter{}).EvolutionFor(context.Background(), "workspace/")
	if err != nil {
		t.Fatalf("EvolutionFor: %v", err)
	}
	m, _ := manifest.Unmarshal(out)
	if len(m.Entries) != 1 {
		t.Fatalf("entries = %d; want 1", len(m.Entries))
	}
	// Content hash must be the STRIPPED version, not raw file contents.
	stripped := stripPlatformInjection([]byte(rawTools))
	if m.Entries[0].ContentHash != manifest.HashHex(stripped) {
		t.Errorf("TOOLS.md hash not stripped:\nhave %s\nwant %s",
			m.Entries[0].ContentHash, manifest.HashHex(stripped))
	}
}

func TestEvoWorkspace_Deterministic(t *testing.T) {
	useTempHome(t)
	writeMd(t, "SOUL.md", "You are Sage.\n")
	writeMd(t, "IDENTITY.md", "name: Sage\n")

	a := &Adapter{}
	out1, _ := a.EvolutionFor(context.Background(), "workspace/")
	out2, _ := a.EvolutionFor(context.Background(), "workspace/")
	if string(out1) != string(out2) {
		t.Errorf("not deterministic across calls")
	}
}

// ── EvolutionFor("workspace/skills/") ───────────────────────────────────────

func TestEvoWorkspaceSkills_EnumeratesSubdirs(t *testing.T) {
	useTempHome(t)
	writeSkillFile(t, "airdrop-hunter", "SKILL.md", "---\nname: airdrop-hunter\n---\nbody\n")
	writeSkillFile(t, "airdrop-hunter", "scripts/sweep.ts", "code")
	writeSkillFile(t, "weather", "SKILL.md", "---\nname: weather\n---\nbody\n")
	// A loose file directly under skills/ — should be ignored (not a folder).
	writeWorkspaceFile(workspaceDir()+"/skills/loose.txt", "ignored")

	out, err := (&Adapter{}).EvolutionFor(context.Background(), "workspace/skills/")
	if err != nil {
		t.Fatalf("EvolutionFor: %v", err)
	}
	m, err := manifest.Unmarshal(out)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(m.Entries) != 2 {
		t.Fatalf("entries = %d; want 2 (only subdirs)", len(m.Entries))
	}
	wantPaths := []string{"airdrop-hunter/", "weather/"}
	for i, e := range m.Entries {
		if e.Path != wantPaths[i] {
			t.Errorf("entries[%d].Path = %q; want %q", i, e.Path, wantPaths[i])
		}
		if e.Kind != manifest.EntryDir {
			t.Errorf("entries[%d].Kind = %q; want dir", i, e.Kind)
		}
		if e.Size == 0 {
			t.Errorf("entries[%d].Size = 0; want >0", i)
		}
	}
}

func TestEvoWorkspaceSkills_OneSkillChangeOnlyOneHashChanges(t *testing.T) {
	useTempHome(t)
	writeSkillFile(t, "airdrop-hunter", "SKILL.md", "v1")
	writeSkillFile(t, "weather", "SKILL.md", "weather-v1")

	a := &Adapter{}
	out1, err := a.EvolutionFor(context.Background(), "workspace/skills/")
	if err != nil {
		t.Fatalf("EvolutionFor 1: %v", err)
	}
	m1, _ := manifest.Unmarshal(out1)

	// Modify only airdrop-hunter.
	writeSkillFile(t, "airdrop-hunter", "SKILL.md", "v2")
	out2, err := a.EvolutionFor(context.Background(), "workspace/skills/")
	if err != nil {
		t.Fatalf("EvolutionFor 2: %v", err)
	}
	m2, _ := manifest.Unmarshal(out2)

	if string(out1) == string(out2) {
		t.Fatalf("manifest didn't change after skill edit")
	}
	// airdrop-hunter hash should differ, weather hash should not.
	ah1 := m1.EntryByPath("airdrop-hunter/").ContentHash
	ah2 := m2.EntryByPath("airdrop-hunter/").ContentHash
	w1 := m1.EntryByPath("weather/").ContentHash
	w2 := m2.EntryByPath("weather/").ContentHash
	if ah1 == ah2 {
		t.Errorf("airdrop-hunter hash didn't change after edit")
	}
	if w1 != w2 {
		t.Errorf("weather hash changed despite no edit:\nbefore %s\nafter  %s", w1, w2)
	}
}

func TestEvoWorkspaceSkills_NoSkillsReturnsEmpty(t *testing.T) {
	useTempHome(t)
	out, err := (&Adapter{}).EvolutionFor(context.Background(), "workspace/skills/")
	if err != nil {
		t.Fatalf("EvolutionFor: %v", err)
	}
	m, _ := manifest.Unmarshal(out)
	if len(m.Entries) != 0 {
		t.Errorf("entries = %d; want 0", len(m.Entries))
	}
}

// ── EvolutionFor("workspace/canvas/") ───────────────────────────────────────

func TestEvoWorkspaceCanvas_MixedFilesAndDirs(t *testing.T) {
	useTempHome(t)
	if err := os.MkdirAll(workspaceDir()+"/canvas/scripts", 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeWorkspaceFile(workspaceDir()+"/canvas/index.html", "<html></html>")
	writeWorkspaceFile(workspaceDir()+"/canvas/scripts/main.js", "console.log(1)")

	out, err := (&Adapter{}).EvolutionFor(context.Background(), "workspace/canvas/")
	if err != nil {
		t.Fatalf("EvolutionFor: %v", err)
	}
	m, _ := manifest.Unmarshal(out)
	if len(m.Entries) != 2 {
		t.Fatalf("entries = %d; want 2", len(m.Entries))
	}
	// Entries sorted by path: "index.html" then "scripts/".
	if m.Entries[0].Path != "index.html" || m.Entries[0].Kind != manifest.EntryFile {
		t.Errorf("entries[0] = %+v; want file index.html", m.Entries[0])
	}
	if m.Entries[1].Path != "scripts/" || m.Entries[1].Kind != manifest.EntryDir {
		t.Errorf("entries[1] = %+v; want dir scripts/", m.Entries[1])
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func writeJSONConfig(t *testing.T, cfg map[string]any) {
	t.Helper()
	if err := os.MkdirAll(openclawHome, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal cfg: %v", err)
	}
	if err := os.WriteFile(openclawJSONPath(), b, 0o600); err != nil {
		t.Fatalf("write openclaw.json: %v", err)
	}
}

func writeMd(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(workspaceDir(), 0o755); err != nil {
		t.Fatalf("mkdir workspace: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspaceDir(), name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func writeSkillFile(t *testing.T, slug, relPath, content string) {
	t.Helper()
	full := filepath.Join(workspaceDir(), "skills", slug, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
}
