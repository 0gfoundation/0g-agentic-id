package studio

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seal-verify/internal/state"
)

type testProvider struct {
	root string
}

func (p testProvider) Name() string { return "test" }
func (p testProvider) StudioLayout() Layout {
	return Layout{Resources: []Resource{
		{Kind: KindPersonality, Format: "markdown", Activation: ActivationActive, Role: "persona", Mode: ModeSingleton, Root: filepath.Join(p.root, "SOUL.md"), SingletonID: "main", StripInjected: true},
		{Kind: KindSkills, Format: "skill_bundle", Activation: ActivationNextSession, Role: "skills/", Mode: ModeBundles, Root: filepath.Join(p.root, "skills"), Required: []string{"SKILL.md"}},
		{Kind: KindFiles, Format: "text_file", Activation: ActivationActive, Role: "files/", Mode: ModeFiles, Root: filepath.Join(p.root, "files")},
	}}
}
func (p testProvider) EvolutionFor(_ context.Context, role string) ([]byte, error) {
	switch role {
	case "persona":
		b, err := os.ReadFile(filepath.Join(p.root, "SOUL.md"))
		if os.IsNotExist(err) {
			return nil, nil
		}
		return b, err
	case "skills/", "files/":
		return CanonicalTree(filepath.Join(p.root, role[:len(role)-1]))
	default:
		return nil, os.ErrNotExist
	}
}

func TestManagerPutCASDeleteAndReceiptTransitions(t *testing.T) {
	root := t.TempDir()
	p := testProvider{root: root}
	agent := state.New()
	m := New(p, agent)

	put, err := m.Mutate(context.Background(), MutationRequest{
		Operation: OperationPut, Kind: KindPersonality, ID: "main",
		Files:      []File{{Path: "SOUL.md", Content: "be precise\n"}},
		IfRevision: nil, IdempotencyKey: "9ec0de3a-97f4-4f64-8969-da9535f20b09",
	})
	if err != nil {
		t.Fatal(err)
	}
	if put.Revision == nil || put.Checkpoint.Status != CheckpointPending {
		t.Fatalf("put=%+v", put)
	}
	if !validUUID(put.MutationID) {
		t.Fatalf("mutation id is not UUID: %q", put.MutationID)
	}
	if got := agent.CurrentEntry("persona").ContentHash; got != put.Checkpoint.ContentHash {
		t.Fatalf("current hash=%q checkpoint=%q", got, put.Checkpoint.ContentHash)
	}

	again, err := m.Mutate(context.Background(), MutationRequest{
		Operation: OperationPut, Kind: KindPersonality, ID: "main",
		Files:      []File{{Path: "SOUL.md", Content: "be precise\n"}},
		IfRevision: nil, IdempotencyKey: "9ec0de3a-97f4-4f64-8969-da9535f20b09",
	})
	if err != nil {
		t.Fatal(err)
	}
	if again.MutationID != put.MutationID {
		t.Fatalf("idempotency returned %q want %q", again.MutationID, put.MutationID)
	}

	wrong := "wrong"
	_, err = m.Mutate(context.Background(), MutationRequest{
		Operation: OperationDelete, Kind: KindPersonality, ID: "main", IfRevision: &wrong,
		IdempotencyKey: "ec55740b-c0ab-45b6-b5bd-2d02857f9c41",
	})
	if !IsConflict(err) {
		t.Fatalf("CAS error=%v", err)
	}

	agent.SeedChainSnapshot("persona", put.Checkpoint.ContentHash, "0xdata")
	receipt, err := m.Receipt(put.MutationID)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Checkpoint.Status != CheckpointConfirmed || receipt.Checkpoint.DataHash != "0xdata" {
		t.Fatalf("confirmed receipt=%+v", receipt)
	}

	current := "different"
	agent.UpdateCurrentSnapshot("persona", current)
	receipt, err = m.Receipt(put.MutationID)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Checkpoint.Status != CheckpointConfirmed {
		t.Fatalf("chain exact hash must remain confirmed: %+v", receipt)
	}

	deleteResult, err := m.Mutate(context.Background(), MutationRequest{
		Operation: OperationDelete, Kind: KindPersonality, ID: "main", IfRevision: put.Revision,
		IdempotencyKey: "d9d7518a-0820-4628-92b1-05faf20df56d",
	})
	if err != nil {
		t.Fatal(err)
	}
	if deleteResult.Revision != nil {
		t.Fatalf("delete revision=%q", *deleteResult.Revision)
	}
	if _, err := os.Stat(filepath.Join(root, "SOUL.md")); !os.IsNotExist(err) {
		t.Fatalf("persona still exists: %v", err)
	}

	receipt, err = m.Receipt(deleteResult.MutationID)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Checkpoint.Status != CheckpointPending {
		t.Fatalf("delete receipt=%+v", receipt)
	}
	agent.UpdateCurrentSnapshot("persona", "later")
	receipt, err = m.Receipt(deleteResult.MutationID)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Checkpoint.Status != CheckpointSuperseded {
		t.Fatalf("superseded receipt=%+v", receipt)
	}
}

func TestPersonalityCanonicalReadAndMutationPreservePlatformInjection(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "SOUL.md")
	injected := "owner\n\n<!-- 0g-platform-injected:start -->\nruntime\n<!-- 0g-platform-injected:end -->\n"
	if err := os.WriteFile(path, []byte(injected), 0o644); err != nil {
		t.Fatal(err)
	}
	m := New(testProvider{root: root}, state.New())
	read, err := m.Read(KindPersonality, "main")
	if err != nil {
		t.Fatal(err)
	}
	if len(read.Files) != 1 || read.Files[0].Content != "owner\n" {
		t.Fatalf("canonical read=%+v", read.Files)
	}
	result, err := m.Mutate(context.Background(), MutationRequest{
		Operation: OperationPut, Kind: KindPersonality, ID: "main", IfRevision: read.Revision,
		Files: []File{{Path: "SOUL.md", Content: "updated\n"}}, IdempotencyKey: "b3598787-6ac2-42f8-bd50-499c7b157b88",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Files[0].Content != "updated\n" {
		t.Fatalf("readback=%+v", result.Files)
	}
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(disk), "runtime") || !strings.HasPrefix(string(disk), "updated\n") {
		t.Fatalf("platform injection not preserved: %q", disk)
	}
	deleted, err := m.Mutate(context.Background(), MutationRequest{Operation: OperationDelete, Kind: KindPersonality, ID: "main", IfRevision: result.Revision, IdempotencyKey: "919342e6-c2cd-472a-bb20-7e8437ff0d85"})
	if err != nil {
		t.Fatal(err)
	}
	if deleted.Revision != nil || len(deleted.Files) != 0 {
		t.Fatalf("deleted readback=%+v", deleted.ReadResult)
	}
	disk, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(disk), "runtime") || strings.Contains(string(disk), "updated") {
		t.Fatalf("delete did not preserve only platform section: %q", disk)
	}
}

func TestManagerRejectsUnsafeFilesAndEnforcesBundleShape(t *testing.T) {
	root := t.TempDir()
	p := testProvider{root: root}
	m := New(p, state.New())

	cases := []MutationRequest{
		{Operation: OperationPut, Kind: KindFiles, ID: "../escape", Files: []File{{Path: "../escape", Content: "x"}}},
		{Operation: OperationPut, Kind: KindFiles, ID: ".env", Files: []File{{Path: ".env", Content: "TOKEN=x"}}},
		{Operation: OperationPut, Kind: KindPersonality, ID: "main", Files: []File{{Path: "SOUL.md", Content: "<!-- 0g-platform-injected:start -->"}}},
		{Operation: OperationPut, Kind: KindSkills, ID: "weather", Files: []File{{Path: "README.md", Content: "missing skill"}}},
	}
	keys := []string{"4aaf3c04-56ad-4ba0-8a91-5d9c177a1010", "4aaf3c04-56ad-4ba0-8a91-5d9c177a1011", "4aaf3c04-56ad-4ba0-8a91-5d9c177a1012", "4aaf3c04-56ad-4ba0-8a91-5d9c177a1013"}
	for i := range cases {
		cases[i].IdempotencyKey = keys[i]
		if _, err := m.Mutate(context.Background(), cases[i]); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}

	if err := os.MkdirAll(filepath.Join(root, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "files", "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Read(KindFiles, "link"); err == nil {
		t.Fatal("symlink read accepted")
	}
}

func TestStateListsOnlyDeclaredResources(t *testing.T) {
	root := t.TempDir()
	p := testProvider{root: root}
	if err := os.MkdirAll(filepath.Join(root, "skills", "weather"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "skills", "weather", "SKILL.md"), []byte("weather"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "unmanaged.txt"), []byte("private"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := New(p, state.New()).State()
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema != Schema || got.Framework != "test" || len(got.Resources) != 3 {
		t.Fatalf("state=%+v", got)
	}
	if len(got.Resources[1].Items) != 1 || got.Resources[1].Items[0].ID != "weather" {
		t.Fatalf("skills=%+v", got.Resources[1])
	}
}

func TestNestedFileReadbackKeepsResourcePath(t *testing.T) {
	m := New(testProvider{root: t.TempDir()}, state.New())
	result, err := m.Mutate(context.Background(), MutationRequest{
		Operation:      OperationPut,
		Kind:           KindFiles,
		ID:             "boards/roadmap.md",
		Files:          []File{{Path: "boards/roadmap.md", Content: "next\n"}},
		IdempotencyKey: "ab8fc18d-0738-4b06-9e22-4c18b9f841bd",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 1 || result.Files[0].Path != "boards/roadmap.md" {
		t.Fatalf("nested file readback = %+v", result.Files)
	}
}
