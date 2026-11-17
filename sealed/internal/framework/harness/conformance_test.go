package harness

import (
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/framework/conformance"
)

// TestConformance runs the shared adapter invariant suite (FRAMEWORK_ADAPTER.md
// §9/§10) against the real state-half implementation: role sanity, Defaults
// round-trip, fixture round-trip + determinism + LoadEntry hash agreement,
// Restore commutativity, unknown-role contract, FrameworkFacts non-empty.
//
// Exercises the whole state/identity half without the harness installed at all — the
// invariants the watcher would turn into infinite re-upload loops in
// production are pure functions of disk state (FRAMEWORK_ADAPTER.md §13
// point 5). The "framework" role has no fixture here, same as every other
// bundled adapter: it is still exercised by the Defaults round-trip.
func TestConformance(t *testing.T) {
	conformance.Run(t, conformance.Config{
		New: func(t *testing.T) framework.Framework {
			dshHome = t.TempDir()
			return New()
		},
		Fixtures: []conformance.Fixture{
			{
				Role: "APPEND_SYSTEM.md",
				Leaf: []byte("# Persona\n\nOwner-authored persona.\n"),
			},
			{
				Role: "skills/",
				Dirs: map[string]map[string][]byte{
					"weather": {
						"SKILL.md": []byte("---\nname: weather\n---\n\nLook up the weather for a city.\n"),
					},
				},
				Files: map[string][]byte{
					"reading-notes.md": []byte("---\nname: reading-notes\n---\n\nSummarize a document into three bullets.\n"),
				},
			},
			{
				Role: "memory/",
				Files: map[string][]byte{
					"MEMORY.md":      []byte("- [Owner prefers short answers](owner-style.md) — answer length\n"),
					"owner-style.md": []byte("---\nname: owner-style\ndescription: how the owner wants answers\ntype: feedback\ntrusted_by: 0x00000000000000000000000000000000000000aa\n---\n\nShort answers, conclusion first.\n"),
				},
			},
			{
				Role: "memory-public/",
				Files: map[string][]byte{
					"MEMORY.md":      []byte("- [Product FAQ](product-faq.md) — common questions about the product\n"),
					"product-faq.md": []byte("---\nname: product-faq\ndescription: common questions about the product\ntype: reference\ntrusted_by: 0x00000000000000000000000000000000000000aa\n---\n\nThe agent answers in English or Chinese.\n"),
				},
			},
		},
	})
}
