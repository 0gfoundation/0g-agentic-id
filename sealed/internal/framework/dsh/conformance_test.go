package dsh

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
// Exercises the whole state/identity half without DSH installed at all — the
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
				// Canonical form: single plugin section, single provider route,
				// struct fields sorted at every level, apiKeyEnv an env-var NAME
				// rather than a secret.
				Role: "settings.yaml",
				Leaf: []byte(`{"llm-pi-ai":{"providers":{"0g-compute":{"apiKeyEnv":"SEAL_MODEL_API_KEY","models":[{"id":"glm-5.2"}]}}}}`),
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
		},
	})
}
