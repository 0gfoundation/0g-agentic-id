package prime

import (
	"context"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/framework/conformance"
)

// TestConformance runs the shared adapter invariant suite (FRAMEWORK_ADAPTER.md
// §9/§10) against the real implementation: role sanity, Defaults round-trip,
// fixture round-trip + determinism + LoadEntry hash agreement, Restore
// commutativity, unknown-role contract, FrameworkFacts non-empty.
//
// It exercises the whole state/identity half without Prime Agent installed —
// which is the point: the invariants the watcher would turn into infinite
// re-upload loops in production are pure functions of disk state.
func TestConformance(t *testing.T) {
	conformance.Run(t, conformance.Config{
		New: func(t *testing.T) framework.Framework {
			primeHome = t.TempDir()
			// Keep the version probe stubbed: a real install on the test
			// machine must never leak into round-trip results.
			probePrimeVersion = func(context.Context) string { return "" }
			return New()
		},
		Fixtures: []conformance.Fixture{
			{
				// Canonical form: entries + schema, keys sorted at every level,
				// refinements dropped, global scope only.
				Role: "harness_state.json",
				Leaf: []byte(`{"entries":{"memory":{"m1":{"id":"m1","scope":"global","title":"owner prefers metric units","version":1}},"prompt":{"p1":{"id":"p1","scope":"global","title":"always cite sources","version":2}}},"schema":1}`),
			},
			{
				// Canonical form: providers map sorted, struct fields in
				// declaration order, apiKey an env-var NAME rather than a secret.
				Role: "models.json",
				Leaf: []byte(`{"providers":{"0g-compute":{"baseUrl":"https://router-api.0g.ai/v1","api":"openai-completions","apiKey":"SEAL_MODEL_API_KEY","authHeader":true,"compat":{"supportsDeveloperRole":false,"supportsReasoningEffort":false},"models":[{"id":"glm-5.2"}]}}}`),
			},
			{
				Role: "APPEND_SYSTEM.md",
				Leaf: []byte("# Persona\n\nOwner-authored persona.\n"),
			},
			{
				Role: "skills/",
				Dirs: map[string]map[string][]byte{
					"weather": {
						"pyproject.toml":          []byte("[project]\nname = \"weather\"\n"),
						"src/weather/__init__.py": []byte("async def weather(city: str) -> str:\n    return city\n"),
					},
				},
			},
		},
	})
}
