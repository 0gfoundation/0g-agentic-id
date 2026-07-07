package openclaw

import (
	"context"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/framework/conformance"
)

// TestFrameworkBindingEmptyVersionResolvesToWhitelistMax mirrors the
// claudecode twin: a version-less binding ({"name","schema_version"}) is
// legal — attestor doesn't speak release schemes — and resolves to the
// adapter's whitelistMax.
func TestFrameworkBindingEmptyVersionResolvesToWhitelistMax(t *testing.T) {
	openclawHome = t.TempDir()
	oldProbe := probeOpenclawVersion
	probeOpenclawVersion = func(context.Context) string { return "" }
	t.Cleanup(func() { probeOpenclawVersion = oldProbe })

	ctx := context.Background()
	a := New()
	if err := a.Restore(ctx, "framework", []byte(`{"name":"openclaw","schema_version":1}`)); err != nil {
		t.Fatal(err)
	}
	got, err := a.EvolutionFor(ctx, "framework")
	if err != nil {
		t.Fatal(err)
	}
	want := `{"name":"openclaw","package_version":"` + whitelistMax() + `","schema_version":1}`
	if string(got) != want {
		t.Errorf("version-less binding:\n got  = %s\n want = %s", got, want)
	}
}

// TestConformance runs the shared adapter conformance suite against the
// openclaw adapter. Added when the suite was written (alongside the
// claudecode port) — the invariants it checks are the ones this adapter
// learned through production phantom-drift incidents.
func TestConformance(t *testing.T) {
	conformance.Run(t, conformance.Config{
		New: func(t *testing.T) framework.Framework {
			openclawHome = t.TempDir()
			// Stub the CLI probe: a real openclaw on the dev machine's
			// PATH would override the binding's package_version and make
			// round-trips environment-dependent.
			oldProbe := probeOpenclawVersion
			probeOpenclawVersion = func(context.Context) string { return "" }
			t.Cleanup(func() { probeOpenclawVersion = oldProbe })
			return New()
		},
		Fixtures: []conformance.Fixture{
			{
				Role: "framework",
				Leaf: []byte(`{"name":"openclaw","package_version":"2026.5.6","schema_version":1}`),
			},
			{
				// Canonical encoding: compact JSON, sorted keys, only the
				// ownedOpenclawKeys allowlist (agents/auth/models).
				Role: "openclaw.json",
				Leaf: []byte(`{"agents":{"defaults":{"model":{"primary":"glm-5.2"}}},"auth":{"mode":"none"},"models":{}}`),
			},
			{
				Role: "workspace/",
				Files: map[string][]byte{
					"MEMORY.md": []byte("long-term memory content\n"),
					"SOUL.md":   []byte("# Persona\n\nOwner-authored persona.\n"),
				},
			},
			{
				Role: "workspace/skills/",
				Dirs: map[string]map[string][]byte{
					"summarize": {
						"skill.json": []byte(`{"name":"summarize"}`),
						"README.md":  []byte("summarize things\n"),
					},
				},
			},
			{
				Role: "workspace/canvas/",
				Files: map[string][]byte{
					"index.html": []byte("<html><body>hi</body></html>\n"),
				},
				Dirs: map[string]map[string][]byte{
					"scripts": {
						"app.js": []byte("console.log('hi')\n"),
					},
				},
			},
		},
	})
}
