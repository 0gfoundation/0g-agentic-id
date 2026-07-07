package claudecode

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"seal-verify/internal/framework"
	"seal-verify/internal/framework/conformance"
	"seal-verify/internal/platform"
)

// newTestAdapter redirects claudeHome into a temp dir and stubs the
// version probe: developer machines plausibly have a real `claude` on
// PATH, and a live probe would make evoFramework environment-dependent.
func newTestAdapter(t *testing.T) *Adapter {
	claudeHome = t.TempDir()
	oldProbe := probeVersion
	probeVersion = func(context.Context) string { return "" }
	t.Cleanup(func() { probeVersion = oldProbe })
	return New()
}

func TestConformance(t *testing.T) {
	conformance.Run(t, conformance.Config{
		New: func(t *testing.T) framework.Framework { return newTestAdapter(t) },
		Fixtures: []conformance.Fixture{
			{
				Role: "framework",
				Leaf: []byte(`{"name":"claude-code","package_version":"2.1.0","schema_version":1}`),
			},
			{
				// Canonical encoding: compact JSON, keys sorted (json.Marshal
				// over map), only allowlisted keys.
				Role: "settings.json",
				Leaf: []byte(`{"model":"claude-fable-5","outputStyle":"concise","permissions":{"allow":["Bash(npm test)"],"deny":["Read(.env)"]}}`),
			},
			{
				Role: "workspace/",
				Files: map[string][]byte{
					"CLAUDE.md": []byte("# Atlas\n\nResearch agent. Prefers primary sources.\n"),
					"NOTES.md":  []byte("standing notes\n"),
				},
			},
			{
				Role: "agents/",
				Files: map[string][]byte{
					"researcher.md": []byte("---\nname: researcher\ndescription: deep-dive research subagent\n---\n\nYou verify claims against sources.\n"),
				},
			},
			{
				Role: "skills/",
				Dirs: map[string]map[string][]byte{
					"deploy": {
						"SKILL.md":       []byte("---\nname: deploy\n---\nHow to deploy.\n"),
						"scripts/run.sh": []byte("#!/bin/sh\necho deploy\n"),
					},
				},
			},
		},
	})
}

// TestInjectionRoundTrip exercises the CLAUDE.md platform injection
// against the strip invariant: injecting the sealed section must not
// change what EvolutionFor reports for workspace/, and re-injecting must
// be idempotent on the agent-owned content.
func TestInjectionRoundTrip(t *testing.T) {
	ctx := context.Background()
	a := newTestAdapter(t)

	owned := []byte("# Atlas\n\nAgent-owned memory.\n")
	if err := a.Restore(ctx, "workspace/", nil); err != nil {
		t.Fatal(err)
	}
	if err := a.RestoreEntry(ctx, "workspace/", "CLAUDE.md", owned); err != nil {
		t.Fatal(err)
	}
	before, err := a.EvolutionFor(ctx, "workspace/")
	if err != nil {
		t.Fatal(err)
	}

	pc := platform.Build(platform.RuntimeSnapshot{
		AgentSeal:    "0x00000000000000000000000000000000DeaDBeef",
		AgentID:      "42",
		SealSignSock: "/run/seal-sign.sock",
		PublicURL:    "http://8080-test.sandbox.example",
		WhitelistMax: whitelistMax(),
	})
	for i := 0; i < 2; i++ { // twice: injection must be idempotent
		if err := upsertClaudeMD(claudeMDPath(), pc); err != nil {
			t.Fatal(err)
		}
	}

	onDisk, err := os.ReadFile(claudeMDPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(onDisk, []byte(platform.MarkerStart)) {
		t.Fatal("injection did not land in CLAUDE.md")
	}

	after, err := a.EvolutionFor(ctx, "workspace/")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("workspace/ hash changed after platform injection:\n before = %s\n after  = %s", before, after)
	}

	// LoadEntry must mirror the strip: the chain payload for CLAUDE.md is
	// the agent-owned content only.
	entry, err := a.LoadEntry(ctx, "workspace/", "CLAUDE.md")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(entry, owned) {
		t.Errorf("LoadEntry(CLAUDE.md) leaked injected content:\n got  = %q\n want = %q", entry, owned)
	}
}

// TestSettingsFiltersRuntimeKeys asserts the allowlist drops Claude
// Code's own bookkeeping and secret-bearing keys from the chain payload.
func TestSettingsFiltersRuntimeKeys(t *testing.T) {
	ctx := context.Background()
	a := newTestAdapter(t)

	dirty := []byte(`{
		"model": "claude-fable-5",
		"env": {"ANTHROPIC_API_KEY": "sk-secret"},
		"apiKeyHelper": "/usr/local/bin/leak.sh",
		"feedbackSurveyState": {"lastShown": "2026-07-01"},
		"permissions": {"allow": ["Bash(ls)"]}
	}`)
	if err := a.Restore(ctx, "settings.json", dirty); err != nil {
		t.Fatal(err)
	}
	got, err := a.EvolutionFor(ctx, "settings.json")
	if err != nil {
		t.Fatal(err)
	}
	want := `{"model":"claude-fable-5","permissions":{"allow":["Bash(ls)"]}}`
	if string(got) != want {
		t.Errorf("settings.json evolution:\n got  = %s\n want = %s", got, want)
	}
	for _, leak := range []string{"sk-secret", "apiKeyHelper", "feedbackSurveyState"} {
		if bytes.Contains(got, []byte(leak)) {
			t.Errorf("chain payload leaks %q", leak)
		}
	}
}

// TestFrameworkBindingRejectsForeignName: a chain binding naming another
// framework must fail loud, not boot with a forged identity.
func TestFrameworkBindingRejectsForeignName(t *testing.T) {
	a := newTestAdapter(t)
	err := a.Restore(context.Background(), "framework",
		[]byte(`{"name":"openclaw","package_version":"2026.5.7","schema_version":1}`))
	if err == nil {
		t.Fatal("Restore accepted a binding for a different framework")
	}
}

// TestPersonaIngestion: the protocol seed role lands as CLAUDE.md +
// settings.json model pin, idempotently, without clobbering settings
// keys the settings.json role owns.
func TestPersonaIngestion(t *testing.T) {
	ctx := context.Background()
	a := newTestAdapter(t)

	// settings.json role restored first — persona must merge, not clobber.
	if err := a.Restore(ctx, "settings.json",
		[]byte(`{"permissions":{"allow":["Bash(ls)"]}}`)); err != nil {
		t.Fatal(err)
	}

	persona := []byte(`{"system_prompt":"You are Sage. DeFi helper\n","inference":{"provider":"anthropic","model":"claude-opus-4-6"}}`)
	for i := 0; i < 2; i++ { // idempotent: HandleLegacy re-runs every pre-drift boot
		if err := a.HandleLegacy(ctx, "persona", persona); err != nil {
			t.Fatal(err)
		}
	}

	md, err := os.ReadFile(claudeMDPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(md) != "You are Sage. DeFi helper\n" {
		t.Errorf("CLAUDE.md = %q", md)
	}

	settings, err := os.ReadFile(settingsJSONPath())
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(settings, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["model"] != "claude-opus-4-6" {
		t.Errorf("settings model = %v; want claude-opus-4-6", cfg["model"])
	}
	if _, ok := cfg["permissions"]; !ok {
		t.Error("persona ingestion clobbered the settings.json role's permissions key")
	}
}

// TestPersonaIngestionSkipsForeignProvider: claude-code is Anthropic-
// native; a persona pinning another provider keeps the default model
// rather than writing an unresolvable name.
func TestPersonaIngestionSkipsForeignProvider(t *testing.T) {
	ctx := context.Background()
	a := newTestAdapter(t)

	persona := []byte(`{"system_prompt":"hi\n","inference":{"provider":"0g-compute","model":"glm-5.2"}}`)
	if err := a.HandleLegacy(ctx, "persona", persona); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(settingsJSONPath()); !os.IsNotExist(err) {
		data, _ := os.ReadFile(settingsJSONPath())
		var cfg map[string]any
		_ = json.Unmarshal(data, &cfg)
		if _, ok := cfg["model"]; ok {
			t.Errorf("foreign provider's model leaked into settings: %s", data)
		}
	}
}

// TestFrameworkBindingEmptyVersionResolvesToWhitelistMax: attestor mints
// version-less bindings ({"name","schema_version"}); the adapter owns
// version knowledge and fills whitelistMax.
func TestFrameworkBindingEmptyVersionResolvesToWhitelistMax(t *testing.T) {
	ctx := context.Background()
	a := newTestAdapter(t)
	if err := a.Restore(ctx, "framework",
		[]byte(`{"name":"claude-code","schema_version":1}`)); err != nil {
		t.Fatal(err)
	}
	got, err := a.EvolutionFor(ctx, "framework")
	if err != nil {
		t.Fatal(err)
	}
	want := `{"name":"claude-code","package_version":"` + whitelistMax() + `","schema_version":1}`
	if string(got) != want {
		t.Errorf("version-less binding:\n got  = %s\n want = %s", got, want)
	}
}
