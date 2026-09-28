package prime

// The persona seed as a pin source. attestor mints exactly two iData roles —
// `framework` and `persona` — so an agent minted before the settings channel
// that never committed drift carries its pin ONLY in the seed: the retired
// models.json role modelsjson.go recovers from first exists on chain after a
// drift commit. For prime the stakes are an outage, not a degradation: Start
// hard-fails on a missing pin, and the code before the migration booted these
// agents fine.

import (
	"context"
	"encoding/json"
	"testing"

	"seal-verify/internal/inference"
)

// The gap population: persona on chain, no models.json entry. The recovered
// document must validate (a non-validating one is the same outage this exists
// to prevent) and must carry the owner's provider VERBATIM — the seed records
// "0g-compute" as the owner spelled it, which is exactly the spelling
// settings.Resolve turns back into the router endpoint the agent was using.
func TestHandleLegacy_Persona_RecoversTheNeverDriftedAgentsPin(t *testing.T) {
	primeHome = t.TempDir()
	a := New()

	seed := []byte(`{"system_prompt":"You are Ada.\n","inference":{"provider":"0g-compute","model":"glm-5.3"}}`)
	if err := a.HandleLegacy(context.Background(), "persona", seed); err != nil {
		t.Fatalf("HandleLegacy(persona): %v", err)
	}

	doc, ok := a.SeededSettings()
	if !ok {
		t.Fatal("SeededSettings() found nothing — this agent boots with no pin, prime.Start refuses that, and the container goes offline where the pre-migration code booted it")
	}
	if doc.Provider != inference.ZGComputeProvider || doc.Model != "glm-5.3" {
		t.Errorf("recovered %+v, want the owner's literal choice 0g-compute/glm-5.3", doc)
	}
	if err := doc.Validate(); err != nil {
		t.Errorf("recovered document does not validate: %v — persisting it would fail every future boot", err)
	}
	if doc.Thinking != "" {
		t.Errorf("thinking = %q, want unset — the seed has no field for the owner's level, so any value here is invented", doc.Thinking)
	}
}

// Phase C walks chain entries in arrival order, so precedence must be a rule
// in the code, not an accident of which branch ran last. The retired
// models.json role is the agent's LATER state (the seed's pin was translated
// into it once, and any re-pin exists only there), so it wins — in both
// orders.
func TestHandleLegacy_Persona_ConfigRoleWinsInEitherOrder(t *testing.T) {
	seed := []byte(`{"inference":{"provider":"0g-compute","model":"glm-4.5-air"}}`)
	entry := []byte(`{"providers":{"openai":{"baseUrl":"https://router-api.0g.ai/v1","models":[{"id":"glm-5.3"}]}}}`)

	for _, order := range []struct {
		name  string
		roles [][2]string
	}{
		{"persona first", [][2]string{{"persona", string(seed)}, {"models.json", string(entry)}}},
		{"config first", [][2]string{{"models.json", string(entry)}, {"persona", string(seed)}}},
	} {
		t.Run(order.name, func(t *testing.T) {
			primeHome = t.TempDir()
			a := New()
			for _, r := range order.roles {
				if err := a.HandleLegacy(context.Background(), r[0], []byte(r[1])); err != nil {
					t.Fatalf("HandleLegacy(%s): %v", r[0], err)
				}
			}
			doc, ok := a.SeededSettings()
			if !ok {
				t.Fatal("nothing recovered")
			}
			// glm-5.3 is the drifted state; glm-4.5-air is the mint snapshot
			// of a route replaced boots ago. Rolling back to it is the
			// opposite of "routes the way it was".
			if doc.Model != "glm-5.3" {
				t.Fatalf("[%s] recovered %+v — the retired config role must outrank the mint seed", order.name, doc)
			}
		})
	}
}

// Nothing in the seed may fail a boot, and half a pin recovers nothing: what
// comes back is PERSISTED as the owner's document, so a half-answer would not
// be a partial recovery, it would be a stored document that fails every later
// boot while outranking this recovery each time.
func TestHandleLegacy_Persona_UnrecoverableSeedsAreNoops(t *testing.T) {
	cases := map[string]string{
		"empty":            ``,
		"whitespace":       "  \n\t",
		"not json":         `persona: yes`,
		"truncated":        `{"inference":{"provider":"0g-c`,
		"json array":       `[1,2,3]`,
		"no inference":     `{"system_prompt":"hi"}`,
		"wrong shape":      `{"inference":"0g-compute/glm-5.3"}`,
		"provider only":    `{"inference":{"provider":"0g-compute"}}`,
		"model only":       `{"inference":{"model":"glm-5.3"}}`,
		"blank after trim": `{"inference":{"provider":"  ","model":"\n"}}`,
	}
	for name, seed := range cases {
		t.Run(name, func(t *testing.T) {
			primeHome = t.TempDir()
			a := New()
			if err := a.HandleLegacy(context.Background(), "persona", []byte(seed)); err != nil {
				t.Fatalf("HandleLegacy returned %v — a bad seed must never fail the boot", err)
			}
			if doc, ok := a.SeededSettings(); ok {
				t.Fatalf("recovered %+v from an unusable seed", doc)
			}
		})
	}
}

// The recovered document must round-trip through the same machinery main.go
// runs it through — Marshal (for report.SeedSettings) and then Parse on a
// later boot — without losing the pin.
func TestHandleLegacy_Persona_RecoveredDocumentRoundTrips(t *testing.T) {
	primeHome = t.TempDir()
	a := New()
	seed := []byte(`{"inference":{"provider":"anthropic","model":"claude-sonnet-5"}}`)
	if err := a.HandleLegacy(context.Background(), "persona", seed); err != nil {
		t.Fatal(err)
	}
	doc, ok := a.SeededSettings()
	if !ok {
		t.Fatal("nothing recovered")
	}
	blob, err := doc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	if back["provider"] != "anthropic" || back["model"] != "claude-sonnet-5" {
		t.Fatalf("round-trip lost the pin: %s", blob)
	}
}
