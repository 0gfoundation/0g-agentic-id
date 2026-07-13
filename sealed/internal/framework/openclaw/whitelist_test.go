package openclaw

import "testing"

// useTestWhitelist swaps the validated-version table for the test and
// restores it afterwards, so assertions don't chase real whitelist bumps.
func useTestWhitelist(t *testing.T, versions []string) {
	t.Helper()
	prev := supportedOpenclawVersions
	supportedOpenclawVersions = versions
	t.Cleanup(func() { supportedOpenclawVersions = prev })
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2026.5.6", "2026.5.7", -1},
		{"2026.5.7", "2026.5.6", 1},
		{"2026.5.7", "2026.5.7", 0},
		{"2026.5.10", "2026.5.7", 1}, // numeric, not lexicographic
		{"2026.5", "2026.5.0", 0},    // missing segment counts as zero
		{"2026.5", "2026.5.1", -1},
		{"2027.1.1", "2026.12.31", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestNearestWhitelisted(t *testing.T) {
	useTestWhitelist(t, []string{"2026.3.1", "2026.5.6", "2026.5.7"})
	cases := map[string]string{
		"2026.9.9":  "2026.5.7", // above max → max
		"2026.5.6":  "2026.5.6", // exact hit (nearest is itself)
		"2026.5.5":  "2026.3.1", // between validated releases → older neighbor
		"2025.1.1":  "2026.3.1", // below everything → oldest validated
		"2026.5.10": "2026.5.7", // numeric ordering, not lexicographic
	}
	for pin, want := range cases {
		if got := nearestWhitelisted(pin); got != want {
			t.Errorf("nearestWhitelisted(%q) = %q, want %q", pin, got, want)
		}
	}
	// Garbage pins must still resolve to SOME validated version —
	// deterministically, never to the garbage itself or "".
	for _, pin := range []string{"latest", "1.0.0-beta", "next", ""} {
		if got := nearestWhitelisted(pin); !isWhitelisted(got) {
			t.Errorf("nearestWhitelisted(%q) = %q, not a validated version", pin, got)
		}
	}
}
