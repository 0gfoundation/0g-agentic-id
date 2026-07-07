package main

import "testing"

// The adapter-selection precedence is the trust-relevant part of
// bootstrap: the on-chain binding (the agent's minted identity) must win
// over any deploy-config knob, and the env fallback exists only for
// chains that carry no binding.
func TestPickFrameworkNamePrecedence(t *testing.T) {
	cases := []struct {
		binding, env string
		want         string
	}{
		{"claude-code", "", "claude-code"},         // binding alone
		{"claude-code", "openclaw", "claude-code"}, // binding beats env
		{"", "claude-code", "claude-code"},         // env fallback
		{"", "", "openclaw"},                       // compat default
		{"openclaw", "openclaw", "openclaw"},       // agreement
	}
	for _, c := range cases {
		got, source := pickFrameworkName(c.binding, c.env)
		if got != c.want {
			t.Errorf("pick(binding=%q env=%q) = %q (%s); want %q", c.binding, c.env, got, source, c.want)
		}
		if source == "" {
			t.Errorf("pick(binding=%q env=%q): empty source", c.binding, c.env)
		}
	}
}

func TestBindingFrameworkName(t *testing.T) {
	entries := []decryptedEntry{
		{Role: "persona", Plaintext: []byte(`{"system_prompt":"x"}`)},
		{Role: "framework", Plaintext: []byte(`{"name":"claude-code","schema_version":1}`)},
	}
	if got := bindingFrameworkName(entries); got != "claude-code" {
		t.Errorf("bindingFrameworkName = %q; want claude-code", got)
	}
	// Absent role → "" (env fallback applies).
	if got := bindingFrameworkName(entries[:1]); got != "" {
		t.Errorf("bindingFrameworkName(no framework role) = %q; want \"\"", got)
	}
	// Malformed plaintext → "" with a warning, not a crash; the selected
	// adapter's Restore still fails loud on it later.
	bad := []decryptedEntry{{Role: "framework", Plaintext: []byte("not-json")}}
	if got := bindingFrameworkName(bad); got != "" {
		t.Errorf("bindingFrameworkName(malformed) = %q; want \"\"", got)
	}
}
