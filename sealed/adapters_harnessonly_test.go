//go:build harnessonly

package main

import (
	"strings"
	"testing"

	"seal-verify/internal/framework"
)

// The 0g-harness image's build registers the 0g-harness adapter alone (and
// its legacy name); an agent bound to another framework does not boot on it.
func TestRegisterAdapters_HarnessOnly(t *testing.T) {
	registerAdapters()
	for _, name := range []string{"0g-harness", "dsh"} {
		if _, err := framework.Get(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, name := range []string{"openclaw", "hermes", "prime-agent"} {
		if _, err := framework.Get(name); err == nil {
			t.Errorf("%s is registered in the harnessonly build", name)
		}
	}
	entries := []decryptedEntry{{Role: "framework", Plaintext: []byte(`{"name":"openclaw","schema_version":1}`)}}
	if _, err := resolveAdapter(entries, ""); err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("an openclaw binding on the 0g-harness image: %v", err)
	}
}
