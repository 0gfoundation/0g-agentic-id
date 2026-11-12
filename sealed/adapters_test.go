//go:build !harnessonly && !zghonly

package main

import (
	"testing"

	"seal-verify/internal/framework"
)

// The default build, which the openclaw, hermes and prime-agent images ship,
// registers every adapter.
func TestRegisterAdapters_Default(t *testing.T) {
	registerAdapters()
	for _, name := range []string{"openclaw", "hermes", "prime-agent", "0g-harness", "dsh"} {
		if _, err := framework.Get(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
