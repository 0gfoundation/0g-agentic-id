package dsh

import (
	"testing"

	"seal-verify/internal/studio"
)

func TestStudioPersonalityIsActive(t *testing.T) {
	resources := (&Adapter{}).StudioLayout().Resources
	if got := resources[0].Activation; got != studio.ActivationActive {
		t.Fatalf("personality activation = %q, want %q", got, studio.ActivationActive)
	}
}
