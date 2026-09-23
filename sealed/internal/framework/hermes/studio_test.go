package hermes

import (
	"testing"

	"seal-verify/internal/studio"
)

func TestStudioActivationMatchesHermesRuntime(t *testing.T) {
	resources := (&Adapter{}).StudioLayout().Resources
	want := map[studio.Kind]studio.Activation{
		studio.KindPersonality: studio.ActivationNextSession,
		studio.KindSkills:      studio.ActivationRestartRequired,
		studio.KindMemory:      studio.ActivationNextSession,
	}
	for _, resource := range resources {
		if got := resource.Activation; got != want[resource.Kind] {
			t.Errorf("%s activation = %q, want %q", resource.Kind, got, want[resource.Kind])
		}
	}
}
