package harness

import "testing"

func TestSupportedVersionsPreserveExistingBindings(t *testing.T) {
	for _, version := range []string{"0.1.0", "0.2.0"} {
		if !isWhitelisted(version) || coerceWhitelisted(version) != version {
			t.Fatalf("existing harness binding %s is no longer accepted", version)
		}
	}
	if whitelistMax() != "0.2.0" {
		t.Fatal("older binding compatibility changed the preferred build version")
	}
}
