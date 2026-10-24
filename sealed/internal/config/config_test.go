package config

import (
	"os"
	"testing"
)

func TestProvisioningSecretsDoNotReachFrameworkEnvironment(t *testing.T) {
	for _, name := range []string{"SEAL_BOOT_TICKET", "SANDBOX_SEAL_KEY", "SANDBOX_SEAL_ATTESTATION", "API_KEY", "SEAL_SECRET_ENV"} {
		t.Setenv(name, "test-secret")
	}
	key := []byte{1, 2, 3}
	ScrubProvisioningSecrets(key)
	for _, name := range []string{"SEAL_BOOT_TICKET", "SANDBOX_SEAL_KEY", "SANDBOX_SEAL_ATTESTATION", "API_KEY", "SEAL_SECRET_ENV"} {
		if os.Getenv(name) != "" {
			t.Errorf("%s retained", name)
		}
	}
	for _, b := range key {
		if b != 0 {
			t.Fatal("key retained")
		}
	}
}
