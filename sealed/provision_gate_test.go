package main

import (
	"errors"
	"strings"
	"testing"

	"seal-verify/internal/config"
)

// ── provisionGate ──────────────────────────────────────────────────────────

func fullBootstrap() *config.Bootstrap {
	return &config.Bootstrap{
		AttestorURL:     "http://attestor.test",
		ChainRPC:        "http://rpc.test",
		ContractAddr:    "0x0000000000000000000000000000000000000001",
		FallbackIndexer: "http://indexer.test",
	}
}

func TestProvisionGate_PrivsepFailureBlocksProvisioning(t *testing.T) {
	refusal := errors.New(`privsep unavailable: no "agent" user in this image; add to its Dockerfile: RUN useradd agent`)
	skip := provisionGate(fullBootstrap(), func() error { return refusal })
	if skip == "" {
		t.Fatal("provisionGate proceeded with privsep unavailable: agent_seal_priv would be fetched into a container whose framework shares sealed's uid")
	}
	if !strings.HasPrefix(skip, "FAIL ") {
		t.Errorf("refusal %q must be logged as a FAIL line", skip)
	}
	if !strings.Contains(skip, refusal.Error()) {
		t.Errorf("refusal %q must carry privsep's cause and fix %q verbatim", skip, refusal)
	}
}

func TestProvisionGate_ProceedsWhenEverythingIsInPlace(t *testing.T) {
	called := false
	if skip := provisionGate(fullBootstrap(), func() error { called = true; return nil }); skip != "" {
		t.Fatalf("provisionGate = %q; want \"\" (proceed)", skip)
	}
	if !called {
		t.Fatal("provisionGate proceeded without consulting privsep")
	}
}

func TestProvisionGate_MissingEnvSkipsBeforePrivsep(t *testing.T) {
	// Local runs without an attestor or chain never provision, so they must
	// not be reported as a privsep FAIL.
	noAttestor := fullBootstrap()
	noAttestor.AttestorURL = ""
	noChain := fullBootstrap()
	noChain.ChainRPC = ""
	for name, tc := range map[string]struct {
		cfg  *config.Bootstrap
		want string
	}{
		"no attestor":  {noAttestor, "ATTESTOR_URL unset"},
		"no chain rpc": {noChain, "missing required env"},
	} {
		t.Run(name, func(t *testing.T) {
			skip := provisionGate(tc.cfg, func() error {
				t.Error("privsep consulted for a boot that never provisions")
				return errors.New("unavailable")
			})
			if !strings.Contains(skip, tc.want) {
				t.Fatalf("provisionGate = %q; want it to contain %q", skip, tc.want)
			}
		})
	}
}
