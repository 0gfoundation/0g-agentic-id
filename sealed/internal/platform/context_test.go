package platform

import (
	"strings"
	"testing"
	"time"
)

// The authorship split this package promises: platform text speaks ONLY
// about doctrine and platform mechanics. Framework facts (paths, upgrade
// commands, config semantics, tool names, injected file names) are the
// adapter's to author — if any leak back in here, every OTHER framework's
// agent gets told falsehoods about its own runtime, which a safety-tuned
// model correctly reads as prompt injection (see FRAMEWORK_ADAPTER.md §12).
func TestBuild_NoFrameworkNouns(t *testing.T) {
	rs := RuntimeSnapshot{
		SealedVersion:    "abc1234",
		FrameworkVersion: "9.9.9",
		WhitelistMax:     "9.9.9",
		AgentSeal:        "0x000000000000000000000000000000000000dEaD",
		AgentID:          "42",
		Owner:            "0x000000000000000000000000000000000000bEEF",
		ChainRPC:         "https://rpc.example",
		ContractAddr:     "0x0000000000000000000000000000000000000001",
		AttestorURL:      "https://attestor.example",
		PublicURL:        "http://8080-x.example",
		SealSignSock:     "/run/seal-sign.sock",
		Provider:         "0g-compute",
		Model:            "some-model",
		ZGComputeRouted:  true,
		BootTime:         time.Unix(1700000000, 0),
	}
	pc := Build(rs)
	all := strings.Join([]string{pc.Identity, pc.Sovereignty, pc.Capabilities, pc.Constraints, pc.Runtime}, "\n")

	for _, banned := range []string{
		"openclaw", "OpenClaw", // the framework itself
		"~/.",                                // any framework home-dir layout
		"npm ",                               // any framework's package manager
		"SOUL.md", "TOOLS.md", "IDENTITY.md", // openclaw's injected file names
		"workspace/skills", "workspace/canvas", // openclaw's tracked layout
		"`exec` tool", // openclaw's tool name
	} {
		if strings.Contains(all, banned) {
			t.Errorf("platform text contains framework noun %q — framework facts belong to the adapter", banned)
		}
	}
}

// Every section must still render non-empty with a fully populated
// snapshot — the noun eviction must not have hollowed a section out.
func TestBuild_SectionsNonEmpty(t *testing.T) {
	rs := RuntimeSnapshot{
		AgentSeal:    "0x000000000000000000000000000000000000dEaD",
		SealSignSock: "/run/seal-sign.sock",
		PublicURL:    "http://8080-x.example",
	}
	pc := Build(rs)
	for name, s := range map[string]string{
		"Identity":     pc.Identity,
		"Sovereignty":  pc.Sovereignty,
		"Capabilities": pc.Capabilities,
		"Constraints":  pc.Constraints,
		"Runtime":      pc.Runtime,
	} {
		if strings.TrimSpace(s) == "" {
			t.Errorf("section %s rendered empty", name)
		}
	}
}
