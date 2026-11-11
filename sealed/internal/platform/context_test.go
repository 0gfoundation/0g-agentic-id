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

// The refusal to export oneself is rendered only for an adapter that
// declares it (RefuseExport), with its canonical phrase; the doctrine every
// other framework's agent reads is unchanged.
func TestSovereignty_RefuseExportOnlyWhenDeclared(t *testing.T) {
	rs := RuntimeSnapshot{AgentSeal: "0x000000000000000000000000000000000000dEaD"}
	without := Build(rs).Sovereignty
	rs.RefuseExport = true
	with := Build(rs).Sovereignty
	for _, s := range []string{"6. Export yourself.", "Refusal 6 (exporting yourself)"} {
		if strings.Contains(without, s) {
			t.Errorf("rendered %q without RefuseExport", s)
		}
		if !strings.Contains(with, s) {
			t.Errorf("did not render %q with RefuseExport", s)
		}
	}
	if strings.Index(with, "5. Modify") > strings.Index(with, "6. Export") {
		t.Error("refusal 6 is not after refusal 5")
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

// The runtime snapshot names the serve-proof validator, or says plainly that
// responses are unsigned — the agent cannot read VERIFIED_FEEDBACK_ADDR
// itself, so this row is how it knows which state it is in.
func TestBuildRuntime_ServeProofValidatorRow(t *testing.T) {
	const v = "0x00000000000000000000000000000000000000B7"
	signed := Build(RuntimeSnapshot{ServeProofValidator: v}).Runtime
	if !strings.Contains(signed, "| serve-proof validator | `"+v+"`") {
		t.Errorf("validator row missing the address:\n%s", signed)
	}
	unsigned := Build(RuntimeSnapshot{}).Runtime
	if !strings.Contains(unsigned, "| serve-proof validator | `none` — responses are unsigned") {
		t.Errorf("no-validator row missing:\n%s", unsigned)
	}
}

// The credentials section is there exactly when the runtime started the
// credential proxy, and names the placeholder grammar sealed matches.
func TestCapabilities_CredentialsSectionFollowsTheSocket(t *testing.T) {
	off := Build(RuntimeSnapshot{SealSignSock: "/s", AgentSeal: "0x01"}).Capabilities
	if strings.Contains(off, "[[credential:") {
		t.Fatal("credentials described while they are off")
	}
	on := Build(RuntimeSnapshot{SealSignSock: "/s", AgentSeal: "0x01", CredSock: "/c", CredRevealSock: "/r"}).Capabilities
	for _, want := range []string{"[[credential:<name>]]", "[[credential:derived:<name>]]", "$SEAL_CRED_SOCKET", "$SEAL_CRED_REVEAL_SOCKET", "$SEAL_CRED_PROXY", "authorization_pending", "X-Seal-Sign", "/credentials/sign", "X-Seal-Credential-Filled"} {
		if !strings.Contains(on, want) {
			t.Fatalf("credentials section lacks %q", want)
		}
	}
}
