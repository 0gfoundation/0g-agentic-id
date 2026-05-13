package openclaw

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Platform-managed TOOLS.md injection.
//
// openclaw injects ~/.openclaw/workspace/{AGENTS,SOUL,TOOLS,MEMORY}.md into
// the LLM's system prompt every turn. We use TOOLS.md ("environment knowledge
// + tool guidance") to teach the agent what platform capabilities exist and
// what they mean — without writing per-deployment values into the file
// itself.
//
// Why instructions, not the values:
//   - The instructions are deployment-agnostic (work in any sandbox)
//   - The values are in env (AGENT_PUBLIC_URL, SEAL_SIGN_SOCK, AGENT_SEAL),
//     set per-container by spawnGateway
//   - knowledge dim's evolution upload can include TOOLS.md without leaking
//     deployment-specific URLs / addresses into other agents' restored
//     workspace
//
// We mark the injected section with HTML comment markers so future restarts
// can find and replace just our section without disturbing whatever else
// the owner / agent put in TOOLS.md.

const (
	platformMarkerStart = "<!-- 0g-platform-injected:start -->"
	platformMarkerEnd   = "<!-- 0g-platform-injected:end -->"
)

// platformCaps bundles the runtime-discovered capabilities advertised in
// the platform-managed section. Each field is optional; an empty field
// suppresses its sub-section.
type platformCaps struct {
	publicURL string // → "Public URL discovery"
	signSock  string // → "TEE-attested identity" + signing sub-section (paired with agentSeal)
	agentSeal string // 0x-address; only meaningful alongside signSock
}

// upsertPlatformSection writes (or replaces) the platform-managed section
// in TOOLS.md. Owner / agent content elsewhere in the file is preserved.
//
// All caps fields empty → strip the existing platform section entirely.
// Useful for local-dev mode without a proxy domain or signer.
func upsertPlatformSection(path string, caps platformCaps) error {
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	cleaned := stripPlatformInjection(existing)

	var subs []string
	// Identity comes first — it frames everything else as "your TEE-attested
	// runtime", which the public-URL section's trust contract references.
	if caps.signSock != "" && caps.agentSeal != "" {
		subs = append(subs, buildIdentityInstructions(caps.signSock, caps.agentSeal))
	}
	if caps.publicURL != "" {
		subs = append(subs, buildPublicURLInstructions(caps.publicURL))
	}

	var out []byte
	if len(subs) == 0 {
		out = cleaned
	} else {
		body := "## Environment\n" +
			"\n" +
			"You are running on the 0G Sealed Sandbox platform — a hardware-" +
			"attested TEE (TDX) running a specific, audited container image. " +
			"The sections below describe the capabilities and identity the " +
			"platform exposes to you at runtime.\n" +
			"\n" +
			strings.Join(subs, "\n")
		section := platformMarkerStart + "\n" + body + platformMarkerEnd + "\n"
		if len(cleaned) > 0 && !bytes.HasSuffix(cleaned, []byte("\n")) {
			cleaned = append(cleaned, '\n')
		}
		if len(cleaned) > 0 {
			cleaned = append(cleaned, '\n')
		}
		out = append(cleaned, []byte(section)...)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// stripPlatformInjection removes the platform-managed section (between
// markerStart and markerEnd) from content. Returns the agent-owned content
// only, with surrounding whitespace tidied.
//
// Used by:
//   - upsertPlatformSection before re-injecting (so updates are idempotent)
//   - knowledge dim's EvolutionFor before tar-gzipping workspace files for
//     upload, so deployment-specific instructions don't ride along into
//     other agents' restored workspace
func stripPlatformInjection(content []byte) []byte {
	s := bytes.Index(content, []byte(platformMarkerStart))
	if s < 0 {
		return content
	}
	rest := content[s:]
	e := bytes.Index(rest, []byte(platformMarkerEnd))
	if e < 0 {
		// markerStart present but no end — strip from markerStart to EOF
		// (the file got truncated mid-section somehow).
		return bytes.TrimRight(content[:s], "\n")
	}
	before := bytes.TrimRight(content[:s], "\n")
	after := bytes.TrimLeft(rest[e+len(platformMarkerEnd):], "\n")
	if len(after) == 0 {
		return before
	}
	return append(append(before, '\n', '\n'), after...)
}

// buildIdentityInstructions composes the "TEE-attested identity" sub-section.
// Leads with what agentSeal means + the trust chain that backs it, then
// covers the signing endpoints. Pure function for testability.
func buildIdentityInstructions(signSock, agentSeal string) string {
	return "### Your TEE-attested identity (agentSeal)\n" +
		"\n" +
		"You have a cryptographic identity called **agentSeal**, whose address " +
		"is exposed as `AGENT_SEAL` in your environment (current value: `" +
		agentSeal + "`). This identity is **proof that you are running inside " +
		"a legitimate TEE runtime**, not a guess or a self-claim:\n" +
		"\n" +
		"- The private key (`agent_seal_priv`) is provisioned by the attestor " +
		"only after it has verified this container's TDX hardware attestation " +
		"and matched the container image hash to a known/audited build.\n" +
		"- The key is delivered via ECIES, encrypted to a public key whose " +
		"corresponding private key exists **only inside this attested " +
		"container's memory**. No other process — including the sandbox owner, " +
		"the host operator, or a tampered runtime — can decrypt it.\n" +
		"- Therefore, a signature produced by `agentSeal` is a third-party-" +
		"verifiable claim that **whatever it signed came from this exact " +
		"audited image running in a real TEE**.\n" +
		"\n" +
		"This is a strictly stronger claim than \"the agent said so\": a " +
		"verifier who knows the expected image hash and TEE attestation chain " +
		"can confirm the runtime is the one they trust.\n" +
		"\n" +
		"### Signing as agentSeal\n" +
		"\n" +
		"You **cannot read `agent_seal_priv` directly** — the sealed runtime " +
		"holds it. To sign as agentSeal, POST to the local sign endpoint at " +
		"`unix://${SEAL_SIGN_SOCK}` (path: `" + signSock + "`). The socket " +
		"only listens inside this container, so the sandbox owner cannot " +
		"reach it from outside.\n" +
		"\n" +
		"Endpoints (all POST, all JSON):\n" +
		"\n" +
		"- `/sign/personal_sign` — EIP-191 message signing.\n" +
		"  Body: `{\"message\": \"...\"}` or `{\"message_hex\": \"0x...\"}`.\n" +
		"  Returns: `{\"signature\", \"address\", \"msg_hash\"}`.\n" +
		"\n" +
		"- `/sign/typed_data` — EIP-712 typed-data signing.\n" +
		"  Body: standard TypedData JSON (`{domain, types, primaryType, message}`).\n" +
		"  Returns: `{\"signature\", \"address\", \"digest\"}`.\n" +
		"\n" +
		"- `/sign/transaction` — sign a chain transaction (returns raw signed " +
		"RLP hex; you broadcast it through any RPC endpoint you choose).\n" +
		"  Body: `{chain_id, nonce, to, value, data, gas_limit, " +
		"max_fee_per_gas, max_priority_fee_per_gas, type}` " +
		"(type defaults to `\"dynamic\"` for EIP-1559; use `\"legacy\"` with " +
		"`gas_price` for legacy chains).\n" +
		"  Returns: `{\"raw_tx\", \"tx_hash\", \"address\", \"signature\"}`.\n" +
		"\n" +
		"Example (curl over unix socket):\n" +
		"\n" +
		"    curl --unix-socket \"$SEAL_SIGN_SOCK\" \\\n" +
		"      -H 'Content-Type: application/json' \\\n" +
		"      -d '{\"message\":\"hello\"}' \\\n" +
		"      http://localhost/sign/personal_sign\n" +
		"\n" +
		"### When to use agentSeal\n" +
		"\n" +
		"- A contract caller / verifier requires `msg.sender == AGENT_SEAL` " +
		"or checks an EIP-712 signature against `AGENT_SEAL`.\n" +
		"- You need an off-chain claim that a third party can verify came " +
		"from a legitimate TEE runtime (not just \"the agent says so\").\n" +
		"- Note: serve-proof headers on responses through `AGENT_PUBLIC_URL` " +
		"are signed automatically by the runtime using agentSeal; you do not " +
		"need to call these endpoints for that case.\n" +
		"\n" +
		"### What NOT to do with agentSeal\n" +
		"\n" +
		"- Do **not** blindly forward owner-controlled bytes to these " +
		"endpoints. The owner cannot reach the socket directly, but you are " +
		"the gatekeeper: if you sign attacker-chosen bytes as agentSeal, the " +
		"resulting signature looks identical to a legitimate runtime claim. " +
		"Always review what you are signing and reject ambiguous requests.\n"
}

// buildPublicURLInstructions composes the "Public URL discovery" sub-section.
// Pure function for testability.
func buildPublicURLInstructions(publicURL string) string {
	return "### Public URL discovery\n" +
		"\n" +
		"Your externally-reachable URL prefix is in environment variable " +
		"`AGENT_PUBLIC_URL`. Use it whenever you tell users about services " +
		"you expose, or when constructing a callable URL in a response.\n" +
		"\n" +
		"To read the value at runtime, use the `exec` tool:\n" +
		"\n" +
		"    printenv AGENT_PUBLIC_URL\n" +
		"\n" +
		"Example: if you registered a handler at `/api/ppt/generate`, tell " +
		"users to call `${AGENT_PUBLIC_URL}/api/ppt/generate` (substituting " +
		"the runtime value).\n" +
		"\n" +
		"### Trust contract\n" +
		"\n" +
		"All HTTP responses through `AGENT_PUBLIC_URL` are signed automatically " +
		"with an `X-Agent-Proof` header (an agentSeal EIP-191 signature over " +
		"the canonical request/response envelope). Verifiers reject responses " +
		"without this header. Do not direct users to ports other than what " +
		"`AGENT_PUBLIC_URL` resolves to.\n"
}
