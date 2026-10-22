package prime

// Filesystem paths the prime adapter manages.
//
// Prime Agent keeps its cross-session ("global") state under
// <primeHome> (~/.prime/agent — `CONFIG_DIR_NAME` in the framework's
// packages/coding-agent/src/config.ts, overridable via
// PRIME_AGENT_CODING_AGENT_DIR / PI_CODING_AGENT_DIR):
//
//	harness/harness_state.json  the Continual Harness state: prompt notes,
//	                            memories, skill registrations, subagent specs
//	                            (the four rlm.harness.create_* APIs)
//	skills/<name>/              agent-installed Python skill packages
//	                            (pyproject.toml + src/<import>/__init__.py)
//	APPEND_SYSTEM.md            framework-native system-prompt append file;
//	                            sealed uses it as the OWNER PERSONA channel
//
// Deliberately NOT managed (never on chain):
//
//   - $RLM_SESSION_DIR/harness/harness_state.json — the per-session ("local")
//     half of the harness state. Prime Agent rewrites its own prompts,
//     memories and skills MID-TASK, and those writes land here; only an
//     explicit promote moves an entry into the global file. Tracking the
//     session half would anchor half-finished harness edits on chain on
//     every 30s watcher tick. The local/global split is the framework's
//     own, which is why this adapter needs no drift-rate heuristics.
//   - the `refinements` array inside harness_state.json — an append-only
//     self-modification event log (see harness.go); runtime audit data, not
//     identity, and monotonically growing.
//   - models.json — the model registration. It is RENDERED from the owner's
//     settings at every Start rather than restored, so a fix shipped after an
//     agent was minted reaches it; tracking a rendered artifact would only
//     anchor a copy that goes stale (see modelsjson.go).
//   - everything outside primeHome, including the sealed platform/doctrine
//     text: the bridge injects that in code at session creation (see
//     agentDocPath), so no platform-injected bytes ever land in a tracked
//     path and EvolutionFor needs no marker stripping.
//
// `primeHome` is a var (not const) so unit tests can redirect into
// t.TempDir(). Production code never reassigns it.

import (
	"fmt"

	"seal-verify/internal/privsep"
)

var primeHome = "/root/.prime/agent"

// ensureDir creates a managed directory (and parents) if absent, without
// following links (internal/privsep).
func ensureDir(dir string) error {
	if err := privsep.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return nil
}

// ensureRoleDir makes dir, inside primeHome, a real directory: Restore is
// authoritative over the shape of the role directories, so a link or file
// the agent left where one belongs is replaced (privsep.EnsureDir), never
// followed, and cannot keep the agent from booting.
func ensureRoleDir(dir string) error {
	if err := privsep.EnsureDir(primeHome, dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return nil
}

func harnessStatePath() string { return primeHome + "/harness" + "/harness_state.json" }
func harnessStateDir() string  { return primeHome + "/harness" }
func skillsDir() string        { return primeHome + "/skills" }
func appendSystemPath() string { return primeHome + "/APPEND_SYSTEM.md" }

// modelsJSONPath is the framework's native model registration. NOT a tracked
// role and not a durable store: RenderSettings rebuilds it from the owner's
// settings document at every Start (see modelsjson.go), so an agent edit here
// survives exactly until the next boot.
func modelsJSONPath() string { return primeHome + "/models.json" }

// kernelVenvPython is the interpreter the framework's IPython kernel runs, in
// the venv its bootstrap provisions (uv-managed Python 3.11 + ipykernel +
// prime-agent-runtime, ~330MB). Provisioned at image build time; Start asserts
// it can import both halves, because THIS is what writes the harness state
// this adapter anchors on chain.
//
// It sits inside primeHome but under none of the tracked paths — a venv is
// reproducible from the pinned version, so tracking it would put 330MB of
// derivable content on chain per agent.
func kernelVenvPython() string { return kernelVenvDir() + "/bin/python" }
func kernelVenvDir() string    { return primeHome + "/kernel-venv" }

// sessionStateDir is the explicit home for the framework's per-session
// ("local") harness state, exported to the framework as RLM_SESSION_DIR.
//
// Not cosmetic. harness.py resolves the local state file from the environment
// (RLM_HARNESS_STATE_DIR, else RLM_SESSION_DIR/harness) and RAISES when neither
// is set — and local is the default scope for every create_*/update_* call, so
// without this the agent's first memory write fails. Worse, harness.py's own
// comment warns that a fall-through lands local writes in the GLOBAL agent-dir
// file, which is the one this adapter tracks: mid-task drafts would go on chain.
// Pinning local state outside primeHome keeps them off chain BY CONSTRUCTION
// rather than by the framework happening to resolve the way we want.
//
// Outside primeHome, so no tracked role can reach it. If the SDK sets its own
// RLM_SESSION_DIR per session, ours is simply overridden — that is the
// framework doing the same job, and this stays a floor for when it does not.
// Start creates it and hands it to the agent user, since the kernel that
// writes it runs as that user; root never reads it back. It sits directly
// in root's home (root:root 0711) rather than in the shared /tmp, so the
// agent can use it but cannot remove or replace its name. On the writable
// layer, like /tmp: it survives a process restart and goes with a
// container recreate.
//
// A var so tests can redirect it; production code never reassigns it.
var sessionStateDir = func() string { return "/root/.prime-session" }

// agentDocPath is where Start writes the assembled agent doc (platform
// mechanics + this adapter's FrameworkFacts) for the HTTP bridge to inject
// via the SDK's agentsFilesOverride. Deliberately OUTSIDE primeHome: it is
// per-boot platform text, so it must never be reachable by a tracked role,
// and the agent's own rlm.harness.delete_prompt_note cannot touch a channel
// it does not own.
func agentDocPath() string { return "/run/seal-agentdoc.md" }

// conversationPath is where the harness persists this agent's ONE conversation
// (CONVERSATION.md). Deliberately OUTSIDE primeHome — a sibling dir, not under
// any tracked role — so the watcher never commits it and a transfer never
// conveys it (off-chain by construction). It is NOT sessionStateDir: that is
// harness memory/notes; this is the message transcript. On
// the writable layer, so it survives a process restart (settings push, crash)
// and is cleared by a container recreate — which is exactly the intended
// lifetime.
//
// The file sits one level below conversationDir, in conversationSessionDir,
// because the SDK keeps each session's artifacts NEXT TO the session's
// directory (dirname(sessionDir)/session-artifacts/<id>): with the file
// directly in conversationDir that resolved to root's home, which the agent
// cannot write. One level down it resolves to
// conversationDir/session-artifacts, inside the tree handed to the agent and
// still off chain. An earlier sealed kept the file directly in
// conversationDir; migrateConversation moves it.
//
// conversationDir is a var so tests can redirect it; production code never
// reassigns it.
var conversationDir = func() string { return "/root/.prime-conversation" }

// handedOverTrees are the trees spawnBridge hands to the agent user
// (privsep.OwnTree) and New declares (privsep.DeclareTree), listed once so
// the two cannot drift apart:
//
//   - primeHome, the framework tree;
//   - sessionStateDir, where harness.py (in the agent's kernel) creates
//     its local state; root never reads it back;
//   - conversationDir as a whole, not only the session directory in it:
//     the bridge appends to the conversation there, and the SDK creates
//     each session's artifacts next to the session directory
//     (dirname(sessionDir)/session-artifacts/<id>), so the agent must be
//     able to create entries in conversationDir itself, or every turn
//     fails (TestHandedOverTreesCoverWhereTheAgentWrites).
//
// Each lives outside primeHome except the first, so none of the other two
// is reachable by a tracked role.
func handedOverTrees() []string {
	return []string{primeHome, sessionStateDir(), conversationDir()}
}

func conversationSessionDir() string { return conversationDir() + "/session" }
func conversationPath() string       { return conversationSessionDir() + "/" + conversationFile }

// conversationFile is the conversation's file name, in conversationSessionDir
// (and, before, directly in conversationDir).
const conversationFile = "owner-chat.jsonl"
