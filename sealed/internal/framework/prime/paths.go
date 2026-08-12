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
//   - everything outside primeHome, including the sealed platform/doctrine
//     text: the bridge injects that in code at session creation (see
//     agentDocPath), so no platform-injected bytes ever land in a tracked
//     path and EvolutionFor needs no marker stripping.
//
// `primeHome` is a var (not const) so unit tests can redirect into
// t.TempDir(). Production code never reassigns it.

import (
	"fmt"
	"os"
)

var primeHome = "/root/.prime/agent"

// ensureDir creates a managed directory (and parents) if absent.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return nil
}

func harnessStatePath() string { return primeHome + "/harness" + "/harness_state.json" }
func harnessStateDir() string  { return primeHome + "/harness" }
func skillsDir() string        { return primeHome + "/skills" }
func appendSystemPath() string { return primeHome + "/APPEND_SYSTEM.md" }

// kernelVenvPython is the interpreter the framework's IPython kernel runs, in
// the venv its bootstrap provisions (uv-managed Python 3.11 + ipykernel +
// prime-agent-runtime, ~330MB). Provisioned at image build time; Start asserts
// it can import both halves, because THIS is what writes the harness state
// this adapter anchors on chain.
//
// It sits inside primeHome but under none of the tracked paths — a venv is
// reproducible from the pinned version, so tracking it would put 330MB of
// derivable content on chain per agent.
func kernelVenvPython() string { return primeHome + "/kernel-venv/bin/python" }

// sessionStateDir is the explicit home for the framework's per-session
// ("local") harness state, exported to the framework as RLM_SESSION_DIR.
//
// Not cosmetic. harness.py resolves the local state file from the environment
// (RLM_HARNESS_STATE_DIR, else RLM_SESSION_DIR/harness) and RAISES when neither
// is set — and local is the default scope for every create_*/update_* call, so
// without this the agent's first memory write fails. Worse, harness.py's own
// comment warns that a fall-through lands local writes in the GLOBAL agent-dir
// file, which is the one this adapter tracks: mid-task drafts would go on chain.
// Pinning local state under /tmp keeps them off chain BY CONSTRUCTION rather
// than by the framework happening to resolve the way we want.
//
// Outside primeHome, so no tracked role can reach it. If the SDK sets its own
// RLM_SESSION_DIR per session, ours is simply overridden — that is the
// framework doing the same job, and this stays a floor for when it does not.
func sessionStateDir() string { return "/tmp/prime-session" }

// agentDocPath is where Start writes the assembled agent doc (platform
// mechanics + this adapter's FrameworkFacts) for the HTTP bridge to inject
// via the SDK's agentsFilesOverride. Deliberately OUTSIDE primeHome: it is
// per-boot platform text, so it must never be reachable by a tracked role,
// and the agent's own rlm.harness.delete_prompt_note cannot touch a channel
// it does not own.
func agentDocPath() string { return "/run/seal-agentdoc.md" }
