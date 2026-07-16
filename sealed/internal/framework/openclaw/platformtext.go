package openclaw

import (
	"strings"
)

// Framework-authored context sections injected into TOOLS.md alongside
// the platform-authored ones (see internal/platform/context.go for the
// split: platform speaks only about doctrine + platform mechanics;
// everything below is openclaw-specific fact — OUR paths, OUR upgrade
// command, OUR config semantics — and therefore ours to author. A new
// framework writes its own equivalents; forgetting to means its agent
// won't know where its durable state lives.
//
// These sections moved here verbatim from platform.Build, where they
// had been hardcoded while openclaw was the only adapter.

// persistentStateText tells the agent which of ITS paths are sealed to
// chain and where to put things. Injected right after the platform
// capabilities section.
func persistentStateText() string {
	var b strings.Builder
	b.WriteString("### Persistent state\n\n")
	b.WriteString("A subset of your on-disk paths is **continuously sealed to chain**: changes are detected within ~30s, encrypted inside this TEE, uploaded to 0G Storage, and anchored on the AgenticID contract via a transaction signed by agentSeal. Everything else is container-local and disappears on the next container rebuild.\n\n")
	b.WriteString("**Tracked paths** (chain-persistent; survive container restart, Reset, Restore, and owner transfer):\n\n")
	b.WriteString("- `~/.openclaw/openclaw.json` — your config (provider/model, installed openclaw version, etc.)\n")
	b.WriteString("- `~/.openclaw/workspace/*.md` — **top-level** markdown files in the workspace root: SOUL.md, IDENTITY.md, MEMORY.md, DREAMS.md, USER.md, AGENTS.md, TOOLS.md, plus any other `.md` you create here (e.g. `notes.md`, `0g-sandbox-review.md`)\n")
	b.WriteString("- `~/.openclaw/workspace/skills/<name>/` — each top-level **subdirectory** under skills/ is packed as one entry. Loose files directly under skills/ (no enclosing directory) are NOT tracked\n")
	b.WriteString("- `~/.openclaw/workspace/canvas/*` — every top-level item (file or directory) under canvas/\n\n")
	b.WriteString("**Not tracked** (container-local; lost on rebuild):\n\n")
	b.WriteString("- Any subdirectory of `workspace/` that isn't `skills/` or `canvas/` — e.g. `workspace/memory/`, `workspace/tmp/`, `workspace/cache/`. Use `MEMORY.md` (top-level) for memory you want to keep, not a `memory/` directory\n")
	b.WriteString("- Non-`.md` files directly under `workspace/`\n")
	b.WriteString("- Anything outside `~/.openclaw/` (`/tmp`, `/var`, the rest of the filesystem)\n")
	b.WriteString("- Process memory, environment variables, transient state of any running command\n\n")
	b.WriteString("**When telling the owner where to put something:**\n\n")
	b.WriteString("- \"Remember this for me long-term\" → write to `MEMORY.md` or create a new top-level `.md` in `workspace/`\n")
	b.WriteString("- \"Install a skill / capability\" → drop it as a subdirectory under `workspace/skills/<name>/`\n")
	b.WriteString("- \"Save this artifact (sketch, doc, canvas)\" → place under `workspace/canvas/`\n")
	b.WriteString("- \"Just for this conversation\" → anywhere off the tracked paths; it's ephemeral by default\n\n")
	b.WriteString("**Cost:** each chain update consumes gas paid by agentSeal. If agentSeal's balance is too low, drift is detected but the convergence transaction fails — the file stays on disk but hasn't reached chain yet, so it would NOT survive a transfer. If the owner is asking about durability and you can see the warning state (`status: warning`) referencing low balance, tell them to top up before relying on the data being persisted.\n")
	return b.String()
}

// frameworkConstraintsText tells the agent about openclaw-specific
// runtime constraints: the version whitelist (rendered live from
// supportedOpenclawVersions) and the openclaw.json config-hash
// allowlist. Injected right after the platform constraints section.
func frameworkConstraintsText() string {
	var b strings.Builder
	if len(supportedOpenclawVersions) > 0 {
		versions := make([]string, len(supportedOpenclawVersions))
		for i, v := range supportedOpenclawVersions {
			versions[i] = "`" + v + "`"
		}
		b.WriteString("**Framework version whitelist.** sealed validates against a closed set of releases: ")
		b.WriteString(strings.Join(versions, ", "))
		if max := whitelistMax(); max != "" {
			b.WriteString(" (max = `" + max + "`).")
		}
		b.WriteString(" If you or the owner upgrade to a non-whitelisted version, sealed's watcher detects the drift within 30s and reconciles back to the whitelist max via `npm install openclaw@<max>`. **Do not suggest framework upgrades that cross the whitelist boundary.** If the owner asks about upgrading, tell them the constraint and that adding a version requires a sealed image rebuild.\n\n")
	}
	b.WriteString("**Config allowlist.** When sealed computes the `openclaw.json` content hash for drift detection, it only considers these top-level keys: `agents`, `auth`, `models`. Keys outside this set (e.g. `logging`, `wizard`) are invisible to the watcher and won't trigger chain drift. This means owner-side config experiments in those sections are container-local and won't persist on chain.\n\n")
	return b.String()
}
