package platform

import (
	"strings"
)

// The agent doc — the "bible" — is ONE shared template. platform owns every
// sentence of platform mechanics (how sealing works, gas, version reconcile,
// config drift, secret stripping) and renders them identically for every
// framework. An adapter fills only the blanks that differ BY framework: its
// home dir, its paths, its versions, its config file + keys. An adapter never
// restates a platform mechanism, so it cannot restate one wrong — and cannot
// silently omit one, because the prose isn't its to write.
//
// FrameworkFacts is that fill-in-the-blanks form (returned by
// Framework.FrameworkFacts()). RenderFrameworkFacts stamps it into the
// template; AssembleAgentDoc splices the result onto the platform-authored
// halves from Build().

// PathNote is one path entry with a framework-specific one-line note. Path
// may be empty for entries described by category rather than a literal path
// (e.g. openclaw's "Non-.md files directly under workspace/").
type PathNote struct {
	Path string
	Note string
}

// DurableHint maps an owner request ("remember this long-term") to where the
// agent should put it ("`memories/MEMORY.md`") for that framework.
type DurableHint struct {
	Ask   string
	Place string
}

// FrameworkFacts is the framework-authored half of the agent doc, expressed
// as VALUES not prose (§9 part 2). Every field is a blank in the shared
// template; the platform mechanics around them are rendered identically for
// all frameworks by RenderFrameworkFacts.
type FrameworkFacts struct {
	// Home is the framework's on-disk root, e.g. "~/.hermes/". Rendered into
	// the sealing sentence and the universal "anything outside <Home>" line.
	Home string

	// Tracked are the chain-persistent paths (survive restart/Reset/Restore/
	// transfer), each with a framework note. Required — an empty Tracked ships
	// an agent that doesn't know where its durable state lives.
	Tracked []PathNote

	// Untracked are the framework-specific container-local paths. The template
	// appends the two universal lines (anything outside Home; process memory /
	// env / transient state), so adapters list only what's peculiar to them.
	Untracked []PathNote

	// DurableHints answer "owner asks X → put it at Y". The template appends
	// the universal "just for this conversation → ephemeral" line.
	DurableHints []DurableHint

	// VersionScheme names the release series, e.g. "releases" or
	// "hermes release tags (CalVer)". Empty defaults to "releases".
	VersionScheme string
	// Versions is the whitelist; each is rendered in backticks. Empty omits
	// the whole version-whitelist paragraph (a framework with no pinning).
	Versions []string
	// VersionMax is the whitelist ceiling; empty omits the "(max = …)" clause.
	VersionMax string
	// ReconcileHow is the command sealed runs to pull a drifted version back,
	// e.g. "`npm install openclaw@<max>`" or "`git checkout <max>` + `uv sync --locked`".
	ReconcileHow string

	// ConfigFile is the drift-tracked config filename, e.g. "openclaw.json".
	// Empty omits the config-allowlist paragraph.
	ConfigFile string
	// ConfigKeys are the allowlisted top-level keys considered for drift.
	ConfigKeys []string
	// ConfigSecret, if set (e.g. "api_key"), adds the clause that this key is
	// stripped before the config reaches chain.
	ConfigSecret string
	// ConfigIgnoredExample, if set, renders an "(e.g. `logging`, `wizard`)"
	// aside illustrating keys that fall outside the allowlist.
	ConfigIgnoredExample []string
}

// RenderFrameworkFacts stamps a framework's blanks into the shared template
// and returns the framework half of the agent doc as markdown. Multi-file
// frameworks (openclaw) call this directly to splice into their own context
// file; AssembleAgentDoc calls it for single-file frameworks.
func RenderFrameworkFacts(f FrameworkFacts) string {
	var b strings.Builder

	// ── Persistent state ──────────────────────────────────────────────────
	b.WriteString("### Persistent state\n\n")
	b.WriteString("A subset of your on-disk paths under `" + f.Home + "` is **continuously sealed to chain**: changes are detected within ~30s, encrypted inside this TEE, uploaded to 0G Storage, and anchored on the AgenticID contract via a transaction signed by agentSeal. Everything else is container-local and disappears on the next container rebuild.\n\n")

	b.WriteString("**Tracked paths** (chain-persistent; survive container restart, Reset, Restore, and owner transfer):\n\n")
	for _, p := range f.Tracked {
		b.WriteString(renderPathNote(p))
	}
	b.WriteString("\n")

	b.WriteString("**Not tracked** (container-local; lost on rebuild):\n\n")
	for _, p := range f.Untracked {
		b.WriteString(renderPathNote(p))
	}
	// Universal not-tracked lines, same for every framework.
	b.WriteString("- Anything outside `" + f.Home + "` (`/tmp`, `/var`, the rest of the filesystem)\n")
	b.WriteString("- Process memory, environment variables, transient state of any running command\n\n")

	b.WriteString("**When telling the owner where to put something:**\n\n")
	for _, h := range f.DurableHints {
		b.WriteString("- \"" + h.Ask + "\" → " + h.Place + "\n")
	}
	b.WriteString("- \"Just for this conversation\" → anywhere off the tracked paths; it's ephemeral by default\n\n")

	b.WriteString("**Cost:** each chain update consumes gas paid by agentSeal. If agentSeal's balance is too low, drift is detected but the convergence transaction fails — the file stays on disk but hasn't reached chain yet, so it would NOT survive a transfer. If the owner is asking about durability and you can see the warning state (`status: warning`) referencing low balance, tell them to top up before relying on the data being persisted.\n")

	// ── Framework constraints ─────────────────────────────────────────────
	if len(f.Versions) > 0 {
		scheme := f.VersionScheme
		if scheme == "" {
			scheme = "releases"
		}
		quoted := make([]string, len(f.Versions))
		for i, v := range f.Versions {
			quoted[i] = "`" + v + "`"
		}
		b.WriteString("\n**Framework version whitelist.** sealed validates against a closed set of " + scheme + ": ")
		b.WriteString(strings.Join(quoted, ", "))
		if f.VersionMax != "" {
			b.WriteString(" (max = `" + f.VersionMax + "`)")
		}
		b.WriteString(". If a non-whitelisted version is installed, sealed's watcher detects the drift within ~30s and reconciles back to the whitelist max via " + f.ReconcileHow + ". **Do not suggest framework upgrades that cross the whitelist boundary.** If the owner asks about upgrading, tell them the constraint and that adding a version requires a sealed image rebuild.\n")
	}

	if f.ConfigFile != "" {
		quoted := make([]string, len(f.ConfigKeys))
		for i, k := range f.ConfigKeys {
			quoted[i] = "`" + k + "`"
		}
		b.WriteString("\n**Config allowlist.** When sealed computes the `" + f.ConfigFile + "` content hash for drift detection, it considers only these top-level keys: ")
		b.WriteString(strings.Join(quoted, ", "))
		if f.ConfigSecret != "" {
			b.WriteString("; and any `" + f.ConfigSecret + "` among them is stripped before the config reaches chain (secrets never leave this container)")
		}
		b.WriteString(". Keys outside this set")
		if len(f.ConfigIgnoredExample) > 0 {
			eg := make([]string, len(f.ConfigIgnoredExample))
			for i, k := range f.ConfigIgnoredExample {
				eg[i] = "`" + k + "`"
			}
			b.WriteString(" (e.g. " + strings.Join(eg, ", ") + ")")
		}
		b.WriteString(" are invisible to the watcher and won't trigger chain drift. This means owner-side config experiments in those sections are container-local and won't persist on chain.\n")
	}

	return strings.TrimRight(b.String(), "\n")
}

// renderPathNote formats one entry as "- `path` — note" (or "- note" when the
// entry has no literal path).
func renderPathNote(p PathNote) string {
	if p.Path == "" {
		return "- " + p.Note + "\n"
	}
	if p.Note == "" {
		return "- `" + p.Path + "`\n"
	}
	return "- `" + p.Path + "` — " + p.Note + "\n"
}

// AssembleAgentDoc splices the platform-authored context (pc) with the
// rendered framework facts into the single markdown agent doc — the complete
// truth the agent is told about its runtime, in one place.
//
// Ordering: identity → sovereignty (doctrine) → capabilities → framework
// facts (paths/versions/config) → platform constraints → runtime. Framework
// facts sit right after capabilities so "here's how to expose a service"
// flows straight into "here's where your state actually lives".
//
// Single-context-file frameworks (hermes) inject the whole return value into
// one file. Multi-file frameworks (openclaw) distribute pc's fields across
// their files and call RenderFrameworkFacts themselves; either way the facts
// come from FrameworkFacts() through the same template, so nothing diverges.
func AssembleAgentDoc(pc PlatformContext, facts FrameworkFacts) string {
	sections := []string{
		pc.Identity,
		pc.Sovereignty,
		pc.Capabilities,
		RenderFrameworkFacts(facts),
		pc.Constraints,
		pc.Runtime,
	}
	var b strings.Builder
	for _, s := range sections {
		if strings.TrimSpace(s) == "" {
			continue
		}
		b.WriteString(strings.TrimRight(s, "\n"))
		b.WriteString("\n\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
