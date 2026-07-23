package hermes

// Filesystem paths the hermes adapter manages.
//
// Hermes Agent keeps all mutable state under <home> (~/.hermes): config.yaml
// (settings), SOUL.md (identity), memories/*.md (distilled long-term memory),
// skills/ (agentskills.io SKILL.md folders — both bundled-at-install and
// agent-created). Sealed owns these paths during Restore (writing iData
// content to disk) and EvolutionFor (reading back to detect agent
// self-modification).
//
// Deliberately NOT managed (never on chain):
//   - .env, auth.json           secrets
//   - state.db / *.db           conversation history + runtime task state
//   - sessions/, logs/, bin/,   ephemeral / cache / process bookkeeping
//     image_cache/, gateway.*
//   - cron/                     scheduled behaviour is owner-scoped, not
//                               identity-scoped: migrating it across a
//                               transfer would keep the OLD owner's timed
//                               jobs running in the NEW owner's container —
//                               a standing-backdoor vector. Deliberate
//                               decision (2026-07), not an omission.
//
// `hermesHome` is a var (not const) so unit tests can redirect into
// t.TempDir(). Production code never reassigns it.

var hermesHome = "/root/.hermes"

// hermesInstallDir is the git checkout the installer creates; version
// pinning = `git checkout <tag>` + `uv sync --locked` inside it. Var for
// the same test-redirection reason.
var hermesInstallDir = "/usr/local/lib/hermes-agent"

func configYAMLPath() string      { return hermesHome + "/config.yaml" }
func soulMDPath() string          { return hermesHome + "/SOUL.md" }
func memoriesDir() string         { return hermesHome + "/memories" }
func skillsDir() string           { return hermesHome + "/skills" }
func bundledManifestPath() string { return skillsDir() + "/.bundled_manifest" }
