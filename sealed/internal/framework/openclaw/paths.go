package openclaw

// Filesystem paths the openclaw adapter manages.
//
// openclaw reads its config from <home>/openclaw.json and absorbs markdown
// files from <home>/workspace/ into agent context. Sealed owns these
// paths during Restore (writing iData content to disk) and EvolutionFor
// (reading back to detect agent self-modification).
//
// `openclawHome` is a var (not const) so unit tests can redirect into
// `t.TempDir()` instead of polluting `/root/.openclaw`. Production code
// never reassigns it.

var openclawHome = "/root/.openclaw"

func openclawJSONPath() string { return openclawHome + "/openclaw.json" }
func workspaceDir() string     { return openclawHome + "/workspace" }

// Workspace markdown files sealed reads / writes:
//
//	SOUL.md    persona dim — system prompt
//	MEMORY.md  knowledge dim — consolidated long-term memory
//	DREAMS.md  knowledge dim — reflection logs
//	USER.md    knowledge dim — user model
//	AGENTS.md  knowledge dim — agent self-guide
//	TOOLS.md   knowledge dim (owner part) + sealed-managed platform section
//
// We write each file at Restore time (even when empty) to pre-empt
// openclaw's `writeFileIfMissing` template fallback — otherwise openclaw
// auto-installs its 7966-byte AGENTS.md template / 650-byte USER.md
// template on first chat, polluting the knowledge dim with identical
// stock content for every agent.
func soulMDPath() string   { return workspaceDir() + "/SOUL.md" }
func memoryMDPath() string { return workspaceDir() + "/MEMORY.md" }
func dreamsMDPath() string { return workspaceDir() + "/DREAMS.md" }
func userMDPath() string   { return workspaceDir() + "/USER.md" }
func agentsMDPath() string { return workspaceDir() + "/AGENTS.md" }
func toolsMDPath() string  { return workspaceDir() + "/TOOLS.md" }
