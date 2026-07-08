package claudecode

// Filesystem paths the claudecode adapter manages.
//
// Claude Code keeps user-level state under <home>/.claude/: settings.json
// (model + permissions + runtime bookkeeping), agents/ (subagent
// definitions, one .md each), skills/ (one directory per skill). Project
// context lives in the working directory Claude Code runs in — sealed
// pins that to a fixed workspace dir so CLAUDE.md and friends are
// chain-trackable at stable paths.
//
// `claudeHome` is a var (not const) so unit tests can redirect into
// t.TempDir() instead of polluting /root/.claude. Production code never
// reassigns it.

var claudeHome = "/root/.claude"

func settingsJSONPath() string { return claudeHome + "/settings.json" }
func agentsDir() string        { return claudeHome + "/agents" }
func skillsDir() string        { return claudeHome + "/skills" }

// workspaceDir is the fixed working directory the bridge runs `claude` in.
// Root-level *.md files here (CLAUDE.md, anything the agent adds) are the
// workspace/ role. Kept under claudeHome so one var redirects everything
// in tests.
func workspaceDir() string { return claudeHome + "/workspace" }

func claudeMDPath() string { return workspaceDir() + "/CLAUDE.md" }

// bridgeScriptPath is where spawn.go materializes the embedded HTTP
// bridge (bridge/server.js, go:embed — see spawn.go) before each spawn.
// Var so tests can redirect it. Claude Code itself is a CLI, not a
// server — the bridge is the long-running upstream process sealed's
// proxy forwards to; it execs `claude -p` per request with session
// continuity.
var bridgeScriptPath = "/opt/claude-bridge/server.js"

// subprocessLogPath is where spawn.go pipes the bridge's (and therefore
// claude's) stdout/stderr; served by proxy on /log/agent.
const subprocessLogPath = "/tmp/claudecode.log"
