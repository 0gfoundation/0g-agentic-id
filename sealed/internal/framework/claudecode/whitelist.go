package claudecode

// supportedClaudeCodeVersions is the closed set of
// @anthropic-ai/claude-code npm releases sealed has been validated
// against. Bump as part of the sealed image release flow — adding a
// version here without rebuilding the claudecode image leaves us
// claiming compat we haven't tested.
//
// Stored as a slice (not a map) so the order encodes "preferred order":
// the LAST entry is whitelistMax, the version sealed reconciles to on
// any framework dim drift.
var supportedClaudeCodeVersions = []string{
	"2.1.180",
	"2.1.198",
}

// whitelistMax returns the version sealed targets when reconciling
// framework dim drift. Always the last element of the supported list.
func whitelistMax() string {
	if len(supportedClaudeCodeVersions) == 0 {
		return ""
	}
	return supportedClaudeCodeVersions[len(supportedClaudeCodeVersions)-1]
}
