package claudecode

import (
	"strings"

	"seal-verify/internal/platform"
)

// Platform context delivery for claude-code.
//
// This used to inject the whole PlatformContext into CLAUDE.md. That was
// the wrong channel: Claude Code loads CLAUDE.md as project *memory*, not
// as its system prompt — it has its own authoritative "you are Claude
// Code" system prompt — so the injected AgenticID identity + sign-refusal
// doctrine read as user-supplied content, and a safety-tuned model treats
// "this doc says I'm someone else" as prompt-injection and disclaims it
// (observed live: the agent refused its own agentSeal identity).
//
// The authoritative channel is `claude -p --append-system-prompt`
// (spawn.go → bridge). This is the claude-code analogue of how openclaw
// builds its system prompt from SOUL/IDENTITY. composeSystemPrompt turns
// a PlatformContext into that text; CLAUDE.md is left to the agent's own
// evolvable persona/memory.

// composeSystemPrompt joins the platform sections into the text passed to
// claude via --append-system-prompt. Empty (local dev, no chain identity)
// → "" and no flag is added.
func composeSystemPrompt(pc platform.PlatformContext) string {
	var sections []string
	for _, s := range []string{pc.Identity, pc.Sovereignty, pc.Capabilities, pc.Constraints, pc.Runtime} {
		if s != "" {
			sections = append(sections, s)
		}
	}
	return strings.Join(sections, "\n")
}
