package prime

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"seal-verify/internal/privsep"
)

// ClearSession implements framework.SessionClearer (CONVERSATION.md §3): wipe
// the persisted conversation so the next bridge start opens a fresh one. The
// caller restarts the framework process after this returns, so the in-memory
// session dies with it — deleting the file alone would leave the live session
// talking as if nothing happened until the next incidental restart.
//
// The whole session directory goes — the conversation file and its
// quarantined (.corrupt-*) and mid-rotation (.rotating) leftovers — and so do
// the SDK's per-session artifacts (conversationDir/session-artifacts) and any
// copy an earlier sealed kept directly in conversationDir (which
// migrateConversation would otherwise move back in): a cleared conversation
// should leave no recoverable residue on disk. The restart's Start recreates
// the session directory (prepareSessionDirs).
//
// The conversation directory is handed to the agent user, so whatever sits
// at these names is removed with privsep.RemoveAll, which removes a link or
// a file there itself rather than follow it: an entry the agent put where
// the session directory belongs cannot make the clear fail.
func (a *Adapter) ClearSession(_ context.Context) error {
	if err := privsep.RemoveAll(conversationSessionDir()); err != nil {
		return fmt.Errorf("prime.ClearSession: %w", err)
	}
	if ents, err := privsep.ReadDir(conversationDir()); err == nil {
		for _, e := range ents {
			if name := e.Name(); name == conversationFile || strings.HasPrefix(name, conversationFile+".") {
				_ = privsep.RemoveAll(filepath.Join(conversationDir(), name))
			}
		}
	}
	if err := privsep.RemoveAll(sessionArtifactsDir()); err != nil {
		return fmt.Errorf("prime.ClearSession: %w", err)
	}
	return nil
}

// sessionArtifactsDir is where the SDK keeps per-session artifacts: next to
// the session directory (see conversationPath).
func sessionArtifactsDir() string { return conversationDir() + "/session-artifacts" }

// legacySessionArtifactsDir is where the SDK kept them while the
// conversation file sat directly in conversationDir (an earlier sealed):
// next to that directory, in root's home, which that sealed let the agent
// own. Each session's artifact directory (<id>/) holds its RLM session
// state and its local Continual Harness state (mid-task memories, prompt
// notes, skills not yet promoted), which a resumed conversation needs:
// ReclaimHome relocates it here into sessionArtifactsDir at boot
// (privsep.DeclareRelocation, in New), before migrateConversation moves the
// conversation file next to it.
func legacySessionArtifactsDir() string {
	return filepath.Join(filepath.Dir(conversationDir()), "session-artifacts")
}
