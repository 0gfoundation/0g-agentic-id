package prime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// ClearSession implements framework.SessionClearer (CONVERSATION.md §3): wipe
// the persisted conversation so the next bridge start opens a fresh one. The
// caller restarts the framework process after this returns, so the in-memory
// session dies with it — deleting the file alone would leave the live session
// talking as if nothing happened until the next incidental restart.
//
// Quarantined (.corrupt-*) and mid-rotation (.rotating) leftovers go too: a
// cleared conversation should leave no recoverable residue on disk.
func (a *Adapter) ClearSession(_ context.Context) error {
	if err := os.Remove(conversationPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("prime.ClearSession: %w", err)
	}
	leftovers, _ := filepath.Glob(conversationPath() + ".*")
	for _, f := range leftovers {
		_ = os.Remove(f)
	}
	return nil
}
