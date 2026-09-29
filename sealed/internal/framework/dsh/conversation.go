package dsh

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// ClearSession implements framework.SessionClearer (CONVERSATION.md §3): wipe
// the persisted event log so the next bridge boot creates a fresh session
// (loadSeed finds nothing). The caller restarts the framework process after
// this returns. Archived (.ceiling-*/.corrupt-*) leftovers go too.
func (a *Adapter) ClearSession(_ context.Context) error {
	if err := os.Remove(conversationPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("dsh.ClearSession: %w", err)
	}
	leftovers, _ := filepath.Glob(conversationPath() + ".*")
	for _, f := range leftovers {
		_ = os.Remove(f)
	}
	return nil
}
