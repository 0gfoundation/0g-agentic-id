package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/privsep"
)

// ClearSession implements framework.SessionClearer (CONVERSATION.md §3): wipe
// the persisted event log so the next harness boot creates a fresh session
// (loadSeed finds nothing). The caller restarts the framework process after
// this returns. Every `<log>.*` sibling goes too: the archived
// (.ceiling-*/.corrupt-*) leftovers and the harness's turn records
// (<log>.records.jsonl — the inbox and task list start empty as well).
//
// $DSH_HOME is handed to the agent user, so the leftovers are found by
// listing it (privsep.ReadDir, no link followed), and whatever sits at each
// name is removed with privsep.RemoveAll, which removes a link or a file
// itself rather than follow it, and a directory with its contents: an entry
// the agent put at the conversation's name cannot make the clear fail.
func (a *Adapter) ClearSession(_ context.Context) error {
	if err := privsep.RemoveAll(conversationPath()); err != nil {
		return fmt.Errorf("harness.ClearSession: %w", err)
	}
	dir := filepath.Dir(conversationPath())
	prefix := filepath.Base(conversationPath()) + "."
	ents, err := privsep.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), prefix) {
			_ = privsep.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
	return nil
}

// compactBridgeURL is the harness's compaction route (POST /v1/compact,
// 0g-harness src/http.mjs). A var so tests can point it at a stub.
var compactBridgeURL = fmt.Sprintf("http://127.0.0.1:%d/v1/compact", bridgePort)

// compactHTTPTimeout bounds the call to the harness. It is longer than the
// harness's own bound on a running compaction (COMPACT_TIMEOUT_MS, 10m) so that
// the harness — which knows why — is the side that gives up; the request may
// also queue behind a running turn first. sealed's route deadline
// (proxy.compactTimeout) caps the whole call regardless.
const compactHTTPTimeout = 14 * time.Minute

// CompactSession implements framework.SessionCompactor: the harness runs the
// composition's compaction engine on the live session. No restart — the
// conversation continues from the compacted history, and the harness's session
// store persists the compaction like any other committed event, so it
// survives a later restart (CONVERSATION.md).
func (a *Adapter) CompactSession(ctx context.Context) (string, error) {
	a.mu.RLock()
	token := a.bridgeToken
	a.mu.RUnlock()
	if token == "" {
		return "", fmt.Errorf("harness.CompactSession: harness not started yet")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, compactBridgeURL, strings.NewReader("{}"))
	if err != nil {
		return "", fmt.Errorf("harness.CompactSession: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: compactHTTPTimeout}).Do(req)
	if err != nil {
		// Giving up waiting does not stop the harness: a compaction that was
		// queued behind a long turn, or is mid-summary, still completes.
		if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
			return "", fmt.Errorf("harness.CompactSession: no answer from the harness in time (%w); the compaction may still finish — the agent log shows the outcome", err)
		}
		return "", fmt.Errorf("harness.CompactSession: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var out struct {
		Note  string `json:"note"`
		Error *struct {
			Message string `json:"message"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK {
		detail := strings.TrimSpace(string(raw))
		if out.Error != nil && out.Error.Message != "" {
			detail = out.Error.Message
			if out.Error.Code != "" {
				detail = out.Error.Code + ": " + detail
			}
		}
		// 409 is the harness's "not now" (a compaction already pending, or the
		// session changed under it): nothing was compacted, a retry may work.
		if resp.StatusCode == http.StatusConflict {
			return "", fmt.Errorf("harness.CompactSession: %w: %s", framework.ErrCompactRefused, detail)
		}
		return "", fmt.Errorf("harness.CompactSession: harness answered %d: %s", resp.StatusCode, detail)
	}
	if out.Note == "" {
		return "compaction finished", nil
	}
	return out.Note, nil
}
