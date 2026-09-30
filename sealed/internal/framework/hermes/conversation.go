package hermes

import (
	"seal-verify/internal/logger"

	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
)

// The agent's ONE conversation lives in hermes's own store (~/.hermes/state.db
// — its docs call that file "conversation history + runtime task state"), and
// the gateway serves it statefully when a request carries X-Hermes-Session-Id
// (history then loads from the db, the request body's last message is the
// turn). This file supplies the missing half: a persistent session identity,
// minted once, attached to every stateful upstream call, and FOLLOWED when
// hermes rotates it — compaction ends the session and continues on a child id,
// so a pinned id would silently fork the conversation at every compaction.
//
// The id file is an untracked dotfile in the hermes home (like state.db
// itself): container-lifetime, never chain-tracked, never conveyed. Note the
// durability split (CONVERSATION.md §4): the id is OURS, the transcript is
// hermes's own state.db — invariant 7's self-rotation does not apply to a
// store the harness owns and compacts itself.

const sessionIDHeader = "X-Hermes-Session-Id"

func conversationIDPath() string { return hermesHome + "/.seal-conversation-id" }

var convMu sync.Mutex

// currentConversationID reads the persisted id, minting one on first use.
// Never fails a turn: an unreadable/unwritable file degrades to a fresh id
// (a new conversation), never to an error.
func currentConversationID() string {
	convMu.Lock()
	defer convMu.Unlock()
	if b, err := os.ReadFile(conversationIDPath()); err == nil {
		if id := sanitizeSessionID(string(b)); id != "" {
			return id
		}
	}
	id := mintConversationID()
	if err := os.WriteFile(conversationIDPath(), []byte(id), 0o600); err != nil {
		// Still never fail the turn — but an unwritable id file means EVERY
		// turn mints a fresh id (a new hermes conversation each time,
		// invariant 1 silently broken). Say so.
		logger.Logf("hermes conversation: cannot persist the session id (%v) — each turn will start a NEW conversation until this is fixed", err)
	}
	return id
}

func mintConversationID() string {
	var buf [12]byte
	_, _ = rand.Read(buf[:])
	return "seal-owner-chat-" + hex.EncodeToString(buf[:])
}

// sanitizeSessionID mirrors the gateway's own guard (control chars, path
// shapes, length) so we never persist an id hermes would reject.
func sanitizeSessionID(s string) string {
	id := strings.TrimSpace(s)
	if id == "" || len(id) > 128 || strings.ContainsAny(id, "\r\n\x00/\\") || strings.Contains(id, "..") {
		return ""
	}
	return id
}

// ConversationHeaders implements framework.ConversationSession.
func (a *Adapter) ConversationHeaders() map[string]string {
	return map[string]string{sessionIDHeader: currentConversationID()}
}

// ObserveConversation implements framework.ConversationSession: hermes echoes
// the EFFECTIVE session id on every response, and compaction rotates it to a
// child session — persist the echo so the next turn continues the child
// instead of forking the parent.
func (a *Adapter) ObserveConversation(sent map[string]string, resp http.Header) {
	echoed := sanitizeSessionID(resp.Get(sessionIDHeader))
	sentID := sanitizeSessionID(sent[sessionIDHeader])
	if echoed == "" || echoed == sentID {
		return // no echo, or no rotation — nothing to advance
	}
	// Compare-and-swap on the generation THIS turn was pinned to: only
	// advance the file if it still holds sentID. If a concurrent /clear (or a
	// later turn's rotation) has already moved it off sentID, this echo is a
	// stale generation and MUST NOT clobber the current one — that is what
	// resurrected a just-cleared conversation before (audit #169 F1/F2).
	convMu.Lock()
	defer convMu.Unlock()
	cur := ""
	if b, err := os.ReadFile(conversationIDPath()); err == nil {
		cur = strings.TrimSpace(string(b))
	}
	if cur != sentID {
		logger.Logf("hermes conversation: dropping a stale rotation echo (%s→%s) — the id moved to %s meanwhile (clear or newer turn)", sentID, echoed, cur)
		return
	}
	if err := os.WriteFile(conversationIDPath(), []byte(echoed), 0o600); err != nil {
		logger.Logf("hermes conversation: cannot persist the rotated session id (%v) — the next boot will resume the pre-compaction parent", err)
	}
}

// ClearSession implements framework.SessionClearer: minting a fresh id IS the
// clear — the next turn starts an empty conversation. The old transcript rows
// stay in hermes's own state.db (its store, its lifecycle) but are no longer
// referenced by anything the platform sends.
func (a *Adapter) ClearSession(_ context.Context) error {
	convMu.Lock()
	defer convMu.Unlock()
	if err := os.WriteFile(conversationIDPath(), []byte(mintConversationID()), 0o600); err != nil {
		return fmt.Errorf("hermes.ClearSession: %w", err)
	}
	return nil
}
