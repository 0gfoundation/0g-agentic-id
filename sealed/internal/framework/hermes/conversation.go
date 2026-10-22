package hermes

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"sync"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/privsep"
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
// The id file lives in framework.StateDir, sealed's own root-only state
// directory, not in the agent-writable hermes home: container-lifetime,
// never chain-tracked, never conveyed. Note the durability split
// (CONVERSATION.md §4): the id is OURS, the transcript is hermes's own
// state.db — invariant 7's self-rotation does not apply to a store the
// harness owns and compacts itself.

const sessionIDHeader = "X-Hermes-Session-Id"

// conversationIDState names the id file in framework.StateDir.
const conversationIDState = "hermes-conversation-id"

func conversationIDPath() string { return framework.StatePath(conversationIDState) }

var convMu sync.Mutex

// currentConversationID reads the persisted id, minting one on first use.
// Never fails a turn: an unreadable/unwritable file degrades to a fresh id
// (a new conversation), never to an error.
func currentConversationID() string {
	convMu.Lock()
	defer convMu.Unlock()
	if b, err := framework.ReadState(conversationIDState); err == nil {
		if id := sanitizeSessionID(string(b)); id != "" {
			return id
		}
	}
	id, migrated, busy := legacyConversationID()
	if busy {
		// The earlier id is there but cannot be read for now (its owner
		// holds a lease on it): this turn gets a fresh id that is not
		// persisted, so a later turn still takes the earlier one over
		// instead of forking the conversation for good.
		logger.Once("hermes.legacy-id-busy", "hermes conversation: %s cannot be read for now (leased); turns get a fresh, unpersisted session id until it can", legacyConversationIDPath())
		return mintConversationID()
	}
	if !migrated {
		id = mintConversationID()
	}
	if err := framework.WriteState(conversationIDState, []byte(id)); err != nil {
		// Still never fail the turn — but an unwritable id file means EVERY
		// turn mints a fresh id (a new hermes conversation each time,
		// invariant 1 silently broken). Say so.
		logger.Logf("hermes conversation: cannot persist the session id (%v) — each turn will start a NEW conversation until this is fixed", err)
		return id
	}
	if migrated {
		// Only once the id is sealed's own: until then the next turn still
		// finds it at the old name.
		if err := privsep.Remove(legacyConversationIDPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
			logger.Logf("hermes conversation: could not remove %s after moving the session id: %v", legacyConversationIDPath(), err)
		}
		logger.Logf("hermes conversation: kept the session id an earlier sealed pinned at %s", legacyConversationIDPath())
	}
	return id
}

// legacyConversationIDPath is where an earlier sealed kept the id: inside
// the tree handed to the agent.
func legacyConversationIDPath() string { return hermesHome + "/.seal-conversation-id" }

// legacyConversationID returns the id an earlier sealed kept, so a container
// upgraded in place keeps its conversation. The file is in the agent's
// tree, so it is read through privsep with a small bound and passed through
// the same check as an id hermes echoes (sanitizeSessionID): after a
// compaction the id is hermes's child id, not one this platform minted.
// The agent, which owns hermes's whole store, gains nothing it could not
// already do there. busy reports a file that is there but cannot be read
// for now (privsep.ErrBusy: its owner holds a lease), which must not be
// taken for an absent one.
func legacyConversationID() (id string, ok, busy bool) {
	b, err := privsep.ReadFile(legacyConversationIDPath(), 256)
	if errors.Is(err, privsep.ErrBusy) {
		return "", false, true
	}
	if err != nil {
		return "", false, false
	}
	id = sanitizeSessionID(string(b))
	return id, id != "", false
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
	if b, err := framework.ReadState(conversationIDState); err == nil {
		cur = strings.TrimSpace(string(b))
	}
	if cur != sentID {
		logger.Logf("hermes conversation: dropping a stale rotation echo (%s→%s) — the id moved to %s meanwhile (clear or newer turn)", sentID, echoed, cur)
		return
	}
	if err := framework.WriteState(conversationIDState, []byte(echoed)); err != nil {
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
	if err := framework.WriteState(conversationIDState, []byte(mintConversationID())); err != nil {
		return fmt.Errorf("hermes.ClearSession: %w", err)
	}
	// An id an earlier sealed kept is superseded too.
	_ = privsep.Remove(legacyConversationIDPath())
	return nil
}
