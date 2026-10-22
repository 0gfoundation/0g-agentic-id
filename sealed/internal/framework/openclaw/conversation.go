package openclaw

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/privsep"
)

// openclaw keeps the agent's conversation itself. Every gateway turn is
// persisted to a per-session JSONL transcript
// (~/.openclaw/agents/main/sessions/<sessionId>.jsonl; sessions.json maps the
// session key to it), and the gateway REPLAYS that session into every turn on
// its OpenAI-compatible door — compaction-aware: the latest summary, then what
// it kept verbatim. This file is openclaw's conversation encapsulation
// (CONVERSATION.md §4): pin ONE session key so every stateful-door turn lands
// in ONE session, and have the door send ONLY the current turn, because the
// gateway brings the rest. It stays ONE session only because the render sets
// session.reset (inference.go): openclaw's default starts a new one daily.
//
// Verified 2026-10-19 against 2026.7.1 (offline, stub model): a turn sent
// alone reached the model with the earlier turns in front of it; a turn sent
// WITH the client's history reached it with that history twice — the
// gateway's replay, plus the client's copy folded into the new message as
// "[Chat messages since your last reply - for context] …".
//
// Until then this package also read the transcript back and sent it as
// history (#169), on the belief that the door ignores its own store. That
// read never matched anything on 2026.7.1 — sessions.json keys a session
// "agent:main:<key>", not "<key>" — and it is gone: had it matched, the model
// would have seen every earlier turn twice, and a compaction would have been
// undone by the full pre-compaction text riding along.
//
// Compaction appends a `compaction` record and keeps every message line
// (`truncateAfterCompaction`, which would rotate the file, is opt-in and off),
// so invariant 7 is not met by the harness here. A MANUAL compaction keeps
// its recent tail only while agents.defaults.compaction.keepRecentTokens is
// set, which the render does (inference.go): unset, openclaw rewrites the
// record to replay from the summary alone, and the tail is lost.
//
// The private-format coupling (sessions.json shape, file naming) is
// quarantined here, in openclaw's own package — the same kind of coupling this
// adapter already has (it parses openclaw.json). An openclaw upgrade that
// changes them is THIS file's maintenance burden.

const sessionKeyHeader = "x-openclaw-session-key"

// The ONE conversation, as the proxy sees it: these three switch the door to
// "pin the session, send only the current turn" and route /clear here.
var (
	_ framework.ConversationSession = (*Adapter)(nil)
	_ framework.ConversationHistory = (*Adapter)(nil)
	_ framework.SessionClearer      = (*Adapter)(nil)
)

// openclawAgentID is the default agent id openclaw stores sessions under.
const openclawAgentID = "main"

// conversationKeyState names the platform's pinned session key in
// framework.StateDir: sealed's own bookkeeping, kept out of the
// agent-writable home.
const conversationKeyState = "openclaw-conversation-key"

func conversationKeyPath() string { return framework.StatePath(conversationKeyState) }
func sessionsDir() string {
	return filepath.Join(openclawHome, "agents", openclawAgentID, "sessions")
}
func sessionsStorePath() string { return filepath.Join(sessionsDir(), "sessions.json") }

var convMu sync.Mutex

func currentConversationKey() string {
	convMu.Lock()
	defer convMu.Unlock()
	if b, err := framework.ReadState(conversationKeyState); err == nil {
		if k := strings.TrimSpace(string(b)); k != "" {
			return k
		}
	}
	k, migrated, busy := legacyConversationKey()
	if busy {
		// The earlier key is there but cannot be read for now (its owner
		// holds a lease on it): this turn gets a fresh key that is not
		// persisted, so a later turn still takes the earlier one over
		// instead of forking the conversation for good.
		logger.Once("openclaw.legacy-key-busy", "openclaw conversation: %s cannot be read for now (leased); turns get a fresh, unpersisted session key until it can", legacyConversationKeyPath())
		return mintConversationKey()
	}
	if !migrated {
		k = mintConversationKey()
	}
	if err := framework.WriteState(conversationKeyState, []byte(k)); err != nil {
		logger.Logf("openclaw conversation: cannot persist the session key (%v)", err)
		return k
	}
	if migrated {
		// Only once the key is sealed's own: until then the next turn
		// still finds it at the old name.
		if err := privsep.Remove(legacyConversationKeyPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
			logger.Logf("openclaw conversation: could not remove %s after moving the session key: %v", legacyConversationKeyPath(), err)
		}
		logger.Logf("openclaw conversation: kept the session key an earlier sealed pinned at %s", legacyConversationKeyPath())
	}
	return k
}

// legacyConversationKeyPath is where an earlier sealed pinned the session
// key: inside the tree handed to the agent.
func legacyConversationKeyPath() string { return openclawHome + "/.seal-conversation-key" }

// legacyConversationKey returns the key an earlier sealed pinned, so a
// container upgraded in place keeps its conversation. The file is in the
// agent's tree, so it is read through privsep with a small bound and used
// only when it has exactly the shape mintConversationKey gives a key (the
// agent, which owns openclaw's whole session store, gains nothing it could
// not already do there). busy reports a file that is there but cannot be
// read for now (privsep.ErrBusy: its owner holds a lease), which must not
// be taken for an absent one.
func legacyConversationKey() (key string, ok, busy bool) {
	b, err := privsep.ReadFile(legacyConversationKeyPath(), 256)
	if errors.Is(err, privsep.ErrBusy) {
		return "", false, true
	}
	if err != nil {
		return "", false, false
	}
	k := strings.TrimSpace(string(b))
	if !isMintedConversationKey(k) {
		logger.Once("openclaw.legacy-key", "openclaw conversation: ignoring %s: not a key this platform minted", legacyConversationKeyPath())
		return "", false, false
	}
	return k, true, false
}

const conversationKeyPrefix = "seal-owner-chat-"

func mintConversationKey() string {
	var buf [12]byte
	_, _ = rand.Read(buf[:])
	return conversationKeyPrefix + hex.EncodeToString(buf[:])
}

// isMintedConversationKey reports whether k has the shape
// mintConversationKey gives a key.
func isMintedConversationKey(k string) bool {
	h, ok := strings.CutPrefix(k, conversationKeyPrefix)
	if !ok || len(h) != 24 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil && strings.ToLower(h) == h
}

// ConversationHeaders implements framework.ConversationSession: pin the one
// session key, so openclaw files every stateful turn under ONE session.
func (a *Adapter) ConversationHeaders() map[string]string {
	return map[string]string{sessionKeyHeader: currentConversationKey()}
}

// ObserveConversation implements framework.ConversationSession. openclaw
// session keys do not rotate — nothing to follow.
func (a *Adapter) ObserveConversation(map[string]string, http.Header) {}

// ConversationHistory implements framework.ConversationHistory with NO prior
// turns, on purpose: the gateway replays the pinned session itself, so the
// door must forward only the current turn — exactly what a history hook with
// nothing to prepend makes it do (proxy synthUpstreamMessages: the client's
// history is dropped, its last user message kept). Without the hook the door
// would forward the client's history, and the model would see it twice.
func (a *Adapter) ConversationHistory(context.Context) ([]framework.ConversationTurn, error) {
	return nil, nil
}

// sessionEntry is the slice of openclaw's sessions.json this package needs:
// the store is a map keyed by session key.
type sessionEntry struct {
	SessionID   string `json:"sessionId"`
	SessionFile string `json:"sessionFile"`
}

// storeKeys are the sessions.json keys a pinned session key may be filed
// under: the gateway's canonical "agent:<agentId>:<key>" (2026.7.1), then the
// bare key.
func storeKeys(key string) []string {
	return []string{"agent:" + openclawAgentID + ":" + key, key}
}

// maxSessionsStore bounds the read of the agent-writable sessions.json — and
// with it the memory decoding it costs PID 1.
const maxSessionsStore = 8 << 20

// afterStoreRead runs between reading sessions.json and removing the files it
// names. A var so a test can swap the directory in that window.
var afterStoreRead = func() {}

// sessionFilesForKey names the files openclaw keeps for one session key, as
// plain names in sessionsDir(): the transcript, and the trajectory record and
// its pointer — the trajectory holds each turn's full prompt and reply, so the
// conversation lives there too (openclaw caps it at 10 MiB per session).
// Empty when the key has no session.
//
// SECURITY (review #169): sessions.json lives under openclawHome, the tree
// privsep hands to the de-privileged framework user — the agent mind can
// rewrite it, and replace any directory in it with a link — while the ROOT
// sealed process deletes what it names. So nothing it says is used as a path:
// only a plain file name directly in sessionsDir() survives. The store is read
// and the files removed through internal/privsep, which follows no link at any
// component, opens only a regular file and never blocks on the open, and
// removes a link at a name itself.
func sessionFilesForKey(key string) ([]string, error) {
	entry, found, err := readSessionEntry(key)
	if err != nil || !found {
		return nil, err
	}
	var stems []string
	if entry.SessionFile != "" {
		if name := sessionFileName(entry.SessionFile); name != "" {
			stems = append(stems, strings.TrimSuffix(name, ".jsonl"))
		} else {
			logger.Logf("openclaw conversation: sessions.json names a transcript outside %s (%q) — ignoring it (agent-writable store; see conversation.go)", sessionsDir(), entry.SessionFile)
		}
	}
	if entry.SessionID != "" {
		if plainFileName(entry.SessionID) {
			stems = append(stems, entry.SessionID)
		} else {
			logger.Logf("openclaw conversation: sessions.json sessionId %q is path-shaped — ignoring it", entry.SessionID)
		}
	}
	var names []string
	seen := map[string]bool{}
	for _, stem := range stems {
		for _, n := range []string{stem + ".jsonl", stem + ".trajectory.jsonl", stem + ".trajectory-path.json"} {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	return names, nil
}

// readSessionEntry returns key's entry from sessions.json; found=false when
// there is no store or no entry. The store is agent-writable: privsep reads it
// only as a regular file reached without a link, refusing anything else (a
// FIFO swapped in cannot block the read), and the read is size-capped.
func readSessionEntry(key string) (sessionEntry, bool, error) {
	raw, err := privsep.ReadFile(sessionsStorePath(), maxSessionsStore)
	if errors.Is(err, fs.ErrNotExist) {
		return sessionEntry{}, false, nil
	}
	if err != nil {
		return sessionEntry{}, false, err
	}
	var store map[string]sessionEntry
	if err := json.Unmarshal(raw, &store); err != nil {
		return sessionEntry{}, false, fmt.Errorf("parse %s: %w", sessionsStorePath(), err)
	}
	for _, k := range storeKeys(key) {
		if e, ok := store[k]; ok {
			return e, true, nil
		}
	}
	return sessionEntry{}, false, nil
}

// sessionFileName returns the base name of candidate when it sits DIRECTLY in
// sessionsDir() (the shape openclaw writes: an absolute path there), else "".
func sessionFileName(candidate string) string {
	p := filepath.Clean(candidate)
	if !filepath.IsAbs(p) {
		// A relative one would resolve against the sealed process's cwd —
		// read it as relative to the sessions dir instead.
		p = filepath.Join(sessionsDir(), p)
	}
	if filepath.Dir(p) != filepath.Clean(sessionsDir()) {
		return ""
	}
	if name := filepath.Base(p); plainFileName(name) {
		return name
	}
	return ""
}

// plainFileName reports whether s can only ever name an entry in the current
// directory.
func plainFileName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\\\x00")
}

// removeSessionFiles deletes the files of key's session from sessionsDir(),
// best-effort and logged. A name that is a link is removed itself, never
// followed, and a link anywhere above it refuses the removal (privsep.Remove).
func removeSessionFiles(key string) {
	names, err := sessionFilesForKey(key)
	if err != nil {
		logger.Logf("openclaw conversation: %v — superseded session files left in place", err)
		return
	}
	afterStoreRead()
	for _, n := range names {
		if err := privsep.Remove(filepath.Join(sessionsDir(), n)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			logger.Logf("openclaw conversation: remove %s: %v", n, err)
		}
	}
}

// ClearSession implements framework.SessionClearer: mint a fresh session key
// — the next turn starts an empty session — and delete the superseded
// session's files. The sessions.json entry is openclaw's own store and is left
// for openclaw to manage (rewriting a live store it owns from outside risks
// corrupting it mid-write).
func (a *Adapter) ClearSession(_ context.Context) error {
	convMu.Lock()
	oldKey := ""
	if b, err := framework.ReadState(conversationKeyState); err == nil {
		oldKey = strings.TrimSpace(string(b))
	}
	legacy, busy := false, false
	if oldKey == "" {
		oldKey, legacy, busy = legacyConversationKey()
	}
	err := framework.WriteState(conversationKeyState, []byte(mintConversationKey()))
	if err == nil && (legacy || busy) {
		// Retired either way: the new key is sealed's own, and a key still
		// at the old name would never be read again.
		_ = privsep.Remove(legacyConversationKeyPath())
	}
	convMu.Unlock()
	if err != nil {
		return fmt.Errorf("openclaw.ClearSession: %w", err)
	}
	// Delete outside the lock. A turn still in flight on oldKey can recreate
	// a file before the restart that follows stops the gateway — a trajectory
	// rewritten that way is a full copy of the cleared conversation, left on
	// the container's disk (never on chain) until a recreate. The key has
	// already rotated, so the gateway serves the new key's session and never
	// the orphan (audit #169 F4: a leftover, not a resurrection).
	if oldKey != "" {
		removeSessionFiles(oldKey)
	}
	return nil
}
