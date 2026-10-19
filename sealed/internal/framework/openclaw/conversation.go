package openclaw

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
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

func conversationKeyPath() string { return openclawHome + "/.seal-conversation-key" }
func sessionsDir() string {
	return filepath.Join(openclawHome, "agents", openclawAgentID, "sessions")
}
func sessionsStorePath() string { return filepath.Join(sessionsDir(), "sessions.json") }

var convMu sync.Mutex

func currentConversationKey() string {
	convMu.Lock()
	defer convMu.Unlock()
	if b, err := os.ReadFile(conversationKeyPath()); err == nil {
		if k := strings.TrimSpace(string(b)); k != "" {
			return k
		}
	}
	k := mintConversationKey()
	_ = os.WriteFile(conversationKeyPath(), []byte(k), 0o600)
	return k
}

func mintConversationKey() string {
	var buf [12]byte
	_, _ = rand.Read(buf[:])
	return "seal-owner-chat-" + hex.EncodeToString(buf[:])
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
// plain names in the directory root is open on: the transcript, and the
// trajectory record and its pointer — the trajectory holds each turn's full
// prompt and reply, so the conversation lives there too (openclaw caps it at
// 10 MiB per session). Empty when the key has no session.
//
// SECURITY (review #169): sessions.json lives under openclawHome, the tree
// privsep hands to the de-privileged framework user — the agent mind can
// rewrite it, and swap any directory in it for a symlink — while the ROOT
// sealed process deletes what it names. So the store is read through the
// same os.Root the deletions go through (one directory, pinned at open: no
// swap in between), and nothing it says is used as a path — only a plain
// file name survives, which os.Root removes without following.
func sessionFilesForKey(root *os.Root, key string) ([]string, error) {
	// A regular file only: a FIFO planted here would block the open forever.
	fi, err := root.Lstat("sessions.json")
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file (%v)", sessionsStorePath(), fi.Mode().Type())
	}
	f, err := root.Open("sessions.json")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxSessionsStore+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxSessionsStore {
		return nil, fmt.Errorf("%s is over %d bytes", sessionsStorePath(), maxSessionsStore)
	}
	var store map[string]sessionEntry
	if err := json.Unmarshal(raw, &store); err != nil {
		return nil, fmt.Errorf("parse %s: %w", sessionsStorePath(), err)
	}
	var entry sessionEntry
	found := false
	for _, k := range storeKeys(key) {
		if e, ok := store[k]; ok {
			entry, found = e, true
			break
		}
	}
	if !found {
		return nil, nil
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
// best-effort and logged. A name that is a symlink is removed itself, never
// followed.
func removeSessionFiles(key string) {
	root, err := os.OpenRoot(sessionsDir())
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Logf("openclaw conversation: open %s: %v — superseded session files left in place", sessionsDir(), err)
		}
		return
	}
	defer root.Close()
	names, err := sessionFilesForKey(root, key)
	if err != nil {
		logger.Logf("openclaw conversation: %v — superseded session files left in place", err)
		return
	}
	afterStoreRead()
	for _, n := range names {
		if err := root.Remove(n); err != nil && !os.IsNotExist(err) {
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
	if b, err := os.ReadFile(conversationKeyPath()); err == nil {
		oldKey = strings.TrimSpace(string(b))
	}
	err := os.WriteFile(conversationKeyPath(), []byte(mintConversationKey()), 0o600)
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
