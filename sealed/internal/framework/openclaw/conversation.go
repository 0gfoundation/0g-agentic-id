package openclaw

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"seal-verify/internal/framework"
)

// openclaw persists every gateway turn to a per-session JSONL transcript
// (~/.openclaw/agents/<id>/sessions/<sessionId>.jsonl, sessionKey→sessionId in
// sessions.json) — but its OpenAI-compatible door never reads it back: the
// client's messages[] is authoritative there. This file is openclaw's
// conversation encapsulation (CONVERSATION.md §4): pin ONE session key so
// every stateful-door turn lands in ONE transcript, and read that transcript
// back as the history for the next turn — so the client sends only the
// current turn and a process restart resumes from openclaw's own store.
//
// The private-format coupling (version:3 JSONL, sessions.json shape) is
// quarantined here, in openclaw's own package — the same kind of coupling
// this adapter already has (it parses openclaw.json). An openclaw upgrade
// that changes the transcript format is THIS file's maintenance burden.
//
// openclaw's own compaction REWRITES the persisted transcript (not
// context-only), so invariant 7's self-rotation is satisfied by the harness
// itself: the file openclaw keeps is the compacted view, and that is exactly
// what we read back.

const sessionKeyHeader = "x-openclaw-session-key"

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
// session key, so openclaw files every stateful turn under ONE transcript.
func (a *Adapter) ConversationHeaders() map[string]string {
	return map[string]string{sessionKeyHeader: currentConversationKey()}
}

// ObserveConversation implements framework.ConversationSession. openclaw
// session keys do not rotate — nothing to follow.
func (a *Adapter) ObserveConversation(http.Header) {}

// sessionEntry is the slice of openclaw's sessions.json this package needs:
// the store is a map keyed by session key.
type sessionEntry struct {
	SessionID   string `json:"sessionId"`
	SessionFile string `json:"sessionFile"`
}

// transcriptPathForKey resolves the pinned key to its transcript file via
// openclaw's own sessions.json. Empty when the key has no session yet (first
// turn ever) — that is data, not an error.
func transcriptPathForKey(key string) (string, error) {
	raw, err := os.ReadFile(sessionsStorePath())
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var store map[string]sessionEntry
	if err := json.Unmarshal(raw, &store); err != nil {
		return "", fmt.Errorf("parse %s: %w", sessionsStorePath(), err)
	}
	entry, ok := store[key]
	if !ok {
		return "", nil
	}
	if entry.SessionFile != "" {
		return entry.SessionFile, nil
	}
	if entry.SessionID == "" {
		return "", nil
	}
	return filepath.Join(sessionsDir(), entry.SessionID+".jsonl"), nil
}

// ConversationHistory implements framework.ConversationHistory: prior turns
// from openclaw's own transcript. Transcript lines are
// {type:"message", message:{role, content}} where content is a string or an
// array of {type:"text", text} parts; everything else (header, tool records)
// is skipped — the same TEXT-history limitation the synth door has always
// documented.
func (a *Adapter) ConversationHistory(_ context.Context) ([]framework.ConversationTurn, error) {
	path, err := transcriptPathForKey(currentConversationKey())
	if err != nil || path == "" {
		return nil, err
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil // mapped but not yet written — first turn in flight
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var turns []framework.ConversationTurn
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 256*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec struct {
			Type    string `json:"type"`
			Message struct {
				Role    string          `json:"role"`
				Content json.RawMessage `json:"content"`
			} `json:"message"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue // torn tail or foreign record — skip, never fail the turn
		}
		if rec.Type != "message" || (rec.Message.Role != "user" && rec.Message.Role != "assistant") {
			continue
		}
		if text := contentText(rec.Message.Content); text != "" {
			turns = append(turns, framework.ConversationTurn{Role: rec.Message.Role, Text: text})
		}
	}
	return turns, nil
}

// contentText flattens openclaw's message content (string, or an array of
// typed parts) to its text.
func contentText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	var b strings.Builder
	for _, p := range parts {
		if p.Type == "text" && p.Text != "" {
			b.WriteString(p.Text)
		}
	}
	return b.String()
}

// ClearSession implements framework.SessionClearer: mint a fresh session key
// — the next turn starts an empty transcript. The superseded transcript file
// is removed best-effort; the sessions.json entry is openclaw's own store and
// is left for openclaw to manage (rewriting a live store it owns from outside
// risks corrupting it mid-write).
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
	if oldKey != "" {
		if path, perr := transcriptPathForKey(oldKey); perr == nil && path != "" {
			_ = os.Remove(path)
		}
	}
	return nil
}
