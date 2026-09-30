package hermes

import (
	"context"
	"net/http"
	"os"
	"testing"
)

func redirectHome(t *testing.T) {
	t.Helper()
	old := hermesHome
	hermesHome = t.TempDir()
	t.Cleanup(func() { hermesHome = old })
}

// One id, minted once, stable across calls — the "one conversation per agent"
// invariant at the identity level.
func TestConversationID_MintedOnceAndStable(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	h1 := a.ConversationHeaders()[sessionIDHeader]
	h2 := a.ConversationHeaders()[sessionIDHeader]
	if h1 == "" || h1 != h2 {
		t.Fatalf("id must be minted once and stay stable: %q vs %q", h1, h2)
	}
}

// hermes ROTATES the session id at compaction (parent ends, child continues).
// Not following the echo would fork the conversation at every compaction.
func TestConversationID_FollowsRotation(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	sent := a.ConversationHeaders() // pins the current id
	h := http.Header{}
	h.Set(sessionIDHeader, "seal-owner-chat-child01")
	a.ObserveConversation(sent, h) // echo differs from sent → legit rotation
	if got := a.ConversationHeaders()[sessionIDHeader]; got != "seal-owner-chat-child01" {
		t.Fatalf("rotation not followed: %q", got)
	}
}

// AUDIT #169 F1: a /clear while a turn is in flight must NOT be undone by that
// turn's late rotation echo. The echo is a stale generation (pinned before the
// clear); CAS on the sent id drops it.
func TestConversationID_ClearSurvivesInFlightEcho(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	sent := a.ConversationHeaders() // T1 pinned id A
	if err := a.ClearSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	cleared := a.ConversationHeaders()[sessionIDHeader] // fresh id C
	// T1's response lands now, echoing A (or a child of A).
	h := http.Header{}
	h.Set(sessionIDHeader, "seal-owner-chat-childOfA")
	a.ObserveConversation(sent, h)
	if got := a.ConversationHeaders()[sessionIDHeader]; got != cleared {
		t.Fatalf("clear was resurrected: id is %q, want the post-clear %q", got, cleared)
	}
}

// AUDIT #169 F2: a stale concurrent turn's echo must not overwrite the id a
// newer turn already rotated to.
func TestConversationID_StaleTurnDoesNotRevertRotation(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	sentA := a.ConversationHeaders() // both turns pinned A
	// T1 rotates A→B (its sent id is still A, echo is B).
	hB := http.Header{}
	hB.Set(sessionIDHeader, "seal-owner-chat-B")
	a.ObserveConversation(sentA, hB)
	if got := a.ConversationHeaders()[sessionIDHeader]; got != "seal-owner-chat-B" {
		t.Fatalf("rotation to B not applied: %q", got)
	}
	// T2, pinned to the now-dead A, completes with no rotation (echo A).
	hA := http.Header{}
	hA.Set(sessionIDHeader, sentA[sessionIDHeader])
	a.ObserveConversation(sentA, hA)
	if got := a.ConversationHeaders()[sessionIDHeader]; got != "seal-owner-chat-B" {
		t.Fatalf("stale turn reverted the id to %q, want B", got)
	}
}

// A hostile/garbled echo must never become the persisted identity: hermes
// itself rejects path-shaped and control-character ids, so persisting one
// would wedge every later turn on a 400.
func TestConversationID_RejectsUnsafeEcho(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	sent := a.ConversationHeaders()
	orig := sent[sessionIDHeader]
	for _, bad := range []string{"../../etc/passwd", "a\r\nb", ""} {
		h := http.Header{}
		h.Set(sessionIDHeader, bad)
		a.ObserveConversation(sent, h)
	}
	if got := a.ConversationHeaders()[sessionIDHeader]; got != orig {
		t.Fatalf("unsafe echo persisted: %q", got)
	}
}

// /clear = a fresh identity; the old transcript stays in hermes's own db but
// nothing the platform sends references it any more.
func TestClearSession_MintsAFreshIdentity(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	before := a.ConversationHeaders()[sessionIDHeader]
	if err := a.ClearSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := a.ConversationHeaders()[sessionIDHeader]
	if after == "" || after == before {
		t.Fatalf("clear must mint a fresh id: before=%q after=%q", before, after)
	}
	if _, err := os.Stat(conversationIDPath()); err != nil {
		t.Fatalf("id file must persist: %v", err)
	}
}
