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
	_ = a.ConversationHeaders()
	h := http.Header{}
	h.Set(sessionIDHeader, "seal-owner-chat-child01")
	a.ObserveConversation(h)
	if got := a.ConversationHeaders()[sessionIDHeader]; got != "seal-owner-chat-child01" {
		t.Fatalf("rotation not followed: %q", got)
	}
}

// A hostile/garbled echo must never become the persisted identity: hermes
// itself rejects path-shaped and control-character ids, so persisting one
// would wedge every later turn on a 400.
func TestConversationID_RejectsUnsafeEcho(t *testing.T) {
	redirectHome(t)
	a := &Adapter{}
	orig := a.ConversationHeaders()[sessionIDHeader]
	for _, bad := range []string{"../../etc/passwd", "a\r\nb", ""} {
		h := http.Header{}
		h.Set(sessionIDHeader, bad)
		a.ObserveConversation(h)
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
