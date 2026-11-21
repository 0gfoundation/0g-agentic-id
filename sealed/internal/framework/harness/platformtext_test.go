package harness

import (
	"strings"
	"testing"
)

// The agent learns both switches of its web tools by their names, and to tell
// its owner at once when one is off rather than imitate a search.
func TestFrameworkFactsNameTheWebSwitches(t *testing.T) {
	notes := strings.Join(New().FrameworkFacts().Notes, "\n")
	for _, want := range []string{
		"turns both off with the `webTools` setting",
		"`web_search` alone with `webSearch.service` = `off`",
		"your instructions say which and why",
		"tell your owner at once instead of working around it (never imitate a search with `web_fetch`)",
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("the notes do not say %q", want)
		}
	}
}

func TestFileDeliveryDistinguishesCopiesFromAutomaticCleanup(t *testing.T) {
	facts := New().FrameworkFacts()
	notes := strings.Join(facts.Notes, "\n")
	for _, want := range []string{
		"Manual `/download` keeps the remote original",
		"independently removes the remote file after verifying the local copy",
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("missing file delivery guidance %q", want)
		}
	}
	for _, entry := range facts.Untracked {
		if entry.Path == "~/outbox/" && strings.Contains(entry.Note, "automatic saver removes the remote file after verifying the local copy") {
			return
		}
	}
	t.Error("the outbox guidance should identify when the remote copy is removed")
}
