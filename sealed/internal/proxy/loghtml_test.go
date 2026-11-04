package proxy

import (
	"strings"
	"testing"

	"seal-verify/internal/state"
)

func TestExplorerFor_KnownChainsOnly(t *testing.T) {
	cases := map[string]string{
		"16661":  "https://chainscan.0g.ai",
		"16602":  "https://chainscan-galileo.0g.ai",
		" 16602": "https://chainscan-galileo.0g.ai",
		"1":      "",
		"":       "",
	}
	for id, want := range cases {
		if got := explorerFor(id); got != want {
			t.Errorf("explorerFor(%q) = %q, want %q", id, got, want)
		}
	}
}

const logAddr = "0x00000000000000000000000000000000000000A9"

func TestRenderLogHTML_LinksOnlyUnderAKnownExplorer(t *testing.T) {
	line := "[12:00:00.000] OK seal " + logAddr
	page := renderLogHTML("t", []string{line}, "https://chainscan.0g.ai")
	if !strings.Contains(page, `href="https://chainscan.0g.ai/address/`+logAddr+`"`) {
		t.Errorf("mainnet page lacks the mainnet explorer link:\n%s", page)
	}
	// Unknown chain: the token stays plain text, no guessed host.
	page = renderLogHTML("t", []string{line}, "")
	if strings.Contains(page, `<a class="hex"`) || !strings.Contains(page, logAddr) {
		t.Errorf("unknown-chain page must render the address unlinked:\n%s", page)
	}
}

// The dialled chain id wins; before SetChainID the armed agent's serve-proof
// domain is used; with neither there is no explorer.
func TestServerExplorerBase_Resolution(t *testing.T) {
	ag := state.New()
	s := New(ag, "")
	if got := s.explorerBase(); got != "" {
		t.Fatalf("unarmed, no chain: explorer = %q, want none", got)
	}
	ag.Set([]byte{1}, "http://127.0.0.1:1", "deadbeef", logAddr, "1", "0x00", "16602", logAddr, "")
	if got := s.explorerBase(); got != "https://chainscan-galileo.0g.ai" {
		t.Fatalf("armed on 16602: explorer = %q", got)
	}
	s.SetChainID("16661")
	if got := s.explorerBase(); got != "https://chainscan.0g.ai" {
		t.Fatalf("dialled 16661: explorer = %q", got)
	}
}
