package platform

import (
	"flag"
	"os"
	"strings"
	"testing"
	"time"
)

// updateBible regenerates AGENT_BIBLE.md from bibleTemplate() instead of
// checking it. Run: go test ./internal/platform/ -run TestAgentBibleGolden -update-bible
var updateBible = flag.Bool("update-bible", false, "regenerate AGENT_BIBLE.md")

// bibleTemplate renders the agent doc with PLACEHOLDER values so the platform
// prose is verbatim from code and only the blanks are markers. It is the
// single source of truth for sealed/AGENT_BIBLE.md — the golden test below
// keeps that file from drifting away from AssembleAgentDoc. Placeholders are
// framework-neutral (they name no specific framework) so the template stays
// a generic reference.
func bibleTemplate() string {
	rs := RuntimeSnapshot{
		SealedVersion:    "(sealed version hash)",
		FrameworkVersion: "(framework version)",
		WhitelistMax:     "(whitelist max)",
		AgentSeal:        "(agentSeal address)",
		AgentID:          "(agentID)",
		Owner:            "(owner address)",
		ChainRPC:         "(chain RPC)",
		ContractAddr:     "(contract address)",
		AttestorURL:      "(attestor URL)",
		PublicURL:        "(public URL)",
		SealSignSock:     "/run/seal-sign.sock",
		Provider:         "(provider)",
		Model:            "(model)",
		ZGComputeRouted:  false,
		BootTime:         time.Unix(0, 0).UTC(),
	}
	facts := FrameworkFacts{
		Home: "(framework home dir, e.g. ~/.acme/)",
		Tracked: []PathNote{
			{Path: "(chain-tracked path)", Note: "(what it holds and any special rule — list every tracked path)"},
		},
		Untracked: []PathNote{
			{Note: "(container-local path or category — list each; the template then appends the universal outside-home and process-memory lines)"},
		},
		DurableHints: []DurableHint{
			{Ask: "(owner request, e.g. \"remember this\")", Place: "(where it goes, e.g. `memories/NOTES.md`)"},
		},
		VersionScheme: "(release scheme, e.g. semver releases / CalVer tags)",
		Versions:      []string{"(whitelisted version — list each)"},
		VersionMax:    "(whitelist max)",
		ReconcileHow:  "(reconcile command, e.g. `npm install <pkg>@<max>` or `git checkout <max>` + a lockfile sync)",
		ConfigFile:    "(config filename)",
		ConfigKeys:    []string{"(chain-tracked top-level key — list each)"},
		ConfigSecret:  "(secret key stripped before chain, e.g. api_key; leave empty if none)",
	}

	doc := AssembleAgentDoc(Build(rs), facts)
	doc = strings.ReplaceAll(doc, "1970-01-01T00:00:00Z", "(boot time)")
	// ZGComputeRouted is a bool so it can't carry a string placeholder; mark
	// the snapshot-table cell as an instance blank like the rest.
	doc = strings.ReplaceAll(doc, "| `no` |", "| `(0g-compute routing, yes/no)` |")

	header := "# Agent Bible (template)\n\n" +
		"> Generated from `platform.AssembleAgentDoc` with placeholder values. " +
		"Regenerate after changing the template or the fill-in form to avoid drift.\n\n" +
		"This is the complete agent doc the 0G Sealed runtime injects into every " +
		"agent — the authoritative statement, read every turn, of the truth about " +
		"its own runtime. The sealed side holds this ONE template; almost all of it " +
		"is fixed prose copied verbatim into every agent. Only the `(…)` are blanks, " +
		"of two kinds:\n\n" +
		"- **Framework blanks** (filled once per adapter, via `FrameworkFacts`): home " +
		"dir, tracked/untracked paths, where memory goes, version whitelist, config " +
		"file + keys. Concentrated in \"Persistent state\", \"Framework version " +
		"whitelist\", \"Config allowlist\".\n" +
		"- **Instance blanks** (filled each boot from chain/env, via `RuntimeSnapshot`): " +
		"agentSeal address, owner, agentID, model, versions, public URL, boot time. " +
		"Scattered through the identity lines, the snapshot table, and inline references.\n\n" +
		"\"Inviolable self\" (the sovereignty rules) and \"Environment\" (capabilities / " +
		"exposing a service) have NO blanks — verbatim for every agent, so the security " +
		"rules leave no one room to rewrite them.\n\n---\n\n"
	return header + doc + "\n"
}

// TestAgentBibleGolden fails if sealed/AGENT_BIBLE.md has drifted from what
// AssembleAgentDoc + the fill-in template now produce. Regenerate with
// -update-bible.
func TestAgentBibleGolden(t *testing.T) {
	const path = "../../AGENT_BIBLE.md"
	want := bibleTemplate()

	if *updateBible {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("regenerated %s", path)
		return
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (generate it with -update-bible)", path, err)
	}
	if string(got) != want {
		t.Errorf("%s is stale vs AssembleAgentDoc — regenerate with:\n"+
			"  go test ./internal/platform/ -run TestAgentBibleGolden -update-bible", path)
	}
}
