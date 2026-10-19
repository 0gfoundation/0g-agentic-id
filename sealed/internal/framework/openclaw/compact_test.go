package openclaw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/inference"
)

var _ framework.SessionCompactor = (*Adapter)(nil)

type cliCall struct {
	env  []string
	args []string
}

// stubCompactCLI replaces the CLI for the duration of t with one that
// records its call and answers out/err.
func stubCompactCLI(t *testing.T, out string, err error) *cliCall {
	t.Helper()
	call := &cliCall{}
	prev := runCompactCLI
	runCompactCLI = func(_ context.Context, env []string, args ...string) ([]byte, error) {
		call.env, call.args = env, args
		return []byte(out), err
	}
	t.Cleanup(func() { runCompactCLI = prev })
	return call
}

func startedAdapter(t *testing.T) *Adapter {
	t.Helper()
	useTempHome(t)
	a := New()
	a.authToken = "gw-token"
	return a
}

// The measured shape of a successful run (openclaw 2026.7.1, local): the
// pinned session, the gateway URL and token by env, the token never in argv.
func TestCompactSession_Compacted(t *testing.T) {
	a := startedAdapter(t)
	call := stubCompactCLI(t, `{"ok":true,"key":"agent:main:x","compacted":true,"result":{"tokensBefore":269717,"tokensAfter":3559}}`, nil)

	note, err := a.CompactSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note, "269717") || !strings.Contains(note, "3559") {
		t.Errorf("note = %q; want the before/after token counts", note)
	}
	key := currentConversationKey()
	if len(call.args) < 3 || call.args[0] != "sessions" || call.args[1] != "compact" || call.args[2] != key || !slices.Contains(call.args, "--json") {
		t.Errorf("args = %v; want sessions compact %s --json …", call.args, key)
	}
	if !slices.Contains(call.env, fmt.Sprintf("OPENCLAW_GATEWAY_URL=ws://127.0.0.1:%d", upstreamPort)) ||
		!slices.Contains(call.env, "OPENCLAW_GATEWAY_TOKEN=gw-token") {
		t.Errorf("env = %v; want the gateway URL and token", call.env)
	}
	if !slices.Contains(call.env, "OPENCLAW_NO_RESPAWN=1") {
		t.Errorf("env = %v; want OPENCLAW_NO_RESPAWN=1 (a respawned CLI outlives its kill)", call.env)
	}
	for _, a := range call.args {
		if strings.Contains(a, "gw-token") {
			t.Errorf("token leaked into argv: %v", call.args)
		}
	}
}

func TestCompactSession_NothingToCompact(t *testing.T) {
	a := startedAdapter(t)
	stubCompactCLI(t, `{"ok":true,"key":"agent:main:x","compacted":false,"reason":"no transcript"}`, nil)
	note, err := a.CompactSession(context.Background())
	if err != nil || note != "nothing to compact (no transcript)" {
		t.Fatalf("note=%q err=%v", note, err)
	}
}

func TestCompactSession_Pending(t *testing.T) {
	a := startedAdapter(t)
	stubCompactCLI(t, `{"ok":true,"compacted":false,"result":{"details":{"pending":true}}}`, nil)
	note, err := a.CompactSession(context.Background())
	if err != nil || !strings.Contains(note, "background") {
		t.Fatalf("note=%q err=%v", note, err)
	}
}

// openclaw's own failure (ok:false + exit 1) reaches the owner with its words,
// and is NOT a refusal: something went wrong, retrying blind won't help.
func TestCompactSession_GatewayFailure(t *testing.T) {
	a := startedAdapter(t)
	stubCompactCLI(t, "warming up\n"+`{"ok":false,"key":"x","error":"failed to interrupt active session"}`, errors.New("exit status 1"))
	_, err := a.CompactSession(context.Background())
	if err == nil || !strings.Contains(err.Error(), "failed to interrupt") {
		t.Fatalf("err = %v; want openclaw's reason", err)
	}
	if errors.Is(err, framework.ErrCompactRefused) {
		t.Fatalf("a failure must not read as a refusal: %v", err)
	}
}

// The gateway's "not now" answers (sessions.compact, 2026.7.1 wording) are
// refusals: nothing was compacted, and the proxy tells the owner to retry.
func TestCompactSession_RefusalIsTyped(t *testing.T) {
	for _, msg := range []string{
		"Session agent:main:x is still active; try again.",
		"Session agent:main:x is still active; try again in a moment.",
		"Session agent:main:x changed before compaction. Retry.",
	} {
		a := startedAdapter(t)
		stubCompactCLI(t, `{"ok":false,"key":"x","error":"`+msg+`"}`, errors.New("exit status 1"))
		_, err := a.CompactSession(context.Background())
		if !errors.Is(err, framework.ErrCompactRefused) || !strings.Contains(err.Error(), msg) {
			t.Fatalf("%q: err = %v; want ErrCompactRefused carrying openclaw's words", msg, err)
		}
	}
}

// A killed CLI must not hold the route hostage through a descendant that
// inherited its output pipes: the run returns within WaitDelay of the kill.
func TestRunCompactCLI_KillDoesNotWaitOnInheritedPipes(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\nsleep 30 &\nsleep 30\n"
	if err := os.WriteFile(filepath.Join(dir, "openclaw"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	prev := compactCLIWaitDelay
	compactCLIWaitDelay = 200 * time.Millisecond
	t.Cleanup(func() { compactCLIWaitDelay = prev })

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := runCompactCLI(ctx, []string{"PATH=" + os.Getenv("PATH")}, "sessions", "compact", "k")
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("runCompactCLI returned after %v; the inherited pipe held it past WaitDelay", took)
	}
	if err == nil {
		t.Fatal("want an error from the killed CLI")
	}
}

// openclaw leaves tokensAfter out when the "compacted" context is not smaller
// — a conversation within the kept tail gets a summary of nothing on top of
// the same history. The note must not claim a shrink it did not see.
func TestCompactSession_NoSmallerSizeIsSaidSo(t *testing.T) {
	a := startedAdapter(t)
	stubCompactCLI(t, `{"ok":true,"compacted":true,"result":{"summary":"s","tokensBefore":110}}`, nil)
	note, err := a.CompactSession(context.Background())
	if err != nil || !strings.Contains(note, "no smaller size") || strings.Contains(note, "replaced by a summary") {
		t.Fatalf("note=%q err=%v; want the no-smaller-size note", note, err)
	}
}

// "…changed before compaction completed. Retry." arrives after the summary
// was written (only the session index update failed): a failure, never a
// "nothing changed" refusal that invites a second compaction.
func TestCompactSession_ChangedAfterCompletionIsAFailure(t *testing.T) {
	a := startedAdapter(t)
	stubCompactCLI(t, `{"ok":false,"key":"x","error":"Session agent:main:x changed before compaction completed. Retry."}`, errors.New("exit status 1"))
	_, err := a.CompactSession(context.Background())
	if err == nil || errors.Is(err, framework.ErrCompactRefused) {
		t.Fatalf("err = %v; want a plain failure", err)
	}
}

// A manual compaction keeps its recent tail only while keepRecentTokens is
// set (openclaw's hardenManualCompactionBoundary), so the render sets
// openclaw's own default whenever nothing else has — and leaves an owner's
// positive value, and its siblings, alone.
func TestRenderSettings_SetsCompactionKeepRecentTokens(t *testing.T) {
	compaction := func(cfg map[string]any) map[string]any {
		agents, _ := cfg["agents"].(map[string]any)
		defaults, _ := agents["defaults"].(map[string]any)
		c, _ := defaults["compaction"].(map[string]any)
		return c
	}
	for _, tc := range []struct {
		name, overlay string
		want          int
	}{
		{"unset gets openclaw's default", "", openclawKeepRecentTokens},
		{"the overlay's value stands", `{"agents":{"defaults":{"compaction":{"keepRecentTokens":8000,"reserveTokens":4000}}}}`, 8000},
		{"a non-positive value is replaced", `{"agents":{"defaults":{"compaction":{"keepRecentTokens":0}}}}`, openclawKeepRecentTokens},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useTempHome(t)
			s := routedSettings(inference.WireOpenAI, "glm-5.3")
			if tc.overlay != "" {
				s.Others = json.RawMessage(tc.overlay)
			}
			c := compaction(renderInto(t, s))
			if v, _ := c["keepRecentTokens"].(float64); int(v) != tc.want {
				t.Fatalf("keepRecentTokens = %v; want %d", c["keepRecentTokens"], tc.want)
			}
			if tc.name == "the overlay's value stands" {
				if v, _ := c["reserveTokens"].(float64); int(v) != 4000 {
					t.Errorf("a sibling key was lost: %v", c)
				}
			}
		})
	}
}

// No JSON at all (CLI missing, crashed): the run error is what surfaces.
func TestCompactSession_CLIFailure(t *testing.T) {
	a := startedAdapter(t)
	stubCompactCLI(t, "", errors.New(`exec: "openclaw": executable file not found in $PATH`))
	_, err := a.CompactSession(context.Background())
	if err == nil || !strings.Contains(err.Error(), "executable file not found") {
		t.Fatalf("err = %v; want the run error", err)
	}
}

func TestCompactSession_BeforeStart(t *testing.T) {
	useTempHome(t)
	call := stubCompactCLI(t, "", nil)
	if _, err := New().CompactSession(context.Background()); err == nil {
		t.Fatal("want an error before the gateway has a token")
	}
	if call.args != nil {
		t.Fatalf("the CLI must not run before start: %v", call.args)
	}
}

// A line the CLI prints ahead of the payload may itself carry a brace.
func TestDecodeCLIJSON_SkipsBraceBearingPreamble(t *testing.T) {
	var res compactResult
	out := []byte("config {gateway} loaded\n" + `{"ok":true,"compacted":true,"result":{"tokensBefore":10,"tokensAfter":2}}`)
	if err := decodeCLIJSON(out, &res); err != nil {
		t.Fatal(err)
	}
	if !res.OK || !res.Compacted || res.Result == nil || *res.Result.TokensAfter != 2 {
		t.Fatalf("decoded %+v", res)
	}
	if err := decodeCLIJSON([]byte("no json here"), &res); err == nil {
		t.Fatal("want an error when there is no JSON object")
	}
}
