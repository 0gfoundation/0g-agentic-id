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
	"seal-verify/internal/settings"
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
	for _, e := range stateEnv() {
		if !slices.Contains(call.env, e) {
			t.Errorf("env = %v; want the gateway's %s", call.env, e)
		}
	}
	for _, e := range call.env {
		if strings.HasPrefix(e, "PATH=") || strings.HasPrefix(e, "HOME=") {
			t.Errorf("env carries %q, which would override the one privsep.AgentCommand sets", e)
		}
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
	writeScript(t, filepath.Join(trustedBin(t), "openclaw"), "sleep 30 &\nsleep 30")
	prev := compactCLIWaitDelay
	compactCLIWaitDelay = 200 * time.Millisecond
	t.Cleanup(func() { compactCLIWaitDelay = prev })

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := runCompactCLI(ctx, nil, "sessions", "compact", "k")
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("runCompactCLI returned after %v; the inherited pipe held it past WaitDelay", took)
	}
	if err == nil {
		t.Fatal("want an error from the killed CLI")
	}
}

// What the CLI prints is the agent's to shape (it reads the agent-writable
// home), so sealed keeps only compactOutputMax bytes of it.
func TestRunCompactCLI_BoundsWhatItKeeps(t *testing.T) {
	writeScript(t, filepath.Join(trustedBin(t), "openclaw"), `head -c 3000000 /dev/zero | tr '\0' x`)
	out, err := runCompactCLI(context.Background(), nil, "sessions", "compact", "k")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != compactOutputMax {
		t.Fatalf("kept %d bytes of the CLI's output; want %d", len(out), compactOutputMax)
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
	for _, tc := range []struct {
		name, overlay string
		want          int
	}{
		{"unset gets openclaw's default", "", openclawKeepRecentTokens},
		{"the overlay's value stands", `{"agents":{"defaults":{"compaction":{"keepRecentTokens":8000,"reserveTokens":4000}}}}`, 8000},
		{"a non-positive value is replaced", `{"agents":{"defaults":{"compaction":{"keepRecentTokens":0}}}}`, openclawKeepRecentTokens},
		// openclaw's schema takes integers only; a fraction would get the
		// whole overlay withdrawn (ensureConfigAcceptable).
		{"a fraction is replaced", `{"agents":{"defaults":{"compaction":{"keepRecentTokens":8000.5}}}}`, openclawKeepRecentTokens},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useTempHome(t)
			s := routedSettings(inference.WireOpenAI, "glm-5.3")
			if tc.overlay != "" {
				s.Others = json.RawMessage(tc.overlay)
			}
			c := compactionBlock(renderInto(t, s))
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

// An openclaw without the `sessions compact` command (2026.5.x, still
// whitelisted) answers "unsupported" — 501 at the proxy — and the CLI never runs.
func TestCompactSession_OlderOpenclawIsUnsupported(t *testing.T) {
	a := startedAdapter(t)
	a.cfg = &config{framework: frameworkBinding{PackageVersion: "2026.5.7"}}
	call := stubCompactCLI(t, "", nil)
	_, err := a.CompactSession(context.Background())
	if !errors.Is(err, framework.ErrCompactUnsupported) || !strings.Contains(err.Error(), "2026.5.7") {
		t.Fatalf("err = %v; want ErrCompactUnsupported naming the version", err)
	}
	if call.args != nil {
		t.Fatalf("the CLI must not run on an unsupported version: %v", call.args)
	}
}

// /compact does not second-guess the session's recorded model: openclaw files
// a built-in provider's alias under the resolved name (anthropic/sonnet →
// claude-sonnet-5), so comparing it with the pin refused such an owner
// forever. The summary's model is the render's job (setCompactionModel).
func TestCompactSession_RunsWhateverTheSessionLastRanOn(t *testing.T) {
	a := startedAdapter(t)
	a.rendered = &settings.Resolved{Doc: settings.Doc{Provider: "anthropic", Model: "sonnet"}}
	if err := os.MkdirAll(sessionsDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	store := `{"agent:main:` + currentConversationKey() + `":{"sessionId":"s1","model":"claude-sonnet-5","modelProvider":"anthropic"}}`
	if err := os.WriteFile(sessionsStorePath(), []byte(store), 0o644); err != nil {
		t.Fatal(err)
	}
	call := stubCompactCLI(t, `{"ok":true,"compacted":true,"result":{"tokensBefore":10,"tokensAfter":2}}`, nil)
	if _, err := a.CompactSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	if call.args == nil {
		t.Fatal("the CLI did not run")
	}
}

// compactionBlock reads agents.defaults.compaction back out of a rendered
// config; nil when absent.
func compactionBlock(cfg map[string]any) map[string]any {
	agents, _ := cfg["agents"].(map[string]any)
	defaults, _ := agents["defaults"].(map[string]any)
	c, _ := defaults["compaction"].(map[string]any)
	return c
}

// The summary is written with the pin: a routed pin is named as the render
// files it, a built-in provider's is left to openclaw (and a routed leftover
// removed), an owner's overlay value stands until the overlay drops it, and a
// document with no provider leaves the key as it is.
func TestRenderSettings_NamesTheCompactionModel(t *testing.T) {
	useTempHome(t)
	model := func(cfg map[string]any) any { return compactionBlock(cfg)["model"] }
	withOverlay := func(s settings.Resolved, overlay string) settings.Resolved {
		s.Others = json.RawMessage(overlay)
		return s
	}
	for _, step := range []struct {
		name string
		s    settings.Resolved
		want any
	}{
		{"routed openai", routedSettings(inference.WireOpenAI, "glm-5.3"), "openai/glm-5.3"},
		{"routed anthropic", routedSettings(inference.WireAnthropic, "claude-sonnet-5"), "anthropic/claude-sonnet-5"},
		{"built-in provider", settings.Resolved{Doc: settings.Doc{Provider: "anthropic", Model: "sonnet"}}, nil},
		{"the overlay names one", withOverlay(routedSettings(inference.WireOpenAI, "glm-5.3"), `{"agents":{"defaults":{"compaction":{"model":"openai/cheap"}}}}`), "openai/cheap"},
		{"the overlay drops it", routedSettings(inference.WireOpenAI, "glm-5.3"), "openai/glm-5.3"},
		{"no provider", settings.Resolved{Doc: settings.Doc{Model: "other-model"}}, "openai/glm-5.3"},
	} {
		if got := model(renderInto(t, step.s)); got != step.want {
			t.Fatalf("%s: compaction.model = %v; want %v", step.name, got, step.want)
		}
	}
}

// An openclaw without `sessions compact` gets none of the compaction keys:
// they would only change its automatic compaction (2026.5.x allows 900s, not
// 180s). An overlay's own compaction keys still pass through.
func TestRenderSettings_OlderOpenclawGetsNoCompactionKeys(t *testing.T) {
	useTempHome(t)
	a := New()
	a.cfg = &config{framework: frameworkBinding{PackageVersion: "2026.5.7"}}
	s := routedSettings(inference.WireOpenAI, "glm-5.3")
	s.Others = json.RawMessage(`{"agents":{"defaults":{"compaction":{"reserveTokens":4000}}}}`)
	if err := a.RenderSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadOpenclawJSON()
	if err != nil {
		t.Fatal(err)
	}
	c := compactionBlock(cfg)
	for _, k := range []string{"keepRecentTokens", "timeoutSeconds", "model"} {
		if v, set := c[k]; set {
			t.Errorf("compaction.%s = %v on 2026.5.7; want it absent", k, v)
		}
	}
	if v, _ := c["reserveTokens"].(float64); v != 4000 {
		t.Errorf("the overlay's reserveTokens was lost: %v", c)
	}
}

// openclaw's "no work" answers come back as ok:false from the CLI; for the
// owner they are nothing to compact, not a failure.
func TestCompactSession_NoWorkIsNothingToCompact(t *testing.T) {
	for _, reason := range []string{"Already compacted", "Nothing to compact (session too small)"} {
		a := startedAdapter(t)
		stubCompactCLI(t, `{"ok":false,"compacted":false,"reason":"`+reason+`"}`, errors.New("exit status 1"))
		note, err := a.CompactSession(context.Background())
		if err != nil || !strings.Contains(note, "nothing to compact") || !strings.Contains(note, reason) {
			t.Fatalf("%q: note=%q err=%v; want a nothing-to-compact note", reason, note, err)
		}
	}
}

// openclaw fails any compaction after 180s by default; the render allows
// openclawCompactionTimeout, and an owner's positive value stands.
func TestRenderSettings_SetsCompactionTimeout(t *testing.T) {
	for _, tc := range []struct {
		name, overlay string
		want          int
	}{
		{"unset gets the platform's", "", openclawCompactionTimeout},
		{"the overlay's value stands", `{"agents":{"defaults":{"compaction":{"timeoutSeconds":300}}}}`, 300},
		{"an invalid value is replaced", `{"agents":{"defaults":{"compaction":{"timeoutSeconds":"10m"}}}}`, openclawCompactionTimeout},
		{"a fraction is replaced", `{"agents":{"defaults":{"compaction":{"timeoutSeconds":300.5}}}}`, openclawCompactionTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useTempHome(t)
			s := routedSettings(inference.WireOpenAI, "glm-5.3")
			if tc.overlay != "" {
				s.Others = json.RawMessage(tc.overlay)
			}
			cfg := renderInto(t, s)
			c := cfg["agents"].(map[string]any)["defaults"].(map[string]any)["compaction"].(map[string]any)
			if v, _ := c["timeoutSeconds"].(float64); int(v) != tc.want {
				t.Fatalf("timeoutSeconds = %v; want %d", c["timeoutSeconds"], tc.want)
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
