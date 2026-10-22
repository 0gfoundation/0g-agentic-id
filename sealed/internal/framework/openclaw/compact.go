package openclaw

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"seal-verify/internal/framework"
	"seal-verify/internal/privsep"
)

// compactCLITimeout bounds one `openclaw sessions compact` run. The gateway's
// summary takes one or more model calls (two in an offline run that split a
// turn) — 73s measured on a 270K-token glm-5.3 session (2026-10-19, openclaw
// 2026.7.1) — with headroom for a reasoning model on a longer history. The
// deadlines nest so the layer that knows why is the one that gives up:
// openclaw's own compaction timeout (rendered, openclawCompactionTimeout =
// 10m) < the CLI's --timeout (11m) < this (12m) < sealed's route deadline
// (proxy.compactTimeout, 15m).
const compactCLITimeout = 12 * time.Minute

// compactMinVersion is the first openclaw with a `sessions compact` CLI
// command. 2026.5.6 and 2026.5.7 — still whitelisted — register only
// `sessions cleanup` and `export-trajectory` (checked in their published
// dist, 2026-10-19).
const compactMinVersion = "2026.7.1"

// hasCompactCLI reports whether openclaw version has `sessions compact`. An
// unknown version (no framework binding restored) counts as having it: Start
// installs whitelistMax then.
func hasCompactCLI(version string) bool {
	return version == "" || compareVersions(version, compactMinVersion) >= 0
}

// packageVersion is the openclaw version this adapter installs and runs.
func (a *Adapter) packageVersion() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.cfg == nil {
		return ""
	}
	return a.cfg.framework.PackageVersion
}

// compactCLIWaitDelay bounds how long the CLI's output pipes may outlive the
// process once it has exited or been killed — the stopgap for any descendant
// that inherited them (see OPENCLAW_NO_RESPAWN in CompactSession).
var compactCLIWaitDelay = 5 * time.Second

// compactOutputMax bounds what sealed keeps of the CLI's stdout. The payload
// is one JSON object carrying the summary, far below this; the CLI reads the
// agent-writable openclaw home, so what it prints is the agent's to shape,
// and the rest is dropped (a cut payload reads as unreadable output).
const compactOutputMax = 1 << 20

// runCompactCLI runs the openclaw CLI with args, its environment extended by
// env, and returns its stdout. A var so tests can stub the CLI.
//
// As the agent user (privsep.AgentCommand), like the gateway and the config
// validator: the CLI reads the agent-writable openclaw home, and anything it
// writes there (device identity, caches) must stay the agent's. The binary
// comes from root-only PATH directories only.
var runCompactCLI = func(ctx context.Context, env []string, args ...string) ([]byte, error) {
	cmd, err := privsep.AgentCommand(ctx, "openclaw", args...)
	if err != nil {
		return nil, err
	}
	cmd.Env = append(cmd.Env, env...)
	cmd.WaitDelay = compactCLIWaitDelay
	stdout := &headBuffer{max: compactOutputMax}
	stderr := &tailBuffer{max: 400}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err = cmd.Run()
	if err != nil && len(stderr.b) > 0 {
		err = fmt.Errorf("%w: %s", err, tailString(string(stderr.b), 400))
	}
	return stdout.b, err
}

// headBuffer keeps the first max bytes written to it and drops the rest.
type headBuffer struct {
	max int
	b   []byte
}

func (w *headBuffer) Write(p []byte) (int, error) {
	if room := w.max - len(w.b); room > 0 {
		w.b = append(w.b, p[:min(len(p), room)]...)
	}
	return len(p), nil
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	max int
	b   []byte
}

func (w *tailBuffer) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	if over := len(w.b) - w.max; over > 0 {
		w.b = append(w.b[:0], w.b[over:]...)
	}
	return len(p), nil
}

// compactResult is the slice of the sessions.compact RPC payload this adapter
// reads (`openclaw sessions compact --json` prints the payload verbatim).
type compactResult struct {
	OK        bool   `json:"ok"`
	Compacted bool   `json:"compacted"`
	Reason    string `json:"reason"`
	Error     string `json:"error"`
	Result    *struct {
		TokensBefore *int `json:"tokensBefore"`
		TokensAfter  *int `json:"tokensAfter"`
		Details      *struct {
			Pending bool `json:"pending"`
		} `json:"details"`
	} `json:"result"`
}

// CompactSession implements framework.SessionCompactor through openclaw's own
// `openclaw sessions compact <key>`, which asks the RUNNING gateway
// (sessions.compact RPC) to compact the pinned session.
//
// What makes it take effect (verified offline against 2026.7.1 with a stub
// model, 2026-10-19): openclaw summarizes everything older than the tail it
// keeps verbatim (agents.defaults.compaction.keepRecentTokens) and appends a
// `compaction` record pointing at the first kept entry; the message lines
// stay in the file (`truncateAfterCompaction`, which would rotate it, is
// opt-in and off). The gateway builds each turn's model context from its own
// session — the summary, then the kept tail — and the stateful door adds no
// history of its own (conversation.go). The kept tail survives a MANUAL
// compaction only because the render sets keepRecentTokens
// (ensureCompactionDefaults): unset, openclaw rewrites the record to
// replay from the summary alone, and the tail — never summarized — is lost.
//
// The gateway listens on a non-default port, so the CLI needs a URL override,
// and openclaw refuses an override without explicit credentials ("config
// credentials are intentionally not reused"). Both go in as
// OPENCLAW_GATEWAY_URL / OPENCLAW_GATEWAY_TOKEN — the pairing the CLI asks
// for — which also keeps the token out of argv.
//
// The summary is written with the pinned model, not the one the session last
// ran on, for a routed pin: the render names it (setCompactionModel).
//
// An openclaw older than compactMinVersion has no `sessions compact` command
// at all → framework.ErrCompactUnsupported (501), before the CLI runs.
func (a *Adapter) CompactSession(ctx context.Context) (string, error) {
	a.mu.RLock()
	token := a.authToken
	a.mu.RUnlock()
	if token == "" {
		return "", fmt.Errorf("openclaw.CompactSession: gateway not started yet")
	}
	if version := a.packageVersion(); !hasCompactCLI(version) {
		return "", fmt.Errorf("openclaw.CompactSession: %w: openclaw %s has no `sessions compact`; it arrives in %s", framework.ErrCompactUnsupported, version, compactMinVersion)
	}
	// The state directory and home the gateway is given (stateEnv), not
	// ones resolved through the agent's ~/.openclaw link.
	env := append(stateEnv(),
		fmt.Sprintf("OPENCLAW_GATEWAY_URL=ws://127.0.0.1:%d", upstreamPort),
		"OPENCLAW_GATEWAY_TOKEN="+token,
		// Without NODE_OPTIONS the CLI re-executes itself (entry.respawn, to
		// add --disable-warning) as a DETACHED child that inherits stdout, so
		// killing the process we started leaves that child holding the pipe —
		// measured: still open 14s after the SIGKILL, when the probe stopped
		// watching; with this set it closed 28ms after. No respawn keeps the
		// CLI one killable process.
		"OPENCLAW_NO_RESPAWN=1",
	)
	ctx, cancel := context.WithTimeout(ctx, compactCLITimeout)
	defer cancel()
	// The CLI's own deadline sits a minute inside ours, so on a slow summary
	// the owner gets openclaw's timeout report rather than a killed process.
	out, runErr := runCompactCLI(ctx, env,
		"sessions", "compact", currentConversationKey(),
		"--json", "--timeout", strconv.FormatInt((compactCLITimeout-time.Minute).Milliseconds(), 10))

	var res compactResult
	if err := decodeCLIJSON(out, &res); err != nil {
		if runErr != nil {
			return "", fmt.Errorf("openclaw.CompactSession: %v", runErr)
		}
		return "", fmt.Errorf("openclaw.CompactSession: unreadable CLI output (%v): %s", err, tailString(string(out), 400))
	}
	if !res.OK {
		detail := res.Error
		if detail == "" {
			detail = res.Reason
		}
		if detail == "" {
			detail = "the gateway reported a failed compaction without a reason"
		}
		if isCompactRefusal(detail) {
			return "", fmt.Errorf("openclaw.CompactSession: %w: %s", framework.ErrCompactRefused, detail)
		}
		if isNothingToCompact(detail) {
			return "nothing to compact (" + detail + ")", nil
		}
		return "", fmt.Errorf("openclaw.CompactSession: %s", detail)
	}
	switch {
	case res.Compacted && res.Result != nil && res.Result.TokensAfter != nil:
		size := fmt.Sprintf("~%d tokens now", *res.Result.TokensAfter)
		if res.Result.TokensBefore != nil {
			size = fmt.Sprintf("~%d → ~%d tokens", *res.Result.TokensBefore, *res.Result.TokensAfter)
		}
		return "compacted: " + size + "; older history replaced by a summary, the most recent part kept as is", nil
	case res.Compacted:
		// openclaw leaves tokensAfter out when its estimate of the compacted
		// context comes out LARGER than before (or cannot be made) — what a
		// conversation that fits in the kept tail gets: a summary of nothing,
		// on top of the same history.
		return fmt.Sprintf("compaction recorded, but openclaw reports no smaller size: a conversation that fits in the recent part it keeps verbatim (~%d tokens) has nothing older to summarize", openclawKeepRecentTokens), nil
	case res.Result != nil && res.Result.Details != nil && res.Result.Details.Pending:
		return "compaction started; openclaw finishes it in the background", nil
	case res.Reason != "":
		return "nothing to compact (" + res.Reason + ")", nil
	default:
		return "nothing to compact", nil
	}
}

// isCompactRefusal reports whether a failed sessions.compact said "not now"
// rather than "failed" — the gateway's own wording (2026.7.1) for a session
// whose work did not drain in time ("Session <key> is still active; try
// again." / "…; try again in a moment.") or that changed before the
// compaction began ("Session <key> changed before compaction. Retry.").
// Neither compacted anything; the CLI relays the message verbatim in its
// JSON `error`. NOT "…changed before compaction completed. Retry.": that one
// comes after the summary was written, when only the session index update
// failed — a failure, not a refusal.
func isCompactRefusal(detail string) bool {
	return strings.Contains(detail, "is still active; try again") ||
		strings.Contains(detail, "changed before compaction. Retry.")
}

// isNothingToCompact reports a manual compaction's "no work" answers — 2026.7.1
// throws "Already compacted" when the session's last entry is a compaction
// and "Nothing to compact (session too small)" when nothing can be prepared.
// The CLI reports them as ok:false and exits 1 (measured: a /compact right
// after another); for the owner they mean nothing to do, not a failure.
func isNothingToCompact(detail string) bool {
	return strings.Contains(detail, "Already compacted") || strings.Contains(detail, "Nothing to compact")
}

// decodeCLIJSON decodes the first JSON object in the CLI's stdout, tolerating
// any line the CLI prints ahead of it — including one that itself contains a
// brace: each '{' is tried in turn until one starts a decodable object.
func decodeCLIJSON(out []byte, v any) error {
	err := fmt.Errorf("no JSON object")
	for off := 0; off < len(out); {
		i := bytes.IndexByte(out[off:], '{')
		if i < 0 {
			break
		}
		start := off + i
		// Validate into a RawMessage first, so a failed attempt can never
		// leave v half-filled for the next one.
		var raw json.RawMessage
		if err = json.NewDecoder(bytes.NewReader(out[start:])).Decode(&raw); err == nil {
			return json.Unmarshal(raw, v)
		}
		off = start + 1
	}
	return err
}

// tailString keeps the last n bytes of s, trimmed, for error messages.
func tailString(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}
