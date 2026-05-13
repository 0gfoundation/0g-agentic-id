package proxy

import (
	"fmt"
	"html"
	"net/http"
	"os"
	"regexp"
	"strings"

	"seal-verify/internal/logger"
)

// explorerBase is the 0G Galileo testnet block explorer; the rest of the
// stack (dashboard, user UI) uses the same host. Hard-coded for v0 since
// sealed runs a single chain; promote to env when we support multi-chain.
const explorerBase = "https://chainscan-galileo.0g.ai"

// hexLine carries the parsed shape of one log entry for HTML rendering:
// timestamp pulled out, body classified by leading tag, hex tokens turned
// into explorer-linked spans.
type hexLine struct {
	ts    string // "" if line has no [HH:MM:SS.mmm] prefix
	body  string // remainder after stripping timestamp
	class string // CSS class for body
}

var tsPrefix = regexp.MustCompile(`^\[(\d{2}:\d{2}:\d{2}\.\d{3})\]\s+`)

// txHash matches 0x + 64 hex (block / tx / data hashes / storage roots).
// addrHash matches 0x + 40 hex (eth addresses). Both link to chainscan.
var txHashRe = regexp.MustCompile(`0x[0-9a-fA-F]{64}`)
var addrHashRe = regexp.MustCompile(`\b0x[0-9a-fA-F]{40}\b`)

// handleLogHTML renders the in-memory bootstrap log as a color-coded HTML
// page. Hex tokens become clickable explorer links; timestamps render in
// a dimmed column so they don't compete with the event content.
func (s *Server) handleLogHTML(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, renderLogHTML("sealed bootstrap log", logger.Lines()))
}

func (s *Server) handleOpenclawLogHTML(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body, err := os.ReadFile("/tmp/openclaw.log")
	if err != nil {
		fmt.Fprint(w, renderLogHTML("openclaw log (unavailable)", []string{fmt.Sprintf("openclaw log not available: %v", err)}))
		return
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	fmt.Fprint(w, renderLogHTML("openclaw log", lines))
}

// parseLine splits the leading timestamp prefix from the rest and picks
// a CSS class for the body. Lines without a timestamp (e.g. openclaw's
// own log) render with an empty ts column.
func parseLine(line string) hexLine {
	var ts, body string
	if m := tsPrefix.FindStringSubmatchIndex(line); m != nil {
		ts = line[m[2]:m[3]]
		body = line[m[1]:]
	} else {
		body = line
	}
	return hexLine{ts: ts, body: body, class: classifyLine(body)}
}

// linkifyHex turns 64-hex (tx/dataHash) and 40-hex (address) tokens into
// explorer links. Display text is truncated to 0x<head6>...<tail4> so the
// log stays readable; full hex stays in the href + title attribute so
// click-to-copy / hover still surfaces it. Operates on already-escaped
// HTML, hence the manual rebuild rather than naive html.EscapeString.
func linkifyHex(escaped string) string {
	escaped = txHashRe.ReplaceAllStringFunc(escaped, func(h string) string {
		short := h[:8] + "..." + h[len(h)-4:]
		return fmt.Sprintf(`<a class="hex" href="%s/tx/%s" target="_blank" rel="noopener" title="%s">%s</a>`, explorerBase, h, h, short)
	})
	escaped = addrHashRe.ReplaceAllStringFunc(escaped, func(h string) string {
		short := h[:6] + "..." + h[len(h)-4:]
		return fmt.Sprintf(`<a class="hex" href="%s/address/%s" target="_blank" rel="noopener" title="%s">%s</a>`, explorerBase, h, h, short)
	})
	return escaped
}

// renderLogHTML builds the full <html> page. Each line gets a CSS class
// chosen by classifyLine; auto-refreshes every 3s so the page stays live
// without WebSocket plumbing.
func renderLogHTML(title string, lines []string) string {
	var b strings.Builder
	b.Grow(len(lines)*120 + 1024)
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8">`)
	b.WriteString(`<meta http-equiv="refresh" content="3">`)
	b.WriteString(`<title>`)
	b.WriteString(html.EscapeString(title))
	b.WriteString(`</title><style>` + logCSS + `</style></head><body>`)
	b.WriteString(`<header><span class="title">`)
	b.WriteString(html.EscapeString(title))
	b.WriteString(`</span><span class="meta">auto-refresh 3s &middot; `)
	b.WriteString(fmt.Sprintf("%d lines", len(lines)))
	b.WriteString(`</span></header><div id="log">`)
	for _, raw := range lines {
		l := parseLine(raw)
		b.WriteString(`<div class="row `)
		b.WriteString(l.class)
		b.WriteString(`">`)
		b.WriteString(`<span class="ts">`)
		b.WriteString(html.EscapeString(l.ts))
		b.WriteString(`</span>`)
		b.WriteString(`<span class="body">`)
		b.WriteString(linkifyHex(html.EscapeString(l.body)))
		b.WriteString(`</span></div>`)
	}
	b.WriteString(`</div>`)
	// Scroll to bottom on every refresh so the latest entry stays visible.
	b.WriteString(`<script>window.scrollTo(0,document.body.scrollHeight);</script>`)
	b.WriteString(`</body></html>`)
	return b.String()
}

// classifyLine returns a CSS class name based on the message body's
// leading tag (after the timestamp prefix has been stripped).
func classifyLine(body string) string {
	trim := strings.TrimSpace(body)
	if trim == "" {
		return "muted"
	}
	if strings.HasPrefix(trim, "---") {
		return "section"
	}
	switch {
	case strings.HasPrefix(trim, "FAIL"):
		return "fail"
	case strings.HasPrefix(trim, "OK"):
		return "ok"
	case strings.HasPrefix(trim, "iData chain uploaded") ||
		strings.HasPrefix(trim, "chain.Update") ||
		strings.HasPrefix(trim, "0g-storage upload OK"):
		return "chain"
	case strings.HasPrefix(trim, "iData drift") ||
		strings.HasPrefix(trim, "drift:") ||
		strings.HasPrefix(trim, "uploader.Push"):
		return "drift"
	case strings.HasPrefix(trim, "watcher:"):
		return "watcher"
	case strings.HasPrefix(trim, "manager:"):
		return "manager"
	case strings.HasPrefix(trim, "openclaw"):
		return "openclaw"
	case strings.HasPrefix(trim, "bootstrap[") ||
		strings.HasPrefix(trim, "bootstrap:") ||
		strings.HasPrefix(trim, "ALL DONE"):
		return "boot"
	}
	return "default"
}

// logCSS matches the dashboard palette (web/dashboard.html :root tokens):
// pure-white surface, oklch neutrals, 0g purple accent, Syne/Roboto Mono
// typography. Embeds Google Fonts so an unmounted /log.html still renders
// with the correct family (the rest of the dashboard relies on a CDN tag).
const logCSS = `
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@500;600;700&family=Roboto+Mono:wght@400;500&display=swap');
:root {
  color-scheme: light;
  --p:      oklch(72% 0.22 310);
  --pd:     oklch(62% 0.24 310);
  --pbg:    oklch(96% 0.05 310);
  --text:   oklch(14% 0 0);
  --text2:  oklch(40% 0 0);
  --muted:  oklch(52% 0 0);
  --border: oklch(91% 0 0);
  --bg:     oklch(100% 0 0);
  --surf:   oklch(100% 0 0);
  --surf2:  oklch(97.5% 0 0);
  --green:  oklch(44% 0.15 145);
  --red:    oklch(42% 0.18 25);
  --orange: oklch(57% 0.16 55);
  --blue:   oklch(52% 0.18 250);
  --sans: 'Syne', -apple-system, sans-serif;
  --mono: 'Roboto Mono', ui-monospace, 'Courier New', monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: var(--mono); font-size: 13px; background: var(--bg); color: var(--text); line-height: 1.6; -webkit-font-smoothing: antialiased; }
header { position: sticky; top: 0; padding: 14px 24px; background: var(--surf); border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; z-index: 10; }
header .title { font-family: var(--sans); font-weight: 700; font-size: 15px; letter-spacing: -0.02em; color: var(--text); }
header .meta { color: var(--muted); font-size: 11px; font-family: var(--sans); font-weight: 500; text-transform: uppercase; letter-spacing: 0.07em; }
#log { padding: 18px 24px; }
.row { display: grid; grid-template-columns: 86px 1fr; gap: 14px; padding: 1px 0; align-items: baseline; }
.row .ts { color: var(--muted); font-size: 11.5px; font-variant-numeric: tabular-nums; }
.row .body { white-space: pre-wrap; word-break: break-word; color: var(--text2); }
.row.section { padding: 16px 0 4px; }
.row.section .body { color: var(--text); font-family: var(--sans); font-weight: 700; font-size: 14px; letter-spacing: -0.01em; }
.row.muted .body { color: var(--muted); }
.row.ok .body { color: var(--green); }
.row.fail .body { color: var(--red); font-weight: 500; }
.row.chain .body { color: var(--pd); }
.row.drift .body { color: var(--p); }
.row.watcher .body { color: var(--muted); }
.row.manager .body { color: var(--orange); }
.row.openclaw .body { color: var(--blue); }
.row.boot .body { color: var(--text); font-family: var(--sans); font-weight: 600; }
a.hex { color: var(--pd); text-decoration: none; border-bottom: 1px dashed oklch(72% 0.22 310 / 0.5); transition: background 120ms ease, border-color 120ms ease; padding: 0 1px; border-radius: 2px; }
a.hex:hover { background: var(--pbg); border-bottom-color: var(--p); }
`
