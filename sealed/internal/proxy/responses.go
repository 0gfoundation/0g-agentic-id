// Synthesized OpenAI Responses API (subset) — the proxy-level long-task
// surface for frameworks whose chat API couples the turn to one HTTP
// connection.
//
// chat/completions dies with its connection, and connections die for reasons
// that are not the owner's intent: the sandbox preview proxy hard-caps request
// duration (~300s on mainnet, 0g-sandbox#122), laptops sleep, networks blip.
// The prime and dsh bridges solve this natively (they declare a Route with
// Kind "responses" and the proxy just forwards). openclaw and hermes cannot:
// at the pinned versions their servers either lack the surface (openclaw
// 2026.7.1: POST-only wire format, no retrieve/resume/cancel) or give it the
// opposite semantics (hermes v2026.7.20: client disconnect on the responses
// stream calls agent.interrupt()). So when the adapter does NOT declare a
// native "responses" route, the proxy synthesizes one here, in front of the
// framework's own /v1/chat/completions on the container-local loopback —
// where no request-duration cap exists:
//
//	POST /v1/responses {input}                  → JSON {id, status}; the
//	                                              SDK's primary path — submit
//	                                              and follow are separate so
//	                                              the id exists before any
//	                                              long-lived byte
//	POST /v1/responses {input, stream:true}     → SSE; first event carries id
//	GET  /v1/responses/{id}                     → poll {status, output_text}
//	GET  /v1/responses/{id}?stream=true&starting_after=N
//	                                            → replay events > N, then live
//	POST /v1/responses/{id}/cancel              → cancel the running turn
//
// The turn is owned by a server-side response record, not by any client
// connection. Cancel aborts the UPSTREAM request — and both openclaw
// (watchClientDisconnect → AbortController) and hermes (disconnect →
// agent.interrupt) treat their client vanishing as an interrupt, which is
// exactly the semantic we want pointed inward.
//
// Auth: these endpoints bypass the framework's own bearer check, so the proxy
// enforces it — the presented token must equal the adapter's AuthResponse
// token (the same credential /_seal/auth hands a verified owner, and the one
// the framework itself would have required).
//
// Records live in a bounded in-memory ring: they survive client disconnects,
// not container restarts — the framework's own session state is the durable
// record. Event shapes mirror the prime/dsh bridge implementation so SDK
// clients see one protocol regardless of which layer serves it.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"seal-verify/internal/logger"
)

const (
	// synthMaxRecords bounds the ring of retained responses.
	synthMaxRecords = 16
	// synthMaxEvents bounds the retained event log per response (~1MB of
	// delta text). Older events fall off: a resume whose starting_after
	// precedes the horizon replays only what remains — the deltas beyond the
	// horizon are gone from the stream, and GET /{id}'s snapshot
	// (output_text) is the way to recover the full text (review B3).
	synthMaxEvents = 4096
	// synthKeepalive is the SSE comment cadence on follower streams.
	synthKeepalive = 10 * time.Second
)

type synthEvent struct {
	Seq  int
	Name string
	Data map[string]any
}

type synthRecord struct {
	id string

	mu        sync.Mutex
	status    string // queued | in_progress | completed | failed | cancelled
	seq       int
	events    []synthEvent
	output    strings.Builder
	errMsg    string
	listeners map[chan synthEvent]struct{}
	cancel    context.CancelFunc
}

type synthHub struct {
	mu    sync.Mutex
	byID  map[string]*synthRecord
	order []string
}

func newSynthHub() *synthHub {
	return &synthHub{byID: map[string]*synthRecord{}}
}

func (h *synthHub) create() *synthRecord {
	buf := make([]byte, 12)
	_, _ = rand.Read(buf)
	rec := &synthRecord{
		id:        "resp_" + hex.EncodeToString(buf),
		status:    "queued",
		listeners: map[chan synthEvent]struct{}{},
	}
	h.mu.Lock()
	h.byID[rec.id] = rec
	h.order = append(h.order, rec.id)
	for len(h.order) > synthMaxRecords {
		old := h.order[0]
		h.order = h.order[1:]
		delete(h.byID, old)
	}
	h.mu.Unlock()
	return rec
}

func (h *synthHub) get(id string) *synthRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.byID[id]
}

// push appends an event and notifies live followers. A follower whose buffer
// is full (stalled consumer: GC pause, slow link, laptop sleep) is DETACHED
// and its channel closed rather than silently skipped — a silent skip would
// leave an undetectable hole in the text (review B2). The closed channel ends
// that follower's stream without a terminal event, and the client resumes
// with starting_after, replaying what it missed from the retained log.
func (r *synthRecord) push(name string, data map[string]any) {
	r.mu.Lock()
	r.seq++
	evt := synthEvent{Seq: r.seq, Name: name, Data: data}
	r.events = append(r.events, evt)
	if len(r.events) > synthMaxEvents {
		r.events = r.events[len(r.events)-synthMaxEvents:]
	}
	for ch := range r.listeners {
		select {
		case ch <- evt:
		default:
			delete(r.listeners, ch)
			close(ch)
		}
	}
	r.mu.Unlock()
}

func (r *synthRecord) snapshot() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]any{
		"id":          r.id,
		"object":      "response",
		"status":      r.status,
		"output_text": r.output.String(),
	}
	if r.errMsg != "" {
		out["error"] = map[string]any{"message": r.errMsg}
	}
	return out
}

func (r *synthRecord) terminal() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status == "completed" || r.status == "failed" || r.status == "cancelled"
}

func synthTerminalEvent(name string) bool {
	return name == "response.completed" || name == "response.failed"
}

// ── HTTP surface ────────────────────────────────────────────────────────────

var synthIDPath = regexp.MustCompile(`^/v1/responses/(resp_[0-9a-f]+)(/cancel)?$`)

// nativeResponsesDeclared reports whether the adapter itself serves a
// Responses surface (prime/dsh bridges declare Kind "responses"); the proxy
// then forwards instead of synthesizing.
func (s *Server) nativeResponsesDeclared() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, rt := range s.fwRoutes {
		if rt.Kind == "responses" {
			return true
		}
	}
	return false
}

// handleSynthResponses serves /v1/responses* when no native route exists.
// chatUpstream is the framework's chat backend (the /v1/ route's backend or
// the adapter's single upstream).
func (s *Server) handleSynthResponses(w http.ResponseWriter, r *http.Request, chatUpstream string) {
	token, err := s.adapterAuthToken(r.Context())
	if err != nil {
		http.Error(w, "framework credential not available: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !synthBearerOK(r, token) {
		writeSynthJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{"message": "bearer token required"}})
		return
	}

	if r.Method == http.MethodPost && r.URL.Path == "/v1/responses" {
		s.handleSynthCreate(w, r, chatUpstream, token)
		return
	}
	if m := synthIDPath.FindStringSubmatch(r.URL.Path); m != nil {
		rec := s.synth.get(m[1])
		if rec == nil {
			writeSynthJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{
				"message": fmt.Sprintf("no such response %s (the proxy keeps the last %d)", m[1], synthMaxRecords)}})
			return
		}
		switch {
		case r.Method == http.MethodPost && m[2] == "/cancel":
			rec.mu.Lock()
			cancel := rec.cancel
			if rec.status == "queued" || rec.status == "in_progress" {
				rec.status = "cancelled"
			}
			rec.mu.Unlock()
			if cancel != nil {
				cancel() // drops the upstream request; the framework treats that as an interrupt
			}
			logger.Logf("responses: %s cancelled by owner", rec.id)
			writeSynthJSON(w, http.StatusOK, rec.snapshot())
		case r.Method == http.MethodGet && m[2] == "":
			q := r.URL.Query()
			if q.Get("stream") == "true" {
				after, _ := strconv.Atoi(q.Get("starting_after"))
				s.streamSynthRecord(w, r, rec, after)
				return
			}
			writeSynthJSON(w, http.StatusOK, rec.snapshot())
		default:
			writeSynthJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": map[string]any{"message": "method not allowed"}})
		}
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleSynthCreate(w http.ResponseWriter, r *http.Request, chatUpstream, token string) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeSynthJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{"message": "read body: " + err.Error()}})
		return
	}
	// reasoning.{effort} is deliberately ABSENT from this struct: the synth
	// layer fronts frameworks whose chat surfaces take no per-request level
	// (openclaw's schema field is decorative, hermes reads global config), so
	// a per-message effort here would be a silent no-op pretending otherwise.
	// The field is dropped at THIS layer — the one place all such traffic
	// passes — which is what makes it safe for clients to always send it.
	var body struct {
		Input  json.RawMessage `json:"input"`
		Stream bool            `json:"stream"`
		Model  string          `json:"model"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		writeSynthJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{"message": "invalid JSON body"}})
		return
	}
	text := synthInputText(body.Input)
	if text == "" {
		writeSynthJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{"message": "input is required (string or messages-style items)"}})
		return
	}

	rec := s.synth.create()
	go s.runSynthTurn(rec, chatUpstream, token, body.Input, body.Model)
	logger.Logf("responses: %s accepted (%.60s…)", rec.id, text)

	if body.Stream {
		s.streamSynthRecord(w, r, rec, 0)
		return
	}
	writeSynthJSON(w, http.StatusOK, rec.snapshot())
}

// runSynthTurn drives one framework turn under a response record: POST the
// framework's own chat/completions (streaming) on loopback and translate its
// SSE into Responses events. The upstream connection belongs to this
// goroutine, not to any client.
func (s *Server) runSynthTurn(rec *synthRecord, chatUpstream, token string, input json.RawMessage, model string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec.mu.Lock()
	rec.cancel = cancel
	if rec.status == "queued" {
		rec.status = "in_progress"
	}
	alreadyCancelled := rec.status == "cancelled"
	rec.mu.Unlock()
	rec.push("response.created", map[string]any{"type": "response.created", "response": rec.snapshot()})
	if alreadyCancelled {
		rec.push("response.completed", map[string]any{"type": "response.completed", "response": rec.snapshot()})
		return
	}

	fail := func(msg string) {
		rec.mu.Lock()
		if rec.status != "cancelled" {
			rec.status = "failed"
			rec.errMsg = msg
		}
		rec.mu.Unlock()
		rec.push("response.failed", map[string]any{"type": "response.failed", "response": rec.snapshot()})
		logger.Logf("responses: %s failed: %s", rec.id, msg)
	}

	payload := map[string]any{
		"messages": synthInputMessages(input),
		"stream":   true,
	}
	if model != "" {
		payload["model"] = model
	}
	reqBody, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, chatUpstream+"/v1/chat/completions", bytes.NewReader(reqBody))
	if err != nil {
		fail("build upstream request: " + err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			rec.push("response.completed", map[string]any{"type": "response.completed", "response": rec.snapshot()})
			return
		}
		fail("upstream: " + err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		fail(fmt.Sprintf("upstream %d: %.500s", resp.StatusCode, string(msg)))
		return
	}

	if err := s.consumeChatSSE(rec, resp.Body); err != nil {
		if ctx.Err() != nil {
			// Owner cancelled: the dropped upstream connection IS the interrupt.
			rec.push("response.completed", map[string]any{"type": "response.completed", "response": rec.snapshot()})
			return
		}
		fail(err.Error())
		return
	}
	rec.mu.Lock()
	if rec.status == "in_progress" {
		rec.status = "completed"
	}
	rec.mu.Unlock()
	rec.push("response.completed", map[string]any{"type": "response.completed", "response": rec.snapshot()})
	logger.Logf("responses: %s finished (%s)", rec.id, rec.snapshot()["status"])
}

// consumeChatSSE translates one OpenAI chat SSE stream into record events:
// delta.content → response.output_text.delta; named events and tool_calls →
// response.activity; an explicit error frame fails the turn. Returns nil at
// [DONE]/EOF.
func (s *Server) consumeChatSSE(rec *synthRecord, body io.Reader) error {
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	eventName := ""
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			eventName = ""
		case strings.HasPrefix(line, ": activity "):
			// prime/dsh bridge convention (not used when they serve natively,
			// but kept so any comment-style progress becomes a real event).
			rec.push("response.activity", map[string]any{"type": "response.activity", "label": strings.TrimPrefix(line, ": activity ")})
		case strings.HasPrefix(line, ":"):
			// other SSE comment (keepalive) — ignore
		case strings.HasPrefix(line, "event: "):
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event: "))
		case strings.HasPrefix(line, "data: "):
			data := strings.TrimPrefix(line, "data: ")
			if strings.TrimSpace(data) == "[DONE]" {
				return nil
			}
			if eventName != "" && eventName != "message" {
				// Named event (e.g. hermes.tool.progress {tool_name}): surface
				// as activity so followers see tool progress.
				var d map[string]any
				if json.Unmarshal([]byte(data), &d) == nil {
					label, _ := d["tool_name"].(string)
					if label == "" {
						label = eventName
					}
					rec.push("response.activity", map[string]any{"type": "response.activity", "label": label})
				}
				continue
			}
			var chunk struct {
				Error *struct {
					Message string `json:"message"`
				} `json:"error"`
				Choices []struct {
					Delta struct {
						Content   string `json:"content"`
						ToolCalls []struct {
							Function struct {
								Name string `json:"name"`
							} `json:"function"`
						} `json:"tool_calls"`
					} `json:"delta"`
				} `json:"choices"`
			}
			if json.Unmarshal([]byte(data), &chunk) != nil {
				continue
			}
			if chunk.Error != nil && chunk.Error.Message != "" {
				return fmt.Errorf("%s", chunk.Error.Message)
			}
			for _, c := range chunk.Choices {
				if c.Delta.Content != "" {
					rec.mu.Lock()
					rec.output.WriteString(c.Delta.Content)
					next := rec.seq + 1
					rec.mu.Unlock()
					rec.push("response.output_text.delta", map[string]any{
						"type": "response.output_text.delta", "delta": c.Delta.Content, "sequence_number": next,
					})
				}
				for _, tc := range c.Delta.ToolCalls {
					if tc.Function.Name != "" {
						rec.push("response.activity", map[string]any{"type": "response.activity", "label": "tool " + tc.Function.Name})
					}
				}
			}
		}
	}
	return sc.Err()
}

// streamSynthRecord writes the record to the client as SSE from sequence >
// startingAfter: replay the retained log, then follow live until a terminal
// event. The client dropping this stream affects nothing but the stream.
func (s *Server) streamSynthRecord(w http.ResponseWriter, r *http.Request, rec *synthRecord, startingAfter int) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeSynthJSON(w, http.StatusInternalServerError, map[string]any{"error": map[string]any{"message": "streaming unsupported"}})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	// Paired with the "accepted" line — see the bridges' equivalent: accepted
	// without "stream open" localizes the failure to this layer.
	logger.Logf("responses: %s stream open (from seq %d)", rec.id, startingAfter)

	write := func(evt synthEvent) {
		data := make(map[string]any, len(evt.Data)+1)
		for k, v := range evt.Data {
			data[k] = v
		}
		data["sequence_number"] = evt.Seq
		buf, _ := json.Marshal(data)
		fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", evt.Seq, evt.Name, buf)
		fl.Flush()
	}

	// Subscribe BEFORE replaying so no event falls between log and live; the
	// seen-cursor suppresses the overlap.
	ch := make(chan synthEvent, 256)
	rec.mu.Lock()
	rec.listeners[ch] = struct{}{}
	replay := make([]synthEvent, len(rec.events))
	copy(replay, rec.events)
	rec.mu.Unlock()
	defer func() {
		rec.mu.Lock()
		delete(rec.listeners, ch)
		rec.mu.Unlock()
	}()

	seen := startingAfter
	done := false
	for _, evt := range replay {
		if evt.Seq <= seen {
			continue
		}
		write(evt)
		seen = evt.Seq
		if synthTerminalEvent(evt.Name) {
			done = true
		}
	}
	if done || rec.terminal() {
		return
	}

	beat := time.NewTicker(synthKeepalive)
	defer beat.Stop()
	beats := 0 // numbered so a client trace can tell "none" from "first N then silence"
	for {
		select {
		case <-r.Context().Done():
			return
		case <-beat.C:
			beats++
			fmt.Fprintf(w, ": keepalive %d\n\n", beats)
			fl.Flush()
		case evt, ok := <-ch:
			if !ok {
				// Detached by push() as a lagging consumer: end the stream
				// WITHOUT a terminal event so the client reconnects with
				// starting_after and replays the hole from the log.
				return
			}
			if evt.Seq <= seen {
				continue
			}
			write(evt)
			seen = evt.Seq
			if synthTerminalEvent(evt.Name) {
				return
			}
		}
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

// adapterAuthToken extracts the framework bearer credential from the
// adapter's AuthResponse payload (every shipped adapter returns {token: …} —
// the same value /_seal/auth hands a verified owner).
func (s *Server) adapterAuthToken(ctx context.Context) (string, error) {
	adapter := s.getAdapter()
	if adapter == nil {
		return "", fmt.Errorf("framework adapter not resolved yet")
	}
	payload, err := adapter.AuthResponse(ctx)
	if err != nil {
		return "", err
	}
	if m, ok := payload.(map[string]any); ok {
		if tok, ok := m["token"].(string); ok && tok != "" {
			return tok, nil
		}
	}
	return "", fmt.Errorf("adapter auth payload carries no token")
}

func synthBearerOK(r *http.Request, token string) bool {
	h := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return false
	}
	return strings.TrimSpace(h[len(prefix):]) == token
}

// synthInputMessages returns the conversation to forward upstream. THE FULL
// history, not just the last user message: the synth layer fronts frameworks
// whose chat surfaces are stateless per request — hermes reconstructs the
// conversation from the request body, so dropping history gave every turn
// amnesia (live: the agent forgot the previous turn entirely). String input
// becomes a single user message; items pass through with their roles.
//
// TEXT history only, a documented limitation (review): items without a
// role/content text form — function_call / function_call_output / reasoning
// items, image-only parts — are dropped, so in tool-heavy conversations the
// upstream model does not see earlier tool RESULTS, only what was said about
// them. Rendering tool items into messages would need per-framework dialect
// choices; revisit if it bites.
func synthInputMessages(input json.RawMessage) []map[string]any {
	if len(input) == 0 {
		return nil
	}
	var s string
	if json.Unmarshal(input, &s) == nil {
		if s == "" {
			return nil
		}
		return []map[string]any{{"role": "user", "content": s}}
	}
	var items []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(input, &items) != nil {
		return nil
	}
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		role := it.Role
		if role == "" {
			role = "user"
		}
		var text string
		if json.Unmarshal(it.Content, &text) != nil {
			var parts []struct {
				Text string `json:"text"`
			}
			if json.Unmarshal(it.Content, &parts) == nil {
				for _, p := range parts {
					if p.Text == "" {
						continue // empty parts contribute nothing, not a newline
					}
					if text != "" {
						text += "\n"
					}
					text += p.Text
				}
			}
		}
		if text == "" {
			continue
		}
		out = append(out, map[string]any{"role": role, "content": text})
	}
	return out
}

// synthInputText extracts the last user text from a Responses `input` — used
// for the record's prompt label and request validation only. Delegates to
// synthInputMessages so the label and the upstream payload can never diverge
// (review: two parallel parsers drift).
func synthInputText(input json.RawMessage) string {
	msgs := synthInputMessages(input)
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i]["role"] == "user" {
			if t, _ := msgs[i]["content"].(string); t != "" {
				return t
			}
		}
	}
	return ""
}

func writeSynthJSON(w http.ResponseWriter, status int, body map[string]any) {
	buf, _ := json.Marshal(body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf)
}
