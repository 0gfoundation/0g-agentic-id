/**
 * sealed ↔ Prime Agent HTTP bridge.
 *
 * Prime Agent ships a daemon-backed CLI whose public transport is a
 * JSONL-framed local socket; sealed's :8080 proxy can only forward HTTP. This
 * bridge is the sealed-owned HTTP surface, and it embeds the SDK directly
 * (createAgentSession) rather than talking to the CLI daemon — so there is
 * exactly one framework process to supervise and no second protocol hop.
 *
 * Because sealed authors this file, the exposed surface is a whitelist by
 * construction: one OpenAI-shaped chat endpoint, nothing else. There is no
 * dashboard, file browser or exec endpoint to fence off.
 *
 * Deliberate properties, each load-bearing:
 *
 *   - The platform/doctrine text is injected here, in code, from SEAL_AGENT_DOC
 *     (a path outside the framework home) into BOTH the system prompt (the
 *     authoritative channel) and a virtual context file (belt). It therefore
 *     never lands in a chain-tracked path, and the agent's own
 *     rlm.harness.delete_prompt_note — which operates on harness entries, a
 *     different store — cannot remove it. See buildSession for why both.
 *   - The owner persona (APPEND_SYSTEM.md) is preserved by spreading the SDK's
 *     own append list rather than replacing it; replacing would silently drop
 *     the mint-time persona.
 *   - The inference API key arrives via authStorage.setRuntimeApiKey(), which
 *     the SDK documents as not persisted to disk. The key therefore never
 *     touches a tracked path, so unlike a config-file framework there is no
 *     secret to strip before iData.
 *   - Requests are serialized. An SDK session is a single conversation; this
 *     is the owner↔agent steering channel, so queueing is right and
 *     interleaving two turns onto one session would corrupt both.
 *
 * Run: node bridge.mjs   (plain ESM — no build step in the image)
 */

import { createServer } from "node:http";
import { readFileSync } from "node:fs";

// The official release package (`prime-agent`), installed globally in the
// image. NOT the @earendil-works/pi-coding-agent npm package: that one ships
// the TypeScript half only — zero .py files — while the harness state this
// adapter anchors on chain is written by Python in the IPython kernel. The
// release tarball carries both halves and exports the same SDK surface.
import {
	AuthStorage,
	createAgentSession,
	DefaultResourceLoader,
	getAgentDir,
	ModelRegistry,
} from "prime-agent";

const PORT = Number(process.env.SEAL_BRIDGE_PORT || "8791");
const TOKEN = process.env.SEAL_BRIDGE_TOKEN || "";
const AGENT_DOC = process.env.SEAL_AGENT_DOC || "";
const PROVIDER = process.env.SEAL_MODEL_PROVIDER || "";
const MODEL_ID = process.env.SEAL_MODEL_ID || "";
const API_KEY = process.env.SEAL_MODEL_API_KEY || "";
// Set when the model is served by an OpenAI/Anthropic-compatible endpoint that
// is NOT the provider's own (the 0G compute router). Then the model has to be
// REGISTERED (models.json), which the adapter writes as a tracked role.
const MODEL_BASE_URL = process.env.SEAL_MODEL_BASE_URL || "";
const MODEL_API = process.env.SEAL_MODEL_API || "openai-completions";

if (!TOKEN) {
	console.error("bridge: SEAL_BRIDGE_TOKEN is required (it gates /v1/*)");
	process.exit(2);
}

const log = (...args) => console.log(`[bridge] ${args.join(" ")}`);

// ── Session ─────────────────────────────────────────────────────────────────

let sessionPromise = null;

function readAgentDoc() {
	if (!AGENT_DOC) return null;
	try {
		return readFileSync(AGENT_DOC, "utf8");
	} catch (err) {
		// A missing doc must not stop the agent from serving; it does mean the
		// platform context is absent, which is worth shouting about.
		log(`WARN could not read agent doc ${AGENT_DOC}: ${err.message}`);
		return null;
	}
}

// models.json (the model registration) is written by the ADAPTER, not here: it
// is a chain-tracked role, so sealed owns it and Restore lands it before this
// process starts. The registry picks it up from the agent dir automatically.

/**
 * Resolve the pinned model, and FAIL if it cannot be resolved.
 *
 * Deliberately no fallback to "first available": that silently ran a model the
 * owner never chose (it picked openai/gpt-4 for a 0g-compute/glm-5.2 pin), which
 * is both wrong and hard to see — the inference pin is part of the agent's
 * on-chain identity, so substituting it must be an error, not a warning.
 */
function resolveModel(modelRegistry) {
	if (!PROVIDER || !MODEL_ID) {
		throw new Error("no model pinned: SEAL_MODEL_PROVIDER and SEAL_MODEL_ID are required");
	}
	const pinned = modelRegistry.find(PROVIDER, MODEL_ID);
	if (!pinned) {
		throw new Error(
			`pinned model ${PROVIDER}/${MODEL_ID} is not resolvable` +
				(MODEL_BASE_URL ? ` even after registering ${MODEL_BASE_URL}` : " (no base URL given, so it must be a built-in)"),
		);
	}
	return pinned;
}

async function buildSession() {
	const agentDir = getAgentDir();
	const authStorage = AuthStorage.create();
	// Also hand the key over at runtime (not persisted). Native providers need
	// this; for a registered custom provider the models.json entry resolves the
	// key from the environment instead.
	if (PROVIDER && API_KEY) authStorage.setRuntimeApiKey(PROVIDER, API_KEY);
	const modelRegistry = ModelRegistry.create(authStorage);

	const doc = readAgentDoc();
	const loader = new DefaultResourceLoader({
		cwd: process.cwd(),
		agentDir,
		// The platform doc goes into BOTH channels, deliberately:
		//
		//   1. appendSystemPromptOverride — the AUTHORITATIVE channel. This is
		//      the lesson of the retired claudecode port (FRAMEWORK_ADAPTER.md
		//      §12 item 24): identity injected into a framework's *memory* or
		//      *context* channel reads as advisory, and a safety-tuned model
		//      disclaimed its own agentSeal identity live because of it. The
		//      sign-refusal doctrine must not be advisory.
		//   2. agentsFilesOverride — belt. A context file survives prompt
		//      surgery the harness might perform on itself and costs nothing.
		//
		// `(base) => [...base, doc]` and not `() => [doc]`: base already carries
		// APPEND_SYSTEM.md, which is the owner-persona role. Replacing the list
		// would silently drop the owner's mint-time persona. The doc goes LAST
		// so platform mechanics are the final word in the system prompt — owner
		// persona is legitimate, but it does not get to override the doctrine.
		appendSystemPromptOverride: (base) => (doc ? [...base, doc] : base),
		agentsFilesOverride: (current) => ({
			agentsFiles: doc
				? [...current.agentsFiles, { path: "/virtual/0G-PLATFORM.md", content: doc }]
				: current.agentsFiles,
		}),
	});
	await loader.reload();

	const model = resolveModel(modelRegistry);
	log(`model resolved: ${model.provider}/${model.id}`);
	const { session } = await createAgentSession({
		model,
		resourceLoader: loader,
		authStorage,
		modelRegistry,
	});
	log(`session ready (platform doc: ${doc ? `${doc.length} bytes` : "ABSENT"})`);
	return session;
}

function getSession() {
	if (!sessionPromise) {
		sessionPromise = buildSession().catch((err) => {
			sessionPromise = null; // let the next request retry a failed build
			throw err;
		});
	}
	return sessionPromise;
}

// ── Activity stream ─────────────────────────────────────────────────────────
//
// The owner↔agent channel is a declared route, so what the owner can observe is
// this adapter's business — and a turn that runs tools for 87 seconds while the
// chat stream stays silent is indistinguishable from a dead one. `/activity`
// carries what the turn is actually doing.
//
// Deliberately a SEPARATE route rather than extra fields in the chat payload: a
// route declares its `kind`, so a client knows what it is getting, whereas a
// private field inside a standard chunk is something other clients cannot read
// (an earlier attempt did exactly that and was reverted).

const activityClients = new Set();

function broadcastActivity(event) {
	const frame = `data: ${JSON.stringify({ ...event, ts: Date.now() })}\n\n`;
	for (const res of activityClients) {
		try {
			res.write(frame);
		} catch {
			activityClients.delete(res); // client went away mid-write
		}
	}
}

function handleActivity(req, res) {
	res.writeHead(200, {
		"content-type": "text/event-stream",
		"cache-control": "no-cache",
		connection: "keep-alive",
	});
	if (typeof res.flushHeaders === "function") res.flushHeaders();
	activityClients.add(res);
	res.write(`data: ${JSON.stringify({ kind: "subscribed", text: "activity stream open", ts: Date.now() })}\n\n`);
	// Same reason as the chat stream: a stretch with no events must still put
	// bytes on the wire or an idle-timeout hop closes a healthy connection.
	const beat = setInterval(() => {
		try {
			res.write(": keepalive\n\n");
		} catch {
			/* cleaned up by the close handler */
		}
	}, 10_000);
	req.on("close", () => {
		clearInterval(beat);
		activityClients.delete(res);
	});
}

// ── Turn serialization ──────────────────────────────────────────────────────

let tail = Promise.resolve();
function serialize(fn) {
	const run = tail.then(fn, fn);
	// Keep the chain alive regardless of individual failures.
	tail = run.then(
		() => undefined,
		() => undefined,
	);
	return run;
}

// ── OpenAI wire shapes ──────────────────────────────────────────────────────

const created = () => Math.floor(Date.now() / 1000);

function chunkFrame(id, model, delta, finish) {
	return `data: ${JSON.stringify({
		id,
		object: "chat.completion.chunk",
		created: created(),
		model,
		choices: [{ index: 0, delta, finish_reason: finish ?? null }],
	})}\n\n`;
}

function completionBody(id, model, content) {
	return {
		id,
		object: "chat.completion",
		created: created(),
		model,
		choices: [{ index: 0, message: { role: "assistant", content }, finish_reason: "stop" }],
	};
}

/**
 * Condense one session event into a short activity line.
 *
 * Deliberately defensive about payload shape: the event union is large
 * (tool_execution_*, bash_*, compaction_*, auto_retry_*, refine_*,
 * rlm_child_update, …) and its fields are not part of any contract we control,
 * so this reads a few likely names and otherwise falls back to the type alone.
 * A progress line is worth degrading; it is never worth crashing a turn over.
 */
function activityLine(event) {
	const t = event?.type;
	if (!t || t === "message_update") return null;
	const pick = (...keys) => {
		for (const k of keys) {
			const v = event[k] ?? event?.detail?.[k] ?? event?.data?.[k];
			if (typeof v === "string" && v.trim()) return v.trim().slice(0, 120);
			if (typeof v === "number") return String(v);
		}
		return "";
	};
	const detail = pick("command", "name", "tool", "toolName", "title", "reason", "id");
	return detail ? `${t} — ${detail}` : t;
}

/** The prompt text for this turn: the last user message's content. */
function lastUserText(messages) {
	if (!Array.isArray(messages)) return "";
	for (let i = messages.length - 1; i >= 0; i--) {
		const m = messages[i];
		if (!m || m.role !== "user") continue;
		if (typeof m.content === "string") return m.content;
		if (Array.isArray(m.content)) {
			return m.content
				.filter((b) => b && b.type === "text" && typeof b.text === "string")
				.map((b) => b.text)
				.join("\n");
		}
	}
	return "";
}

// ── Request handling ────────────────────────────────────────────────────────

function readBody(req) {
	return new Promise((resolve, reject) => {
		const parts = [];
		req.on("data", (c) => parts.push(c));
		req.on("end", () => resolve(Buffer.concat(parts).toString("utf8")));
		req.on("error", reject);
	});
}

function sendJSON(res, status, body) {
	const payload = JSON.stringify(body);
	res.writeHead(status, {
		"content-type": "application/json",
		"content-length": Buffer.byteLength(payload),
	});
	res.end(payload);
}

function authorized(req) {
	const header = req.headers.authorization || "";
	const prefix = "bearer ";
	if (!header.toLowerCase().startsWith(prefix)) return false;
	return header.slice(prefix.length).trim() === TOKEN;
}

/**
 * Run one turn, forwarding assistant text as it is generated. onDelta may be
 * called many times; the resolved value is the full concatenated text.
 */
async function runTurn(session, text, onDelta, onActivity) {
	let full = "";
	let lastThinkingAt = 0;
	// Per-assistant-message accounting for the message_end backfill: `full` is
	// cumulative across the whole turn, so compare each message only against
	// what streamed SINCE ITS OWN message_start — a turn with two assistant
	// messages where the second isn't streamed must still backfill the second
	// (review F3).
	let msgStartLen = 0;
	// Extract plain text from a prime message's content (array of {type,text}
	// blocks, or a bare string).
	const messageText = (message) => {
		const content = message?.content;
		if (typeof content === "string") return content;
		if (Array.isArray(content)) {
			return content.map((b) => (b && b.type === "text" && typeof b.text === "string" ? b.text : "")).join("");
		}
		return "";
	};
	const unsubscribe = session.subscribe((event) => {
		if (event.type === "message_update") {
			const e = event.assistantMessageEvent;
			if (e && e.type === "text_delta" && typeof e.delta === "string") {
				full += e.delta;
				if (onDelta) onDelta(e.delta);
				return;
			}
			// A non-text message_update is the model THINKING (reasoning deltas —
			// prime's reasoning-capable models emit these before any answer). Like
			// dsh, surface it as a throttled "thinking" activity so a long silent
			// pre-answer phase isn't mistaken for a hang. Throttle: reasoning
			// fires many deltas/sec.
			if (e && onActivity && /reason|think/i.test(e.type || "")) {
				const now = Date.now();
				if (now - lastThinkingAt > 2000) { lastThinkingAt = now; onActivity("thinking", "thinking"); }
			}
			return;
		}
		// message_end carries the COMPLETE assistant message. Some models (or
		// non-streaming provider paths) deliver the answer here rather than as
		// incremental text_delta — in which case the loop above forwarded
		// nothing and the turn looks empty ("stream ended without output").
		// Backfill: if this assistant message's text wasn't already streamed,
		// forward whatever text_delta didn't cover. Diagnostic-logged so we can
		// see, per turn, whether text arrived via deltas or only here.
		if (event.type === "message_start" && event.message?.role === "assistant") {
			msgStartLen = full.length;
			return;
		}
		if (event.type === "message_end" && event.message?.role === "assistant") {
			const whole = messageText(event.message);
			const streamed = full.slice(msgStartLen);
			log(`message_end: role=assistant textLen=${whole.length} streamedLen=${streamed.length}`);
			if (whole && !streamed) { if (onDelta) onDelta(whole); full += whole; }
			else if (whole && streamed && whole.length > streamed.length && whole.startsWith(streamed)) {
				const tail = whole.slice(streamed.length);
				if (onDelta) onDelta(tail); full += tail;
			}
			msgStartLen = full.length;
			return;
		}
		// Everything else is turn progress. An agent turn spends most of its time
		// NOT producing assistant text — it thinks, runs tools, spawns subagents —
		// so without this the stream is silent for minutes and an idle-timeout hop
		// in front of the agent drops a connection that was working fine.
		const line = activityLine(event);
		if (line && onActivity) onActivity(line, event.type);
	});
	try {
		// streamingBehavior is REQUIRED by prime whenever a turn may already be
		// in flight (the SDK rejects an un-annotated prompt with "Agent is
		// already processing"). Our own serialize() chain can still race prime's
		// server-side turn state — e.g. a prior turn aborted/truncated on the
		// client but is still running in prime — so always annotate. "followUp"
		// queues behind the running turn (don't drop the owner's message, don't
		// interrupt work in progress); queueIfBusy/resumeIfIdle make the enqueue
		// robust whether prime is mid-turn or idle-with-backlog.
		await session.prompt(text, {
			streamingBehavior: "followUp",
			queueIfBusy: true,
			resumeIfIdle: true,
		});
	} finally {
		// subscribe() may return an unsubscribe function or nothing; tolerate both
		// so a stale listener can't leak deltas into the next turn.
		if (typeof unsubscribe === "function") unsubscribe();
	}
	return full;
}

async function handleChat(req, res) {
	const raw = await readBody(req);
	let body;
	try {
		body = JSON.parse(raw || "{}");
	} catch {
		return sendJSON(res, 400, { error: { message: "invalid JSON body" } });
	}

	const text = lastUserText(body.messages);
	if (!text) {
		return sendJSON(res, 400, { error: { message: "no user message in `messages`" } });
	}

	const session = await getSession();
	const id = `chatcmpl-${created()}`;
	const model = body.model || `${PROVIDER || "prime"}/${MODEL_ID || "default"}`;

	// Interrupt: closing the HTTP connection is the OpenAI-conventional cancel
	// signal. The SDK session exposes abort() — stop the turn when the client
	// goes away, guarded so a QUEUED request's disconnect never aborts someone
	// else's active turn (turns are serialized), which also un-blocks the queue.
	let myTurnActive = false;
	let disconnected = false;
	const onGone = () => {
		if (disconnected) return;
		disconnected = true;
		if (myTurnActive) {
			// session.abort(): Promise<void> — verified against the installed SDK
			// (dist/core/agent-session.d.ts). Guarded anyway: on an SDK where it
			// is absent the turn must keep its old run-to-completion behaviour
			// with a loud log, not a TypeError.
			if (typeof session.abort === "function") {
				log("client disconnected mid-turn — aborting");
				Promise.resolve(session.abort()).catch((err) => log(`WARN session.abort: ${(err && err.message) || err}`));
			} else {
				log("WARN client disconnected mid-turn but this SDK exposes no session.abort() — turn continues server-side");
			}
		}
	};
	res.on("close", () => { if (!res.writableEnded) onGone(); });
	// Writes after a disconnect throw (incl. from the keepalive interval, where
	// an exception would take the bridge down) — guard every write.
	const safeWrite = (s) => {
		if (disconnected || res.writableEnded || res.destroyed) return;
		try { res.write(s); } catch { /* client raced us to the close */ }
	};
	const runMine = (fn) => serialize(() => {
		if (disconnected) return "";
		myTurnActive = true;
		return Promise.resolve(fn()).finally(() => { myTurnActive = false; });
	});

	if (body.stream) {
		res.writeHead(200, {
			"content-type": "text/event-stream",
			"cache-control": "no-cache",
			connection: "keep-alive",
		});
		safeWrite(chunkFrame(id, model, { role: "assistant" }));
		if (typeof res.flushHeaders === "function") res.flushHeaders();

		// Keepalive as SSE COMMENTS, and nothing else on the wire.
		//
		// An agent turn spends most of its time not producing assistant text — it
		// thinks, runs tools, spawns subagents — so this stream is legitimately
		// silent for minutes, and silence is what makes an idle-timeout hop in
		// front of the agent drop a connection that is working fine.
		//
		// Comments are part of the SSE format and every parser skips them
		// (including this SDK's), so they keep the response standard: a client
		// sees exactly the text frames it would see from any OpenAI-compatible
		// server. Turn activity is NOT put on the wire — chat/completions has no
		// standard slot for it, and inventing a private field would make our
		// payload something other clients cannot read. It goes to the bridge log
		// instead, where /log/agent surfaces it for debugging. Reporting progress
		// to a client properly wants a Responses-shaped surface; that is its own
		// piece of work.
		const beat = setInterval(() => safeWrite(": keepalive\n\n"), 10_000);

		const started = Date.now();
		broadcastActivity({ turn: id, kind: "turn_start", text: text.slice(0, 200) });
		let failure = null;
		try {
			await runMine(() =>
				runTurn(
					session,
					text,
					(delta) => safeWrite(chunkFrame(id, model, { content: delta })),
					(line, type) => {
						log(`  ${line}`);
						broadcastActivity({ turn: id, kind: type, text: line });
						// Also ride the chat stream as an SSE COMMENT so the owner's
						// CLI can render a ⚙ status line — a prime turn is mostly
						// silent (thinking, tools, subagents) and an un-narrated
						// stream looks dead. Mirrors the dsh bridge's `: activity`.
						// SSE comments are ignored by any spec-compliant client that
						// doesn't opt in, so this is backward-safe.
						safeWrite(`: activity ${line}\n\n`);
					},
				),
			);
		} catch (err) {
			failure = String((err && err.message) || err);
		} finally {
			clearInterval(beat);
		}

		const secs = Math.round((Date.now() - started) / 1000);
		if (disconnected) {
			log(`turn ended after ${secs}s (client disconnected)`);
			broadcastActivity({ turn: id, kind: "turn_aborted", text: `${secs}s` });
			return res.destroyed ? undefined : res.end();
		}
		if (failure) {
			// The status line went out with the first byte, so a mid-turn failure
			// can only ever truncate the body. Say so explicitly instead: an error
			// frame plus finish_reason="error", so a client that reads either can
			// tell a failed turn from a short answer. (Surfacing this through
			// AgentClient.chatStream, which yields text only, needs an SDK change.)
			log(`turn FAILED after ${secs}s: ${failure}`);
			broadcastActivity({ turn: id, kind: "turn_failed", text: failure });
			safeWrite(`data: ${JSON.stringify({ id, object: "chat.completion.chunk", created: created(), model, error: { message: failure } })}\n\n`);
			safeWrite(chunkFrame(id, model, {}, "error"));
		} else {
			log(`turn done in ${secs}s (streamed)`);
			broadcastActivity({ turn: id, kind: "turn_end", text: `${secs}s` });
			safeWrite(chunkFrame(id, model, {}, "stop"));
		}
		safeWrite("data: [DONE]\n\n");
		return res.end();
	}

	const t0 = Date.now();
	broadcastActivity({ turn: id, kind: "turn_start", text: text.slice(0, 200) });
	const full = await runMine(() =>
		runTurn(session, text, null, (line, type) => {
			log(`  ${line}`);
			broadcastActivity({ turn: id, kind: type, text: line });
		}),
	);
	if (disconnected) {
		log("turn ended (client disconnected, buffered)");
		return;
	}
	const buffered = Math.round((Date.now() - t0) / 1000);
	log(`turn done in ${buffered}s (buffered)`);
	broadcastActivity({ turn: id, kind: "turn_end", text: `${buffered}s` });
	return sendJSON(res, 200, completionBody(id, model, full));
}

const server = createServer((req, res) => {
	const path = (req.url || "").split("?")[0];

	// Loopback-only liveness/readiness for sealed's probes. NOT reachable from
	// outside: the proxy forwards /v1/ only.
	if (req.method === "GET" && path === "/healthz") {
		res.writeHead(200, { "content-type": "text/plain" });
		return res.end("ok");
	}

	if (!authorized(req)) {
		return sendJSON(res, 401, { error: { message: "bearer token required" } });
	}

	if (req.method === "GET" && path === "/activity") {
		return handleActivity(req, res);
	}

	if (req.method === "POST" && path === "/v1/chat/completions") {
		return handleChat(req, res).catch((err) => {
			log(`ERROR ${err && err.stack ? err.stack : err}`);
			if (res.headersSent) return res.end();
			sendJSON(res, 500, { error: { message: String((err && err.message) || err) } });
		});
	}

	// Owner's brake pedal: unconditionally abort the CURRENT turn, whoever
	// started it. This is what makes Esc mean "stop the task" rather than
	// "stop watching" — and the only way (short of /reset) to stop an orphaned
	// turn whose originating connection is gone. Aborting is not a rollback:
	// tool calls already executed stay executed; the turn just stops issuing
	// new ones. Queued follow-ups survive and run next.
	if (req.method === "POST" && path === "/v1/interrupt") {
		return (async () => {
			try {
				const session = await getSession();
				// Stopping a prime turn, done right. Two synchronous steps, NO
				// awaiting — every wedge we hit came from waiting on something
				// that never completes:
				//   1. requestAbort() — SYNCHRONOUS and immediate: aborts the bash
				//      AbortController (killProcessTree on the detached group),
				//      aborts the agent/model call, cancels the turn, and suspends
				//      the input pump (_sessionInputPumpSuspended=true).
				//   2. resumeQueuedWork() — SYNCHRONOUS: lifts that suspension so
				//      the next message is admitted. The pump otherwise only
				//      auto-resumes on a NON-streaming prompt, and our chat is
				//      streaming (followUp), so without this every later message
				//      is silently swallowed.
				// NOT abort(): abort() = requestAbort() + await waitForIdle(). If
				// the turn is stuck (bash mid-syscall, model retry) waitForIdle
				// never resolves, so a resume chained after it never runs — the
				// session wedges until /reset. requestAbort already did the actual
				// stopping; the idle wait buys us nothing but a hang.
				if (typeof session.requestAbort === "function" && typeof session.resumeQueuedWork === "function") {
					// Guard the PAIR: requestAbort suspends the input pump and only
					// resumeQueuedWork lifts it — an SDK bump that renames one but
					// not the other must fall through to abort() (safe alone), not
					// wedge the session (review F1).
					session.requestAbort();
					// requestAbort() stops the main loop + bash, but NOT spawned
					// subagents — a task like "stand up a service" delegates work
					// to RLM child runs that keep going after requestAbort (prime's
					// own comment: the child's terminal update "is delayed
					// indefinitely when the child is stuck mid-stream, which is
					// exactly when users reach for the kill"). abort() cancels them
					// via _cancelActiveRlmChildRuns; replicate that here — it's
					// synchronous — instead of calling abort() (which then awaits
					// waitForIdle and hangs). Underscore = private-by-convention,
					// not enforced; guard so an SDK bump that renames it degrades.
					if (typeof session._cancelActiveRlmChildRuns === "function") {
						try { session._cancelActiveRlmChildRuns("interrupted by owner"); }
						catch (e) { log(`interrupt: cancel child runs failed: ${(e && e.message) || e}`); }
					}
					session.resumeQueuedWork();
					// Record the interruption IN THE TRANSCRIPT. Aborting kills the
					// in-flight calls, but the model's context still shows a task
					// half-done — on the next message it happily resumes the work
					// (observed live: post-interrupt turns kept running ipython to
					// finish the cancelled task while the owner's new message waited).
					// A custom message makes the cancellation visible to the model,
					// same as the CLI's own "[interrupted]" transcript marker. This
					// relays the OWNER's action — mechanism, not behavioral steering.
					if (typeof session.sendCustomMessage === "function") {
						session.sendCustomMessage(
							{
								customType: "owner_interrupt",
								content: "[The owner interrupted the current task. Stop working on it — do not resume it unless the owner asks again. Await the owner's next message.]",
								display: true,
							},
							{ deliverAs: "nextTurn" },
						).catch((e) => log(`interrupt: sendCustomMessage failed: ${(e && e.message) || e}`));
					}
					log("interrupt: requestAbort + cancelChildRuns + resumeQueuedWork by owner");
					return sendJSON(res, 200, { ok: true, aborted: true });
				}
				if (typeof session.abort === "function") {
					session.abort().catch((e) => log(`interrupt: abort() rejected: ${(e && e.message) || e}`));
					log("interrupt: abort() invoked by owner (no requestAbort)");
					return sendJSON(res, 200, { ok: true, aborted: true });
				}
				return sendJSON(res, 200, { ok: true, aborted: false, note: "this SDK exposes no abort" });
			} catch (err) {
				return sendJSON(res, 500, { error: { message: String((err && err.message) || err) } });
			}
		})();
	}

	return sendJSON(res, 404, { error: { message: `no route for ${req.method} ${path}` } });
});

server.listen(PORT, "127.0.0.1", () => log(`listening on 127.0.0.1:${PORT}`));
