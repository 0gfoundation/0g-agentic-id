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
	const unsubscribe = session.subscribe((event) => {
		if (event.type === "message_update") {
			const e = event.assistantMessageEvent;
			if (!e || e.type !== "text_delta" || typeof e.delta !== "string") return;
			full += e.delta;
			if (onDelta) onDelta(e.delta);
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
		await session.prompt(text);
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

	if (body.stream) {
		res.writeHead(200, {
			"content-type": "text/event-stream",
			"cache-control": "no-cache",
			connection: "keep-alive",
		});
		res.write(chunkFrame(id, model, { role: "assistant" }));
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
		const beat = setInterval(() => res.write(": keepalive\n\n"), 10_000);

		const started = Date.now();
		broadcastActivity({ turn: id, kind: "turn_start", text: text.slice(0, 200) });
		let failure = null;
		try {
			await serialize(() =>
				runTurn(
					session,
					text,
					(delta) => res.write(chunkFrame(id, model, { content: delta })),
					(line, type) => {
						log(`  ${line}`);
						broadcastActivity({ turn: id, kind: type, text: line });
					},
				),
			);
		} catch (err) {
			failure = String((err && err.message) || err);
		} finally {
			clearInterval(beat);
		}

		const secs = Math.round((Date.now() - started) / 1000);
		if (failure) {
			// The status line went out with the first byte, so a mid-turn failure
			// can only ever truncate the body. Say so explicitly instead: an error
			// frame plus finish_reason="error", so a client that reads either can
			// tell a failed turn from a short answer. (Surfacing this through
			// AgentClient.chatStream, which yields text only, needs an SDK change.)
			log(`turn FAILED after ${secs}s: ${failure}`);
			broadcastActivity({ turn: id, kind: "turn_failed", text: failure });
			res.write(`data: ${JSON.stringify({ id, object: "chat.completion.chunk", created: created(), model, error: { message: failure } })}\n\n`);
			res.write(chunkFrame(id, model, {}, "error"));
		} else {
			log(`turn done in ${secs}s (streamed)`);
			broadcastActivity({ turn: id, kind: "turn_end", text: `${secs}s` });
			res.write(chunkFrame(id, model, {}, "stop"));
		}
		res.write("data: [DONE]\n\n");
		return res.end();
	}

	const t0 = Date.now();
	broadcastActivity({ turn: id, kind: "turn_start", text: text.slice(0, 200) });
	const full = await serialize(() =>
		runTurn(session, text, null, (line, type) => {
			log(`  ${line}`);
			broadcastActivity({ turn: id, kind: type, text: line });
		}),
	);
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

	return sendJSON(res, 404, { error: { message: `no route for ${req.method} ${path}` } });
});

server.listen(PORT, "127.0.0.1", () => log(`listening on 127.0.0.1:${PORT}`));
