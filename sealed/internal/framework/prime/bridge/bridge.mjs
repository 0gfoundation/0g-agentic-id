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
 *   - The platform/doctrine text is injected here, in code, via the SDK's
 *     agentsFilesOverride. It is read from SEAL_AGENT_DOC (outside the
 *     framework home) and handed to the session as a virtual context file, so
 *     it never lands in a chain-tracked path and the agent's own
 *     rlm.harness.delete_prompt_note — which operates on harness entries, a
 *     different mechanism — cannot remove it.
 *   - APPEND_SYSTEM.md is NOT overridden: the DefaultResourceLoader appends it
 *     natively, and that file is the owner-persona role. Leaving the default
 *     alone is what makes the mint-time persona take effect.
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

import {
	AuthStorage,
	createAgentSession,
	DefaultResourceLoader,
	getAgentDir,
	ModelRegistry,
} from "@earendil-works/pi-coding-agent";

const PORT = Number(process.env.SEAL_BRIDGE_PORT || "8791");
const TOKEN = process.env.SEAL_BRIDGE_TOKEN || "";
const AGENT_DOC = process.env.SEAL_AGENT_DOC || "";
const PROVIDER = process.env.SEAL_MODEL_PROVIDER || "";
const MODEL_ID = process.env.SEAL_MODEL_ID || "";
const API_KEY = process.env.SEAL_MODEL_API_KEY || "";

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

async function resolveModel(modelRegistry) {
	if (PROVIDER && MODEL_ID) {
		const pinned = modelRegistry.find(PROVIDER, MODEL_ID);
		if (pinned) return pinned;
		log(`WARN pinned model ${PROVIDER}/${MODEL_ID} not in the registry; falling back to first available`);
	}
	const available = await modelRegistry.getAvailable();
	if (!available.length) {
		throw new Error("no model available (no valid API key, or the pinned model is unknown)");
	}
	return available[0];
}

async function buildSession() {
	const authStorage = AuthStorage.create();
	// Runtime override: not persisted to disk (SDK example 09). The key comes
	// from the owner's deploy envelope via sealed's RuntimeContext.
	if (PROVIDER && API_KEY) authStorage.setRuntimeApiKey(PROVIDER, API_KEY);
	const modelRegistry = ModelRegistry.create(authStorage);

	const doc = readAgentDoc();
	const loader = new DefaultResourceLoader({
		cwd: process.cwd(),
		agentDir: getAgentDir(),
		// Inject the sealed platform doc as a virtual context file. Note there
		// is no appendSystemPromptOverride here on purpose: the default picks up
		// APPEND_SYSTEM.md, which is the owner-persona role.
		agentsFilesOverride: (current) => ({
			agentsFiles: doc
				? [...current.agentsFiles, { path: "/virtual/0G-PLATFORM.md", content: doc }]
				: current.agentsFiles,
		}),
	});
	await loader.reload();

	const model = await resolveModel(modelRegistry);
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
async function runTurn(session, text, onDelta) {
	let full = "";
	const unsubscribe = session.subscribe((event) => {
		if (event.type !== "message_update") return;
		const e = event.assistantMessageEvent;
		if (!e || e.type !== "text_delta" || typeof e.delta !== "string") return;
		full += e.delta;
		if (onDelta) onDelta(e.delta);
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
		await serialize(() => runTurn(session, text, (delta) => res.write(chunkFrame(id, model, { content: delta }))));
		res.write(chunkFrame(id, model, {}, "stop"));
		res.write("data: [DONE]\n\n");
		return res.end();
	}

	const full = await serialize(() => runTurn(session, text, null));
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
