import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";

const TOKEN = "test-bridge-token";
const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";

async function freePort() {
	const server = createServer();
	server.listen(0, "127.0.0.1");
	await once(server, "listening");
	const { port } = server.address();
	server.close();
	await once(server, "close");
	return port;
}

async function waitFor(fn, message, timeout = 3000) {
	const deadline = Date.now() + timeout;
	let value;
	while (Date.now() < deadline) {
		value = await fn();
		if (value) return value;
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
	throw new Error(`${message}: ${JSON.stringify(value)}`);
}

async function startBridge(t) {
	const root = await mkdtemp(join(tmpdir(), "prime-bridge-test-"));
	const packageDir = join(root, "node_modules", "prime-agent");
	await mkdir(packageDir, { recursive: true });
	const logPath = join(root, "sdk.jsonl");
	const resourcePath = join(root, "persona-skills.txt");
	await writeFile(join(packageDir, "package.json"), JSON.stringify({ name: "prime-agent", type: "module", exports: "./index.mjs" }));
	await writeFile(join(packageDir, "index.mjs"), `
import { appendFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
const path = process.env.MOCK_SDK_LOG;
const write = (event) => appendFile(path, JSON.stringify(event) + "\\n");
let next = 0;
class Session {
  constructor() { this.id = ++next; this.listeners = new Set(); this.history = []; this.aborted = false; this.resources = readFileSync(process.env.MOCK_RESOURCES, "utf8"); }
  subscribe(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }
  setThinkingLevel() {}
  async prompt(text) {
    this.aborted = false; this.history.push(text); await write({ event: "start", session: this.id, text });
    const delay = text.startsWith("slow") ? 300 : 15;
    for (let elapsed = 0; elapsed < delay; elapsed += 5) {
      await new Promise((resolve) => setTimeout(resolve, 5));
      if (this.aborted) { await write({ event: "stopped", session: this.id, text }); throw new Error("aborted"); }
    }
    const output = "s" + this.id + ":" + this.history.join("|");
    for (const fn of this.listeners) fn({ type: "message_start", message: { role: "assistant" } });
    for (const fn of this.listeners) fn({ type: "message_update", assistantMessageEvent: { type: "text_delta", delta: output } });
    for (const fn of this.listeners) fn({ type: "message_end", message: { role: "assistant", content: output } });
    await write({ event: "end", session: this.id, text });
  }
  requestAbort() { this.aborted = true; void write({ event: "abort", session: this.id }); }
  resumeQueuedWork() {}
  _cancelActiveRlmChildRuns() {}
  sendCustomMessage() { return Promise.resolve(); }
  async reload() { this.resources = readFileSync(process.env.MOCK_RESOURCES, "utf8"); await write({ event: "reload", session: this.id, resources: this.resources, history: [...this.history] }); }
  async dispose() { await write({ event: "dispose", session: this.id }); }
}
export const AuthStorage = { create: () => ({ setRuntimeApiKey() {} }) };
export const ModelRegistry = { create: () => ({ find: () => ({ provider: "mock", id: "model" }) }) };
export class DefaultResourceLoader { async reload() {} }
export const getAgentDir = () => process.cwd();
export const SessionManager = { inMemory: (cwd, sessionDir) => ({ cwd, sessionDir, inMemory: true }) };
export async function createAgentSession(options) { const session = new Session(); await write({ event: "create", session: session.id, rlmSessionDir: options.rlmSessionDir, manager: options.sessionManager }); return { session }; }
`);
	await writeFile(logPath, "");
	await writeFile(resourcePath, "persona-v1|skills-v1");
	await writeFile(join(root, "bridge.mjs"), await readFile(new URL("./bridge.mjs", import.meta.url)));
	const port = await freePort();
	const child = spawn(process.execPath, [join(root, "bridge.mjs")], {
		cwd: root,
		env: {
			...process.env,
			SEAL_BRIDGE_PORT: String(port),
			SEAL_BRIDGE_TOKEN: TOKEN,
			SEAL_MODEL_PROVIDER: "mock",
			SEAL_MODEL_ID: "model",
			MOCK_SDK_LOG: logPath,
			MOCK_RESOURCES: resourcePath,
		},
		stdio: ["ignore", "pipe", "pipe"],
	});
	let output = "";
	child.stdout.on("data", (chunk) => { output += chunk; });
	child.stderr.on("data", (chunk) => { output += chunk; });
	const base = `http://127.0.0.1:${port}`;
	await waitFor(async () => fetch(`${base}/healthz`).then((r) => r.ok).catch(() => false), "bridge did not start");
	t.after(async () => {
		child.kill("SIGTERM");
		await Promise.race([once(child, "exit"), new Promise((resolve) => setTimeout(resolve, 1000))]);
		await rm(root, { recursive: true, force: true });
	});
	const request = async (path, options = {}) => {
		const response = await fetch(base + path, {
			...options,
			headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json", ...options.headers },
		});
		const body = await response.json();
		return { status: response.status, body };
	};
	const events = async () => (await readFile(logPath, "utf8")).trim().split("\n").filter(Boolean).map(JSON.parse);
	return { request, events, output, resourcePath };
}

async function completed(request, id) {
	return waitFor(async () => {
		const result = await request(`/v1/responses/${id}`);
		return result.body.status === "completed" || result.body.status === "cancelled" || result.body.status === "failed" ? result : null;
	}, `response ${id} did not finish`);
}

test("explicit sessions isolate conversations, queues, cancellation, reload, and disposal", async (t) => {
	const { request, events, resourcePath } = await startBridge(t);

	assert.equal((await request("/v1/sessions", { method: "POST", body: "{}" })).status, 400);
	assert.equal((await request("/v1/sessions", { method: "POST", body: JSON.stringify({ id: "NOT-A-UUID" }) })).status, 400);
	assert.equal((await request("/v1/sessions", { method: "POST", body: JSON.stringify({ id: A }) })).status, 201);
	assert.equal((await request("/v1/sessions", { method: "POST", body: JSON.stringify({ id: A }) })).status, 200);
	assert.equal((await request("/v1/sessions", { method: "POST", body: JSON.stringify({ id: B }) })).status, 201);
	const raceID = "44444444-4444-4444-8444-444444444444";
	const raced = await Promise.all([
		request("/v1/sessions", { method: "POST", body: JSON.stringify({ id: raceID }) }),
		request("/v1/sessions", { method: "POST", body: JSON.stringify({ id: raceID }) }),
	]);
	assert.deepEqual(raced.map((result) => result.status).sort(), [200, 201]);
	assert.equal((await request(`/v1/sessions/${raceID}`, { method: "DELETE" })).status, 200);

	const submit = (session_id, input) => request("/v1/responses", {
		method: "POST",
		body: JSON.stringify({ session_id, input }),
	});
	const a1 = await submit(A, "a1");
	const b1 = await submit(B, "b1");
	const [a1Done, b1Done] = await Promise.all([completed(request, a1.body.id), completed(request, b1.body.id)]);
	assert.equal(a1Done.body.session_id, A);
	assert.equal(b1Done.body.session_id, B);
	assert.match(a1Done.body.output_text, /^s\d+:a1$/);
	assert.match(b1Done.body.output_text, /^s\d+:b1$/);
	assert.notEqual(a1Done.body.output_text.slice(0, 2), b1Done.body.output_text.slice(0, 2));
	const creates = (await events()).filter((e) => e.event === "create");
	assert.equal(creates.length, 2);
	assert.ok(creates.every((e) => e.manager?.inMemory && e.rlmSessionDir === e.manager.sessionDir));
	assert.notEqual(creates[0].rlmSessionDir, creates[1].rlmSessionDir);

	const a2 = await submit(A, "a2");
	const b2 = await submit(B, "b2");
	assert.match((await completed(request, a2.body.id)).body.output_text, /^s\d+:a1\|a2$/);
	assert.match((await completed(request, b2.body.id)).body.output_text, /^s\d+:b1\|b2$/);
	const chat = await request("/v1/chat/completions", {
		method: "POST",
		body: JSON.stringify({ session_id: A, messages: [{ role: "user", content: "chat-a" }] }),
	});
	assert.equal(chat.status, 200);
	assert.match(chat.body.choices[0].message.content, /^s\d+:a1\|a2\|chat-a$/);
	await writeFile(resourcePath, "persona-v2|skills-v2");
	assert.equal((await request(`/v1/sessions/${A}/reload`, { method: "POST" })).status, 200);
	const afterReload = await submit(A, "after-reload");
	assert.match((await completed(request, afterReload.body.id)).body.output_text, /^s\d+:a1\|a2\|chat-a\|after-reload$/);
	assert.deepEqual((await events()).find((e) => e.event === "reload"), {
		event: "reload",
		session: creates.find((e) => e.rlmSessionDir === creates[0].rlmSessionDir).session,
		resources: "persona-v2|skills-v2",
		history: ["a1", "a2", "chat-a"],
	});

	const unknown = "33333333-3333-4333-8333-333333333333";
	assert.equal((await submit(unknown, "missing")).status, 404);
	assert.equal((await request("/v1/chat/completions", { method: "POST", body: JSON.stringify({ session_id: unknown, messages: [{ role: "user", content: "missing" }] }) })).status, 404);

	const slowA = await submit(A, "slow-a");
	const afterA = await submit(A, "after-a");
	const slowB = await submit(B, "slow-b");
	const queuedB = await submit(B, "queued-b");
	await waitFor(async () => (await events()).filter((e) => e.event === "start" && /^slow-/.test(e.text)).length === 2, "different sessions did not run concurrently");
	assert.equal((await request(`/v1/sessions/${A}`, { method: "DELETE" })).status, 409);
	assert.equal((await request(`/v1/sessions/${A}/reload`, { method: "POST" })).status, 409);
	assert.equal((await request(`/v1/responses/${queuedB.body.id}/cancel`, { method: "POST" })).status, 200);
	assert.equal((await completed(request, queuedB.body.id)).body.status, "cancelled");
	assert.equal((await request(`/v1/responses/${slowA.body.id}/cancel`, { method: "POST" })).status, 200);
	assert.equal((await completed(request, slowA.body.id)).body.status, "cancelled");
	assert.equal((await completed(request, afterA.body.id)).body.status, "completed");
	assert.equal((await completed(request, slowB.body.id)).body.status, "completed");
	const aborted = (await events()).filter((e) => e.event === "abort").map((e) => e.session);
	assert.equal(aborted.length, 1);

	await waitFor(async () => (await request(`/v1/sessions/${A}`)).body.status === "available", "cancelled session stayed busy");
	assert.equal((await request(`/v1/sessions/${A}`, { method: "DELETE" })).status, 200);
	assert.equal((await request(`/v1/sessions/${A}`)).status, 404);
	assert.equal((await request(`/v1/sessions/${A}/reload`, { method: "POST" })).status, 404);
	assert.equal((await events()).filter((e) => e.event === "dispose").length, 1);
	assert.equal((await submit(A, "raced-after-delete")).status, 404);
});

test("legacy requests retain one session and explicit registry is bounded without eviction", async (t) => {
	const { request } = await startBridge(t);
	const submitLegacy = (input) => request("/v1/responses", { method: "POST", body: JSON.stringify({ input }) });
	const first = await submitLegacy("legacy-1");
	const second = await submitLegacy("legacy-2");
	assert.match((await completed(request, first.body.id)).body.output_text, /^s\d+:legacy-1$/);
	assert.match((await completed(request, second.body.id)).body.output_text, /^s\d+:legacy-1\|legacy-2$/);

	for (let i = 0; i < 50; i += 1) {
		const id = `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`;
		assert.equal((await request("/v1/sessions", { method: "POST", body: JSON.stringify({ id }) })).status, 201);
	}
	assert.equal((await request("/v1/sessions", { method: "POST", body: JSON.stringify({ id: "ffffffff-ffff-4fff-8fff-ffffffffffff" }) })).status, 409);
	assert.equal((await request("/v1/sessions/00000000-0000-4000-8000-000000000000")).status, 200);
});
