import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const TOKEN = "test-bridge-token";

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
	while (Date.now() < deadline) {
		const value = await fn();
		if (value) return value;
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
	throw new Error(message);
}

async function writePackage(root, name, source) {
	const dir = join(root, "node_modules", ...name.split("/"));
	await mkdir(dir, { recursive: true });
	await writeFile(join(dir, "package.json"), JSON.stringify({ name, type: "module", exports: "./index.mjs" }));
	await writeFile(join(dir, "index.mjs"), source);
}

async function startBridge(t) {
	const root = await mkdtemp(join(tmpdir(), "dsh-bridge-test-"));
	const personaPath = join(root, "APPEND_SYSTEM.md");
	const eventPath = join(root, "events.jsonl");
	await writeFile(personaPath, "persona-v1");
	await writeFile(eventPath, "");

	await writePackage(root, "@deepseek-ai/cordis", `
import { appendFile } from "node:fs/promises";
const listeners = new Map();
const sections = [];
const history = [];
const write = (event) => appendFile(process.env.MOCK_EVENT_PATH, JSON.stringify(event) + "\\n");
export class Context {
  constructor() {
    this.systemPrompt = { section: (section) => { sections.push(section); return () => {}; } };
    this.tools = { register() {}, guard() {} };
    this.agents = { create: async () => ({ agent: new Agent() }) };
  }
  async plugin(plugin, config) {
    const apply = plugin && typeof plugin === "object" && Object.hasOwn(plugin, "apply") ? plugin.apply : undefined;
    if (typeof apply === "function") await apply(this, config);
  }
  on(name, fn) {
    const set = listeners.get(name) ?? new Set(); set.add(fn); listeners.set(name, set);
    return () => set.delete(fn);
  }
}
class Agent {
  constructor() { this.session = {}; this.pending = Promise.resolve(); }
  followup(message) {
    this.pending = (async () => {
      const prompt = sections.map((section) => typeof section.text === "function" ? section.text({}) : section.text).filter(Boolean).join("\\n\\n");
      const text = message.content[0].text; history.push(text);
      await write({ prompt, history: [...history] });
      const output = JSON.stringify({ prompt, history });
      for (const fn of listeners.get("session/event") ?? []) fn(this.session, { type: "assistant/chunk", data: { chunk: { type: "text-delta", text: output } } });
    })();
  }
  whenIdle() { return this.pending; }
  cancel() {}
}
`);
	await writePackage(root, "@deepseek-ai/dsh-agent-spine-demo", `
export async function apply(ctx, config) {
  ctx.systemPrompt.section({ name: "deployment:persona", order: 0, text: config.persona ?? "" });
}
`);
	await writePackage(root, "@deepseek-ai/dsh-llm", "export const createUserMessage = (value) => value;\n");
	await writePackage(root, "@deepseek-ai/dsh-session", "export const SessionId = (value) => value;\n");
	await writePackage(root, "@deepseek-ai/dsh-tools", "export const defineTool = (value) => value;\n");
	for (const name of [
		"@deepseek-ai/dsh-llm-pi-ai",
		"@deepseek-ai/dsh-credentials-local",
		"@deepseek-ai/dsh-bash-local",
		"@deepseek-ai/dsh-subprocess-local",
		"@deepseek-ai/dsh-sandbox-policy",
		"@deepseek-ai/dsh-fs-local",
		"@deepseek-ai/dsh-tool-fs",
		"@deepseek-ai/dsh-token-meter",
		"@deepseek-ai/dsh-compaction-basic",
		"@deepseek-ai/dsh-tool-call-timeout-policy",
	]) await writePackage(root, name, "export default function plugin() {}\n");

	for (const file of ["bridge.mjs", "seal-tools.mjs", "seal-guard.mjs"]) {
		await writeFile(join(root, file), await readFile(new URL(`./${file}`, import.meta.url)));
	}
	const port = await freePort();
	const child = spawn(process.execPath, [join(root, "bridge.mjs")], {
		cwd: root,
		env: {
			...process.env,
			SEAL_BRIDGE_PORT: String(port),
			SEAL_BRIDGE_TOKEN: TOKEN,
			SEAL_MODEL_PROVIDER: "mock",
			SEAL_MODEL_ID: "model",
			SEAL_PERSONA_PATH: personaPath,
			MOCK_EVENT_PATH: eventPath,
		},
		stdio: ["ignore", "pipe", "pipe"],
	});
	let output = "";
	child.stdout.on("data", (chunk) => { output += chunk; });
	child.stderr.on("data", (chunk) => { output += chunk; });
	const base = `http://127.0.0.1:${port}`;
	await waitFor(async () => fetch(`${base}/healthz`).then((response) => response.ok).catch(() => false), `bridge did not start: ${output}`);
	t.after(async () => {
		child.kill("SIGTERM");
		await Promise.race([once(child, "exit"), new Promise((resolve) => setTimeout(resolve, 1000))]);
		await rm(root, { recursive: true, force: true });
	});
	const chat = async (text) => {
		const response = await fetch(`${base}/v1/chat/completions`, {
			method: "POST",
			headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
			body: JSON.stringify({ messages: [{ role: "user", content: text }] }),
		});
		assert.equal(response.status, 200, output);
		return JSON.parse((await response.json()).choices[0].message.content);
	};
	return { chat, personaPath };
}

test("persona edits activate on the next turn without replacing agent context", async (t) => {
	const { chat, personaPath } = await startBridge(t);
	const first = await chat("first");
	assert.match(first.prompt, /persona-v1/);
	assert.deepEqual(first.history, ["first"]);

	await writeFile(personaPath, "persona-v2");
	const second = await chat("second");
	assert.match(second.prompt, /persona-v2/);
	assert.doesNotMatch(second.prompt, /persona-v1/);
	assert.deepEqual(second.history, ["first", "second"]);
});
