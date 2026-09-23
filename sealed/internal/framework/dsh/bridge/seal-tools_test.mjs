import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

async function fixture(t, handler) {
	const root = await mkdtemp(join(tmpdir(), "dsh-seal-tools-test-"));
	const socketPath = join(root, "seal.sock");
	const packageDir = join(root, "node_modules", "@deepseek-ai", "dsh-tools");
	await mkdir(packageDir, { recursive: true });
	await writeFile(join(packageDir, "package.json"), JSON.stringify({ name: "@deepseek-ai/dsh-tools", type: "module", exports: "./index.mjs" }));
	await writeFile(join(packageDir, "index.mjs"), `
function validateValueSchema(node, path) {
  if (!node || typeof node !== 'object' || Array.isArray(node)) throw new Error(path + ' must be an object')
  if (node.type === 'object') {
    if (typeof node.additionalProperties !== 'boolean') {
      throw new Error(path + '.additionalProperties must be explicitly true or false')
    }
    for (const [name, child] of Object.entries(node.properties || {})) validateValueSchema(child, path + '.properties.' + name)
  }
  if (node.type === 'array' && node.items) validateValueSchema(node.items, path + '.items')
  for (const [index, child] of (node.oneOf || []).entries()) validateValueSchema(child, path + '.oneOf[' + index + ']')
}
export const defineTool = (value) => {
  for (const [name, schema] of Object.entries(value.parameters || {})) validateValueSchema(schema, 'parameters.' + name)
  validateValueSchema(value.output.schema, 'output.schema')
  return value
}
`);
	for (const file of ["seal-tools.mjs", "seal-guard.mjs"]) {
		await writeFile(join(root, file), await readFile(new URL(`./${file}`, import.meta.url)));
	}
	const server = createServer(handler);
	server.listen(socketPath);
	await once(server, "listening");
	t.after(async () => {
		server.closeAllConnections();
		server.close();
		await once(server, "close");
		await rm(root, { recursive: true, force: true });
	});
	const previous = process.env.SEAL_SIGN_SOCK;
	process.env.SEAL_SIGN_SOCK = socketPath;
	t.after(() => {
		if (previous === undefined) delete process.env.SEAL_SIGN_SOCK;
		else process.env.SEAL_SIGN_SOCK = previous;
	});
	const nonce = `${Date.now()}-${Math.random()}`;
	const toolsModule = await import(`${pathToFileURL(join(root, "seal-tools.mjs")).href}?${nonce}`);
	const guardModule = await import(`${pathToFileURL(join(root, "seal-guard.mjs")).href}?${nonce}`);
	const tools = new Map();
	const sections = [];
	toolsModule.apply({
		systemPrompt: { section: (section) => sections.push(section) },
		tools: { register: (tool) => tools.set(tool.name, tool) },
	});
	let guard;
	guardModule.apply({ tools: { guard: (value) => { guard = value; } } });
	return { tools, sections, guard, socketPath };
}

async function body(req) {
	const chunks = [];
	for await (const chunk of req) chunks.push(chunk);
	return Buffer.concat(chunks).toString("utf8");
}

test("connection tools use the private socket without exposing routing credentials", async (t) => {
	const seen = [];
	const { tools, sections, guard, socketPath } = await fixture(t, async (req, res) => {
		seen.push({ method: req.method, path: req.url, body: await body(req) });
		res.setHeader("content-type", "application/json");
		if (req.url === "/sign/personal_sign") {
			res.end(JSON.stringify({ signature: "0xsigned", address: "0xagent" }));
			return;
		}
		if (req.url === "/services") {
			res.end(JSON.stringify({ services: [{ path: "/api/demo" }] }));
			return;
		}
		if (req.method === "GET") {
			res.end(JSON.stringify({ connections: [
				{ id: "calendar_main", operation: "calendar.check_availability", label: "Work calendar", capability: "secret" },
				{ id: "crm_api", operation: "api.request", label: "CRM records", skill_id: "crm_lookup" },
				{ id: "unsafe/id", operation: "notion.search_shared_titles" },
			] }));
			return;
		}
		res.end(JSON.stringify({ result: { available: true }, capability: "secret" }));
	});

	assert.deepEqual([...tools.keys()], ["seal_sign", "seal_register_service", "seal_connections", "seal_connection_call"]);
	assert.match(sections[0].text, /seal_connections/);
	assert.match(sections[0].text, /seal_connection_call/);
	assert.deepEqual(
		await tools.get("seal_sign").execute({ message: "hello" }, { signal: new AbortController().signal }),
		{ signature: "0xsigned", address: "0xagent" },
	);
	assert.deepEqual(
		await tools.get("seal_register_service").execute({ services: [{ path: "/api/demo" }] }, { signal: new AbortController().signal }),
		{ registered: 1 },
	);
	const list = await tools.get("seal_connections").execute({}, { signal: new AbortController().signal });
	assert.deepEqual(list, { connections: [
		{ id: "calendar_main", operation: "calendar.check_availability", label: "Work calendar" },
		{ id: "crm_api", operation: "api.request", label: "CRM records" },
	] });

	const call = tools.get("seal_connection_call");
	assert.deepEqual(call.parameters.operation.enum, ["api.request", "calendar.check_availability", "notion.search_shared_titles"]);
	assert.equal(call.parameters.input.oneOf.length, 3);
	assert.deepEqual(call.parameters.input.oneOf.map((branch) => Object.keys(branch.properties)), [["timeMin", "timeMax"], ["query"], ["query", "body"]]);
	assert.equal(call.parameters.input.oneOf[2].properties.query.type, "array");
	assert.deepEqual(Object.keys(call.parameters.input.oneOf[2].properties.query.items.properties), ["name", "value"]);
	const result = await call.execute({
		grant_id: "calendar_main",
		operation: "calendar.check_availability",
		invocation_id: "00000000-0000-4000-8000-000000000001",
		input: { timeMin: "2026-09-23T09:00:00Z", timeMax: "2026-09-23T10:00:00Z" },
	}, { signal: new AbortController().signal });
	assert.deepEqual(result, { result: { available: true } });
	await call.execute({
		grant_id: "crm_api",
		operation: "api.request",
		invocation_id: "00000000-0000-4000-8000-000000000002",
		input: { query: [{ name: "customer", value: "42" }], body: { active: true } },
	}, { signal: new AbortController().signal });
	await assert.rejects(call.execute({
		grant_id: "crm_api",
		operation: "api.request",
		invocation_id: "00000000-0000-4000-8000-000000000003",
		input: { query: [{ name: "customer", value: "42" }, { name: "customer", value: "43" }] },
	}, { signal: new AbortController().signal }), /duplicate api\.request query name/);
	assert.deepEqual(seen, [
		{ method: "POST", path: "/sign/personal_sign", body: JSON.stringify({ message: "hello" }) },
		{ method: "POST", path: "/services", body: JSON.stringify({ services: [{ path: "/api/demo" }] }) },
		{ method: "GET", path: "/connections", body: "" },
		{ method: "POST", path: "/connections/invoke", body: JSON.stringify({
			grant_id: "calendar_main",
			operation: "calendar.check_availability",
			invocation_id: "00000000-0000-4000-8000-000000000001",
			input: { timeMin: "2026-09-23T09:00:00Z", timeMax: "2026-09-23T10:00:00Z" },
		}) },
		{ method: "POST", path: "/connections/invoke", body: JSON.stringify({
			grant_id: "crm_api",
			operation: "api.request",
			invocation_id: "00000000-0000-4000-8000-000000000002",
			input: { query: { customer: "42" }, body: { active: true } },
		}) },
	]);
	assert.match(guard({ name: "bash", arguments: { command: `curl --unix-socket ${socketPath} http://localhost/connections` } }), /seal_connections/);
	assert.match(guard({ name: "terminal", arguments: { command: "curl --unix-socket /run/seal-sign.sock http://localhost/connections/invoke" } }), /seal_connection_call/);
	assert.equal(guard({ name: "bash", arguments: { command: "pwd" } }), undefined);
});

test("socket responses are bounded and an aborted call settles", async (t) => {
	let mode = "oversize";
	const { tools } = await fixture(t, async (_req, res) => {
		if (mode === "oversize") {
			res.end("x".repeat(1_048_577));
			return;
		}
		// Deliberately leave the response open until the caller aborts.
	});
	await assert.rejects(
		tools.get("seal_connections").execute({}, { signal: new AbortController().signal }),
		/response exceeds 1048576 bytes/,
	);
	mode = "wait";
	const controller = new AbortController();
	const pending = tools.get("seal_connections").execute({}, { signal: controller.signal });
	controller.abort();
	await assert.rejects(pending, (error) => error?.name === "AbortError");
});

test("only the proven refresh response permits a new invocation id", async (t) => {
	let proven = true;
	const { tools } = await fixture(t, async (_req, res) => {
		res.statusCode = 503;
		res.setHeader("content-type", "application/json");
		if (proven) res.setHeader("retry-after", "1");
		res.end(JSON.stringify({
			error: { code: "connection_refresh_in_progress" },
			retryWithNewInvocationId: proven,
		}));
	});
	const call = () => tools.get("seal_connection_call").execute({
		grant_id: "calendar_main",
		operation: "notion.search_shared_titles",
		invocation_id: "00000000-0000-4000-8000-000000000001",
		input: { query: "planning" },
	}, { signal: new AbortController().signal });
	await assert.rejects(call(), /provider call began; retry after 1 second with a NEW invocation_id/);
	proven = false;
	await assert.rejects(call(), (error) => {
		assert.doesNotMatch(error.message, /new invocation_id/i);
		return true;
	});
});
