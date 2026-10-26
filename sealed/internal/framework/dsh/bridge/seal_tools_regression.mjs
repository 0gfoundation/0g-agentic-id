// Regression guard for seal-tools.mjs against the REAL @deepseek-ai SDK —
// the three sign tools' parity with the sealed sign socket's endpoints.
//
// The socket's request/response shapes live in internal/proxy/sign.go; this
// script spins a FAKE sign socket on a unix socket (node http), points
// SEAL_SIGN_SOCK at it, loads the plugin through a minimal cordis-style ctx,
// and asserts, per tool:
//
//   1. registration shape (names, output schema) against the surface the
//      session log depends on;
//   2. the request body the plugin forwards — field names and pass-through
//      only of set fields (the socket decodes the same names; a rename here
//      breaks signing with a confusing server-side error);
//   3. the structured output the plugin returns (raw_tx/tx_hash/address,
//      signature/address/digest) — the model broadcasts raw_tx verbatim;
//   4. non-200 from the socket rejects with the server's error message.
//
// The SDK ships in the built image, not in this repo, so this script takes it
// from $DSH_SDK_ROOT (a node_modules dir containing @deepseek-ai/*, e.g. the
// image's global tree, or one extracted via `docker cp`). Absent → exit 0 with
// a SKIP line, the repo's convention for environment-gated tests. Run:
//   DSH_SDK_ROOT=/path/to/node_modules node seal_tools_regression.mjs
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";

const ROOT = process.env.DSH_SDK_ROOT || "";
if (!ROOT) {
	console.log("SKIP: DSH_SDK_ROOT not set — run inside the dsh image or against an extracted tree");
	process.exit(0);
}
const { defineTool } = await import(join(ROOT, "@deepseek-ai/dsh-tools/lib/index.js"));

// SEAL_SIGN_SOCK is read at module load; set it to the fake socket's path
// BEFORE importing the plugin. (The real guard for shell access is
// seal-guard.mjs; this script only exercises the tool channel.)
const dir = mkdtempSync(join(tmpdir(), "seal-tools-"));
const sockPath = join(dir, "sign.sock");
process.env.SEAL_SIGN_SOCK = sockPath;

const plugin = await import(new URL("./seal-tools.mjs", import.meta.url));

const failures = [];
const check = (ok, msg) => { if (!ok) failures.push(msg); };
const j = (x) => JSON.stringify(x);

// ── fake sign socket: records requests, answers with canned shapes ────────
const hits = [];
let nextStatus = 200;
let nextBody = null;
const server = createServer((req, res) => {
	const parts = [];
	req.on("data", (c) => parts.push(c));
	req.on("end", () => {
		const body = parts.length ? JSON.parse(Buffer.concat(parts).toString("utf8")) : null;
		hits.push({ path: req.url, method: req.method, body });
		res.writeHead(nextStatus, { "content-type": "application/json" });
		res.end(JSON.stringify(nextStatus === 200 ? nextBody : { error: "boom: field rejected" }));
	});
});
await new Promise((r) => server.listen(sockPath, r));

// ── minimal cordis ctx: collect registrations ──────────────────────────────
const registered = [];
const ctx = {
	systemPrompt: { section: () => {} },
	tools: {
		register: (t) => registered.push(t),
		guard: () => {},
	},
};
plugin.apply(ctx);

const names = registered.map((t) => t.name);
check(j(names) === j(["seal_sign", "seal_sign_transaction", "seal_sign_typed_data", "seal_register_service"]),
	`registered tools: ${j(names)}`);
const signTools = Object.fromEntries(registered.map((t) => [t.name, t]));

// ── seal_sign: unchanged behavior (parity guard for the pre-existing tool) ─
nextBody = { signature: "0xsig", address: "0xaddr", msg_hash: "0xhash" };
let out = await signTools.seal_sign.execute({ message: "hello" }, { signal: undefined });
check(out.signature === "0xsig" && out.address === "0xaddr", `seal_sign output: ${j(out)}`);
check(hits.at(-1).path === "/sign/personal_sign" && hits.at(-1).body.message === "hello",
	`seal_sign forward: ${j(hits.at(-1))}`);
try {
	await signTools.seal_sign.execute({}, { signal: undefined });
	failures.push("seal_sign empty args must throw");
} catch { /* expected */ }

// ── seal_sign_transaction: forward shape + output mapping ──────────────────
nextBody = { raw_tx: "0x02f8…", tx_hash: "0xabc", address: "0xaddr", signature: { v: "0x1", r: "0x2", s: "0x3" } };
out = await signTools.seal_sign_transaction.execute({
	chain_id: "16602", nonce: 47, to: "0x2ce8…", value: "0", data: "0xbfe9…",
	gas_limit: 73933, type: "legacy", gas_price: "4000000007",
}, { signal: undefined });
check(out.raw_tx === "0x02f8…" && out.tx_hash === "0xabc" && out.address === "0xaddr",
	`seal_sign_transaction output: ${j(out)}`);
check(out.signature.v === "0x1", `seal_sign_transaction signature passthrough: ${j(out.signature)}`);
const fwd = hits.at(-1);
check(fwd.path === "/sign/transaction", `tx forwarded to wrong path: ${fwd.path}`);
check(fwd.body.chain_id === "16602" && fwd.body.nonce === 47 && fwd.body.gas_limit === 73933 &&
	fwd.body.type === "legacy" && fwd.body.gas_price === "4000000007",
	`tx forwarded body: ${j(fwd.body)}`);
check(!("max_fee_per_gas" in fwd.body), `legacy tx must not carry 1559 fields: ${j(fwd.body)}`);
// unset type-dependent fields must be ABSENT, not null/empty:
nextBody = { raw_tx: "0x", tx_hash: "0x", address: "0x", signature: {} };
await signTools.seal_sign_transaction.execute({
	chain_id: "16602", nonce: 2, to: "0xrcpt", data: "0x", gas_limit: 21000,
	max_fee_per_gas: "1000", max_priority_fee_per_gas: "1",
}, { signal: undefined });
const dyn = hits.at(-1).body;
check(!("gas_price" in dyn) && dyn.max_fee_per_gas === "1000",
	`dynamic tx must omit gas_price, carry 1559 pair: ${j(dyn)}`);
// contract creation: to:"" forwarded verbatim, unset value stays absent
nextBody = { raw_tx: "0x", tx_hash: "0x", address: "0x", signature: {} };
await signTools.seal_sign_transaction.execute({
	chain_id: "16602", nonce: 3, to: "", data: "0x6080", gas_limit: 200000,
}, { signal: undefined });
const create = hits.at(-1).body;
check(create.to === "" && !("value" in create) && !("type" in create),
	`creation tx: to forwarded as "", unset value/type absent: ${j(create)}`);
try {
	await signTools.seal_sign_transaction.execute({ chain_id: "16602" }, { signal: undefined });
	failures.push("tx without required fields must throw");
} catch { /* expected */ }

// ── seal_sign_typed_data: EIP712Domain injection + output mapping ─────────
// viem/ethers convention omits EIP712Domain from types; the geth hasher the
// real socket uses requires it. The tool injects one in canonical order from
// the domain keys present (same as sdk/src/seal.ts) — the forwarded body
// must carry it even though the caller's payload didn't.
nextBody = { signature: "0xsig712", address: "0xaddr", digest: "0xdig" };
const td = { domain: { name: "x", chainId: 16602, verifyingContract: "0xabc" }, types: { Mail: [{ name: "a", type: "uint256" }] }, primaryType: "Mail", message: { a: 1 } };
out = await signTools.seal_sign_typed_data.execute({ typed_data: td }, { signal: undefined });
check(out.signature === "0xsig712" && out.digest === "0xdig", `typed output: ${j(out)}`);
const tfwd = hits.at(-1);
check(tfwd.path === "/sign/typed_data" && tfwd.body.primaryType === "Mail" && tfwd.body.domain.name === "x",
	`typed forward: ${j(tfwd)}`);
check(j(tfwd.body.types.EIP712Domain) === j([
	{ name: "name", type: "string" },
	{ name: "chainId", type: "uint256" },
	{ name: "verifyingContract", type: "address" },
]), `EIP712Domain injected in canonical order: ${j(tfwd.body.types.EIP712Domain)}`);
try {
	await signTools.seal_sign_typed_data.execute({}, { signal: undefined });
	failures.push("typed without typed_data must throw");
} catch { /* expected */ }

// ── typed_data precision guard: numbers above 2^53 must not pass ──────────
// JSON.parse silently rounds 1234567890123456789 → …768; the seal would sign
// a different amount with no error. Non-safe integers are rejected with the
// field path so the model knows what to turn into a decimal string.
try {
	await signTools.seal_sign_typed_data.execute({ typed_data: {
		domain: { name: "x" }, types: { Mail: [{ name: "amount", type: "uint256" }] },
		primaryType: "Mail", message: { amount: 1234567890123456789 },
	} }, { signal: undefined });
	failures.push("unsafe integer must be rejected before the socket");
} catch (e) {
	check(String(e).includes("typed_data.message.amount") && String(e).includes("decimal strings"),
		`unsafe-integer error must name the field: ${e}`);
}

// ── tx guards: `to` presence + numeric-string fields ──────────────────────
// Omitting `to` would silently sign a contract CREATION at the socket — the
// schema marks it required and execute double-checks; junk numeric strings
// ("1.5", "1e18") would sign value 0 at the socket — rejected here instead.
try {
	await signTools.seal_sign_transaction.execute({
		chain_id: "16602", nonce: 1, data: "0x", gas_limit: 21000, value: "1000",
	}, { signal: undefined });
	failures.push("tx without `to` must be rejected (creation needs explicit \"\")");
} catch { /* expected */ }
try {
	await signTools.seal_sign_transaction.execute({
		chain_id: "16602", nonce: 1, to: "0xabc", data: "0x", gas_limit: 21000, value: "1.5",
	}, { signal: undefined });
	failures.push("value \"1.5\" must be rejected (socket would sign 0 wei)");
} catch (e) {
	check(String(e).includes('value: "1.5"'), `bad-value error names the field: ${e}`);
}
try {
	await signTools.seal_sign_transaction.execute({
		chain_id: "0", nonce: 1, to: "0xabc", data: "0x", gas_limit: 21000,
	}, { signal: undefined });
	failures.push("chain_id \"0\" must not be forwarded (geth signer panics)");
} catch { /* expected — schema-level or execute-level, either way not forwarded */ }

// ── socket error surface: non-200 rejects with the server's message ────────
nextStatus = 400; nextBody = null;
try {
	await signTools.seal_sign.execute({ message: "x" }, { signal: undefined });
	failures.push("non-200 must reject");
} catch (e) {
	check(String(e.message).includes("boom: field rejected"), `error must carry server message: ${e.message}`);
}
nextStatus = 200;

// ── render blocks: the model sees the full raw_tx (it broadcasts it) ───────
const txTool = signTools.seal_sign_transaction;
const rendered = txTool.output.render({}, { raw_tx: "0xraw", tx_hash: "0xh", address: "0xa", signature: {} });
check(rendered[0].text.includes("0xraw"), `render must include raw_tx: ${rendered[0].text}`);

// ── required-field schema declarations compile to harness validation ──────
// (defineTool compiles property-level required into the top-level required[]
// array; the harness then rejects a missing field with ToolArgsError BEFORE
// execute runs — the run-time guards are the second line, not the only one.)
const compiled = signTools.seal_sign_transaction.parameters;
check(j(compiled.required) === j(["chain_id", "nonce", "to", "data", "gas_limit"]),
	`tx required fields: ${j(compiled.required)}`);
check(signTools.seal_sign_typed_data.parameters.required?.[0] === "typed_data",
	`typed_data must be schema-required: ${j(signTools.seal_sign_typed_data.parameters.required)}`);

server.close();
try { rmSync(dir, { recursive: true, force: true }); } catch { /* tmpdir cleanup best-effort */ }

// ── seal-guard allow/deny split (the b857a41 regression: a broadened guard
// denied the documented settings channel; this pins the scoped rule) ──
{
	const guards = [];
	const ctx = { tools: { guard: (fn) => guards.push(fn) } };
	await import("./seal-guard.mjs").then((m) => m.apply(ctx));
	check(guards.length === 1, "one guard registered");
	const g = guards[0];
	const sockPath = process.env.SEAL_SIGN_SOCK;
	const cases = [
		// DENIED: a socket spelling + a /sign/ path
		["deny", "bash", { command: 'curl --unix-socket "$SEAL_SIGN_SOCK" http://localhost/sign/personal_sign -d "{}"' }],
		["deny", "bash", { command: `curl --unix-socket ${sockPath} http://localhost/sign/transaction -d "{}"` }],
		["deny", "bash", { command: `curl --unix-socket ${sockPath} http://localhost/sign` }],
		// ALLOWED: the documented non-sign endpoints (b857a41 blocked these)
		["allow", "bash", { command: 'curl --unix-socket "$SEAL_SIGN_SOCK" http://localhost/settings' }],
		["allow", "bash", { command: `curl --unix-socket ${sockPath} -X POST -d '{"thinking":"high"}' http://localhost/settings` }],
		["allow", "bash", { command: `curl --unix-socket ${sockPath} http://localhost/services` }],
		["allow", "bash", { command: 'curl --unix-socket "$SEAL_SIGN_SOCK" -X POST -d "[]" http://localhost/services' }],
		// ALLOWED: neither socket nor sign
		["allow", "bash", { command: "curl http://example.com/api" }],
		["allow", "bash", { command: "ls -la" }],
		// ALLOWED: a /sign/ path with NO socket spelling — pins the AND's
		// socket half (dropping namesSocket && must fail this case)
		["allow", "bash", { command: "curl http://localhost:9999/sign/personal_sign" }],
		["allow", "bash", { command: "cat docs/sign-endpoints.md && echo done" }],
		// NOT scanned at all: non-shell tools (the SHELL_TOOLS bound)
		["allow", "read_file", { command: `curl --unix-socket ${sockPath} http://localhost/sign/personal_sign` }],
	];
	for (const [want, tool, args] of cases) {
		const verdict = g({ name: tool, arguments: args });
		check(want === "deny" ? typeof verdict === "string" : verdict === undefined,
			`${tool} ${args.command.slice(0, 60)} → ${want}`);
	}
	// the denial text no longer offers seal_register_service (its endpoint is
	// open now) and no longer overclaims "closed"
	const v = g({ name: "bash", arguments: { command: 'curl --unix-socket "$SEAL_SIGN_SOCK" http://localhost/sign/personal_sign' } });
	check(!/seal_register_service/.test(String(v)), "denial text does not offer seal_register_service");
	check(/steered away/.test(String(v)), "denial text says steered away, not closed");
}


if (failures.length) {
	console.error("FAIL:", failures.length, "assertion(s)");
	for (const f of failures) console.error("  -", f);
	process.exit(1);
}
console.log("OK: seal-tools regression — 4 tools registered, 3 sign endpoints mapped, shapes + errors verified");
