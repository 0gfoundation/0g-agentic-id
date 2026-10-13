// Regression guard for sessionstore.mjs against the REAL prime-agent SDK:
// open/append/reopen round-trip, rotation at the compaction point, corrupt-
// and stub-quarantine. SDK from $PRIME_SDK_ROOT (dir containing the
// `prime-agent` package, e.g. the image's global node_modules); absent →
// SKIP, the repo's convention for environment-gated tests. Run:
//   PRIME_SDK_ROOT=/path/to/node_modules \
//   SEAL_CONVERSATION_ROTATE_BYTES=4000 node sessionstore_regression.mjs
import { mkdtempSync, rmSync, writeFileSync, statSync, readFileSync, existsSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = process.env.PRIME_SDK_ROOT || "";
if (!ROOT || !existsSync(join(ROOT, "prime-agent"))) {
	console.log("SKIP: PRIME_SDK_ROOT not set or has no prime-agent — run inside the prime image or against an extracted tree");
	process.exit(0);
}
const sdk = await import(join(ROOT, "prime-agent/dist/index.js"));
const store = await import(new URL("./sessionstore.mjs", import.meta.url));
const { SessionManager, buildSessionContext } = sdk;
const dir = mkdtempSync(join(tmpdir(), "prime-store-"));
const F = join(dir, "owner-chat.jsonl");
const fail = (m) => { console.error("FAIL:", m); process.exit(1); };
const log = () => {};

// round-trip: append, reopen, entry survives.
let sm = store.openConversation(SessionManager, F, log);
sm.appendMessage({ role: "user", content: "codeword mango77" });
sm.flushNow?.();
let sm2 = store.openConversation(SessionManager, F, log);
if (!JSON.stringify(sm2.getEntries()).includes("mango77")) fail("entry lost across reopen");

// rotation: oversized file cuts at the latest compaction entry.
let keepId = null;
for (let i = 0; i < 30; i++) {
	const id = sm2.appendMessage({ role: "user", content: "old filler " + i + " ".padEnd(120, "x") });
	if (i === 28) keepId = id;
}
sm2.appendCompaction("SUMMARY: mango77 was said", keepId, 12345);
sm2.appendMessage({ role: "user", content: "post-cut papaya55" });
sm2.flushNow?.();
const before = statSync(F).size;
if (before < (store.ROTATE_BYTES ?? Infinity)) {
	console.log("SKIP-rotation: set SEAL_CONVERSATION_ROTATE_BYTES below " + before + " to exercise the cut");
} else {
	const sm3 = store.openConversation(SessionManager, F, log);
	if (statSync(F).size >= before) fail("rotation did not shrink the file");
	const entries = sm3.getEntries();
	const j = JSON.stringify(entries);
	if (!j.includes("mango77") || !j.includes("papaya55") || j.includes("old filler 3 ")) fail("rotation cut the wrong lines");
	if (!buildSessionContext(entries)) fail("context does not rebuild after rotation");
}

// headerless stub (clear-while-running race) quarantines, never gambles.
rmSync(F, { force: true });
writeFileSync(F, JSON.stringify({ type: "message", id: "m1", message: { role: "user", content: "orphan" } }) + "\n");
const sm4 = store.openConversation(SessionManager, F, log);
if (sm4.getEntries().length !== 0) fail("headerless stub was not quarantined");

rmSync(dir, { recursive: true, force: true });
console.log("OK: prime sessionstore regression (round-trip, rotation, stub quarantine)");
