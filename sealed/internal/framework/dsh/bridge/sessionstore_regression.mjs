// Regression guard for sessionstore.mjs against the REAL @deepseek-ai SDK —
// notably the seq-contiguity invariant (#169 finding 1: the constructor's
// unpublished session/end-seed marker bricked the SECOND restart).
//
// The SDK ships in the built image, not in this repo, so this script takes it
// from $DSH_SDK_ROOT (a node_modules dir containing @deepseek-ai/*, e.g. the
// image's global tree, or one extracted via `docker cp`). Absent → exit 0 with
// a SKIP line, the repo's convention for environment-gated tests (fork tests
// skip without FORK_RPC). Run:
//   DSH_SDK_ROOT=/path/to/node_modules node sessionstore_regression.mjs
import { mkdtempSync, rmSync, appendFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = process.env.DSH_SDK_ROOT || "";
if (!ROOT || !existsSync(join(ROOT, "@deepseek-ai"))) {
	console.log("SKIP: DSH_SDK_ROOT not set or has no @deepseek-ai — run inside the dsh image or against an extracted tree");
	process.exit(0);
}
const sdk = await import(join(ROOT, "@deepseek-ai/dsh-session/lib/index.js"));
const llm = await import(join(ROOT, "@deepseek-ai/dsh-llm/lib/index.js"));
const store = await import(new URL("./sessionstore.mjs", import.meta.url));

const { Session, SessionId, decodeStorageRecord, interruptedTurnClosers, packChunkRuns } = sdk;
const codecs = { decodeStorageRecord, interruptedTurnClosers, packChunkRuns };
const dir = mkdtempSync(join(tmpdir(), "dsh-store-"));
const F = join(dir, "owner-chat.session.jsonl");
const fail = (m) => { console.error("FAIL:", m); process.exit(1); };
const log = () => {};
const umsg = (t) => llm.createUserMessage({ content: [{ type: "text", text: t }], source: { kind: "user" } });

// gen1: fresh boot, one full turn, firehose-persisted (the bridge's shape).
let sess = Session.create(SessionId("owner-chat"));
let seedMax = -1;
const live = (e) => { if (typeof e.seq === "number" && e.seq <= seedMax) return; store.appendEvent(F, e, codecs, log); };
for (const [t, d, o] of [["turn/start", {}], ["user/message", umsg("gen1 fig11"), { surfaceOp: "append" }], ["turn/end", { reason: { kind: "completed" } }]]) {
	live(o ? sess.append(t, d, o) : sess.append(t, d));
}
const header = sess.header;

// gen2: restart — loadSeed must pre-mark end-seed; restore; another turn.
let seed = store.loadSeed(F, codecs, log);
if (!seed || seed[seed.length - 1].type !== "session/end-seed") fail("loadSeed did not pre-mark session/end-seed (finding 1 regressed)");
let s2;
try { s2 = Session.fromRestore(SessionId("owner-chat"), seed, header); } catch (e) { fail("gen2 restore rejected: " + e.message); }
seedMax = seed[seed.length - 1].seq;
for (const [t, d, o] of [["turn/start", {}], ["user/message", umsg("gen2 plum22"), { surfaceOp: "append" }], ["turn/end", { reason: { kind: "completed" } }]]) {
	live(o ? s2.append(t, d, o) : s2.append(t, d));
}

// gen3: SECOND restart — the bite point. Seqs must be contiguous from 0.
seed = store.loadSeed(F, codecs, log);
const seqs = seed.map((e) => e.seq);
if (!seqs.every((q, i) => q === i)) fail("seq hole after second restart: " + seqs.join(","));
let s3;
try { s3 = Session.fromRestore(SessionId("owner-chat"), seed, header); } catch (e) { fail("gen3 restore rejected (the finding-1 brick): " + e.message); }
const j = JSON.stringify(seed);
if (!j.includes("fig11") || !j.includes("plum22")) fail("a codeword was lost across restarts");

// crash tail: torn line + open turn must repair and still restore. Driven on
// THE SESSION RESTORED FROM THIS LOAD (s3) — in the bridge, loadSeed runs
// only at process start and the live session is built from that seed; a
// stale session appending past a later load cannot happen.
seedMax = seed[seed.length - 1].seq;
for (const [t, d, o] of [["turn/start", {}], ["user/message", umsg("mid-crash"), { surfaceOp: "append" }]]) {
	live(o ? s3.append(t, d, o) : s3.append(t, d));
}
appendFileSync(F, '{"type":"assistant/chu');
seed = store.loadSeed(F, codecs, log);
if (interruptedTurnClosers(seed).length !== 0) fail("crash repair left an open turn");
try { Session.fromRestore(SessionId("owner-chat"), seed, header); } catch (e) { fail("post-crash restore rejected: " + e.message); }

// stale stub (clear-while-running race) must archive, not brick.
rmSync(F, { force: true });
appendFileSync(F, JSON.stringify({ type: "turn/start", seq: 7, time: 1, data: {} }) + "\n");
if (store.loadSeed(F, codecs, log) !== null) fail("stale stub was not archived");

rmSync(dir, { recursive: true, force: true });
console.log("OK: dsh sessionstore regression (4 generations, crash repair, stale stub)");
