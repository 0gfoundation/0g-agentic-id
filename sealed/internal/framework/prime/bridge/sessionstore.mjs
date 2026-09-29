// Conversation store for the prime bridge (CONVERSATION.md).
//
// The harness owns the conversation: the bridge opens the SDK's own
// SessionManager on ONE fixed file (one agent, one conversation) and the SDK
// appends every entry and rebuilds the context on reopen. This module adds
// the two obligations the SDK does not cover:
//
//   - self-rotation (invariant 7): the store is append-only and the SDK never
//     rotates it; past a size ceiling we cut at the latest compaction point —
//     the safe boundary, because the live context is exactly "compaction
//     summary + entries from firstKeptEntryId onward".
//   - corruption quarantine: a torn write from a crash must never brick the
//     agent; the chain-side memory roles are the durable knowledge, this file
//     is working context. Unreadable → quarantine, start fresh.
//
// Dependency-injected (`SessionManager` is passed in, not imported) so tests
// can drive it with the real SDK extracted from the image without a global
// install of `prime-agent`.

import { readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";

export const ROTATE_BYTES = Number(process.env.SEAL_CONVERSATION_ROTATE_BYTES || 8 * 1024 * 1024);

// Quarantine keeps only the most recent leftover PER REASON — otherwise
// .corrupt-*/.stale-* siblings accumulate with conversation volume on a
// runner's shared disk (review #169), the very risk invariant 7 caps.
function quarantine(file, why, log) {
	try {
		const dir = dirname(file);
		const prefix = basename(file) + "." + why + "-";
		for (const name of readdirSync(dir)) {
			if (name.startsWith(prefix)) rmSync(join(dir, name), { force: true });
		}
	} catch { /* pruning is best-effort */ }
	try {
		renameSync(file, `${file}.${why}-${Date.now()}`);
		log(`conversation store quarantined (${why})`);
	} catch { /* nothing to move */ }
}

/**
 * Cut the file at its latest compaction entry: keep the header line, the
 * compaction entry (re-parented to root — its parent is in the discarded
 * region) and every line after it. Line-wise on the raw file so nothing is
 * re-encoded except the one re-parented entry. No compaction entry → nothing
 * safe to cut at → skip (a conversation only reaches the ceiling after long
 * use, which compacts along the way).
 */
export function rotateIfOversized(file, log = () => {}) {
	let size = 0;
	try { size = statSync(file).size; } catch { return false; }
	if (size < ROTATE_BYTES) return false;
	const lines = readFileSync(file, "utf8").split("\n");
	let cutIdx = -1;
	for (let i = lines.length - 1; i > 0; i--) {
		if (!lines[i]) continue;
		try { if (JSON.parse(lines[i]).type === "compaction") { cutIdx = i; break; } } catch { /* torn line */ }
	}
	if (cutIdx <= 0) { log(`conversation store at ${size}B with no compaction point — rotation skipped`); return false; }
	const cut = JSON.parse(lines[cutIdx]);
	cut.parentId = null;
	const out = [lines[0], JSON.stringify(cut), ...lines.slice(cutIdx + 1)].join("\n");
	writeFileSync(file + ".rotating", out.endsWith("\n") ? out : out + "\n");
	renameSync(file + ".rotating", file);
	log(`conversation store rotated at compaction point: ${size}B -> ${statSync(file).size}B`);
	return true;
}

/** Open the persistent conversation; never throws the agent dead. */
export function openConversation(SessionManager, file, log = () => {}) {
	try { rotateIfOversized(file, log); } catch (e) { log(`conversation rotation failed (non-fatal): ${(e && e.message) || e}`); }
	// A stub left by a clear-while-running race (the old process appended past
	// the removal) has no session-header first line; don't gamble on how
	// SessionManager.open treats it — quarantine deterministically.
	try {
		const first = readFileSync(file, "utf8").split("\n", 1)[0];
		if (first && JSON.parse(first).type !== "session") {
			log("conversation store has no session header (a truncated stub) — quarantining and starting fresh");
			quarantine(file, "stale", log);
		}
	} catch { /* absent or unparsable first line — open()/quarantine below decide */ }
	try {
		return SessionManager.open(file);
	} catch (e) {
		log(`conversation store unreadable (${(e && e.message) || e}) — quarantining and starting fresh`);
		quarantine(file, "corrupt", log);
		return SessionManager.open(file);
	}
}
