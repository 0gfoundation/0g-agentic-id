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

import { readFileSync, renameSync, statSync, writeFileSync } from "node:fs";

export const ROTATE_BYTES = Number(process.env.SEAL_CONVERSATION_ROTATE_BYTES || 8 * 1024 * 1024);

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
	try {
		return SessionManager.open(file);
	} catch (e) {
		log(`conversation store unreadable (${(e && e.message) || e}) — quarantining and starting fresh`);
		try { renameSync(file, `${file}.corrupt-${Date.now()}`); } catch { /* best effort */ }
		return SessionManager.open(file);
	}
}
