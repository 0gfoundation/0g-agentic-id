// Conversation store for the dsh bridge (CONVERSATION.md).
//
// DSH's session is event-sourced and its own docs make persistence a plugin
// concern ("subscribe to session/event, drain on session/flush") — but no
// concrete SessionPersistence backend ships in the composition. This module is
// that backend, reduced to the one-conversation case: append every committed
// event of the `owner-chat` session to ONE JSONL file with the SDK's own
// codecs (`packChunkRuns`/`decodeStorageRecord`), and on boot hand the decoded
// log to `ctx.agents.create({ seed })` — the SDK's documented replay path.
//
// Seed rules (SDK contract): contiguous from seq 0, lossless JSON, no open
// turn. A crash tail is handled twice over — a torn last line stops the read
// at the last good line, and `interruptedTurnClosers` closes a mid-turn crash
// with the SDK's own synthetic closers (also appended, so the file itself
// becomes balanced).
//
// Rotation (invariant 7) is NECESSARILY cruder than prime's: a seed must be
// contiguous from seq 0, so the head cannot be cut. At the size ceiling the
// store is archived and the conversation restarts fresh — loudly. The chain-
// side memory roles carry everything the agent chose to keep, so the loss is
// working context only, at a boundary that takes megabytes of events to reach.
//
// Dependency-injected (the SDK fns are passed in) so tests drive it with the
// real @deepseek-ai packages extracted from the image.

import { appendFileSync, readFileSync, renameSync, statSync } from "node:fs";

export const ROTATE_BYTES = Number(process.env.SEAL_CONVERSATION_ROTATE_BYTES || 8 * 1024 * 1024);

function archive(file, why, log) {
	try {
		renameSync(file, `${file}.${why}-${Date.now()}`);
		log(`conversation store archived (${why})`);
	} catch { /* nothing to archive */ }
}

/**
 * Load the persisted conversation as a seed for `ctx.agents.create`, or null
 * when there is nothing (or nothing usable) to restore. Never throws: a
 * conversation must not brick the agent — corrupt stores quarantine.
 * sdk = { decodeStorageRecord, interruptedTurnClosers, packChunkRuns }.
 */
export function loadSeed(file, sdk, log = () => {}) {
	let size = 0;
	try { size = statSync(file).size; } catch { return null; }
	if (size >= ROTATE_BYTES) {
		log(`conversation store at ${size}B — seeds must be contiguous from seq 0, so the head cannot be cut: archiving and starting fresh (chain memory untouched)`);
		archive(file, "ceiling", log);
		return null;
	}
	try {
		const events = [];
		for (const line of readFileSync(file, "utf8").split("\n")) {
			if (!line) continue;
			let v;
			try { v = JSON.parse(line); } catch { break; } // torn tail: stop at the last good line
			events.push(...sdk.decodeStorageRecord(v)); // malformed chunk row throws → corrupt store
		}
		if (!events.length) return null;
		const closers = sdk.interruptedTurnClosers(events);
		if (closers.length) {
			log(`repairing an interrupted turn: ${closers.length} synthetic closer(s)`);
			for (const e of closers) appendEvent(file, e, sdk, log); // balance the file too
			events.push(...closers);
		}
		log(`conversation restored from disk: ${events.length} events`);
		return events;
	} catch (e) {
		log(`conversation store unreadable (${(e && e.message) || e}) — quarantining and starting fresh`);
		archive(file, "corrupt", log);
		return null;
	}
}

/** Append one committed session event. Best-effort: an append failure costs
 *  durability of that event, never the turn. */
export function appendEvent(file, event, sdk, log = () => {}) {
	try {
		for (const rec of sdk.packChunkRuns([event])) {
			appendFileSync(file, JSON.stringify(rec) + "\n");
		}
	} catch (e) {
		log(`conversation append failed (non-fatal): ${(e && e.message) || e}`);
	}
}
