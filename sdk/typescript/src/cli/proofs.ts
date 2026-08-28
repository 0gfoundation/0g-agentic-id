/**
 * @file proofs.ts
 * @description The proof jar: locally saved serve-proofs ("tickets") captured
 * from agent interactions, so `rate` can spend a ticket from an interaction
 * that already happened — including rating an agent that has since gone
 * offline. Physics of a ticket: expires one hour after issuance (the sealed
 * proxy sets the deadline; the chain enforces it), single-use (signature is
 * the nonce), and redeemable ONLY by the wallet named in `submitter` — so a
 * jar entry leaking is harmless to anyone else.
 *
 * Stored next to the CLI config (`proofs.json`, 0600 out of caution). Each
 * entry carries the proof AND the task-receipt materials (method/uri/body
 * hashes/status) captured from the same interaction, so submission can open
 * the taskHash commitment on-chain (TEE-verified endpoint).
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { ServeProof, TaskReveal } from '../types';
import { configPaths } from './config';

/** A saved ticket: the proof plus its receipt materials and provenance. */
export interface SavedProof {
  agentId: string;            // decimal string (JSON-safe bigint)
  submitter: `0x${string}`;   // the only wallet that can redeem it
  endpoint: string;           // full URL the interaction hit (for the feedback `endpoint` field)
  capturedAt: number;         // unix seconds
  deadline: number;           // unix seconds — from the proof
  proof: {
    agentId: string; submitter: `0x${string}`; timestamp: string; deadline: string;
    taskHash: `0x${string}`; dataHashes: `0x${string}`[]; frameworkHash: `0x${string}`;
    signature: `0x${string}`;
  };
  task: TaskReveal;
}

function jarPath(): string {
  return join(configPaths().dir, 'proofs.json');
}

function loadJar(): SavedProof[] {
  const p = jarPath();
  if (!existsSync(p)) return [];
  try {
    const all = JSON.parse(readFileSync(p, 'utf8')) as SavedProof[];
    const now = Math.floor(Date.now() / 1000);
    return all.filter((e) => e.deadline > now); // prune expired on load
  } catch {
    return [];
  }
}

function writeJar(entries: SavedProof[]): void {
  mkdirSync(configPaths().dir, { recursive: true });
  writeFileSync(jarPath(), `${JSON.stringify(entries, null, 2)}\n`, { mode: 0o600 });
}

/** Save (or replace) the ticket for (agentId, submitter) — latest wins. */
export function saveProof(proof: ServeProof, task: TaskReveal, endpoint: string): void {
  const entry: SavedProof = {
    agentId: proof.agentId.toString(),
    submitter: proof.submitter,
    endpoint,
    capturedAt: Math.floor(Date.now() / 1000),
    deadline: Number(proof.deadline),
    proof: {
      agentId: proof.agentId.toString(),
      submitter: proof.submitter,
      timestamp: proof.timestamp.toString(),
      deadline: proof.deadline.toString(),
      taskHash: proof.taskHash,
      dataHashes: proof.dataHashes,
      frameworkHash: proof.frameworkHash,
      signature: proof.signature,
    },
    task,
  };
  const rest = loadJar().filter(
    (e) => !(e.agentId === entry.agentId && e.submitter.toLowerCase() === entry.submitter.toLowerCase()),
  );
  writeJar([...rest, entry]);
}

/** An unexpired ticket for (agentId, wallet), if any — with a mining-time
 *  margin so a ticket seconds from expiry isn't offered. */
export function findProof(agentId: bigint, wallet: `0x${string}`, marginSeconds = 120): SavedProof | null {
  const now = Math.floor(Date.now() / 1000);
  return (
    loadJar().find(
      (e) =>
        e.agentId === agentId.toString() &&
        e.submitter.toLowerCase() === wallet.toLowerCase() &&
        e.deadline > now + marginSeconds,
    ) ?? null
  );
}

/** Remove a spent (or refused) ticket. */
export function removeProof(agentId: bigint, wallet: `0x${string}`): void {
  writeJar(
    loadJar().filter(
      (e) => !(e.agentId === agentId.toString() && e.submitter.toLowerCase() === wallet.toLowerCase()),
    ),
  );
}

/** Rehydrate the bigint fields for SDK submission. */
export function toServeProof(e: SavedProof): ServeProof {
  return {
    agentId: BigInt(e.proof.agentId),
    submitter: e.proof.submitter,
    timestamp: BigInt(e.proof.timestamp),
    deadline: BigInt(e.proof.deadline),
    taskHash: e.proof.taskHash,
    dataHashes: e.proof.dataHashes,
    frameworkHash: e.proof.frameworkHash,
    signature: e.proof.signature,
  };
}
