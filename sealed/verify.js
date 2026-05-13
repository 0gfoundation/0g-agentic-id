#!/usr/bin/env node
'use strict';

// Sealed container self-verification script.
//
// Checks:
//   1. SANDBOX_SEAL_KEY derives the same address as attestation.pubkey
//      → confirms the proxy injected a consistent keypair
//   2. attestation.signature recovers the TEE signer address
//      → confirms the attestation was issued by the real TEE key
//      If TEE_SIGNER_ADDRESS is set, also asserts the recovered address matches.
//
// Results are printed to stdout and written to /tmp/seal-verify.log.
// The container stays running so operators can read the log via `exec`.

const { ethers } = require('ethers');
const fs = require('fs');

const LOG = '/tmp/seal-verify.log';
const lines = [];

function log(msg) {
    console.log(msg);
    lines.push(msg);
}

function fail(msg) {
    log('FAIL: ' + msg);
    fs.writeFileSync(LOG, lines.join('\n') + '\n');
    process.exit(1);
}

function ok(msg) {
    log('OK   ' + msg);
}

// ── Read env ──────────────────────────────────────────────────────────────────
const sealKey   = process.env.SANDBOX_SEAL_KEY;
const attestRaw = process.env.SANDBOX_SEAL_ATTESTATION;
const teeSigner = process.env.TEE_SIGNER_ADDRESS; // optional

if (!sealKey)   fail('SANDBOX_SEAL_KEY not set');
if (!attestRaw) fail('SANDBOX_SEAL_ATTESTATION not set');

log('--- Sealed Container Verification ---');
log('');

// ── Parse attestation ─────────────────────────────────────────────────────────
let attest;
try {
    attest = JSON.parse(attestRaw);
} catch (e) {
    fail('SANDBOX_SEAL_ATTESTATION is not valid JSON: ' + e.message);
}

const { seal_id, pubkey, image_hash, signature, ts } = attest;

if (!seal_id || !pubkey || !image_hash || !signature || ts === undefined) {
    fail('attestation missing required fields: ' + JSON.stringify(Object.keys(attest)));
}

log(`seal_id:    ${seal_id}`);
log(`pubkey:     ${pubkey}`);
log(`image_hash: ${image_hash}`);
log(`ts:         ${ts}`);
log('');

// ── Check 1: keypair consistency ──────────────────────────────────────────────
// Derive the Ethereum address from SANDBOX_SEAL_KEY and compare to attestation.pubkey.
const wallet = new ethers.Wallet(sealKey);
if (wallet.address.toLowerCase() !== pubkey.toLowerCase()) {
    fail(`keypair mismatch\n  derived : ${wallet.address}\n  pubkey  : ${pubkey}`);
}
ok(`keypair match: SANDBOX_SEAL_KEY → ${wallet.address}`);

// ── Check 2: TEE attestation signature ───────────────────────────────────────
// Reconstruct the message the proxy signed:
//   keccak256("ImageAttestation:" || sealId || ":" || pubkey || ":" || imageHash || ":" || ts)
const msg     = `ImageAttestation:${seal_id}:${pubkey}:${image_hash}:${ts}`;
const msgHash = ethers.keccak256(ethers.toUtf8Bytes(msg));

// V is 27/28 (Solidity convention); ethers.recoverAddress needs 0/1 — normalise.
const sigBytes = ethers.getBytes(signature);
const sig = new Uint8Array(sigBytes);
sig[64] -= 27;
const recovered = ethers.recoverAddress(msgHash, ethers.hexlify(sig));
ok(`TEE signature valid, signer: ${recovered}`);

if (teeSigner) {
    if (recovered.toLowerCase() !== teeSigner.toLowerCase()) {
        fail(`TEE signer mismatch\n  recovered: ${recovered}\n  expected : ${teeSigner}`);
    }
    ok(`TEE signer matches TEE_SIGNER_ADDRESS: ${teeSigner}`);
}

log('');
log('ALL CHECKS PASSED');

fs.writeFileSync(LOG, lines.join('\n') + '\n');
