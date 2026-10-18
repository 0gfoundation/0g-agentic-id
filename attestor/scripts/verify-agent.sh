#!/usr/bin/env bash
# Post-deploy verification for a LIVE agent — the checks that prove the
# identity chain end-to-end, runnable with curl+jq+cast only (no node).
#
#   1. identity tri-check: attestor row addr == on-chain getAgentSeal
#      == the addr the container says it was provisioned with
#   2. decrypt check: the sealed bootstrap log has zero FAILs and one
#      "decrypted" per iData entry (catches KMS master drift: a key
#      derived from a different master fails ECIES with "message
#      authentication failed")
#   3. serve-proof: /hello returns 200 + X-Agent-Proof, its envelope names
#      this agent, and (with cast) the signature recovers to the seal addr
#      over the EIP-191 version-0x00 ServeProof digest bound to /config's
#      verified_feedback_addr — the same check VerifiedFeedbackRegistry
#      makes, gas-free, so a validator / image skew shows up here first
#
# Usage:
#   API=http://sandbox.example:8080 AGENT_ID=61 scripts/verify-agent.sh
#   scripts/verify-agent.sh --kat   # offline: pin check 3b's digest to the
#                                   # cross-impl known-answer vector (cast + jq)
#
# Env:
#   API       attestor base URL            (default http://localhost:8080)
#   AGENT_ID  on-chain agentId to verify   (required)
#   RPC       chain RPC for the getAgentSeal cross-check; skipped if cast
#             is unavailable                (default: /config's chain_rpc)
set -euo pipefail

# serveproof_digest CHAIN_ID IDENTITY_REGISTRY VALIDATOR ENVELOPE_JSON prints
# the ServeProof signed digest for an X-Agent-Proof envelope — what agent_seal
# signs RAW (no further wrap): keccak256(0x19 ‖ 0x00 ‖ validator ‖ proofHash),
# proofHash = keccak256(abi.encode(chainId, identityRegistry, submitter,
# agentId, timestamp, deadline, taskHash, keccak256(packed dataHashes),
# frameworkHash)). One of the five consensus-critical copies listed in
# AGENTS.md; `--kat` pins it (run by sdk/typescript/test/serveproof-copies).
serveproof_digest() {
  local env_json=$4 dh inner
  _env() { printf '%s' "$env_json" | jq -r "$1"; }
  dh=$(cast keccak "0x$(_env '(.data_hashes // []) | map(ltrimstr("0x")) | join("")')") &&
  inner=$(cast keccak "$(cast abi-encode \
    'f(uint256,address,address,uint256,uint256,uint256,bytes32,bytes32,bytes32)' \
    "$1" "$2" "$(_env '.submitter // "0x0000000000000000000000000000000000000000"')" \
    "$(_env '.agent_id // empty')" "$(_env .timestamp)" "$(_env .deadline)" \
    "$(_env .task_hash)" "$dh" "$(_env .framework_hash)")") &&
  cast keccak "0x1900${3#0x}${inner#0x}"
}

if [ "${1:-}" = "--kat" ]; then
  # Same fixed inputs and expected digest as contracts / sealed / the SDK.
  KAT_ENV='{"agent_id":"42","submitter":"0x00000000000000000000000000000000000000C1","timestamp":1700000000,"deadline":1700003600,"task_hash":"0x1111111111111111111111111111111111111111111111111111111111111111","data_hashes":["0x2222222222222222222222222222222222222222222222222222222222222222","0x3333333333333333333333333333333333333333333333333333333333333333"],"framework_hash":"0x4444444444444444444444444444444444444444444444444444444444444444"}'
  KAT_WANT=0xd496f88d3bf02a04b2a078a15fcbf00f0793088cf291bb58a4534853af155d0b
  KAT_GOT=$(serveproof_digest 16602 0x00000000000000000000000000000000000000A9 \
    0x00000000000000000000000000000000000000B7 "$KAT_ENV") || KAT_GOT=""
  if [ "$KAT_GOT" = "$KAT_WANT" ]; then echo "OK   serveproof_digest KAT ($KAT_GOT)"; exit 0; fi
  echo "FAIL serveproof_digest KAT: got '$KAT_GOT', want $KAT_WANT"; exit 1
fi

API="${API:-http://localhost:8080}"
: "${AGENT_ID:?set AGENT_ID (decimal on-chain agent id)}"
# sandbox_id / agent_seal_addr are owner-tier fields; the public /deployments
# list omits them, so this check needs the owner key to sign the owner-scoped
# request.
: "${OWNER_PRIV:?set OWNER_PRIV (owner key; needed for the owner-scoped deployment row)}"

fail=0
say()  { printf '%s\n' "$*"; }
ok()   { say "OK   $*"; }
bad()  { say "FAIL $*"; fail=1; }

CONFIG=$(curl -fsS -m 10 "$API/config")
RPC="${RPC:-$(echo "$CONFIG" | jq -r .chain_rpc)}"
CONTRACT=$(echo "$CONFIG" | jq -r .agentic_id_addr)
CHAIN_ID=$(echo "$CONFIG" | jq -r .chain_id)
# ServeProof validator: the VerifiedFeedbackRegistry proxy the attestor
# injects into containers as VERIFIED_FEEDBACK_ADDR. Blank → no proofs.
VF=$(echo "$CONFIG" | jq -r '.verified_feedback_addr // empty' | tr '[:upper:]' '[:lower:]')
[ "$VF" = "0x0000000000000000000000000000000000000000" ] && VF=""
PROXY=$(echo "$CONFIG" | jq -r .sandbox_proxy_addr)
SERVE_PORT=$(echo "$CONFIG" | jq -r .agent_serve_port)

# ── locate the deployment row via the attestor API ─────────────────────
# agent_id is served as 0x-hex; accept a decimal AGENT_ID and match on value.
# Use the owner-scoped tier (EIP-191 signature) so the row carries sandbox_id /
# agent_seal_addr — the public list omits them.
AGENT_HEX=$(printf '0x%x' "$AGENT_ID")
OWNER_ADDR=$(cast wallet address "$OWNER_PRIV")
AUTH_TS=$(date +%s)
AUTH_MSG="0GDeployments:${OWNER_ADDR}:${AUTH_TS}"
AUTH_SIG=$(cast wallet sign --private-key "$OWNER_PRIV" "$AUTH_MSG")
ROW=$(curl -fsS -m 10 -H "X-Auth-Message: $AUTH_MSG" -H "X-Auth-Signature: $AUTH_SIG" \
      "$API/deployments?owner=$OWNER_ADDR" \
  | jq -c --arg hex "$AGENT_HEX" --arg dec "$AGENT_ID" \
      '[.[] | select(((.agent_id // "")|ascii_downcase)==$hex or ((.agent_id // "")|tostring)==$dec)] | first // empty')
[ -n "$ROW" ] || { bad "no deployment row for agent_id=$AGENT_ID at $API"; exit 1; }

DB_ADDR=$(echo "$ROW" | jq -r .agent_seal_addr | tr '[:upper:]' '[:lower:]')
SANDBOX=$(echo "$ROW" | jq -r '.sandbox_id // empty')
PHASE=$(echo "$ROW" | jq -r .phase)
say "row: phase=$PHASE seal_addr=$DB_ADDR sandbox=$SANDBOX"
[ "$PHASE" = "running" ] && ok "phase=running" || bad "phase=$PHASE (expected running)"
[ -n "$SANDBOX" ] || { bad "no sandbox_id on the row"; exit 1; }

# ── 1a. chain: getAgentSeal must equal the row ──────────────────────────
if command -v cast >/dev/null 2>&1; then
  CHAIN_ADDR=$(cast call --rpc-url "$RPC" "$CONTRACT" "getAgentSeal(uint256)(address)" "$AGENT_ID" | tr '[:upper:]' '[:lower:]')
  if [ "$CHAIN_ADDR" = "$DB_ADDR" ]; then ok "chain getAgentSeal == attestor row ($CHAIN_ADDR)"
  else bad "chain getAgentSeal=$CHAIN_ADDR != row=$DB_ADDR"; fi
else
  say "SKIP chain cross-check (cast not installed)"
fi

# ── 1b + 2. sealed bootstrap log: provisioned addr + decrypt health ─────
LOG_URL="http://${SERVE_PORT}-${SANDBOX}.${PROXY}/log.html"
LOG=$(curl -fsS -m 20 "$LOG_URL" | sed 's/<[^>]*>/\n/g')
# The log page abbreviates addresses ("0xBbab...d211"), so compare by
# prefix+suffix instead of full equality.
PROV_ABBR=$(printf '%s' "$LOG" | grep -aA3 "provisioned agent_seal_priv" | grep -aoE "0x[a-fA-F0-9]+(\.\.\.[a-fA-F0-9]+)?" | head -1 | tr '[:upper:]' '[:lower:]' || true)
if [ -n "$PROV_ABBR" ]; then
  PFX=${PROV_ABBR%%...*}; SFX=${PROV_ABBR##*...}
  if [[ "$DB_ADDR" == "$PFX"* && "$DB_ADDR" == *"$SFX" ]]; then
    ok "container provisioned addr matches row ($PROV_ABBR ~ $DB_ADDR)"
  else
    bad "container provisioned addr=$PROV_ABBR does not match row=$DB_ADDR (KMS derive drift?)"
  fi
else
  say "SKIP provisioned-addr check (line not found in log page)"
fi

FAILS=$(printf '%s' "$LOG" | grep -ac "^FAIL" || true)
DECRYPTED=$(printf '%s' "$LOG" | grep -ac "decrypted (" || true)
if [ "${FAILS:-0}" -eq 0 ] && [ "${DECRYPTED:-0}" -ge 1 ]; then
  ok "bootstrap decrypt: $DECRYPTED entries decrypted, 0 FAIL lines"
else
  bad "bootstrap log: FAIL lines=$FAILS decrypted=$DECRYPTED (url: $LOG_URL)"
fi

# ── 3. /hello + X-Agent-Proof ───────────────────────────────────────────
HELLO_URL="http://${SERVE_PORT}-${SANDBOX}.${PROXY}/hello"
HDRS=$(mktemp); BODY=$(mktemp)
HTTP=$(curl -s -m 20 -D "$HDRS" -o "$BODY" -w "%{http_code}" "$HELLO_URL" || echo 000)
PROOF=$(grep -ai "^x-agent-proof:" "$HDRS" | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r' || true)
HELLO_AGENT=$(jq -r '.agent // empty' "$BODY" 2>/dev/null | tr '[:upper:]' '[:lower:]')
rm -f "$HDRS" "$BODY"
[ "$HTTP" = "200" ] && ok "/hello HTTP 200" || bad "/hello HTTP $HTTP"
if [ -n "$PROOF" ]; then
  ok "X-Agent-Proof header present"
else
  bad "X-Agent-Proof header missing"
  [ -n "$VF" ] || say "     (/config has no verified_feedback_addr: containers get a blank VERIFIED_FEEDBACK_ADDR and emit no proof)"
fi
if [ -n "$HELLO_AGENT" ] && [ "$HELLO_AGENT" = "$DB_ADDR" ]; then
  ok "/hello agent field == seal addr"
elif [ -n "$HELLO_AGENT" ]; then
  bad "/hello agent=$HELLO_AGENT != row=$DB_ADDR"
fi

# ── 3b. ServeProof signature recovery (what the registry checks) ────────
# digest = serveproof_digest (top of file); the signature is over the digest
# RAW (cast --no-hash).
if [ -n "$PROOF" ]; then
  SIG=${PROOF%%.*}
  # base64url → JSON (jq: url alphabet → std, re-pad, decode)
  ENV_JSON=$(printf '%s' "${PROOF#*.}" \
    | jq -Rr 'gsub("-";"+") | gsub("_";"/") | . + ("=" * ((4 - length % 4) % 4)) | @base64d' 2>/dev/null || true)
  E_AGENT=$(printf '%s' "$ENV_JSON" | jq -r '.agent_id // empty' 2>/dev/null || true)
  E_VAL=$(printf '%s' "$ENV_JSON" | jq -r '.validator // empty' 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
  if [ "$E_AGENT" = "$AGENT_ID" ]; then ok "proof envelope agent_id == $AGENT_ID"
  else bad "proof envelope agent_id='$E_AGENT' != $AGENT_ID"; fi
  if ! command -v cast >/dev/null 2>&1; then
    say "SKIP ServeProof signature recovery (cast not installed)"
  elif [ -z "$VF" ]; then
    say "SKIP ServeProof signature recovery (/config has no verified_feedback_addr — unverifiable)"
  elif [ -n "$E_VAL" ] && [ "$E_VAL" != "$VF" ]; then
    bad "proof signed for a different registry: envelope validator=$E_VAL != /config verified_feedback_addr=$VF"
  else
    DIGEST=$(serveproof_digest "$CHAIN_ID" "$CONTRACT" "$VF" "$ENV_JSON") || DIGEST=""
    if [ -z "$DIGEST" ]; then
      bad "ServeProof digest: could not rebuild from envelope ($ENV_JSON)"
    elif cast wallet verify --no-hash --address "$DB_ADDR" "$DIGEST" "$SIG" >/dev/null 2>&1; then
      ok "ServeProof signature recovers to seal addr (validator $VF)"
    else
      hint=""; [ -n "$E_VAL" ] || hint=" (envelope has no validator — legacy sealed image? owner must /reset)"
      bad "ServeProof signature does not recover to seal addr $DB_ADDR$hint"
    fi
  fi
fi

say ""
if [ "$fail" -eq 0 ]; then say "✅ verify-agent: ALL CHECKS PASSED (agent_id=$AGENT_ID)"; else say "❌ verify-agent: FAILURES ABOVE (agent_id=$AGENT_ID)"; exit 1; fi
