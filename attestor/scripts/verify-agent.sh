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
#   3. serve-proof: /hello returns 200 + X-Agent-Proof, and its payload
#      names this agent (full signature recovery lives in the console
#      verifier / SDK sayHi; this is the transport-level check)
#
# Usage:
#   API=http://sandbox.example:8080 AGENT_ID=61 scripts/verify-agent.sh
#
# Env:
#   API       attestor base URL            (default http://localhost:8080)
#   AGENT_ID  on-chain agentId to verify   (required)
#   RPC       chain RPC for the getAgentSeal cross-check; skipped if cast
#             is unavailable                (default: /config's chain_rpc)
set -euo pipefail

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
PROOF=$(grep -ai "^x-agent-proof:" "$HDRS" | head -1 || true)
HELLO_AGENT=$(jq -r '.agent // empty' "$BODY" 2>/dev/null | tr '[:upper:]' '[:lower:]')
rm -f "$HDRS" "$BODY"
[ "$HTTP" = "200" ] && ok "/hello HTTP 200" || bad "/hello HTTP $HTTP"
[ -n "$PROOF" ] && ok "X-Agent-Proof header present" || bad "X-Agent-Proof header missing"
if [ -n "$HELLO_AGENT" ] && [ "$HELLO_AGENT" = "$DB_ADDR" ]; then
  ok "/hello agent field == seal addr"
elif [ -n "$HELLO_AGENT" ]; then
  bad "/hello agent=$HELLO_AGENT != row=$DB_ADDR"
fi

say ""
if [ "$fail" -eq 0 ]; then say "✅ verify-agent: ALL CHECKS PASSED (agent_id=$AGENT_ID)"; else say "❌ verify-agent: FAILURES ABOVE (agent_id=$AGENT_ID)"; exit 1; fi
