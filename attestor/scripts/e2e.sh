#!/usr/bin/env bash
# End-to-end smoke test. Requires: attestor-api, attestor-worker, attestor-indexer
# all running + Postgres up.
#
# Env:
#   OWNER_PRIV   — required. 32-byte hex private key of the agent owner.
#                  Also used to sign the sandbox envelope. For MOCK_SANDBOX=true
#                  any valid key works; for real sandbox the derived address
#                  must be funded (sandbox charges per create).
#   API          — attestor-api base URL (default http://localhost:8080)

set -euo pipefail

API="${API:-http://localhost:8080}"
: "${OWNER_PRIV:?set OWNER_PRIV (32-byte hex, e.g. from attestor/.env)}"
IDEMP_KEY="test-$(date +%s)"

OWNER=$(cast wallet address --private-key "$OWNER_PRIV")

# secp256k1 compressed pubkey for priv=1 (the generator G). Used as container
# pubkey in /provision so ECIES encryption succeeds. Not secret.
CONTAINER_PUB="0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"

ZERO_HASH="0x0000000000000000000000000000000000000000000000000000000000000001"
ZERO_SIG_65="0x$(printf '00%.0s' {1..65})"

banner() { printf "\n── %s ──\n" "$1"; }

# ── Build sandbox envelope ─────────────────────────────────────────────
# User signs a canonical JSON; attestor relays the bytes + sig verbatim to
# sandbox. Field order MUST be {action, expires_at, nonce, payload, resource_id}
# — matches Go's json.Marshal of the sandbox `signedRequest` struct.

NONCE=$(openssl rand -hex 16)
EXPIRES_AT=$(($(date +%s) + 180))

# The payload is whatever the user wants sandbox to receive as the HTTP body.
# Attestor doesn't inspect it — only relays. For the smoke test a minimal
# object is fine; in real flows this would carry snapshot ref / env vars.
PAYLOAD=$(jq -cn \
  --arg snapshot "0g-test-sealed" \
  '{snapshot:$snapshot, sealed:true, env:{API_KEY:"sk-test-abc123xyz"}}')

# Canonical JSON with strict field order. `-c` is mandatory: any whitespace
# will shift the bytes vs what base64 encodes, and the signature will no
# longer recover to OWNER.
CANONICAL=$(jq -cn \
  --arg action "create" \
  --argjson expires_at "$EXPIRES_AT" \
  --arg nonce "$NONCE" \
  --argjson payload "$PAYLOAD" \
  --arg resource_id "" \
  '{action:$action, expires_at:$expires_at, nonce:$nonce, payload:$payload, resource_id:$resource_id}')

# EIP-191 personal_sign with V ∈ {27,28}. `cast wallet sign` does this by
# default — do NOT add --no-hash (that skips the prefix and breaks recover).
SIG=$(cast wallet sign --private-key "$OWNER_PRIV" "$CANONICAL")

# Base64 the *exact* bytes that were signed. Use printf (not echo) and strip
# any wrapping newline so the bytes round-trip byte-for-byte on the server.
B64=$(printf '%s' "$CANONICAL" | base64 | tr -d '\n')

ENVELOPE=$(jq -cn \
  --arg wallet_address "$OWNER" \
  --arg signed_message_b64 "$B64" \
  --arg wallet_signature "$SIG" \
  '{wallet_address:$wallet_address, signed_message_b64:$signed_message_b64, wallet_signature:$wallet_signature}')

echo "owner       = $OWNER"
echo "expires_at  = $EXPIRES_AT ($(date -d @"$EXPIRES_AT" -u 2>/dev/null || true))"
echo "nonce       = $NONCE"

# ── 1. POST /deploy ────────────────────────────────────────────────────
banner "1. POST /deploy"
deploy_payload=$(jq -cn \
  --arg idempotency_key "$IDEMP_KEY" \
  --arg owner "$OWNER" \
  --arg owner_signature "$ZERO_SIG_65" \
  --argjson i_data '[
    {
      "role": "config",
      "plaintext": {
        "framework": {"name": "openclaw", "version": "0.1.0"},
        "persona":   {"system_prompt": "you are e2e"},
        "inference": {"provider": "mock", "model": "mock"}
      },
      "extra": {}
    }
  ]' \
  --argjson agent_card '{"name":"E2EAgent","description":"smoke test"}' \
  --argjson sandbox_envelope "$ENVELOPE" \
  '{
     idempotency_key:  $idempotency_key,
     owner:            $owner,
     owner_signature:  $owner_signature,
     i_data:           $i_data,
     agent_card:       $agent_card,
     sandbox_envelope: $sandbox_envelope
   }')

resp=$(curl -fsS -X POST "$API/deploy" \
  -H "Content-Type: application/json" \
  -d "$deploy_payload")
echo "$resp" | jq .

SEAL_ID=$(echo "$resp" | jq -r .seal_id)
AGENT_SEAL_ADDR=$(echo "$resp" | jq -r .agent_seal_addr)
echo "seal_id         = $SEAL_ID"
echo "agent_seal_addr = $AGENT_SEAL_ADDR"

banner "2. Poll /deployment/:id until phase ∈ {ready, running, failed}"
for i in $(seq 1 30); do
  state=$(curl -fsS "$API/deployment/$SEAL_ID")
  phase=$(echo "$state" | jq -r .phase)
  storage=$(echo "$state" | jq -r .storage_stage.state)
  mint=$(echo "$state" | jq -r .mint_stage.state)
  container=$(echo "$state" | jq -r .container_stage.state)
  agent_id=$(echo "$state" | jq -r '.agent_id // "null"')
  printf "  [%02d] phase=%-12s storage=%-10s mint=%-10s container=%-10s agent_id=%s\n" \
    "$i" "$phase" "$storage" "$mint" "$container" "$agent_id"
  if [[ "$phase" == "ready" || "$phase" == "running" || "$phase" == "failed" ]]; then
    break
  fi
  sleep 0.5
done

if [[ "$phase" == "failed" ]]; then
  echo "❌ deploy failed"; echo "$state" | jq .; exit 1
fi

# banner "4. POST /status (container reports running)"
# status_payload=$(cat <<JSON
# {
#   "seal_id": "$SEAL_ID",
#   "status":  "running",
#   "agent_seal_signature": "$ZERO_SIG_65"
# }
# JSON
# )
# curl -fsS -X POST "$API/status" \
#   -H "Content-Type: application/json" \
#   -d "$status_payload" | jq .

banner "3. Final /deployment/:id — expect provisioned_at set"
final=$(curl -fsS "$API/deployment/$SEAL_ID")
echo "$final" | jq '{
  phase,
  agent_id,
  sandbox_id,
  provisioned_at,
  storage_stage: .storage_stage.state,
  mint_stage:    .mint_stage.state,
  container_stage: .container_stage.state
}'

provisioned_at=$(echo "$final" | jq -r '.provisioned_at // "null"')
if [[ "$provisioned_at" != "null" ]]; then
  echo "✅ PASS — provisioned_at=$provisioned_at"
  exit 0
else
  echo "❌ FAIL — provisioned_at not set (container didn't reach /provision)"
  exit 1
fi
