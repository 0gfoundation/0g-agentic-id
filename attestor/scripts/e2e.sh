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
# Snapshot comes from the attestor's /config (operators bump
# ATTESTOR_SANDBOX_SNAPSHOT); hardcoding it here rots — a stale name makes
# sandbox create 400 ("snapshot not found") while storage/mint succeed,
# minting an offline agent. Fall back to the legacy default only if /config
# is unreadable (older attestor).
SNAPSHOT=$(curl -fsS -m 10 "$API/config" | jq -r '.sandbox_snapshot // empty' || true)
SNAPSHOT="${SNAPSHOT:-0g-test-sealed}"
echo "snapshot    = $SNAPSHOT (from $API/config)"

# Inference key injected into the container. Honors $API_KEY (regression.sh
# exports it); a dummy default is fine for identity/decrypt/serve-proof
# checks but real chat needs a real 0g-compute key.
API_KEY="${API_KEY:-sk-test-abc123xyz}"
PAYLOAD=$(jq -cn \
  --arg snapshot "$SNAPSHOT" \
  --arg apikey "$API_KEY" \
  '{snapshot:$snapshot, sealed:true, env:{API_KEY:$apikey}}')

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
# Top-level display fields replace the old opaque `agent_card`. `i_data`
# is the complete minted content (WYSIWYS) — built below with the
# required framework binding.
AGENT_NAME="E2EAgent"
AGENT_DESCRIPTION="smoke test"

# WYSIWYS: the attestor synthesizes no iData — the client ships the
# complete set, and a role="framework" binding is REQUIRED (validated
# against /config's supported_frameworks before the mint). This is the
# same two-entry default the SDK's defaultIData() builds.
IDATA=$(jq -cn --arg name "$AGENT_NAME" --arg desc "$AGENT_DESCRIPTION" '[
  {role:"framework", plaintext:{name:"openclaw", schema_version:1}, extra:{}},
  {role:"persona", plaintext:{system_prompt:("You are "+$name+". "+$desc+"\n"),
    inference:{provider:"anthropic", model:"claude-opus-4-6"}}, extra:{}}
]')

# Build the canonical owner-signed payload. Field order here doesn't need
# to match server struct order (serde parses unordered); what MUST match
# is that the EXACT bytes below are what's signed + base64'd.
# Using `--arg owner` (lowercase hex from cast wallet address) keeps the
# Address round-trip stable; serde accepts either checksummed or lower.
OWNER_LOWER=$(printf '%s' "$OWNER" | tr '[:upper:]' '[:lower:]')
OWNER_CANONICAL=$(jq -cn \
  --arg domain "AgenticID.Deploy.v1" \
  --arg idempotency_key "$IDEMP_KEY" \
  --arg owner "$OWNER_LOWER" \
  --arg name "$AGENT_NAME" \
  --arg description "$AGENT_DESCRIPTION" \
  --argjson image null \
  --argjson i_data "$IDATA" \
  '{domain:$domain, idempotency_key:$idempotency_key, owner:$owner, name:$name, description:$description, image:$image, i_data:$i_data}')

OWNER_SIG=$(cast wallet sign --private-key "$OWNER_PRIV" "$OWNER_CANONICAL")
OWNER_SIGNED_B64=$(printf '%s' "$OWNER_CANONICAL" | base64 | tr -d '\n')

deploy_payload=$(jq -cn \
  --arg idempotency_key "$IDEMP_KEY" \
  --arg owner "$OWNER" \
  --arg owner_signature "$OWNER_SIG" \
  --arg owner_signed_message_b64 "$OWNER_SIGNED_B64" \
  --arg name "$AGENT_NAME" \
  --arg description "$AGENT_DESCRIPTION" \
  --argjson i_data "$IDATA" \
  --argjson sandbox_envelope "$ENVELOPE" \
  '{
     idempotency_key:           $idempotency_key,
     owner:                     $owner,
     owner_signature:           $owner_signature,
     owner_signed_message_b64:  $owner_signed_message_b64,
     name:                      $name,
     description:               $description,
     i_data:                    $i_data,
     sandbox_envelope:          $sandbox_envelope
   }')

resp=$(curl -fsS -X POST "$API/deploy" \
  -H "Content-Type: application/json" \
  -d "$deploy_payload")
echo "$resp" | jq .

SEAL_ID=$(echo "$resp" | jq -r .seal_id)
AGENT_SEAL_ADDR=$(echo "$resp" | jq -r .agent_seal_addr)
echo "seal_id         = $SEAL_ID"
echo "agent_seal_addr = $AGENT_SEAL_ADDR"

banner "2. Poll /deployment/:id until phase ∈ {running, failed}"
# `ready` means container provisioned but hasn't reported /status running.
# We wait for the full handshake: container completed bootstrap and posted
# back, attestor flipped phase to running. Up to ~2 minutes — storage
# upload + container bootstrap together can take this long.
# First boot pulls image layers + npm-installs the framework — regularly
# >2 min on a cold provider. 300s keeps the deploy-side poll from declaring
# failure on a container that is merely still booting.
# A transient poll failure (timeout, connection reset) must cost one tick,
# not the whole deploy — a real round died on a single `curl: (28)` while
# the deploy itself succeeded (#120). Only PERSISTENT unreachability
# (5 consecutive failures) is fatal; every failed tick stays visible.
phase=""
consec_fails=0
for i in $(seq 1 300); do
  if ! state=$(curl -fsS -m 10 "$API/deployment/$SEAL_ID"); then
    consec_fails=$((consec_fails + 1))
    printf "  [%03d] poll failed (%d consecutive; fatal at 5)\n" "$i" "$consec_fails"
    if [ "$consec_fails" -ge 5 ]; then
      echo "❌ poll: attestor unreachable ($consec_fails consecutive failures)"; exit 1
    fi
    sleep 1; continue
  fi
  consec_fails=0
  phase=$(echo "$state" | jq -r .phase)
  storage=$(echo "$state" | jq -r .storage_stage.state)
  mint=$(echo "$state" | jq -r .mint_stage.state)
  container=$(echo "$state" | jq -r .container_stage.state)
  agent_id=$(echo "$state" | jq -r '.agent_id // "null"')
  printf "  [%03d] phase=%-12s storage=%-10s mint=%-10s container=%-10s agent_id=%s\n" \
    "$i" "$phase" "$storage" "$mint" "$container" "$agent_id"
  if [[ "$phase" == "running" || "$phase" == "failed" ]]; then
    break
  fi
  sleep 1
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

banner "3. Final /deployment/:id — expect phase=running"
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

if [[ "$phase" == "running" ]]; then
  echo "✅ PASS — phase=running (container completed bootstrap and reported running)"
  exit 0
else
  echo "❌ FAIL — phase=$phase (timed out waiting for container /status running)"
  exit 1
fi
