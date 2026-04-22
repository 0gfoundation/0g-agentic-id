#!/usr/bin/env bash
# End-to-end smoke test. Requires: attestor-api, attestor-worker, attestor-indexer
# all running + Postgres up.

set -euo pipefail

API="${API:-http://localhost:8080}"
IDEMP_KEY="test-$(date +%s)"

OWNER="0x1111111111111111111111111111111111111111"

# secp256k1 compressed pubkey for priv=1 (the generator G). Used as container
# pubkey in /provision so ECIES encryption succeeds. Not secret.
CONTAINER_PUB="0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"

ZERO_HASH="0x0000000000000000000000000000000000000000000000000000000000000001"
ZERO_SIG_65="0x$(printf '00%.0s' {1..65})"

jq_bin="$(command -v jq || true)"
if [[ -z "$jq_bin" ]]; then echo "install jq first"; exit 1; fi

banner() { printf "\n── %s ──\n" "$1"; }

banner "1. POST /deploy"
deploy_payload=$(cat <<JSON
{
  "idempotency_key": "$IDEMP_KEY",
  "owner": "$OWNER",
  "owner_signature": "$ZERO_SIG_65",
  "i_data": [
    {
      "role": "config",
      "plaintext": {
        "framework": {"name": "openclaw", "version": "0.1.0"},
        "persona":   {"system_prompt": "you are e2e"},
        "inference": {"provider": "mock", "model": "mock"}
      },
      "extra": {}
    }
  ],
  "agent_card": {
    "name": "E2EAgent",
    "description": "smoke test"
  }
}
JSON
)

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

banner "3. POST /provision (simulate container)"
provision_payload=$(cat <<JSON
{
  "seal_id":          "$SEAL_ID",
  "container_pubkey": "$CONTAINER_PUB",
  "image_hash":       "$ZERO_HASH",
  "issued_at":        $(date +%s),
  "sandbox_signature":"$ZERO_SIG_65"
}
JSON
)
prov=$(curl -fsS -X POST "$API/provision" \
  -H "Content-Type: application/json" \
  -d "$provision_payload")
echo "$prov" | jq '{encrypted_len: (.encrypted_agent_seal_priv|length)}'

banner "4. POST /status (container reports running)"
status_payload=$(cat <<JSON
{
  "seal_id": "$SEAL_ID",
  "status":  "running",
  "agent_seal_signature": "$ZERO_SIG_65"
}
JSON
)
curl -fsS -X POST "$API/status" \
  -H "Content-Type: application/json" \
  -d "$status_payload" | jq .

banner "5. Final /deployment/:id — expect phase=running"
final=$(curl -fsS "$API/deployment/$SEAL_ID")
echo "$final" | jq '{
  phase,
  agent_id,
  storage_stage: .storage_stage.state,
  mint_stage:    .mint_stage.state,
  container_stage: .container_stage.state
}'

phase=$(echo "$final" | jq -r .phase)
if [[ "$phase" == "running" ]]; then
  echo "✅ PASS — phase=running"
  exit 0
else
  echo "❌ FAIL — phase=$phase (expected running)"
  exit 1
fi
