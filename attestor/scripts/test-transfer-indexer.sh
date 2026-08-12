#!/usr/bin/env bash
# Test that indexer picks up Transfer events and updates owner in DB.
set -euo pipefail

API="${API:-http://localhost:8080}"
RPC="${ATTESTOR_CHAIN_RPC:-https://evmrpc-testnet.0g.ai}"
CONTRACT="${ATTESTOR_AGENTIC_ID_ADDR:-0xf952e7dd046779f34c0ca0c058e1d940b7b9d525}"

# Attestor EOA (MOCK_APP_PRIVATE_KEY — corresponds to 0xf39F...C66)
ATTESTOR_PRIV="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ATTESTOR_ADDR="0xf39Fd6e51aad88F6F4ce6aB8827279cfFFb92266"
NEW_OWNER="0x000000000000000000000000000000000000dEaD"
ZERO_SIG_65="0x$(printf '00%.0s' {1..65})"
IDEMP_KEY="transfer-test-$(date +%s)"

banner() { printf "\n── %s ──\n" "$1"; }

# 1. Deploy agent with OWNER = attestor so we can transfer it
banner "1. Deploy agent with owner=$ATTESTOR_ADDR"
DEPLOY=$(curl -fsS -X POST "$API/deploy" \
  -H "Content-Type: application/json" \
  -d "$(cat <<JSON
{
  "idempotency_key": "$IDEMP_KEY",
  "owner": "$ATTESTOR_ADDR",
  "owner_signature": "$ZERO_SIG_65",
  "name": "TransferTest",
  "description": "indexer transfer detection",
  "i_data": [{"role":"config","plaintext":{"test":true},"extra":{}}]
}
JSON
)")
SEAL_ID=$(echo "$DEPLOY" | jq -r .seal_id)
echo "seal_id = $SEAL_ID"

# 2. Wait for mint to complete
banner "2. Wait for mint (up to 30s)"
for i in $(seq 1 30); do
  # One fetch per tick; `|| true` keeps a transient curl failure from killing
  # the script via set -e — the post-loop check handles the empty case (#120)
  STATE=$(curl -fsS -m 10 "$API/deployment/$SEAL_ID" || true)
  AGENT_ID=$(echo "$STATE" | jq -r '.agent_id // ""' 2>/dev/null || true)
  PHASE=$(echo "$STATE" | jq -r '.phase // ""' 2>/dev/null || true)
  if [[ -n "$AGENT_ID" && "$AGENT_ID" != "null" && "$AGENT_ID" != "" ]]; then
    echo "agent_id = $AGENT_ID (phase=$PHASE)"
    break
  fi
  sleep 1
done

if [[ -z "${AGENT_ID:-}" || "$AGENT_ID" == "null" ]]; then
  echo "❌ mint did not produce agent_id in time"
  exit 1
fi

# 3. Verify DB owner is attestor
banner "3. Check DB owner before transfer"
SEAL_HEX=${SEAL_ID#0x}
QUERY_OWNER="SELECT '0x' || encode(owner,'hex') FROM deployments WHERE seal_id = decode('$SEAL_HEX','hex');"
BEFORE=$(docker exec attestor-postgres psql -U attestor -d attestor -tAc "$QUERY_OWNER" | tr -d '[:space:]')
echo "owner_before = $BEFORE"

# 4. Transfer on chain
banner "4. cast send transferFrom($ATTESTOR_ADDR → $NEW_OWNER)"
cast send "$CONTRACT" \
  'transferFrom(address,address,uint256)' \
  "$ATTESTOR_ADDR" "$NEW_OWNER" "$AGENT_ID" \
  --rpc-url "$RPC" \
  --private-key "$ATTESTOR_PRIV" 2>&1 | grep -E '^(transactionHash|status|blockNumber)' || true

# 5. Wait for indexer to pick it up
banner "5. Wait for indexer (10s)"
sleep 10

# 6. Verify DB owner is updated
banner "6. Check DB owner after indexer"
AFTER=$(docker exec attestor-postgres psql -U attestor -d attestor -tAc "$QUERY_OWNER" | tr -d '[:space:]')
echo "owner_after = $AFTER"
echo "expected    = ${NEW_OWNER,,}"

if [[ "${AFTER,,}" == "${NEW_OWNER,,}" ]]; then
  echo "✅ PASS — indexer detected Transfer and updated owner"
else
  echo "❌ FAIL — owner not updated (still $AFTER)"
  echo "   indexer may not have caught up; wait longer and re-check"
  exit 1
fi
