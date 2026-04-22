#!/usr/bin/env bash
# Test that indexer picks up EntryUpdated events.
# Owner calls updateAt on an agent they own -> EntryUpdated emitted ->
# indexer should update i_data[index].description + data_hash in DB.
set -euo pipefail

API="${API:-http://localhost:8080}"
RPC="${ATTESTOR_CHAIN_RPC:-https://evmrpc-testnet.0g.ai}"
CONTRACT="${ATTESTOR_AGENTIC_ID_ADDR:-0xf952e7dd046779f34c0ca0c058e1d940b7b9d525}"

ATTESTOR_PRIV="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ATTESTOR_ADDR="0xf39Fd6e51aad88F6F4ce6aB8827279cfFFb92266"
ZERO_SIG_65="0x$(printf '00%.0s' {1..65})"
IDEMP_KEY="entry-updated-test-$(date +%s)"

NEW_DESC='UPDATED BY INDEXER TEST'
NEW_HASH='0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'

banner() { printf "\n── %s ──\n" "$1"; }

# 1. Deploy with owner=attestor so we can call updateAt
banner "1. Deploy agent (owner=attestor)"
DEPLOY=$(curl -fsS -X POST "$API/deploy" \
  -H "Content-Type: application/json" \
  -d "$(cat <<JSON
{
  "idempotency_key": "$IDEMP_KEY",
  "owner": "$ATTESTOR_ADDR",
  "owner_signature": "$ZERO_SIG_65",
  "i_data": [{"role":"config","plaintext":{"test":true},"extra":{}}],
  "agent_card": {"name":"EntryTest","description":"test"}
}
JSON
)")
SEAL_ID=$(echo "$DEPLOY" | jq -r .seal_id)
echo "seal_id = $SEAL_ID"

# 2. Wait for mint
banner "2. Wait for mint"
AGENT_ID=""
for i in $(seq 1 30); do
  AGENT_ID=$(curl -fsS "$API/deployment/$SEAL_ID" | jq -r '.agent_id // ""')
  [[ -n "$AGENT_ID" && "$AGENT_ID" != "null" ]] && break
  sleep 1
done
echo "agent_id = $AGENT_ID"
AGENT_ID_DEC=$((AGENT_ID))
echo "agent_id (decimal) = $AGENT_ID_DEC"

# 3. Show DB state before
banner "3. DB description before"
SEAL_HEX=${SEAL_ID#0x}
BEFORE_DESC=$(docker exec attestor-postgres psql -U attestor -d attestor -tAc \
  "SELECT i_data->0->>'description' FROM deployments WHERE seal_id = decode('$SEAL_HEX','hex');")
echo "description_before = $BEFORE_DESC"

# 4. Call updateAt on chain
banner "4. cast send updateAt(agentId=$AGENT_ID_DEC, index=0, newData=(...))"
cast send "$CONTRACT" \
  'updateAt(uint256,uint256,(string,bytes32))' \
  "$AGENT_ID_DEC" 0 "(\"$NEW_DESC\",$NEW_HASH)" \
  --rpc-url "$RPC" \
  --private-key "$ATTESTOR_PRIV" \
  --priority-gas-price 2gwei 2>&1 | grep -iE 'transaction|block|status' | head

# 5. Wait for indexer
banner "5. Wait for indexer (15s)"
sleep 15

# 6. Check DB
banner "6. DB after"
AFTER_DESC=$(docker exec attestor-postgres psql -U attestor -d attestor -tAc \
  "SELECT i_data->0->>'description' FROM deployments WHERE seal_id = decode('$SEAL_HEX','hex');")
AFTER_HASH=$(docker exec attestor-postgres psql -U attestor -d attestor -tAc \
  "SELECT i_data->0->>'data_hash' FROM deployments WHERE seal_id = decode('$SEAL_HEX','hex');")
echo "description_after = $AFTER_DESC"
echo "data_hash_after   = $AFTER_HASH"

if [[ "$AFTER_DESC" == "$NEW_DESC" ]]; then
  echo "✅ PASS — indexer detected EntryUpdated"
else
  echo "❌ FAIL — description not updated"
  exit 1
fi
