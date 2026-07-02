#!/usr/bin/env bash
# Upgrade the DEV AgenticIDReputationRegistry beacon impl to the current
# (client-less ServeProof) code. proxy address + storage are preserved.
#
# Dev deployment (CANONICAL_BINDING.md §5.2, AgenticID 0x5BB5, owner 0xB831):
#   Reputation proxy   0x884c2809888Bfd789919331eA1fB2DA9C31363d2  (bound to 0x5BB5)
#   Reputation beacon  0xd85172b48E824D8168E95f9D70E33091e5e1f9e2  <- upgrade target
#   Timelock           0x9715F9ffEa7d01552657CE9C6B115Ee6B32aA696  (minDelay=0, open executor)
#
# Prereq: DEPLOYER_KEY = the 0xB831 private key (deployer + Timelock PROPOSER).
# Timelock delay is 0, so schedule + execute run back-to-back, no wait.
#
#   DEPLOYER_KEY=0x... bash script/upgrade-dev-reputation.sh
set -euo pipefail

RPC="${RPC:-https://evmrpc-testnet.0g.ai}"
TIMELOCK=0x9715F9ffEa7d01552657CE9C6B115Ee6B32aA696
BEACON=0xd85172b48E824D8168E95f9D70E33091e5e1f9e2
PROXY=0x884c2809888Bfd789919331eA1fB2DA9C31363d2
IDENTITY=0x5BB50987521A3fb7Da6Cd6aCC0ad1061D975B24A
GAS=(--legacy --gas-price 10000000000)  # 0G testnet: 10 gwei legacy

: "${DEPLOYER_KEY:?set DEPLOYER_KEY (0xB831 private key)}"
export TIMELOCK BEACON

echo "== pre-flight =="
echo "  beacon impl (before): $(cast call "$BEACON" 'implementation()(address)' --rpc-url "$RPC")"
echo "  proxy identityRegistry: $(cast call "$PROXY" 'getIdentityRegistry()(address)' --rpc-url "$RPC")  (must be $IDENTITY)"

echo "== 1. deploy new impl =="
NEW_IMPL=$(forge create src/AgenticIDReputationRegistry.sol:AgenticIDReputationRegistry \
  --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" --broadcast "${GAS[@]}" --json | jq -r '.deployedTo')
echo "  NEW_IMPL=$NEW_IMPL"
export NEW_IMPL

echo "== 2. schedule (Timelock, as PROPOSER) =="
forge script script/ScheduleUpgrade.s.sol --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" \
  --broadcast "${GAS[@]}"

echo "== 3. execute (open executor; delay=0) =="
forge script script/ExecuteUpgrade.s.sol --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" \
  --broadcast "${GAS[@]}"

echo "== post =="
echo "  beacon impl (after): $(cast call "$BEACON" 'implementation()(address)' --rpc-url "$RPC")"
echo "  (should equal NEW_IMPL=$NEW_IMPL)"
echo
echo "Reputation proxy unchanged: $PROXY  (update SDK DEV_ADDRESSES to agenticID=$IDENTITY, reputationRegistry=$PROXY)"
