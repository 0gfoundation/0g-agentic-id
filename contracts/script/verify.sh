#!/usr/bin/env bash
# Verify a BeaconProxy -> beacon -> implementation and its linked libraries.
# Usage (from contracts/): script/verify.sh <proxy> [<impl-path:name>]
# Build with the actual deployment profile first. Compiler settings and library
# addresses come only from artifacts whose entire runtime matches the chain.
# No --watch: the 0G explorer's verification polling is unreliable.
set -euo pipefail

PROXY=${1:-}
IMPL_HINT=${2:-}
if [ -z "$PROXY" ]; then
    echo "usage: $0 <proxy-address> [<impl-path:name>]" >&2
    exit 1
fi
: "${RPC_URL:=https://evmrpc-testnet.0g.ai}"
: "${VERIFIER_URL:=https://chainscan-galileo.0g.ai/open/api}"
: "${CHAIN_ID:=16602}"
: "${ARTIFACTS_DIR:=out}"

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
HELPER="$SCRIPT_DIR/verify_artifact.py"
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/agentic-verify.XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT
ORDER="$WORK_DIR/order.tsv"
touch "$ORDER"

ERC1967_BEACON_SLOT=0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50
IMPL_CANDIDATES=(
    "src/AgenticID.sol:AgenticID"
    "src/AgenticIDReputationRegistry.sol:AgenticIDReputationRegistry"
    "src/VerifiedFeedbackRegistry.sol:VerifiedFeedbackRegistry"
    "src/verifiers/TEEDataVerifier.sol:TEEDataVerifier"
)
BEACON_SRC="lib/openzeppelin-contracts/contracts/proxy/beacon/UpgradeableBeacon.sol:UpgradeableBeacon"
PROXY_SRC="lib/openzeppelin-contracts/contracts/proxy/beacon/BeaconProxy.sol:BeaconProxy"

check_address() {
    if [[ ! "$1" =~ ^0x[0-9a-fA-F]{40}$ ]] || [[ "$1" =~ ^0x0{40}$ ]]; then
        echo "error: invalid nonzero contract address: $1" >&2
        return 1
    fi
}

is_verified() {
    local source
    source=$(curl --fail -sS --get "$VERIFIER_URL" \
        --data-urlencode module=contract --data-urlencode action=getsourcecode \
        --data-urlencode "address=$1" | jq -r '.result[0].SourceCode // ""')
    [ -n "$source" ] && [ "$source" != "null" ]
}

# Freeze all plans before forge can rebuild artifacts with another profile.
# Dependencies are queued first; each linked library is matched and verified.
prepare_one() {
    local label=$1 addr=$2 hint=$3
    check_address "$addr"
    addr=$(printf '%s' "$addr" | tr 'A-F' 'a-f')
    local plan="$WORK_DIR/$addr.json"
    if [ -f "$plan" ]; then
        if [ -n "$hint" ] && [ "$(jq -r '.source' "$plan")" != "$hint" ]; then
            echo "error: $addr was requested as two different source contracts" >&2
            return 1
        fi
        return
    fi
    local runtime="$WORK_DIR/$addr.runtime"
    cast code "$addr" --rpc-url "$RPC_URL" > "$runtime"
    local candidates=() candidate
    if [ -n "$hint" ]; then
        candidates=(--candidate "$hint")
    else
        for candidate in "${IMPL_CANDIDATES[@]}"; do
            candidates+=(--candidate "$candidate")
        done
    fi
    python3 "$HELPER" match --artifacts "$ARTIFACTS_DIR" \
        --runtime-file "$runtime" --address "$addr" "${candidates[@]}" > "$plan"
    printf 'matched %-7s %s -> %s\n' "$label" "$addr" "$(jq -r '.source' "$plan")"
    local lib_addr lib_source
    while IFS=$'\t' read -r lib_addr lib_source; do
        prepare_one library "$lib_addr" "$lib_source"
    done < <(jq -r '.libraries[] | [.address, .source] | @tsv' "$plan")
    printf '%s\t%s\n' "$label" "$addr" >> "$ORDER"
}

verify_one() {
    local label=$1 addr=$2 plan="$WORK_DIR/$2.json"
    local src
    src=$(jq -r '.source' "$plan")
    printf '\n=== %-7s %s\n       source: %s\n' "$label" "$addr" "$src"
    if is_verified "$addr"; then
        printf '       already verified, skip\n'
        return
    fi
    local creation="$WORK_DIR/$addr.creation" args
    curl --fail -sS --get "$VERIFIER_URL" --data-urlencode module=contract \
        --data-urlencode action=getcontractcreation --data-urlencode "contractaddresses=$addr" \
        | jq -r '.result[0].creationBytecode // ""' > "$creation"
    args=$(python3 "$HELPER" constructor-args --plan-file "$plan" --creation-file "$creation")
    python3 "$HELPER" verify --plan-file "$plan" --address "$addr" \
        --chain "$CHAIN_ID" --verifier-url "$VERIFIER_URL" --constructor-args "$args"
}

check_address "$PROXY"
PROXY=$(printf '%s' "$PROXY" | tr 'A-F' 'a-f')
raw=$(cast storage "$PROXY" "$ERC1967_BEACON_SLOT" --rpc-url "$RPC_URL")
BEACON=0x${raw: -40}
check_address "$BEACON"
IMPL=$(cast call "$BEACON" "implementation()(address)" --rpc-url "$RPC_URL")
check_address "$IMPL"
printf 'rpc: %s\nverifier: %s\nproxy: %s\nbeacon: %s\nimpl: %s\n\n' \
    "$RPC_URL" "$VERIFIER_URL" "$PROXY" "$BEACON" "$IMPL"

prepare_one impl "$IMPL" "$IMPL_HINT"
prepare_one beacon "$BEACON" "$BEACON_SRC"
prepare_one proxy "$PROXY" "$PROXY_SRC"
# The proxy delegates through its immutable beacon, not the discovery slot.
# Reject an inconsistent chain before any submission or already-verified skip.
python3 "$HELPER" check-beacon --plan-file "$WORK_DIR/$PROXY.json" --beacon "$BEACON"
while IFS=$'\t' read -r label addr; do
    verify_one "$label" "$addr"
done < "$ORDER"
echo "done."
