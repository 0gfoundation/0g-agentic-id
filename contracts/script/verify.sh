#!/usr/bin/env bash
# Proxy-driven verify for a BeaconProxy chain on 0g Galileo testnet
# (or any Etherscan-compatible explorer).
#
# Usage:
#   script/verify.sh <proxy-address> [<impl-path:name>]
#
# Given a BeaconProxy address, walks proxy -> beacon -> impl via the ERC-1967
# beacon slot + beacon.implementation(), and for each of the three:
#   - checks whether the explorer already has verified source (getsourcecode);
#   - if not, extracts constructor args by subtracting runtime bytecode from
#     the creation bytecode (pulled from the explorer), and submits via
#     `forge verify-contract` without --watch (so the command exits cleanly
#     — polling against this endpoint is broken in forge 1.6, but submission
#     is all we need; the explorer processes within ~10s).
#
# Defaults (override via env):
#   RPC_URL         = https://evmrpc-testnet.0g.ai
#   VERIFIER_URL    = https://chainscan-galileo.0g.ai/open/api
#   CHAIN_ID        = 16602
#   COMPILER_VERSION= 0.8.24
#   OPTIMIZER_RUNS  = 200
#
# If <impl-path:name> is omitted, the script tries to match the on-chain impl
# runtime bytecode against a small list of known candidates (AgenticID /
# AgenticIDReputationRegistry / TEEDataVerifier). If the contract is a new
# type, pass the identifier explicitly, e.g.
#   script/verify.sh 0xaBE9...4971 src/AgenticIDV3.sol:AgenticIDV3

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
: "${COMPILER_VERSION:=0.8.24}"
: "${OPTIMIZER_RUNS:=200}"

# ERC-1967: bytes32(uint256(keccak256("eip1967.proxy.beacon")) - 1)
ERC1967_BEACON_SLOT=0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50

# Known impl candidates for auto-detect mode. Paths are relative to the
# foundry project root (where this script is invoked from); `forge inspect`
# resolves them via foundry.toml's `src = "src"`. Add new versions as they
# ship.
IMPL_CANDIDATES=(
    "src/AgenticID.sol:AgenticID"
    "src/AgenticIDReputationRegistry.sol:AgenticIDReputationRegistry"
    "src/verifiers/TEEDataVerifier.sol:TEEDataVerifier"
)

BEACON_SRC="lib/openzeppelin-contracts/contracts/proxy/beacon/UpgradeableBeacon.sol:UpgradeableBeacon"
PROXY_SRC="lib/openzeppelin-contracts/contracts/proxy/beacon/BeaconProxy.sol:BeaconProxy"

# ── chain resolution ────────────────────────────────────────────────────────

raw=$(cast storage "$PROXY" "$ERC1967_BEACON_SLOT" --rpc-url "$RPC_URL")
BEACON=0x${raw: -40}
if [ "$(printf '%s' "$BEACON" | tr 'A-F' 'a-f')" = "0x0000000000000000000000000000000000000000" ]; then
    echo "error: $PROXY has zero ERC-1967 beacon slot (not a BeaconProxy?)" >&2
    exit 1
fi
IMPL=$(cast call "$BEACON" "implementation()(address)" --rpc-url "$RPC_URL")

printf 'rpc     : %s\n' "$RPC_URL"
printf 'verifier: %s\n' "$VERIFIER_URL"
printf 'proxy   : %s\n' "$PROXY"
printf 'beacon  : %s\n' "$BEACON"
printf 'impl    : %s\n\n' "$IMPL"

# ── helpers ─────────────────────────────────────────────────────────────────

is_verified() {
    local addr=$1
    local sc
    sc=$(curl -sS "$VERIFIER_URL?module=contract&action=getsourcecode&address=$addr" \
         | jq -r '.result[0].SourceCode // ""')
    [ -n "$sc" ] && [ "$sc" != "null" ]
}

# ctor_args <addr> — echoes the constructor args as hex (no 0x), or empty.
ctor_args() {
    local addr=$1
    local creation runtime
    creation=$(curl -sS "$VERIFIER_URL?module=contract&action=getcontractcreation&contractaddresses=$addr" \
               | jq -r '.result[0].creationBytecode // ""')
    creation=${creation#0x}
    runtime=$(cast code "$addr" --rpc-url "$RPC_URL")
    runtime=${runtime#0x}
    if [ -z "$creation" ] || [ -z "$runtime" ]; then
        echo ""
        return
    fi
    python3 - "$creation" "$runtime" <<'PY'
import sys
creation, runtime = sys.argv[1], sys.argv[2]
idx = creation.rfind(runtime)
if idx < 0:
    sys.stderr.write("  warn: runtime bytecode not found in creation bytecode\n")
    sys.exit(0)
sys.stdout.write(creation[idx + len(runtime):])
PY
}

# try to match impl runtime against a known candidate's compiled bytecode.
auto_detect_impl() {
    local runtime
    runtime=$(cast code "$IMPL" --rpc-url "$RPC_URL")
    runtime=${runtime#0x}
    local cand compiled
    for cand in "${IMPL_CANDIDATES[@]}"; do
        # use fully-qualified path:name to disambiguate duplicate contract names
        compiled=$(forge inspect "$cand" deployedBytecode 2>/dev/null || true)
        compiled=${compiled#0x}
        if [ -n "$compiled" ] && [ "$compiled" = "$runtime" ]; then
            echo "$cand"
            return
        fi
    done
    echo ""
}

verify_one() {
    local label=$1 addr=$2 src=$3
    printf '=== %-6s %s\n' "$label" "$addr"
    printf '       source: %s\n' "$src"
    if is_verified "$addr"; then
        printf '       ✓ already verified, skip\n\n'
        return
    fi
    local args=""
    # BeaconProxy / UpgradeableBeacon always have ctor args; impl usually doesn't.
    args=$(ctor_args "$addr")
    local arg_flag=()
    [ -n "$args" ] && arg_flag=(--constructor-args "0x$args")
    forge verify-contract "$addr" "$src" \
        --chain-id "$CHAIN_ID" \
        --verifier custom \
        --verifier-url "$VERIFIER_URL" \
        --verifier-api-key placeholder \
        --compiler-version "$COMPILER_VERSION" \
        --num-of-optimizations "$OPTIMIZER_RUNS" \
        --via-ir \
        ${arg_flag[@]+"${arg_flag[@]}"} \
        2>&1 | grep -E "GUID|Response|Submitting|Error|error" | sed 's/^/       /' || true
    printf '\n'
}

# ── main ────────────────────────────────────────────────────────────────────

if [ -z "$IMPL_HINT" ]; then
    IMPL_HINT=$(auto_detect_impl)
    if [ -z "$IMPL_HINT" ]; then
        echo "error: could not auto-detect impl source — pass as 2nd arg" >&2
        echo "       candidates tried:" >&2
        printf '         %s\n' "${IMPL_CANDIDATES[@]}" >&2
        exit 1
    fi
    printf 'impl source (auto-detected): %s\n\n' "$IMPL_HINT"
fi

verify_one "impl"   "$IMPL"   "$IMPL_HINT"
verify_one "beacon" "$BEACON" "$BEACON_SRC"
verify_one "proxy"  "$PROXY"  "$PROXY_SRC"

echo "done."
