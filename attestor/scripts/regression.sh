#!/usr/bin/env bash
# One-command live regression. Deploys a fresh source agent, captures its
# ids, and drives every check in dependency order, printing a final table.
# No id juggling — this is what you run to regress the whole system.
#
# Env:
#   ATTESTOR_URL     attestor base URL           (default http://localhost:8080)
#   OWNER_PRIV       funded owner key (required) — gas + sandbox balance; the
#                    self-contained legs also fund ephemeral wallets from it
#   API_KEY          inference key injected into containers (default a dummy;
#                    fine — the checks don't exercise the model)
#   REPUTATION_ADDR  client-less reputation registry bound to this AgenticID;
#                    if unset, the feedback/lifecycle leg is skipped
#   RUN_UNIT=1       also run the free T0 suites (cargo/go) first
#   SKIP_TRANSFER=1  skip the (slow, ~10 min) self-contained transfer-live leg
#
# Free negative checks always run. Every live leg spends testnet gas +
# sandbox balance. Exits non-zero if any leg fails.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SDK="$ROOT/sdk/typescript"
API="${ATTESTOR_URL:-http://localhost:8080}"
: "${OWNER_PRIV:?set OWNER_PRIV (funded owner key)}"
export API ATTESTOR_URL="$API" OWNER_PRIV
export API_KEY="${API_KEY:-sk-regression-dummy}"

# /deployments has two tiers: the public (no-param) list deliberately omits
# sandbox_id / stages, so read the owner-scoped tier (EIP-191 owner signature)
# to get the operational fields the live legs need.
OWNER_ADDR=$(cast wallet address "$OWNER_PRIV")
owner_deployments() {
  local ts msg sig
  ts=$(date +%s)
  msg="0GDeployments:${OWNER_ADDR}:${ts}"
  sig=$(cast wallet sign --private-key "$OWNER_PRIV" "$msg")
  curl -fsS -H "X-Auth-Message: $msg" -H "X-Auth-Signature: $sig" "$API/deployments?owner=$OWNER_ADDR"
}

# Agent base URL for a seal_id. Prefer the row's own agent_card.url origin —
# it carries the CORRECT scheme (production art.0g.ai is 443-only; a
# hand-built http:// URL times out there, #128) and is provision-updated, so
# it survives resets. Fall back to constructing from the proxy config for
# rows without a card url (e.g. -dev environments).
agent_url_of() { # agent_url_of <seal_id>
  local row url
  row=$(owner_deployments | jq -c --arg s "$1" '.[] | select(.seal_id==$s)')
  url=$(echo "$row" | jq -r '.agent_card.url // ""' | sed -E 's#^(https?://[^/]+).*#\1#')
  if [ -n "$url" ]; then echo "$url"; else
    echo "http://${PORT}-$(echo "$row" | jq -r .sandbox_id).${PROXY}"
  fi
}

declare -a NAMES RESULTS
step() { # step "name" cmd...
  local name="$1"; shift
  printf '\n\033[1m══ %s ══\033[0m\n' "$name"
  if "$@"; then NAMES+=("$name"); RESULTS+=("PASS"); else NAMES+=("$name"); RESULTS+=("FAIL"); fi
}
skip() { NAMES+=("$1"); RESULTS+=("SKIP"); printf '\n── %s: SKIPPED (%s) ──\n' "$1" "$2"; }

# ── SDK build (needed by the .cjs legs) ───────────────────────────────
if [ ! -f "$SDK/dist/index.js" ]; then
  echo "building SDK…"; (cd "$SDK" && npm ci --silent && npm run build --silent) || { echo "SDK build failed"; exit 1; }
fi

# ── T0 unit (optional, free) ──────────────────────────────────────────
if [ "${RUN_UNIT:-0}" = "1" ]; then
  step "T0 attestor cargo test" bash -c "cd '$ROOT/attestor' && cargo test --workspace --quiet"
  step "T0 sealed go test"      bash -c "cd '$ROOT/sealed' && go test ./... >/dev/null"
fi

# ── negative path (free) ──────────────────────────────────────────────
step "smoke (negative deploy → 400)" bash -c "cd '$SDK' && node scripts/smoke.cjs"

# ── CLI smoke, public tier (free): read paths + the WALLET_REQUIRED gates ──
# OWNER_PRIV= (empty): this leg must run KEYLESS, but the script honors
# OWNER_PRIV as a fallback alias and regression exports it globally (#128).
step "cli-smoke (public tier + gates)" bash -c "cd '$SDK' && OWNER_PRIV= AGENTIC_ATTESTOR_URL='$API' node scripts/cli-smoke.cjs"

# ── deploy a fresh source, capture its coordinates ────────────────────
DEPLOY_LOG="$(mktemp)"
printf '\n\033[1m══ deploy source ══\033[0m\n'
if bash "$HERE/e2e.sh" | tee "$DEPLOY_LOG"; then
  SEAL_ID=$(grep -oE 'seal_id *= *0x[0-9a-fA-F]+' "$DEPLOY_LOG" | grep -oE '0x[0-9a-fA-F]+' | head -1)
else
  echo "deploy failed — aborting live legs"; NAMES+=("deploy source"); RESULTS+=("FAIL"); SEAL_ID=""
fi

if [ -n "${SEAL_ID:-}" ]; then
  NAMES+=("deploy source"); RESULTS+=("PASS")
  ROW=$(owner_deployments | jq -c --arg s "$SEAL_ID" '.[] | select(.seal_id==$s)')
  AGENT_HEX=$(echo "$ROW" | jq -r .agent_id)
  AGENT_ID=$((AGENT_HEX))
  SANDBOX=$(echo "$ROW" | jq -r .sandbox_id)
  SEAL_ADDR=$(echo "$ROW" | jq -r .agent_seal_addr)
  PROXY=$(curl -fsS "$API/config" | jq -r .sandbox_proxy_addr)
  PORT=$(curl -fsS "$API/config" | jq -r .agent_serve_port)
  AGENT_URL=$(agent_url_of "$SEAL_ID")
  echo "source: agent_id=$AGENT_ID seal=$SEAL_ID sandbox=$SANDBOX url=$AGENT_URL"

  # CLI owner tier against the fresh deployment: doctor all six green,
  # list --mine non-empty, status pinned to this agent, and the owner-tier
  # failure-reason folding when the env has a failed row (#116). Read-only.
  step "cli-smoke (owner tier)" bash -c "cd '$SDK' && AGENTIC_ATTESTOR_URL='$API' AGENTIC_PRIVATE_KEY='$OWNER_PRIV' AGENT_ID='$AGENT_ID' node scripts/cli-smoke.cjs"
  # identity / decrypt / serve-proof
  step "verify-agent (identity+decrypt+proof)" env AGENT_ID="$AGENT_ID" bash "$HERE/verify-agent.sh"
  # sayHi real verify + reset determinism
  step "agent-e2e (sayHi+reset)" bash -c "cd '$SDK' && AGENT_URL='$AGENT_URL' SEAL_ID='$SEAL_ID' AGENT_ID='$AGENT_ID' node scripts/agent-e2e.cjs"
  # auto-update: top up agentSeal, watch on-chain commit
  step "evolution-probe (auto-update)" bash -c "cd '$SDK' && AGENT_ID='$AGENT_ID' SEAL_ADDR='$SEAL_ADDR' node scripts/evolution-probe.cjs"
  # clone + feedback + transfer + owner gate (consumes the source via transfer, so LAST among source-bound legs).
  # Re-derive the URL first: agent-e2e's reset above recreated the container
  # with a NEW sandbox_id, so the deploy-time AGENT_URL is now stale.
  AGENT_URL=$(agent_url_of "$SEAL_ID")
  echo "source url refreshed post-reset: $AGENT_URL"
  if [ -n "${REPUTATION_ADDR:-}" ]; then
    step "lifecycle-e2e (clone+feedback+transfer+gate)" bash -c "cd '$SDK' && AGENT_URL='$AGENT_URL' SEAL_ID='$SEAL_ID' AGENT_ID='$AGENT_ID' REPUTATION_ADDR='$REPUTATION_ADDR' node scripts/lifecycle-e2e.cjs"
  else
    skip "lifecycle-e2e (clone+feedback+transfer+gate)" "REPUTATION_ADDR unset"
  fi
fi

# ── self-contained transfer live (deploys its own source; slow) ───────
if [ "${SKIP_TRANSFER:-0}" = "1" ]; then
  skip "transfer-live (new owner recreates)" "SKIP_TRANSFER=1"
else
  step "transfer-live (new owner recreates)" bash -c "cd '$SDK' && node scripts/transfer-live.cjs"
fi

# ── summary ───────────────────────────────────────────────────────────
printf '\n\033[1m════ regression summary ════\033[0m\n'
fail=0
for i in "${!NAMES[@]}"; do
  r="${RESULTS[$i]}"
  case "$r" in PASS) c=32;; FAIL) c=31; fail=1;; *) c=33;; esac
  printf "  \033[%sm%-6s\033[0m %s\n" "$c" "$r" "${NAMES[$i]}"
done
[ "$fail" = 0 ] && { printf '\n\033[32m✅ regression: all green\033[0m\n'; exit 0; } \
                 || { printf '\n\033[31m❌ regression: failures above\033[0m\n'; exit 1; }
