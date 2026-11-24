#!/usr/bin/env bash
# Clone the PM Expert template (0G testnet agent 637), configure it, start it
# and give its wallet gas, in one go:
#
#   curl -fsSL https://raw.githubusercontent.com/0gfoundation/0g-agentic-id/dev/experts/pm-expert/clone.sh | bash
#
# Before: `npm install -g @0gfoundation/0g-agentdna@next` (0.5.2 or later),
# `0g-agentdna login` on the testnet attestor, `0g-agentdna doctor` green, and
# a clone grant for your wallet from the template's owner (`grant 637 <wallet>`).
# GAS=<og> sets the agent wallet top-up (default 3): `... | GAS=5 bash`.
#
# Every one-shot call reads /dev/null: under `curl | bash` the script itself is
# this shell's stdin, and a command that reads stdin would swallow the rest.
set -uo pipefail

SRC=637
GAS=${GAS:-3}

command -v 0g-agentdna >/dev/null 2>&1 || {
  echo "0g-agentdna not found: npm install -g @0gfoundation/0g-agentdna@next" >&2
  exit 1
}
# The npm `latest` tag is the mainnet CLI (0.4.x), which cannot do this.
VER=$(0g-agentdna --version </dev/null 2>/dev/null)
case "$VER" in
  0.[0-4].*|'')
    echo "0g-agentdna ${VER:-?} is too old for testnet: npm install -g @0gfoundation/0g-agentdna@next" >&2
    exit 1 ;;
esac

# 1. Clone. The shell prints "cloned: new agent <id> → <owner>".
OUT=$(printf 'clone %s\nquit\n' "$SRC" | 0g-agentdna 2>&1)
echo "$OUT"
ID=$(echo "$OUT" | grep -oE 'cloned: new agent [0-9]+' | grep -oE '[0-9]+$')
if [ -z "$ID" ]; then
  echo "Clone failed (see above). Without a grant, ask the template's owner for one." >&2
  exit 1
fi

# 2. Settings do not travel with a clone: the template's recommended ones.
0g-agentdna settings "$ID" provider=0g-compute model=glm-5.3 others='{
  "subagents": true,
  "subagentModels": [{"provider": "0g-compute", "model": "glm-5.3-flash"}],
  "mcpServers": [{"serverName": "browser", "transport": "stdio", "command": "sealed-browser-mcp"}],
  "memoryExtract": false,
  "webTools": true
}' </dev/null || exit 1

# 3. A clone lands offline: reset brings it up. The empty line answers the
#    model-key question with the key `login` saved.
printf 'reset %s\n\nquit\n' "$ID" | 0g-agentdna 2>&1

# 4. The agent pays gas for its own on-chain writes; deploy and clone fund none.
printf 'use %s\n/topup %s\n/quit\n' "$ID" "$GAS" | 0g-agentdna 2>&1

0g-agentdna status "$ID" </dev/null
echo "Done: new agent ${ID}. Run: 0g-agentdna ${ID}"
