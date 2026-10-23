# 0g-agenticid CLI Reference

> Matches `@0gfoundation/0g-agenticid-sdk` ≥ 0.1.7 · the CLI ships inside the SDK package — no separate install
> Every command, flag, and exit code below was verified against `sdk/typescript/src/cli/` source

## 1. Installation & Mental Model

```bash
npm install @0gfoundation/0g-agenticid-sdk
npx 0g-agenticid --help
```

One entry point, **two shapes**:

| Shape | Invocation | Purpose |
|---|---|---|
| Interactive shell | bare `npx 0g-agenticid` (optionally with an agent ref: `npx 0g-agenticid 286`) | deploy, chat, rate — daily human use |
| Script subcommands | `npx 0g-agenticid <command>` | diagnostics & automation — all support `--json` |

Key rule: **only `doctor` / `status` / `list` / `settings` / `update` are reserved subcommands.** Any other positional is treated as an agent reference (decimal = agentId, `0x…` = sealId) and routes straight into that agent's session — command names and agent refs can never collide.

Prerequisite: **Node.js ≥ 22** (recommended: `nvm install 22 && nvm use 22`).

## 2. Global Options

| Option | Effect |
|---|---|
| `--json` | Machine output: stdout carries exactly one `{ok, data \| error}` envelope; all progress goes to stderr |
| `--mine` | (list only) restrict to deployments owned by `AGENTIC_PRIVATE_KEY`; owner-signed, adds owner-only fields (failure reason, sandboxId) |
| `--phase <p>` | (list only) filter by phase: `deploying` `running` `stopped` `offline` `failed` |
| `--help` | help text |
| `--version` | package version (identical to the SDK's) |

The `--json` envelope contract:

- `error = {code, message, remedy?, details?}`; bigints serialize as decimal strings; absent values are `null`, never omitted
- doctor packs its per-check results under `(data|error.details).checks`, each `status: pass|fail|skip`
- an unknown flag throws immediately and exits 2

## 3. Environment Variables & Config Files

Environment variables **always override** the config files — CI and one-off runs never touch disk.

| Variable | Required | Notes |
|---|---|---|
| `AGENTIC_ATTESTOR_URL` | yes (for writes) | attestor base URL — **one URL pins the whole environment** (contracts, RPC, appIds all come from its `/config`). Production `https://agenticid.0g.ai`, testnet `https://agenticid-testnet.0g.ai` |
| `AGENTIC_PRIVATE_KEY` | no | owner key (`0x…` hex). **Env only — there is deliberately no `--key` flag.** Unlocks all write operations and owner-signed surfaces |
| `AGENTIC_RPC_URL` | no | overrides the RPC the attestor advertises |
| `AGENTIC_API_KEY` | no | inference key (deploy/reset); overrides the one stored by `login` |
| `AGENTIC_VERIFIED_FEEDBACK_ADDR` | no | reputation-pair address override, for attestors whose `/config` doesn't advertise them yet |
| `AGENTIC_FEEDBACK_BATCHER_ADDR` | no | FeedbackBatcher address override, same situation |

Configure nothing → **read-only mode**: `list` (public tier) / `status` / `hello` work; every write is refused.

Persisted files under `~/.config/0g-agenticid/`:

| File | Contents | Mode |
|---|---|---|
| `config.json` | attestor URL | — |
| `credentials` | owner key + inference key (JSON) | 0600 |
| `proofs.json` | the rating-ticket jar | 0600 |

## 4. Subcommands

### `doctor`

Checks every deploy prerequisite: attestor reachable, RPC, wallet, gas, trust-root ack, sandbox prepaid balance (≥ 0.1 OG). **Every failing item prints a one-line remedy.** All green = exit 0; otherwise exit 3, the error carrying the FIRST failing check's code. Diagnostics only — the ack/deposit remedies are transactions (they need gas) and must be executed via the deploy console or the SDK.

### `status <agent>`

One agent's full picture: phase, the three coordinates (agentId / sealId / agentSeal), url, failure reason. `<agent>` is a decimal agentId or a `0x…` sealId — the CLI converts between them. With a wallet configured, failure reasons withheld from the public listing (issue #64) are fetched automatically via the owner-signed listing.

### `list [--mine] [--phase <p>]`

Deployment listing. The public tier carries sealIds; `--mine` adds owner-only fields. An empty result is `[]` with exit 0.

### `settings <agent> [k=v …]`

Reads/writes the agent's configuration document (which model it thinks with, and how hard).

- no assignment → show the document; with assignments → change it
- keys: `provider`, `model`, `thinking` (`low|high|max`), `others` (opaque JSON passthrough for the framework's own knobs — quote it: `others='{"a": 1}'`)
- assignments **merge** into the stored document; an empty value (`thinking=`) clears a field
- **both reading and writing are owner-signed** (the document is the owner's), i.e. both need `AGENTIC_PRIVATE_KEY`
- a write is a **compare-and-swap** against the version just read: if another client changed the document meanwhile, it is refused (exit 3, `SETTINGS_CONFLICT`) — **never silently overwritten**
- a merged document with no `model` is refused before signing (the one state the container hard-fails on); the model is checked against the 0G router catalog first — an absence is a stderr warning only, never a refusal

### `update`

Self-update: compares against the npm registry and `npm install -g`s the latest (a git-checkout / npm-link install is reported, not overwritten). `--json` only reports.

## 5. Interactive Shell

### Manager level (`0g-agenticid>` prompt)

| Command | Effect |
|---|---|
| `list` | public listing; `*` marks your wallet's agents |
| `use <agentId\|sealId>` | enter an agent's session (any phase) |
| `deploy` | wizard: pick framework → model; async deploy |
| `hello <id>` | hit any agent's public `/hello`; with a wallet configured, banks a rating ticket |
| `call <id> [path] [json-body]` | call an agent's registered public service; bare `call` lists its services; responses bank tickets |
| `rate <id> [score] [/endpoint]` | spend a ticket to rate on-chain — **no interaction, no rating** |
| `start` / `stop` / `reset` / `retry <id>` | container lifecycle (owner-signed; on-chain identity unchanged) |
| `clone` / `transfer` / `grant` / `revoke` / `authorizer` | clone, transfer, clone-authorization management |
| `settings <id> [k=v …]` | same semantics as the subcommand |
| `balance` / `deposit [og]` / `withdraw [og]` | prepaid account: balance + burn rate / fund / refund withdrawal (time-locked; bare argument claims everything) |
| `ack` | acknowledge the TEE trust root (implicit in deploy/start/reset) |
| `login` | guided setup: attestor URL → owner key → inference key (Enter keeps current; key input echoes `*`) |
| `whoami` / `help` / `quit` | — |

### Session level (`agent 286 ›` prompt)

Type to talk. **Esc / Ctrl-C interrupts the turn in flight** (server-side cancel on every bundled framework) and also cancels a `/start` or `/reset` wait.

Slash commands (verified against `interactive.ts`): `/hello` `/balance` `/topup [og]` `/stop` `/start` `/reset` `/settings [k=v …]` `/think [low|high|max]` `/clear` (wipes the conversation; chain-tracked memory untouched — unlike `/reset`) `/tasks` `/result [id]` `/cancel [id]` (stop a task — default newest in flight; the brake that still works after a re-attach, when Esc no longer knows the turn) `/agentlog [n]` `/startuplog [n]` `/back` (alias `/unuse`) `/quit` (alias `/exit`).

The framework used by `/reset` and the chat model selector is **picked by you** from the attestor's list — never guessed.

### The rating-ticket jar

`proofs.json` holds the serve-proofs banked by `hello` / `call`; `rate` spends them. The physics:

- valid for roughly 1 hour (deadline set by the sealed server, enforced on-chain)
- single-use; at most 5 per (agent, wallet) pair
- **redeemable only by the wallet named in the proof's `submitter`** — a leaked jar is useless to anyone else
- owners cannot rate their own agents

## 6. Exit Codes

| exit | Meaning | Action |
|---|---|---|
| 0 | success | — |
| 1 | unknown error (incl. NOT_IMPLEMENTED) | read the message |
| 2 | usage error (incl. unknown command, bad flag, bad agent ref, agent not found) | branch on `error.code` to tell them apart |
| 3 | **fixable precondition** (missing attestor URL, unreachable, wallet required, `SETTINGS_CONFLICT`, …) | read `error.remedy`, fix, retry |
| 4 | timeout | check again later |
| 5 | auth | stop |

## 7. Examples

```bash
npx 0g-agenticid                                    # interactive: deploy and chat
npx 0g-agenticid 286                                # straight into agent 286's session
npx 0g-agenticid doctor                             # preflight check
npx 0g-agenticid status 33                          # one agent's full picture
npx 0g-agenticid settings 286                       # show config
npx 0g-agenticid settings 286 model=glm-5.3 thinking=high   # change model + effort
npx 0g-agenticid list --mine --phase failed --json | jq -r '.data[].sealId'   # scripted
```
