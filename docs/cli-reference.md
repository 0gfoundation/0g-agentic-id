# 0g-agentdna CLI Reference

> Matches `@0gfoundation/0g-agentdna` ≥ 0.2.1 · the CLI ships inside the SDK package — no separate install
> Every command, flag, and exit code below was verified against `sdk/typescript/src/cli/` source

## 1. Installation & Mental Model

```bash
npm install @0gfoundation/0g-agentdna
npx @0gfoundation/0g-agentdna --help
```

One entry point, **two shapes**:

| Shape | Invocation | Purpose |
|---|---|---|
| Interactive shell | bare `npx @0gfoundation/0g-agentdna` (optionally with an agent ref: `npx @0gfoundation/0g-agentdna 286`) | deploy, chat, rate — daily human use |
| Script subcommands | `npx @0gfoundation/0g-agentdna <command>` | diagnostics & automation — all support `--json` |

Key rule: **only `doctor` / `status` / `list` / `settings` / `providers` / `update` are reserved subcommands.** Any other positional is treated as an agent reference (decimal = agentId, `0x…` = sealId) and routes straight into that agent's session — command names and agent refs can never collide.

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
| `AGENTIC_API_KEY` | no | legacy compute-only inference key (deploy/reset); other providers use their matching key stored by `login` |
| `AGENTIC_VERIFIED_FEEDBACK_ADDR` | no | reputation-pair address override, for attestors whose `/config` doesn't advertise them yet |
| `AGENTIC_FEEDBACK_BATCHER_ADDR` | no | FeedbackBatcher address override, same situation |

Configure nothing → **read-only mode**: `list` (public tier) / `status` / `hello` work; every write is refused.

Persisted files under `~/.config/0g-agentdna/`:

| File | Contents | Mode |
|---|---|---|
| `config.json` | attestor URL | — |
| `credentials` | owner key + provider-scoped inference keys (JSON) | 0600 |
| `proofs.json` | the rating-ticket jar | 0600 |

Legacy config is migrated automatically from `~/.config/0g-agenticid/`; see the [migration guide](../sdk/typescript/MIGRATION.md).

## 4. Subcommands

### `doctor`

Checks every deploy prerequisite: attestor reachable, RPC, wallet, gas, trust-root ack, sandbox prepaid balance (≥ 0.1 OG). **Every failing item prints a one-line remedy.** All green = exit 0; otherwise exit 3, the error carrying the FIRST failing check's code. Diagnostics only — the ack/deposit remedies are transactions (they need gas) and must be executed via the deploy console or the SDK.

### `status <agent>`

One agent's full picture: phase, the three coordinates (agentId / sealId / agentSeal), url, failure reason. `<agent>` is a decimal agentId or a `0x…` sealId — the CLI converts between them. With a wallet configured, failure reasons withheld from the public listing (issue #64) are fetched automatically via the owner-signed listing.

### `list [--mine] [--phase <p>]`

Deployment listing. The public tier carries sealIds and — for minted rows — the owner and agentSeal addresses (both chain-public once minted); `--mine` adds owner-only fields (`WHERE owner = $1` — agent-owned children never appear in your own `--mine`; nesting is only visible in the public listing). An empty result is `[]` with exit 0. Human mode shows AGENTID/PHASE/FRAMEWORK/AGENTSEAL/OWNER/NAME (NAME last, sanitized and truncated — owner-controlled names cannot forge rows); an unminted row renders its sealId prefix (`0x` + 10 hex, paste-back-ready) in the AGENTID cell, and the OWNER cell annotates `⇄ #<agentId>` when a row is owned by another listed agent; sealId, url and whole addresses live in `--json`.

### `settings <agent> [k=v …]`

Reads/writes the agent's configuration document (which model it thinks with, and how hard).

- no assignment → show the document; with assignments → change it
- keys: `provider`, `model`, `thinking` (`low|high|max`), `others` (opaque JSON passthrough for the framework's own knobs — quote it: `others='{"a": 1}'`)
- assignments **merge** into the stored document; an empty value (`thinking=`) clears a field
- **both reading and writing are owner-signed** (the document is the owner's), i.e. both need `AGENTIC_PRIVATE_KEY`
- a write is a **compare-and-swap** against the version just read: if another client changed the document meanwhile, it is refused (exit 3, `SETTINGS_CONFLICT`) — **never silently overwritten**
- a merged document with no `model` is refused before signing (the one state the container hard-fails on); the model is checked against the selected provider's catalog first — an absence is a stderr warning only, never a refusal

### `providers`

Lists providers from the attestor registry (`--json` supported). Registry publication is an operations API / SDK admin action, authorized by the attestor Tapp owner; it is not a CLI command.

### `update`

Self-update: compares against the npm registry and `npm install -g`s the latest (a git-checkout / npm-link install is reported, not overwritten). `--json` only reports.

## 5. Interactive Shell

### Manager level (`0g-agentdna>` prompt)

| Command | Effect |
|---|---|
| `list` | public listing: sealId, FRAMEWORK, AGENTSEAL, OWNER (`⇄ #<agentId>` on agent-owned agents); `*` marks your wallet's agents |
| `use <agentId\|sealId>` | enter an agent's session (any phase) |
| `deploy` | wizard: pick framework → provider → model; async deploy |
| `hello <id>` | hit any agent's public `/hello`; with a wallet configured, banks a rating ticket |
| `call <id> [path] [json-body]` | call an agent's registered public service; bare `call` lists its services; responses bank tickets |
| `rate <id> [score] [/endpoint]` | spend a ticket to rate on-chain — **no interaction, no rating** |
| `start` / `stop` / `reset` / `retry <id>` | container lifecycle (owner-signed; on-chain identity unchanged). `reset` of an agent with no settings document (e.g. a fresh clone) first stores the default pin `provider=0g-compute model=0gm-1.0-35b-a3b` |
| `clone` / `transfer` / `grant` / `revoke` / `authorizer` | clone, transfer, clone-authorization management |
| `settings <id> [k=v …]` | same semantics as the subcommand |
| `balance` / `deposit [og]` / `withdraw [og]` | prepaid account: balance + burn rate / fund / refund withdrawal (time-locked; bare argument claims everything) |
| `ack` | acknowledge the TEE trust root (implicit in deploy/start/reset) |
| `login` | guided setup: attestor URL → owner key → provider → inference key (Enter keeps current; key input echoes `*`) |
| `whoami` / `help` / `quit` | — |

### Session level (`agent 286 ›` prompt)

Type to talk. **Esc / Ctrl-C interrupts the turn in flight** (server-side cancel on every bundled framework) and also cancels a `/start` or `/reset` wait.

Slash commands (verified against `interactive.ts`): `/hello` `/balance` `/topup [og]` `/stop` `/start` `/reset` `/settings [k=v …]` `/think [low|high|max]` `/clear` (wipes the conversation; chain-tracked memory untouched — unlike `/reset`) `/tasks` (on 0g-harness: every turn, background command and subagent, with who did it and who asked; elsewhere: this session's long tasks) `/result [id]` (on 0g-harness also a subagent's answer) `/cancel [id|all]` (stop tasks — bare form brakes everything this session knows to be in flight, newest first; with an id, just that one. The brake for turns that outlived their stream: Esc only cancels a turn the current connection started. /result <id> adopts an id into the session. On 0g-harness an id can be any task `/tasks` lists, and `all` stops everything running on the agent) `/inbox [all]` (0g-harness: what the agent said on its own — a background job finished, a reminder came due; bare: unread, `all`: the read ones too) `/schedules` (0g-harness: the reminders the agent set for itself) `/agentlog [n]` `/startuplog [n]` `/back` (alias `/unuse`) `/quit` (alias `/exit`).

On a 0g-harness agent, what the agent says on its own prints above the prompt as it arrives (during a command or a chat turn it waits for the next prompt), and what came while you were away prints when you enter the session. `/settings others=…` refuses the 0g-harness switches (`toolJobs`, `subagents`, `schedule`, `maxParallelToolCalls`) for an agent whose recorded framework is another one.

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
npx @0gfoundation/0g-agentdna                                    # interactive: deploy and chat
npx @0gfoundation/0g-agentdna 286                                # straight into agent 286's session
npx @0gfoundation/0g-agentdna doctor                             # preflight check
npx @0gfoundation/0g-agentdna status 33                          # one agent's full picture
npx @0gfoundation/0g-agentdna settings 286                       # show config
npx @0gfoundation/0g-agentdna settings 286 model=glm-5.3 thinking=high   # change model + effort
npx @0gfoundation/0g-agentdna list --mine --phase failed --json | jq -r '.data[].sealId'   # scripted
```
