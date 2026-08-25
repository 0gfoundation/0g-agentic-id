# DSH adapter — composition & capability tiers

DSH (DeepSeek Harness, `@deepseek-ai/dsh`) is the only *composed* framework
in this repo: it has no fixed runtime, it is a tree of Cordis plugins assembled
per boot. This adapter owns that assembly. What an agent can do is decided
here, not by the framework.

For the adapter contract (roles, Restore/EvolutionFor, FrameworkFacts) see
`../../FRAMEWORK_ADAPTER.md` and the package doc in `dsh.go`. This file is
about the **composition**: which plugins are mounted, why, and how capability
tiers are meant to grow.

## Where the composition lives

In `bridge/bridge.mjs`, in code, `go:embed`'d into the sealed binary and
materialized at Start. It is **not** a `cordis.yml`, a profile, or any
`$DSH_HOME` patch layer. Consequence: the composition rides the sealed image
hash (measured, on-chain in `validFrameworkHashes`), and an agent editing its
own home cannot change what mounts next boot. This is the structural form of
doctrine refusal 5 (the agent does not rewrite its own runtime).

## Current tier: `minimal` (the only one today)

A single fixed composition — enough to be a useful agent, nothing more.

**Mounted:**

| capability | plugins |
|---|---|
| chat + agent loop | spine (`dsh-agent-spine-demo`): session, tools, system-prompt, agent, agent-loop, skills |
| inference | `dsh-llm-pi-ai` (0g-compute route resolved by the adapter), `dsh-credentials-local` |
| shell | `dsh-subprocess-local` + `dsh-bash-local` + `dsh-sandbox-policy: danger-full-access` |
| filesystem | `dsh-fs-local` + `dsh-tool-fs` |
| skills | `dsh-skill-filesystem` (the `skills/` iData role — agent-installed, chain-tracked) |
| context headroom | `dsh-token-meter` + `dsh-compaction-basic` |
| loop hygiene | `dsh-tool-call-timeout-policy` |
| **platform control points** | `seal-tools.mjs` (seal_sign / seal_register_service as native, session-logged tools), `seal-guard.mjs` (denies shell calls that reach the sign socket) |

**Deliberately NOT mounted** (each a decision):

- `session-persistence-*` — the append-only session log would phantom-drift
  every watcher tick and its format is pinned v0 with no compat; one Agent
  object in process memory instead.
- `settings-file` — its hot-reload would layer settings.yaml over the
  composition, letting an agent edit inject an arbitrary inference route. The
  tracked `settings.yaml` role is read by the adapter and passed as env; DSH
  never reads the file.
- `tool-cordis` — in-process tool definition, unaudited and gone on restart.
- `sandbox` stack — privsep (kernel uid split) is the isolation wall; DSH's
  own `sandbox-local` fails closed without bwrap/Landlock, which slim TEE
  containers lack.
- `web`, `e2b`, `subagent`, `terminal` persistent, `jobs`, `goals`,
  `workspaceContext`, `agent-presets` — capability surface deferred (see below).

## Why shell is mounted (not banned)

privsep runs the framework subprocess as a low-privilege `agent` user, so the
kernel — not doctrine — walls it off from sealed's memory and secrets. Shell is
therefore a normal capability, and doctrine refusal 2 governs *authorship*
(externally-drafted command bytes), not shell access. See `../../AGENT_DOCTRINE.md`.

## Capability tiers (planned — phase 2)

Today there is one tier (`minimal`) and no way for an owner to pick another.
The intended shape:

- A small **platform-audited menu** of tiers — e.g. `minimal` / `standard` /
  `coder` — each a composition this adapter ships, differing only in which
  capability plugins mount (e.g. `coder` adds e2b tool sandbox, subagents,
  persistent shell). The platform plane (bridge, seal-tools/guard, doctrine
  injection, inference route) is identical across tiers and never
  owner-selectable.
- Owner picks a tier at deploy (like framework + model today); the tier id is
  recorded in the on-chain `framework` binding, so a verifier can see which
  capability tier an agent runs — content still backed by the image hash.
- Tier change = reset (same path as changing framework/model), never a runtime
  hot-swap: the composition is part of the measured boundary.

Other deferred items tracked on the DSH PR: `~/.dsh/AGENTS.md` as a persona
role, a `memory/` DirectoryManifest role, e2b tool sandbox as the "tool
sandbox" side of the habitat model.
