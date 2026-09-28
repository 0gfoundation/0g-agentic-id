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
`$DSH_HOME` patch layer. Consequence: the plugin set and every platform
decision in it ride the sealed image hash (measured, on-chain in
`validFrameworkHashes`), and an agent editing its own home cannot change what
mounts next boot. This is the structural form of doctrine refusal 5 (the agent
does not rewrite its own runtime).

The **owner** can vary two spine options inside a fixed allowlist (see
*Owner-settable* below): they arrive as `SEAL_DSH_*` env from the owner's
signed settings document, applied at each spawn. So what the image hash fixes
is the composition *and the set of variations an owner may ask for* — not a
single immutable tree. Nothing outside that allowlist is settable by anyone:
which plugins mount, the sandbox policy mode, the filesystem root, the spine
invariant checks and the platform plane (bridge, seal-tools, seal-guard) are
decided here, in measured code.

## Current tier: `minimal` (the only one today)

A single fixed composition — enough to be a useful agent, nothing more.

**Mounted:**

| capability | plugins |
|---|---|
| chat + agent loop | spine (`dsh-agent-spine-demo`): session, tools, system-prompt, agent, agent-loop, skills |
| inference | `dsh-llm-pi-ai` (route rendered from the owner's settings by the adapter), `dsh-credentials-local` |
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
- `settings-file` — its hot-reload would layer `$DSH_HOME/settings.yaml` over
  the composition, letting an agent edit inject an arbitrary inference route.
  The pin reaches the bridge as `SEAL_MODEL_*` env instead, rendered from the
  owner's settings document before Start (`settings.go`). There is no
  `settings.yaml` any more: it used to be this adapter's own chain-tracked
  store for the pin, and the settings document replaced it.
- `tool-cordis` — in-process tool definition, unaudited and gone on restart.
- `sandbox` stack — privsep (kernel uid split) is the isolation wall; DSH's
  own `sandbox-local` fails closed without bwrap/Landlock, which slim TEE
  containers lack.
- `web`, `e2b`, `subagent`, `terminal` persistent, `goals`, `agent-presets` —
  capability surface deferred (see below).

**Owner-settable** (the settings document's `framework` section → `SEAL_DSH_*`
env → the spine's options; defaults are what the bridge used to hardcode, so an
owner who sets nothing gets exactly the shipped composition). A push takes
effect on the next spawn — the process restarts, the container does not:

| knob | default | what it does |
|---|---|---|
| `toolJobs` | `false` | spine background-job tools |
| `maxParallelToolCalls` | `1` | tool calls one turn may run at once |

A bad value here never fails a boot. `RenderSettings` runs before every spawn,
so an error would be an agent that cannot start rather than a rejected push;
an unparseable or out-of-range value falls back to the shipped default, says so
in the log, and the other knobs still apply (`settings.go`).

`workspaceContext` was in this table and is **refused**. It mounts the spine's
workspace-context extra, which reads `~/.dsh/AGENTS.md` into every turn's
system context — and that file is agent-writable (privsep hands the home to the
agent user, which has bash and `fs-local`) and belongs to no role, so nothing
restores it, commits it, or lets a verifier see it. An owner knob must not be
able to open an untracked channel into the system prompt; that is a
platform-boundary change. Making `~/.dsh/AGENTS.md` a tracked role is the work
that would let it come back as an option (deferred, see below).

The platform's own composition decisions are NOT owner-settable: the sandbox
policy mode, the spine invariant checks, the filesystem root, seal-tools and
seal-guard. They are the part of the boundary the image hash attests.

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
  hot-swap: which plugins mount is part of the measured boundary, and a tier is
  a different plugin set. This is a different thing from the two allowlisted
  spine options above, which are values passed into a composition that does not
  change, and therefore apply on a settings push + process restart.

Other deferred items tracked on the DSH PR: `~/.dsh/AGENTS.md` as a persona
role, a `memory/` DirectoryManifest role, e2b tool sandbox as the "tool
sandbox" side of the habitat model.
