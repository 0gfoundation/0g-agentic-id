# 0g-harness adapter — composition & capability tiers

[0g-harness](https://github.com/0gfoundation/0g-harness) is the only
*composed* framework in this repo. It is built on DSH (DeepSeek Harness,
`@deepseek-ai/dsh`): it has no fixed runtime, it is a tree of Cordis plugins
assembled per boot. What an agent can do is decided by that assembly, not by
the framework.

For the adapter contract (roles, Restore/EvolutionFor, FrameworkFacts) see
`../../FRAMEWORK_ADAPTER.md` and the package doc in `harness.go`. This file is
about the **composition**: which plugins are mounted, why, and how capability
grows.

## The framework name

The framework is `0g-harness`: the name in the on-chain `framework` binding, in
the attestor's `ATTESTOR_FRAMEWORKS` and in the deployment record. Its old name
is `dsh`. An agent whose binding names `dsh` boots on this adapter, and its
binding is rewritten to `0g-harness` by the agent's first commit (the
`framework` role is drift-watched like every role; the commit spends the
agentSeal's gas like every commit). A stopped agent is rewritten when it next
boots. The attestor renames `dsh` in its deployment records when it starts
(`attestor/crates/shared/src/schema.sql`).

## Where the composition lives

In 0g-harness (`src/composition.mjs`), in code. 0g-harness is the process this
adapter runs.

- **Fixed at build time.** The 0g-harness image installs one exact build of it
  at build time (`../../images/harness/Dockerfile`, `HARNESS_REF`), with its
  whole dependency tree locked. So the plugin set and every platform decision
  in it ride the image hash (measured, and listed on chain in
  `validFrameworkHashes`).
- **Out of the agent's reach.** The composition is **not** a `cordis.yml`, a
  profile, or any `$DSH_HOME` patch layer, so an agent editing its own home
  cannot change what mounts next boot. This is the structural form of doctrine
  refusal 5 (the agent does not rewrite its own runtime).
- **Version check.** The image build also checks that the installed
  0g-harness version is the one `whitelist.go` records in every 0g-harness
  agent's `framework` role. So the role always names the version that runs.
  The harness locks the DSH packages it runs on (its `npm-shrinkwrap.json`).

The **owner** can vary four options inside a fixed allowlist (see
*Owner-settable* below). They arrive as `SEAL_HARNESS_*` env from the owner's
signed settings document, applied at each spawn. So the image hash fixes the
composition *and the set of variations an owner may ask for*.

Nothing outside that allowlist is settable by anyone. Measured code decides:
- which plugins mount;
- the sandbox policy mode;
- the filesystem root;
- the spine invariant checks;
- the platform plane: the harness, seal-tools, seal-guard and subagent-guard.

## The process

`spawn.go` starts the harness and wires it up:
- It runs `node /usr/local/lib/node_modules/@0gfoundation/0g-harness/bin/0g-harness.mjs`
  as the agent user, on loopback port 8794.
- It passes the environment `environ()` builds. The contract is the harness's
  `docs/PROTOCOL.md`.

The harness then does three things:
- it keeps one agent with one conversation (`owner-chat`);
- it persists that conversation next to its turn records (`../../CONVERSATION.md`);
- it routes every turn's output to whoever opened the turn. A turn the owner
  opened answers that request. A turn the agent opened itself goes to the
  inbox: for example when a background job finishes or a reminder comes due.

`FrameworkRoutes()` advertises the surface on `/hello`, one kind per
capability: `chat`, `responses`, `inbox`, `events`, `tasks`, `schedules`. A
client enables a feature only on the kinds an agent declares. The other
frameworks declare none of the last four, and nothing about them changes.

## Current composition

**Mounted:**

| capability | plugins |
|---|---|
| chat + agent loop | spine (`dsh-agent-spine-demo`): session, tools, system-prompt, agent, agent-loop, skills, job registry |
| inference | `dsh-llm-pi-ai` (route rendered from the owner's settings by the adapter), `dsh-credentials-local` |
| shell | `dsh-subprocess-local` + `dsh-bash-local` + `dsh-sandbox-policy: danger-full-access` |
| filesystem | `dsh-fs-local` + `dsh-tool-fs` |
| skills | `dsh-skill-filesystem` (the `skills/` iData role — agent-installed, chain-tracked) |
| context headroom | `dsh-token-meter` + `dsh-compaction-basic` |
| loop hygiene | `dsh-tool-call-timeout-policy` |
| background jobs (`toolJobs` on) | `dsh-tool-jobs`: commands run in the background; a job finishing while the agent is idle opens a turn, whose reply goes to the inbox |
| subagents (`subagents` on) | `dsh-subagent` + `dsh-subagent-spawn-in-process` + `dsh-tool-subagent`. Each helper is one-shot and runs in the background as a job. Depth is 1. Its tools are `read` and `skill` only |
| reminders (`schedule` on) | `dsh-schedule`, plus the harness's minimal `sessionPersistence` service (the flush checkpoint dsh-schedule requires) |
| **platform control points** | `seal-tools`: `seal_sign`, `seal_sign_transaction`, `seal_sign_typed_data` and `seal_register_service` as native, session-logged tools. The three sign tools map the sign socket's three sign endpoints one-to-one |
| | `seal-guard`: steers shell calls away from the socket's `/sign/` endpoints; `/settings` and `/services` stay open |
| | `subagent-guard`: only the main agent writes files, runs commands or signs |

**Deliberately NOT mounted** (each a decision):

- **`session-persistence-*`**: its log format is pinned v0 with no
  compatibility promise, and no concrete backend ships. The harness persists
  the conversation itself, and restores it as a resume, without a
  `seedLength`. So pending inbox work and reminders survive a restart. It
  provides only the durability checkpoint dsh-schedule needs.
- **`settings-file`**: its hot-reload would layer `$DSH_HOME/settings.yaml`
  over the composition, letting an agent edit inject an arbitrary inference
  route. Instead, the pin reaches the harness as `SEAL_MODEL_*` env, rendered
  from the owner's settings document before Start (`settings.go`). No
  `settings.yaml` exists.
- **`tool-cordis`**: in-process tool definition, unaudited and gone on restart.
- **The `sandbox` stack**: privsep (the kernel uid split) is the isolation
  wall. DSH's own `sandbox-local` fails closed without bwrap/Landlock, which
  slim TEE containers lack.
- **`web`, `e2b`, persistent `terminal`, `goals`, `agent-presets`,
  continuable subagents**: capability surface deferred (see below).

**Owner-settable.** The chain is: the settings document's `others` section →
`SEAL_HARNESS_*` env. An owner who sets nothing gets exactly the shipped
composition. A push takes effect on the next spawn: the process restarts, the
container does not.

| knob | default | what it does |
|---|---|---|
| `toolJobs` | `false` | background commands (`run_in_background`) and the `job_*` tools |
| `subagents` | `false` | the `subagent` tool: read-only helpers the main agent runs in the background (turns the job tools on with it) |
| `schedule` | `false` | `schedule_create` / `schedule_list` / `schedule_delete`: reminders the agent sets for itself |
| `maxParallelToolCalls` | `1` | tool calls one turn may run at once |

A bad value here never fails a boot. `RenderSettings` runs before every spawn,
so an error would mean an agent that cannot start, not a rejected push. So an
unparseable or out-of-range value falls back to the shipped default and says
so in the log. The other knobs still apply (`settings.go`).

**`workspaceContext` is refused.**
- **What it would do:** mount the spine's workspace-context extra, which reads
  `~/.dsh/AGENTS.md` into every turn's system context.
- **Why that file is a problem:** it is agent-writable (privsep hands
  `$DSH_HOME` to the agent user, which has bash and `fs-local`), and it belongs
  to no role. So nothing restores it, nothing commits it, and no verifier can
  see it.
- **Why an owner knob can't open it:** opening an untracked channel into the
  system prompt is a platform-boundary change. The work that would make it an
  option is making `~/.dsh/AGENTS.md` a tracked role (deferred, see below).

The platform's own composition decisions are NOT owner-settable: the sandbox
policy mode, the spine invariant checks, the filesystem root, seal-tools,
seal-guard and subagent-guard. They are the part of the boundary the image hash
attests.

## Why shell is mounted (not banned)

privsep runs the framework subprocess as a low-privilege `agent` user. So the
kernel, not doctrine, walls it off from sealed's memory and secrets. Shell is
therefore a normal capability. Doctrine refusal 2 governs *authorship*
(externally-drafted command bytes), not shell access. See
`../../AGENT_DOCTRINE.md`.

## Capability tiers (planned)

Background jobs, subagents and reminders are owner switches on the one
composition. Larger capability changes take the shape of tiers:

- **A menu of tiers.** The platform audits a small menu, e.g. `minimal` /
  `coder`. Each tier is a composition the harness ships, and tiers differ only
  in which capability plugins mount: e.g. `coder` adds the e2b tool sandbox and
  a persistent shell. The platform plane is identical across tiers and never
  owner-selectable: the harness surface, seal-tools/guard, subagent-guard,
  doctrine injection and the inference route.
- **Picked at deploy, visible on chain.** The owner picks a tier at deploy,
  like framework + model. The tier id is recorded in the on-chain `framework`
  binding, so a verifier can see which capability tier an agent runs. The tier's
  content is still backed by the image hash.
- **Changed by reset only.** Changing tier means a reset (the same path as
  changing framework/model), never a runtime hot-swap: which plugins mount is
  part of the measured boundary, and a tier is a different plugin set. The four
  allowlisted options above are different: they are values passed into a
  composition that does not change, so they apply on a settings push + process
  restart.

Other deferred items:
- `~/.dsh/AGENTS.md` as a persona role;
- a `memory/` DirectoryManifest role;
- the e2b tool sandbox, as the "tool sandbox" side of the habitat model.
