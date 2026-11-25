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

- **Fixed at build time, run by hash.** One exact build of it (`HARNESS_REF`
  in `../../images/harness/Dockerfile`), with its whole dependency tree
  locked, is built into a package on the image's base and node: a
  deterministic tar of the installed tree, named by its sha256. The image
  carries none. Packages are published on the `artifacts` release and listed
  on the trust registry's harness list; sealed downloads the one the version
  rule picks — the owner's pick while listed, else the one running, else the
  newest listed (`../../LAYERS.md` §5) — and unpacks it as
  `/opt/0g-harness/<sha256>/`, owned by root and read-only to the agent. So
  the plugin set and every platform decision in it ride the package hash,
  which serve-proofs carry (`harnessHash`), and a new harness version needs
  no new image.
- **Out of the agent's reach.** The composition is **not** a `cordis.yml`, a
  profile, or any `$DSH_HOME` patch layer, so an agent editing its own home
  cannot change what mounts next boot. This is the structural form of doctrine
  refusal 5 (the agent does not rewrite its own runtime).
- **Version check.** The package build also checks that the installed
  0g-harness version is the one `whitelist.go` records in every 0g-harness
  agent's `framework` role. So the role always names the version that runs.
  The harness locks the DSH packages it runs on (its `npm-shrinkwrap.json`).

The **owner** can vary four options inside a fixed allowlist (see
*Owner-settable* below). They arrive as `SEAL_HARNESS_*` env from the owner's
signed settings document, applied at each spawn. So the package hash and the
sealed hash, both on the trust registry's lists, fix the composition *and the
set of variations an owner may ask for*.

Nothing outside that allowlist is settable by anyone. Measured code decides:
- which plugins mount;
- the sandbox policy mode;
- the filesystem root;
- the spine invariant checks;
- the platform plane: the harness, seal-tools and subagent-guard.

## The process

`spawn.go` starts the harness and wires it up:
- It runs `node /opt/0g-harness/<sha256>/bin/0g-harness.mjs` as the agent
  user, on loopback port 8794. With no package chosen it starts nothing and
  fails.
- It passes the environment `environ()` builds. The contract is the harness's
  `docs/PROTOCOL.md`. It includes `SEAL_OWNER`, the owner read from chain at
  boot (lowercased), against which the harness checks each memory's
  `trusted_by`.
- The harness calls the model through sealed's inference route
  (`internal/inferproxy`), a loopback address, for every provider sealed
  knows the endpoint of: the registry's managed providers, and `openai` and
  `anthropic` at their official endpoints, fixed in sealed. The route names
  the owner's model, appends the agent doc to the system prompt and sets the
  key; the harness holds a placeholder (`../../CONFIG_SURFACE.md` §3, §7).
  With `webTools` on and the owner's search service payable, the route also
  serves `POST /v1/web/search` for `web_search`: it takes only a `{"query"}`
  body and sends it to that service with no agent doc (`inferproxy`
  `websearch.go`), answering in the 0G router's result shape; the harness
  gets its address as `SEAL_HARNESS_WEB_SEARCH_URL`.
- The owner's further subagent models (`subagentModels`) are routes of the
  same proxy (`modelroutes.go`): a model on the main model's own endpoint and
  key is one more model the main route takes; any other is a named route
  under `/p/<id>` with its own upstream, key and models. Each route pins its
  models and carries the agent doc; a named route refuses any other model
  name. The harness gets them as `SEAL_HARNESS_MODEL_ROUTES` (no keys).
  The log names the first request each route forwards for a further model,
  `inference route <id>: first request for model <model>` (`main` for the
  main route).
- One rule decides how the search service and each further model are paid:
  the main model's provider with no credential named uses the model key; a
  named owner credential goes through the credential proxy as its
  placeholder, which the proxy fills only on the hosts and in the positions
  the owner allowed; otherwise the search or model is not offered, and the
  log says why. A model key entry (`model.<provider>`) cannot be named: it
  has no placeholder, so the search or model naming it is not offered. A
  named credential is checked when a request runs: the credential proxy
  refuses one the owner does not hold, and `web_search` reports that
  refusal's code and message, for the 0G router too.
- The harness checks its own token on `/v1/*` (`SEAL_BRIDGE_TOKEN`). The
  owner gets a different one from `/_seal/auth`, and sealed's proxy swaps it
  for the harness's on the way in, so nothing the harness runs sees the
  owner's token.

The harness then does three things:
- it keeps one agent with one conversation (`owner-chat`);
- it persists that conversation next to its turn records (`../../CONVERSATION.md`);
- it routes every turn's output to whoever opened the turn. A turn the owner
  opened answers that request. A turn the agent opened itself goes to the
  inbox: for example when a background job finishes or a reminder comes due.

`FrameworkRoutes()` advertises the surface on `/hello`, one kind per
capability: `chat`, `responses`, `inbox`, `events`, `activities`, `tasks`, `task-feed`, `schedules`, `files`, `memory`, `steer`, `sessions`. A
client enables a feature only on the kinds an agent declares. The other
frameworks declare none of the last ten, and nothing about them changes.
`activities` is the list of what runs or ran (turns, background commands,
subagents).
`tasks` are zgh-style tasks: a piece of work the owner hands the agent, run
in a session and workspace of its own (`~/tasks/<id>` by default), at most
four at once, and ended by an outcome the agent records (`raise_question`,
`request_action`, `report_complete`); its state is queued, working, idle,
needs-input, done, failed or archived. `task-feed` is the feed of their
changes; its kind also tells a client that `/v1/tasks` names these tasks
(an earlier runtime declared kind `tasks` for the activity list's old name).
`steer` is the owner's word for the turn already running: the harness reads it
before that turn's next model call, and queues it as an ordinary turn when no
owner turn is running.
`sessions` are the owner's other conversations (zgh-style): fresh, forked from
another session's log, or resumed; each prompt is the session's next turn or
a steer into its running one, and each has its own event stream. Every
session is the same agent with the same owner (persona, skills, memory, home
and credentials are shared); `owner-chat` is the default one behind `chat`
and `responses` (CONVERSATION.md invariant 2).
Each route lists its exact endpoints, those of the harness's protocol v1
(`routes_test.go`), and sealed's proxy forwards nothing else: an unlisted
path gets 404, an unlisted method 405. `/hello` is public, so each route's
description is one plain sentence on what the route is for; the requests and
their fields are in the harness's `docs/PROTOCOL.md`.

The harness can ask sealed to restart it (`POST /harness/restart` on the sign
socket): sealed stops the process and starts it again from the package it is
set to run (`../../LAYERS.md` §5.3). A boot keeps the persona
(`APPEND_SYSTEM.md`), the `skills/`, `memory/` and `memory-public/` the agent changed after
its last commit, as long as the chain still holds what this container last
committed (`../../LAYERS.md` §3).

## Current composition

**Mounted:**

| capability | plugins |
|---|---|
| chat + agent loop | explicit DSH 0.2 core in `src/plugins/core.mjs`: session, tools, system-prompt, agent, agent-loop, skills, job registry |
| inference | `dsh-llm-pi-ai` (route rendered from the owner's settings by the adapter), `dsh-credentials-local` |
| shell | `dsh-subprocess-local` + `dsh-bash-local` + `dsh-sandbox-policy: danger-full-access` |
| filesystem | `dsh-fs-local` + `dsh-tool-fs` |
| owner images and files | `dsh-attachment-local` (the owner's images, normalized, below `~/.dsh-attachments` in the agent's home, untracked; it also enables `read_image`). Files the owner uploads (`POST /v1/files`) land in the file inbox `~/inbox` (not the message inbox `/v1/inbox`), untracked; the image ships `pdftotext` for PDFs among them. Files the agent hands over go in `~/outbox`, untracked; the owner lists, downloads and deletes them (`GET /v1/files`, `GET /v1/files/{outbox|inbox}/{name}`, at most 50 MiB; `DELETE /v1/files/{outbox|inbox}/{name}`), and a turn that leaves new or changed files there says so (`harness.outbox_files`). A manual CLI download keeps the remote file. The CLI acknowledges the SHA-256 of its saved copy through `POST /v1/files/outbox/{name}/ack`. A supporting runtime removes only the matching revision. An older runtime keeps the file. Neither folder keeps files: the harness removes those older than 30 days from both, and the oldest in `~/inbox` while it holds more than 1 GiB (`SEAL_HARNESS_FILES_MAX_AGE_DAYS`, `SEAL_HARNESS_INBOX_MAX_BYTES`; sealed sets neither, so these defaults hold). The agent's notes on `~/inbox` and `~/outbox` (`platformtext.go`) tell it so, and that what must last belongs in memory or a skill |
| skills | `dsh-skill-filesystem` (the `skills/` iData role — agent-installed, chain-tracked) |
| long-term memory | the harness's own system-prompt section (`src/memory.mjs`): the guidance and, up to `memoryInlineBytes` of bodies, every memory whole, above it the two `MEMORY.md` indexes, read at every model step; the memory files are two iData roles (`memory.go`), `memory/` (private: the owner's sessions and tasks only) and `memory-public/` (public: written only on the owner's explicit request) — one `<name>.md` per memory directly in `$DSH_HOME/memory/` or `$DSH_HOME/memory-public/`, chain-tracked; each memory's `trusted_by` names the owner who confirmed it, and one not confirmed by the current owner (`SEAL_OWNER`) is reference only; the committed copy carries placeholders for credential values and `[redacted:<kind>]` for secrets of a known format (`../../../CREDENTIALS.md`, What is outside); consolidated now and then while the agent is idle (`src/memory-tidy.mjs`, switch `memoryTidy`), or now on `POST /v1/memory/tidy` (kind `memory`) |
| context headroom | `dsh-token-meter` + `dsh-compaction-basic` |
| loop hygiene | `dsh-tool-call-timeout-policy` |
| background jobs (`toolJobs` on) | `dsh-tool-jobs`: commands run in the background; a job finishing while the agent is idle opens a turn, whose reply goes to the inbox |
| subagents (`subagents` on) | `dsh-subagent` + `dsh-subagent-spawn-in-process` + `dsh-tool-subagent`. Each helper is one-shot and runs in the background as a job. Depth is 1. Its tools are `read` and `skill` only |
| persistence | DSH single-writer `dsh-session-persistence-jsonl`; legacy 0.1.1 conversations migrate through the released session-format catalog |
| reminders (`schedule` on) | `dsh-schedule` and `dsh-tool-schedule`, with native session persistence and a separate JSON schedule store |
| **platform control points** | DSH native `dsh-mcp-client` through private stdio-to-Unix bridges. sealed lists tools on its sockets (POST /mcp: signing, services, settings, the sandbox's resources and credentials on the sign socket, reveal on its own socket) and runs each call through that socket's endpoint; checks, refusals and records remain in sealed |
| | `subagent-guard`: only the main agent writes files, runs commands or signs |

**Deliberately NOT mounted** (each a decision):

- **`settings-file`**: its hot-reload would layer `$DSH_HOME/settings.yaml`
  over the composition, letting an agent edit inject an arbitrary inference
  route. Instead, the pin reaches the harness as `SEAL_MODEL_*` env, rendered
  from the owner's settings document before Start (`settings.go`). No
  `settings.yaml` exists.
- **`tool-cordis`**: in-process tool definition, unaudited and gone on restart.
- **The DSH `sandbox` stack**: the owner Harness uses local executors behind
  privsep's kernel UID boundary. Hosted programs run under sealed's own
  confinement (a service UID, Landlock, seccomp: `sealed/isolation/README.md`),
  started by sealed's own program in its launcher mode, so the launcher is
  always the build of the sealed that runs it.
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
| `schedule` | `false` | `schedule_create` / `schedule_list` / `schedule_view` / `schedule_edit`, `schedule_create_task` and `schedule_runs`: reminders and scheduled work the agent sets for itself, delivered to the session that set it, to a new session, or as a new task at each occurrence; a reminder a task sets for itself starts a run of it |
| `maxParallelToolCalls` | `1` | tool calls one model step may run at once. It applies only to the tools that declare themselves safe to run together: `read`, `read_image`, `web_search`, `web_fetch` and `subagent`. `bash`, `write`, `edit`, the `seal_*` tools and the job and schedule tools always run alone, after the calls before them finish |
| `modelImages` | unset | overrides whether the owner's model takes images (`true`/`false`). Unset: the provider's model list decides (`architecture.input_modalities` on the 0G router: glm-5.3 text only, glm-5.3-flash with images), and where it says nothing, pi-ai's catalog. With images the owner's images reach the model; without, each is saved in `~/inbox` and the agent is told it cannot view it |
| `memoryExtract` | `true` | before a compaction of an owner session, and after a turn that saved nothing once enough is new, the harness makes one model call that writes long-term memory from those messages (0g-harness `src/memory-extract.mjs`); `false` turns both off. Rendered as `SEAL_HARNESS_MEMORY_EXTRACT`. |
| `memoryExtractMinMessages` | `6` | how many of the owner's and the agent's messages must be new since the last pass before a turn that saved nothing is read for memories (1 to 1000). Rendered as `SEAL_HARNESS_MEMORY_EXTRACT_MIN_MESSAGES`. |
| `memoryRecall` | `true` | above `memoryInlineBytes`, before each owner message the harness makes one model call that picks up to 5 memories whose bodies will help and puts them ahead of the message (0g-harness `src/memory-recall.mjs`); `false` turns it off. Rendered as `SEAL_HARNESS_MEMORY_RECALL`. |
| `memoryTidy` | `true` | now and then, while the agent is idle, the harness makes one model call per memory role that consolidates that role's memories the current owner trusts: merges duplicates, drops what is stale or contradicted, never moves anything between the roles (0g-harness `src/memory-tidy.mjs`; due 24 h after the last pass once the memories changed, or sooner when an index nears its cap); `false` turns the automatic pass off, and `POST /v1/memory/tidy` still runs one on request. Rendered as `SEAL_HARNESS_MEMORY_TIDY`. |
| `webTools` | `true` | the `web_fetch` tool (one public http(s) page as text; private and loopback addresses refused, also after DNS; out through the credential proxy) and `web_search` through the service `webSearch` picks (0g-harness `src/web.mjs`); `false` turns both off. Rendered as `SEAL_HARNESS_WEB`. |
| `webSearch` | `{"service":"0g-router"}` | `{"service", "credential"?, "model"?}`. `service`: `0g-router` (the router's result list), `openai` (one Responses call with the `web_search` tool) or `anthropic` (one Messages call with the `web_search_20250305` server tool), whose answer comes back first and its sources after it; `off` removes `web_search`. Paid with the model key when the model's provider is that service and no `credential` is named, else with the named owner credential, which must allow the service's host and key header. `model` runs an `openai`/`anthropic` search; default: the main model when it is on that provider. The provider registry's `webSearch` field says which service each provider's key pays (`0g-agentdna providers`). With no `web_search` (`off`, or a service the settings cannot pay), sealed passes the reason as `SEAL_HARNESS_WEB_SEARCH_OFF` (at most 300 characters; for `off`: "your owner turned it off (settings: webSearch.service = off)"), and the harness tells the agent which tool is off and why; with `webTools` off it names that switch instead. |
| `subagentModels` | none | further models subagents may name, at most 8 `{"provider", "model", "credential"?}`, paid by the same rule as `webSearch`; the main model is always offered. Needs `subagents`. A malformed list is dropped whole. |
| `subagentDefault` | the main model | `{"provider", "model"}`: what a subagent runs on when the call names no model; the main model or one of `subagentModels`, else ignored. |
| `memoryInlineBytes` | `8192` | up to this many bytes of memory bodies (both memory roles) every memory is in the system prompt whole and there is no recall; above it, the indexes and recall (256 to 65536). Rendered as `SEAL_HARNESS_MEMORY_INLINE_BYTES`. |

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
policy mode, the spine invariant checks, the filesystem root, seal-tools and
subagent-guard. They are the part of the boundary the package hash attests.

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
  owner-selectable: the harness surface, seal-tools, subagent-guard,
  doctrine injection and the inference route.
- **Picked at deploy, visible on chain.** The owner picks a tier at deploy,
  like framework + model. The tier id is recorded in the on-chain `framework`
  binding, so a verifier can see which capability tier an agent runs. The tier's
  content is still backed by the package hash.
- **Changed by reset only.** Changing tier means a reset (the same path as
  changing framework/model), never a runtime hot-swap: which plugins mount is
  part of the measured boundary, and a tier is a different plugin set. The four
  allowlisted options above are different: they are values passed into a
  composition that does not change, so they apply on a settings push + process
  restart.

Other deferred items:
- `~/.dsh/AGENTS.md` as a persona role;
- the e2b tool sandbox, as the "tool sandbox" side of the habitat model.
