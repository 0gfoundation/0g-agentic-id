# Changelog

Release notes, one section per version, newest first, in English. A section is
written in the same pull request that sets the version number, and its heading
loses `(unreleased)` when the version ships.

- The first line of a section is the one-line summary the CLI shows. The whole
  section (at most 4000 bytes) is what `0g-agentdna releases` and the release
  emails show.
- Each environment's release file is generated from this file plus that
  environment's own dates and images, `releases/<env>.json`
  (`attestor/scripts/release-entry.mjs`; attestor README, "Announcing a
  release").

## 0.5.2

Files created by 0g-harness are acknowledged by revision, and model settings survive a sealed runtime handoff.

- After saving a file, the CLI acknowledges the exact revision it downloaded. If the agent overwrites the same name during the transfer, the newer revision stays available. The CLI can find a previously saved revision under a numbered filename. With an older runtime, it keeps the remote copy when it cannot acknowledge it safely.
- File delivery guidance now explains when automatic downloads run and how to download a file manually. Existing sessions whose titles start with a number can be reopened by quoting their title.
- Pasting a line that ends in the last terminal column preserves the plain CLI’s scrollback.
- Model and credential updates distinguish changes applied to a running agent from changes saved for its next start. A sealed handoff no longer rolls back the selected model.
- The schedule list shows the interval and run count for repeating jobs, marks overdue runs as due now, and shows when the next run time is unknown.

On testnet, install the CLI with `npm install -g @0gfoundation/0g-agentdna@next`.

## 0.5.1

Pasted slash commands execute in the CLI, file deliveries retry automatically, and 0g-harness reports when a hosted service has stopped.

- The CLI accepts quoted activity IDs and session titles, looks up short IDs in the latest 500 activities, and groups a turn’s tool calls on one line. The deploy wizard selects 0g-harness by default when it is offered.
- A session opened while its agent is stopped can save files and clean up remote copies after the agent starts. Failed transfers retry, and each successful save prints the local path once.
- The CLI includes a 0g-compute credential preset. Owners can store a model key while the agent is stopped and use it on the next start.
- On the updated 0g-harness runtime, hosted services start on OverlayFS snapshots and report their lifecycle state in `/hello`. The SDK and CLI omit stopped services from the list of callable services.

On testnet, install the CLI with `npm install -g @0gfoundation/0g-agentdna@next`.

## 0.5.0

Layered runtime (the sealed program and the 0g-harness package update themselves), owner credentials, operators, sessions and tasks, configurable web search, a new CLI agent session.

- Runtime: an agent runs a base image, a sealed program and, on 0g-harness, an official harness package, each on the trust registry. When a sealed or harness version is delisted, the agent moves to the newest listed one by itself, with no reset. On 0g-harness the image no longer carries the sealed program or the harness: at every start they come from the trust registry, so later versions reach every agent, stopped or new, without a reset. `/hello` says in one plain sentence what each route is for. A memory commit that returns to content uploaded earlier in the same run reuses it instead of uploading it again.
- Credentials: the keys an agent uses, the model key included, are kept in an owner-signed credential set and filled in by sealed on the way out; the agent never holds them (`0g-agentdna cred`).
- Operators: an owner can appoint one operator wallet that creates, funds and controls the agent's sandbox; the NFT and the settings stay with the owner (SDK `setOperator`).
- 0g-harness: long-term memory in private and public folders, image and file exchange, downloads, mid-turn steering, sessions and long tasks, an activity list, web fetch and web search (the search service is configurable), subagents on further models, a browser (off by default), hosted services with their own data. Files you send and files the agent leaves for you stay on the agent for up to 30 days, and one it left goes once you have downloaded it (SDK `deleteFile` removes any); the agent tells you what it made, not where it put it. When web search is off, the agent is told why and tells you instead of working around it.
- CLI agent session: an input box like Claude Code's, with a status line and tool calls summed up in one line. While the agent works, Enter adds a message to its turn (0g-harness), Tab queues it for the next turn and ↑ takes a queued one back; Esc stops the turn and puts unsent messages back in the box. On 0g-harness, a file dragged into the terminal goes with the message, and files the agent leaves for you are saved to `~/agentdna/<agentId>/outbox` by themselves (`/files auto off` stops it). `/sessions`, `/tasks` and `/activities` fit the terminal and take short ids (`/sessions switch 2`); `/hello` is short (`/hello full` prints every route).
- CLI: multi-line input; `releases`; a notice when one of your agents should move to a new version; errors in one or two plain lines that say what to type; `login` and the deploy wizard check each answer and ask again; amounts are checked before any transaction.
- `retry` is always signed by the owner, and the attestor refuses an unsigned one; when the agent's container failed or was stopped, a retry also creates a new one.
- Node.js 24.22.3 (the November 2026 security release).

What to do: update the CLI (`0g-agentdna update`), then reset each agent (in `0g-agentdna`: `reset <agent>`) before the date this notice gives. Until then your agents keep running. A reset keeps the agent's persona, skills, settings and the memory kept on chain; the conversation starts fresh.
