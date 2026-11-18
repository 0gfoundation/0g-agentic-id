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

## 0.5.0 (unreleased)

Layered runtime (the sealed program and the 0g-harness package update themselves), owner credentials, operators, sessions and tasks, configurable web search.

- Runtime: an agent runs a base image, a sealed program and, on 0g-harness, an official harness package, each on the trust registry. When a sealed or harness version is delisted, the agent moves to the newest listed one by itself, with no reset.
- Credentials: the keys an agent uses, the model key included, are kept in an owner-signed credential set and filled in by sealed on the way out; the agent never holds them (`0g-agentdna cred`).
- Operators: an owner can appoint one operator wallet that creates, funds and controls the agent's sandbox; the NFT and the settings stay with the owner (SDK `setOperator`).
- 0g-harness: long-term memory in private and public folders, image and file exchange, downloads, mid-turn steering, sessions and long tasks, an activity list, web fetch and web search (the search service is configurable), subagents on further models, a browser (off by default), hosted services with their own data.
- CLI: multi-line input; `releases`; a notice when one of your agents should move to a new version; errors in one or two plain lines that say what to type; `login` and the deploy wizard check each answer and ask again; amounts are checked before any transaction.
- Node.js 24.22.3 (the November 2026 security release).

What to do: update the CLI (`0g-agentdna update`), then reset each agent (in `0g-agentdna`: `reset <agent>`) before the date this notice gives. Until then your agents keep running. A reset keeps the agent's persona, skills, settings and the memory kept on chain; the conversation starts fresh.
