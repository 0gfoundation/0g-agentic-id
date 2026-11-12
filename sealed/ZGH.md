# zgh backend

The zgh image keeps AgenticID's `0g-harness` binding contract (including its
`dsh` alias). It selects `harness.NewZGH` with build tag `zghonly`; the other
images and adapters retain their existing behavior. The executable path and
layered-package namespace stay `bin/0g-harness.mjs` and `/opt/0g-harness/<hash>`.
This is an implementation migration, not a new on-chain identity protocol.
The integration package version is 0.3.0; the package's `runtime.json` names its
zgh source commit. A legacy DSH package cannot run under zgh's route declaration:
its missing/wrong runtime metadata fails Start and the existing package
fallback mechanism can select the new image's pinned base.

## Restore and storage

| Input | Restore behavior |
| --- | --- |
| Mint-only `framework` + `persona` seed | Existing adapter reads the seed's system_prompt and inference pin; writes persona to APPEND_SYSTEM.md and recovers the pin through owner settings |
| Evolved `APPEND_SYSTEM.md` + `skills/` | Existing role/manifest restoration keeps plaintext byte-for-byte; zgh reads the files |
| Evolved persona plus leftover mint seed | Canonical persona wins; old seed cannot overwrite it |
| Flat `<name>.md` skills | Opt-in zgh compatibility reader, without rewriting their source or role names |
| Retired `settings.yaml` role | Existing compatibility path recovers the model pin into owner settings |
| No historic memory role | No synthesized memory from chats; zgh begins with empty local memory |

Old container-local DSH conversation logs are retained as local files but are not converted into zgh sessions. This migration covers on-chain identity data.

The existing bootstrap completes role/entry restore and legacy handling, then
recovers owner settings before enabling ordinary drift commits. The adapter
still declares only `framework`, `APPEND_SYSTEM.md`, `skills/`. Local zgh session,
task and memory files are outside that allowlist. They are not uploaded as core
iData, even if zgh extracts them. No directory-wide memory export is introduced.
The persona precedence rule depends on restored roles, not update counters or a
local migrated flag. Ordinary same-container edits retain the existing
uncommitted-state handling. `/clear` removes local zgh runtime state while
retaining persona and skills.

## Owner protocol

The zgh backend advertises chat plus `zgh-sessions-v1` and `zgh-tasks-v1`.
Native task state, workspace, multi-input and archive semantics are not the
legacy `tasks` kind or OpenAI Responses. The adapter declares their individual
endpoints; sealed still owns authentication, bearer translation, owner lock,
signing and proxying. Finite native owner API and SSE responses retain the
framework-route signing rules. Native sessions/tasks run as the owner and are
not employer isolation boundaries.

The SDK attaches `nativeSessions`/`nativeTasks` only when the matching signed
`/hello.routes` kinds are present. The CLI's capability-based help adds:

- `/sessions`, `/session new|resume|fork|show|prompt|cancel|events`;
- `/tasks`, `/task new|input|answer|start|cancel|archive|events`;
- `/task show|cancel <id>` unambiguously addresses native tasks. `/result` and
  `/cancel` keep their existing owner-turn meaning when Responses is also
  advertised; otherwise they are native task aliases.

`/session prompt <id> <text>` queues input and reports acceptance; `/session
events <id>` shows progress, with Esc stopping observation. Plain chat addresses
the resident owner session. No local transcript becomes an authoritative task
store. OpenClaw, Hermes, Prime and the DSH backend keep existing command paths.

## Employers and services

The existing service host is unchanged: arbitrary MCP programs are supported,
with a fresh UID, sandbox and tmpfs per request-mode MCP POST. The zgh artifact
includes a minimal `runServiceAgent` helper and publishing skill. The owner
chooses persona, native tool implementations, model routing and business logic.
DSH-specific service configure callbacks must be republished using zgh's
`ctx.registerTool`; Cordis plugins cannot be mounted into zgh.

`X-Seal-Runtime-Input` remains private stdin, stripped from forwarded HTTP. It
bypasses the resident owner process and is not stored in sealed's owner vault.
The trusted task code sees plaintext. Its tools can use the credential without
automatically inserting it into model requests. End-of-response, cancellation,
timeout, stop and transfer terminate the temporary process. Asynchronous tasks
that outlive a request are not offered by this request-mode helper. Native
`zgh worker join` is a separate controller protocol and is not used here.

## Build and rollout

Build/test/package zgh in its private repository using `products/sealed` and its
`sealed embedding` workflow. Obtain the Linux x64 `runtime.tgz` artifact and
SHA-256. Keep the file at ignored `sealed/images/zgh/runtime.tgz`, verify its
hash, then from sealed/ run:

```sh
docker build -f images/zgh/Dockerfile --build-arg ZGH_PACKAGE_SHA256=<sha256> -t <image> .
```

This public repository contains no private source fetch, token or copied zgh
implementation. The image is built with only this backend. Existing image,
sealed and harness artifact allowlists still gate rollout; runtime proof hashes
and inference enforcement are unchanged. Select the new image explicitly or
change the environment's 0g-harness image mapping when publishing a release.
No running deployment is automatically reset by these code changes.
