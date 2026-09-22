# Native Studio runtime API

> 中文版见 [STUDIO.zh.md](STUDIO.zh.md)。

Studio exposes adapter-owned text resources through sealed, independently of
model output. Adapters opt in with `studio.Provider` and `StudioLayout()`.
Discovery declares `{ "prefix": "/_seal/studio/", "kind": "studio",
"auth": "bearer", "signed": false }`.

Every management request validates the existing owner bearer and resolves the
live chain owner against the owner at boot. Missing ownership proof returns
503; transfer returns 409 `ownership_changed` until the sandbox restarts under
the new owner. No generic shell endpoint or caller-chosen filesystem root exists.

## Native resources

| Adapter | Native resources | Activation |
| --- | --- | --- |
| OpenClaw | `SOUL.md`, custom skills, Markdown memory, canvas text files | `active`: next prompt / watcher refresh |
| Hermes | `SOUL.md`, memory, non-bundled skills | Personality/memory `next_session`; skills `restart_required` because the pinned prompt index is cached |
| Prime | `APPEND_SYSTEM.md`, Python skill bundles | `next_session`, or idle session reload |
| DSH | `APPEND_SYSTEM.md`, directory skill bundles | Personality `active` on the next prompt; skills `restart_required` |

`active` does not change an already executing prompt. This API does not install
Cordis plugins or expose unsupported schedules, subagents or persistent memory.

`GET /_seal/studio/state` returns `schema: "0g.studio.state.v1"`, framework and
resources with `kind`, `format`, `activation`, and `{id,revision}` items.
`POST /state/read` accepts `{kind,id}` and returns actual files, revision,
activation and checkpoint. Paths in this section are relative to
`/_seal/studio/` unless written in full.

`POST /state/mutate` accepts:

```json
{
  "operation": "put",
  "kind": "personality",
  "id": "main",
  "files": [{"path": "APPEND_SYSTEM.md", "content": "Be concise."}],
  "if_revision": null,
  "idempotency_key": "12345678-1234-4123-8123-123456789abc"
}
```

Use the adapter's actual singleton filename. `if_revision: null` creates only
an absent item; updates/deletes require the last read revision. Delete omits
files. Skills require `SKILL.md`; Prime additionally requires `pyproject.toml`
and a file under `src/`. A resource is capped at 64 UTF-8 files and 1 MiB.
Traversal, symlinks, protected platform markers and secret/config paths are
rejected. Bundled Hermes skills cannot be replaced. Writes preserve platform
injection and return actual readback plus `mutation_id`.

`GET /state/receipts/:mutation_id` reports `pending`, `confirmed` or
`superseded` for the exact `EvolutionFor` role content hash. Only the matching
chain entry confirms a checkpoint; the existing watcher/upload transaction
still owns persistence. Mutation keys and receipts retain the last 256 entries
in process memory. After recreation or receipt eviction, re-read state before
editing. A local write is not a confirmed chain upload.

## Prime conversations

Prime declares bearer `/v1/sessions` with kind `sessions`. `POST` with a
canonical lowercase UUID `{id}` creates once (201) or returns the existing
session (200). `GET /v1/sessions/:id` returns `{id,object:"session",status}`.
Chat and Responses accept `session_id`; unknown explicit IDs return 404. Each
session has a separate in-memory SDK session manager, local Python directory
and queue. Tasks retain their originating session for follow/cancel.

`POST /v1/sessions/:id/reload` calls the pinned SDK's `session.reload()` and
retains history. Reload and `DELETE /v1/sessions/:id` reject busy sessions with
409. Deletion waits for disposal; at most 50 sessions can exist, without
automatic eviction. Omitted `session_id` keeps the legacy singleton. A sandbox
restart loses process-local conversations; saved client work is not restoration.

## Connected-account operations

Owners install a revocable narrow capability using
`PUT /_seal/studio/connections/:grant_id` with
`{engine_origin,capability,operation}`. Engine origins must be public HTTPS;
private destinations, redirects and unsafe DNS resolutions are refused. GET
`/_seal/studio/connections` returns only `{connections:[{id,operation}]}`.
DELETE removes local access. The 50-entry inventory and capabilities live only
in sealed memory, outside agent prompts, files, environment and chain state.

The agent-private Unix socket exposes GET `/connections` and POST
`/connections/invoke` with `{grant_id,invocation_id,input}`. Sealed forwards to
the engine's `/connections/runtime/agent-grants/:grant_id/invoke` with the
capability in an Authorization header. Provider OAuth tokens remain at the
engine. DSH uses `seal_connections` and `seal_connection_call`; its shell guard
remains enabled. Other frameworks can use the documented Unix socket.

Supported operations are Calendar availability (`timeMin,timeMax`) and Notion
shared-title search (`query`). The engine rechecks ownership/account/revocation
and admits each invocation ID once. Admitted work may finish after revocation.
Unknown outcomes must not automatically retry under a new ID. The sole explicit
exception is `503 connection_refresh_in_progress` with
`retryWithNewInvocationId:true` and `Retry-After:1`, which proves no tool call
began. Recreating the sandbox requires the owner to restore a rotated capability.

Local tests cover filesystem/restore, serialized bridge requests, private socket
transport and authorization. Actual model execution, image measurement,
chain upload/restore and live provider OAuth require separate deployment proof.
