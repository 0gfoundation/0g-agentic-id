# Hosted MCP services

The owner Harness discovers `seal_service_publish/start/stop/list/logs` on
sealed's private sign socket using DSH's native MCP client. Its bundled
`publish-mcp-service` skill supplies application workflow. Sealed supplies
process primitives, not employer accounts, business tasks or payments.

## Publication

A manifest requires `id`, `command`, `args`, `files`; optional fields are
`worker`, `description`, `env`, `network`, `egress_hosts`, `memory_mb`,
`processes`, `request_timeout_seconds`. Files are `{path,data}` with relative
paths and standard-base64 contents. `env` is durable **public configuration**.
Commands name trusted image interpreters such as `node`; owner code executes
only after privilege drop. Source/dependencies are regular read-only files
at `/app`; root never unpacks archives, interprets symlinks or installs packages.

Programs listen on `$MCP_SOCKET` (`/run/service.sock`); the public endpoint is
`<sandbox-url>/api/mcp/<id>`, advertised by `/hello`. The original path is kept.
Publication uses the existing public 8080 and adds no port or management entry.

Omit `worker` for a small stateless server: each POST starts a temporary sandbox.
For async jobs, declare `worker:{command,args}`: sealed starts an **isolated
coordinator** for MCP, with service-private persistent `/work` and a private,
service-scoped process-control socket. Every job it submits starts a **separate
temporary worker**, with tmpfs `/work` and `/tmp`. The coordinator is application
code with no owner Harness, signing or credential authority. Workers cannot
inherit its control socket or opt out of isolation. Execution receipts bind
results to actual temporary workers.

Start enables admission and starts a declared coordinator. Poll list until
`running`, then verify actual MCP behavior; this is not a business health check.
Stop disables admission and terminates coordinator/workers. Stop before updating.
Version is SHA-256 of the normalized manifest; pin it when verifying results.
Eight releases are retained; republish an earlier bundle for rollback.

The root registry is owner/identity-bound; enabled services resume only after
chain bootstrap validates that binding. Coordinators may restart and read their
own work database; **task processes, private input and tmpfs never resume**.
Interrupted executions are reported, never silently rerun. Owner transfer
permanently closes the manager and existing owner gate. Stop/start preserves
application `/work`; it is not iData, on-chain data or cross-sandbox backup.

Limits: 16 services, 512 files and 16 MiB decoded/release, 24 MiB publication JSON,
8 MiB registry. Internal MCP requests cap at 1 MiB; larger manifests can be
POSTed from a local JSON file to `/service-host` on `$SEAL_SIGN_SOCK` as
`{action:"publish",manifest:...}`. GET lists; start/stop/logs take `id`.
No management endpoint is public. `logs` is empty: coordinator/request stdout
and stderr are discarded; job stdout is a private handoff to its application,
never an owner-readable log.

## Isolation and network

Coordinators use host UIDs 200000–200015; active temporary workers use distinct
UIDs 210000–210031, at most 32 across services. The trusted launcher clears
supplementary groups and drops UID/GID before bubblewrap. Programs have private
PID, mount, user, IPC, UTS and **network** namespaces, no capabilities and
no-new-privs. Only image runtime, immutable code and their own work/run mounts
are present. Owner home/state, sealed state, sign/reveal sockets and other
workers' files are absent. The image-base Harness is read-only at
`$HARNESS_RUNTIME_ROOT`; resident writable differences and conversations are not
shared. Missing namespace support fails closed.

`network:"none"` is default. `network:"egress"` requires 1–32 explicit
`egress_hosts` as `host:port`. A private Unix HTTP/CONNECT proxy permits only
those destinations and rejects private, loopback, link-local and metadata IPs,
including DNS answers. Raw host networking is unavailable. Node automatically
loads the image proxy bootstrap (Node >=24.14); other runtimes must explicitly
support the Unix proxy. Ignoring the proxy grants no route outside the namespace.
Owner credential proxies are never inherited.

Rlimits: virtual address space (8192 MiB default, 128–16384), processes per UID
(64 default, 1–256), 256 descriptors and 64 MiB/file. These are not aggregate CPU,
RSS or disk quotas; the sandbox supplies the outer resource boundary. Workers
end at EOF, terminate, timeout (300 seconds default, 1–3600), stop or transfer.
Disconnect cancels a one-shot request worker; a detached job survives its
submitting HTTP connection and is managed by the coordinator.

For 0g-harness/dsh, public `/api/*` must match a hosted service. Legacy loopback
publication is refused, including when service-host initialization fails;
framework routes cannot reopen it. Other adapters retain their legacy behavior.
Providers may separately configure ports at sandbox creation; publication grants
no such authority.

## Private input and process control

Callers explicitly trusting the program with plaintext can send
`X-Seal-Runtime-Input: base64(JSON string map)` over HTTPS, at most 16 KiB decoded.
This is a sealed extension, not MCP sampling/OAuth. Keep it out of HTTP logs.
Private headers and caller-supplied references are stripped before application
HTTP handling. One-shot servers read the map from anonymous stdin. Coordinators
receive only a one-use opaque reference and must launch the selected worker
before responding. Only that worker receives the private map, framed separately
from public input in stdin. Unused references end with the request.

No employer vault, reveal approval, renewal/writeback or private-input persistence
is added. Values never transit the resident owner Harness or automatically enter
model messages. They are not registered with the owner credential scrubber.
The task program can disclose what it reads and must be trusted; process isolation
does not hide input from its own code author. ServeProof does not bind this header.

Only the coordinator gets `$SEAL_EXEC_SOCKET`: POST `/executions` actions
`spawn/get/find/wait/terminate/release`. Sealed fixes the service scope. Spawn takes
`key`, base64 opaque `input`, optional `input_handle`; random handles query status.
Keys are `<unix-ms>-<16..48 random URL-safe characters>`. Concurrent same-key,
same-input, same-code retries return one execution; changes conflict. `find`
recovers a lost acknowledgement without spawning. Keys older than ten minutes
cannot start anything, even after record GC.

Public input caps at 512 KiB; opaque stdout at 1 MiB/execution and 32 MiB globally;
reads return up to 64 KiB. At most 1024 records, collected ten minutes after exit.
Output is memory only, lost on sealed restart. Applications must persist output
before `release`; metadata/dedup survives release until GC. Waiter timeout does
not cancel execution. Metadata contains hashes, version, UID, timing, exit facts
and receipt, never input/stdout, employer ownership, business progress or payments.

## Execution receipts and HTTP attribution

Successful jobs receive a `0G.SealedExecution.v1` agentSeal receipt under a separate
EIP-191 version-0x00 digest. It binds chain/registry/agent, validator, UID, source
version, public-input/stdout SHA-256, limits and enforced isolation profile.
`isolation.worker_runtime_hash` is the actual image-base Harness used by the worker;
outer `harness_hash` belongs to the resident layered runtime context and may differ.
If a layered runtime cannot name its current hashes, no execution receipt is
signed until those hashes are ready. Owner personal_sign/EIP-712/transaction tools cannot sign this digest; there is
no arbitrary receipt-signing API.

Harness `verifyExecutionReceipt` checks signature, trusted identity, isolation,
public input and exact stdout, then derives the result from that stdout. Obtain
trust anchors from a verified AgenticID/TEE connection, not receipt assertions;
pin source/runtime hashes when required. Receipts attest mechanisms/bytes, not
business correctness, private input, payment or a separate kernel. They are not
feedback registry ServeProofs or on-chain transactions. ServeProof digests do not
change. Finite JSON retains ordinary HTTP proofs; MCP SSE is flushed with
`X-Agent-Proof-Mode: stream-unsigned`. Upstream proof headers are discarded.

## Application workflow and x402

Harness supplies `servePaidService`, `ExecutionClient`, `runServiceWorker`, wallet
access tokens, buyer fetch and receipt verification. Its ordinary MCP tools
`submit/status/result/cancel` implement wallet-scoped authorization, durable
results/progress and idempotency. Workers can run business code or a fresh DSH
loop. Native MCP Tasks, sampling and employer model API keys are not required.

The template verifies exact EVM EIP-3009 authorization, runs the isolated job,
**persists results before settlement**, settles through an external facilitator,
independently checks the direct token transaction via RPC, then opens result
retrieval. Retry reuses the same authorization. Unknown settlement keeps results
locked and reconciles by payer/nonce on chain. A confirmed unused nonce with a
still-valid original authorization permits bounded resubmission of that same
signature; no fresh authorization or worker rerun. Pending/used/unknown nonce
stays locked; confirmed on-chain expiry ends the failed payment attempt.
Pricing, authorization, payment/results and facilitator settings
belong to the application. Sealed adds no wallet, escrow or x402 API. Setup is in
the companion Harness `skills/publish-mcp-service/paid-service.md`.

x402 is **not atomic fair exchange between payment and delivery**. Saved results
make a lost response retryable while the sandbox/storage remains available;
total storage loss after payment still needs application recovery/refund policy.
Neither execution receipts nor HTTP proofs remove this limitation.

## Validation

Run root suites without/with the agent account and `SEALED_PRIVSEP_TESTS=1`.
`SEALED_SERVICE_TESTS=1` checks real namespaces, UIDs, stdin, deduplication, limits,
cancellation, atomic private-input handoff, repeated Stop/Start and GC. `SEALED_LOOP_TESTS=1` adds the public DSH/tool path and a
complete paid MCP path: real SDKs/signatures, wallet isolation, concurrent retry,
private stdin, progress, cancellation, receipt verification/tamper rejection and
lost settlement responses before/after broadcast. Local chain/facilitator fixtures spend no funds and
do not prove a live deployment. Mount the companion source checkout (including test/helpers) under
`/opt/0g-harness/<hash>`, its base pointer and Node in the privileged Linux test.
