# Hosted MCP services

The owner Harness discovers `seal_service_publish/start/stop/list/logs` on
sealed's private sign socket using DSH's native MCP client. Its bundled
`publish-mcp-service` skill supplies application workflow. Sealed supplies
process primitives, not employer accounts, business tasks or payments.

## Publication

A manifest requires `id`, `command`, `args`, `files`; optional fields are
`worker`, `description`, `env`, `network`, `egress_hosts`, `memory_mb`,
`resident_memory_mb`, `processes`, `inference_budget`, `request_timeout_seconds`. Files are `{path,data}` with relative
paths and standard-base64 contents. `env` is durable **public configuration**.
Commands name trusted image interpreters such as `node` or `python3`; owner code executes
only after privilege drop. Source/dependencies are regular read-only files in
the release directory, the program's working directory (name them by relative
path); root never unpacks archives, interprets symlinks or installs packages.

Programs listen on `$MCP_SOCKET` (in their private run directory); the public endpoint is
`<sandbox-url>/api/mcp/<id>`, advertised by `/hello` as `kind: "hosted"` with
the `version` it runs and its `release` path (`?sealed-release=1`). The original path is kept.
Publication uses the existing public 8080 and adds no port or management entry.

Omit `worker` for a small stateless server: each POST starts a temporary sandbox.
For async jobs, declare `worker:{command,args}`: sealed starts an **isolated
coordinator** for MCP, with a service-private persistent `$HOME` and a private,
service-scoped process-control socket. Every job it submits starts a **separate
temporary worker**, with private temporary `$HOME` and `$TMPDIR`. The coordinator is application
code with no owner Harness, signing or credential authority. Workers cannot
inherit its control socket or opt out of isolation. Execution receipts bind
results to actual temporary workers.

Start enables admission and starts a declared coordinator. Poll list until
`running`, then verify actual MCP behavior; this is not a business health check.
Stop disables admission and terminates coordinator/workers. Stop before updating.
Version is SHA-256 of the normalized manifest. Fetch
`GET /api/mcp/<id>?sealed-release=1` before supplying credentials: sealed returns
`{version,manifest,canonical_manifest}` even while stopped, without executing
service code. `canonical_manifest` is base64 of the exact normalized JSON whose
SHA-256 is `version`. Authenticate this finite response's ServeProof through the
caller's verified AgenticID/TEE connection, inspect the code, then pin that version.
Eight releases are retained; republish an earlier bundle for rollback.

The root registry is owner/identity-bound; enabled services resume only after
chain bootstrap validates that binding. Coordinators may restart and read their
own work database; **task processes, private input and temporary directories never resume**.
Interrupted executions are reported, never silently rerun. Owner transfer
permanently closes the manager and existing owner gate. Stop/start preserves
the coordinator's `$HOME`; it is not iData, on-chain data or cross-sandbox backup.

Limits: 16 services, 512 files and 16 MiB decoded/release, 24 MiB publication JSON,
8 MiB registry. Internal MCP requests cap at 1 MiB; larger manifests can be
POSTed from a local JSON file to `/service-host` on `$SEAL_SIGN_SOCK` as
`{action:"publish",manifest:...}`. GET lists; start/stop/logs take `id`.
No management endpoint is public. `logs` is empty: coordinator/request stdout
and stderr are discarded; job stdout is a private handoff to its application,
never an owner-readable log.

## Isolation and network

Every service process runs at a service identity of its own, drawn at random
from container UIDs 20001–64999 (20000 is the confinement probe's); the
provider's UID/GID maps must include 20000–64999.
The kernel counts `RLIMIT_NPROC` per UID across every sandbox of a runner
(measured on the dev runner), so fixed slots would let one sandbox's processes
block another's. The trusted launcher clears supplementary groups, drops UID/GID,
sets no-new-privs, `oom_score_adj` 1000 and nice 19 (with `RLIMIT_NICE` 0, so it
cannot raise its priority), then confines the process with Landlock (ABI 6 or
later) and a seccomp filter before executing the interpreter. Service processes
share the sandbox's CPU quota with sealed and the owner: on the dev runner a
nice-19 process in its own session got as much CPU as a nice-0 one, so nice does
not reserve CPU for sealed or the owner there (isolation/README.md):

- Landlock lets it read and execute only the image's system directories, its
  release and the leased Harness runtime, read `/etc/resolv.conf`, `/etc/hosts`,
  `/etc/ssl/certs` and `/etc/ssl/openssl.cnf` (Node exits when it exists but cannot be read)
  and sealed's network adapters, use `/dev/null`, `zero`, `full`, `random`, `urandom`,
  list its private run directory, create sockets and remove entries there (no
  file or link, so a socket sealed dials cannot become a link), and write (and create files,
  links and sockets in, and execute from) only its private `$HOME` and
  `$TMPDIR`. `/proc` is unreadable. TCP bind and connect are refused. Abstract
  Unix sockets and signals reach only its own processes.
- The seccomp filter allows sockets of family `AF_UNIX` only; refuses io_uring,
  System V IPC, POSIX message queues and kernel keyrings (objects that outlive
  the process, or reach the next task at the same UID) and every x32 call;
  refuses `clone` with `CLONE_PARENT` (its child would be sealed's, which never
  waits for it, and would stay a zombie counting against the identity) and
  answers `clone3` with ENOSYS, so libc uses `clone`; and answers `fallocate`
  with EOPNOTSUPP, so writes, which the file-size limit bounds, are the only way
  to take disk space.

Owner home/state, sealed state, sign/reveal sockets and other workers' files are
unreachable. Unix sockets sealed hands the process are owned by its identity;
any other path socket keeps its file mode, which Landlock does not cover.
At every launch sealed checks that the active verified Harness package is still
listed, then pins it against package pruning until all job processes exit.
That package is read-only at `$HARNESS_RUNTIME_ROOT`; resident writable
differences and conversations are not shared. No image-base package is required.
A kernel without Landlock ABI 6, or a container whose seccomp policy refuses
Landlock, fails closed with `unsupported`. The provider needs no change: the dev
runner (kernel 6.17, Landlock ABI 7, Docker 28.5.2 inside Sysbox, the six
capabilities, Docker's default seccomp) provides all of it; see
[isolation/README.md](isolation/README.md).

`network:"none"` is default. `network:"egress"` requires 1–32 explicit
`egress_hosts` as `host:port`, a host at most 253 characters. A private Unix HTTP/CONNECT proxy (at most 64
open connections per identity) permits only
those destinations and rejects private, loopback, link-local and metadata IPs,
including DNS answers. A service process has no network socket of its own:
sealed's listeners on the container's loopback (shared with the owner) stay out
of reach, since inet sockets and TCP connect are refused. sealed loads its
network adapter (`internal/servicenet`, built into the sealed binary, written
root-owned and read-only to `/var/lib/sealed-service-programs/<id>/.servicenet`
at start) into every Node and Python
service process: Node through `--import`, Python through `PYTHONPATH`, ahead of
the manifest's own `PYTHONPATH`. The adapter sends the runtime's ordinary TCP
clients through the Unix proxy as CONNECT tunnels, leaving host names for the
proxy to resolve: in Node every `node:net`/`node:tls` connect, so `fetch`,
`node:http`/`https`, http2 and the clients built on them (axios, got, ws); in
Python `socket.create_connection` (urllib, http.client), urllib3 (requests),
asyncio (httpx, websockets) and aiohappyeyeballs (aiohttp). Host `seal-model`
goes to the model proxy, at `$SEAL_MODEL_URL` (`http://seal-model/model`). A
client that opens its own TCP socket, Python run with `-S`, `-I` or `-E`, and
other runtimes have no route unless they speak to the Unix proxy themselves.
The adapter is a convenience, not a boundary. Owner credential proxies are
never inherited.

Per-process rlimits: virtual address space (8192 MiB default, 128–16384),
processes and threads per identity (64 default, 1–256; at least 16 when the
command or the worker is `node`, checked when a release is published),
256 descriptors and 64 MiB/file. All service processes together hold at most
2048 processes and threads: each running request, execution and coordinator
reserves its `processes` limit, and a launch the budget cannot hold is refused.
One-shot request workers (each POST to a service without a worker) may hold at
most 16 of the 32 worker slots and 1024 of those processes, so executions a
coordinator spawns always have room.
Sealed reads the identity's resident memory every 500 ms (`resident_memory_mb`,
default 256 MiB, 64–4096) and the blocks allocated below its private `$HOME`,
`$TMPDIR` and run directory every 2 s, each entry counting at least 4 KiB
(128 MiB together for a temporary worker; 576 MiB for a coordinator, whose
`$HOME` is durable application state), and kills the identity over a limit. On
the same 2 s tick, while the filesystem holding the task directories has less
than 1 GiB or 65536 inodes free, sealed stops every service process and refuses
new ones; that also reclaims space no walk sees, such as files deleted while
still open. These are watched, not kernel limits: a burst between two reads can
pass them. Memory no process has resident (a memfd written but not mapped, pipe
buffers) is bounded only by the sandbox's memory limit. Under memory pressure
the kernel's OOM killer takes service processes first (`oom_score_adj` 1000),
and Landlock keeps them from lowering it. Cleanup becomes the identity and signals every process of it (a
descendant cannot change identity, so none escapes by re-parenting or a new
session), then confirms from root that none remains before reusing the identity
or unpinning the runtime. A starting sealed first stops every process of any
service identity: a previous sealed in the container may have left some, since
the loader stops its descendants only as PID 1 and the runner starts sandboxes
with `--init`. An identity it cannot clear is quarantined: never handed out, and
a coordinator saved on it reports why it does not start. A wanted coordinator
that exits or cannot start is retried after 2 s, doubling up to 60 s while it
keeps failing within a minute of starting; its state is then `restarting`, with
the cause (a limit, `readiness_timeout`, `coordinator_exit` or the admission
error), `unsupported` when the kernel or container lacks the confinement, or
`quarantined` while the cleanup of its identity is unproven. A coordinator that
ends because it is no longer wanted leaves its service `stopped`. This is not a separate CPU allocation or a disk quota; the sandbox's
outer limits still apply. Workers end at EOF, terminate, timeout
(300 seconds default, 1–3600), stop or transfer. Disconnect cancels a one-shot
request worker; a detached job survives its submitting HTTP connection and is
managed by the coordinator.

For 0g-harness/dsh, `/api/mcp/` is reserved for hosted services and cannot fall
back to a legacy backend, including when hosting is unavailable. Other legacy
`/api/*` routes and registration remain usable. Other adapters retain their
legacy route behavior, including their own `/api/mcp/...` registrations.
Providers may separately configure ports at sandbox creation; publication grants
no such authority.

## Private input and process control

Callers explicitly trusting the program with plaintext can send
`X-Seal-Runtime-Input: base64(JSON string map)` over HTTPS, at most 16 KiB decoded.
It requires `X-Seal-Service-Version: <audited version>`; a changed version returns
409 before delivery. Both request admission and one-use handoff consumption check
the version, so stop/publish/start cannot retarget a pending credential handoff.
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
does not hide input from its own code author. Auditing source and binding delivery
to its version makes that trust explicit. ServeProof does not bind this header.
A coordinator's durable `$HOME` keeps its identity and directory across published
versions, so a later version the owner publishes can read what earlier versions
stored there (a paid service's task inputs and results, for example); private
input is never stored there. Callers' trust covers the versions that will read
that state, not only the one they audited.

## Task-funded model access

Optional `inference_budget:{calls,input_bytes,output_tokens}` grants each temporary
worker its own private model socket. Calls are 1–64; aggregate input is 1 KiB–16 MiB
(512 KiB/request); output ceiling is 1–8192 tokens/request. Failed upstream attempts
count too. The worker's lifetime cancels requests; response streams cap at 8 MiB.
The socket fixes the owner's currently resolved HTTPS provider/model and injects
the real model key only inside sealed. It offers no credential lookup, signing,
redirect following or arbitrary upstream routing; coordinators receive no socket.
The route works with `network:"none"`. Sealed sets `SEAL_MODEL_ID` and
`SEAL_MODEL_API`, and its network adapter sets `SEAL_MODEL_URL` in Node and
Python; Harness `mountServiceModel` uses a public placeholder; the real key never
reaches it. Other runtimes can speak HTTP to the private Unix socket. These limits bound requests and requested output, not actual token
usage or currency spend; pricing and refunds remain application policy.

Only the coordinator gets `$SEAL_EXEC_SOCKET`: POST `/executions` actions
`spawn/get/find/wait/terminate/release/capabilities`. Sealed fixes the service scope. Spawn takes
`key`, base64 opaque `input`, optional `input_handle`; random handles query status.
Keys are `<unix-ms>-<16..48 random URL-safe characters>`. Concurrent same-key,
same-input, same-code retries return one execution; changes conflict. `find`
recovers a lost acknowledgement without spawning. Keys older than ten minutes
cannot start anything, even after record GC. An execution is two files: an
immutable key record (service, key, input hash, version, times, UID), synced to
disk before its worker starts, and a status record rewritten on each change. A
crash before the key record is synced leaves no record, and nothing ran. With
the status unusable or missing, the key record restores the execution as
`interrupted` (reason `record_lost` for a status file it cannot read,
`sealed_restarted` when there is none), never as a start that did not run, so
the key never runs again.
The control socket accepts at most 64 connections, and a request body must
arrive within 30 s.

`capabilities` takes no other field and answers
`{"launch":true|false,"receipts":true|false}`. `receipts`: whether an execution
that exits 0 now would receive a signed receipt (see Execution receipts).
`launch`: whether sealed's own preparation for a service process succeeds now
(the confinement probe, free space, and the verified runtime's listing and pin).
A paid service asks before charging and takes work only when both are true.
Concurrent asks share one preparation, and its answer is reused for 5 s.

An execution's `state` is one of `starting` (reserved; the worker is not running
yet), `running`, `exited` (exit code 0), `failed`, `timed_out` (reason
`deadline`), `cancelled` (`terminated`), `interrupted` (`sealed_restarted`: sealed
restarted while it ran; `record_lost`: its status record could not be read) and `quarantined` (sealed cannot yet prove the identity's
processes gone; the identity stays reserved). `reason` names the cause:
`start_failed`, `process_exit`, `output_limit`, `memory_limit`, `disk_limit`,
`sandbox_disk_low`, `cleanup_failed`, `resource_cleanup_failed`,
`metadata_write_failed`. `reason:"start_failed"` with no `exit_code` means the
worker never ran: the state is `failed`, or `quarantined` until its cleanup is proven.
`failed` with `process_exit` and `exit_code` 0 means the worker exited 0 but a
process it left still held its output open 250 ms later.

Public input caps at 512 KiB; opaque stdout at 1 MiB/execution and 32 MiB globally;
reads return up to 64 KiB. At most 1024 records, collected ten minutes after exit
and never while their key could still be accepted. A file sealed cannot read
at boot is set aside (`.bad-<name>`) and logged; it never disables hosting.
Output is memory only, lost on sealed restart. Applications must persist output
before `release`; metadata/dedup survives release until GC. Waiter timeout does
not cancel execution. Metadata contains hashes, version, UID, timing, exit facts
and receipt, never input/stdout, employer ownership, business progress or payments.

## Execution receipts and HTTP attribution

Successful jobs receive a `0G.SealedExecution.v1` agentSeal receipt under a separate
EIP-191 version-0x00 digest, when sealed can sign one: that needs the agent key,
an anchored AgenticID serve-proof validator (`VERIFIED_FEEDBACK_ADDR`), the agent
id, chain and identity registry. Without a validator no receipt is signed for the
container's whole life, so a paid service, which charges for a receipted result,
refuses work while `capabilities` reports `receipts:false`. It binds chain/registry/agent, validator, UID, source
version, public-input/stdout SHA-256, limits and enforced isolation profile.
`isolation.worker_runtime_hash` is the actual leased Harness package used by the worker;
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

The template verifies exact EVM EIP-3009 authorization, settles through an external
facilitator, and independently verifies canonical chain receipt/confirmation depth
**before starting a worker**. A facilitator's success response alone is insufficient.
Direct token calls and conservatively verified uniform wrapper batches are supported;
ambiguous batches need operator reconciliation. Unknown settlement starts no work
and reconciles the same payer/nonce; safe retries reuse the original signature.
Private-input tasks may require resubmitting the same request and credential header
after reconciliation; polling never starts work with missing credentials. Separate
bounded pools limit unpaid quotes, pending payments, paid records and active workers.
Once paid, cancellation/failure does not trigger an automatic refund; the owner must
define recovery/refund policy. Successful output is persisted for repeat retrieval.
Pricing, authorization, payment/results and facilitator settings
belong to the application. Sealed adds no wallet, escrow or x402 API. Setup is in
the companion Harness `skills/publish-mcp-service/paid-service.md`.

x402 is **not atomic fair exchange between payment and delivery**. Saved results
make a lost response retryable while the sandbox/storage remains available;
total storage loss after payment still needs application recovery/refund policy.
Neither execution receipts nor HTTP proofs remove this limitation.

## Validation

Run root suites without/with the agent account and `SEALED_PRIVSEP_TESTS=1`.
`SEALED_LANDLOCK_TESTS=1` (internal/servicesandbox) checks the confinement itself:
files, `/proc`, `oom_score_adj`, nice, links in the run directory, inet/UDP,
SMC and vsock sockets, System V IPC, message queues, keyrings, `fallocate`,
`clone` with `CLONE_PARENT`, signals and abstract sockets outside the domain,
and cleanup by identity.
`SEALED_SERVICE_TESTS=1` checks real confinement, identities, stdin, deduplication, limits,
cancellation, atomic private-input handoff, repeated Stop/Start and GC. `SEALED_LOOP_TESTS=1` adds the public DSH/tool path and a
complete paid MCP path: real SDKs/signatures, wallet isolation, concurrent retry,
private stdin, progress, cancellation, receipt verification/tamper rejection and
lost settlement responses before/after broadcast. Local chain/facilitator fixtures spend no funds and
do not prove a live deployment. Mount the companion source checkout (including test/helpers) under
`/opt/0g-harness/<hash>`, its fixture base pointer and Node for the local tests.
Production admission never reads that fixture pointer. Run these as root on a
kernel with Landlock ABI 6, in a container with the provider's six capabilities
and Docker's default seccomp profile; a privileged-container pass alone does not
establish provider compatibility.
