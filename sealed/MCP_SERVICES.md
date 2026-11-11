# Hosted MCP services

The owner Harness connects to sealed's private MCP server on the sign socket.
It discovers `seal_service_publish`, `seal_service_start`, `seal_service_stop`,
`seal_service_list` and `seal_service_logs`. The paired 0g-harness change uses
DSH's native MCP client; its bundled `publish-mcp-service` skill owns the
authoring and publication workflow. Existing signing and credential tools
continue to be defined by sealed.

## Publication contract

Publish a manifest with `id`, `command`, `args`, `files` and optional
`description`, `env`, `network`, `memory_mb` and `processes`. Each file has a
relative `path` and standard-base64 `data`. Commands name an interpreter in
the trusted image PATH, such as `node`; its code runs only after dropping
privileges and entering the sandbox. Arguments usually name `/app/server.mjs`.
Files are regular, read-only source/dependency files; archives and links are
not unpacked. Dependency installation belongs to the unprivileged agent.

The server listens on the Unix socket in `$MCP_SOCKET`, `/run/service.sock`.
It receives the original public request path. Its public MCP endpoint is
`<sandbox-url>/api/mcp/<id>`. `/hello` advertises it. A stopped or starting
service returns 503; callers must poll `seal_service_list` for `running` and
then test an actual MCP exchange. Readiness means socket availability, not
that every business operation has passed a health check.

`/app` is an immutable release, `/work` persists, and `/tmp` is temporary.
Stop before publishing a new version. Publishing returns a SHA-256 version
over the normalized manifest; the latest eight source releases are retained.
Republish an earlier bundle for rollback. Publishing does not overwrite work.
The root-only registry is bound to the owner and sealed identity. Active
services resume only after chain bootstrap validates that binding. Desired
stopped state survives reboot. Crashes restart at a bounded rate; stop ends
the process namespace and cancels pending restart. Owner transfer closes the
manager, as well as the proxy's existing owner gate.

There are at most 16 services and 512 files per release. A bundle decodes to at
most 16 MiB; publication JSON is limited to 24 MiB and the aggregate durable
registry to 8 MiB. Internal MCP requests have a 1 MiB limit. For a larger
bundle the owner may POST `{action:"publish",manifest:...}` to `/service-host`
on the same private socket using a local JSON file. GET `/service-host` lists;
POST actions `start`, `stop`, `logs` take an `id`. No management endpoint is
added to the public TCP listener.

## Isolation and limits

Each service gets a unique host UID/GID in the reserved 200000–200015 range.
The trusted `sealed-service-launcher` drops supplementary groups and identity
before invoking bubblewrap. The service receives a PID, user, IPC and UTS
namespace, a minimal environment, no capabilities, no-new-privs, and only the
image runtime plus its own app/work/run mounts. Sealed state, the owner home,
management/sign/reveal sockets and other services' work are not mounted.
Owner-authored source releases are root-writable and readable by the owner;
credentials must not be included in them. Work/run directories are private
to the service UID. Logs and registry remain in sealed's private state tree.

The image must support unprivileged user/mount namespaces; unavailable
isolation fails startup rather than running the program without it. The
Harness image ships bubblewrap, util-linux and the trusted launcher.

`network:"none"` is the default and creates a private network namespace.
`network:"host"` explicitly grants the container network, including loopback;
it does not provide tenant network isolation. Signing/credential sockets and
proxy credentials are never inherited. Host-network services are trusted with
that network access and must not be described as employer-isolated workers.

Limits are per-process virtual address space (default 8192 MiB, 128–16384),
per-service UID process count (default 64, 1–256), 256 file descriptors and
64 MiB per file. Stdout/stderr retain only the latest 64 KiB. These are rlimits,
not aggregate CPU/memory/disk quotas; the enclosing sandbox still supplies its
resource boundary. A service can handle many employers; each employer does not
automatically receive its own process or filesystem boundary.

## MCP transport and attribution

An MCP endpoint forwards POST, GET and DELETE to its backend, including MCP
session/protocol headers and client responses to server requests. The backend
may return 405 for optional methods. SSE is flushed immediately, with buffering
disabled, so sampling and elicitation can complete while a tool call is open.

Finite JSON responses retain ordinary ServeProof behavior. An SSE stream has
no complete body to hash in its initial header; it is explicitly labeled
`X-Agent-Proof-Mode: stream-unsigned` with no `X-Agent-Proof`. Upstream proof
headers are discarded. Signed `/hello` still provides identity/discovery.
This does not change any ServeProof digest, claim transcript proof for an open
stream or introduce a payment/delivery guarantee.

Business tools, model selection, sampling, progress queries, authorization and
payments belong to the owner-authored server. Employer temporary credential
custody, scoped grants and per-task workers are separate future capabilities.
Sampling is model generation, not access to arbitrary employer credentials.

## Validation

Run the sealed root suites with and without the image's agent account, plus
`SEALED_SERVICE_TESTS=1` in a namespace-capable Linux test container. The service
tests exercise publication, identity binding, real UID/mount isolation,
immutable code, crash restart, stop and reboot recovery. Proxy tests check
live sampling-request SSE, session headers, DELETE and forged-proof removal.
