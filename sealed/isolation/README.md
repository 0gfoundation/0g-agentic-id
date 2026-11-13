# Hosted service confinement

[中文](README.zh.md)

Sealed runs each hosted service process (`internal/servicesandbox`, started by
`sealed-service-launcher`) inside the agent's own sandbox, with no namespace, no
capability beyond the provider's six and no change to the provider:

| Mechanism | What it enforces |
| --- | --- |
| Service identity | A UID/GID of its own, drawn at random from 20000–64999; no supplementary groups; no-new-privs |
| rlimits | Virtual memory, processes and threads per identity (`RLIMIT_NPROC`), 256 descriptors, 64 MiB per file, no core files; set by the launcher after it leaves root |
| Landlock (ABI 6 or later) | Read/execute only the image's system directories, the release and the leased runtime; read three `/etc` entries; harmless `/dev` nodes; sockets only in the private run directory; write only the private `$HOME` and `$TMPDIR`; no `/proc`; no TCP bind/connect; abstract Unix sockets and signals scoped to the process's own domain |
| seccomp filter | No inet, netlink or packet socket; no io_uring |
| `oom_score_adj` 1000 | The kernel's OOM killer takes service processes before sealed or the owner Harness; Landlock keeps them from lowering it |
| Resource watcher | sealed reads the identity's resident memory every 500 ms and its private directories every 2 s, and kills the identity over a limit |
| Cleanup by identity | The launcher becomes the identity and signals every process of it; root then confirms none remains |

The process's only way out is a Unix socket sealed hands it: the egress proxy
(published hosts only, as CONNECT tunnels) and the per-task model proxy. Its
loopback is the container's, shared with the owner, so nothing listens there.

## Measured on the dev runner (2026-11-13)

A Sysbox container on the runner image's base (`docker:28.5.2-dind-alpine3.22`)
ran containers with the runner's sandbox flags (runc, the six capabilities,
Docker's default seccomp profile, `--init`, a memory limit). Kernel
6.17.0-42-generic, Landlock ABI 7, AppArmor `unconfined` inside. A process at UID
51000 with no-new-privs, after `landlock_restrict_self`:

- refused: a world-readable file outside its rules, `/etc`, writing `/tmp`,
  another process's `/proc`, lowering its own `oom_score_adj`, TCP to 127.0.0.1
  and to the internet, an abstract Unix socket and a signal to a same-UID process
  outside its domain;
- allowed: its own work directory and executing a child;
- a mode-0666 path Unix socket outside its rules still connected: Landlock does
  not cover path sockets, which rely on their file modes.

Its own seccomp filter refused `socket(AF_INET/AF_INET6)` and allowed `AF_UNIX`.
`RLIMIT_NPROC` stopped forks at the limit, and `kill(-1, SIGKILL)` as the identity
removed every process of it, including ones in their own session re-parented to
init. Between two containers, the count for one UID was shared (11 processes in
one left the other unable to fork under a limit of 8), and `kill(-1)` did not cross
containers. Hence identities are random, not fixed slots.

The container's root is not exempt from `RLIMIT_NPROC` there either (it is not
the initial user namespace's root), and its count covers every root process of
the runner: with the limit set before the launcher left root, the launcher could
not start a thread (`failed to create new OS thread`, EAGAIN, 2026-11-13). The
launcher therefore sets every rlimit after the identity drop.

The probe and its results: 0g-tapp-ops `deploy/dev/landlock-probe-20261113/` and
`deployments/sandbox.md` (2026-11-13 15:55).

## Limits of this design

- Memory and disk are watched, not kernel limits: a burst between two reads can
  pass them, and the sandbox's own memory limit is the hard bound.
- Processes see the system's process IDs (signals and `/proc` are refused).
- Identities of different sandboxes share `RLIMIT_NPROC` when they collide.

## Tests

`SEALED_LANDLOCK_TESTS=1 go test ./internal/servicesandbox` and
`SEALED_SERVICE_TESTS=1 SEALED_ISOLATION_EXPECT=supported go test ./internal/servicehost`,
as root, in a container with the six capabilities and Docker's default seccomp
profile on a kernel with Landlock ABI 6 (the dev runner). On a kernel without
Landlock, `SEALED_ISOLATION_EXPECT=unsupported` checks that admission fails closed.
