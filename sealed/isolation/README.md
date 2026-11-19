# Hosted service confinement

[中文](README.zh.md)

Sealed runs each hosted service process (`internal/servicesandbox`) inside the
agent's own sandbox, with no namespace, no capability beyond the provider's six
and no change to the provider:

| Mechanism | What it enforces |
| --- | --- |
| Service identity | A UID/GID of its own, drawn at random from 20001–64999 (20000 is the probe's); no supplementary groups; no-new-privs |
| rlimits | Virtual memory, processes and threads per identity (`RLIMIT_NPROC`), 256 descriptors, 64 MiB per file, no core files; set by the launcher after it leaves root |
| CPU priority | nice 19 with `RLIMIT_NICE` 0: service processes cannot raise their priority; they share the sandbox's CPU quota with sealed and the owner Harness (see the measurement below) |
| Process budget | All service processes together hold at most 2048 processes and threads, reserved per launch from each manifest's `processes` |
| Landlock (ABI 6 or later) | Read/execute only the image's system directories, the release and the leased runtime; read a temporary worker's copy of the agent data its release asked for (`agent_data`, read-only, MCP_SERVICES.md "Agent data"); read four `/etc` entries (`resolv.conf`, `hosts`, `ssl/certs`, `ssl/openssl.cnf`) and sealed's network adapters; harmless `/dev` nodes; in the private run directory only listing, creating sockets and removing entries; full access (write, create, execute) only below the private `$HOME` and `$TMPDIR`; no `/proc`; no TCP bind/connect; abstract Unix sockets and signals scoped to the process's own domain |
| seccomp filter | Sockets of family `AF_UNIX` only; no io_uring, System V IPC, POSIX message queue, kernel keyring or x32 call; no `clone` with `CLONE_PARENT`, and `clone3` answers ENOSYS so libc uses `clone`; `fallocate` answers EOPNOTSUPP |
| `oom_score_adj` 1000 | The kernel's OOM killer takes service processes before sealed or the owner Harness; Landlock keeps them from lowering it |
| Resource watcher | sealed reads the identity's resident memory every 500 ms and the blocks allocated below its private directories (`$HOME`, `$TMPDIR`, the run directory; each entry at least 4 KiB) every 2 s, and kills the identity over a limit; below 1 GiB or 65536 inodes free on the task directories' filesystem it stops every service process and refuses new ones |
| Cleanup by identity | The launcher becomes the identity and signals every process of it; root then confirms none remains. A starting sealed does this for every service identity that has a process, and never hands out one it could not clear |

The process's only way out is a Unix socket: those sealed hands it (the egress
proxy, published hosts only, as CONNECT tunnels, and the per-task model proxy),
and any path socket whose own file mode admits it, which Landlock does not cover.
Sealed's own listeners on the container's loopback (shared with the owner) stay
out of reach, since inet sockets and TCP connect are refused.

The launcher is sealed's own program: sealed starts its own executable as root
with `sealed-service-launcher` as the first argument (`privsep.RootSelf`), and
`main` hands that run to the launcher before anything else runs. A sealed
version therefore always runs with the launcher built with it.

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

The container's root is not exempt from `RLIMIT_NPROC` either (it is not the
initial user namespace's root), and its count covers every root process of the
runner: a root process under a limit of a few hundred could not start a thread
(`failed to create new OS thread`, EAGAIN, 2026-11-13). The launcher sets every
rlimit after the identity drop.

The probe and its results: 0g-tapp-ops `deploy/dev/landlock-probe-20261113/` and
`deployments/sandbox.md` (2026-11-13 15:55).

As nobody, without sealed's filter, in a container with the runner's sandbox
flags (2026-11-14):

- `socket(AF_SMC)` succeeded: address families other than inet, netlink and
  packet are available, and the filter allows `AF_UNIX` only.
- `kernel.shm_rmid_forced` was 0: a System V shared memory segment outlives its
  process, outside any process's resident memory, and the filter refuses System
  V IPC.
- An x32 call ended the process with SIGSYS (Docker's default profile); sealed's
  filter refuses x32 calls as well.
- The container's `pids.max` was `max`: the process budget is the bound across
  service processes.
- The root filesystem was overlay on an ext filesystem, where Daytona's runner
  sets no per-sandbox size (it does only on xfs), and `statfs` reported the
  whole disk: the free-space floor protects that disk.
- With a 1-CPU quota (2026-11-14), `kernel.sched_autogroup_enabled` was 1, and a
  nice-19 busy loop in its own session (as the launcher starts a service) got as
  much CPU as a nice-0 one over 4 s (ratio 1.056): nice 19 does not make service
  processes yield the sandbox's CPU there.

## Limits of this design

- Memory and disk are watched, not kernel limits: a burst between two reads can
  pass them, and the sandbox's own memory limit is the hard bound. Memory no
  process has resident (a memfd written but not mapped, pipe buffers) is bounded
  only by that limit; the OOM killer takes service processes first. Disk held by
  files deleted while open is not counted per identity (root, without
  `CAP_SYS_PTRACE`, cannot read another identity's descriptors); the free-space
  floor bounds it.
- CPU is shared: service processes, sealed and the owner draw on one sandbox
  CPU quota, and sealed reserves none of it for itself or the owner; nice 19
  orders them only where the kernel applies nice between them, which the dev
  runner measurement did not show.
- Processes see the system's process IDs (signals and `/proc` are refused).
- Identities of different sandboxes share `RLIMIT_NPROC` when they collide.

## Tests

`SEALED_LANDLOCK_TESTS=1 go test ./internal/servicesandbox` and
`SEALED_SERVICE_TESTS=1 SEALED_ISOLATION_EXPECT=supported go test ./internal/servicehost`,
as root, in a container with the six capabilities and Docker's default seccomp
profile on a kernel with Landlock ABI 6 (the dev runner). On a kernel without
Landlock, `SEALED_ISOLATION_EXPECT=unsupported` checks that admission fails closed.
