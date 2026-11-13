# Delegated service cgroups

Hosted service code requires kernel cgroup-v2 memory and PID limits. Sealed does
not infer these guarantees from per-process `prlimit`, process-group signals,
RSS polling, or a writable directory. When the provider has not delegated the
layout below, `servicecgroup.New()` returns `ErrUnsupported` and service admission
must fail closed.

The provider must place the sealed supervisor in a root-owned `0g-supervisor`
cgroup and pre-create a sibling `0g-service-jobs` pool beneath the same billed
sandbox parent. `/proc/self/cgroup` must identify the supervisor leaf. The
cgroup-v2 mount is fixed at `/sys/fs/cgroup`; no owner setting selects another
mount or pool. The provider remains responsible for linking that parent to the
sandbox's billing and container boundary.

```
billed sandbox parent                 finite memory.max and pids.max
├── 0g-supervisor                     contains the sealed supervisor
└── 0g-service-jobs                   finite aggregate memory.max and pids.max
    ├── job-<sealed-generated key>     coordinator or temporary process tree
    └── job-<sealed-generated key>     another coordinator or process tree
```

The parent and pool must be domain cgroups with `memory` and `pids` available
and enabled in `cgroup.subtree_control`. The pool has no direct processes. Its
finite memory/PID limits must be below the parent's limits, leaving supervisor
headroom. Control files and every traversed cgroup directory must be root-owned
and not writable by group/other. Sealed follows no links or subordinate mounts
when opening the layout. It neither creates this provider layout nor moves its
own process to make a failing probe pass. The service processes do not receive a
cgroup filesystem mount or the supervisor's control descriptors.

Before admitting code, the probe creates a random empty child, writes and reads
back `memory.max`, `memory.swap.max=0`, `pids.max`, and `memory.oom.group=1`, opens
its writable `cgroup.procs`, exercises `cgroup.kill`, observes an empty subtree,
and removes it. Missing controllers, read-only delegation, unbounded limits,
incorrect process membership, symlinks, or unsupported kernel operations refuse
admission. This requires kernel support for `openat2` containment and
`cgroup.kill`; there is no weaker fallback.

For each sealed-generated job identity, `Pool.Acquire` creates a fresh child and
sets those limits before exposing its migration descriptor. The trusted launcher
writes its own PID (`0`) through that descriptor before dropping privileges and
starting service code, then closes it. Descendants inherit membership across
fork, exec, process-group changes, and sessions. Memory is bounded for the whole
process tree, swap is disabled, and the PID controller counts both processes and
threads. The pool's limits bound all simultaneous service trees together; they
are additional to each tree's requested limits.

Cleanup writes `cgroup.kill=1` and waits for the kernel's `cgroup.events`
`populated=0` before removing the child. A timeout or error leaves the lease
pinned for retry. The caller must quarantine its UID and service/admission slot
until that same lease is verified empty and removed. A successful signal or
parent-process exit is insufficient. `Pool.Close` refuses active leases.

The backend's production probe never enables additional capabilities or changes
seccomp/AppArmor policy. The current sandbox provider deployment has not been
shown to provision this delegation. The local privileged Docker fixture can
prepare it before dropping the runtime to its constrained capabilities; that
fixture is evidence of kernel behavior, not evidence of provider availability.

Run the unit and live checks on Linux:

```
go test ./internal/servicecgroup
# Only after trusted provider/bootstrap setup has created the exact layout:
SEALED_CGROUP_TESTS=1 go test -count=1 ./internal/servicecgroup
```

The gated tests exercise aggregate OOM killing with two descendants individually
below the memory cap, PID-controller exhaustion across descendants, and cleanup
of a child that started another session. Without the explicit gate they skip;
ordinary filesystem fixtures test refusal/read-back/cleanup logic only and do
not establish kernel enforcement.

Kernel behavior follows the [official cgroup-v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html).
