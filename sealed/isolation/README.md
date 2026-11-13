# Hosted service namespace policy

[中文](README.zh.md)

`docker-bubblewrap-seccomp.json` is a proposed runner policy for sealed's
temporary service processes. It is based on [Moby v27.5.1's default
profile](https://github.com/moby/moby/blob/v27.5.1/profiles/seccomp/default.json),
under the [Apache 2.0 license](LICENSE.moby), with four added rules:

| System call | Additional permission |
| --- | --- |
| `clone` | Exact flags `0x7c020011`: user, mount, PID, network, IPC and UTS namespaces, plus `SIGCHLD` |
| `clone` | Exact flags `0x7e020011`: the same namespaces plus a cgroup namespace |
| `unshare` | Exact flags `CLONE_NEWUSER` (`0x10000000`), used by bubblewrap's final privilege separation |
| `mount`, `umount2`, `pivot_root` | Namespace filesystem setup; kernel capability checks still apply |

The profile's SHA256 is
`add283d4e086d3198b77d6e8baf56151ab20e2d4a739dfe26e5b942a591e4225`.
The additional `clone` argument layout targets Linux amd64/arm64. Other
architectures require their own review and verification.

## Provider contract

The runner must apply this reviewed profile when it creates a hosting-capable
sealed container. Docker's CLI accepts `--security-opt seccomp=<file>`; a runner
using Docker's Go API supplies `HostConfig.SecurityOpt` with `seccomp=` followed
by the JSON contents. Loading this file inside sealed cannot relax an inherited
seccomp filter. Applying a new profile also requires recreating existing
containers; restarting their existing processes does not change the filter.

Keep the six container capabilities `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETUID`,
`SETGID`, `KILL`, the Sysbox runner boundary, and Docker's proc masks. Do not use
`privileged`, `SYS_ADMIN`, an unconfined seccomp/AppArmor profile, or a host Docker
socket. If an LSM independently denies unprivileged user namespaces, the provider
needs an appropriately constrained LSM policy too.

Sealed reserves coordinator UIDs/GIDs `50000–50015` and temporary worker UIDs/GIDs
`51000–51031`; both ranges fit the provider's 65536-ID Sysbox mapping. Sealed
checks the actual UID/GID maps and runs a trusted namespace probe before service
admission. A denied probe reports `unsupported` with the concrete provider
failure. There is no launch without the required namespaces.

Worker `/proc` is empty. A fresh procfs mount is denied below Docker's inherited
masked proc mounts, while mounting the parent's procfs would expose owner
processes. Programs requiring procfs, including `/dev/fd` paths pointing into it,
must account for this constraint. Root and `/dev` are read-only; worker `/tmp`
and `/work` use separate 64 MiB tmpfs mounts.

This namespace profile alone does not provide hard aggregate resource limits.
Production admission also needs a provider-delegated cgroup v2 boundary with
enforced `memory.max`, `memory.swap.max`, `pids.max`, and complete descendant
cleanup. That boundary must stay within the billed sandbox's aggregate limits.
Rlimits are additional process limits, not substitutes for aggregate cgroups.
The shared host directory used for `/run` sockets also needs a bounded backing
filesystem or a transport that does not grant workers writable host storage.
No cgroup delegation or bounded host filesystem is created by this JSON file.

## Verification and remaining qualification

The namespace tests passed locally on Linux arm64, kernel `6.10.14-linuxkit`,
bubblewrap `0.12.0`, with only the six capabilities above, normal Docker proc
masks and this explicit profile. They exercise concurrent temporary workers,
private input delivery, read-only code/root, empty procfs, private networking,
tmpfs sizes, cancellation and cleanup. Node `24.22.1` also ran and launched a
child process inside this boundary. The same probe correctly reported
unsupported under the unchanged Moby default profile. The UID-map test uses a
65536-ID mapping fixture.

Separate real-kernel cgroup tests and the public DSH/paid-MCP integration also
passed after a trusted local bootstrap prepared the finite billed-parent/pool
layout, then dropped to exactly the same six capabilities (`CapEff=CapBnd=0xeb`)
and seccomp mode 2. They exercised aggregate descendant OOM, PID exhaustion and
cleanup of a child in another session. See [CGROUPS.md](CGROUPS.md). Bootstrap
setup privileges were absent when service code ran.

These results do **not** constitute actual Sysbox, production amd64, AppArmor,
or hosted provider validation. Those checks remain required on the target runner
before enabling production service admission. This file does not claim a running
production service or a production deployment.

For a local reproduction, start in `sealed/` and set `SEALED_TEST_IMAGE` to a
Linux test image containing Go 1.24, bubblewrap 0.12.0 and Python 3:

```sh
docker run --rm --cap-drop ALL \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
  --cap-add SETUID --cap-add SETGID --cap-add KILL \
  --security-opt seccomp="$PWD/isolation/docker-bubblewrap-seccomp.json" \
  -v "$PWD":/src -w /src \
  -e SEALED_SERVICE_TESTS=1 -e SEALED_ISOLATION_EXPECT=supported \
  "${SEALED_TEST_IMAGE:?set a Linux test image}" \
  sh -c 'go build -o /usr/local/bin/sealed-service-launcher ./cmd/service-launcher && go test ./internal/servicehost -count=1'
```

For the denial check, use the unchanged Moby v27.5.1 default profile, set
`SEALED_ISOLATION_EXPECT=unsupported`, omit `SEALED_SERVICE_TESTS`, and run
`go test ./internal/servicehost -run 'TestServiceIdentityFitsProviderUIDMap|TestProviderNamespacePolicy|TestServiceAdmissionReportsUnsupportedProvider' -count=1`.
The supported namespace run does not prove that a provider supplied the separate
production cgroup and filesystem prerequisites.
