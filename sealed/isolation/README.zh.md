# 托管服务的命名空间策略

[English](README.md)

`docker-bubblewrap-seccomp.json` 是供 runner 审核采用的 sealed 临时服务进程策略。
它基于 [Moby v27.5.1 默认配置](https://github.com/moby/moby/blob/v27.5.1/profiles/seccomp/default.json)，
遵循 [Apache 2.0 许可证](LICENSE.moby)，增加以下四条规则：

| 系统调用 | 额外允许的操作 |
| --- | --- |
| `clone` | 精确标志 `0x7c020011`：user、mount、PID、network、IPC、UTS 命名空间，以及 `SIGCHLD` |
| `clone` | 精确标志 `0x7e020011`：上述命名空间，加上 cgroup 命名空间 |
| `unshare` | 精确标志 `CLONE_NEWUSER`（`0x10000000`），用于 bubblewrap 最后的权限分离 |
| `mount`、`umount2`、`pivot_root` | 设置命名空间内的文件系统；内核的 capability 检查仍然有效 |

配置的 SHA256 为
`add283d4e086d3198b77d6e8baf56151ab20e2d4a739dfe26e5b942a591e4225`。
新增 `clone` 规则的参数布局面向 Linux amd64/arm64；其他架构需要单独审核和验证。

## Provider 约定

runner 必须在创建支持托管服务的 sealed 容器时应用审核后的策略。
Docker CLI 接受 `--security-opt seccomp=<file>`；使用 Docker Go API 的 runner
应将 `seccomp=` 加 JSON 内容写入 `HostConfig.SecurityOpt`。
在 sealed 内加载本文件不能放宽继承的 seccomp 过滤器。
更换策略也需要重建现有容器；只重启容器内的现有进程不会改变过滤器。

保留容器的六项 capability：`CHOWN`、`DAC_OVERRIDE`、`FOWNER`、`SETUID`、
`SETGID`、`KILL`，保留 Sysbox runner 隔离边界和 Docker 的 proc 屏蔽挂载。
不要使用 `privileged`、`SYS_ADMIN`、unconfined seccomp/AppArmor 配置或宿主
Docker socket。如果 LSM 另外禁止非特权 user namespace，provider 还需要提供
相应的受限 LSM 策略。

sealed 为 coordinator 保留 UID/GID `50000–50015`，为临时 worker 保留
UID/GID `51000–51031`；两组都落在 provider 的 Sysbox 65536-ID 映射范围内。
sealed 会检查实际 UID/GID 映射，并在接纳服务前运行可信的命名空间探针。
探针被拒绝时，服务报告 `unsupported` 和具体 provider 错误；不会取消必要的
命名空间后继续启动。

worker 的 `/proc` 为空。在 Docker 继承的 proc 屏蔽挂载之下，新挂载 procfs
会被拒绝；挂载父进程的 procfs 则会暴露 owner 进程。依赖 procfs 的程序，
包括通过 `/dev/fd` 指向 procfs 的访问，需要适应该限制。根目录和 `/dev`
只读；worker 的 `/tmp` 与 `/work` 分别使用 64 MiB tmpfs。

仅使用此命名空间策略不能提供严格的任务总资源上限。生产环境还需要 provider
委派 cgroup v2 边界，实际执行 `memory.max`、`memory.swap.max`、`pids.max`，
并完整清理所有后代进程。任务必须始终处于计费 sandbox 的总资源上限之内。
rlimit 是额外的进程限制，不能替代聚合 cgroup 限制。用于 `/run` socket 的共享
宿主目录还需要有容量上限的底层文件系统，或改用不向 worker 开放宿主可写存储的
传输方式。本 JSON 文件不会创建 cgroup 委派或有容量上限的宿主文件系统。

## 已验证范围与剩余验证

本地命名空间测试在 Linux arm64、内核 `6.10.14-linuxkit`、bubblewrap
`0.12.0` 下通过，仅授予上述六项 capability，保留 Docker 默认 proc 屏蔽挂载，
并显式使用本策略。测试覆盖并发临时 worker、私密输入投递、代码和根目录只读、
空 procfs、私有网络、tmpfs 容量、取消和清理。Node `24.22.1` 也在该边界内
运行并启动了子进程。使用未修改的 Moby 默认策略时，同一探针正确报告不支持。
UID-map 测试使用 65536-ID 映射样例。

另行通过了真实内核 cgroup 测试和公开 DSH/收费 MCP 联合测试：本地可信引导先准备
有限额的计费父组和服务池，然后降到完全相同的六项 capability（CapEff=CapBnd=0xeb）
和 seccomp mode 2，才运行测试及服务代码。覆盖后代总内存 OOM、进程数耗尽和另开
会话的子进程清理，见 [CGROUPS.zh.md](CGROUPS.zh.md)。服务代码运行时已无引导阶段权限。

这些结果**不代表**已在实际 Sysbox、生产 amd64、AppArmor 或托管 provider 上通过验证。
在目标 runner 开启生产服务接纳前，仍需完成这些验证。本文件不声称已有生产服务或已完成生产部署。

本地复现时，进入 `sealed/`，将 `SEALED_TEST_IMAGE` 设置为包含 Go 1.24、
bubblewrap 0.12.0 和 Python 3 的 Linux 测试镜像：

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

验证拒绝行为时，改用未修改的 Moby v27.5.1 默认策略，设置
`SEALED_ISOLATION_EXPECT=unsupported`，不设置 `SEALED_SERVICE_TESTS`，运行
`go test ./internal/servicehost -run 'TestServiceIdentityFitsProviderUIDMap|TestProviderNamespacePolicy|TestServiceAdmissionReportsUnsupportedProvider' -count=1`。
命名空间测试通过，并不能证明 provider 已提供生产环境另外要求的 cgroup 和文件系统条件。
