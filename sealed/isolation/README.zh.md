# 托管服务的进程限制

[English](README.md)

sealed 在 agent 自己的沙箱里运行每个托管服务进程（`internal/servicesandbox`，由
`sealed-service-launcher` 启动），不用 namespace，不需要 provider 六项以外的 capability，
也不改 provider：

| 机制 | 限制内容 |
| --- | --- |
| 服务身份 | 独立的 UID/GID，从 20000–64999 随机抽取；无附加组；no-new-privs |
| rlimit | 虚拟内存、每个身份的进程和线程数（`RLIMIT_NPROC`）、256 描述符、单文件 64 MiB、不生成 core；由 launcher 离开 root 之后设置 |
| Landlock（ABI 6 及以上） | 只读/执行镜像系统目录、版本目录和租用的运行包；读三个 `/etc` 条目；无害的 `/dev` 节点；只在私有 run 目录建 socket；只写私有 `$HOME` 和 `$TMPDIR`；`/proc` 不可读；TCP bind/connect 被拒；抽象 Unix socket 和信号限于自身域 |
| seccomp 过滤器 | 不能建 inet、netlink、packet socket；不能用 io_uring |
| `oom_score_adj` 1000 | 内核 OOM 先杀服务进程，再轮到 sealed 或 owner Harness；Landlock 使其无法调低 |
| 资源监视 | sealed 每 500 ms 读该身份的驻留内存、每 2 s 读私有目录，超限即杀掉该身份 |
| 按身份清理 | launcher 切换到该身份给它的所有进程发信号，root 再确认一个不剩 |

进程对外只有 sealed 交给它的 Unix socket：出网代理（只到发布的主机，以 CONNECT 隧道）和
每个任务的模型代理。它的 loopback 是整个容器共用的（owner 也在上面），所以不在上面监听。

## 在 dev runner 上的实测（2026-11-13）

在 runner 镜像同款基础（`docker:28.5.2-dind-alpine3.22`）的 Sysbox 容器里，按 runner 的
沙箱参数起容器（runc、六项 capability、Docker 默认 seccomp、`--init`、内存上限）。内核
6.17.0-42-generic，Landlock ABI 7，容器内 AppArmor 为 `unconfined`。UID 51000、no-new-privs
的进程执行 `landlock_restrict_self` 之后：

- 被拒：规则外所有人可读的文件、`/etc`、写 `/tmp`、别的进程的 `/proc`、调低自己的
  `oom_score_adj`、连 127.0.0.1 和外网的 TCP、域外的抽象 Unix socket、给域外同 UID 进程发信号；
- 允许：自己的工作目录、启动子进程；
- 规则外权限 0666 的路径型 Unix socket 仍能连上：Landlock 不管路径型 socket，只能靠文件权限。

进程给自己装的 seccomp 过滤器拒绝 `socket(AF_INET/AF_INET6)`，允许 `AF_UNIX`。`RLIMIT_NPROC`
到上限即不能再 fork；以该身份执行 `kill(-1, SIGKILL)` 能清掉它的全部进程，包括开了新会话、
已挂到 init 下的进程。两个容器之间，同一 UID 的计数是合并的（一个容器里有 11 个进程时，另一个
在上限 8 下一个也开不出来），而 `kill(-1)` 不会跨容器。所以身份是随机抽取，不用固定编号。

容器里的 root 在那里同样不豁免 `RLIMIT_NPROC`（它不是初始用户命名空间的 root），而且计数覆盖
整个 runner 的所有 root 进程：在 launcher 离开 root 之前设上限时，launcher 开不出新线程
（`failed to create new OS thread`，EAGAIN，2026-11-14）。所以 launcher 在切换身份之后才设置
全部 rlimit。

探测程序和结果：0g-tapp-ops 的 `deploy/dev/landlock-probe-20261113/` 和
`deployments/sandbox.md`（2026-11-13 15:55）。

## 这个设计的边界

- 内存和磁盘是监视，不是内核限额：两次读取之间的瞬时峰值可能越过，硬上限是沙箱自身的内存限制。
- 进程能看到系统的进程号（信号和 `/proc` 被拒）。
- 不同沙箱的身份碰巧相同时，共用 `RLIMIT_NPROC` 计数。

## 测试

`SEALED_LANDLOCK_TESTS=1 go test ./internal/servicesandbox` 和
`SEALED_SERVICE_TESTS=1 SEALED_ISOLATION_EXPECT=supported go test ./internal/servicehost`，
以 root 在带六项 capability 和 Docker 默认 seccomp 的容器里、在 Landlock ABI 6 及以上的内核上运行
（dev runner）。在没有 Landlock 的内核上，`SEALED_ISOLATION_EXPECT=unsupported` 检查接纳会明确拒绝。
