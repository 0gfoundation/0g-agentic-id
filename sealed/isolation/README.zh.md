# 托管服务的进程限制

[English](README.md)

sealed 在 agent 自己的沙箱里运行每个托管服务进程（`internal/servicesandbox`，由
`sealed-service-launcher` 启动），不用 namespace，不需要 provider 六项以外的 capability，
也不改 provider：

| 机制 | 限制内容 |
| --- | --- |
| 服务身份 | 独立的 UID/GID，从 20001–64999 随机抽取（20000 留给探测）；无附加组；no-new-privs |
| rlimit | 虚拟内存、每个身份的进程和线程数（`RLIMIT_NPROC`）、256 描述符、单文件 64 MiB、不生成 core；由 launcher 离开 root 之后设置 |
| CPU 优先级 | nice 19，`RLIMIT_NICE` 为 0：服务进程无法调高自己的优先级；它们与 sealed、owner Harness 共用沙箱的 CPU 配额（见下面的实测） |
| 进程额度 | 所有服务进程合计最多 2048 个进程和线程，每次启动按 manifest 的 `processes` 占用 |
| Landlock（ABI 6 及以上） | 只读/执行镜像系统目录、版本目录和租用的运行包；读三个 `/etc` 条目；无害的 `/dev` 节点；在私有 run 目录里只能列目录、建 socket 和删除条目；只在私有 `$HOME` 和 `$TMPDIR` 下有完整权限（写、建、执行）；`/proc` 不可读；TCP bind/connect 被拒；抽象 Unix socket 和信号限于自身域 |
| seccomp 过滤器 | 只能建 `AF_UNIX` 协议族的 socket；不能用 io_uring、System V IPC、POSIX 消息队列、内核 keyring 和任何 x32 调用；不能带 `CLONE_PARENT` 调 `clone`，`clone3` 返回 ENOSYS，libc 随即使用 `clone`；`fallocate` 返回 EOPNOTSUPP |
| `oom_score_adj` 1000 | 内核 OOM 先杀服务进程，再轮到 sealed 或 owner Harness；Landlock 使其无法调低 |
| 资源监视 | sealed 每 500 ms 读该身份的驻留内存、每 2 s 统计私有目录（`$HOME`、`$TMPDIR`、run 目录；每个条目至少按 4 KiB 计）下实际分配的块，超限即杀掉该身份；任务目录所在文件系统剩余不足 1 GiB 或不足 65536 个 inode 时停掉所有服务进程并拒绝新的启动 |
| 按身份清理 | launcher 切换到该身份给它的所有进程发信号，root 再确认一个不剩。sealed 启动时对每个还有进程的服务身份都这样清理一遍，清不掉的身份从此不分配给任何任务 |

进程对外只有 Unix socket：sealed 交给它的那些（出网代理，只到发布的主机，以 CONNECT 隧道；
每个任务的模型代理），以及文件权限本身允许它连接的路径型 socket，Landlock 不管这类 socket。sealed 自己在容器 loopback（owner 也共用）上的监听端口它连不到，因为 inet
socket 和 TCP connect 都被拒绝。

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

容器里的 root 同样不豁免 `RLIMIT_NPROC`（它不是初始用户命名空间的 root），而且计数覆盖整个
runner 的所有 root 进程：上限为几百的 root 进程开不出新线程（`failed to create new OS thread`，
EAGAIN，2026-11-13）。launcher 在切换身份之后设置全部 rlimit。

探测程序和结果：0g-tapp-ops 的 `deploy/dev/landlock-probe-20261113/` 和
`deployments/sandbox.md`（2026-11-13 15:55）。

以 nobody 身份、不装 sealed 的过滤器、在带 runner 沙箱参数的容器里（2026-11-14）：

- `socket(AF_SMC)` 成功：inet、netlink、packet 以外的协议族可用，过滤器只允许 `AF_UNIX`。
- `kernel.shm_rmid_forced` 为 0：System V 共享内存段在进程退出后仍然存在，且不计入任何进程的
  驻留内存，过滤器拒绝 System V IPC。
- x32 调用让进程收到 SIGSYS 而结束（Docker 默认策略）；sealed 的过滤器也拒绝 x32 调用。
- 容器的 `pids.max` 为 `max`：进程额度是所有服务进程合计的上限。
- 根文件系统是 ext 文件系统上的 overlay，Daytona 的 runner 在这种文件系统上不给单个沙箱设
  容量（只在 xfs 上设），`statfs` 报的是整块盘：剩余空间下限保护这块盘。
- CPU 配额为 1 个 CPU 时（2026-11-15），`kernel.sched_autogroup_enabled` 为 1；自开会话（launcher
  启动服务的方式）的 nice 19 忙循环在 4 秒内分到的 CPU 和 nice 0 的一样多（比值 1.056）：在那里
  nice 19 不能让服务进程让出沙箱的 CPU。

## 这个设计的边界

- 内存和磁盘是监视，不是内核限额：两次读取之间的瞬时峰值可能越过，硬上限是沙箱自身的内存限制。
  不驻留在任何进程里的内存（写入但未映射的 memfd、管道缓冲）只受这个上限约束；内核 OOM 先杀
  服务进程。已删除但仍打开的文件占用的磁盘不按身份统计（root 没有 `CAP_SYS_PTRACE`，读不了
  别的身份的描述符），由剩余空间下限兜底。
- CPU 是共用的：服务进程、sealed 和 owner 共用一份沙箱 CPU 配额，sealed 不为自己或 owner 留出
  任何部分；nice 19 只在内核对它们应用 nice 时才排序，dev runner 的实测没有看到这一点。
- 进程能看到系统的进程号（信号和 `/proc` 被拒）。
- 不同沙箱的身份碰巧相同时，共用 `RLIMIT_NPROC` 计数。

## 测试

`SEALED_LANDLOCK_TESTS=1 go test ./internal/servicesandbox` 和
`SEALED_SERVICE_TESTS=1 SEALED_ISOLATION_EXPECT=supported go test ./internal/servicehost`，
以 root 在带六项 capability 和 Docker 默认 seccomp 的容器里、在 Landlock ABI 6 及以上的内核上运行
（dev runner）。在没有 Landlock 的内核上，`SEALED_ISOLATION_EXPECT=unsupported` 检查接纳会明确拒绝。
