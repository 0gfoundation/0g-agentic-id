# 服务 cgroup 委派

托管服务代码必须有内核 cgroup-v2 内存和 PID 限额。sealed 不会把单进程
`prlimit`、进程组信号、RSS 轮询或可写目录当作这些保证。提供商未委派下述
结构时，`servicecgroup.New()` 返回 `ErrUnsupported`，服务准入必须失败关闭。

提供商必须把 sealed supervisor 放入 root 拥有的 `0g-supervisor` cgroup，
并在同一个计费沙箱父 cgroup 下预建同级 `0g-service-jobs` 池。
`/proc/self/cgroup` 必须指向 supervisor 叶节点。cgroup-v2 固定挂载于
`/sys/fs/cgroup`；owner 设置不能选择其他挂载点或池。提供商负责把这个父节点
关联到沙箱计费和容器边界。

```
计费沙箱父节点                       有限 memory.max 和 pids.max
├── 0g-supervisor                    包含 sealed supervisor
└── 0g-service-jobs                  有限的全池 memory.max 和 pids.max
    ├── job-<sealed 生成的 key>       coordinator 或临时进程树
    └── job-<sealed 生成的 key>       另一 coordinator 或进程树
```

父节点和池必须是 domain cgroup，提供 `memory`、`pids` controller，并已在
`cgroup.subtree_control` 中启用。池自身没有直属进程。池的有限内存/PID 限额
必须小于父节点，给 supervisor 留出余量。控制文件和经过的每级 cgroup 目录
必须由 root 拥有，且 group/other 不可写。sealed 打开该结构时不跟随链接或
下级挂载点；不会自行建立提供商结构，也不会迁移自身进程来绕过探测失败。
服务进程拿不到 cgroup 文件系统挂载或 supervisor 控制描述符。

准入前，探测创建随机空子节点，写入并读回 `memory.max`、
`memory.swap.max=0`、`pids.max` 和 `memory.oom.group=1`，打开可写
`cgroup.procs`，实际执行 `cgroup.kill`，观察子树为空后删除。controller
缺失、只读委派、无限额、进程归属不符、符号链接或内核操作不支持都会拒绝
准入。要求内核支持 `openat2` 路径约束和 `cgroup.kill`，不存在更弱的回退。

`Pool.Acquire` 为每个 sealed 生成的任务标识建立全新子节点，设好限额后才
提供迁移描述符。可信 launcher 在降权、启动服务代码之前，通过该描述符写入
自身 PID（`0`），随后关闭描述符。fork、exec、更换进程组和会话的后代仍继承
归属。内存限制覆盖整个进程树，禁用 swap，PID controller 同时统计进程和线程。
池限额额外约束所有并行服务树，不能代替各树自身的请求限额。

清理写入 `cgroup.kill=1`，等待内核 `cgroup.events` 的 `populated=0` 后才
删除节点。超时或失败保留 lease 供重试。调用者必须隔离其 UID 和服务/准入槽，
直到同一 lease 被确认为空并移除。仅发出信号或父进程退出都不足以完成清理。
`Pool.Close` 会拒绝仍有活跃 lease 的池。

生产探测不会增加 capability，也不改变 seccomp/AppArmor 策略。目前尚未证明
沙箱提供商部署已提供该委派。本地特权 Docker fixture 可在可信初始化阶段准备
结构，再把运行时降到受限 capability；这只能证明内核行为，不能证明提供商已
支持。

在 Linux 上运行：

```
go test ./internal/servicecgroup
# 仅在可信提供商/初始化已建立精确结构后：
SEALED_CGROUP_TESTS=1 go test -count=1 ./internal/servicecgroup
```

受开关控制的测试覆盖两个单独低于内存上限的后代触发总量 OOM、后代耗尽 PID
controller，以及清理另起会话的子进程。未显式启用时会跳过。普通文件系统 fixture
只验证拒绝、读回和清理逻辑，不证明内核强制限额。

内核语义以 [Linux cgroup-v2 官方文档](https://docs.kernel.org/admin-guide/cgroup-v2.html) 为准。
