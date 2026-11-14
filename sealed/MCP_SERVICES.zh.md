# 托管 MCP 服务

owner Harness 用 DSH 原生 MCP 客户端发现 sealed 私有 sign socket 上的
`seal_service_publish/start/stop/list/logs`。配套 `publish-mcp-service` skill
负责应用流程；sealed 只提供进程原语，不管理雇主账号、业务任务或付款。

## 发布

manifest 必填 `id`、`command`、`args`、`files`；可选 `worker`、`description`、
`env`、`network`、`egress_hosts`、`memory_mb`、`resident_memory_mb`、`processes`、`inference_budget`、
`request_timeout_seconds`。文件是 `{path,data}`，即相对路径和标准 base64。
`env` 是持久保存的**公开配置**。command 指定镜像中的可信解释器，例如 node；代码只在
降权后执行。源码和依赖是版本目录里的普通只读文件，该目录就是程序的工作目录（用相对路径引用）；root 不解压、不处理符号链接、不安装包。

程序监听 `$MCP_SOCKET`（在它私有的 run 目录里），公开入口是
`<sandbox-url>/api/mcp/<id>`，由 `/hello` 宣告，保留原始请求路径。沿用现有公网
8080，不新增端口或管理入口。

简单无状态服务不填 `worker`，每个 POST 启动临时沙箱。异步任务声明
`worker:{command,args}`：sealed 启动**隔离的服务进程**处理 MCP，带服务私有、持久化的
`$HOME` 和仅限该服务的进程控制 socket；每个任务再启动**独立临时 worker**，用私有的临时
`$HOME`、`$TMPDIR`。服务进程属于应用代码，拿不到 owner Harness、签名或凭证权限。
worker 不继承控制 socket，不能选择跳过隔离；执行证明将结果绑定到真实的临时 worker。

start 开放请求并启动声明的服务进程；轮询 list 到 running 后仍须验证实际 MCP 行为，
这不是业务健康检查。stop 关闭请求并终止服务进程和 worker，更新前必须 stop。
version 是规范化 manifest 的 SHA-256。发送凭证前，获取
`GET /api/mcp/<id>?sealed-release=1`：sealed 即使在服务停止时也返回
`{version,manifest,canonical_manifest}`，不执行服务代码。canonical_manifest 是规范化
JSON 原始字节的 base64，其 SHA-256 必须等于 version。通过已验证的 AgenticID/TEE
连接核验这个有限响应的 ServeProof，检查代码，再固定该版本。保留八个源码版本，回滚时
重新发布旧 bundle。

root registry 绑定 owner/identity，链上启动校验通过后才恢复已开启的服务。
服务进程可重启并读取自己的业务数据库；**任务进程、私有输入和临时目录不恢复**。
中断执行只报告、不自动重跑。owner 转移永久关闭 manager 及原有 owner gate。
stop/start 保留服务进程的 `$HOME`，但它不是 iData、上链数据或跨沙箱备份。

限制：16 个服务，每版 512 文件、解码后 16 MiB，发布 JSON 24 MiB，registry 8 MiB。
内部 MCP 请求上限 1 MiB；更大 manifest 可从本地 JSON 文件经 `$SEAL_SIGN_SOCK`
向 `/service-host` POST `{action:"publish",manifest:...}`。GET 列表，
start/stop/logs 接收 id。不公开管理接口。logs 为空：服务/请求进程 stdout/stderr 丢弃，
任务 stdout 只私下交给所属应用，不成为 owner 可读日志。

## 隔离与网络

每个服务进程都用自己的服务身份运行，从容器 UID 20001–64999 中随机抽取（20000 留给隔离
探测）；provider 的 UID/GID 映射必须覆盖 20000–64999。内核按 UID 在同一 runner 的所有沙箱之间合计 `RLIMIT_NPROC`
（在 dev runner 上实测），固定编号会让一个沙箱的进程卡住另一个沙箱。可信 launcher 清除
附加组、切换 UID/GID、启用 no-new-privs、把 `oom_score_adj` 设为 1000，再用 Landlock
（ABI 6 及以上）和 seccomp 过滤器限制进程，然后才执行解释器：

- Landlock 只允许它读取并执行镜像的系统目录、自己的版本和租用的 Harness 运行包，读取
  `/etc/resolv.conf`、`/etc/hosts`、`/etc/ssl/certs`，使用 `/dev/null`、`zero`、`full`、
  `random`、`urandom`，在私有 run 目录里创建 socket（只能建 socket，sealed 要连的 socket
  不能被换成链接），只在自己私有的 `$HOME` 和 `$TMPDIR` 里写（以及建文件、链接、socket，
  执行其中的程序）。`/proc` 不可读，TCP bind/connect 被拒绝，抽象 Unix socket 和信号只能
  到达它自己的进程。
- seccomp 过滤器只允许 `AF_UNIX` 协议族的 socket；拒绝 io_uring、System V IPC、POSIX
  消息队列和内核 keyring（这些对象比进程活得久，或会留给下一个用同一 UID 的任务）以及所有
  x32 调用；`fallocate` 返回 EOPNOTSUPP，占用磁盘只能靠写入，而写入受单文件上限约束。

owner 家目录/状态、sealed 状态、sign/reveal socket、其他 worker 的文件都访问不到。sealed
交给进程的 Unix socket 归它的身份所有；其他路径型 socket 仍按文件权限控制，Landlock 不管。
每次启动均检查当前已验证 Harness 包仍在允许列表中，并锁定包，直到任务全部进程退出才允许清理。
该包只读，位于 `$HARNESS_RUNTIME_ROOT`，不共享常驻 Harness 的可写差分和对话，也不要求镜像带 base 包。
内核没有 Landlock ABI 6、或容器的 seccomp 策略不允许 Landlock 时，明确报告 unsupported。
provider 不需要任何改动：dev runner（内核 6.17、Landlock ABI 7、Sysbox 内的 Docker 28.5.2、
六项 capability、Docker 默认 seccomp）全部满足，见 [isolation/README.zh.md](isolation/README.zh.md)。

默认 `network:"none"`；`network:"egress"` 必须指定 1–32 个 `host:port`
格式的 egress_hosts。私有 Unix HTTP/CONNECT 代理只允许这些目标，并拒绝私网、
loopback、link-local、metadata IP，包括 DNS 解析结果。服务进程没有自己的网络 socket；
它的 loopback 是整个容器共用的（owner 也在上面），所以不在上面监听。Node 自动加载镜像
引导（Node >=24.14），把 `fetch` 以 CONNECT 隧道经 Unix 代理发出；其他语言需自行连接
Unix 代理。不继承 owner 凭证代理。

单进程 rlimit：虚拟地址空间（默认 8192 MiB，128–16384）、每个身份的进程和线程数（默认 64，
1–256，`node` 至少 16）、256 描述符和单文件 64 MiB。所有服务进程合计最多 2048 个进程和线程：
每个运行中的请求、执行和服务进程按自己的 `processes` 上限占用额度，额度不够的启动会被拒绝。
sealed 每 500 ms 读取该身份的驻留内存（resident_memory_mb，默认 256 MiB，64–4096），每 2 s
统计私有 `$HOME` 和 `$TMPDIR` 下实际分配的块（临时 worker 两者合计 128 MiB；服务进程合计
576 MiB，其 `$HOME` 是持久业务状态），超过即杀掉该身份。同样每 2 s，任务目录所在文件系统
剩余空间不足 1 GiB 时，sealed 停掉所有服务进程并拒绝新的启动；这也会回收遍历看不到的空间，
比如已删除但仍打开的文件。这些是监视，不是内核限额：两次读取之间的瞬时峰值可能越过。内存
紧张时内核 OOM 先杀服务进程（`oom_score_adj` 1000），Landlock 使它们无法调低。清理时
launcher 切换到该身份给它的所有进程发信号（子进程改不了身份，重新挂靠或新会话都逃不掉），
再由 root 确认一个不剩，才复用身份和解除运行包锁定。sealed 启动时先停掉所有服务身份的进程：
容器里上一个 sealed 可能留下了进程，因为 loader 只有作为 PID 1 时才会清理它的后代，而 runner
用 `--init` 启动沙箱。这不提供独立 CPU 分配或磁盘配额，仍受外围沙箱限制。worker 在 EOF、terminate、超时（默认 300 秒，1–3600）、stop 或转移时结束。
断线会终止单次请求 worker；异步任务不随提交它的 HTTP 连接结束，继续由服务进程管理。

0g-harness/dsh 只保留 `/api/mcp/` 给托管服务，该路径在 hosting 不可用时也不能回退到旧后端。
其他旧 `/api/*` 服务和注册接口继续可用；其他适配器保留原有路由行为，包括自身的 `/api/mcp/...`。
provider 可以在创建沙箱时另配端口，服务发布本身不授予此权限。

## 私有输入和进程控制

调用者明确同意程序读取明文时，可经 HTTPS 发送
`X-Seal-Runtime-Input: base64(JSON string map)`，解码后最多 16 KiB。
必须同时发送 `X-Seal-Service-Version: <已核验版本>`；版本改变就在交付前返回 409。
请求接纳和一次性交接消费时均检查版本，stop/publish/start 不能把待交接凭证转交给新版代码。
这是 sealed 扩展，不是 MCP sampling/OAuth，不能记入 HTTP 日志。应用处理请求前删除
私有 header 和调用者伪造的交接引用。单次请求服务从匿名 stdin 读 map；服务进程只拿
一次性随机引用，必须在响应前启动选中的 worker。只有该 worker 从 stdin 收到与公开
输入分别分帧的私有 map；未使用引用随请求结束清理。

不增加雇主 vault、reveal 审批、续期/writeback、私有输入持久化。值不经过 owner 常驻
Harness，不自动进模型消息，不注册到 owner credential scrubber。任务代码可能泄露
自己读取的内容，调用者必须信任代码；隔离不能向代码作者隐藏输入。检查源码并将交付绑定到
已核验版本，让这个信任关系明确。ServeProof 不绑定此 header。

## 任务的模型调用通道

可选 `inference_budget:{calls,input_bytes,output_tokens}` 为每个临时 worker 开独立私有
模型 socket。调用次数 1–64，总输入 1 KiB–16 MiB（单次 512 KiB），单次输出上限 1–8192 token；
上游失败也计数。worker 生命周期取消调用，单次响应流限 8 MiB。
socket 固定 owner 当前解析的 HTTPS provider/model，真实模型密钥只在 sealed 内注入。
不提供凭证查询、签名、跟随重定向或任意上游路由；服务管理进程拿不到该 socket。
`network:"none"` 也可使用。Node 引导设置 SEAL_MODEL_URL、SEAL_MODEL_ID、SEAL_MODEL_API；
Harness mountServiceModel 使用公开占位符，拿不到真实密钥。其他语言可对私有 Unix socket 发 HTTP。
这些限制约束请求和请求的输出上限，不等于实际 token 用量或货币支出额度；定价、退款仍属于应用。

只有服务进程拿到 `$SEAL_EXEC_SOCKET`：向私有 `/executions` POST
`spawn/get/find/wait/terminate/release`。sealed 固定 service scope。spawn 接收
key、base64 公开 input、可选 input_handle，状态用随机 handle 查询。key 格式
`<unix-ms>-<16..48 random URL-safe characters>`。同 key/输入/代码的并发重试
只返回一次执行，修改输入/代码冲突。find 只读找回丢失回执，不启动任何进程。
十分钟前的 key 即使已 GC，也不能启动新执行。

公开输入上限 512 KiB，stdout 每次 1 MiB、全局 32 MiB，每次读最多 64 KiB。
记录最多 1024 条，退出十分钟后回收。输出仅内存保存，sealed 重启会丢失；应用必须在
release 前持久保存。release 后元数据/去重保留至 GC。wait 超时不取消执行。
元数据只含 hash、版本、UID、时间、退出事实、证明，不含输入/stdout，也不定义雇主归属、
业务进度或付款状态。

## 执行证明与 HTTP 归属

成功任务获得 agentSeal 在独立 EIP-191 version-0x00 域下签署的
`0G.SealedExecution.v1` 证明，绑定 chain/registry/agent、validator、UID、源码版本、
公开输入/stdout SHA-256、限额和实际隔离配置。isolation.worker_runtime_hash 是
worker 真正锁定使用的 Harness 包；外层 harness_hash 属于常驻分层 runtime，可能不同。
分层运行时还无法确定当前 hash 时不签执行证明，等待版本身份就绪。
owner 的 personal_sign/EIP-712/交易工具不能签这个摘要，没有任意内容的证明签名 API。

Harness `verifyExecutionReceipt` 校验签名、可信身份、隔离、公开输入及完整 stdout，
再从这个 stdout 解析结果。信任锚应来自验证过的 AgenticID/TEE 连接，不能仅信证明自报
地址；需要时固定源码/runtime hash。它证明机制和字节，不保证业务正确性、私有输入、付款
或独立内核，不是 feedback registry ServeProof 或上链交易。已有 ServeProof 摘要不变。
有限 JSON 保留普通 HTTP proof，MCP SSE 标记 stream-unsigned 即时转发，删除上游伪造证明。

## 应用流程与 x402

Harness 提供 servePaidService、ExecutionClient、runServiceWorker、钱包访问 token、
买方 fetch 和执行证明校验。普通 MCP 工具 submit/status/result/cancel 按钱包鉴权，
保存结果/进度并保证幂等。worker 可运行业务代码或新 DSH loop，不依赖 MCP Tasks、
sampling，也不强制雇主交模型 API key。

模板验证 exact EVM EIP-3009 付款授权，经外部 facilitator 结算，**独立确认规范链上回执和确认深度后
才启动 worker**。单凭 facilitator 返回成功不够。支持直接 token 调用和保守核验的同价 wrapper 批量，
无法无歧义核验的批次需运营对账。结算未知时不启动工作，按同一 payer/nonce 对账，安全重试复用原签名。
对账后，带私有输入的任务可能需要重发同一请求和凭证 header；查询进度不会在缺凭证时暗中启动任务。
免费报价、待付款、已付款记录和活跃 worker 分池限额。付款后取消或失败不自动退款，owner 必须制定恢复/
退款规则。成功输出持久保存，供重试领取。
定价、鉴权、付款/结果、facilitator 设置均属应用；sealed 不增加钱包、托管或 x402 API。
接入见配套 Harness 的 skills/publish-mcp-service/paid-service.md。

x402 **不是付款和交付的跨系统原子公平交换**。保存结果让丢失响应可在沙箱及存储仍可用时
重试；扣款后存储整体丢失仍需应用恢复/退款政策，执行证明和 HTTP proof 都不能消除此限制。

## 验证

以 root 分别在没有/有 agent 用户时运行，设置 SEALED_PRIVSEP_TESTS=1。
SEALED_LANDLOCK_TESTS=1（internal/servicesandbox）测限制本身：文件、`/proc`、`oom_score_adj`、run 目录里的链接、
inet/UDP socket、对域外的信号和抽象 socket，以及按身份清理。
SEALED_SERVICE_TESTS=1 测真实限制、身份、stdin、去重、限额、取消、原子私有输入交接、反复 Stop/Start 和回收。
SEALED_LOOP_TESTS=1 加测公开 DSH/tool 链路和完整收费 MCP 链路：真实 SDK/签名、钱包
隔离、并发重试、私有 stdin、进度、取消、证明校验/拒绝篡改及广播前/后的结算响应丢失。
链和 facilitator 为本地模拟，不花资金、不证明已真实部署。本地测试挂载配套源码 checkout
（包括 test/helpers）到 /opt/0g-harness/<hash>，以及测试 base 指针和 Node；生产接纳不读该测试指针。
这些测试要以 root 在 Landlock ABI 6 及以上的内核上、在带 provider 六项 capability 和 Docker 默认 seccomp 的容器里运行；只通过特权容器测试不能证明 provider 兼容。
