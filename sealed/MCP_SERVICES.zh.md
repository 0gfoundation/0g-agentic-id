# 托管 MCP 服务

owner Harness 用 DSH 原生 MCP 客户端发现 sealed 私有 sign socket 上的
`seal_service_publish/start/stop/list/logs`。配套 `publish-mcp-service` skill
负责应用流程；sealed 只提供进程原语，不管理雇主账号、业务任务或付款。

## 发布

manifest 必填 `id`、`command`、`args`、`files`；可选 `worker`、`description`、
`env`、`network`、`egress_hosts`、`memory_mb`、`processes`、
`request_timeout_seconds`。文件是 `{path,data}`，即相对路径和标准 base64。
`env` 是持久保存的**公开配置**。command 指定镜像中的可信解释器，例如 node；代码只在
降权后执行。源码和依赖以普通只读文件挂载到 `/app`；root 不解压、不处理符号链接、不安装包。

程序监听 `$MCP_SOCKET`（`/run/service.sock`），公开入口是
`<sandbox-url>/api/mcp/<id>`，由 `/hello` 宣告，保留原始请求路径。沿用现有公网
8080，不新增端口或管理入口。

简单无状态服务不填 `worker`，每个 POST 启动临时沙箱。异步任务声明
`worker:{command,args}`：sealed 启动**隔离的服务进程**处理 MCP，带服务私有、持久化的
`/work` 和仅限该服务的进程控制 socket；每个任务再启动**独立临时 worker**，用 tmpfs
`/work`、`/tmp`。服务进程属于应用代码，拿不到 owner Harness、签名或凭证权限。
worker 不继承控制 socket，不能选择跳过隔离；执行证明将结果绑定到真实的临时 worker。

start 开放请求并启动声明的服务进程；轮询 list 到 running 后仍须验证实际 MCP 行为，
这不是业务健康检查。stop 关闭请求并终止服务进程和 worker，更新前必须 stop。
version 是规范化 manifest 的 SHA-256，可在验证结果时固定。保留八个源码版本，回滚时
重新发布旧 bundle。

root registry 绑定 owner/identity，链上启动校验通过后才恢复已开启的服务。
服务进程可重启并读取自己的业务数据库；**任务进程、私有输入和 tmpfs 不恢复**。
中断执行只报告、不自动重跑。owner 转移永久关闭 manager 及原有 owner gate。
stop/start 保留应用 `/work`，但它不是 iData、上链数据或跨沙箱备份。

限制：16 个服务，每版 512 文件、解码后 16 MiB，发布 JSON 24 MiB，registry 8 MiB。
内部 MCP 请求上限 1 MiB；更大 manifest 可从本地 JSON 文件经 `$SEAL_SIGN_SOCK`
向 `/service-host` POST `{action:"publish",manifest:...}`。GET 列表，
start/stop/logs 接收 id。不公开管理接口。logs 为空：服务/请求进程 stdout/stderr 丢弃，
任务 stdout 只私下交给所属应用，不成为 owner 可读日志。

## 隔离与网络

服务进程用宿主 UID 200000–200015；活跃临时 worker 使用不同 UID 210000–210031，
所有服务合计最多 32 个。可信 launcher 清除附加组并切换 UID/GID 后才启动 bubblewrap。
程序有独立 PID、mount、user、IPC、UTS、**network** namespace，无 capabilities，
启用 no-new-privs。只挂载镜像运行时、不可变源码和自己的 work/run；owner 家目录/状态、
sealed 状态、sign/reveal socket、其他 worker 文件均不可见。镜像基础 Harness 只读
挂载为 `$HARNESS_RUNTIME_ROOT`，不共享常驻 Harness 的可写差分和对话。
namespace 不可用就拒绝运行。

默认 `network:"none"`；`network:"egress"` 必须指定 1–32 个 `host:port`
格式的 egress_hosts。私有 Unix HTTP/CONNECT 代理只允许这些目标，并拒绝私网、
loopback、link-local、metadata IP，包括 DNS 解析结果。不能使用宿主网络。
Node 自动加载镜像代理引导（Node >=24.14）；其他语言需明确支持 Unix 代理。
不使用代理的代码没有对外路由，也不继承 owner 凭证代理。

rlimit 限虚拟地址空间（默认 8192 MiB，128–16384）、每 UID 进程数（默认 64，
1–256）、256 描述符、单文件 64 MiB。这不是总 CPU、RSS、磁盘配额，外围限制仍由沙箱
提供。worker 在 EOF、terminate、超时（默认 300 秒，1–3600）、stop 或转移时结束。
断线会终止单次请求 worker；异步任务不随提交它的 HTTP 连接结束，继续由服务进程管理。

0g-harness/dsh 的公开 `/api/*` 必须匹配托管服务。旧 loopback 发布被拒绝，
service-host 初始化失败时也不能回退，framework 路由不能重新打开入口。
其他适配器保持旧行为。provider 可以在创建沙箱时另配端口，服务发布本身不授予此权限。

## 私有输入和进程控制

调用者明确同意程序读取明文时，可经 HTTPS 发送
`X-Seal-Runtime-Input: base64(JSON string map)`，解码后最多 16 KiB。
这是 sealed 扩展，不是 MCP sampling/OAuth，不能记入 HTTP 日志。应用处理请求前删除
私有 header 和调用者伪造的交接引用。单次请求服务从匿名 stdin 读 map；服务进程只拿
一次性随机引用，必须在响应前启动选中的 worker。只有该 worker 从 stdin 收到与公开
输入分别分帧的私有 map；未使用引用随请求结束清理。

不增加雇主 vault、reveal 审批、续期/writeback、私有输入持久化。值不经过 owner 常驻
Harness，不自动进模型消息，不注册到 owner credential scrubber。任务代码可能泄露
自己读取的内容，调用者必须信任代码；隔离不能向代码作者隐藏输入。ServeProof 不绑定此 header。

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
worker 真正使用的镜像基础 Harness；外层 harness_hash 属于常驻分层 runtime，可能不同。
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

模板验证 exact EVM EIP-3009 付款授权，执行隔离任务，**先持久保存结果再结算**，通过
外部 facilitator 结算，用 RPC 独立核对直接调用 token 的交易后开放结果。重试复用原授权；
结算未知时暂不交付，按 payer/nonce 链上对账，不自动另授权扣款。
定价、鉴权、付款/结果、facilitator 设置均属应用；sealed 不增加钱包、托管或 x402 API。
接入见配套 Harness 的 skills/publish-mcp-service/paid-service.md。

x402 **不是付款和交付的跨系统原子公平交换**。保存结果让丢失响应可在沙箱及存储仍可用时
重试；扣款后存储整体丢失仍需应用恢复/退款政策，执行证明和 HTTP proof 都不能消除此限制。

## 验证

以 root 分别在没有/有 agent 用户时运行，设置 SEALED_PRIVSEP_TESTS=1。
SEALED_SERVICE_TESTS=1 测真实 namespace、UID、stdin、去重、限额、取消和回收。
SEALED_LOOP_TESTS=1 加测公开 DSH/tool 链路和完整收费 MCP 链路：真实 SDK/签名、钱包
隔离、并发重试、私有 stdin、进度、取消、证明校验/拒绝篡改及结算响应丢失。
链和 facilitator 为本地模拟，不花资金、不证明已真实部署。特权 Linux 测试容器需挂载
配套源码 checkout（包括 test/helpers）到 /opt/0g-harness/<hash>，以及 base 指针和 Node。
