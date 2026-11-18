# 托管 MCP 服务

owner Harness 用 DSH 原生 MCP 客户端发现 sealed 私有 sign socket 上的
`seal_service_publish/start/stop/list/logs`。配套 `publish-mcp-service` skill
负责应用流程；sealed 只提供进程原语，不管理雇主账号、业务任务或付款。

## 发布

manifest 必填 `id`、`command`、`args`、`files`；可选 `worker`、`description`、
`env`、`network`、`egress_hosts`、`memory_mb`、`resident_memory_mb`、`processes`、`inference_budget`、
`request_timeout_seconds`、`agent_data`。文件是 `{path,data}`，即相对路径和标准 base64。
`env` 是持久保存的**公开配置**。command 指定镜像中的可信解释器，例如 node 或 python3；代码只在
降权后执行。源码和依赖是版本目录里的普通只读文件，该目录就是程序的工作目录（用相对路径引用）；root 不解压、不处理符号链接、不安装包。

程序监听 `$MCP_SOCKET`（在它私有的 run 目录里），公开入口是
`<sandbox-url>/api/mcp/<id>`，由 `/hello` 宣告为 `kind: "hosted"`，并附它运行的 `version`
和审计路径 `release`（`?sealed-release=1`），保留原始请求路径。沿用现有公网
8080，不新增端口或管理入口。

简单无状态服务不填 `worker`，每个 POST 启动临时沙箱。异步任务声明
`worker:{command,args}`：sealed 启动**隔离的协调进程**（coordinator）处理 MCP，带服务私有、持久化的
`$HOME` 和仅限该服务的进程控制 socket；每个任务再启动**独立临时 worker**，用私有的临时
`$HOME`、`$TMPDIR`。协调进程属于应用代码，拿不到 owner Harness、签名或凭证权限。
worker 不继承控制 socket，不能选择跳过隔离；执行证明将结果绑定到真实的临时 worker。

start 开放请求并启动声明的协调进程；轮询 list 到 running 后仍须验证实际 MCP 行为，
这不是业务健康检查。stop 关闭请求并终止协调进程和 worker，更新前必须 stop。
version 是规范化 manifest 的 SHA-256。发送凭证前，获取
`GET /api/mcp/<id>?sealed-release=1`：sealed 即使在服务停止时也返回
`{version,manifest,canonical_manifest}`，不执行服务代码。canonical_manifest 是规范化
JSON 原始字节的 base64，其 SHA-256 必须等于 version。通过已验证的 AgenticID/TEE
连接核验这个有限响应的 ServeProof，检查代码，再固定该版本。保留八个源码版本，回滚时
重新发布旧 bundle。

root registry 绑定 owner/identity，链上启动校验通过后才恢复已开启的服务。
协调进程可重启并读取自己的业务数据库；**任务进程、私有输入和临时目录不恢复**。
中断执行只报告、不自动重跑。owner 转移永久关闭 manager 及原有 owner gate。
stop/start 保留协调进程的 `$HOME`，但它不是 iData、上链数据或跨沙箱备份。

限制：16 个服务，每版 512 文件、解码后 16 MiB，发布 JSON 24 MiB，registry 8 MiB。
内部 MCP 请求上限 1 MiB；更大 manifest 可从本地 JSON 文件经 `$SEAL_SIGN_SOCK`
向 `/service-host` POST `{action:"publish",manifest:...}`。GET 列表，
start/stop/logs 接收 id。不公开管理接口。logs 为空：协调进程和请求进程的 stdout/stderr 丢弃，
任务 stdout 只私下交给所属应用，不成为 owner 可读日志。

## 隔离与网络

每个服务进程都用自己的服务身份运行，从容器 UID 20001–64999 中随机抽取（20000 留给隔离
探测）；provider 的 UID/GID 映射必须覆盖 20000–64999。内核按 UID 在同一 runner 的所有沙箱之间合计 `RLIMIT_NPROC`
（在 dev runner 上实测），固定编号会让一个沙箱的进程卡住另一个沙箱。可信 launcher 清除
附加组、切换 UID/GID、启用 no-new-privs、把 `oom_score_adj` 设为 1000、nice 设为 19（`RLIMIT_NICE`
为 0，无法调高优先级），再用 Landlock（ABI 6 及以上）和 seccomp 过滤器限制进程，然后才执行解释器。
服务进程与 sealed、owner 共用沙箱的 CPU 配额：在 dev runner 上，自开会话、nice 19 的进程和
nice 0 的进程分到的 CPU 一样多，所以 nice 在那里不能给 sealed 或 owner 留出 CPU
（isolation/README.zh.md）：

- Landlock 只允许它读取并执行镜像的系统目录、自己的版本和租用的 Harness 运行包，读取
  `/etc/resolv.conf`、`/etc/hosts`、`/etc/ssl/certs`、`/etc/ssl/openssl.cnf`（该文件存在却读不到时 Node 会直接退出）和 sealed 的网络适配器，使用 `/dev/null`、`zero`、`full`、
  `random`、`urandom`，在私有 run 目录里列目录、建 socket、删除条目（不能建文件或链接，
  sealed 要连的 socket 不能被换成链接），只在自己私有的 `$HOME` 和 `$TMPDIR` 里写（以及建文件、链接、socket，
  执行其中的程序）。`/proc` 不可读，TCP bind/connect 被拒绝，抽象 Unix socket 和信号只能
  到达它自己的进程。
- seccomp 过滤器只允许 `AF_UNIX` 协议族的 socket；拒绝 io_uring、System V IPC、POSIX
  消息队列和内核 keyring（这些对象比进程活得久，或会留给下一个用同一 UID 的任务）以及所有
  x32 调用；拒绝带 `CLONE_PARENT` 的 `clone`（子进程会挂到 sealed 下，sealed 不回收它，它会
  变成僵尸一直占该身份的计数），`clone3` 返回 ENOSYS，libc 随即使用 `clone`；`fallocate` 返回
  EOPNOTSUPP，占用磁盘只能靠写入，而写入受单文件上限约束。

owner 家目录/状态、sealed 状态、sign/reveal socket、其他 worker 的文件都访问不到。sealed
交给进程的 Unix socket 归它的身份所有；其他路径型 socket 仍按文件权限控制，Landlock 不管。
每次启动均检查当前已验证 Harness 包仍在允许列表中，并锁定包，直到任务全部进程退出才允许清理。
该包只读，位于 `$HARNESS_RUNTIME_ROOT`，不共享常驻 Harness 的可写差分和对话，也不要求镜像带 base 包。
内核没有 Landlock ABI 6、或容器的 seccomp 策略不允许 Landlock 时，明确报告 unsupported。
provider 不需要任何改动：dev runner（内核 6.17、Landlock ABI 7、Sysbox 内的 Docker 28.5.2、
六项 capability、Docker 默认 seccomp）全部满足，见 [isolation/README.zh.md](isolation/README.zh.md)。

默认 `network:"none"`；`network:"egress"` 必须指定 1–32 个 `host:port`
格式的 egress_hosts，主机名最多 253 个字符。私有 Unix HTTP/CONNECT 代理（每个身份最多 64 个连接）只允许这些目标，并拒绝私网、
loopback、link-local、metadata IP，包括 DNS 解析结果。服务进程没有自己的网络 socket：
sealed 在容器 loopback（owner 也共用）上的监听端口它连不到，因为 inet socket 和 TCP connect
都被拒绝。sealed 把自己的网络适配器（`internal/servicenet`，编进 sealed 程序，启动时写到
`/var/lib/sealed-service-programs/<id>/.servicenet`，属 root、只读）加载进每个 Node 和 Python 服务进程：Node 用 `--import`，Python 用 `PYTHONPATH`，排在
manifest 自己的 `PYTHONPATH` 之前。适配器把运行时常用的 TCP 客户端以 CONNECT 隧道经 Unix 代理发出，
主机名交给代理解析：Node 中是所有 `node:net`/`node:tls` 连接，即 `fetch`、`node:http`/`https`、http2
及基于它们的客户端（axios、got、ws）；Python 中是 `socket.create_connection`（urllib、http.client）、
urllib3（requests）、asyncio（httpx、websockets）和 aiohappyeyeballs（aiohttp）。主机 `seal-model`
走模型代理，地址在 `$SEAL_MODEL_URL`（`http://seal-model/model`）。自行创建 TCP socket 的客户端、
用 `-S`、`-I` 或 `-E` 运行的 Python，以及其他运行时，除非自己连接 Unix 代理，否则没有出口。
适配器只是便利，不是边界。不继承 owner 凭证代理。

单进程 rlimit：虚拟地址空间（默认 8192 MiB，128–16384）、每个身份的进程和线程数（默认 64，
1–256；命令或 worker 是 `node` 时至少 16，发布时检查）、256 描述符和单文件 64 MiB。所有服务进程合计最多 2048 个进程和线程：
每个运行中的请求、执行和协调进程按自己的 `processes` 上限占用额度，额度不够的启动会被拒绝。
单次请求 worker（对没有 worker 的服务的每个 POST）最多占 32 个 worker 名额中的 16 个、上述额度中的
1024 个，协调进程派出的执行总有空间。
sealed 每 500 ms 读取该身份的驻留内存（resident_memory_mb，默认 256 MiB，64–4096），每 2 s
统计私有 `$HOME`、`$TMPDIR` 和 run 目录下实际分配的块，每个条目至少按 4 KiB 计（临时 worker
合计 128 MiB；协调进程合计 576 MiB，其 `$HOME` 是持久业务状态），超过即杀掉该身份。同样每 2 s，
任务目录所在文件系统剩余空间不足 1 GiB 或剩余 inode 不足 65536 个时，sealed 停掉所有服务进程
并拒绝新的启动；这也会回收遍历看不到的空间，比如已删除但仍打开的文件。从同一条线起，owner 的
状态显示磁盘警告（[ARCHITECTURE.zh.md](ARCHITECTURE.zh.md) §9，sandbox 磁盘）。这些是监视，不是内核
限额：两次读取之间的瞬时峰值可能越过。不驻留在任何进程里的内存（写入但未映射的 memfd、管道
缓冲）只受沙箱内存上限约束。内存紧张时内核 OOM 先杀服务进程（`oom_score_adj` 1000），Landlock
使它们无法调低。清理时
launcher 切换到该身份给它的所有进程发信号（子进程改不了身份，重新挂靠或新会话都逃不掉），
再由 root 确认一个不剩，才复用身份和解除运行包锁定。sealed 启动时先停掉所有服务身份的进程：
容器里上一个 sealed 可能留下了进程，因为 loader 只有作为 PID 1 时才会清理它的后代，而 runner
用 `--init` 启动沙箱。清不掉的身份被隔离：从此不分配给任何任务，存在它上面的协调进程会报告无法启动的原因。
期望运行的协调进程退出或启动失败后，2 s 后重试，启动后一分钟内反复失败时间隔加倍、最多 60 s；
此时状态为 `restarting`，错误里是原因（超限、`readiness_timeout`、`coordinator_exit` 或接纳错误）；
内核或容器不具备隔离条件时为 `unsupported`；身份的清理还没得到证明时为 `quarantined`。服务被停用后
结束的协调进程，其服务状态为 `stopped`。
这不提供独立 CPU 分配或磁盘配额，仍受外围沙箱限制。worker 在 EOF、terminate、超时（默认 300 秒，1–3600）、stop 或转移时结束。
断线会终止单次请求 worker；异步任务不随提交它的 HTTP 连接结束，继续由协调进程管理。

0g-harness/dsh 只保留 `/api/mcp/` 给托管服务，该路径在 hosting 不可用时也不能回退到旧后端。
其他旧 `/api/*` 服务和注册接口继续可用；其他适配器保留原有路由行为，包括自身的 `/api/mcp/...`。
provider 可以在创建沙箱时另配端口，服务发布本身不授予此权限。

## agent 数据

版本可以用 `agent_data: {persona, skills, public_memory}`（布尔值，至少一项）申请
agent 自己数据的只读副本。这项授权是 manifest 的一部分，会改变 `version`，审计版本的调用方
看得到。之后每个临时 worker（一次性请求或一次执行）都能在 `$SEAL_AGENT_DATA` 下读到：

- `persona/APPEND_SYSTEM.md`：agent 的人设；
- `skills/`：它的 skills，按文件展开（skill 目录会解包）；
- `memory-public/`：agent 的公开长期记忆，即已提交的 `memory-public/` 角色整份（每条记忆一个文件，
  加上角色自己的 `MEMORY.md` 索引）。私有的 `memory/` 角色从不放进副本；
- `versions.json`：每类数据的版本。

这些 worker 还会拿到 `SEAL_OWNER`，即本容器服务的 NFT owner（小写）。每条记忆写明确认它的 owner
（`trusted_by`）；由之前的 owner 确认的记忆是继承来的，只作参考，不能作为行动依据。

每类都是链上提交的版本，内容和提交时一样：已清除 sealed 持有的凭据值和已知格式的秘密，绝不是
尚未提交的修改。sealed 在自己的状态目录里保留各个已提交版本，在 agent 的文件正好是已提交版本时
生成（每次确认提交之后，以及启动时）。如果某个版本本容器从未在文件对应时生成过、而文件已经改了，
需要它的 worker 会被拒绝（`start_failed`），直到 agent 下一次提交；从未提交的角色是空的。
副本在每个 worker 启动前单独准备，归 root 所有，在 Landlock 授权下只读，随任务目录一起删除：
之后的提交不会改变正在运行的任务读到的内容，任务也改不了自己的副本。协调进程拿不到。
owner 的私人记忆、对话、agent 的 inbox/outbox 和家目录、owner 凭据和 sign socket 都碰不到。

版本是 `{kind, content_hash, data_hash, snapshot_hash, files}`：`content_hash` 和
`data_hash` 是角色在链上的固定值（已提交明文的 sha256，以及 AgenticID 条目里的 0G 存储根；
从未提交时为空；公开记忆就是 `memory-public/` 角色自己的值），`snapshot_hash` 是任务能读到的
文件按路径排序后 `path NUL sha256 LF` 的 sha256。调用方拿链上固定值对照链；`snapshot_hash`
指向同一批文件、逐个文件哈希，持有明文文件的人不需要 iData manifest 格式就能核对。执行状态用
`agent_data` 带上这些版本，执行证明也带上：调用方事后能确认是哪份代码加哪份数据得出的结果。
Harness 的 `runServiceAgent({agentData: true})` 会把人设、skills 和公开记忆（索引加只读工具
`agent_memory_read`）装进任务的 agent 循环，并把每条继承来的记忆标成仅供参考。

### v1 限制

- **只给临时 worker。** 版本的协调进程拿不到 agent 数据。
- **只从 agent 的文件生成。** sealed 不从 0G 存储下载已提交版本。如果本容器从未生成过已提交版本、
  而文件已经改过（例如重启时还有未提交的修改），需要它的 worker 会被拒绝，直到下一次提交。
- **公开按文件夹划分。** 记忆在 `memory-public/` 里并已提交，才算公开；挂载的是整份已提交的文件夹，
  不能逐条选择。0g-harness 只在 owner 明确要求时写入这里：记忆提取只写私有记忆，整理只在各自的
  文件夹内进行，从不在两个文件夹之间移动记忆。
- **可信度由读取方判断。** 继承来的记忆也会挂载。sealed 传入 `SEAL_OWNER`；读取方如果不拿它和
  `trusted_by` 比较，就会把所有记忆一样对待。
- **skills 全给或不给。** `skills` 授权全部已提交的 skills，不能逐个选择。
- **人设整份给出。** `persona` 授权整份已提交的 `APPEND_SYSTEM.md`，每个版本单独的授权是唯一的控制。
- **`snapshot_hash` 依赖签名。** 调用方可以拿 `content_hash` 和 `data_hash` 对照链上，但没有明文
  就算不出 `snapshot_hash`（iData 在 0G 存储上是加密的），只能依赖 agentSeal 对执行证明的签名。

## 私有输入和进程控制

调用者明确同意程序读取明文时，可经 HTTPS 发送
`X-Seal-Runtime-Input: base64(JSON string map)`，解码后最多 16 KiB。
必须同时发送 `X-Seal-Service-Version: <已核验版本>`；版本改变就在交付前返回 409。
请求接纳和一次性交接消费时均检查版本，stop/publish/start 不能把待交接凭证转交给新版代码。
这是 sealed 扩展，不是 MCP sampling/OAuth，不能记入 HTTP 日志。应用处理请求前删除
私有 header 和调用者伪造的交接引用。单次请求服务从匿名 stdin 读 map；协调进程只拿
一次性随机引用，必须在响应前启动选中的 worker。只有该 worker 从 stdin 收到与公开
输入分别分帧的私有 map；未使用引用随请求结束清理。

不增加雇主 vault、reveal 审批、续期/writeback、私有输入持久化。值不经过 owner 常驻
Harness，不自动进模型消息，不注册到 owner credential scrubber。任务代码可能泄露
自己读取的内容，调用者必须信任代码；隔离不能向代码作者隐藏输入。检查源码并将交付绑定到
已核验版本，让这个信任关系明确。ServeProof 不绑定此 header。协调进程的持久 `$HOME` 在各个
发布版本之间保留同一身份和目录，所以 owner 之后发布的版本能读到之前版本存在里面的内容（比如
收费服务的任务输入和结果）；私有输入从不存进去。调用者的信任要覆盖之后会读取这些状态的版本，
不只是自己核验过的那一个。

## 任务的模型调用通道

可选 `inference_budget:{calls,input_bytes,output_tokens}` 为每个临时 worker 开独立私有
模型 socket。调用次数 1–64，总输入 1 KiB–16 MiB（单次 512 KiB），单次输出上限 1–8192 token；
上游失败也计数。worker 生命周期取消调用，单次响应流限 8 MiB。
socket 固定 owner 当前解析的 HTTPS provider/model，真实模型密钥只在 sealed 内注入。
不提供凭证查询、签名、跟随重定向或任意上游路由；协调进程拿不到该 socket。
`network:"none"` 也可使用。sealed 设置 SEAL_MODEL_ID、SEAL_MODEL_API，其网络适配器在 Node 和 Python 中设置 SEAL_MODEL_URL；
Harness mountServiceModel 使用公开占位符，拿不到真实密钥。其他语言可对私有 Unix socket 发 HTTP。
这些限制约束请求和请求的输出上限，不等于实际 token 用量或货币支出额度；定价、退款仍属于应用。

只有协调进程拿到 `$SEAL_EXEC_SOCKET`：向私有 `/executions` POST
`spawn/get/find/wait/terminate/release/capabilities`。sealed 固定 service scope。spawn 接收
key、base64 公开 input、可选 input_handle，状态用随机 handle 查询。key 格式
`<unix-ms>-<16..48 random URL-safe characters>`。同 key/输入/代码的并发重试
只返回一次执行，修改输入/代码冲突。find 只读找回丢失回执，不启动任何进程。
十分钟前的 key 即使已 GC，也不能启动新执行。每个执行有两个文件：不可变的 key 记录（service、key、
输入 hash、版本、时间、UID），在 worker 启动前同步写入磁盘；以及每次变化都重写的状态记录。
key 记录同步之前崩溃不留记录，也没有任何程序运行过。状态记录不可用或不存在时，key 记录把该执行恢复为
interrupted（状态文件读不出来时 reason 为 record_lost，没有状态文件时为 sealed_restarted），而不是"从未运行"，
所以该 key 永远不会再次运行。控制 socket 最多 64 个连接，请求体须在 30 秒内送达。

capabilities 不带其他字段，返回 `{"launch":true|false,"receipts":true|false}`。receipts：
现在退出码为 0 的执行能否拿到签名证明（见执行证明）。launch：sealed 自己为服务进程做的准备
（隔离探测、剩余空间、已验证运行包的列表检查与锁定）现在能否成功。收费服务在扣款前先查询，
两项都为 true 才接活。同时到达的查询共用一次准备，结果复用 5 秒。

执行的 state 取值：starting（已预留，worker 还没运行）、running、exited（退出码 0）、
failed、timed_out（reason 为 deadline）、cancelled（terminated）、interrupted
（sealed_restarted：运行中 sealed 重启；record_lost：状态记录读不出来）和 quarantined（sealed 还不能证明该身份的进程已全部
退出，身份保持预留）。reason 写明原因：start_failed、process_exit、output_limit、
memory_limit、disk_limit、sandbox_disk_low、cleanup_failed、resource_cleanup_failed、
metadata_write_failed。reason 为 start_failed 且没有 exit_code，表示 worker 从未运行：
state 为 failed，清理得到证明之前为 quarantined。failed 且 reason 为 process_exit、exit_code 为 0，
表示 worker 以 0 退出，但它留下的进程在 250 ms 后仍占着它的输出。

公开输入上限 512 KiB，stdout 每次 1 MiB、全局 32 MiB，每次读最多 64 KiB。
记录最多 1024 条，退出十分钟后回收，但在其 key 仍可能被接受时不回收。启动时读不了的文件
移到一边（`.bad-<name>`）并记日志，不会让托管服务不可用。输出仅内存保存，sealed 重启会丢失；应用必须在
release 前持久保存。release 后元数据/去重保留至 GC。wait 超时不取消执行。
元数据只含 hash、版本、UID、时间、退出事实、证明，不含输入/stdout，也不定义雇主归属、
业务进度或付款状态。

## 执行证明与 HTTP 归属

成功任务获得 agentSeal 在独立 EIP-191 version-0x00 域下签署的
`0G.SealedExecution.v1` 证明，前提是 sealed 能签：需要 agent 密钥、链上锚定的 AgenticID
serve-proof validator（`VERIFIED_FEEDBACK_ADDR`）、agent id、链和身份注册合约。没有 validator 时
该容器整个生命周期都不签证明，所以收费服务（收费对应带证明的结果）在 capabilities 报告
`receipts:false` 时拒绝接活。证明绑定 chain/registry/agent、validator、UID、源码版本、
公开输入/stdout SHA-256、任务读到的 agent 数据版本（`execution.agent_data`）、限额和实际隔离配置。isolation.worker_runtime_hash 是
worker 真正锁定使用的 Harness 包；外层 harness_hash 属于常驻分层 runtime，可能不同。
分层运行时还无法确定当前 hash 时不签执行证明，等待版本身份就绪。
owner 的 personal_sign/EIP-712/交易工具不能签这个摘要，没有任意内容的证明签名 API。

Harness `verifyExecutionReceipt` 校验签名、可信身份、隔离、公开输入及完整 stdout，
再从这个 stdout 解析结果；传入 `agentData` 时还核对任务读到的 agent 数据版本。信任锚应来自验证过的 AgenticID/TEE 连接，不能仅信证明自报
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
SEALED_LANDLOCK_TESTS=1（internal/servicesandbox）测限制本身：文件、`/proc`、`oom_score_adj`、nice、run 目录里的链接、
inet/UDP、SMC 和 vsock socket、System V IPC、消息队列、keyring、`fallocate`、带 `CLONE_PARENT` 的 `clone`、
对域外的信号和抽象 socket，以及按身份清理。
SEALED_SERVICE_TESTS=1 测真实限制、身份、stdin、去重、限额、取消、原子私有输入交接、反复 Stop/Start 和回收。
SEALED_LOOP_TESTS=1 加测公开 DSH/tool 链路和完整收费 MCP 链路：真实 SDK/签名、钱包
隔离、并发重试、私有 stdin、进度、取消、证明校验/拒绝篡改及广播前/后的结算响应丢失。
链和 facilitator 为本地模拟，不花资金、不证明已真实部署。本地测试挂载配套源码 checkout
（包括 test/helpers）到 /opt/0g-harness/<hash>，以及测试 base 指针和 Node；生产接纳不读该测试指针。
这些测试要以 root 在 Landlock ABI 6 及以上的内核上、在带 provider 六项 capability 和 Docker 默认 seccomp 的容器里运行；只通过特权容器测试不能证明 provider 兼容。
