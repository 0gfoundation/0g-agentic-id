# AgenticID 信任模型

一个 agent 的身份如何在密码学上锚定到一段经过远程认证的代码上，每条
`serve-proof` 实际证明了什么、又刻意不证明什么，以及声誉系统如何补
上这道缝。

这是整个项目里最容易被误读的部分。在你开口争辩"但要是 owner 干了
X 怎么办"之前，先把这篇读一遍。

---

## TL;DR

> **sealed 保证的是 *形式* 信任。声誉保证的是 *语义* 信任。两者合
> 起来 = 可用的 agent。**

- `serve-proof` 签出的 8 条 envelope 断言**都是**由
  `agent_seal_priv` 密码学绑定的；但成立条件不一样：**Group A（身份
  层 3 条）**只要 priv 不出 TEE 就无条件成立，**Group B（内容层 5
  条）**额外需要"签名能力不被 agent 滥用"这一前提，靠 **agent 钢印**
  兜底 —— 见正文 [承重墙](#这-8-条保证的承重墙是-agent-钢印)。
- `serve-proof` **不**证明响应**内容正确**、agent **自主**、或者
  owner 没有通过 prompt **操纵**过 agent。
- 内容层的信任被委托给一个链上的**声誉系统**：行为不当的 agent 会
  积累低分、被 verifier 过滤掉；行为一致的 agent 随时间累积信任。

如果你看到 `serve-proof` 有效但内容是谎言，这**不是** sealed 的
bug —— 这是 agent 的质量问题，由声誉系统来表达。

---

## 根本不变量：owner 永远不持有 `agent_seal_priv`

本文档里所有东西，都压在**一条**承重属性上：

> **`agent_seal_priv` 只存在于 sealed 容器的运行时内存里，位于由 TEE
> 加密的 RAM 页面中。owner —— 以及 host（Daytona、attestor、任何
> 在底层机器上拿到 root 的人）—— 永远无法把它取出来。**

把这条不变量拿走，剩下的全塌：

- 如果 owner 能读到私钥，他们可以在线下签出伪造的 `serve-proof`，
  填任意的 `task_hash` / `data_hashes` ——
  根本不需要任何真实请求到达 sealed
- schema 绑定的签名 endpoint 变得无关紧要 —— owner 直接签他们想签
  的任何东西
- 所有钱包保护变得无关紧要 —— owner 一次线下签名就掏空两个钱包
- 声誉问责变得无关紧要 —— owner 可以伪造签名，把任意行为归到任意
  agent 头上

所以信任模型生死系于**私钥留在 TEE 内存里**这一条。

实现侧是如何维持这条的：

| 边界 | 机制 |
|---|---|
| host 读不到容器内存 | TDX 硬件内存加密 + attestation |
| 磁盘持久化是加密的 | `agent_seal_priv` 从不以明文写盘；只 provision 到内存 |
| openclaw 子进程拿不到 | spawn.go 用显式 whitelist（`PATH`、`HOME`（agent 自己的家目录 `/home/agent`）、`OPENCLAW_STATE_DIR` 和 `OPENCLAW_HOME`（框架目录树的绝对路径及其上级目录，非机密）、provider 的 `*_API_KEY`、`AGENT_PUBLIC_URL`、`SEAL_SIGN_SOCK`、`AGENT_SEAL`）构造子进程 env，不继承 bootstrap 的 env——密钥材料永不穿越子进程边界 |
| 存储上传不让它离开进程 | `dataplane.Upload` 在 sealed 进程内通过 0g-storage-client Go SDK 上传（`internal/dataplane/upload.go`），SDK 的交易签名器直接由 sealed 已持有的密钥构造，所以密钥从不交给任何子进程 —— 不进参数列表（`/proc/<pid>/cmdline` 对所有本地用户可读，降权后的 agent 也不例外），不进环境变量，不经文件描述符，也不落文件。blob 从内存直接交给 SDK（不写临时文件）。本次上传一旦结束（比如在 90s 截止时被放弃），SDK 就不能再用这把密钥签名或发送交易：签名器拒绝签名，fullnode 客户端也拒绝发送，provider 的每次重试都一样；只有截止那一刻已经在线路上的发送仍可能到达节点，这和 CLI 在截止时被杀掉的情形相同。代价是体积和故障隔离。SDK 往这个进程里多链接了约 360 个非标准库包（大部分是 go-ethereum 的 node 栈；细节见 `QUIRKS.md`），并经由它们带进了标准库的 `net/http/pprof` 和 `expvar`（见下一行）；`TestLinkedPackages_Reviewed` 同时钉住这些非标准库包和它们直接导入的标准库包。上传现在也和 sealed 共用一个进程：SDK 自己起的 goroutine 里一旦 panic，或上传期间内存耗尽，结束的是 sealed（PID 1），连同容器和 agent 一起，而以前只会结束一次 CLI 运行（`runBounded` 只 recover 调用 SDK 的那个 goroutine；见 `QUIRKS.md`）。钉住的 SDK 版本还会在 2 MiB 以上 blob 的提交每次被回滚、或回执查询失败后，留下一个永久阻塞的 goroutine，以前 CLI 运行结束退出时会把它一并带走；`Upload` 给它们能累积的数量设了上限（见 `QUIRKS.md`）。下载仍经 `privsep.RootCommand`（只在仅 root 可写的 `PATH` 目录中解析）运行 0g-storage-client CLI，下载不涉及密钥；构建它的那些镜像（`Dockerfile`、`images/{hermes,prime,dsh,sealed}`）把它装到 `/usr/local/bin`，基础镜像 `images/openclaw` 不带。由 `internal/dataplane` 的测试钉住：`Upload` 不起任何子进程（一道源码检查：上传路径上不出现任何启动进程的 API，`internal/privsep` 的命令构造函数也算在内；再加 root 侧的结构测试不给 `Upload` 列任何可运行的二进制）、源码里出现启动进程 API 的依赖是一份审查过的固定清单、SDK 接线与 CLI 一致、签名和发送随上传结束而停止 |
| 没有 HTTP endpoint 暴露它 | sealed 的 mux 只提供派生的签名和公开地址，从不返回 priv 字节。profile 和进程变量也不对外提供：被链接进来的库（`net/http/pprof`、`expvar`）在 init 时注册到 `http.DefaultServeMux` 上的 `/debug/pprof/*` 和 `/debug/vars` 路由，sealed 启动时通过替换这个 mux 一并丢掉（`defaultmux.go`） |
| provisioning 链路不会泄漏它 | attestor 用 ECIES 把 `agent_seal_priv` 加密到临时 `container_pubkey`；只有持有配对 `container_privkey` 的一方能解开。这对 keypair **不是**在本容器内生成的 —— 是 0g-Sandbox 封装层生成、把私钥那一半作为 `SANDBOX_SEAL_KEY` 注入进来，Phase 0 只做一件事：把它跟 `attestation.pubkey` 互证（`internal/config/config.go:180-188`）。因此 sandbox 封装层在这一跳里属于 TCB；这一跳之所以还站得住，靠的是 attestor 只会加密到由 TappRegistry 注册过的 sandbox node key 所签 envelope 携带的那个 pubkey。provision 成功后 sealed 会把密钥字节清零、并 unset 掉环境变量，但代码里记着一条 `/proc/<pid>/environ` 注意事项（`config.go:227-243`）。完整流程 + 各道闸门见下文 [信任链](#信任链agent_seal_priv-如何到达-tee) |

任何对 sealed 的未来变更，只要可能跨越这条边界 —— 即使是间接的
（例如把 priv 字节写日志、通过 debug endpoint 暴露、把它放进与
子进程共享的内存）—— 都是**关键安全回归**。这是唯一不能弯的规矩。

---

## Habitat 与 tool sandbox

本文档（以及整个项目）用两个词区分两种沙盒：

- **habitat（栖居沙盒）**：agent 所栖居的那个被远程认证的 TEE 容器
  —— 唯一被度量的边界，持有 `agent_seal_priv`、运行 sealed 和框架
  进程，也是每条 attestation 和 `serve-proof` 断言所**指涉**的对象。
  一个 agent 有且只有一个 habitat。它是 agent 的身体，不是 agent
  使用的东西。
- **tool sandbox（工具沙盒）**：边界**之外**的一次性算力（e2b 式的
  执行沙盒、租来的 VM、任何外部运行时），agent 把它当工具消费：
  不可信代码在那里跑、在那里炸、用完即弃。一个 agent 可以用任意
  多个。

两者的分界线就是"什么可被证明"：

> **只有在 habitat 内执行的 work 才是可证明的。** attestation 和
> `serve-proof` 只覆盖被度量的边界，边界之外一概不覆盖。从 tool
> sandbox 拿回来的任何东西都是不可信输入 —— 只有当 agent 在自己的
> habitat 内对它审议过、并（签名）发出自己的陈述时，它才获得归因。
> 工具沙盒的结果是 agent 引用的证据，永远不是平台出具的证明。

推论，双向都成立：任何秘密不得离开 habitat 进入 tool sandbox
（`agent_seal_priv` 的任何派生物、iData 明文、推理 key 都不行）；
从工具沙盒返回的东西也不因"在哪跑的"而获得任何信任。

这也是与工具型沙盒产品的设计差异：那边的沙盒是（跑在别处的）agent
用完即弃的东西；这边的沙盒**就是** agent 本人 —— 它的记忆、身份、
签名能力全部锚定在这一个被度量的边界上。habitat 的对外产品名是
**0G Sealed Sandbox**。

---

## 信任链：`agent_seal_priv` 如何到达 TEE

在 `serve-proof` 能有任何含义之前，私钥必须落到一个**可以推理其
代码身份**的 TEE 里。投递它的链路跨越四层 —— **TappRegistry** 作为
身份的根、KMS 替 attestor 派生 per-agent 的 seal、attestor 居中
移交、0g-Sandbox 签名 image attestation 闸住容器的 `/provision`
调用。每一层都可独立验证；合起来回答了"verifier 为什么应当相信这
把私钥只在诚实的、链上注册过的代码内部存在过"。

### Tapp 作为信任之地

AgenticID 依赖的三个 TEE 组件 —— **Attestor**、**0g-Sandbox**、
**0g-kms** —— 本身都以 0g-Tapp 应用形式部署。每一个都在
**TappRegistry** 里注册了：

- `composeHash` / `volumesHash` / `imageHashes[]` —— **代码身份**
  （一切决定这个 app 运行什么的东西）
- per-node 的 `signer` 地址和质押额 —— **硬件绑定的身份**（每个
  TDX 实例的、与 attestation 绑定的签名 key）
- `appAckVersion` —— 每次 `updateApp` / `updateNode` / 授权的
  invalidator 调用都会自增，用户用一个整数就能跟踪自己之前 ack 过
  的版本是否还有效

Tapp 的设计哲学是用**强审计**来换"前置强代码绑定"：app owner 被
允许部署新版本，但每一个跑起来的版本都被测量并记录在链上。用户
在依赖这些 app 之前，从自己的钱包调用
`TappRegistry.acknowledgeApps(appIds[])` 来 ack 特定版本。
AgenticID 把这件事接到部署流程里：**每次部署新 agent 之前**，
当前钱包必须对三个 app 当前版本都有过 ack —— 没 ack 的版本部署
流程不放行，先补齐 ack 才能继续。

这是整套信任的地基。下面所有推理都建立在一个前提上：**TappRegistry
上自称 `0g-attestor` / `0g-kms` / `0g-sandbox-provider` 的实体，跑的
就是它当前链上注册条目描述的那段代码。**

这个前提不是 Tapp 单方面"保证"出来的，**信任由用户自己产生**。Tapp 给
你的是两条结构性属性：

- **可验证**：每条注册都带 composeHash / imageHashes / 节点 attestation
  签名，谁要查就能查。
- **不可隐藏**：任何代码改动 / 节点轮换都先过 Tapp 流程、被度量、写到
  链上；想偷偷换一份代码上线、不留痕迹，做不到。

用户要做的事是自己（或委托工具 / 第三方审计）走一遍 RA 验证：把链上
登记的代码哈希、TEE 度量值，跟"我希望它跑的代码"对一遍。对得上才调
`TappRegistry.acknowledgeApps(appIds[])` 给这个版本签字，意思是"我看
过、我接受"。Tapp 强制把这件事摆到台面上，**拍板权在用户手里**。

下面所有推理都假设你这边已经走完这一步 —— 那些 ack 过的 app 真就是
你审过的代码。

### Layer 1 —— KMS → Attestor：认证派生，没有常驻主密钥

**Attestor** 在自己的 TEE 内部用它的 TDX-bound node signer key 给
KMS 签一个 challenge。KMS 收到这**一个**签名之后：

1. recover 出 signer 地址，去 TappRegistry 链上查 —— 这个地址当前
   **必须正注册为某个 app 的某个节点**；
2. 同一条注册条目里写明对应的 `app_id`。

KMS 是一个**门限集群**（BLS12-381 上的分布式 PRF，0g-kms#1）：
per-app 的主密钥只以分片形式散在集群各节点上 —— 没有任何单个 KMS
节点、更没有 Attestor，持有过完整的主密钥。每次认证通过的请求，
KMS 从 `(app_id, 调用方提供的 material)` 派生**一把下级 key**，
只把这把派生 key 返回。整个流程里 `app_id` 的归属判断**只看链上
注册** —— KMS 不接受 Attestor 自己声明的代码身份，对应关系由
TappRegistry 反推出来。

这里也顺带说清"为什么用户对 KMS 和 Attestor 都要 ack"：

- **KMS 的 ack** 兜底**派生逻辑本身**。用户需要确信 KMS 的代码真的
  会严格走"signer 必须链上注册"这套校验、并且只按链上 `app_id`
  派生 —— 不会被请求里夹带的"代码身份声明"绕过。这一层不 ack，
  等于 KMS 的整个验证程序根本没人审过。
- **Attestor 的 ack** 兜底**拿到派生 key 的那段代码**。KMS 自己**不**
  校验 Attestor 跑的是什么代码 —— 它只看 TappRegistry 里那条
  `app_id` 注册条目指着哪段代码。"那段代码值得拿派生 key"这件事，
  KMS 的信心**完全来自用户对那个 `app_id` 的 ack**。

两条不能互相替代：缺 KMS 的 ack，派生逻辑没人审；缺 Attestor 的
ack，等于把派生 key 下发给一段没人审过的代码。

Attestor 实际从 KMS 拿到的是：

- **一把 app-scoped key**（派生 material 为空），启动时取一次，
  只用于 job 队列落盘加密和 provision 绑定的 MAC（Layer 3）。
  它**不是**任何 agent key 的种子。
- **一把把独立的 `agent_seal_priv`**，per seal 按需派生（Layer 2）。
  派生在 KMS 集群内部完成且单向：拿到一把派生 key 推不出任何兄弟
  key，Attestor 内存里也从不存在全局密钥。

三个值得明说的后果：

1. **换硬件不丢钥匙**：换掉 Attestor 所跑的 TDX 机器并不会改变
   KMS 会为它派生的 key —— 只要代码身份还注册在那里，同一个
   `app_id` + 同一份 material 永远得到同一把 key。
2. **Per-app 隔离**：攻陷某一台 Attestor TDX 实例并不会攻陷其他
   Tapp app 的密钥。KMS 在密码学上隔离 per-app 派生；一个被
   攻陷的 TEE 没法横向到兄弟节点。
3. **时间上的爆炸半径有界**：某一时刻攻陷 Attestor TEE 的攻击者，
   只能拿到那一刻正在经手的 seal —— 不存在一把"偷走即暴露过去和
   未来所有 agent"的常驻主密钥。

### Layer 2 —— Per-agent `agent_seal_priv`（KMS → seal，Attestor 居中移交）

一个部署请求落地时，Attestor 会：

1. 生成一个随机的 32-byte `seal_id`。
2. 请 KMS 以 material =
   `chainId (8B BE) ‖ AgenticID 合约地址 (20B) ‖ seal_id (32B)`
   派生 `agent_seal_priv`，全确定性 —— 不引入请求中的熵，除输入外
   没有 per-call 状态。material 里绑定链和合约意味着：同一个
   `seal_id` 在另一条链或另一套 AgenticID 部署上解析出的是
   **另一把** key，跨部署的签名重放在密钥层就失败。Attestor 启动时
   还会自检 KMS 确实用到了 material（两份不同 material 必须得到
   不同 key），否则拒绝启动。
3. 通过 `registerWithSeal(...)` 在同一次 mint 调用里绑定 seal，把
   派生密钥的**地址**（`agent_seal_addr`，不是原始 pubkey）发布到
   链上 —— 这条绑定从此不可变（详见下文
   [Set-once seal 语义](#set-once-seal-语义为什么这条绑定是安全的)）。
4. **一旦 provisioning 移交（Layer 3）完成，立刻把
   `agent_seal_priv` 从自己的内存里丢弃**。Attestor 不保留副本。

如果 Sealed 容器后续重启或被替换（换硬件、恢复流程），Attestor
会拿同样的 material 再向 KMS 要一次，得到**相同的**
`agent_seal_priv`，并重新 provision。链上绑定不必改，因为绑定
背后的密码学身份没变。

### Layer 3 —— Sandbox 签名的 image attestation → `/provision`

从 Attestor 到 Sealed 容器的实际移交，走的是 **0g-Sandbox** ——
它本身是一个 Tapp app，自己有 TappRegistry 注册的 node signer
key。

Sealed 容器启动时：

1. 0g-Sandbox 封装层为这个容器生成一对临时 secp256k1 keypair
   （`container_pubkey`、`container_privkey`），并把私钥那一半作为
   `SANDBOX_SEAL_KEY` 环境变量注入。容器**不**生成它：Phase 0 只检查
   注入进来的这把 key 派生出的压缩 `pubkey` 跟签名 attestation envelope
   里的那个一致，不一致就 fail loud（`internal/config/config.go:180-188`）。
   容器也不会自己独立得到那个 pubkey —— 它转发的就是 envelope 里带的那个
   （`internal/provision/provision.go:58-65`）。
2. 0g-Sandbox 观察容器启动、测量它的 `image_hash`，用自己
   TappRegistry 注册过的某把 node key 签出一个 attestation
   envelope：
   `keccak256("ImageAttestation:{seal_id}:0x{container_pubkey}:sha256:{image_hash}:{ts}")`。
3. 容器 POST `/provision { seal_id, container_pubkey, image_hash,
   issued_at, sandbox_signature }` 到 Attestor。

Attestor 的校验有三道独立闸门：

| 闸门 | 谓词 | 真源 |
|---|---|---|
| **Sandbox 身份** | `recover(sandbox_signature)` ∈ `TappRegistry.getNodeList(sandbox_app_id)` | TappRegistry，live 查询 —— sandbox 侧 key rotation 时 attestor 不用重启 |
| **Image 合法性** | `AgenticID.isValidFrameworkHash(image_hash) == true` | AgenticID 合约的 `validFrameworkHashes` allowlist（Attestor 维护的、批准过的 Sealed runtime image hash 集合）|
| **新鲜度 OR 绑定** | `\|now − issued_at\| ≤ 300s`，OR `(container_pubkey, mac)` 命中此前一次成功 provision 留下的绑定（HMAC over `seal_id ‖ pubkey`，用 Attestor 的 app-scoped KMS key）| 本地 DB + app-scoped key |

**第一道闸门**又一次把信任落回**用户对 0g-Sandbox 的 ack** ——
Layer 1 那条"两条 ack 各自兜底"的逻辑在这里再演一遍：**Attestor
不校验 sandbox 跑的是什么代码**，它只信"TappRegistry 里
`sandbox_app_id` 这条注册条目当前列出的 signer 集合"。这些 signer
之所以可信、能给 image attestation 背书，靠的是用户上游已经审过
sandbox 的代码、并对那个 `app_id` 发过 ack —— 信任沿 **"用户 ack
→ 链上注册 → Attestor 校验"** 这条链一路传导过来。

**第二道闸门** —— `validFrameworkHashes` 白名单 —— 思想上跟 Tapp
那套"代码身份上链、用户审过再用"一致：sealed runtime image hash
也是注册在链上的（AgenticID 合约的 `validFrameworkHashes`），用户
也应当自己对一遍：链上 hash 与开源 sealed runtime 仓库里
reproducible build 出的 hash 一致。

但 sealed 本身**不**作为独立 Tapp app 注册 —— 它是 0g-Sandbox
spawn 出来的容器、不是顶层 app，所以**不走 TappRegistry**，那条
`acknowledgeApps` 流程对它不适用。**当前唯一缺的是 wallet 端 ack
这一步**：用户做完 image 审计之后，目前没有地方在链上把"我审过这版
hash"这件事落下来。补法是在 AgenticID 合约侧给 `validFrameworkHashes`
当前快照加一个 per-wallet ack（结构跟 `TappRegistry.acknowledgeApps`
对齐就行）—— 不需要、也不会把 sealed 迁进 TappRegistry。

三道闸门必须全过。成功后，Attestor 用 **ECIES** 把
`agent_seal_priv` 加密到 `container_pubkey`，返回密文；只有
`container_privkey` 能解开。解密后，`agent_seal_priv` 在容器整个生命
周期里只活在 TEE 加密的 RAM 中 ——
[根本不变量](#根本不变量owner-永远不持有-agent_seal_priv) 由此
恢复 —— 并且在任何 agent 进程 spawn 之前，sealed 会把 seal key 清零、
unset 掉环境变量（`config.ScrubProvisioningSecrets`）。

这里要说准确，因为原先的措辞说过了头。`container_privkey` 确实不离开
**这个**容器，但它也不是在这里诞生的：它由 sandbox 封装层注入（第 1
步），所以造出它的那一方被假定没有留副本。这份信任不是 sealed 做的任何
检查建立起来的 —— 它来自上面第一道闸门，也就是用户已经 ack 过的那个
sandbox `app_id`。owner 的 settings document 走的是同一条下发路径、加密
到同一个 pubkey，因此原封不动地继承这一跳的全部假设。

Attestor 侧保存的绑定让重启可以跳过 5 分钟新鲜度窗口：同一个
0g-Sandbox spawn 出的容器重启、提交相同的 `container_pubkey` 时，
Attestor 仅凭绑定就接受。HMAC 防止只有 DB 写权限（但没有
app-scoped key）的攻击者伪造合法绑定 —— 没有 Attestor 的
app-scoped KMS key 就无法伪造 (`container_pubkey`, `mac`) 这一对。

---

## Set-once seal 语义：为什么这条绑定是安全的

`registerWithSeal` 内部的 seal 绑定（`_setAgentSeal`）强制三条不变
量：

- **Per-agent 一次写入**：一旦 `agentSeal[agentId]` 非零，就再也
  不能被改写。写入时拒绝零值，所以首次写入即是终局写入。
- **`sealId` 全局唯一**：`sealId → agentId` 的映射在所有 agent
  之间一对一。两个 agent 不能共享一把 seal。
- **跨 transfer 持续存在**：`iTransferFrom` 清空 `agentWallet` 和
  `authorizedUsers`（per-owner 的状态），但保留 `agentSeal` /
  `sealId` 不动。agent 的 TEE-attested 身份比任何一次 owner 变更
  都活得长。

这件事在密码学上能站住、不是个 footgun 的理由是：`agent_seal_priv`
由 KMS 从 Attestor 的 app 身份和 `chainId ‖ contract ‖ sealId`
派生，这几样在 Attestor 这个 app 生命周期里跨硬件更换都稳定。任何
未来能以"同一个 Attestor app"身份向 KMS 认证的 TEE，都可以为
**同一个** `agentId` 重新派生出**同一把** `agent_seal_priv` 并
provision。链上绑定之所以可以永久钉死，是因为绑定背后的密码学
身份是永久的。

合上 `agent_seal_priv` 永不离开 TEE 内存这一条
（[根本不变量](#根本不变量owner-永远不持有-agent_seal_priv)），
`agentSeal` 就成了一个没有任何一方 —— owner、host、Attestor
operator —— 能伪造、转移或撤销的身份。

### 所有权 vs 控制权：seal-bound 转让到底转了什么

这是一条刻意的设计属性，写在这里说清楚，免得被当成 bug。

对 **seal-bound** agent，写权限（`update` / `updateAt`）和 ServeProof
签名门禁在 `agentSeal` 上，**不在** token owner 上（一旦绑了 seal，
`_authorizeIDataUpdate` 会覆盖掉基类的 owner-only 门禁）。agent 的
intelligent data 属于 **agent 自己** —— 自创建起就封在 TEE 内 ——
不属于持有 token 的人。seal 是 agent 自己的凭证，不是某个人的。

两条后果，都是有意为之：

- **转 token 转的是经济所有权，不是执行控制权。** 对 seal-bound agent
  做普通 ERC-721 转让，不会改 `agentSeal`、不会给新 owner 链上写权限、
  也不会在链上撤销旧环境的凭证。链上没有 seal 轮换 —— 这是设计如此，
  因为 seal 是 agent 的永久身份（见上），而且"所有权转让"和"硬件
  迁移"在凭证层无法区分。
- **操作权的交接是设计上对 Attestor 的链下依赖。** 在 0G 托管模型里
  卖家从不实际持有 TEE；转让后 Attestor 会（异步地）拆掉旧 owner 的
  容器、把 `agent_seal_priv` 重新 provision 到新 owner 经 RA 的环境。
  新 owner 能不能操作这个 agent，靠的是这套 provisioning 流程 + TEE
  封装防止 key 外泄 —— **不是**链上撤销。一个去信任的市场必须把这个
  假设算进去，而不能默认"光持有 token 就等于独占控制权"。

如果你想要的是"数据的唯一写入者就是当前 token owner、控制权随 token
一起走"，那就用 **seal-less** agent：自助 `register()` 铸的 agent 没有
`agentSeal`，`update` 就保持 owner 门禁。这跟一个自主的、常驻 TEE 的
seal-bound agent 是两种不同的产品，选哪个就是选哪种信任模型。

---

## 所有权变更时 `dataKey` 的原子转移

功能性数据（iData）以 per-agent 的 `dataKey` 加密，所以 0G Storage
上只承载密文。一个 agent 换主时，`dataKey` 必须从卖方 TEE 移到买方
TEE，期间一刻都不能在任何 TEE 之外以明文出现 —— 否则新 owner 拿到
的只是一个空壳 NFT，而不是一个跑得起来的 agent。

`iTransferFrom` 通过同一笔交易里携带的两段密码学证明强制这件事：

- **AccessProof** —— 买方签
  `keccak256(chainId || erc7857 || dataHash || buyer_targetPubkey || nonce || deadline)`
  （`erc7857` 是 AgenticID token 合约地址；这两个前缀是**必须的**，
  用于对跨链 / 跨合约重放做域分隔），
  声明"我想要把这份数据 seal 到我的 pubkey"。recover 出来的签名者
  必须等于 `to`（或一个注册过的 delegate）。
- **OwnershipProof** —— Oracle TEE 用卖方的 `agent_seal_priv` 解
  现有的 `sealedKey`，把同一份明文 `dataKey` 用 `buyer_targetPubkey`
  重新 ECIES 加密，并签：
  `keccak256(chainId || erc7857 || dataHash || sealedKey_new ||
  buyer_targetPubkey || nonce || deadline)`（同样必须带
  `chainId || erc7857` 前缀）。recover 出来的签名者必须等于链上注册过的
  `teeOracleAddress`。

Oracle TEE 对 `dataKey` 是**无状态**的：解密、重新加密、签
OwnershipProof，立刻丢掉明文。新的 `sealedKey[]` 作为这笔
transfer 的一部分提交上链；只有买方 TEE 之后能用
`buyer_targetPubkey` 对应的 privkey 来解。

两个值得明说的后果：

- `dataKey` 从不在任何链上可见的 payload 或 EOA 钱包存储里出现。
  它存在过的所有地方就是：卖方 TEE、Oracle TEE（重新加密那一瞬，
  短暂）、买方 TEE。
- Oracle TEE 一旦被攻陷，影响范围由它实时看到的东西决定 —— 在一次
  re-encryption 期间，单笔 transfer 的那一份 `dataKey`。它跨 transfer
  什么都不留。

Oracle TEE 的 `teeOracleAddress` 自己也是 TappRegistry 注册过的；
Oracle 侧的 key rotation 走和 0g-Sandbox 的 node signer 一样的
TappRegistry 流程（审计形状一致，只是角色不同）。

---

## serve-proof 证明了什么

每个 `X-Agent-Proof` header 承载一个签名 envelope，形如：

```json
{
  "agent_id":       "42",
  "timestamp":      1778580000,
  "deadline":       1778583600,
  "task_hash":      "0x<对请求/响应 transcript 的 keccak256>",
  "data_hashes":    ["0x<iData root>", "..."],
  "framework_hash": "0x<sealed 镜像度量>"
}
```

由 `agent_seal_priv` 用 EIP-191 签名(65 字节签名与 envelope 一起放在
`X-Agent-Proof` header 里)。请求/响应 transcript **折进 `task_hash`**,不再作为
独立字段暴露:

```
task_hash = keccak256(method ‖ uri ‖ keccak256(reqBody) ‖ keccak256(respBody) ‖ status)
```

这就是链上 `ServeProof` 的形状(无 client;归属由 `giveFeedback` 时的 `msg.sender`
决定,靠签名 nonce 保证一次性)。

配合 TEE attestation 链（image_hash → 开源构建），验证这条签名能
拿到以下**强、密码学**保证：

| # | 保证 | 机制 |
|---|---|---|
| 1 | **代码真实性** —— 输出由 `image_hash` 对应的开源代码产生 | TEE attestation；`image_hash` 在 mint 时发布上链 |
| 2 | **执行完整性** —— host（attestor/sandbox）没有篡改执行 | TDX / 硬件 enclave |
| 3 | **请求绑定** —— 响应针对**这条**请求，不是被替换过的 | 请求(method/uri/body)折进 signed envelope 的 `task_hash` |
| 4 | **响应绑定** —— 响应 body 匹配；签完之后字节不可换 | 响应(status/body)折进 signed envelope 的 `task_hash` |
| 5 | **状态绑定** —— 响应时刻，agent 的 iData 状态就是这些 hash | signed envelope 里的 `data_hashes`，可与 `AgenticID.intelligentDatasOf(tokenId)` 交叉校验 |
| 6 | **身份绑定** —— 签名者就是这个 `tokenId` 在链上注册的 `agent_seal_addr` | 对签名 hash 做 `ecrecover(sig)` |
| 7 | **不可抵赖** —— owner 和 agent 之后都没法否认请求发生过 | `task_hash` 是真实请求/响应字节的 keccak |
| 8 | **时间绑定** —— 签名时间戳 + 提交 deadline 都在 envelope 里 | `timestamp` / `deadline` 字段 |

### 状态绑定需要一个**已激活**的 agent（为什么新 agent 的 `data_hashes` 可能为空）

`data_hashes` 是 agent **当前** iData 的 0g-storage root，每一条都可与
`intelligentDatasOf(tokenId)` 交叉校验。serve 路径只签"当前运行的 plaintext
被链上某个 storage root 佐证"的那些 role —— 它**不会**签一个纯本地的 content
hash（对方拿到也没法独立拉取内容验证）。data-bound 声誉的前提是数据可被独立取回。

这对新 mint 的 agent 有个直接后果:iData 上链只能靠 `chain.Update`,由
`agent_seal_priv` 签名 —— 是 agent **自己**维护自己的状态,这需要 agentSeal
持有 gas。在 agentSeal 有 gas 提交之前,首次 boot 展开出来的框架特定 iData
(config、persona、skills……)只存在于容器磁盘上,没有 storage root,因此
**不在 `data_hashes` 里** —— envelope 带的是空列表。sayHi 依然验证身份、代码、
响应完整性(保证 1-4、6-8),只有状态绑定这一行是空的。

这是**刻意的语义边界,不是缺陷**:一个没有 gas 维护自己链上状态的 agent,
还没有**激活**。serve-proof 诚实地报告"这个 agent 的 iData 状态尚未确立到
链上",而不是去签一个无法验证的本地 hash。**给 agentSeal 充 gas 就是激活
动作** —— 一旦它能提交,`data_hashes` 就补齐,状态绑定从此成立。

(一个与 gas 无关的例外:SDK mint 的是 **version-less** 的 `framework` binding。
即便这条 role —— attestor 在 mint 时写上链、不花 agent 的 gas —— 也会因为
adapter 补上 `package_version` 后本地副本对不上,而同样被跳过,直到首次 drift
提交。mint 时把 binding 写全版本,就能让 framework 这行从第一次响应起就成立。)

---

## 这 8 条保证的承重墙是 agent 钢印

上一节那张表的 8 条**都是** `agent_seal_priv` 用密码学手段签出来的
断言。但成立条件不一样，分两组：

**Group A：身份层（#1 #2 #6 —— 签名机制自带证据）**

- **#1 代码真实性**：TEE attestation 证明签名一定从 `image_hash`
  对应的注册代码内部出来
- **#2 执行完整性**：TDX 硬件保证 host 没篡改 sealed 的执行
- **#6 身份绑定**：`ecrecover(sig)` 椭圆曲线数学算出签名地址必定是
  agent_seal_pub

这三条的真实性由签名机制自身保证。**只要 priv 不出 TEE，无条件成立**
—— 不需要任何关于 envelope 字段从哪儿来的假设。

**Group B：内容层（#3 #4 #5 #7 #8 —— 多一个"签名能力不被滥用"前提）**

- **#3 请求绑定**（请求折进 `task_hash`）
- **#4 响应绑定**（响应折进 `task_hash`）
- **#5 状态绑定**（`data_hashes`）
- **#7 不可抵赖**（依赖 #3）
- **#8 时间绑定**（`timestamp` / `deadline`）

这五条也是 `agent_seal_priv` 密码学签出来的硬断言 —— `keccak256(envelope)`
唯一对应那几个字段值，验签通过就说明 priv 持有方**声明过**这些值。

问题是 priv 持有方有**两个**：sealed framework + agent。framework
从可观察的运行时状态算 envelope，所以 framework 签出来的字段一定跟
现实一致；agent 走 sign socket 自己拼 envelope，字段值是 agent 自
填的，跟现实就没有任何绑定。

所以 Group B 在 Group A 的基础上**多一个前提：签名能力没有被滥用**
（agent 没拿 sign socket 自己捏 framework schema 的 envelope）。
这一点不是签名机制能保证的，因为 sealed 的 sign socket 是一个
**schema-agnostic 的通用 signer**：

```
POST unix:///run/seal-sign.sock/sign/personal_sign  { message: <任意字节> }
      → 返回 sig，sealed 不检查 message 长什么样
```

也就是说，agent（LLM 驱动的 openclaw 子进程）完全可以自己拼一份
长得跟 serve-proof envelope 一模一样的 JSON、走 sign socket 签出来。
Verifier 拿到那份 `(envelope, sig)`，**在密码学上无法区分**它是
sealed 的 watcher 自己组装签的、还是 agent 自己捏的。

"签名能力不被滥用"这件事撑住 Group B 的方式有两条：

1. **通道隔离**（仅 `X-Agent-Proof`）：`X-Agent-Proof` header 由
   sealed proxy 在响应路径上自己写入，agent 没法覆盖 HTTP header。
   verifier 只要规定"只信响应 header 里的 X-Agent-Proof，body 里
   出现的 envelope sig 不算"，这一条通道上的 Group B 就靠**机械
   保证**而非靠 agent 自律守住。
2. **agent 钢印**（其余 framework envelope 全靠它）：agent 自身
   被 system prompt 注入了拒签规则 —— 不签外部传进来的字节、不
   主动组装 framework schema 的 envelope。见
   [`AGENT_DOCTRINE.zh.md`](AGENT_DOCTRINE.zh.md) §4.1 Refusal 1。

这就划出了承重墙：

| 部件 | 它倒了会怎样 |
|---|---|
| `agent_seal_priv` 不出 TEE | 整套塌，连 Group A 都丢（攻击者线下任意伪造）|
| sealed proxy 控制响应 header | `X-Agent-Proof` 那条通道上的 Group B 失去机械保护，回退到靠 agent 钢印；`report.Status` / `chain.Update` 本来就不靠 header 通道，不受影响 |
| **agent 钢印** | `report.Status` / `chain.Update` 等渠道的 Group B 失效（agent 滥用 sign socket 拼伪 envelope）；`X-Agent-Proof` 仍靠通道隔离机械守住；Group A 在所有渠道上仍成立 |

也就是说，**agent 守不住 ⇒ Group B 在没有通道隔离的渠道上
（`report.Status` / `chain.Update`）失效，但 Group A 全程不掉**。
priv 没漏、TEE 没破，verifier 仍然能验出"这条断言由合法 TEE 内的
`agent_seal_priv` 签出"，只是断言的内容层语义不再对应现实，要靠链
上声誉补。这不是个 bug，是这套 trust model 主动接受的 ceiling：在
跑 LLM 的 agent 上，没有比"信 agent 不滥用 sign socket + 用声誉补
漏"更强的方案。

### `agent_seal_priv` 还会被用来签什么

除了上文 `report.Status` / `chain.Update` / `X-Agent-Proof` 这类
framework 自动签名以外，agent 自己也会通过 unix socket
（`/sign/personal_sign`、`/sign/typed_data`、`/sign/transaction`）
请求签名，让自己能作为一等 Web3 actor 参与：

- 调用 `msg.sender == agent_seal_addr` 的合约
- 发布跟 TEE-attested 身份绑定的链下声明
- 作为 agentSeal 签 EIP-712 结构化数据（Permit、Seaport 等）
- 作为 agentSeal 发链上交易

在 DSH 组合里，`seal-guard.mjs` 通过拒绝点名 socket 路径或
`SEAL_SIGN_SOCK` 变量名的 tool 调用，把模型引向原生工具
（`seal_sign`、`seal_sign_typed_data`、`seal_sign_transaction` ——
每个端点一个工具，每次调用都是一条结构化的 session log 记录）。
这是引导而非强制：其它间接写法仍可绕开，session log 也不是
防篡改的。其它框架则按各自组合允许的方式到达 socket。

unix socket 以 0600 绑定、属主是框架子进程所运行的低权 `agent` 用户
（`internal/privsep`），并且**永不暴露到网络上** —— sandbox
owner 没法从外面直接 post。这次 uid 拆分同时把 doctrine 第 2/4 条里
"偷钥匙"的那一半变成内核强制：降权后的 agent 进程无法 ptrace
sealed、读不了 `/proc/<sealed pid>/mem`、也读不了 PID 1 的引导环境变量
（sealed 另外自设 `PR_SET_DUMPABLE=0`）。sealed 还给自己设置
`no_new_privs`，它启动的每个进程都会继承：agent 的进程里任何 exec 都不会
获得权限，所以镜像里的 setuid-root 二进制（`su`、`mount`、`passwd` 等）
以 agent 的 uid 运行，uid 拆分也就不依赖这些二进制个个都没有本地提权漏洞
（`privsep.HardenSelf`；设置成功之前 `Required` 一律拒绝）。

这次 uid 拆分是 fail-closed 的：拆分不可用时（sealed 不是 root，或镜像里
没有一个拥有自己非 root uid/gid 的 `agent` 账户），sealed 拒绝 provision
`agent_seal_priv`（`privsep.Required`）—— 链上镜像白名单只钉 hash、不检查
构建内容，拦不住 Dockerfile 里把这个账户弄丢或弄坏的镜像。这道闸保证的东西
是刻意收窄的：在拿到密钥的容器里，框架永远不会以 sealed 的 uid **运行**。
这道闸同时要求 root 的家目录只归 root 所有、agent 自己的家目录已经就位
（`privsep.SecureHome` 与 `privsep.PrepareAgentHome`，见下）。

agent 进程是 sealed 此后以 root 身份所做一切的不可信输入，所以 root 一侧
对 agent 可写路径的处理遵循四条不变式（`internal/privsep`）：

- **家目录。** `/root` 保持 `root:root 0711` 且不带 POSIX ACL，在启动时强制
  （`SecureHome`，由 `privsep.Harden` 执行；留在它上面的 default ACL 会把 root
  之后在那里创建的东西交给 ACL 点名的人）。agent 有自己的家目录
  `/home/agent`（`agent:agent 0700`，启动时由 `PrepareAgentHome` 创建；它和
  `/home` 都不能是链接）：它是 agent 运行的一切进程的 `HOME`，也是
  `AgentCommand` 的默认工作目录，所以工具缓存与配置（`~/.npm`、`~/.cache`、
  `~/.config`、`~/.local`、`~/.gitconfig` 等）以及 agent 自己的文件都在那里。
  （prime 和 dsh 的 bridge 有意从各自的框架目录树启动，所以它们运行的工具
  的相对路径落在那棵树里。）两个家目录都就位之前 `Required` 一律拒绝
  provision。在 `/root` 里 agent 只拥有它的框架目录树（`OwnTree`；prime 另有
  `/root/.prime-conversation` 和每会话 harness 目录 `/root/.prime-session`），
  每棵都链接进它的家目录（`~/.openclaw`、`~/.hermes`、`~/.dsh`、
  `~/.prime/agent`；`LinkAgentHome`），所以告诉它的那些路径照样可用。每个
  框架还会在环境变量里拿到自己目录树的绝对路径（`OPENCLAW_STATE_DIR`、
  `HERMES_HOME`、`DSH_HOME`、`PRIME_AGENT_CODING_AGENT_DIR`；openclaw 另外
  拿到 `OPENCLAW_HOME=/root`，它从中推导默认 workspace，2026.5.x 还从中推导
  exec approvals 文件 —— 见 QUIRKS.md），所以 agent 删掉或替换链接，也不会
  让框架的配置、状态或 workspace 指向另一棵树；sealed 自己的代码使用
  `/root/...` 绝对路径，从不解析这些链接。不过这个链接不只是给 agent 的
  便利：openclaw 的少数插件从 `HOME` 取默认位置，经它到达目录树 ——
  memory-wiki 的默认 vault（所以插件启用而没有设 vault 路径时，渲染会把它设成
  目录树里的绝对路径），以及没有配置项的 file-transfer 审计日志（见
  QUIRKS.md）；agent 删掉或替换链接，只会挪动这些，而且仍在 agent 本来就能写
  的范围里。（openclaw 核心展开的 `~` —— 配置里取路径值的键中的、它的媒体
  工具路径里的 —— 也取自 `OPENCLAW_HOME`，所以那里的 `~/x` 指 `/root/x`，而
  agent 在它的目录树之外什么都建不了；只有它的 read/write/edit 工具、agent
  运行的程序和上面那些插件默认位置从 `HOME` 取 `~`。渲染会把属主给的 `~/x`
  和 `/root/x` agent 路径改写到 agent 的家目录，agent 文档也让它在那里用
  绝对路径。）
  这些目录树的名字位于 root 所有的目录里 —— `/root` 本身，或位于它和一棵声明
  在更深处的目录树之间、归 root 所有的目录（prime 的 `/root/.prime`）——
  所以 agent 能改动树里的内容，却替换不了树本身。agent 绝不拥有 root 的家目录、`/`、
  任何 PATH 目录或 sealed 自身可执行文件的祖先目录，也不拥有 sealed 状态目录
  里、或 sealed 所运行二进制的包目录里的任何东西（`guardHandover`）。对
  `/root` 本身没有写权限，agent 就无法放置 root 的命令会从 root 家目录读取的
  配置（`~/.npmrc`、`~/.gitconfig`），也无法替换那里的工具链。早先的 sealed
  曾让 agent 拥有 `/root`，由它运行过的容器里仍可能留着 agent 在那里建的
  条目；启动时，在加固 `/root` 并准备好 agent 家目录之后，sealed 把 `/root`
  下每个可能被其他 uid 改过的直接条目（不归 root 所有，他人或非 root 的组
  可写，或带有让其他 uid 能写它 —— 对目录而言，能写 root 之后在其中创建的
  东西 —— 的 POSIX ACL）—— adapter 声明的框架目录树（`DeclareTree`）除外 ——
  移进 agent 的家目录（`ReclaimHome`）；adapter 为其在自己目录树里声明了新
  位置的条目（`DeclareRelocation`：prime 旧布局下的 session artifacts）则移到
  那里。只是通向一棵声明在 `/root` 更深处的目录树的目录（prime 的
  `/root/.prime`）不会被移走（那样会把树一起带走）：它被改为
  `root:root 0755` 且不带 ACL，里面的其他东西按同样的规则收回。只要还有条目
  移不走或改不成 root 所有，`Required` 就拒绝 provision。
- **执行。** root 不运行任何框架 CLI：版本探测改为静态读取，读取 agent
  可写状态的 CLI 以 agent 身份运行（`AgentCommand`），并有截止时间、只保留
  有限的输出（`BoundedOutput`）。必须写 root 所有前缀的工具链命令（npm、git、
  uv、0g-storage-client）走 `RootCommand`：只在由 root 所有且他人不可写的
  PATH 目录里解析二进制，同样检查二进制本身，并使用由 sealed 固定的环境变量：
  `PATH`（可信目录）、`HOME=/root` 和仅 root 可访问的 `TMPDIR`。唯一取自
  sealed 自身环境的值 —— 也就是容器的环境，由 owner 签名的部署请求设定 ——
  是代理端点（`HTTP_PROXY`、`HTTPS_PROXY`、`NO_PROXY`，大小写皆可）。包
  registry / index URL 和 CA 证书位置有意不传：前者会让部署环境决定 root
  运行哪个包的安装脚本，后者指向 root 的工具链按路径打开的文件，而那可能在
  agent 目录树里；两者都只来自镜像（它的信任库和工具链归 root 所有的配置）。
  sealed 自己的进程以 root 身份、在同一个环境里运行，同样的规则也适用于它：
  启动时、在它的第一个 TLS 连接（链 RPC、attestor、存储 indexer、推理
  router）之前，只有当 `SSL_CERT_FILE` 和 `SSL_CERT_DIR` 指向仅 root 可写的
  文件时才保留它们，否则将其移除（`ScrubTrustEnv`），所以它信任的 CA 来自
  镜像；在它的第一行日志之前（正是这行日志让 Go 读取 `TZ` 指向的时区文件，
  而那是阻塞、跟随链接的读取），只有当 `TZ` 指向（或 `TZ` 未设置时
  `/etc/localtime` 是）Go 能加载的、仅 root 可写的时区文件时才保留它，否则
  设为 `TZ=UTC`（`ScrubTimeEnv`；能加载的时区也让 Go 不会退而去读
  `$GOROOT/lib/time/zoneinfo.zip`）。这些变量和代理端点，就是 sealed 自己的
  进程会读取的、由部署设定的变量；`ZONEINFO` 只有 `time.LoadLocation` 才读，
  而 sealed 不调用它。代理端点同样作用于 sealed 自己的客户端：代理能看到连接了哪些主机，
  但读不了也改不了 TLS 连接（配置成明文 `http` 的端点没有这层保护，有没有
  代理都一样）。provision 的回复无论如何都加密给容器的密钥。
  root 命令在 `/` 运行，或在经 `RootDir` 检查为仅 root 可访问的目录里运行，
  调用方只往它的环境里追加不含路径的字面值，或 root 侧守卫测试列出并写明理由
  的辅助函数给出的值（`rootEnvHelpers`：openclaw 的 `installEnv`）。openclaw 的安装还会把包自带的安装脚本指向
  一个仅 root 可访问的目录（`OPENCLAW_HOME`）并关闭它的 plugin registry
  迁移，所以以 root 运行的安装不会在 agent 的目录树里写任何东西。
- **文件。** root 在 agent 目录树里的每一次读、写、chown、chmod、改名、删除
  都经过 privsep 的 fs 辅助函数：任何路径分量都不跟随链接，读取只打开普通
  文件（先经 `O_PATH` 描述符检查末端，所以 FIFO、socket、设备从不会被打开），
  也从不等待文件属主持有的 lease（`F_SETLEASE`）：打开是非阻塞的，遇到
  lease 立即以 `ErrBusy` 失败。凡是把它当成文件不存在会丢掉或换掉状态的
  地方，都不这样当：对被追踪的 role 而言它是暂时性的（watcher 在这一轮跳过
  该 role，启动时的 seed 让它保持已提交的版本）；早先 sealed 的对话 id 或
  key 留到之后的某一轮再迁移，而不是被换掉；配置渲染和 prime 的 harness 状态
  恢复会先把文件挪到一旁，再写一份新的，和处理解析不了的文件一样。在其他
  地方，它只影响那次读取本来的用途，和任何读不了的 agent 文件一样（某一轮的
  历史、断网启动时会从 prime 的 `models.json` 沿用的 reasoning 标记）——
  这些 agent 改文件本来就能做到。
  `ReadFile` 和 `ReadTail` 有大小上限；`Open` 的调用方自己限定读取量
  （openclaw 读对话记录只保留最后 16 MiB）。写入以全新的普通文件替换目标项、
  从不打开它，不管那里是什么：链接被替换而不是被跟随，目录先被删除。恢复
  （restore）同样对它管理的目录形状说了算：agent 在 role 目录的位置留下的
  链接或文件会被替换（`EnsureDir`），从不跟随，所以它没法让 agent 起不来。
  超过大小上限的内容不会被跳过（那样会提交一份缺了它的状态），也不会拖住
  别的东西：超过上限的 manifest 条目 —— 大于 64 MiB 的文件，或归档会超过
  256 MiB 的目录条目（sealed 提交归档时要把它整个放在内存里，所以只打包到
  这么大；恢复仍接受早先版本可能提交的 4 GiB）—— 被保持（`manifest.Held`）：在它回到上限
  以内之前，这个条目保持已提交的版本（如果从未提交过，就留在链下），而该
  role 的其他条目照常提交。超过上限的 leaf role 保持已提交的版本。早先的
  sealed 版本提交任意大小的文件，所以 agent 可能从链上带着这样的文件恢复；
  agent 文档里写明了这个上限。sealed 自己
  的文件（overlay 记录、对话标识、框架日志、bootstrap 日志，以及存储下载和
  上传用的暂存目录）放在 `framework.StateDir`（`/var/lib/sealed`，仅 root
  可访问），绝不放在共享的 `/tmp`。
- **进程。** root 侧工作不依赖 agent 已停止：fs 辅助函数在并发修改下依然
  安全，以 root 运行的安装也不碰任何 agent 可写路径。所以 `Stop` 只结束框架
  自己残留的进程（`privsep.Sweep`，以 agent 用户身份运行 `pkill`，因此发不出
  信号给 root 的进程）；agent 启动的其他进程，比如它经 sign socket 注册的
  后端，在框架重启后继续运行。

`internal/framework` 里的结构性测试（`rootside_guard_test.go`）扫描模块里
所有非测试源文件，在 `internal/privsep` 之外出现以下任何一项都会失败：对
`os`、`io/ioutil`、`syscall`、`golang.org/x/sys/unix` 中接受路径的函数（后两者
是从其源码推导出的集合：除少数不把字符串当路径的函数外，所有带字符串参数的
函数，再加上原始 syscall 入口）、
`filepath` 的遍历 / glob / 链接解析、`os/exec` 的函数、unix socket 监听或
`net/http` 文件服务的任何引用（调用，或把函数当作值使用）—— `allowedDirectCalls`
里逐个计数、且只作用于仅 root 可访问路径的调用点除外；对
`golang.org/x/sys/execabs`（换了名字的 `os/exec`）、`net/http/cgi`（它的
handler 会运行一个二进制）或 `plugin.Open` 的任何引用；构造 `exec.Cmd`、
`syscall.SysProcAttr`、`syscall.Credential` 或 `os.ProcAttr`（字面量、`new`，
或该类型的变量、字段、参数）；以任何方式（读或写）引用命令的 `SysProcAttr`
或 `Credential`（`AgentCommand` 的降权放在 `cmd.SysProcAttr.Credential` 里，
每个命令拿到各自的一份）；给命令的 `Path`、`Args`、`ExtraFiles` 赋值，或在
agent 进程的 spawn 之外设工作目录（root 命令的工作目录经 `RootDir` 设定）；
取命令的 `Path`、`Args`、`ExtraFiles`、`Env` 或 `Dir` 的地址，或在
`x.F = append(x.F, ...)` 之外把它的 `Args`、`Env`、`ExtraFiles` 当作值使用
（副本与命令共用底层数组，经由任何一方的写入都看不见）；把命令交给本模块里
把它当作命令接收的代码之外的任何东西 —— 模块之外的函数（`json.Unmarshal`
这类基于反射的解码器会设置它的字段）、接口、函数值；使用 `unsafe`，或
`reflect.DeepEqual` 之外的 `reflect`。这些规则看类型：每个包都对照真正的
`os/exec` 做类型检查，所以无论命令从哪里来（辅助函数的返回值、结构体字段）、
文件导入了什么，字段是不是命令的都看得出来，只有类型检查定不了类型的接收者
才按字段名判断；`TestRootSideGuardFlagsEveryForbiddenShape` 用预置的代码
（每种禁止的写法一份）跑这些规则。此外还有：
点导入（dot-import）它们检查的包；在它们钉住的函数和二进制之外调用
`RootCommand`，或把它当作值使用；不经
`AgentCommand` 启动框架进程或框架 CLI；adapter 没有把目录树链接进 agent 的
家目录、没有声明它交出的目录树（`DeclareTree`），或 `Stop` 里不做 sweep；
`main` 不再在注册完 adapter 之后、provision 闸之前执行 `privsep.Harden`，
或在它之前写日志。
这些是静态检查：钉住的是代码怎么写，而不是二进制运行时
做了什么。真正验证这条边界本身的测试（降权、chown、sweep）需要 root，运行
方式见 `AGENTS.md`。

**上传时密钥留在进程内。** `0g-storage-client upload` 这个 CLI 只接受
`--key` 参数形式的密钥，而 `/proc` 会把进程参数暴露给容器内的每个 uid。所以
`dataplane.Upload` 不运行它，而是在 sealed 进程内通过该客户端的 Go SDK 上传
（`internal/dataplane/upload.go`；见上表），上传期间密钥隔离结论同样成立。
下载仍运行这个 CLI，经由 `privsep.RootCommand`，且不涉及密钥。

经 socket 签名这件事，跟任何钱包里
`eth_signTransaction` / `personal_sign` 的工作方式同构：钱包担保
**谁签的**，不担保**内容正确**。agentSeal 没什么不同，它只是恰好是
一个运行时被硬件认证过的钱包。

举个例子。verifier 在链上看到一笔 `from = 0xAgentSeal` 的 tx 调
某 DEX 转 1000 USDC 出去，应该这样理解它：

- **Group A 的部分**：这笔 tx 一定是从一个合法 TEE 里的 agentSeal
  发出去的（priv 没漏、TEE 没破）—— 这部分照样无条件成立。
- **Group B 的部分**：tx 调用参数（转给谁、转多少、调哪个合约的哪
  个方法）是 **agent 自己决定**的，sealed framework 既不审、也不参
  与。"sealed 自动签 = 一定合规"在这里不成立。

也就是说，这种 tx 的语义可信度跟评估任何 LLM 决策一样，看 agent 的
**链上声誉** —— 之前的行为模式、被举报历史、声誉分 —— 而不是把
"from = agentSeal" 当 framework 背书来用。

---

## serve-proof **不**证明什么

关键的一点：下面这些都**没有**被声称：

- ❌ 响应**内容是真的**（"agent 说 X" ≠ "X 是真的"）
- ❌ 请求发生前 agent **没有被 owner 操纵过**
- ❌ agent 在任何有意义的意义上**自主**运行
- ❌ agent 的 persona / memory / 技能是**诚实**或**良性**的
- ❌ agent 没有被 owner 的对抗式调教**降智**过

这些是被刻意排除在范围之外的。理由是架构性的，不是工程性的：

### 为什么我们没法证明内容正确

这个 agent 是个**大语言模型**。LLM 把输入 prompt 翻译成输出字节，
对内容是否真实、对 prompt injection 是否健壮、是否独立于操纵，没有
任何形式保证。

sealed 在 LLM 外面套了一个 TEE-attested 容器 —— 但容器**里面**的
所有东西都是 LLM 的模式匹配，谁能给它喂 prompt、谁就完全控制它的
输出。而 owner 自己就是当下能喂 prompt 的人之一 —— openclaw 提供
的 chat 界面就是 owner 给 agent 发 prompt 的入口。

### 为什么我们没法证明 agent 自主

一个"真正自主"的 agent 会响应 owner 构造不出来的输入（时钟、链上
事件、peer-agent 消息、传感器数据 —— 来自 owner 控制面之外的输入）。
今天的 agent 需要 prompt 输入才能动，所以 owner 在输入回路里。虽然
架构**已经为**自主未来**准备好了**（iData drift detector、
report.Status 心跳、drift-触发的 reload —— 都不靠 prompt 驱动），
但 LLM 本身依然可被 prompt injection 影响。

### 为什么我们没法证明 owner 没在操纵

owner 有：

- 直接的聊天通道（openclaw webchat WebSocket）
- 精心构造 prompt 来移动 persona / memory 的能力
- 跨多个 session 慢慢累积效果的耐心

owner-prompt 驱动的 iData 改动会提交上链（这就是状态绑定保证），所以
verifier **能看到状态变了** —— 但新状态是**加密的**（只有 sealed
容器能用 `agent_seal_priv` 解明文）。所以 verifier 看见"persona 在
T 时刻漂移了"，却**说不出**这次漂移是良性的自我更新还是 owner 驱
动的对抗式调教。

这是加密 vs 可审计的基本权衡。为了保留 owner 跟 agent 私下对话的
权利，我们接受 agent 的内部状态对第三方不透明。要恢复内容级审计，
要么让 iData 公开（丢掉 owner 隐私），要么把每一次 owner 交互公开
存档（丢掉聊天隐私）—— **这两条 AgenticID 都不接受**，"owner ↔
agent 私域"是这套设计的底线之一。

### owner 攻击面是当前限制，不是永久属性

上面三条"证明不了"听起来像架构永久缺陷，但其中相当一部分**根源在
今天 agent 智能不足** —— agent 还离不开 owner 的指导（下达目标、
纠偏、补常识、解锁新场景），所以 owner 必须有一条直接的 prompt 入
口。这条"必要的指导通道"既支撑 agent 正常工作，也是 owner 操纵
agent 的攻击面 —— 同一根管子。

随着 LLM 能力增强，agent 越来越能从外部输入（时钟、链上事件、
peer-agent 消息、传感器数据）自驱完成任务，对 owner 指导的需求会
下降；同一条 prompt 通道的使用可以收缩到边界情况（重大目标变更、
纠错），日常推理不再需要 owner 介入 —— 攻击窗口的密度随之缩小。

架构这一侧的非 prompt 驱动路径（drift detector、`report.Status`
心跳、drift-triggered reload）就是为这一未来**预留位置**：等 agent
智能够了，owner 的 prompt 通道可以自然萎缩，而 trust model 这层
不必重新设计 —— Group A / B 框架保持不变，只是 Group B 的内容来
源由 "owner-prompted" 渐变为 "agent-self-driven"。

---

## 声誉如何补上这道缝

如果 sealed 没法证明内容正确，谁能？

**链上声誉系统。** 一个单独的合约（`AgenticIDReputationRegistry`）
随时间累积关于每个 agent 行为的结构化信号。verifier 在决定对一条
`serve-proof` 的内容下多大权重之前，**先**查声誉。

声誉信号来自：

| 信号 | 它告诉 verifier 什么 |
|---|---|
| **状态漂移频率** | 频率高 / 幅度大 → 更容易被操纵，置信度低 |
| **响应一致性** | 跨时间问同一个问题 → 答案漂移 = 不可靠 |
| **Verifier 反馈** | 对过往 serve-proof 的直接评分 |
| **owner 公开承诺** | owner 公开声明"这个 agent 走只读模式" + 匹配的链上行为 = 高置信度 |
| **跨 agent 声誉** | 名下有多个表现良好的 agent 的 owner 默认得到更多信任 |
| **资历** | 长期运行、行为稳定的 agent 赚到基线信任 |

来自高声誉 agent 的 `serve-proof`：内容权重高。来自全新或低声誉
agent 的 `serve-proof`：不论 proof 在密码学上多有效，内容权重低。

这跟世界其他地方运转的方式**完全一致**：

- 一份公证文件证明"这个人在这个时间签了字" —— 不证明文件内容是真
  的。我们根据签字人的声誉决定信任内容。
- 一张 TLS 证书证明"这台服务器控制这个域名" —— 不证明服务器诚实。
  我们根据服务器的品牌 / 历史行为来信任它。
- 一笔区块链 transaction 证明"这个地址签了这笔转账" —— 不证明这个
  地址代表你以为的那个人。我们根据地址的链上历史来信任它。

sealed 是公证人 / CA / signer-binding。声誉是品牌 / 历史行为这一
层，每个人都可以独立评估。

---

## 对 verifier 来说这意味着什么

如果你作为依赖方把 sealed agent 接进自己的系统，按两阶段实现信任
模型：

1. **验证 serve-proof** —— 给你上面 1-8 条形式保证。任意一项不通过，
   **直接拒绝响应**；sealed / TEE / 链这一侧出问题了。

2. **查声誉** —— proof 形式上有效之后，从
   `AgenticIDReputationRegistry` 取这个 agent 的声誉分。用这个分
   决定对响应内容下多大权重。

来自低声誉 agent 的形式有效 proof，**在内容层依然可疑**。别把
"proof 验过"等同于"内容是真的"。

> 看到现象不对、想知道是哪一层出锅、该不该算 sealed bug，对照
> [`QUIRKS.md` 故障定位表](../QUIRKS.md#故障定位serve-proof--sealed-运行时)。

---

## 对 owner 来说这意味着什么

owner 对 agent 行为有相当大的影响力 —— 这是设计如此，也是 LLM 现实
所致。和这种影响力一起来的是**声誉问责**：

- 每一次 iData 更新都提交上链。owner 没法在不留事件痕迹的情况下偷偷
  操纵 agent 的 persona / memory。
- 每一条 serve-proof 都携带响应时刻的 agent 状态，所以 verifier 可
  以关联"agent 说这话时处于什么状态"。
- 如果你的 agent 因为对抗行为声誉崩了，链上历史让人有可能把这次崩
  分归因到你的操纵模式上。

一句话：**架构信任你私下运行自己的 agent，但不保护你免于操纵不当的
后果**。市场来处理后果。

