# AgenticID Attestor

> AgenticID 协议的链下后端 —— 把 owner、TEE、链上合约这三个不同信任
> 域协调起来。

Attestor 代表 owner 发起 mint tx、给经过 RA 的 Agent TEE 派
`agent_seal_priv`、把每个 agent 的 iData 加密上传到 0G Storage，并把
链上索引实时同步给前端。在 trust chain 里它处于**链 ↔ TEE 之间的
中介**位置，本身也作为一个 Tapp app 注册在 TappRegistry 上（每把
`agent_seal_priv` 怎么由 KMS per-seal 派生、为什么没有常驻 master 见
[`../sealed/TRUST_MODEL.zh.md`](../sealed/TRUST_MODEL.zh.md)）。

三个 binary 共享一份 Postgres、对外暴露 HTTP + WebSocket：

- **api** — owner 入口（deploy / 生命周期）、容器 `/provision` +
  `/status` 接收、`/probe` 同步探活、WebSocket 实时事件推送
- **worker** — 异步任务消费者；跑 storage 加密上传 / mint tx /
  sandbox 生命周期；带 60s sweep loop（job retention + job reaper +
  provision deadline + heartbeat staleness）
- **indexer** — 链上事件监听 + AgentCard 重建；Postgres 落库后通过
  EventBus 推 WS 给前端

目前三个 binary 跑在一个节点上，但设计并不绑定单机：队列用
`FOR UPDATE SKIP LOCKED` 领活（`shared/src/jobs.rs`），任意多个
worker 可以共享；agentSeal 由 KMS per-seal 按需派生，任何节点都能 provision 任何 agent，节点
本地没有密钥状态。多节点**尚未实际跑过**——生产使用共享 KMS 稳定 app signer、
绑定实例的 AgenticID 授权与 gas；Postgres 从
per-host compose 里抽出来共享、以及 **indexer 保持单实例**（链上
checkpoint 是单写者，两个 indexer 会重复消费事件）。归属
node-federation 工作流。

job payload（owner 签名的 iData 明文、带 env 的 sandbox envelope）以明文
JSON 存储。一行只在 job 处于 pending 时持有 payload：claim 时清空，所有
在执行前就把 job 判失败的路径（payload 无法解码、owner envelope 已过期）
也会清空。落盘保护来自 tapp FDE 卷：`docker-compose.yml` 声明了
`x-tapp: data: encrypted`，Postgres 的 named volume 因此落在 app 由 KMS
加密的卷上。放在这个卷之外的 Postgres（例如多节点共享的那种）会以未加密
形式保存 pending payload。

worker 从不重新排队 job。job 运行期间每 30 s 刷新该行的 heartbeat；sweep
里的 reaper 会把 heartbeat 超过 5 min 的 running job（其 worker 已经不在）
以及 owner envelope 在 30 s 内过期的 pending `/start`、`/stop`、`/reset`
job（claim 也会跳过这些）标记为失败。对被放弃的 job，它把 `Submitted` 的
storage stage 置为失败（若是 deploy 或 clone，还包括它没来得及启动的
storage/mint stage），让 `/retry` 能恢复；给没有 provision deadline 的
`Submitted` 容器补上标准的 5 min deadline；`Submitted` 的 mint 一律不动，
它的交易由 `/retry` 按 receipt 对账。被 reap 的行会记录原因，直到这些后续
处理跑完为止：后续处理出错、或者执行 sweep 的 worker 先退出了，下一轮 sweep
都会重试，期间 retention sweep 也会保留这一行。只是卡住（而非退出）的
worker 会从下一次 heartbeat 得知自己的 job 已被 reap，随即放弃该 job；
`done`/`failed` 只会替换 `running`，所以它迟到的结果不会覆盖被 reap 的行。

从加密 job payload 的旧版本升级时，先排空队列：停掉 api 和 indexer 服务，
不再进新 job（indexer 从 checkpoint 继续，不会漏事件），worker 保持运行。
旧版 worker 开始一个 job 时打 `claimed job`，只在失败时再打一行
（`job failed`），所以当超过一个 job 可能运行的时长都没有新的 `claimed job`
行时，队列就排空了：留 15 分钟；如果最后 claim 的是带多个 iData 条目的
deploy，要留得更久（每个条目的上传预算是 750 s）。能连到数据库时，
`SELECT count(*) FROM jobs WHERE status IN ('pending','running')` 返回 0
即可确认。然后再升级。旧版本写入的 job 无法解码：pending 的会在 claim 时
判失败（`undecodable job payload`），running 的会被 reap（`job reaped`，
没有 `seal_id`），两者都不会结算它的 deployment，该 deployment 会一直停在
`deploying`，只能重新部署。从本版本起，worker 在每行 `claimed job` 之后都会
打 `job done` 或 `job failed`（或由 reaper 记为已 reap），以后排空队列只看
worker 日志即可。

### 升级到 AgentDNA 1.4

1.4 同时改变 provider 证书（v3）、attestor TLS 声明和 `/provision` 请求，不兼容旧版本：
每个 agent 都需要新容器。按顺序执行，每一步的检查通过之后再继续。

1. **镜像。**为每个框架构建 sealed 镜像，注册为 provider snapshot，并用
   `addValidFrameworkHash` 加入其镜像哈希。检查：每个镜像的
   `isValidFrameworkHash(<hash>)` 都返回 `true`。
2. **配置。**把 `ATTESTOR_SANDBOX_SNAPSHOT` 和 `ATTESTOR_FRAMEWORKS` 指向新的
   snapshot，使用本版本发布的框架名。检查：升级后 `GET /config` 列出每个框架及其新
   snapshot。
3. **暂停并排空。**公告一个窗口，期间 owner 不部署也不 reset：provider 与 attestor
   版本不一致时 create 会失败，无论哪一方先升级。按上文排空 job 队列。
4. **在该窗口内升级 provider 和 attestor。**检查：`GET <provider>/api/attestor-tls`
   返回 200，`GET <ATTESTOR_URL>/attestor-tls?provider=<provider signer>` 返回 200，
   且 api 日志出现 `attestor tls self-check: provider statement verified`。自检只在
   api 启动时运行一次：如果 attestor 先于 provider 提供声明启动，自检记录的是
   `attestor tls self-check: no valid provider statement`。此时上面的转发请求会加载声明，
   并记录 `attestor tls: provider statement refreshed`，同样算检查通过（重启 api 会重新
   自检）。provider 报 `attestor instance requires explicit re-authorization` 说明它保存的
   attestor 实例已过期：先按 sandbox provider 的 `docs/APP_IDENTITY.md` 重新授权该实例
   再继续。
5. **每个框架 reset 一个。**每个框架各 reset 一个 agent，等到 `running`。sealed 日志
   出现 `attestor tls: statement accepted` 和 `OK   status reported`。被拒的 provision
   会出现在 api 日志里（`provision rejected`），也是该 agent 容器 stage 上的原因。
6. **公告。**owner reset 自己的 agent。1.4 之前创建的 sandbox 不能 resume
   （`/start` 带 `start`），会得到 409，因为那个运行时无法 provision。preflight 要求时，
   owner 需重新确认 provider（SDK `ack()`）。请 owner 错开 reset：worker 一次只跑一个
   job，签名后约 150 s 内没开始执行的 reset 会被丢弃，agent 保持原样。控制台显示
   `request expired before it ran — sign it again`；CLI 会一直等新容器直到超时，然后提示
   agent 没有上线、请重新 reset。

**回滚。**1.4 attestor 是单向的：它的 schema 删除了 1.3 attestor 要读的列
（`inference_provider_registry.acceptance_mac`、`deployments.container_pubkey_mac`），
在同一数据库上启动的 1.3 attestor 读不了 provider registry；它也无法验证 1.4 创建的容器
的 v3 证书，也解码不了 1.4 的 job。某一步检查失败时，按该步的处理方法向前修复，不要重新
部署 1.3 镜像。

## Workspace

```
attestor/
├── Cargo.toml                Rust workspace
├── crates/
│   ├── shared/               types / traits / chain / sandbox / crypto / repo / mocks
│   ├── api/                  HTTP + WS server + 静态 web/ 资源
│   ├── worker/               异步任务 + 60s sweep loop
│   └── indexer/              链上事件监听
├── scripts/                  e2e / verify-agent / regression 测试脚本
├── version-meld/             vendored crate 修复，经 [patch.crates-io]（Cargo.toml）接入，Dockerfile 会拷进构建
├── docker-compose.yml        api / worker / indexer / postgres 全栈（`x-tapp: data: encrypted`；Postgres 不对外发布）
├── docker-compose.dev.yml    本地 overlay：把 Postgres 发布到 127.0.0.1:5432，供裸跑的 binary 使用
├── Dockerfile                三 binary 共用镜像（cargo build --release 多入口）
└── .env.example              所有运行时配置
```

## 本地开发

容器化（推荐，跟生产对齐）：

```bash
docker compose build                                # 重 build 三个 binary
docker compose up -d                                # 起 postgres + 3 个 attestor binary
docker compose logs -f attestor-api                 # 看 api 日志
```

Postgres 只在 compose 网络内可达，不会发布到宿主机。

本地构建注意：compose 里设了 `pull_policy: always`，且 `image:` 默认值
（`ATTESTOR_IMAGE`）指向一个 VPC 内网 Aliyun registry tag——出了那个
VPC 默认 registry 根本不可达；而在可达的环境里，`up -d` 会重新拉取
registry 镜像、覆盖你刚 `docker compose build` 出来的本地产物。要真正
跑本地构建，先把 `ATTESTOR_IMAGE` 设成本地构建的 tag（registry 上不存
在的名字），或改掉 `pull_policy` 再 `up -d`。

非容器（裸跑，开发调试用）：

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d postgres   # 只起 Postgres，监听 127.0.0.1:5432
cp .env.example .env && vim .env                    # 填真实 chain / app_id / addr
cargo run -p attestor-api    # 一个终端
cargo run -p attestor-worker # 另一个终端
cargo run -p attestor-indexer# 第三个终端
```

## HTTP 接口

按类别分：

### 静态 / UI

| 路径 | 干什么 |
|---|---|
| `GET /` | 内嵌的 deploy 控制台 SPA |
| `GET /static/ethers.js` | 内嵌的 ethers.js 资源（前端用，不走 CDN）|
| `GET /avatar/default.svg` | 默认 agent 头像（确定性 pixel-art，部署预览用）|
| `GET /avatar/:seed.svg` | 按 32-byte hex seed 派生头像（agent card 等场景）|

`ATTESTOR_CONSOLE_ENABLED=false`（headless 模式）时，`GET /` 和
`/static/*` 返回 404——只有 avatar 路由和下面的 HTTP API 保持可用。

### 健康 / 配置

| 路径 | 干什么 | 鉴权 |
|---|---|---|
| `GET /health` | 进程级 liveness probe | — |
| `GET /config` | 链 RPC / 合约地址 / appId / snapshot 等前端要的公开配置 | — |
| `GET /inference/providers` | 带版本的 provider 注册表；可用 `?version=N` 读取经接受凭据校验的历史版本，供 stop/start 保持旧路由；内置初始名单为版本 0 | 公开 |
| `PUT /admin/inference/providers` | 通过 HTTP 发布完整名单，Postgres 留存历史并校验版本，无需 SSH 或重启，见 [运维流程](../sdk/typescript/PROVIDERS.zh.md) | attestor Tapp 当前 owner 签名（EOA/EIP-1271） |

### 生命周期（owner-driven）

| 路径 | 干什么 | 鉴权 |
|---|---|---|
| `POST /deploy` | 用户部署 agent | owner EIP-191 + sandbox envelope EIP-191 |
| `POST /clone` | 源 owner 为另一 owner 铸一个全新 agent，复用源的链上 iData（dataKey 重封给新 agentSeal）；落 Offline，由新 owner 自行上线 | owner EIP-191，校验签名者 == **链上实时 `ownerOf(source)`**（非自声明 owner） |
| `POST /start` / `/stop` / `/retry` / `/reset` | 启停 / 重试 / 重置。只有当前启动票据为其签发的 sandbox 才能 `start`（resume），否则返回 `409`：AgentDNA 1.4 之前创建的 sandbox（没有启动票据，或票据没有签发时间），以及 reset 的 create 失败后仍留在记录上的旧 sandbox，都无法 provision，需 reset | owner envelope，签名校验到链上 owner（`/retry` 不带 envelope 时仅限幂等的 attestor 侧重跑，靠 owner 字段匹配把关）|
| `GET /settings?seal_id=0x…` | owner 读自己的配置文档，连带当前 `version`（下一次写要签的 base）。文档是 owner 的，不进任何公开层——只有这一条路能读。响应还带 `confirmed_version` / `attempts` / `fallback_active`：客户端据此告诉 owner「上次推送没起来、agent 正跑着上一份文档、再推一次就是重试」| owner 对 `AgenticID.Settings.v1:0x<sealId>:<ts>:<base version>` 的 EIP-191 签名（放 `X-Auth-Message`），校验到**链上实时 owner** |
| `POST /settings` | owner 写 agent 的那一份配置文档。attestor 只当**不透明 blob** 存：不解析、不校验、不打日志，所以扩配置词表永远不用改 attestor。不上链——配置可随时重给，记忆不行。写是 compare-and-swap：base version 过期就 409 带 `current_version`，于是抓包重放回不去旧文档，两个客户端也不会互相无声覆盖 | owner 对 `AgenticID.Settings.v1:0x<sealId>:<ts>:<base version>:<文档 sha256>` 的 EIP-191 签名（放 `X-Auth-Message`），校验到**链上实时 owner** |
| `POST /probe` | 同步探活：失联容器 flip 到 `Failed`；sandbox 仍保留但没在跑的 flip 到 `Stopped`（可 Resume）| 无 |

### 容器对接（agent runtime → attestor）

| 路径 | 干什么 | 鉴权 |
|---|---|---|
| `GET /provision?seal_id=…` | 返回 `{"generation", "certificate_required"}`：已启用的启动代次（不返回票据），以及当前是否尚未记录容器公钥、下一次启动必须携带证书。没有已启用的授权时返回 `403 no authorized boot; reset required` | 公开元数据 |
| `GET /attestor-tls?provider=0x…` | 原样（逐字节）转发 sandbox provider 对本 attestor TLS SPKI pin 的最新签名声明（EIP-712 `AttestorTLS`，取自已发现 provider 的 `/api/attestor-tls`）。转发前检查 provider 签名、租期（最长 300 秒）以及本 attestor 自己的 TLS 公钥在 pin 中；到期前 60 秒刷新，声明到期前 15 秒停止下发（sealed 要求剩余超过 5 秒），且只在刷新时询问 sandbox discovery，因此 discovery 续期或不可用不会阻塞或拒绝缓存能回答的请求。未知 provider → 404；没有有效声明 → 503 并带 `Retry-After: 5`。始终 `Cache-Control: no-store`。每份新声明都会打日志；api 启动时取一次并记录结果。sealed 之后对 attestor 的所有连接都钉在这些 pin 上 | 公开 |
| `POST /provision` | 容器领取 ECIES 加密的 `agentSeal_priv`、owner 配置文档，以及不透明的单次启动状态令牌（`encrypted_status_binding`，明文 `{"token":"<64 hex>"}`；只存其 SHA-256，旁边记录实际下发的配置版本和摘要）。**首次启动**携带 v3 证书（`certificate`：`SANDBOX_SEAL_ATTESTATION` 对象，provider 密钥签的 EIP-712 `ImageAttestation`）。attestor 要求签名者与 scope 是已发现的 provider 实例，签发时间在启动票据之前 300 秒到当前时间 + 300 秒之间，镜像在 `validFrameworkHashes` 中，且公钥是 provider 为本 attestor 在当前票据下创建的 sandbox 所报告的公钥（`401 certificate is not for the sandbox this attestor created; reset required`），然后记录容器公钥、镜像和 provider 实例。**之后的启动**不带证书：由已记录的公钥签 boot claim，已记录的 provider 实例必须仍是当前发现的实例（否则 `403 provider instance no longer trusted; reset required`），已记录镜像仍须在白名单中（否则 `401 recorded image_hash not in validFrameworkHashes; reset required`）。没有记录也没有证书 → `409 certificate_required`；证书对应另一把公钥 → `403 container key differs from record; reset required`。每个请求都带 owner 授权的票据、启动代次和容器公钥签名的 boot claim，`boot_started_at` 必须严格递增；create 尚未落库时返回 409。拒绝的请求不删除容器；对已授权启动的 401/403 会打日志（`provision rejected`），在该代次仍有效时记为 `last_provision_error`，并立即把容器 stage 置为 `failed`（发布 `container_failed`）。未确认配置多次启动后回退至 last-known-good（同一次启动的重试算同一次尝试）| provider 签名的证书（首次启动）或已记录的容器公钥 + owner 授权的票据、启动代次和容器公钥签名的 boot claim |
| `POST /status` | sealed 心跳与状态（`StatusReport.v2` canonical）。签名覆盖状态令牌哈希和实际使用的配置摘要；在一个事务里检查令牌属于当前启动，再更新状态、心跳与精确版本确认。只有实际使用的配置摘要等于该次启动下发摘要的 `running` / `warning` 上报才能提升配置；旧容器上报被忽略，`error` 不改配置 | agentSeal 原始 keccak 签名 + 当前状态令牌 |
| `POST /settings/seed` | 容器把从旧 config role 里捞回来的配置文档交还 attestor，保证重建容器后不丢。仅播种且一次性：只在 `settings_version = 0` 时落库；行上没有 sandbox 记录时直接忽略（幽灵容器——这个 agent 历史上每个容器都握着 agentSeal 私钥）| agentSeal 对 `SettingsSeed:0x<sealId>:<sha256>` 的签名 |

### 读 / 实时

| 路径 | 干什么 |
|---|---|
| `GET /deployments` | 列出当前 deployment |
| `GET /deployment/:seal_id` | 单条 deployment 详情（无需认证；不返回 settings 文档、容器记录、iData 重试材料） |
| `GET /agent-seal-pubkey?seal_id=` | agent 的 agentSeal 公钥。SDK（以及本 console 的 Restore/Reset）用它加密推理 key（`SEAL_SECRET_ENV`），owner 钱包签名弹窗里不再出现明文 key（issue #166）。只回答已知 seal_id；按 seal 缓存，并限制同时进行的 KMS 派生数量 |
| `GET /ws/subscribe` | WebSocket 事件流（indexer / worker 通过 EventBus 推 ） |

详细签名 canonical 见 `crates/shared/src/auth/`；v3 容器证书和 attestor TLS 声明见
`crates/shared/src/image_attestation.rs` 与 `attestor_tls.rs`，与 provider、sealed
共用的 known-answer 向量在 `crates/shared/testdata/`。

## 链上依赖

| 合约 | 用途 |
|---|---|
| **AgenticID** | NFT mint、iData 注册、`validFrameworkHashes` 白名单 |
| **VerifiedFeedbackRegistry** | 验证 ServeProof——agentSeal 的 EIP-191 version 0x00 签名 `keccak256(0x19 ‖ 0x00 ‖ validator ‖ proofHash)`，validator = 本 proxy——并在官方 ERC-8004 reputation registry 之上记录 TEE 标记。attestor 从不写它：只在 `GET /config` 公布地址，并作为 `VERIFIED_FEEDBACK_ADDR` 注入每个新容器（`ATTESTOR_VERIFIED_FEEDBACK_ADDR`）；唯一的读取在 worker / api 启动时——`getIdentityRegistry()` 必须等于 `ATTESTOR_AGENTIC_ID_ADDR`，否则启动失败 |
| **TappRegistry** | attestor / 0g-kms / 0g-sandbox-provider 三个 Tapp app 的代码身份 + 节点签名注册表，也是 provider 证书与 TLS 声明的 EIP-712 `verifyingContract`；`/provision` 用已认证的 sandbox discovery 校验证书签名者与注册 scope |
| **SandboxServing** | sandbox 预付费余额 + voucher 结算；前端 deploy gate 要求 owner 余额 ≥ 0.1 OG |

合约部署 / 升级 / verify 见 [`../contracts/README.md`](../contracts/README.md) §10。

## 关键配置

完整列表在 `.env.example`（约 40 项有效配置，另有若干注释掉的可选项），下面按类别列出 load-bearing 的。

### Chain 接入

| env | 含义 |
|---|---|
| `ATTESTOR_CHAIN_RPC` / `ATTESTOR_CHAIN_ID` | 0G 链 RPC + chainId。RPC URL 是公开的（`GET /config` 会返回它，agent 的启动日志也会打印它），所以不能内嵌凭据；见 `.env.example` |
| `ATTESTOR_AGENTIC_ID_ADDR` | AgenticID 合约地址 |
| `ATTESTOR_VERIFIED_FEEDBACK_ADDR` | 绑定该 AgenticID 的 VerifiedFeedbackRegistry **proxy**。在 `GET /config` 公布，并作为 ServeProof validator 以 `VERIFIED_FEEDBACK_ADDR` 注入每个新容器。留空或为零地址 ⇒ `/config` 不公布该地址，容器拿到空值，因而不发 `X-Agent-Proof`；填了但不是地址则启动失败，其 `getIdentityRegistry()` 不是 `ATTESTOR_AGENTIC_ID_ADDR` 也启动失败（worker 和 api 启动时各读一次）。容器 env 只在创建时写入，改值需要逐个重建 agent（owner 签名的 `/reset`）|
| `ATTESTOR_CANONICAL_8004_ADDR` | 官方 ERC-8004 IdentityRegistry（可选；按 chainId 自动选——主网 `0x8004A169…`、测试网 `0x8004A818…`）|
| `ATTESTOR_TAPP_REGISTRY_ADDR` | TappRegistry 合约地址 |
| `ATTESTOR_PRIORITY_FEE_GWEI` / `ATTESTOR_MAX_FEE_GWEI` | EIP-1559 gas 上下界（0G testnet `priority` 最低 2）|

### Tapp 身份 + KMS

| env | 含义 |
|---|---|
| `ATTESTOR_APP_ID` | attestor 自己在 TappRegistry 注册的 appId |
| `ATTESTOR_KMS_APP_ID` / `ATTESTOR_SANDBOX_APP_ID` | 信任的另外两个 Tapp app（trust-roots ack 用）|
| `ATTESTOR_TAPP_IP` / `ATTESTOR_TAPP_PORT` | tapp-server 本地 gRPC 端点（稳定 app signer 与按 `material` 逐 seal 派生的 KMS key；生产签名与身份发现要求本地 socket）；docker 里通过 `host.docker.internal` 解到宿主 |
| `MOCK_TEE` / `MOCK_KMS` | dev mock 开关 |
| `MOCK_APP_PRIVATE_KEY` / `MOCK_APP_ETH_ADDRESS` | `MOCK_TEE=true` 时必填；私钥需推得出地址（启动校验）|
| `MOCK_APP_SECRET` | `MOCK_KMS=true` 时必填，32 字节 hex；三个 binary 必须读到**同一个值**否则派生分叉 |

### Sandbox + SandboxServing

| env | 含义 |
|---|---|
| `ATTESTOR_SANDBOX_PROVIDER_ADDR` | 仅开发覆盖（`MOCK_TEE=true`）；生产按 sandbox appId 发现 app_signer |
| `ATTESTOR_SANDBOX_SERVING_ADDR` | SandboxServing 合约地址（前端 deploy gate 查 owner 余额 ≥ 0.1 OG 用）|
| `ATTESTOR_SANDBOX_ENDPOINT` | Dev-only locator; production uses the authorized on-chain HTTPS URL |
| `ATTESTOR_SANDBOX_SNAPSHOT` | 实例化新 agent 用的 sealed runtime snapshot 名（升 image 时改这里）|
| `ATTESTOR_SANDBOX_PUBLIC_PORTS` | 逗号分隔的公开端口白名单（0g-sandbox#57）。设置后 sandbox create 会带上 `publicPorts`，只有名单内端口对外可达，其余回落到 Daytona 认证。必须包含 agent 服务端口（8080）。留空 = 全端口公开——在 provider 切到 0g-daytona fork 镜像之前，这是唯一安全的取值 |
| `ATTESTOR_SUPPORTED_FRAMEWORKS` | 逗号分隔的可选框架名单——铸造前在 deploy 边缘校验，并经 `GET /config` 提供给前端框架选择器。必须与 `ATTESTOR_SANDBOX_SNAPSHOT` 指向的 sealed 镜像实际打包的 adapter 一致。不设/为空 = 默认 `openclaw` |
| `ATTESTOR_SECRET_ENV_ENABLED` | 显式开启（`true`/`1`/`on`/`yes`）。开启后 `GET /config` 公布 `secret_env_scheme`，SDK 在 start/reset/retry 时把推理 key 加密给 agentSeal 公钥，而不是明文签进 envelope。只有当 `ATTESTOR_SANDBOX_SNAPSHOT` / `ATTESTOR_FRAMEWORKS` 里所有镜像都能读 `SEAL_SECRET_ENV` 时才开启。默认关闭 |
| `ATTESTOR_PUBLIC_URL` | attestor 自己的外网 URL，注入到 sandbox 容器的 `ATTESTOR_URL`（去掉末尾 `/`）；要让容器能 POST `/provision` 和 `/status` 回来 |
| `MOCK_SANDBOX` | dev mock 开关；`true` 时不真起容器、只 log |

attestor 与已配置 sealed 镜像统一发布。`/config.inference_capabilities` 根据本版本及已有 framework/snapshot 配置自动生成，不另设能力 ENV。provider 运维写入由 `ATTESTOR_TAPP_REGISTRY_ADDR` 中 `ATTESTOR_APP_ID` 的实时 owner 授权，见 [上线流程](../sdk/typescript/PROVIDERS.zh.md)。

### Storage（0g-storage）

| env | 含义 |
|---|---|
| `ATTESTOR_STORAGE_INDEXER` | 0g-storage indexer URL（dataKey 加密包上传目标）。它是公开的（记进每个 iData 条目的链上 `dataDescription`，agent 的启动日志也会打印它），所以不能内嵌凭据；见 `.env.example` |
| `MOCK_STORAGE` | `true` 用 keccak256 替代真 merkle root，不上传；`false` 走真 SDK（稳定 app signer 需要所配置 0G 链上的 gas）|

### 数据库 / 进程

| env | 含义 |
|---|---|
| `ATTESTOR_DB_URL` | Postgres 连接串 |
| `ATTESTOR_BIND` | HTTP listen，默认 `0.0.0.0:8080` |
| `ATTESTOR_JOB_RETENTION_SECONDS` | 完成 / 失败 job 的保留时长（sweep 周期性清理），默认 3600 |
| `ATTESTOR_INDEXER_START_BLOCK` | indexer 首次扫描起点；空 → `latest-128` |
| `RUST_LOG` | 日志 filter |

### Agent runtime URL 拼装

容器对外 URL 形如 `http://<port>-<sandbox_id>.<proxy_addr><path>`，下面四项决定 path / port：

| env | 含义 |
|---|---|
| `ATTESTOR_SANDBOX_PROXY_ADDR` | sandbox proxy 的公共域名（nip.io 风格，如 `sandbox.example:4000`）|
| `ATTESTOR_AGENT_SERVE_PORT` + `ATTESTOR_AGENT_SERVE_PATH` | agent 对外服务入口（写进链上 tokenURI 作为 AgentCard `url`，**8004 里 "A2A" 指 AgentCard 本身、不是这个 path**，所以这里别用 "A2A" 名字）|
| `ATTESTOR_AGENT_DASHBOARD_PORT` + `ATTESTOR_AGENT_DASHBOARD_PATH` | owner-only operator dashboard 入口（deploy console 用）|

### AgentCard 资源（Ali OSS）

| env | 含义 |
|---|---|
| `OSS_ACCESS_KEY_ID` / `OSS_ACCESS_KEY_SECRET` | OSS 凭证；空就 deploy 失败 |
| `OSS_BUCKET` / `OSS_REGION` | bucket + 区域 |
| `OSS_KEY_PREFIX`（可选）| 默认 `0x<AGENTIC_ID_ADDR>`，按合约地址 namespace |

## 测试

```bash
cargo test --workspace              # 全量
cargo test -p attestor-shared       # 单 crate
```

所有测试都在内联 `#[cfg(test)]` 模块里（没有独立的 `tests/` 目录，
`--test '*'` 匹配不到任何东西），用 InMemory 实现（`mocks.rs`）绕过
Postgres / chain / sandbox 依赖，单测从 6s 起。

完整回归流程（本地全 mock、testnet 实测、故障速查表）见
[TESTING.md](TESTING.md)——`scripts/e2e.sh` 负责部署，
`scripts/verify-agent.sh` 负责验证。

实测脚本从部署记录或 SDK 获取容器 URL，并以 owner 身份读取启动日志。
CLI smoke 使用临时配置目录。clone/transfer 测试把生成的钱包私钥保存到
临时目录（或 `TEST_ARTIFACT_DIR` 下），文件权限为 `0600`，便于失败后恢复
测试资产；测试结束后应停止对应容器。

稳定应用身份、生产合约迁移与 TEE TLS 部署见 [APP_IDENTITY.zh.md](APP_IDENTITY.zh.md)。
