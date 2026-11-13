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

sweep 还会把容器已经 15 min 没有发 `/status` 的 running deployment 与它的 sandbox
对账。provider 给出答复时以它为准：sandbox 已删除则把 agent 标为 failed；sandbox 处于
`error` 则标为 failed 并删除 sandbox；其他非运行状态标为 stopped，owner 可以 resume。
sandbox 处于 started，或 provider 查不到它的状态时，由 agent 的 `/healthz` 决定：
不可达就把 agent 标为 failed 并删除 sandbox。这个判断依赖心跳过期，所以只适用于本可以
上报的容器。首次 provision 不是在 0.4 下完成的容器无法上报：attestor 拒绝它的上报。
对这样的容器只看 provider 的答复；不会探测它，也不会因为不可达而删除它。0.4 容器只有在
provider 提供有效的 attestor TLS 声明（sealed 用它 pin 这个 attestor）时才能上报。
因此 worker 每轮 sweep 都向 provider 取这份声明，只有在过去 15 min 的每次检查中
provider 都提供了它，才把过期心跳当作故障；每次 worker 启动后也要先等这 15 min。
provider 故障期间，running 的 agent 因此保持 running，不会被标为 offline。provider
自己的答复不受这个等待影响。

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

### 升级到 AgentDNA 0.4

0.4 同时改变 provider 证书（v3）、attestor TLS 声明和 `/provision` 请求，不兼容旧版本：
每个 agent 都需要新容器。按顺序执行，每一步的检查通过之后再继续。

开始第 1 步之前，要升级的 attestor、sealed 和 provider 镜像必须是用发布分支头构建、并已在
dev 上通过发布测试计划的那几个：记下它们的 digest，并且只升级这些 digest。第 4 步的升级是
单向的，第一次线上 provision 发生在第 5 步，所以没有在 dev 上跑过的改动会在所有 agent 都已
下线之后才第一次遇到线上 provider。

1. **镜像。**为每个框架构建 sealed 镜像，注册为 provider snapshot，并把其镜像哈希
   列入信任注册表（AgenticID 1.4.0 起在 TrustRegistry 上调
   `list(keccak256("image"), <hash>)`，经拥有该注册表的本环境 Timelock 排期执行，
   mainnet 要等 1 天；更早的 AgenticID 上用 `addValidFrameworkHash`）。
   0g-harness 镜像不带 sealed，也不带 harness 包：用它的 Dockerfile 构建这两样（导出命令
   写在 `sealed/images/harness/Dockerfile` 开头），以各自的 sha256 命名附到
   `0gfoundation/0g-agentic-id` 的 `artifacts` 发布（release）上，并在这个镜像的任何容器
   启动之前列入它们的哈希（`keccak256("sealed")`、`keccak256("harness")`）：在那之前它
   什么都不运行。检查：每个镜像的 `isValidFrameworkHash(<hash>)` 都返回 `true`，sealed 和
   harness 哈希的 `isListed` 返回 `true`，且
   `https://github.com/0gfoundation/0g-agentic-id/releases/download/artifacts/<sha256>`
   能取到两个文件。
2. **配置。**在第 4 步升级 attestor 之前，把 `ATTESTOR_SANDBOX_SNAPSHOT` 和
   `ATTESTOR_FRAMEWORKS` 指向新的 snapshot，使用本版本发布的框架名。harness 框架现在叫
   `0g-harness`：仍写着 `dsh` 的条目（testnet 上是 `dsh:0g-sealed-dsh`）会让 api、
   worker 和 indexer 启动失败，需替换为 `0g-harness:<新的 0g-harness snapshot>`。检查：
   升级后 `GET /config` 列出每个框架及其新 snapshot。
3. **暂停并排空。**公告一个窗口，期间 owner 不部署也不 reset：provider 与 attestor
   版本不一致时 create 会失败，无论哪一方先升级。同一公告中说明：第 4 步 provider 升级时
   所有 agent 都会下线，并一直保持下线，直到 owner 在第 7 步之后 reset。按上文排空 job
   队列。
4. **在该窗口内升级 provider 和 attestor。**检查：`GET <provider>/api/attestor-tls`
   返回 200，`GET <ATTESTOR_URL>/attestor-tls?provider=<provider signer>` 返回 200，
   且 api 日志出现 `attestor tls self-check: provider statement verified`。自检只在
   api 启动时运行一次：如果 attestor 先于 provider 提供声明启动，自检记录的是
   `attestor tls self-check: no valid provider statement`。此时上面的转发请求会加载声明，
   并记录 `attestor tls: provider statement refreshed`，同样算检查通过（重启 api 会重新
   自检）。provider 报 `attestor instance requires explicit re-authorization` 说明它保存的
   attestor 实例已过期：先按 sandbox provider 的 `docs/APP_IDENTITY.md` 重新授权该实例
   再继续。
5. **每个框架 reset 一个。**每个框架各 reset 一个 agent，等到 `running`。用 0.2.2 CLI，
   并用 owner 会用来 reset 的其他每个客户端各做一次：提供内嵌 console 时用 console
   （headless attestor，即 `ATTESTOR_CONSOLE_ENABLED=false`，不提供 console），以及任何
   web 前端。每个客户端各自构造 create 请求，请求必须带上 provider（`provider`，取自
   `GET /config` 的 `sandbox_provider_addr`）和该 agent 框架的镜像（取自 `GET /config`
   的 `frameworks[]`）。缺少 provider 时 worker 会拒绝 create（`owner envelope targets another provider`）；
   用了其他框架的镜像时，该 agent 的框架无法启动。sealed 日志
   出现 `attestor tls: statement accepted` 和 `OK   status reported`。被拒的 provision
   会出现在 api 日志里（`provision rejected`），也是该 agent 容器 stage 上的原因。
6. **发布 SDK。**AgentDNA 0.4 的第一个 CLI 是 `@0gfoundation/0g-agentdna` 0.2.2（从 0.4.0 起，版本号跟随发布号）。npm 上已有的版本
   （0.2.0、0.2.1）早于它：它们的 `reset` 可能在 worker 替换容器之前就从 AgenticID 1.3 容器读到
   `running` 并报告完成，部署向导也不会把 0g-harness agent 限定为支持工具调用的模型。
   按[发布顺序](../sdk/typescript/MIGRATION.zh.md#发布顺序)发布 0.2.2 及其兼容包，
   使用 `next` dist-tag。dist-tag 由所有网络共用，而 `0g-agentdna update` 和普通安装都取
   `latest`，所以 `latest` 保持在仍在 AgenticID 1.3 的网络所用的版本上（mainnet 在其自身的 0.4 升级
   之前即是如此），等所有网络都运行 0.4 后再指向 0.2.2。在正在升级的网络上设置
   `ATTESTOR_CLI_LATEST=0.2.2`，以及一行 `ATTESTOR_CLI_NOTES`，提醒 CLI 用户在 reset 前
   先执行 `npm install -g @0gfoundation/0g-agentdna@0.2.2`（`update` 会装 `latest`），
   并重启 api。检查：`npm view @0gfoundation/0g-agentdna dist-tags.next` 输出 `0.2.2`，
   `dist-tags.latest` 不变，`GET /config` 显示 `"cli_latest":"0.2.2"`。
7. **公告。**使用 CLI 的 owner 先更新（`npm install -g @0gfoundation/0g-agentdna@0.2.2`）。公告里要写明这条安装命令：0.2.2 之前的 CLI 会提示 `update available … 0g-agentdna update`，而 `update` 装的是 `latest`，不是 0.2.2。CLI 需要 Node.js 18 或更高版本，在 Node 16 上会报 `fetch is not defined`。然后 owner reset 自己的
   agent。容器创建于 0.4 之前的 agent 自第 4 步起都已下线，显示为 `stopped`，只有 reset
   才能恢复：0.4 之前创建的 sandbox 不能 resume（`/start` 带 `start`），会得到 409，因为
   那个运行时无法 provision。preflight 要求时，owner 需重新确认 provider（SDK `ack()`）。
   请 owner 错开 reset：worker 一次只跑一个 job，签名后约 150 s 内没开始执行的 reset
   会被丢弃，agent 保持原样。控制台显示 `request expired before it ran — sign it again`；
   0.2.2 的 CLI 会一直等新容器直到超时，然后提示 agent 没有上线、请重新 reset。

   第 4 步 provider 升级时会 archive 所有运行中的 sandbox，所以容器创建于 0.4 之前的
   agent 从那时起都已停止。心跳过期 15 min 后，sweep 发现它的 sandbox 已 archive，把它
   标为 `stopped`。它已提交到链上和存储中的状态都保留，reset 即可恢复。仍在运行的 0.4
   之前创建的容器（provider 没有 archive 它）同样无法上报：0.4 attestor 拒绝它的状态上报
   （其 token 格式早于 0.4）。sweep 对它只按 provider 的答复处理（已删除、`error`、
   stopped 或 archived），否则保持 `running`；不会因为不可达而探测或删除它。

**回滚。**0.4 attestor 是单向的：它的 schema 删除了 AgenticID 1.3 attestor 要读的列
（`inference_provider_registry.acceptance_mac`、`deployments.container_pubkey_mac`），
在同一数据库上启动的 AgenticID 1.3 attestor 读不了 provider registry，且 `dsh` 行已改名为
`0g-harness`；它也无法验证 0.4 创建的容器的 v3 证书，也解码不了 0.4 的 job。某一步检查失败时，按该步的处理方法向前修复，不要重新
部署 AgenticID 1.3 镜像。

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
| `POST /deploy` | 用户部署 agent。sandbox envelope 的 `env` 含 `API_KEY` / `SEAL_SECRET_ENV` 以外的键时返回 `400` 并指出该键。带 `await_credentials: true`（与其余字段一起签名）时，等 agent 的凭据集存好再创建容器；没等到时，mint 完成 10 秒后创建，mint 失败则立即停止等待、不创建容器，最多等 60 秒：SDK 在部署被接受后立即把模型 key 存进凭据集，立即创建的容器会先于它启动 | owner EIP-191 + sandbox envelope EIP-191 |
| `POST /clone` | 源 owner 为另一 owner 铸一个全新 agent，复用源的链上 iData（dataKey 重封给新 agentSeal）；落 Offline，由新 owner 自行上线 | owner EIP-191，校验签名者 == **链上实时 `ownerOf(source)`**（非自声明 owner） |
| `POST /start` / `/stop` / `/retry` / `/reset` | 启停 / 重试 / 重置。只有当前启动票据为其签发的 sandbox 才能 `start`（resume），否则返回 `409`：AgentDNA 0.4 之前创建的 sandbox（没有启动票据，或票据没有签发时间），以及 reset 的 create 失败后仍留在记录上的旧 sandbox，都无法 provision，需 reset。envelope 的 `resource_id` 不是该部署当前 sandbox 的 `start` 或 `stop` 同样返回 `409`（API 与 worker 都会检查），因此 reset 之前留存的 sandbox id 不会以该 agent 的名义被启动或停止。create envelope（reset、首次 provision 的 `start`、带 envelope 的 `retry`）的 `env` 含 `API_KEY` / `SEAL_SECRET_ENV` 以外的键时返回 `400` 并指出该键，不会排入任何任务 | owner envelope，签名校验到链上 owner（`/retry` 不带 envelope 时仅限幂等的 attestor 侧重跑，靠 owner 字段匹配把关）|
| `GET /settings?seal_id=0x…` | owner 读自己的配置文档，连带当前 `version`（下一次写要签的 base）。文档是 owner 的，不进任何公开层——只有这一条路能读。响应还带 `confirmed_version` / `attempts` / `fallback_active`：客户端据此告诉 owner「上次推送没起来、agent 正跑着上一份文档、再推一次就是重试」| owner 对 `AgenticID.Settings.v1:0x<sealId>:<ts>:<base version>` 的 EIP-191 签名（放 `X-Auth-Message`），校验到**链上实时 owner** |
| `POST /settings` | owner 写 agent 的那一份配置文档。attestor 只当**不透明 blob** 存：不解析、不校验、不打日志，所以扩配置词表永远不用改 attestor。不上链——配置可随时重给，记忆不行。写是 compare-and-swap：base version 过期就 409 带 `current_version`，于是抓包重放回不去旧文档，两个客户端也不会互相无声覆盖 | owner 对 `AgenticID.Settings.v1:0x<sealId>:<ts>:<base version>:<文档 sha256>` 的 EIP-191 签名（放 `X-Auth-Message`），校验到**链上实时 owner** |
| `GET /credentials?seal_id=0x…` | owner 读取 agent 的凭据集（定义；值只以加密给 agent 的密文出现）、写回，以及下一个凭据集要签的所有权纪元。见 `sealed/CREDENTIALS.zh.md` | owner 对 `AgenticID.Credentials.v1:0x<sealId>:<ts>:0` 的 EIP-191 签名，校验到**链上实时 owner**；mint 之前校验到部署记录里的 owner（mint 给到的地址） |
| `POST /credentials` | owner 存入新的凭据集（owner 签的 EIP-712 `CredentialSet`，这里校验：agent、纪元、版本、每个定义和值的 hash）。按版本号比较并交换（409 带 `version`、`owner_epoch`）；新凭据集里仍带 `writeback: true` 的条目，其写回一并保留（只有仍绑定同一个值或登录时，sealed 开机才使用它） | owner 对 `AgenticID.Credentials.v1:0x<sealId>:<ts>:<base version>:<请求体 sha256>` 的 EIP-191 签名，校验到**链上实时 owner**；mint 之前校验到部署记录里的 owner（mint 给到的地址） |
| `GET /credentials/pending` | 签名者名下每个 agent 的凭据待办数量（逐个校验链上实时 owner） | owner 对 `AgenticID.CredentialsPending.v1:<owner>:<ts>` 的 EIP-191 签名 |
| `GET` / `POST /credentials/notify` | owner 读取或设置（`{"email": … \| null}`）通知地址：agent 待办数量上升或凭据快到期时发邮件到这里；响应说明这个 attestor 是否发邮件 | owner 对 `AgenticID.CredentialsNotify.v1:<owner>:<ts>[:<请求体 sha256>]` 的 EIP-191 签名 |
| `POST /probe` | 同步探活：失联容器 flip 到 `Failed`；sandbox 仍保留但没在跑的 flip 到 `Stopped`（可 Resume）| 无 |

### 容器对接（agent runtime → attestor）

| 路径 | 干什么 | 鉴权 |
|---|---|---|
| `GET /provision?seal_id=…` | 返回 `{"generation", "certificate_required", "layered"}`：已启用的启动代次（不返回票据），当前是否尚未记录容器公钥、下一次启动必须携带证书，以及本 attestor 是否运行分层流程（`sealed/LAYERS.zh.md` 第 10 节）——链上有信任注册表（AgenticID 的 `trustRegistry()` 不为零）时为 true。只有 AgenticID 拒绝该调用时为 false，1.4.0 之前的 AgenticID 就是这样（revert：JSON-RPC 错误码 3 或 "execution reverted"）；其他读取失败，包括节点返回的其他错误，一律返回 503。结果缓存 60 秒。没有已启用的授权时返回 `403 no authorized boot; reset required` | 公开元数据 |
| `GET /attestor-tls?provider=0x…` | 原样（逐字节）转发 sandbox provider 对本 attestor TLS SPKI pin 的最新签名声明（EIP-712 `AttestorTLS`，取自已发现 provider 的 `/api/attestor-tls`）。转发前检查 provider 签名、租期（最长 300 秒）以及本 attestor 自己的 TLS 公钥在 pin 中；到期前 60 秒刷新，声明到期前 15 秒停止下发（sealed 要求剩余超过 5 秒），且只在刷新时询问 sandbox discovery，因此 discovery 续期或不可用不会阻塞或拒绝缓存能回答的请求。未知 provider → 404；没有有效声明 → 503 并带 `Retry-After: 5`。始终 `Cache-Control: no-store`。每份新声明都会打日志；api 启动时取一次并记录结果。sealed 之后对 attestor 的所有连接都钉在这些 pin 上 | 公开 |
| `POST /provision` | 容器领取 ECIES 加密的 `agentSeal_priv`、owner 配置文档、owner 的凭据集（`encrypted_credentials`：`{document, owner_epoch}` 及其写回，只发给当前所有权），以及不透明的单次启动状态令牌（`encrypted_status_binding`，明文 `{"token":"<64 hex>"}`；只存其 SHA-256，旁边记录实际下发的配置版本和摘要）。**首次启动**携带 v3 证书（`certificate`：`SANDBOX_SEAL_ATTESTATION` 对象，provider 密钥签的 EIP-712 `ImageAttestation`）。attestor 要求签名者与 scope 是已发现的 provider 实例，签发时间在启动票据之前 300 秒到当前时间 + 300 秒之间，镜像在 `validFrameworkHashes` 中，且公钥是 provider 为本 attestor 在当前票据下创建的 sandbox 所报告的公钥（`401 certificate is not for the sandbox this attestor created; reset required`），然后记录容器公钥、镜像和 provider 实例。**之后的启动**不带证书：由已记录的公钥签 boot claim，已记录的 provider 实例必须仍是当前发现的实例（否则 `403 provider instance no longer trusted; reset required`），已记录镜像仍须在白名单中（否则 `401 recorded image_hash not in validFrameworkHashes; reset required`）。没有记录也没有证书 → `409 certificate_required`；证书对应另一把公钥 → `403 container key differs from record; reset required`。每个请求都带 owner 授权的票据、启动代次和容器公钥签名的 boot claim，`boot_started_at` 必须严格递增；create 尚未落库时返回 409。拒绝的请求不删除容器；对已授权启动的 401/403 会打日志（`provision rejected`），在该代次仍有效时记为 `last_provision_error`，并立即把容器 stage 置为 `failed`（发布 `container_failed`）；下一次被接受的启动或新容器的票据会清除它。未确认配置多次启动后回退至 last-known-good（同一次启动的重试算同一次尝试）。**分层流程**：由加载器启动 sealed 的容器加上 `sealed_hash`（`0x` + 64 位十六进制），并把它签进 boot claim（`ProvisionBoot.v2:…:<sealed hash>`）；信任注册表的 sealed 名单必须包含它。不在名单上返回 `403`，记为 `last_provision_error`，但不让 agent 下线：sealed 切到最新的已列出版本，在同一代次下重新申领。链上没有信任注册表时带 `sealed_hash` 返回 `400`。不带它的 claim（`ProvisionBoot.v1`）来自没有加载器的镜像，按原流程处理（`crates/shared/src/legacy.rs`）| provider 签名的证书（首次启动）或已记录的容器公钥 + owner 授权的票据、启动代次和容器公钥签名的 boot claim |
| `POST /status` | sealed 心跳与状态（`StatusReport.v2` canonical；`StatusReport.v3` 末尾追加等待 owner 处理的凭据待办数量，按 seal 记录：配置了通知时，数量上升会给 owner 发邮件）。签名覆盖状态令牌哈希和实际使用的配置摘要；在一个事务里检查令牌属于当前启动，再更新状态、心跳与精确版本确认。只有实际使用的配置摘要等于该次启动下发摘要的 `running` / `warning` 上报才能提升配置；旧容器上报被忽略，`error` 不改配置。上报的级别和原因（`error_detail`）作为 `container_status` 记在该行 | agentSeal 原始 keccak 签名 + 当前状态令牌 |
| `POST /credentials/writeback` | 容器把自己获得的值（轮换得到的 refresh token、MCP 登录结果）加密给自己的 agentSeal 后存下，供下次启动使用。只接受当前启动的容器、凭据集中带 `writeback: true` 的条目 | agentSeal 对 `CredentialWriteback.v2:0x<sealId>:<name>:<binding>:<boot_id>:<密文 keccak256>` 的原始 keccak 签名，`binding` 为 `value:0x<64 位 hex>` 或 `mcp:0x<64 位 hex>`（见 `sealed/CREDENTIALS.zh.md`） |
| `POST /settings/seed` | 容器把从旧 config role 里捞回来的配置文档交还 attestor，保证重建容器后不丢。仅播种且一次性：只在 `settings_version = 0` 时落库；行上没有 sandbox 记录时直接忽略（幽灵容器——这个 agent 历史上每个容器都握着 agentSeal 私钥）| agentSeal 对 `SettingsSeed:0x<sealId>:<sha256>` 的签名 |

### 读 / 实时

| 路径 | 干什么 |
|---|---|
| `GET /deployments` | 列出当前 deployment。带 `?owner=` 和 owner 签名时，自己的行还带各 stage、`sandbox_id`、`last_provision_error` 和 `container_status` |
| `GET /deployment/:seal_id` | 单条 deployment 详情（无需认证；不返回 settings 文档、容器记录、iData 重试材料）。`container_status`（`{level, reason, at}`）是当前容器最近一次 `/status` 上报：`phase` 把 `warning` 显示为 `running`，所以 agent 在运行却无法应答（例如配置里没有模型）时要看这里。新的启动被授权或被接受时清空，该次启动上报之前不出现 |
| `GET /agent-seal-pubkey?seal_id=` | agent 的 agentSeal 公钥。SDK（以及本 console 的 Restore/Reset）用它加密推理 key（`SEAL_SECRET_ENV`），owner 钱包签名弹窗里不再出现明文 key（issue #166）。只回答已知 seal_id；按 seal 缓存，并限制同时进行的 KMS 派生数量 |
| `GET /ws/subscribe` | WebSocket 事件流（indexer / worker 通过 EventBus 推 ） |

详细签名 canonical 见 `crates/shared/src/auth/`；v3 容器证书和 attestor TLS 声明见
`crates/shared/src/image_attestation.rs` 与 `attestor_tls.rs`，与 provider、sealed
共用的 known-answer 向量在 `crates/shared/testdata/`。

## 链上依赖

| 合约 | 用途 |
|---|---|
| **AgenticID** | NFT mint、iData 注册、镜像白名单 `isValidFrameworkHash`（1.4.0 起经信任注册表读取）以及 `trustRegistry()` |
| **TrustRegistry** | 部署方的信任决定（AgenticID 1.4.0 起，经其 `trustRegistry()` 找到）：受信 attestor，以及按类别的代码名单——`image`、`sealed`、`harness`。owner 是本环境的 Timelock（列入和信任是排期执行、可取消的操作；mainnet 延迟 1 天，dev/test 为 0）；guardian 密钥可以立即下架、撤销信任。`/provision` 用 sealed 名单检查分层启动的 sealed 程序。attestor 只读它 |
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
| `ATTESTOR_SUPPORTED_FRAMEWORKS` | 逗号分隔的可选框架名单——铸造前在 deploy 边缘校验，并经 `GET /config` 提供给前端框架选择器。必须与 `ATTESTOR_SANDBOX_SNAPSHOT` 指向的 sealed 镜像实际打包的 adapter 一致。不设/为空 = 默认 `openclaw`。是 `ATTESTOR_FRAMEWORKS`（每项 `name[:image]`，见 `.env.example`）的旧版回退；两者中出现 `dsh` 都会让启动失败 |
| `ATTESTOR_SECRET_ENV_ENABLED` | 显式开启（`true`/`1`/`on`/`yes`）。开启后 `GET /config` 公布 `secret_env_scheme`，SDK 在 start/reset/retry 时把推理 key 加密给 agentSeal 公钥，而不是明文签进 envelope。只有当 `ATTESTOR_SANDBOX_SNAPSHOT` / `ATTESTOR_FRAMEWORKS` 里所有镜像都能读 `SEAL_SECRET_ENV` 时才开启。默认关闭 |
| `ATTESTOR_PUBLIC_URL` | attestor 自己的外网 URL，注入到 sandbox 容器的 `ATTESTOR_URL`（去掉末尾 `/`）；要让容器能 POST `/provision` 和 `/status` 回来 |
| `MOCK_SANDBOX` | dev mock 开关；`true` 时不真起容器、只 log |

从把 harness 框架叫作 `dsh` 的版本升级时：在同一次升级里把 `ATTESTOR_FRAMEWORKS` 中的该项改名为 `0g-harness`，并指向 0g-harness 镜像。启动时会把所有 `dsh` 部署行改名为 `0g-harness`，并拒绝仍写着 `dsh` 的配置，两者不会不一致。

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

### owner 通知

| env | 含义 |
|---|---|
| `ATTESTOR_NOTIFY_RESEND_API_KEY` / `ATTESTOR_NOTIFY_FROM` | 通过 Resend 的 HTTP API 发邮件。两者都设置时：登记了地址（`POST /credentials/notify`）的 owner，在 agent 的凭据待办数量上升时、以及凭据 `expires_at` 前一周（每小时检查）收到邮件。邮件只写明是哪个 agent、有几条，不包含 agent 写的内容。任一为空则不发邮件 |
| `ATTESTOR_NOTIFY_COOLDOWN_SECONDS` | 同一个 agent 两封邮件之间的最短间隔（秒）。默认 600 |

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
