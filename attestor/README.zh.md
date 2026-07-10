# AgenticID Attestor

> AgenticID 协议的链下后端 —— 把 owner、TEE、链上合约这三个不同信任
> 域协调起来。

Attestor 代表 owner 发起 mint tx、给经过 RA 的 Agent TEE 派
`agent_seal_priv`、把每个 agent 的 iData 加密上传到 0G Storage，并把
链上索引实时同步给前端。在 trust chain 里它处于**链 ↔ TEE 之间的
中介**位置，本身也作为一个 Tapp app 注册在 TappRegistry 上（怎么
拿 `master_secret`、怎么派 `agent_seal_priv` 见
[`../sealed/TRUST_MODEL.zh.md`](../sealed/TRUST_MODEL.zh.md)）。

三个 binary 共享一份 Postgres、对外暴露 HTTP + WebSocket：

- **api** — owner 入口（deploy / 生命周期）、容器 `/provision` +
  `/status` 接收、`/probe` 同步探活、WebSocket 实时事件推送
- **worker** — 异步任务消费者；跑 storage 加密上传 / mint tx /
  sandbox 生命周期；带 60s sweep loop（job retention + provision
  deadline + heartbeat staleness）
- **indexer** — 链上事件监听 + AgentCard 重建；Postgres 落库后通过
  EventBus 推 WS 给前端

## Workspace

```
attestor/
├── Cargo.toml                Rust workspace
├── crates/
│   ├── shared/               types / traits / chain / sandbox / crypto / repo / mocks
│   ├── api/                  HTTP + WS server + 静态 web/ 资源
│   ├── worker/               异步任务 + 三类 sweep
│   └── indexer/              链上事件监听
├── docker-compose.yml        api / worker / indexer / postgres 全栈
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

非容器（裸跑，开发调试用）：

```bash
docker compose up -d postgres                       # 只起 Postgres
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

### 健康 / 配置

| 路径 | 干什么 | 鉴权 |
|---|---|---|
| `GET /health` | 进程级 liveness probe | — |
| `GET /config` | 链 RPC / 合约地址 / appId / snapshot 等前端要的公开配置 | — |

### 生命周期（owner-driven）

| 路径 | 干什么 | 鉴权 |
|---|---|---|
| `POST /deploy` | 用户部署 agent | owner EIP-191 + sandbox envelope EIP-191 |
| `POST /clone` | 源 owner 为另一 owner 铸一个全新 agent，复用源的链上 iData（dataKey 重封给新 agentSeal）；落 Offline，由新 owner 自行上线 | owner EIP-191，校验签名者 == **链上实时 `ownerOf(source)`**（非自声明 owner） |
| `POST /start` / `/stop` / `/retry` / `/reset` | 启停 / 重试 / 重置 | owner envelope |
| `POST /probe` | 同步探活，flip 失联容器到 `Failed` | 无 |

### 容器对接（agent runtime → attestor）

| 路径 | 干什么 | 鉴权 |
|---|---|---|
| `POST /provision` | 容器换 `agentSeal_priv` | sandbox TEE 签名 + TappRegistry 节点验证 + `validFrameworkHashes` 白名单 |
| `POST /status` | sealed 心跳 / 状态汇报 | agentSeal EIP-191 |

### 读 / 实时

| 路径 | 干什么 |
|---|---|
| `GET /deployments` | 列出当前 deployment |
| `GET /deployment/:seal_id` | 单条 deployment 详情 |
| `GET /ws/subscribe` | WebSocket 事件流（indexer / worker 通过 EventBus 推 ） |

详细签名 canonical 见 `crates/shared/src/auth/`。

## 链上依赖

| 合约 | 用途 |
|---|---|
| **AgenticID** | NFT mint、iData 注册、ServeProof 验证、`validFrameworkHashes` 白名单 |
| **TappRegistry** | attestor / 0g-kms / 0g-sandbox-provider 三个 Tapp app 的代码身份 + 节点签名注册表；`/provision` 走 `getNodeList` 验 sandbox signer |
| **SandboxServing** | sandbox 预付费余额 + voucher 结算；前端 deploy gate 要求 owner 余额 ≥ 0.1 OG |

合约部署 / 升级 / verify 见 [`../contracts/README.md`](../contracts/README.md) §10。

## 关键配置

完整列表在 `.env.example`（约 30 项），下面按类别列出 load-bearing 的。

### Chain 接入

| env | 含义 |
|---|---|
| `ATTESTOR_CHAIN_RPC` / `ATTESTOR_CHAIN_ID` | 0G 链 RPC + chainId |
| `ATTESTOR_AGENTIC_ID_ADDR` | AgenticID 合约地址 |
| `ATTESTOR_CANONICAL_8004_ADDR` | 官方 ERC-8004 IdentityRegistry（可选；按 chainId 自动选——主网 `0x8004A169…`、测试网 `0x8004A818…`）|
| `ATTESTOR_TAPP_REGISTRY_ADDR` | TappRegistry 合约地址 |
| `ATTESTOR_PRIORITY_FEE_GWEI` / `ATTESTOR_MAX_FEE_GWEI` | EIP-1559 gas 上下界（0G testnet `priority` 最低 2）|

### Tapp 身份 + KMS

| env | 含义 |
|---|---|
| `ATTESTOR_APP_ID` | attestor 自己在 TappRegistry 注册的 appId |
| `ATTESTOR_KMS_APP_ID` / `ATTESTOR_SANDBOX_APP_ID` | 信任的另外两个 Tapp app（trust-roots ack 用）|
| `ATTESTOR_TAPP_IP` / `ATTESTOR_TAPP_PORT` | tapp-server 本地 gRPC 端点（拿 TEE EOA key + KMS app secret）；docker 里通过 `host.docker.internal` 解到宿主 |
| `MOCK_TEE` / `MOCK_KMS` | dev mock 开关 |
| `MOCK_APP_PRIVATE_KEY` / `MOCK_APP_ETH_ADDRESS` | `MOCK_TEE=true` 时必填；私钥需推得出地址（启动校验）|
| `MOCK_APP_SECRET` | `MOCK_KMS=true` 时必填，32 字节 hex；三个 binary 必须读到**同一个值**否则派生分叉 |

### Sandbox + SandboxServing

| env | 含义 |
|---|---|
| `ATTESTOR_SANDBOX_PROVIDER_ADDR` | sandbox provider EOA（在 SandboxServing 上注册过）|
| `ATTESTOR_SANDBOX_SERVING_ADDR` | SandboxServing 合约地址（前端 deploy gate 查 owner 余额 ≥ 0.1 OG 用）|
| `ATTESTOR_SANDBOX_ENDPOINT` | 0g-sandbox HTTP endpoint |
| `ATTESTOR_SANDBOX_SNAPSHOT` | 实例化新 agent 用的 sealed runtime snapshot 名（升 image 时改这里）|
| `ATTESTOR_SANDBOX_PUBLIC_PORTS` | 逗号分隔的公开端口白名单（0g-sandbox#57）。设置后 sandbox create 会带上 `publicPorts`，只有名单内端口对外可达，其余回落到 Daytona 认证。必须包含 agent 服务端口（8080）。留空 = 全端口公开——在 provider 切到 0g-daytona fork 镜像之前，这是唯一安全的取值 |
| `ATTESTOR_SUPPORTED_FRAMEWORKS` | 逗号分隔的可选框架名单——铸造前在 deploy 边缘校验，并经 `GET /config` 提供给前端框架选择器。必须与 `ATTESTOR_SANDBOX_SNAPSHOT` 指向的 sealed 镜像实际打包的 adapter 一致。不设/为空 = 默认 `openclaw` |
| `ATTESTOR_PUBLIC_URL` | attestor 自己的外网 URL，注入到 sandbox 容器的 `ATTESTOR_URL`；要让容器能 POST `/provision` 和 `/status` 回来 |
| `MOCK_SANDBOX` | dev mock 开关；`true` 时不真起容器、只 log |

### Storage（0g-storage）

| env | 含义 |
|---|---|
| `ATTESTOR_STORAGE_INDEXER` | 0g-storage indexer URL（dataKey 加密包上传目标）|
| `MOCK_STORAGE` | `true` 用 keccak256 替代真 merkle root，不上传；`false` 走真 SDK（attestor TEE EOA 需要 0G testnet gas）|

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
| `ATTESTOR_SANDBOX_PROXY_ADDR` | sandbox proxy 的公共域名（nip.io 风格，如 `47.236.111.154.nip.io:4000`）|
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
cargo test                          # 全量
cargo test -p attestor-shared       # 单 crate
cargo test --test '*'               # 仅集成测试
```

集成测试用 InMemory 实现（`mocks.rs`）绕过 Postgres / chain / sandbox 依赖，单测从 6s 起。
