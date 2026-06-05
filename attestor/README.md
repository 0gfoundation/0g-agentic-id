# Attestor Backend

AgenticID 协议的链下后端。三个 binary、共享一份 Postgres、对外暴露
HTTP + WebSocket：

- **api** — 用户 deploy / lifecycle 入口、容器 `/provision` + `/status`
  接收、`/probe` 同步探活、WebSocket 实时事件推送
- **worker** — 异步任务消费者；跑 storage 加密上传 / mint tx / sandbox
  生命周期；带 60s sweep loop（job retention + provision deadline +
  heartbeat staleness）
- **indexer** — 链上事件监听 + AgentCard 重建，Postgres 落库后通过
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

## 对外面（HTTP）

| 路径 | 干什么 | 鉴权 |
|---|---|---|
| `GET /` | 内嵌的 deploy 控制台 SPA | — |
| `GET /config` | 链 RPC / 合约地址 / appId / snapshot 等公开配置 | — |
| `POST /deploy` | 用户部署 agent | owner EIP-191 + sandbox envelope EIP-191 |
| `POST /start` / `/stop` / `/retry` / `/reset` | 生命周期 | owner envelope |
| `POST /probe` | 同步探活，flip 失联容器到 Failed | 无 |
| `POST /provision` | 容器换 `agentSeal_priv` | sandbox TEE 签名 + TappRegistry 节点验证 + `validFrameworkHashes` 白名单 |
| `POST /status` | sealed 心跳 / 状态汇报 | agentSeal EIP-191 |
| `GET /deployments` / `/deployment/:seal_id` | 读 | — |
| `GET /ws/subscribe` | WebSocket 事件流 | — |

详细签名 canonical 见 `crates/shared/src/auth/`。

## 链上依赖

| 合约 | 用途 |
|---|---|
| **AgenticID** | NFT mint、iData 注册、ServeProof 验证、`validFrameworkHashes` 白名单 |
| **TappRegistry** | attestor / 0g-kms / 0g-sandbox-provider 三个 Tapp app 的代码身份 + 节点签名注册表；`/provision` 走 `getNodeList` 验 sandbox signer |
| **SandboxServing** | sandbox 预付费余额 + voucher 结算；前端 deploy gate 要求 owner 余额 ≥ 0.1 OG |

合约部署 / 升级 / verify 见 [`../contracts/README.md`](../contracts/README.md) §10。

## 关键配置

详见 `.env.example`，几个 load-bearing 的：

| env | 含义 |
|---|---|
| `ATTESTOR_CHAIN_RPC` / `ATTESTOR_CHAIN_ID` / `ATTESTOR_AGENTIC_ID_ADDR` | 链接入 |
| `ATTESTOR_TAPP_REGISTRY_ADDR` | TappRegistry 合约 |
| `ATTESTOR_APP_ID` | attestor 自己在 TappRegistry 注册的 appId |
| `ATTESTOR_KMS_APP_ID` / `ATTESTOR_SANDBOX_APP_ID` | 信任的另外两个 Tapp app |
| `ATTESTOR_SANDBOX_PROVIDER_ADDR` / `ATTESTOR_SANDBOX_SERVING_ADDR` | sandbox provider EOA + SandboxServing 合约（前端 top-up 用）|
| `ATTESTOR_SANDBOX_SNAPSHOT` | 实例化新 agent 用的 sealed runtime snapshot 名 |
| `MOCK_TEE` / `MOCK_KMS` / `MOCK_SANDBOX` / `MOCK_STORAGE` | dev 模式开关；生产全 `false` |

## 测试

```bash
cargo test                          # 全量
cargo test -p attestor-shared       # 单 crate
cargo test --test '*'               # 仅集成测试
```

集成测试用 InMemory 实现（`mocks.rs`）绕过 Postgres / chain / sandbox 依赖，单测从 6s 起。

## 信任模型

[`../sealed/TRUST_MODEL.md`](../sealed/TRUST_MODEL.md) 把端到端讲清楚了：Tapp 部署 → KMS → attestor master secret → 每个 agent 的 `agent_seal_priv` 派生 → sandbox 签 image attestation → 容器 `/provision` 拿密钥 → ServeProof / X-Agent-Proof 验证。
