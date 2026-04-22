# Attestor Backend

AgenticID protocol 的 Attestor 后端。负责：

- 用户 deploy 请求 → 加密 iData / 上传 0G Storage / 发 mint tx
- 容器 provision → 验凭证后下发 `agentSeal_priv`
- 状态回调 / 心跳 / 重启
- 链上事件索引 + WebSocket 推送

## Workspace

```
attestor/
├── Cargo.toml
├── crates/
│   ├── shared/    types / traits / config / postgres repo / crypto / mocks
│   ├── api/       HTTP + WS server (binary)
│   ├── worker/    异步任务消费者 (binary)
│   └── indexer/   链上事件监听 (binary)
├── docker-compose.yml    (Postgres only)
└── .env.example
```

## 本地开发

```bash
# 1. 起 Postgres
docker compose up -d

# 2. 初始化 env
cp .env.example .env

# 3. 编译
cargo build

# 4. 开三个终端分别起
cargo run -p attestor-api
cargo run -p attestor-worker
cargo run -p attestor-indexer
```

## 当前阶段

v0 — 架构骨架。接口按生产形态定义：

- **真实实现**：crypto（k256/ecies/aes-gcm）、Postgres repo / JobQueue / EventBus
- **Mock 实现**：ChainClient、StorageClient、SandboxClient

替换 mock 的优先级：
1. ChainClient → alloy + AgenticID 合约 ABI
2. StorageClient → 0G Storage SDK
3. SandboxClient → 真实 0g-sandbox HTTP 接口
4. TappRegistry ack 流程
5. 心跳超时处理
