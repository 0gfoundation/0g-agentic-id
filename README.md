# 0G AgenticID

Monorepo 分两个子项目：

| 子项目 | 内容 | 工具链 |
|---|---|---|
| [`contracts/`](contracts/README.md) | Solidity 合约、Foundry 测试、部署/升级/verify 脚本 | Foundry (forge / cast) |
| [`attestor/`](attestor/) | 后端服务（Attestor / Oracle TEE、API、worker、indexer） | Rust (cargo workspace) |

跨子项目的事（共享 ABI、联合 CI 等）以后按需加。

## 常用命令

```bash
# 合约
cd contracts && forge test                      # 跑测试套件
cd contracts && forge build                     # 编译

# 后端
cd attestor && cargo test                       # 跑 Rust 测试
cd attestor && cargo build                      # 构建
```

具体部署 / 升级 / verify 流程见 [`contracts/README.md` §10](contracts/README.md)。
