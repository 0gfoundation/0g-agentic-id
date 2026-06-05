# 已知坑与 workaround

把项目所有"细节的坑"集中在这里，跨子项目都查这一份。新加的 workaround
请同样移到这里，正文文档只保留对应小节的反向链接。

---

## Foundry / Solidity 编译

### `via_ir = true` 是必需的

`giveFeedback` 参数多、栈深，关掉 `via_ir` 会编译失败（"stack too deep"）。
`foundry.toml` 已经默认开启，不要改。

### forge-std 钉在 v1.12.0

`forge-std` 在 v1.13.0+ 改了内部 memory 布局，跟 Solidity 0.8.24 + `via_ir`
组合时触发已知 codegen bug。解钉前置条件：solc 升级到 ≥ 0.8.27（多个 via_ir
bug 已修）。

### 测试里的 `via_ir + vm.warp` 陷阱

跟上面的 codegen bug 同源：在测试里用 `vm.warp(...)` 推时间后，**不要**继续
读那之前用 `block.timestamp` 派生的 local 变量。优化器会 rematerialize 那条
读取，产出错误的值（典型表现：deadline 算出来翻倍）。

正确做法：`vm.warp` 之前把 `block.timestamp` 一类的值 freeze 进 local，warp
之后只引用这些 freeze 过的 local，不要再 `block.timestamp + delta` 这样写。

---

## 0G Galileo Testnet RPC

### `eth_maxPriorityFeePerGas` 返回 1 wei

按 RPC 标准走 `with_recommended_fillers()` 自动估 EIP-1559 fee 会拿到 1 wei
priority fee，结果 mempool 直接拒（"tip cap below minimum 2 gwei"）。

attestor 的 alloy chain client（`attestor/crates/shared/src/chain.rs`）已经
绕过去了——skip `GasFiller`，每笔 tx 手动 `set_max_priority_fee_per_gas` +
`set_max_fee_per_gas`，gas limit 用 `estimate_gas` + 20% buffer 显式估出来。

### Foundry 脚本要硬编码 gas-price

同样的原因，`forge script` / `forge create` 命令需要显式 `--priority-gas-price
2000000000 --gas-price 5000000000`，否则要么估出 1 wei 被拒，要么走 0G 默认估
得过低排不上。

### 部署 / 升级文档里随处可见的这两个数字就是这个 workaround

参见 [`contracts/DEPLOYMENT.md`](contracts/DEPLOYMENT.md) 的 deploy / upgrade
命令块。

---

## Etherscan 兼容 verifier（0G 端点）

### `forge verify-contract --watch` 卡轮询

0G 的 Etherscan-兼容 verifier 在某些状态下不返回 forge 期望的轮询响应，
`--watch` 会一直转圈。

`script/verify.sh` 不带 `--watch`，提交后命令立刻干净退出。状态查询通过
后续的 `getsourcecode` 调用幂等 check。

---

## 其它

### 0g-storage Rust SDK 依赖 patch

`zg-storage-client` 上游引用的 `core2` 在 crates.io 被撤包。attestor
workspace 通过 `[patch.crates-io]` 重定向到 `tcharding` fork 才能编过：

```toml
[patch.crates-io]
core2 = { git = "https://github.com/tcharding/core2", branch = "..." }
```

Go CLI（`0g-storage-client`）也仍是可替换方案——sealed 用的就是 Go CLI。

### 0g-sandbox 计费拒收随机密钥

sandbox 计费路径会校验签名者钱包在链上有余额（rough sanity check），随机
生成、未充值的 keypair 调 sandbox API 会被拒。E2E 测试需要用充过值的钱包。

---

## 故障定位（serve-proof / sealed 运行时）

verifier 或运维看到一个"看着不对劲"的现象时，按下表落到对应那一层：

| 症状 | 出错的层 | 行动 |
|---|---|---|
| `serve-proof` 签名验不过 | sealed / TEE 被攻陷 | **关键** —— 排查 sealed 代码、TEE attestation 链 |
| 签名验过，但 `req_body_hash` 不匹配你发出的请求 body | 请求在传输中被替换（MITM）或 sealed bug | **关键** —— 排查传输层 + sealed 代码 |
| 签名验过，`data_hashes` 不匹配 `AgenticID.intelligentDatasOf(tokenId)` | sealed 的状态绑定 bug | **关键** —— sealed 在响应时刻撒谎说 agent 状态是什么 |
| 一切都验过，但响应**内容错 / 有害** | agent 质量问题 | **不是 sealed bug。** 报给声誉系统；声誉分会反映 |
| agent 的 persona 以可疑方式漂移了 | 怀疑 owner 操纵 | **不是 sealed bug。** verifier 应当降低内容权重；链上历史（`EntryUpdated` events）展示漂移时间线 |
| agent 不响应 | 容器宕了、owner 关了、gas 烧光 | 运维问题；owner 负责让容器活着并有 gas |

trust model 的层次划分参见 [`sealed/TRUST_MODEL.zh.md`](sealed/TRUST_MODEL.zh.md)。
