# AgenticID 合约 TODO

已知但暂未做的事，作为工程 backlog 参考；正式 tracking 在 GitHub issues。

## 测试 / 验证

- **链下 SDK 的 ECIES 端到端测试** —— 合约对 `sealedKey` 是黑箱（只验 Oracle
  签名覆盖到它，不验其加密正确性）。"Oracle TEE 封 dataKey → buyer 解出原始
  dataKey" 这一段只能在 TS / Rust SDK 的集成测试里用工业级 ECIES 库验；
  Solidity 层做不到。
- **fuzz + invariant test 补强** —— 当前都是单点样例；nonce / deadline /
  pubkey 长度边界、`giveFeedback` 的 `valueDecimals` 归一化逻辑适合 `forge
  fuzz` 扫。
- **gas 基线** —— `forge snapshot` 未建立；合约优化 / 升级时缺少回归参照。

## 协议层

- **"Agent TEE 在线状态"的链上感知** —— 当前完全 off-chain 协商，由 attestor
  心跳 sweep + `/probe` 兜底。要做成链上一等公民需要新的合约入口。
- **Oracle 签 OwnershipProof 时不绑定 agentId** —— 依赖 oracle framework 自律，
  没在合约层强制。
- **卖家对 `targetPubkey` 的约束机制** —— 当前 buyer 可以把 `targetPubkey`
  指定为任意 EOA pubkey（dataKey 会落到明文钱包）。如果卖家想强制"数据永远不
  出 TEE"，需要在合约层加 `dataPolicy` 字段或通过 TappRegistry 做 TEE pubkey
  白名单。

## 工具链

- **solc 升级 + forge-std 解钉** —— forge-std v1.12.0 是暂时方案（见 README §1
  warning）；未来 solc 升到 0.8.27+ 后可以解钉到最新 forge-std。
