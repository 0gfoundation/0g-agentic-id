# AgenticID 合约升级规范

升级/改版合约时遵循本规范。**部署记录、地址、每个合约的当前版本与 changelog 在
[`DEPLOYMENT.md`](DEPLOYMENT.md)**(本文只讲"怎么定版本 + 怎么升")。

架构:每个合约走 `BeaconProxy + UpgradeableBeacon + Impl`,三个 beacon 由同一个
`TimelockController` 持有;升级 = `schedule → wait → execute` 两阶段。proxy 地址与
storage 在 beacon 升级中不变。

## 1. 版本号规范(`major.minor.patch`)

`VERSION` 是每个合约的编译期常量。按"改动能怎么落地 + 影响谁"定三位:

| 位 | 触发 | 谁关心 |
|---|---|---|
| **大版本 major**(`X.0.0`)| storage 布局不兼容 / 必须**新部署(新 proxy)+ 协调链下迁移** / 协议级重设计 —— **不能 beacon 原地升** | 运维:不能安全原地升,要迁移 |
| **中版本 minor**(`1.X.0`)| **ABI 或行为变了**,但 storage 兼容、**能 beacon 原地升** | 集成方(SDK / 其他合约 / indexer):要改调用 |
| **小版本 patch**(`1.0.X`)| 向后兼容的 bugfix / 不改接口 | 无:放心升 |

一句话判据:
- **要不要新 proxy / 迁 storage?** 要 → **大版本**。
- 能 beacon 原地升,但 **ABI/行为变了?** → **中版本**。
- 能原地升且**接口不变**(纯修 bug)→ **小版本**。

例:reputation 去掉 `ServeProof.client`(ABI 变、storage 兼容、beacon 升级)→ `1.0.0 → 1.1.0`(中版本)。

## 2. 小/中版本升级(beacon 原地升,两阶段)

`TIMELOCK_DELAY=0`(dev)也保持同样步骤,与 prod 一致。gas 见
[`../QUIRKS.md`](../QUIRKS.md)(forge 1.6 + 0G 用 `--legacy --gas-price 5000000000 --slow`)。

```bash
# Step 1: 按 §1 bump 源码里的 VERSION 常量 + 更新 impl 内的 @dev changelog,forge test 全绿

# Step 2: 部署新 impl
forge create src/AgenticIDReputationRegistry.sol:AgenticIDReputationRegistry \
  --rpc-url <RPC> --chain 16602 --private-key <PK> --legacy --gas-price 5000000000 --broadcast

# Step 3: Proposer 排期(BEACON 是要升的 beacon,不是 proxy)
export TIMELOCK=0x... BEACON=0x... NEW_IMPL=0x<上一步输出>
forge script script/ScheduleUpgrade.s.sol --rpc-url <RPC> --chain 16602 \
  --private-key <PROPOSER_PK> --legacy --gas-price 5000000000 --broadcast --slow

# Step 4: 等 delay(delay=0 也建议轮询 isOperationReady)后 Executor 执行
#         TIMELOCK/BEACON/NEW_IMPL 必须与 Step 3 完全一致
forge script script/ExecuteUpgrade.s.sol --rpc-url <RPC> --chain 16602 \
  --private-key <EXECUTOR_PK> --legacy --gas-price 5000000000 --broadcast --slow
```

`ExecuteUpgrade` 内置 `require(beacon.implementation() == newImpl)` 自校验。

## 3. 大版本升级(不能原地升 → 重部署 + 迁移)

storage 不兼容 / 协议重设计时,**不能**走 beacon upgrade:

- 走 [`DEPLOYMENT.md`](DEPLOYMENT.md) §3 `Deploy.s.sol` 全新部署(或单独部署新 impl+beacon+proxy)。
- 需要时迁移旧数据;更新所有指向它的配置(attestor `.env` 的 `ATTESTOR_*_ADDR`、SDK
  `constants.ts` 的地址)。
- 旧部署移入 `DEPLOYMENT.md` §6.3(废弃/不要用)。

## 4. 升级后 checklist

- [ ] `VERSION` 常量已按 §1 bump,impl 内 `@dev` changelog 已更新
- [ ] `forge test` 全绿
- [ ] 链上核对:`proxy.VERSION() == 新版本` 且 `beacon.implementation() == 新 impl`
- [ ] `script/verify.sh <proxy>` 重新 verify 新 impl(见 DEPLOYMENT §5)
- [ ] `DEPLOYMENT.md`:§6 对应环境更新 impl 地址 + VERSION;§7 追加一条 changelog
- [ ] dev / test 两套环境按需都升,避免版本漂移(当前状态见 §6)
