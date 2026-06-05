# AgenticID 合约部署 / 升级 / Verify

> 后面命令里反复出现的 `--priority-gas-price 2000000000 --gas-price 5000000000`
> 是 0G testnet 的硬编码 workaround，**不是建议参数**——背景见
> [`../QUIRKS.md`](../QUIRKS.md)。

## 1. 架构

每个可升级合约（`AgenticID` / `TEEDataVerifier` / `AgenticIDReputationRegistry`）走
**BeaconProxy + UpgradeableBeacon + Implementation** 三层。三个 Beacon 的 owner
共享同一个 **TimelockController**，升级必须 `schedule → wait → execute` 两阶段。

暂停独立于升级：每个合约有 `pauser` 角色（**不**通过 Timelock），`pause()` 秒级生效，
阻断所有 `whenNotPaused` 写路径（`register` / `setAgentWallet` / `iTransferFrom` /
`giveFeedback` 等），view 不受影响。`owner` 可随时 `setPauser` 更换。

三种角色分工：

| 角色 | 身份 | 受 Timelock 保护 |
|---|---|---|
| Timelock | 所有 Beacon 的 owner，唯一能调 `beacon.upgradeTo` | — |
| Owner（`OwnableUpgradeable`）| attestor 白名单 / verifier 切换 / pauser 轮换 | 否（直接生效）|
| Pauser | 紧急开关 | 否（紧急路径不能延时）|

## 2. 部署

`script/Deploy.s.sol` 通过环境变量一次性部署 10 个合约（Timelock + 3 × (impl + beacon + proxy)）：

```bash
export OWNER=0x...
export PAUSER=0x...
export TEE_ORACLE=0x...           # TEE 内生成的 oracle 签名地址
export TIMELOCK_DELAY=172800      # prod 建议 ≥ 2 天；dev 可设 0
forge script script/Deploy.s.sol \
  --rpc-url <RPC> --private-key <PK> --broadcast \
  --priority-gas-price 2000000000 --gas-price 5000000000
```

可选环境变量：`PROPOSERS` / `EXECUTORS`（逗号分隔地址，默认 proposers=[OWNER]，
executors=[0x0]=开放执行）、`NFT_NAME` / `NFT_SYMBOL`、`MAX_PROOF_AGE`。

输出会打印 10 个合约地址——记下来，升级和 verify 都要用。

## 3. 升级

两阶段流程（dev 下 `TIMELOCK_DELAY=0` 也保持同样步骤，与 prod 一致）：

```bash
# Step 1: 部署新 impl（单独部署，不走 --verify，最后一步统一 verify）
forge create src/AgenticIDV3.sol:AgenticIDV3 \
  --rpc-url <RPC> --chain 16602 --private-key <PK> \
  --priority-gas-price 2000000000 --gas-price 5000000000 \
  --broadcast

# Step 2: Proposer 排期
export TIMELOCK=0x...
export BEACON=0x<要升级的 beacon>    # 注意不是 proxy
export NEW_IMPL=0x<上一步 forge create 输出的>
forge script script/ScheduleUpgrade.s.sol \
  --rpc-url <RPC> --chain 16602 --private-key <PROPOSER_PK> \
  --priority-gas-price 2000000000 --with-gas-price 5000000000 \
  --broadcast --slow

# Step 3: 等 Timelock delay 过去。两种方式：
#   (a) 粗暴：sleep $TIMELOCK_DELAY 再加几秒 buffer
#   (b) 轮询 isOperationReady（推荐）：
ZERO=0x0000000000000000000000000000000000000000000000000000000000000000
OP=$(cast call $TIMELOCK \
  "hashOperation(address,uint256,bytes,bytes32,bytes32)(bytes32)" \
  $BEACON 0 $(cast calldata "upgradeTo(address)" $NEW_IMPL) $ZERO $ZERO \
  --rpc-url <RPC>)
until [ "$(cast call $TIMELOCK 'isOperationReady(bytes32)(bool)' $OP --rpc-url <RPC>)" = "true" ]; do
  sleep 5
done

# Step 4: Executor 执行（TIMELOCK/BEACON/NEW_IMPL 必须与 Step 2 完全一致）
forge script script/ExecuteUpgrade.s.sol \
  --rpc-url <RPC> --chain 16602 --private-key <EXECUTOR_PK> \
  --priority-gas-price 2000000000 --with-gas-price 5000000000 \
  --broadcast --slow
```

`ExecuteUpgrade` 内置 `require(beacon.implementation() == newImpl)` 自校验。
升级后 proxy 地址不变，storage 完全保留，impl 切到新地址。

## 4. Verify

`script/verify.sh` 是 proxy 驱动的幂等 verify 工具——唯一输入是 **BeaconProxy
地址**，永远不变；工具内部自动发现 beacon 和 impl，逐个 check-then-verify：

```bash
# 首次部署后 / 升级后 / 随时重跑 —— 同一条命令
script/verify.sh <proxy-address>

# 三个 proxy 链挨个（testnet 当前地址见 §5）：
script/verify.sh 0xf952e7dD046779f34C0Ca0c058e1D940B7B9d525   # AgenticID
script/verify.sh 0x2EAa6fcB9847A5A4B25acCdeca3C957a1732C23F   # TEEDataVerifier
script/verify.sh 0x4AAbc18962C2Bb5E451a0FDfa39c0C47a51bD971   # Reputation
```

工具流程：

1. 读 ERC-1967 beacon slot → 拿到 beacon 地址；
2. 调 `beacon.implementation()` → 拿到当前 impl 地址；
3. 对 `(impl, beacon, proxy)` 三个各自：
   - `getsourcecode` 查已否 verify，已 verify 直接 skip；
   - 未 verify：从 `getcontractcreation` 拉 creation bytecode，从 `eth_getCode`
     拉 runtime bytecode，creation 减 runtime 得出 constructor args；
   - 调 `forge verify-contract`，**不**带 `--watch`（绕过 0g 端点轮询 bug，
     见 [`../QUIRKS.md`](../QUIRKS.md)），命令干净退出。

**Impl 源码识别**：工具会把链上 impl runtime 跟本仓库已知 impl 候选（`AgenticID`
/ `AgenticIDReputationRegistry` / `TEEDataVerifier`）编译出来的 `deployedBytecode`
对比，自动挑中 match 的那个。新增 impl 类型时（比如 `AgenticIDV3`），要么在
`script/verify.sh` 顶部的 `IMPL_CANDIDATES` 数组加一行，要么显式传参：

```bash
script/verify.sh <proxy-address> src/AgenticIDV3.sol:AgenticIDV3
```

**环境变量**（都有缺省）：`RPC_URL` / `VERIFIER_URL` / `CHAIN_ID` /
`COMPILER_VERSION` / `OPTIMIZER_RUNS`。

`ScheduleUpgrade.s.sol` / `ExecuteUpgrade.s.sol` 只调 Timelock 函数、不部署合约，
不需要 verify。Proxy 和 Beacon 是"一次性"verify——部署后永远不动；每次升级后
再跑一次 `verify.sh <proxy>` 即可，已 verify 的自动 skip，只把新 impl 提交。
浏览器的 "Read as Proxy" 需要 proxy + beacon + impl 三者都 verify 才能自动展开
业务 ABI。

## 5. 0g Galileo Testnet 参考部署（chain 16602）

本地 `broadcast/Deploy.s.sol/16602/run-latest.json` 始终是最新一次部署的真相；
参考快照（当前测试网中的活地址，已经走过完整 upgrade + verify 流程）：

```
TimelockController        0xb551faaa1488ec26bc7751ee2fa4382416951af0
TEEDataVerifier impl      0x1634a8bF0FB0FC014D79225EF065C4181CCF8fE5
TEEDataVerifier beacon    0x36B413e2a5c9740b2E71613f35Bad3B414337Ef4
TEEDataVerifier proxy     0x2EAa6fcB9847A5A4B25acCdeca3C957a1732C23F
AgenticID impl            0x983d0245Ffe04A0d045a321c3671BF8ff59B13ee
AgenticID beacon          0x0CF993283b24D77aa2e52aBFb8b87FA39cb9e3c0
AgenticID proxy           0xf952e7dD046779f34C0Ca0c058e1D940B7B9d525
ReputationRegistry impl   0x4b074bc143756C28C17b233E355338a76bDbB0BD
ReputationRegistry beacon 0xbF80fb46E9Ec0379547B0D2C502f067a0AA7944a
ReputationRegistry proxy  0x4AAbc18962C2Bb5E451a0FDfa39c0C47a51bD971
```

Timelock delay = 60s，三个角色都是同一部署者地址，**仅供测试**。Prod 必须：

- `TEE_ORACLE` 换成真实 TEE 内签名地址
- `TIMELOCK_DELAY` 改成 ≥ 2 天
- `OWNER` / `PAUSER` / `PROPOSERS` / `EXECUTORS` 改成多签
