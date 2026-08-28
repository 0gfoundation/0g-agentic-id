# AgenticID Contracts

Solidity 合约层实现了 **AgenticID 协议**：托管绑定（custody-bind）到 canonical
ERC-8004 身份注册表，并在其上叠加 ERC-7857 智能 NFT，为 TEE 内运行的 AI agent
提供可验证的链上身份、数据密钥原子交付、以及抗 sybil 的声誉系统。

---

## 1. 工具链与编译

### 环境要求

- **Foundry**（forge/cast/anvil）—— 合约编译、测试、脚本
- **solc 0.8.24** —— 由 foundry 管理，不要手动改
- **OpenZeppelin v5.0.2** —— `contracts` 和 `contracts-upgradeable` 两套，通过 submodule 装在 `lib/`

### 安装 Foundry

**常规环境**：
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

**老 glibc 环境**（Alibaba Cloud Linux 3 / CentOS 8 等，glibc < 2.33）：
```bash
foundryup -i nightly --platform alpine    # musl 静态链接，不依赖系统 glibc
```

### 安装依赖

所有依赖都已在 `.gitmodules` 里：

```bash
git clone --recurse-submodules <repo>
# 或已 clone 过：
git submodule update --init --recursive
```

版本钉法（仅作参考，正常 clone 会自动拿到）：

| 依赖 | 版本 |
|---|---|
| `openzeppelin-contracts` | v5.0.2 |
| `openzeppelin-contracts-upgradeable` | v5.0.2 |
| `forge-std` | **v1.12.0**（见下方警告） |

> ⚠️ **forge-std 钉在 v1.12.0 是有意的**，跟 `via_ir` 一起踩了已知 codegen
> bug；详见 [`../QUIRKS.md`](../QUIRKS.md)。

### 编译与测试

```bash
forge build                     # 增量编译到 out/
forge build --force             # 强制全量重编
forge test                      # 跑全量测试（当前 190 tests / 21 suites；2 个 fork 测试无 FORK_RPC 时跳过）
forge test -vvvv                # 详细 trace
forge test --match-path test/TransferFlow.t.sol   # 只跑指定 suite
forge fmt                       # 格式化
forge clean                     # 清 out/
```

### `foundry.toml` 关键配置说明

```toml
[profile.default]
src = "src"                     # 源码目录（foundry 默认值）
libs = ["lib"]                  # OZ submodules
solc = "0.8.24"                 # 锁版本
via_ir = true                   # ⚠️ 必需：giveFeedback 参数多会 stack too deep
optimizer = true
optimizer_runs = 200

remappings = [
    "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/",
    "@openzeppelin/contracts-upgradeable/=lib/openzeppelin-contracts-upgradeable/contracts/",
]
```

`via_ir = true` 是必需的——`giveFeedback` 参数多会 stack too deep（细节见
[`../QUIRKS.md`](../QUIRKS.md)）。

---

## 2. 合约布局

```
contracts/src/
├── AgenticID.sol                               主合约（身份 + 7857 token + seal）
├── VerifiedFeedbackRegistry.sol                canonical ERC-8004 声誉注册表之上的
│                                               TEE 验证层（attestFeedback + ServeProof）
├── FeedbackBatcher.sol                         EIP-7702 委托目标：canonical feedback + 盖章
│                                               一笔自调用原子完成（无状态、无 beacon）
├── AgenticIDReputationRegistry.sol             已废弃的私有声誉分叉——被
│                                               VerifiedFeedbackRegistry 取代；为存量部署保留
├── ERC7857Upgradeable.sol                      7857 核心（iTransferFrom + proof 校验）
├── ERC8004CanonicalBoundUpgradeable.sol        ERC-8004 身份，托管绑定到 canonical
│                                               注册表（read-through / write-forward）
├── extensions/
│   ├── ERC7857AuthorizeUpgradeable.sol         链下使用授权名单
│   ├── ERC7857CloneableUpgradeable.sol         iCloneFrom
│   └── ERC7857IDataStorageUpgradeable.sol      IntelligentData 存储/更新
├── verifiers/
│   ├── BaseDataVerifier.sol                    transfer proof 基类（含 pauser 角色）
│   └── TEEDataVerifier.sol                     TEE 签名的 ownership proof 实现
├── utils/
│   └── NonceRegistryUpgradeable.sol            防重放（verifier 和各声誉注册表各自使用）
├── proxy/
│   ├── BeaconProxy.sol                         OZ re-export（为了编译器拉进 artifact）
│   └── UpgradeableBeacon.sol                   OZ re-export
└── interfaces/
    ├── ICanonicalIdentityRegistry.sol          AgenticID 绑定的固定 canonical ERC-8004 注册表接口
    ├── ICanonicalReputationRegistry.sol        验证层锚定的固定 canonical ERC-8004
    │                                           Reputation Registry 接口
    └── I*.sol                                  其余全部接口定义
```

### Canonical 绑定

ERC-8004 身份**没有**在这里重新实现——而是托管绑定到固定的 canonical ERC-8004
IdentityRegistry（0G 上：mainnet `0x8004A169…`、testnet `0x8004A818…`；
`Deploy.s.sol` 按 chainId 选择）。注册时把 canonical token 铸给 **AgenticID
合约本身**（托管），同时把**同一个 agentId** 的本地 ERC-721 token 铸给真正的
owner。所以一个 agent 横跨两条记录：canonical 注册表（身份事实源，生态里的
8004 工具直接读它；canonical token 永不离开托管）和本地 AgenticID token
（可转让的 owner + 7857 / seal 扩展）。agentId 来自 canonical 注册表的全局
0 起计数器，所有注册方共享。

`AgenticID` 通过 C3 linearization 把这些路径叠起来：

```
AgenticID
  ├── ERC8004CanonicalBoundUpgradeable           (agentURI / metadata / agentWallet，经 canonical 托管)
  ├── ERC7857IDataStorageUpgradeable             (IntelligentData[])
  ├── ERC7857AuthorizeUpgradeable                (authorizedUsers[])
  ├── ERC7857CloneableUpgradeable                (iCloneFrom)
  └── OwnableUpgradeable                          (owner / attestor 管理)
```

ERC-721 同时经 8004 和 7857 两条路径进来，C3 把它收敛成单实例：一个 agent =
一个本地 tokenId = 一个 canonical agentId。

---

## 3. off-chain 三个 TEE 角色

合约逻辑只能表达出协议的一半，另一半靠三个 off-chain TEE 协作：

| 角色 | 持有的秘密 | 职责 |
|---|---|---|
| **Attestor TEE** | 只持有 KMS 派生的 key（无常驻 master）| 每把 `agentSeal_priv` 由 KMS 按 `chainId ‖ contract ‖ sealId` per-seal 派生后取得；mint 时生成 `dataKey` 并封给 `agentSeal_pub`；后续给经 RA 的 Agent TEE provision `agentSeal_priv` |
| **Agent TEE** | `agentSeal_priv`（单个 agent 的）+ `dataKey` | 跑 agent 业务、用 `dataKey` 解密模型/配置；签 ServeProof；转让时验 AccessProof 后把 `dataKey`（ECIES 加密）交给 Oracle TEE |
| **Oracle TEE** | `teeOracleAddress_priv`（签 OwnershipProof）+ `Oracle_ECIES_priv`（解 ECIES 拿 `dataKey`）| 转让时解 ECIES 拿 `dataKey` → 用 `buyer_pubkey` 重封 → 签 OwnershipProof；立即丢弃 `dataKey` |

关键安全属性：
- `dataKey` 只在 TEE 内流动，**从不出现在链上明文或 EOA 钱包**
- TEE 单点故障影响有限：Agent TEE 挂 → attestor 再 provision；Oracle TEE 挂 → 转让暂停但重启可恢复（无持久状态）
- KMS 挂 → protocol 级事件，靠集群容灾保证（0g-kms 多节点门限集群，master 只以分片存在，k/n 健康即可）

---

## 4. 流程 1: 注册

### 路径 A — attestor-mint

**链下步骤**（Attestor TEE 内）：
1. 生成 `sealId`（随机或按策略派生）；由 KMS 按 `chainId ‖ contract ‖ sealId` 派生 `agentSeal_priv`，得到 `agentSeal_addr`
2. 对每条将要上链的 IntelligentData_i：
   - 生成 `dataKey_i`
   - 用 `dataKey_i` 加密 plaintext，上传密文到链下存储
   - 算 `dataHash_i`
   - `sealedKey_i = E(dataKey_i, agentSeal_pub)`
3. 丢弃 `dataKey_i`（attestor 不持久化）

**链上调用**：
```solidity
AgenticID.registerWithSeal(
    to,                              // 最终 owner，通常是用户 EOA
    agentURI,                        // 可传 "" 让 owner 后续 setAgentURI
    metadata[],                      // 任意 key-value
    intelligentDatas[],              // (description, dataHash) 列表
    sealedKeys[],                    // 与 intelligentDatas 顺序对齐
    agentSeal_addr,
    sealId
)
```

前置要求：`msg.sender` 在 `trustedAttestors` 名单里（`onlyOwner` 维护），且
sealed 运行时的 `image_hash` 在 `validFrameworkHashes` 里（由 attestor 在
provision seal 之前链下校验）。这次调用把 canonical token 铸给 AgenticID
合约（托管），把本地 token 铸给 `to`。

**事件**——分布在两个合约上：
- **canonical 注册表**上：`Registered(agentId, agentURI, owner=AgenticID)`、
  `MetadataSet × N`、`URIUpdated`（身份记录；`owner` 是托管合约本身）
- **AgenticID** 上：`Transfer(0x0, to, agentId)`（本地 mint）、
  `Updated(agentId, [], newDatas)`、`AgentSealSet(agentId, agentSeal_addr, sealId)`、
  `ITransferred(0x0, to, agentId, entries[])`（sealedKey payload 发布）

**Agent TEE 稍后启动**：
- 产生 RA quote 交给 attestor
- attestor 验 RA 通过 → 下发 `agentSeal_priv`
- Agent TEE 读链上 `ITransferred` 拿到 `sealedKey_i`，解出 `dataKey_i`，加载数据，上线

### 路径 B — self-mint

无 TEE 参与、用户自己上传数据：
```solidity
AgenticID.register(agentURI, metadata[], intelligentDatas[], sealedKeys[])
```

`msg.sender == to`，用户自己决定 `sealedKeys[i]` 封给哪个公钥（自己的 EOA 密钥 / 某台 TEE / 自选）。合约**不验证** sealedKey 的加密目标——调用者丢了那把解密 key 会让后续 transfer 无法产生 OwnershipProof，agent 卡死。

此时 agent 没有 `agentSeal`，不能签 ServeProof、不能积累已验证声誉。而且这是永久的：seal 只在 mint 时通过 `registerWithSeal`（路径 A）绑定，没有事后"给已有 agent 补 seal"的调用——`sealId` 声明的是"数据自创建起就一直封在 TEE 内、从未外泄"，这份出身证明无法事后安到一个明文自助上链的 agent 上。要 seal-bound agent 就得走 attestor-mint 路径。

### 关键不变量

| 字段 | 如何设置 | 转让后 |
|---|---|---|
| `agentSeal` | mint 时经 `registerWithSeal` 绑定一次；不可变 | 保留 |
| `sealId` | 永不可变 | 保留 |
| `agentWallet` | 转发给 canonical 注册表官方 4 参 `setAgentWallet`（`newWallet` 的 EIP-712 同意签名，owner = AgenticID 合约，deadline ≤ 5 分钟）| **清空** |
| `authorizedUsers` | owner 可增删 | **清空** |
| `agentURI` / `metadata` | owner（URI 亦可由 trusted attestor）经转发写到 canonical | 保留 |
| `IntelligentData[]` | **seal 已绑** → 仅 `agentSeal` 可调 `update` / `updateAt`（纯 `msg.sender` 门禁）；**seal 未绑** → owner 可改 | 保留 |

---

## 5. 流程 2: 声誉积累

Feedback 本体存在**官方 canonical ERC-8004 Reputation Registry**（0G 上：
mainnet `0x8004BAa1…`、testnet `0x8004B663…`；它绑定的正是 AgenticID 托管的
canonical Identity Registry，agentId 空间共享）。Client 直接往那里提交
feedback——per-client 归因是原生的，所有 8004 读方零适配可见。本地的
`VerifiedFeedbackRegistry` 只存 **TEE 验证章**：哪些 canonical 条目背后有
ServeProof 证明的真实服务调用。存储归 canonical，信任归本地。

### ServeProof（链下，Agent TEE 签）

Client 向 Agent TEE 发起一次真实业务调用。Agent TEE 完成后在 TEE 内部构造：

```solidity
struct ServeProof {
    uint256   agentId;
    address   submitter;             // 唯一有权兑现这张 proof 的地址
    uint256   timestamp;
    uint256   deadline;              // 过期即 revert
    bytes32   taskHash;              // 任务哈希（输入/输出/合同），由 client 选；验证者只 ecrecover、不强制语义
    bytes32[] dataHashes;            // 当下 TEE 加载的 IntelligentData hash 列表
    bytes32   frameworkHash;         // AgenticID framework 代码 hash
    bytes     signature;             // agentSeal_priv 签名
}
```

签名内容（域 + submitter 双重绑定：跨链/跨部署不可移植，跨钱包不可转让）：
```
inner = keccak256(abi.encode(block.chainid, identityRegistry, submitter,
                             agentId, timestamp, deadline, taskHash,
                             keccak256(abi.encodePacked(dataHashes)),
                             frameworkHash))
signature = personal_sign(inner, agentSeal_priv)
```

### 链上提交——client 两笔调用（SDK 打包成一步）

在启用 EIP-7702 的链上（0G Galileo 已实测支持），SDK 会把两笔合成**一笔原子的
type-4 交易**：client 的 EOA 委托给 `FeedbackBatcher` 后自调用
`giveFeedbackAndAttest`——代码跑在 EOA 自己的账户上下文里（两个内部调用的
msg.sender 都是 client 本人），index 在同一笔交易内读取；盖章失败会连
canonical 写入一起回滚。链不支持 7702 时 SDK 退回下面的两笔顺序流程。

```solidity
// 1. feedback → canonical 注册表（归因 = msg.sender，原生）
canonicalReputation.giveFeedback(agentId, value, valueDecimals,
                                 tag1, tag2, endpoint, feedbackURI, feedbackHash);

// 2. 验证章 → 本地注册表
VerifiedFeedbackRegistry.attestFeedback(agentId, feedbackIndex, serveProof);
```

`attestFeedback` 校验的事：
1. `agentId == proof.agentId`，且 `proof.submitter == msg.sender`（只有声明的 client 能兑——堵抢跑/盗用）
2. 重建 `inner`，ecrecover 后和 `IAgenticID.getAgentSeal(agentId)` 比较 → 过签名
3. 调用者不是 agent owner 或被授权 operator（对照**本地** AgenticID 的 owner——canonical 注册表自己查不了，它眼里每个托管 token 的 owner 都是 AgenticID 合约）
4. canonical 条目 `(agentId, msg.sender, feedbackIndex)` 存在且尚无章
5. 通过 NonceRegistry 登记 `key = keccak256("SERVEPROOF", agentId, signature)`，同时校验 `deadline`（每张 proof 只能兑一次）
6. 存下 proof 的 `dataHashes` / `frameworkHash`，emit `FeedbackVerified`

**防 sybil 的核心**：没有 agentSeal 就没有有效的 ServeProof，而 agentSeal_priv
只有 Agent TEE 持有。canonical 注册表是 permissionless 的——谁都能往里写未验证
的 feedback——但没有真实服务调用就拿不到验证章。在乎真伪的读方拿章的集合和
canonical 条目做交集。

### 其他操作

- `revokeFeedback` / `appendResponse`：直接在 canonical 注册表上操作（client 撤回自己的条目；章不动，但 `getVerifiedSummary` 跟随 canonical 的 revoked 标记）。

### 读接口

- `isVerified(agentId, client, idx)` —— 这条 canonical 条目有没有章？
- `getVerifiedIndexes(agentId, client)` / `getVerifiedClients(agentId)` —— 枚举已验证集合
- `getVerifiedSummary(agentId, clients[], tag1, tag2)` —— 聚合指定 client 的**已验证** canonical 条目（值实时从 canonical 读取；跳过 revoked；求和 + 计数，归一到固定 18 decimals；`clients` 必须非空——由调用方决定信谁）。仅限链下 `eth_call`。
- `attestFeedbackWithTask(…, TaskReveal)` —— 额外开箱 proof 的 taskHash 承诺（方法 / 路径 / 正文**哈希** / 状态码——正文本身不上链）：合约重算哈希比对,把路径记为该条目的 **TEE 验证接口**。`getVerifiedEndpoint` 读回;`getVerifiedSummaryForEndpoint(agentId, clients[], uri)` 按接口聚合,不依赖 client 自报的 tag。
- `getServeData(agentId, client, idx)` —— 该条 feedback 当时的 `dataHashes` + `frameworkHash`，**买家尽调入口**：和 `intelligentDatasOf(agentId)` 对比即可判断这份声誉挣到手之后 agent 的数据有没有变。

> **已废弃**：先前的私有分叉（`AgenticIDReputationRegistry`，proof 门禁的
> `giveFeedback` + 自有 feedback 存储）被这套拆分取代。存量环境上它仍在运行、
> 源码保留在仓库，但新部署只带 `VerifiedFeedbackRegistry`。

---

## 6. 流程 3: 转让与克隆

转让行为按 agent 有无 seal（`getAgentSeal(tokenId) != 0`）分叉：

- **seal 绑定 agent**（运营实体）：ownership 走标准 ERC-721 `transferFrom` /
  `safeTransferFrom`——单纯换 owner。iData 始终锁在不可变 `agentSeal` 的 TEE
  之下，无需重加密；运营权链下随 ownership 走（attestor 给新 owner 重新
  provision）。seal 绑定的 token 调 `iTransferFrom` 和 `iCloneFrom` 都会
  **revert**（`AgenticIDSealedAgentUseTransfer` / `AgenticIDCannotCloneSealedAgent`）。
- **无 seal agent**（数据 blob）：普通 transfer 保持禁用；ownership 只能走下面
  proof 门禁的 `iTransferFrom`，原子地把 dataKey 重加密给买家。`iCloneFrom` 可用。

### `iTransferFrom`（无 seal）—— 更换 ownership + 原子交付 dataKey

**链下准备**（对每条 IntelligentData 都走一次）：

1. **Buyer 签 AccessProof**
   ```
   inner = keccak256(abi.encodePacked(chainId, erc7857, dataHash, buyer_targetPubkey, nonce_ap, deadline_ap))
   ap.proof = personal_sign(inner, buyer_priv)
   ```
   `buyer_targetPubkey` 有两种模式：空串 = 用 buyer 的以太坊 pubkey（64 字节未压缩）；非空 = 自选加密公钥。`chainId` 和 `erc7857`（AgenticID token 合约地址）对两种 proof 做域分隔，签名无法在其他链或其他合约上重放。

2. **Agent TEE ↔ Oracle TEE 协作**
   - Seller 把买家签的 AccessProof 提交给卖家 Agent TEE
   - 卖家 Agent TEE 验 AccessProof 签名（recover 出来等于 `to` 或 `accessDelegates[to]`），决定是否授权这次转让
   - 卖家 Agent TEE 查 TappRegistry 拿到 `Oracle_pubkey`（TappRegistry 注册过即 RA 过，无需重复 attest）
   - Agent TEE 解出 `dataKey`，用 Oracle_pubkey 做 ECIES → `cipher`
   - Agent TEE 把 `cipher + buyer_targetPubkey + nonce_op + deadline_op` 发给 Oracle TEE
   - Oracle TEE 解 ECIES 拿 `dataKey`，用 `buyer_targetPubkey` 重封 → `sealedKey_new`
   - Oracle TEE 签 OwnershipProof：
     ```
     inner = keccak256(abi.encodePacked(chainId, erc7857, dataHash, sealedKey_new,
                                        buyer_targetPubkey, nonce_op, deadline_op))
     op.proof = personal_sign(inner, teeOracleAddress_priv)
     ```
   - Oracle 立即丢弃 `dataKey`

3. **Seller 组装 TransferValidityProof[] 提交**

**链上调用**：
```solidity
AgenticID.iTransferFrom(from, to, tokenId, proofs[])
```

合约逻辑（`ERC7857Upgradeable._proofCheck` + `BaseDataVerifier.verifyTransferValidity`）：
1. `_checkAuthorized(from, msg.sender, tokenId)`：caller 是 owner 或 approved
2. 对每条 proof：
   - `ap.dataHash == op.dataHash`
   - AccessProof 签名 recover 出 `accessAssistant`，必须等于 `to` 或 `accessDelegates[to]`
   - OwnershipProof 签名 recover 必须等于 `teeOracleAddress`
   - 两个 nonce 都走 NonceRegistry（按 `msg.sender` + 分类 tag 命名空间）+ 各自 deadline 校验
   - 加密目标校验：以太坊模式要求 `keccak256(targetPubkey)[12:] == to`；自定义模式要求 `keccak256(targetPubkey) == keccak256(wantedKey)`
3. 验完后按 MRO 走 `_update` 链：`agentWallet` 和 `authorizedUsers` 被清空，`agentSeal` / `sealId` 保留
4. emit `ITransferred(from, to, tokenId, entries[])` —— 权威转让事件

**转让后 buyer 的两条路**：
- **纯读数据**：用 `buyer_targetPubkey` 对应的 priv 解 `sealedKey_new` 拿 `dataKey`，下载并解密 IntelligentData 本地用。不需要 TEE 也不需要 attestor。但不能签 ServeProof，声誉断线。
- **接手运营 agent**：部署自己的 Agent TEE，经 attestor RA 领相同的 `agentSeal_priv`（set-once 保证地址不变），TEE 里同时拿到 `dataKey` 和 `agentSeal_priv`，继续对外服务、签新 ServeProof。

### `iCloneFrom`（无 seal）—— 铸克隆 token，源不变

`ERC7857CloneableUpgradeable.iCloneFrom(from, to, tokenId, proofs[])`

- 只对**无 seal** 的源可用；源有 seal 时 revert
  `AgenticIDCannotCloneSealedAgent`（克隆会把共享的 dataKey 重封给克隆目标，
  泄露源的数据，且克隆体无法在自己的 seal 下运营——seal 绑定 agent 的分叉
  应走 attestor）。
- proof 校验流程**与 iTransferFrom 完全一致**（走同一个 `_proofCheck`）
- 不动源 `tokenId`，`_incrementTokenId` 注册一个新的 **canonical 身份**
  （新全局 agentId，托管），把 `newTokenId` 铸给 `to`
- 新 token 继承同一份 `IntelligentData[]`，**没有 seal**
  （`getAgentSeal(newTokenId) == 0`）
- emit `Cloned(tokenId, newTokenId, from, to, entries)`，不 emit `ITransferred`

---

## 7. 防重放：NonceRegistry

`contracts/src/utils/NonceRegistryUpgradeable.sol` 被 **transfer verifier** 和
**各声誉注册表**继承（各自持有独立存储）。AgenticID 本体不消费 nonce——
`setAgentWallet` 转发给 canonical 注册表，后者用 ≤ 5 分钟 deadline（无 nonce）。

| 操作 | 消费方 | nonce key 派生 |
|---|---|---|
| transfer access proof | verifier | `keccak256("ERC7857_TRANSFER_ACCESS", erc7857Contract, nonce)` |
| transfer ownership proof | verifier | `keccak256("ERC7857_TRANSFER_OWNERSHIP", erc7857Contract, nonce)` |
| ServeProof | verified-feedback 注册表（及已废弃分叉） | `keccak256("SERVEPROOF", agentId, signature)` |

每个 nonce 消费时还会校验 `block.timestamp <= deadline`。Nonce 记录可经 `cleanExpiredNonces(keys)` 回收，前提是 `maxProofAge` 大于业务最长 deadline 窗口。

---

## 8. 关键设计要点

- **Canonical 托管绑定**。身份记录活在固定的 canonical ERC-8004 注册表上；
  AgenticID 托管其 token（全局唯一 agentId，canonical 记录永不离开托管），
  通过 read-through / write-forward 暴露同一个身份。生态里的 8004 工具读
  canonical 注册表时原生看到 AgenticID agent；可转让的 owner 活在本地
  AgenticID token 上。
- **agentSeal / sealId：set-once 永久绑定**。一个 agentId 的 seal 只能设一次，转让也不清除。换硬件时 attestor 给新 Agent TEE provision 同一个 `agentSeal_priv` 即可。
- **转让按 seal 分叉**。seal 绑定 agent 走标准 `transferFrom` 只转 ownership（数据始终锁在 TEE）；无 seal agent 走 proof 门禁的 `iTransferFrom`（dataKey 重加密给买家）。`iCloneFrom` 仅限无 seal。
- **mint 对称性**：`register` 和 `registerWithSeal` 都 emit `ITransferred(0x0, to, agentId, entries[])`，indexer 对 mint 和 transfer 统一处理。
- **dataKey 只在 TEE 内流动**：attestor 生成后丢弃、Agent TEE 持有、Oracle TEE 转让时短暂持有后丢弃。链上只见 sealedKey 密文。
- **Oracle 加密 pubkey 在 TappRegistry**：通过 0g-Tapp 的 `TappRegistry` 合约（外部依赖、已上线）的 `getNode` / `getNodeList` 视图发布，不进 `TEEDataVerifier` 存储，保持 verifier 简洁。Agent TEE 转让时直接查 registry。
- **8004 兼容在两条轴上都是 canonical 的**。身份托管绑定 canonical Identity Registry（0x8004… 单例），8004 身份工具原生看到 AgenticID agent。Feedback 由 client **直接提交到 canonical Reputation Registry**（per-client 归因原生、所有 8004 工具可读），本地 `VerifiedFeedbackRegistry` 叠加 TEE 层：给有 ServeProof 背书的 canonical 条目盖章并存审计数据。在乎真伪的读方做交集；不在乎的读方照常拿标准 8004 声誉。身份的无参 `register()` overload 仍**有意禁用**（注册必须携带 IntelligentData）。先前的私有声誉分叉（`AgenticIDReputationRegistry`）**已废弃**——存量环境仍在运行，新部署不再包含。目标 ERC-8004 修订版：**2026-01-25**。

---

## 9. 测试

190 个 Foundry tests / 21 suites（188 通过，2 个 fork 测试未设 `FORK_RPC`
时跳过），`forge test` 全绿。覆盖每个 `external` / `public` 函数和每条文档化
的 error 路径。

| Suite | Cases | 覆盖 |
|---|---|---|
| `AgenticID.t.sol` | 10 | register / registerWithSeal / 禁用 overload / attestor 白名单 |
| `AgentSeal.t.sol` | 5 | set-once / sealId 冲突 / 零值 / 补 seal / 非 attestor |
| `TransferFlow.t.sol` | 23 | iTransferFrom eth + 自定义模式、delegate、签名/nonce/deadline/pubkey 全面攻击面 |
| `Clone.t.sol` | 9 | iCloneFrom + 源保留 + 新 token 无 seal + Cloned vs ITransferred |
| `TransferHook.t.sol` | 4 | `_update` 清 agentWallet / authorizedUsers，保留 seal/data/URI/metadata |
| `VerifiedFeedback.t.sol` | 27 | attestFeedback ServeProof 验签 / canonical 条目绑定 / 防自评 / 对着 canonical mock 的 verified summary |
| `FeedbackBatcher.t.sol` | 6 | EIP-7702 委托批处理（7702 cheatcode）：原子写+盖章、坏 proof 回滚、自调门禁 vs 直调/外人调用 |
| `Reputation.t.sol` | 24 | 已废弃分叉：giveFeedback ServeProof 验签 + revoke / appendResponse 全路径（含跨实现 digest 已知答案向量）|
| `DataStorage.t.sol` | 13 | update / updateAt + 空 / 越界 / 非 owner |
| `Authorize.t.sol` | 9 | 授权增删查清 + 重复 / 零址 / 非 owner |
| `AgentWallet.t.sol` | 8 | setAgentWallet EIP-712 + 过期 / 重放 / 非 owner / unset |
| `AgentURIAndMetadata.t.sol` | 9 | setAgentURI / setMetadata + 覆写 / nonexistent |
| `VerifierAdmin.t.sol` | 7 | oracle 轮换 / pause（pauser 角色）/ maxProofAge / onlyOwner |
| `AgenticIDAdmin.t.sol` | 7 | attestor 增删 / frameworkHash / setVerifier / onlyOwner |
| `Upgradeable.t.sol` | 9 | Timelock 升级 beacon（非 Timelock 拒绝 / 延时前拒绝 / 延时后成功+state 保留）+ pauser 角色（非 pauser 拒绝 / 暂停阻断写路径 / view 正常 / 解锁 / setPauser 轮换）|
| `CanonicalBinding.t.sol` | 9 | canonical 托管（token 由合约持有、本地转让后不动）/ 全局 agentId 计数器 / URI + metadata 的 canonical 可见性 / mint 时 agentWallet 清空 / agentId-0 sealId 哨兵 / clone 注册新 canonical id |
| `UpgradeReputation.t.sol` | 2 | 声誉 beacon 归 Timelock 所有 + feedback 存储在 beacon 升级后保留 |
| `InitializerGuard.t.sol` | 3 | proxy + impl 都不可 reinit |
| `StorageLayout.t.sol` | 2 | 每个 ERC-7201 槽常量与其 namespace 推导一致（+ BaseDataVerifier 有意为之的字面量）|
| `ERC165.t.sol` | 2 | 9 个声明接口正、`0xffffffff` / unknown 负 |
| `CanonicalForkIntegration.t.sol` | 2 | 对着线上 canonical 注册表 self-mint + verified-feedback attest（仅设了 `FORK_RPC` 才跑，否则跳过）|

共享 scaffolding 在 `test/AgenticIDTestBase.sol`：两种 EIP-191 变体
（hex-encoded 用于 transfer proof，raw-32-byte 用于 ServeProof / wallet sig）、
proxy 部署、proof / mint helpers。新增 suite 通常只需要继承 + 写业务断言。


## 10. 进一步阅读

- **[`DEPLOYMENT.md`](DEPLOYMENT.md)** —— 部署 / 升级 / Etherscan verify 全套
  runbook（10 合约一次部署、Timelock 两阶段升级、`verify.sh` 工作原理、0g
  Galileo testnet 参考地址）。
