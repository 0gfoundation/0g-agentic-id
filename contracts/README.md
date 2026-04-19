# AgenticID Contracts

Solidity 合约层实现了 **AgenticID 协议**：把 ERC-8004 身份/声誉 注册表和 ERC-7857
智能 NFT 结合起来，为 TEE 内运行的 AI agent 提供可验证的链上身份、数据密钥原子
交付、以及抗 sybil 的声誉系统。

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

> ⚠️ **forge-std 钉在 v1.12.0 是有意的。** v1.13.0+ 改了内部 memory 布局，会触发
> Solidity 0.8.24 + via_ir 的一个 codegen bug——local `uint256` 变量在特定调用序列
> 下会被意外改写（表现为 `deadline` 从 3601 变 7202）。要升级 forge-std 须先把
> solc 升到 >= 0.8.27（多个 via_ir bug 已修）。

### 编译与测试

```bash
forge build                     # 增量编译到 out/
forge build --force             # 强制全量重编
forge test                      # 跑全量测试（当前 103 tests / 14 suites）
forge test -vvvv                # 详细 trace
forge test --match-path test/TransferFlow.t.sol   # 只跑指定 suite
forge fmt                       # 格式化
forge clean                     # 清 out/
```

### `foundry.toml` 关键配置说明

```toml
[profile.default]
src = "contracts"               # 源码目录（不是默认的 src/）
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

`via_ir = true` 是最重要的一条——IR 编译后端解决深堆栈问题，少了这行编译会失败。

---

## 2. 合约布局

```
contracts/
├── AgenticID.sol                               主合约（身份 + 7857 token）
├── AgenticIDReputationRegistry.sol             声誉注册表
├── ERC7857Upgradeable.sol                      7857 核心（iTransferFrom）
├── ERC8004IdentityRegistryUpgradeable.sol      8004 身份（register/metadata/wallet）
├── extensions/
│   ├── ERC7857AuthorizeUpgradeable.sol         链下使用授权名单
│   ├── ERC7857CloneableUpgradeable.sol         iCloneFrom
│   └── ERC7857IDataStorageUpgradeable.sol      IntelligentData 存储/更新
├── verifiers/
│   ├── BaseDataVerifier.sol                    transfer proof 基类
│   └── TEEDataVerifier.sol                     TEE 签名的 ownership proof 实现
├── utils/
│   └── NonceRegistryUpgradeable.sol            统一 nonce + deadline 防重放
└── interfaces/
    └── I*.sol                                  全部接口定义
```

AgenticID 通过 C3 linearization 把四条路径叠起来：

```
AgenticID
  ├── ERC8004IdentityRegistryUpgradeable         (agentURI / metadata / agentWallet)
  ├── ERC7857IDataStorageUpgradeable             (IntelligentData[])
  ├── ERC7857AuthorizeUpgradeable                (authorizedUsers[])
  ├── ERC7857CloneableUpgradeable                (iCloneFrom)
  └── OwnableUpgradeable                          (owner / attestor 管理) (#comment1：这是什么？)
```

共享同一个 ERC-721 token 实例，一个 agent = 一个 tokenId = 一个 agentId。

---

## 3. off-chain 三个 TEE 角色

合约逻辑只能表达出协议的一半，另一半靠三个 off-chain TEE 协作：

| 角色 | 持有的秘密 | 职责 |
|---|---|---|
| **Attestor TEE** | `masterKey`（KMS 提供）| 生成 `agentSeal_priv = derive(masterKey, sealId)`；mint 时生成 `dataKey` 并封给 `agentSeal_pub`；后续给经 RA 的 Agent TEE provision `agentSeal_priv` |
| **Agent TEE** | `agentSeal_priv`（单个 agent 的）+ `dataKey` | 跑 agent 业务、用 `dataKey` 解密模型/配置；签 ServeProof；转让时验 AccessProof 后把 `dataKey`（ECIES 加密）交给 Oracle TEE | (#comment2：卖方Agent TEE不用验 AccessProof？是买方Agent TEE要生成AccessProof？这里具体流程我还没想清楚，怎么验证买方是一个Agent TEE，得参考注册（Deploy）流程让Attestor TEE参与)
| **Oracle TEE** | `teeOracleAddress_priv` + `Oracle_ECIES_priv` (#comment3: 这两个priv是同一个？) | 转让时解 ECIES 拿 `dataKey` → 用 `buyer_pubkey` 重封 → 签 OwnershipProof；立即丢弃 `dataKey` | 

关键安全属性：
- `dataKey` 只在 TEE 内流动，**从不出现在链上明文或 EOA 钱包**
- TEE 单点故障影响有限：Agent TEE 挂 → attestor 再 provision；Oracle TEE 挂 → 转让暂停但重启可恢复（无持久状态）
- KMS 挂 → protocol 级事件，需 `masterKey` 容灾保证 (#comment4：集群容灾)

---

## 4. 流程 1: 注册

### 路径 A — attestor-mint

**链下步骤**（Attestor TEE 内）：
1. 生成 `sealId`（随机或按策略派生），推出 `agentSeal_priv = derive(masterKey, sealId)` 和 `agentSeal_addr`
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

前置要求 `msg.sender` 在 `trustedAttestors` 名单里（`onlyOwner` 维护）。

**事件**：
- `Registered(agentId, agentURI, to)` —— ERC-8004 身份注册
- `Transfer(0x0, to, agentId)` —— ERC-721 mint
- `MetadataSet × N`、`Updated(agentId, [], newDatas)`
- `AgentSealSet(agentId, agentSeal_addr, sealId)`
- `ITransferred(0x0, to, agentId, entries[])` —— sealedKey payload 发布

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

此时 agent 没有 `agentSeal`，不能签 ServeProof、不能积累声誉。想获得这个能力，owner 后续可以找 attestor 调 `setAgentSeal(agentId, agentSeal_addr, sealId)`——一次性操作，之后永久锁定。

### 关键不变量

| 字段 | 一旦设置 | 转让后 |
|---|---|---|
| `agentSeal` | 永不可变（`setAgentSeal` 只能调一次）| 保留 |
| `sealId` | 永不可变 | 保留 |
| `agentWallet` | 可重设（带 EIP-712 签名）| **清空** |
| `authorizedUsers` | 可增删 | **清空** |
| `agentURI` / `metadata` | owner 可改 | 保留 |
| `IntelligentData[]` | owner 可改（`update`/`updateAt`）| 保留 |

---

## 5. 流程 2: 声誉积累

### ServeProof（链下，Agent TEE 签）

Client 向 Agent TEE 发起一次真实业务调用。Agent TEE 完成后在 TEE 内部构造：

```solidity
struct ServeProof {
    uint256   agentId;
    address   client;
    uint256   timestamp;
    uint256   deadline;              // 过期即 revert
    bytes32   taskHash;              // 任务哈希（输入/输出 / 合同） (#comment5：这必要的么？)
    bytes32[] dataHashes;            // 当下 TEE 加载的 IntelligentData hash 列表
    bytes32   frameworkHash;         // AgenticID framework 代码 hash
    bytes     signature;             // agentSeal_priv 签名
}
```

签名内容：
```
inner = keccak256(abi.encode(agentId, client, timestamp, deadline,
                             taskHash,
                             keccak256(abi.encodePacked(dataHashes)),
                             frameworkHash))
signature = personal_sign(inner, agentSeal_priv)
```

### 链上调用 `giveFeedback`

```solidity
AgenticIDReputationRegistry.giveFeedback(
    agentId, value, valueDecimals,
    tag1, tag2,
    endpoint, feedbackURI, feedbackHash,
    serveProof
)
```

合约做的事：
1. `proof.client == msg.sender`
2. 重建 `inner`，ecrecover 后和 `IAgenticID.getAgentSeal(agentId)` 比较 → 过签名
3. 通过 NonceRegistry 登记 `key = keccak256("SERVEPROOF", agentId, signature)`，同时校验 `deadline`
4. push `FeedbackEntry`，记 `clients`/`isClient`
5. emit `NewFeedback` + `FeedbackWithProof`

**防 sybil 的核心**：没有 agentSeal 就没有有效的 ServeProof，而 agentSeal_priv 只有 Agent TEE 持有。客户伪造不出 ServeProof，也没法不调 agent 就自己打分。

### 其他操作

- `appendResponse(agentId, client, feedbackIndex, responseURI, responseHash)`：agent owner 对某条 feedback 回复。每个 (agentId, client, feedbackIndex, responder) 限一次。
- `revokeFeedback(agentId, feedbackIndex)`：client 撤回自己的 feedback。

### 读接口（全兼容 ERC-8004）

- `readFeedback(agentId, client, idx)` —— 单条
- `readAllFeedback(agentId, clients[], tag1, tag2, includeRevoked)` —— 过滤读取
- `getSummary(agentId, clients[], tag1, tag2)` —— 归一到 18 decimals 求和 + 计数
- `getClients(agentId)` —— 所有曾提交 feedback 的 client
- `getServeData(agentId, client, idx)` —— 返回该条 feedback 当时的 `dataHashes` + `frameworkHash`，**买家尽调入口**

---

## 6. 流程 3: 转让与克隆

### `iTransferFrom` —— 更换 ownership + 原子交付 dataKey

**链下准备**（对每条 IntelligentData 都走一次）：

1. **Buyer 签 AccessProof**
   ```
   inner = keccak256(abi.encodePacked(dataHash, buyer_targetPubkey, nonce_ap, deadline_ap))
   ap.proof = personal_sign(inner, buyer_priv)
   ```
   `buyer_targetPubkey` 有两种模式：空串 = 用 buyer 的以太坊 pubkey（64 字节未压缩）；非空 = 自选加密公钥。

2. **Agent TEE ↔ Oracle TEE 协作**
   - Seller 把 AccessProof 提交给 Agent TEE (#comment6：AccessProof是买家验的)
   - Agent TEE 验 AccessProof 签名，决定是否授权这次转让 (#comment6：AccessProof是买家验的，正确的应该是有一个买家 Agent TEE 去下载dataHash的内容，但流程我还没想清楚是怎样的：也许是，1. 对Attestor发起购买某agent #tokenId；2. Attestor 帮买家初始化一个 agent TEE，并传入 tokenId；3. 买家agent tee下载dataHash内容，返回AccessProof并要AgentSeal（这里签的AccessProof用买家agent tee签的，Attesstor收到后会用买家agentSeal重新签）；4. Attestor再问卖家agent Tee要ownershipProof；5.卖家agent TEE call oracle拿到ownershipProof，返回给Attestor；6. 链上验证proof，完成tranfser。这里Attestor的作用是保证买家是一个agentTee，数据不会出tee。这个过程更偏向clone过程，如果是transfer的话，直接把token ownership转给买家就好了？)
   - Agent TEE 查 TappRegistry 拿到 `Oracle_pubkey`，验 Oracle 的 RA (#comment7：注册上的就是已经RA过了)
   - Agent TEE 解出 `dataKey`，用 Oracle_pubkey 做 ECIES → `cipher`
   - Agent TEE 把 `cipher + buyer_targetPubkey + nonce_op + deadline_op` 发给 Oracle TEE
   - Oracle TEE 解 ECIES 拿 `dataKey`，用 `buyer_targetPubkey` 重封 → `sealedKey_new`
   - Oracle TEE 签 OwnershipProof：
     ```
     inner = keccak256(abi.encodePacked(dataHash, sealedKey_new,
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

### `iCloneFrom` —— 铸克隆 token，源不变

`ERC7857CloneableUpgradeable.iCloneFrom(from, to, tokenId, proofs[])`

- proof 校验流程**与 iTransferFrom 完全一致**（走同一个 `_proofCheck`）
- 不动源 `tokenId`，`_incrementTokenId` 铸 `newTokenId` 给 `to`
- 新 token 继承同一份 `IntelligentData[]`
- 新 token **没有 seal**（`getAgentSeal(newTokenId) == 0`），attestor 需另行 `setAgentSeal` 才能让新 token 签 ServeProof
- emit `Cloned(tokenId, newTokenId, from, to, entries)`，不 emit `ITransferred`

---

## 7. 防重放：统一的 NonceRegistry

所有带签名的操作都过 `contracts/utils/NonceRegistryUpgradeable.sol`：

| 操作 | nonce key 派生 |
|---|---|
| transfer access proof | `keccak256("ERC7857_TRANSFER_ACCESS", erc7857Contract, nonce)` |
| transfer ownership proof | `keccak256("ERC7857_TRANSFER_OWNERSHIP", erc7857Contract, nonce)` |
| ServeProof | `keccak256("SERVEPROOF", agentId, signature)` |
| setAgentWallet | `keccak256("SET_AGENT_WALLET", agentId, newWallet, nonce)` |

每个 nonce 消费时还会校验 `block.timestamp <= deadline`。Nonce 记录可经 `cleanExpiredNonces(keys)` 回收，前提是 `maxProofAge` 大于业务最长 deadline 窗口。

---

## 8. 关键设计要点

- **agentSeal / sealId：set-once 永久绑定**。一个 agentId 的 seal 只能设一次，转让也不清除。换硬件时 attestor 给新 Agent TEE provision 同一个 `agentSeal_priv` 即可。
- **mint 对称性**：`register` 和 `registerWithSeal` 都 emit `ITransferred(0x0, to, agentId, entries[])`，indexer 对 mint 和 transfer 统一处理。
- **dataKey 只在 TEE 内流动**：attestor 生成后丢弃、Agent TEE 持有、Oracle TEE 转让时短暂持有后丢弃。链上只见 sealedKey 密文。
- **Oracle 加密 pubkey off-chain**：通过 `TappRegistry` 外部合约的 info 接口发布，不进 `TEEDataVerifier` 存储，保持 verifier 简洁。
- **8004 读接口全兼容**：任何读取 ERC-8004 身份/声誉的工具对 AgenticID agent 透明可用；但写接口（`register()` 无参、`giveFeedback` 无 proof）被**有意禁用**，强制使用携带 IntelligentData 或 ServeProof 的扩展版本。

---

## 9. 测试

103 个 Foundry tests / 14 suites，`forge test` 全绿。覆盖每个
`external` / `public` 函数和每条文档化的 error 路径。

| Suite | Cases | 覆盖 |
|---|---|---|
| `AgenticID.t.sol` | 8 | register / registerWithSeal / 禁用 overload / attestor 白名单 |
| `AgentSeal.t.sol` | 6 | set-once / sealId 冲突 / 零值 / 补 seal / 非 attestor |
| `TransferFlow.t.sol` | 16 | iTransferFrom eth + 自定义模式、delegate、签名/nonce/deadline/pubkey 全面攻击面 |
| `Clone.t.sol` | 7 | iCloneFrom + 源保留 + 新 token 无 seal + Cloned vs ITransferred |
| `TransferHook.t.sol` | 4 | `_update` 清 agentWallet / authorizedUsers，保留 seal/data/URI/metadata |
| `Reputation.t.sol` | 13 | giveFeedback ServeProof 验签 + revoke / appendResponse 全路径 |
| `DataStorage.t.sol` | 6 | update / updateAt + 空 / 越界 / 非 owner |
| `Authorize.t.sol` | 9 | 授权增删查清 + 重复 / 零址 / 非 owner |
| `AgentWallet.t.sol` | 7 | setAgentWallet EIP-712 + 过期 / 重放 / 非 owner / unset |
| `AgentURIAndMetadata.t.sol` | 7 | setAgentURI / setMetadata + 覆写 / nonexistent |
| `VerifierAdmin.t.sol` | 7 | oracle 轮换 / pause / maxProofAge / onlyOwner |
| `AgenticIDAdmin.t.sol` | 8 | attestor 增删 / frameworkHash / setVerifier / onlyOwner |
| `InitializerGuard.t.sol` | 3 | proxy + impl 都不可 reinit |
| `ERC165.t.sol` | 2 | 9 个声明接口正、`0xffffffff` / unknown 负 |

共享 scaffolding 在 `test/AgenticIDTestBase.sol`：两种 EIP-191 变体
（hex-encoded 用于 transfer proof，raw-32-byte 用于 ServeProof / wallet sig）、
proxy 部署、proof / mint helpers。新增 suite 通常只需要继承 + 写业务断言。

## 10. 已知未做的事

- **链下 SDK 的 ECIES 端到端测试**：合约对 `sealedKey` 是黑箱（只验 Oracle 签名覆盖到
  它，不验其加密正确性）。"Oracle TEE 封 dataKey → buyer 解出原始 dataKey" 这一段
  只能在 TS/Rust SDK 的集成测试里用工业级 ECIES 库验；Solidity 层做不到
- `TappRegistry` 合约本身（被引用但未定稿）
- "Agent TEE 在线状态"的链上感知（当前完全 off-chain 协商）
- Oracle 签 OwnershipProof 时不绑定 agentId（依赖 oracle 的 framework 自律）
- 卖家对 `targetPubkey` 的约束机制：当前 buyer 可以把 `targetPubkey` 指定为任意
  EOA pubkey（dataKey 会落到明文钱包）。如果卖家想强制"数据永远不出 TEE"，需要
  在合约层加 `dataPolicy` 字段或通过 TappRegistry 做 TEE pubkey 白名单
- **fuzz + invariant test 补强**：当前都是单点样例；nonce / deadline / pubkey 长度
  边界、`giveFeedback` 的 `valueDecimals` 归一化逻辑适合 `forge fuzz` 扫
- **gas 基线**：`forge snapshot` 未建立；合约优化 / 升级时缺少回归参照
- **solc 升级 + forge-std 解钉**：forge-std v1.12.0 是暂时方案，未来 solc 升到
  0.8.27+ 后可以解钉到最新 forge-std（见 §1 警告）
