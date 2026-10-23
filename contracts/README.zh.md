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
forge test                      # 跑全量测试（当前 290 tests / 28 suites；2 个 fork 测试无 FORK_RPC 时跳过）
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
  └── Ownable2StepUpgradeable                     (两步 owner / attestor 管理)
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

签名内容（域 + submitter + 注册表三重绑定：跨链/跨部署不可移植，跨钱包不可转让，只能在唯一一个注册表兑现）：
```
inner     = keccak256(abi.encode(block.chainid, identityRegistry, submitter,
                                 agentId, timestamp, deadline, taskHash,
                                 keccak256(abi.encodePacked(dataHashes)),
                                 frameworkHash))
digest    = keccak256(0x19 ‖ 0x00 ‖ verifiedFeedbackRegistry ‖ inner)   // EIP-191 version 0x00
signature = sign(digest, agentSeal_priv)                               // 直接签 digest——不再套一层 EIP-191
```

`verifiedFeedbackRegistry` 是 `VerifiedFeedbackRegistry` 的 **proxy** 地址，即
EIP-191 的 "intended validator"（链上实现：
`MessageHashUtils.toDataWithIntendedValidatorHash(address(this), abi.encodePacked(inner))`）。
sealed 运行时从 `VERIFIED_FEEDBACK_ADDR` 得知该地址——由 attestor 在创建 sandbox
时依据 `ATTESTOR_VERIFIED_FEEDBACK_ADDR` 注入。容器的 `VERIFIED_FEEDBACK_ADDR`
未设置、格式错误或为零地址——或者它的 `getIdentityRegistry()` 不是容器的
`AGENTIC_ID_ADDR`——→ 容器干脆不出 `X-Agent-Proof`。attestor 一侧，
`ATTESTOR_VERIFIED_FEEDBACK_ADDR` 留空或为零地址 → 容器拿到空值（因而不出
proof）；填了但不是地址、或其 `getIdentityRegistry()` 不是
`ATTESTOR_AGENTIC_ID_ADDR`，则 attestor 启动失败。自 `VerifiedFeedbackRegistry`
1.2.0 起它取代旧的 `personal_sign(inner)` 包装，旧格式一律**拒绝**——硬切换、
无回退（上线步骤见 [`DEPLOYMENT.md`](DEPLOYMENT.md) §7）。
该 digest 属于共识关键：五份副本各自独立实现——合约、`sealed/internal/proxy/`、
SDK 的 `ServeProof.ts`、attestor 控制台的 say-hi 校验和
`attestor/scripts/verify-agent.sh`（清单维护在根目录 [`AGENTS.md`](../AGENTS.md)）
——并都钉同一组已知答案向量（`VerifiedFeedback.t.sol`
`test_serveProofDigest_knownAnswerVector`）。

### 链上提交——client 两笔调用（SDK 打包成一步）

在启用 EIP-7702 的链上（0G Galileo 已实测支持），SDK 会把两笔合成**一笔原子的
type-4 交易**：client 的 EOA 委托给 `FeedbackBatcher` 后自调用
`giveFeedbackAndAttest`——代码跑在 EOA 自己的账户上下文里（两个内部调用的
msg.sender 都是 client 本人），index 在同一笔交易内读取；盖章失败会连
canonical 写入一起回滚。链不支持 7702 时 SDK 退回下面的两笔顺序流程。

**委托是持久的**：type-4 落链后委托一直挂在 EOA 上（`getCode(你的地址)` 读到
`0xef0100‖batcher` 即已委托），后续打分因此免重签；注销 = 再签一次指向零地址
的委托（7702 标准出口）。环境更换 batcher 地址后，已委托的 EOA 在下次
giveFeedback 时由 SDK 自动迁移。

```solidity
// 1. feedback → canonical 注册表（归因 = msg.sender，原生）
canonicalReputation.giveFeedback(agentId, value, valueDecimals,
                                 tag1, tag2, endpoint, feedbackURI, feedbackHash);

// 2. 验证章 → 本地注册表
VerifiedFeedbackRegistry.attestFeedback(agentId, feedbackIndex, serveProof);
```

`attestFeedback` 校验的事：
1. `agentId == proof.agentId`，且 `proof.submitter == msg.sender`（只有声明的 client 能兑——堵抢跑/盗用）；`0 < proof.timestamp ≤ proof.deadline`（1.2.0，FIND-15——`dataHashes` / `frameworkHash` 按 seal 签名的 proof 所声明的原样存储，不与 iData 或 framework 白名单比对）
2. 重建 `inner`，按 `toDataWithIntendedValidatorHash(address(this), inner)` 包装（EIP-191 version 0x00，validator 为本注册表 proxy），ecrecover 该 digest 后和 `IAgenticID.getAgentSeal(agentId)` 比较 → 过签名。旧的 `personal_sign` 包装 proof 会 revert `VerifiedFeedbackInvalidProofSignature`
3. 调用者不是 agent owner、被授权 operator、该 agent 的收款钱包（`getAgentWallet`，1.2.0——FIND-13），也不是该 agent 自己的 `agentSeal`（owner/operator 对照**本地** AgenticID 的 owner——canonical 注册表自己查不了，它眼里每个托管 token 的 owner 都是 AgenticID 合约）。这是 ERC-8004 合规检查，不是防 sybil——见下文残余风险
4. canonical 条目 `(agentId, msg.sender, feedbackIndex)` 存在、尚无章，且值在范围内：|value| ≤ 1e9、decimals ≤ 18（1.2.0，FIND-04——canonical 注册表接受最大 1e38，一条这样的条目曾会让包含该 client 的所有 summary 都 revert；否则 `VerifiedFeedbackValueOutOfRange`）
5. 通过 NonceRegistry 登记 `key = keccak256("SERVEPROOF", agentId, signature)`，同时校验 `deadline`（每张 proof 只能兑一次）
6. 存下 proof 的 `dataHashes` / `frameworkHash`，emit `FeedbackVerified`

**防 sybil 的核心**建立在两个前提上：只有 Agent TEE 持有 `agentSeal_priv`，
**并且** TEE 内没有任何东西会按需签 ServeProof digest。第二条并不能由第一条推出——
sealed 的 **sign socket**（`/sign/personal_sign`、`/sign/typed_data`、
`/sign/transaction`）允许 agent 进程用 agentSeal 签名。它的原像只有
`0x19 0x45…`（personal_sign）、`0x19 0x01…`（EIP-712），或由 socket 按字段自行
构造的交易编码——从不签裸 hash，也从不签 EIP-191 version `0x00`。由于 digest 是
`0x19 0x00 ‖ registry ‖ inner`，agent 无法离线伪造 ServeProof 内容。（1.2.0 之前
digest 是 `personal_sign(inner)`，socket 对任意 32 字节消息都会签出它——审计
FIND-01。）这条 socket 不变量是承重的：给 socket 加上裸 hash 或 version `0x00`
签名能力，就会重新打开伪造口子。

canonical 注册表是 permissionless 的——谁都能往里写未验证的 feedback——但验证章
需要一张 TEE 真实签发的 proof。在乎真伪的读方拿章的集合和 canonical 条目做交集。
这一点从该环境的 1.2.0 升级区块起成立（记录在 [`DEPLOYMENT.md`](DEPLOYMENT.md)
§6）：此前的章没有 FIND-01 / FIND-02 保证，而链上 view（`isVerified`、
`getServeData`、`getVerifiedSummary*`）无法排除它们——要按区块过滤
`FeedbackVerified` 日志。

**残余风险（上述机制不覆盖）**：agent——或其 owner——仍可以带着自己控制的
`X-Client-Address` 向自己的 proxy（如 loopback `:8080`，或公开的 `/hello`）发
请求，拿到*真实*的 proof，再从那个钱包兑现。owner / operator / 收款钱包 /
agentSeal 防自评检查拦不住这种做法——一个新钱包（哪怕是 seal 出资的）就能通过。这是已文档化的
sybil 类问题，所以 `getVerifiedSummary` 要求调用方显式给出信任的 client 列表。

### 其他操作

- `revokeFeedback` / `appendResponse`：直接在 canonical 注册表上操作（client 撤回自己的条目；章不动，但 `getVerifiedSummary` 跟随 canonical 的 revoked 标记）。

### 读接口

- `isVerified(agentId, client, idx)` —— 这条 canonical 条目有没有章？
- `getVerifiedIndexes(agentId, client)` / `getVerifiedClients(agentId)` —— 枚举已验证集合
- `getVerifiedSummary(agentId, clients[], tag1, tag2)` —— 聚合指定 client 的**已验证** canonical 条目（值实时从 canonical 读取；跳过 revoked，也跳过 1.2.0 之前盖章、超出值范围的条目；求和 + 计数，归一到固定 18 decimals；`clients` 必须非空——由调用方决定信谁）。仅限链下 `eth_call`。
- `attestFeedbackWithTask(…, TaskReveal)` —— 额外开箱 proof 的 taskHash 承诺（方法 / 路径 / 正文**哈希** / 状态码——正文本身不上链）：合约重算哈希比对,把路径记为该条目的 **TEE 验证接口**。`getVerifiedEndpoint` 读回;`getVerifiedSummaryForEndpoint(agentId, clients[], uri)` 按接口聚合,不依赖 client 自报的 tag（`uri` 不能为空——`VerifiedFeedbackEndpointRequired`，1.2.0：未开箱的条目存的是 ""，空过滤条件恰好匹配所有接口未经证明的条目，FIND-09）。reveal 必须满足：method 在已知 HTTP 集合内、URI 以 `/` 开头、`statusCode` 在 **100..999**（恰好三位数——Go `net/http` 的输出范围），否则 revert `VerifiedFeedbackInvalidTaskReveal`。否则 packed 原像有歧义：一两位数的 status 能让 reveal 把正文哈希的字节挪进 URI，记下一个调用从未访问过的接口（审计 FIND-02，1.2.0 起强制）。
- `getServeData(agentId, client, idx)` —— 该条 feedback 当时的 `dataHashes` + `frameworkHash`，**买家尽调入口**：和 `intelligentDatasOf(agentId)` 对比即可判断这份声誉挣到手之后 agent 的数据有没有变。
- 上述所有 view 也会计入该环境 1.2.0 升级区块（`DEPLOYMENT.md` §6）之前的章，而这些章没有 FIND-01 / FIND-02 保证（审计数据和验证接口都不可信）。view 不带区块过滤；只要切换后章的读方，按区块过滤 `FeedbackVerified` 日志。

> **已废弃——必须暂停**：先前的私有分叉（`AgenticIDReputationRegistry`，proof
> 门禁的 `giveFeedback` + 自有 feedback 存储）被这套拆分取代。存量的 test 和 dev
> 环境上它仍在运行（mainnet 从未部署）、源码保留在仓库，但新部署只带
> `VerifiedFeedbackRegistry`。它仍按**旧的** `personal_sign(inner)` digest 验签——
> agent 进程可经 sign socket 对任意 `inner` 拿到这种签名——所以它接受的 feedback
> 可被伪造。其 pauser 必须在 `VerifiedFeedbackRegistry` 1.2.0 切换之前（或同时）
> 对每个在线实例调用 `pause()`。1.2.0 的注册表绑定 proof 在它上面验不过，所以同一
> 张 proof 不再能两边各兑一次。

---

## 6. 流程 3: 转让与克隆

转让行为按 agent 有无 seal（`getAgentSeal(tokenId) != 0`）分叉：

- **seal 绑定 agent**（运营实体）：ownership 走标准 ERC-721 `transferFrom` /
  `safeTransferFrom`——单纯换 owner。iData 始终锁在不可变 `agentSeal` 的 TEE
  之下，无需重加密；运营权链下随 ownership 走（attestor 给新 owner 重新
  provision）。seal 绑定的 token 调 `iTransferFrom` 和 `iCloneFrom` 都会
  **revert**（`AgenticIDSealedAgentUseTransfer` / `AgenticIDCannotCloneSealedAgent`）。
  fork 一个 seal 绑定的 agent 走 attestor 的 `/clone` 端点，两种授权模式
  （issue #133）：**owner 模式**——源 agent 现任 owner 签
  `AgenticID.Clone.v1` 意图；**contract 模式**（市场分叉）——**买家**签
  `AgenticID.CloneContract.v1` 意图（canonical 绑定 `keccak256(auth_data)` 与
  authorizer 地址），由 owner 配置的 `ICloneAuthorizer` 在 `CloneGate.cloneFrom`
  里（卫星合约——AgenticID 顶着 EIP-170 字节码上限，本体不动）
  原子决策。
- **无 seal agent**（数据 blob）：普通 transfer 保持禁用；ownership 只能走下面
  proof 门禁的 `iTransferFrom`，原子地把 dataKey 重加密给买家。`iCloneFrom` 可用。

### 政策模式克隆（issue #133）：`CloneGate` 卫星合约

seal 绑定 agent 的 owner 可以把 fork 授权委托给一个政策合约——市场分叉流程：

所有政策克隆逻辑都在 `CloneGate` 卫星里——AgenticID 本体不动（它顶着 EIP-170
上限；新能力一律以伴生合约交付，同 `VerifiedFeedbackRegistry`）。gate 需在
trusted-attestor 白名单内（它经 `registerWithSeal` 铸造）；AgenticID 暂停即
克隆暂停。流程：

1. **发布者一次性 opt-in：** `CloneGate.setCloneAuthorizer(tokenId, authorizer)`——
   `ICloneAuthorizer` 的纯 view `canClone(source, to, caller, authData)` 决定
   contract 模式克隆是否放行。配置绑定设置它的 owner：token 换手即失效
   （`cloneAuthorizerOf` 返回**生效中**的 authorizer，owner 变了就返回 0）。
   注意失效是**休眠而非抹除**：原 owner 回购 token（A→B→A）后旧政策会静默
   复活；要永久清除需显式 `setCloneAuthorizer(id, 0)`。`cloneSourceOf` 血统
   跨转让保留（历史事实）。authorizer 为零 → contract 模式 fail-closed。

   不想自己写政策合约的发布者，可将 token 指向**官方通用政策
   `StandardCloneAuthorizer`**（不可升级、无任何特权角色）：按
   `(sourceAgentId, buyer)` 记录的**纯放行开关**——`grant`/`revoke` 只有源
   token 的**当前 owner**（即卖家，无平台管理员）能调，`authData` 一律忽略，
   且每条授权带与 gate 配置一致的 owner-at-grant 惰性失效。有意不做按张
   计票：view 版 `canClone` 信任模型下 N 张票等于 1 张票，订单对账留在
   卖家自己的记录里，一次性消费 = 卖家看到 `ClonedFrom` 事件后 `revoke`
   ——理由见 `ICloneAuthorizer` 的信任模型注释。`examples/DevCloneAuthorizer`
   仍作为自写政策的最简参考骨架保留。
2. **买家分叉：** 签一个 clone-intent，canonical 绑定操作本体（幂等键、源、
   目标）**和政策上下文**（`keccak256(auth_data)` + authorizer 地址——relayer
   只能转运意图，不能换 auth_data 重放，也不能跨政策轮换搬运），经 attestor
   `/clone`（或 SDK 的 `ag.agent.clone({ authorization: { authData } })`）提交。
3. **原子门禁：** attestor worker 走 `CloneGate.cloneFrom` 铸造（内部调
   `registerWithSeal`），`canClone` 与铸造同交易
   执行——迟到的 deny、被清空的 authorizer、过期的 re-seal 都会让整笔交易
   revert。`nonReentrant`，与 iTransferFrom/iCloneFrom 同款。revert 的
   authorizer 冒泡自己的 revert 数据（fail-closed、保留诊断信息）；
   `AgenticIDCloneDenied` 只用于未配置/明确拒绝。

### `iTransferFrom`（无 seal）—— 更换 ownership + 原子交付 dataKey

**链下准备**（对每条 IntelligentData 都走一次）：

1. **Buyer 签 AccessProof**
   ```
   inner = keccak256(abi.encode(chainId, erc7857, tokenId, from, isClone, dataHash, buyer_targetPubkey, nonce_ap, deadline_ap))
   ap.proof = personal_sign(inner, buyer_priv)
   ```
   `buyer_targetPubkey` 有两种模式：空串 = 用 buyer 的以太坊 pubkey（64 字节未压缩）；非空 = 自选加密公钥。`chainId` 和 `erc7857`（AgenticID token 合约地址）对两种 proof 做域分隔，签名无法在其他链或其他合约上重放；`tokenId` 和 `from`（被卖的 token 及其卖家）把 proof 绑定到这个 token，声明了相同 dataHash 的仿冒 token 无法兑现它们；`isClone`（这里为 `false`，`iCloneFrom` 时为 `true`）绑定动作，转让 proof 不能被拿去兑现克隆（1.2.0，审计 FIND-05）。

2. **Agent TEE ↔ Oracle TEE 协作**
   - Seller 把买家签的 AccessProof 提交给卖家 Agent TEE
   - 卖家 Agent TEE 验 AccessProof 签名（recover 出来等于 `to` 或 `accessDelegates[to]`），决定是否授权这次转让
   - 卖家 Agent TEE 查 TappRegistry 拿到 `Oracle_pubkey`（TappRegistry 注册过即 RA 过，无需重复 attest）
   - Agent TEE 解出 `dataKey`，用 Oracle_pubkey 做 ECIES → `cipher`
   - Agent TEE 把 `cipher + tokenId + from + buyer_targetPubkey + nonce_op + deadline_op` 发给 Oracle TEE
   - Oracle TEE 解 ECIES 拿 `dataKey`，用 `buyer_targetPubkey` 重封 → `sealedKey_new`
   - Oracle TEE 签 OwnershipProof：
     ```
     inner = keccak256(abi.encode(chainId, erc7857, tokenId, from, isClone, dataHash,
                                  sealedKey_new, buyer_targetPubkey, nonce_op, deadline_op))
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
   - 两个签名都按本次调用的 `tokenId` / `from` 和动作校验——`_proofCheck` 把它们传给 `verifyTransferValidity(tokenId, from, isClone, proofs)`
   - 两个 nonce 都走 NonceRegistry（按 `msg.sender` + 分类 tag 命名空间；1.2.0 起 access nonce 还按 recover 出的签名者区分，ownership nonce 还按 tokenId 区分）+ 各自 deadline 校验
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
- proof 校验流程**与 iTransferFrom 完全一致**（走同一个 `_proofCheck`；proof 按源 `tokenId`、其 owner `from` 及 `isClone = true` 签名）
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
| transfer access proof | verifier | `keccak256("ERC7857_TRANSFER_ACCESS", erc7857Contract, signer, nonce)`——1.2.0 起含 `signer`（recover 出的买家 / delegate），两个买家选了相同 nonce 字节也不会冲突（FIND-06） |
| transfer ownership proof | verifier | `keccak256("ERC7857_TRANSFER_OWNERSHIP", erc7857Contract, tokenId, nonce)`——1.2.0 起含 `tokenId`，别的 token 的 oracle proof 占用不了这个 token 的 nonce |
| ServeProof | verified-feedback 注册表（及已废弃分叉） | `keccak256("SERVEPROOF", agentId, signature)` |

每个 nonce 消费时还会校验 `block.timestamp <= deadline`，并拒绝超过 `now + maxProofAge` 的 deadline（`NonceDeadlineTooFar`）。`now > consumedAt + maxProofAge` 之后记录可经 `cleanExpiredNonces(keys)` 回收——那时 proof 已过期。这只在 `maxProofAge` 从不调小时成立，所以 1.2.0 起 `setMaxProofAge` 只能调大，范围限定在 2 小时–365 天（ServeProof 有效期的两倍），`initialize` 也检查同一范围（审计 FIND-07：调小它会让仍有效的已消费 proof 能被重放）。

---

## 8. 关键设计要点

- **Canonical 托管绑定**。身份记录活在固定的 canonical ERC-8004 注册表上；
  AgenticID 托管其 token（全局唯一 agentId，canonical 记录永不离开托管），
  通过 read-through / write-forward 暴露同一个身份。生态里的 8004 工具读
  canonical 注册表时原生看到 AgenticID agent；可转让的 owner 活在本地
  AgenticID token 上。
- **治理：owner 直接调用且两步转移，升级走 Timelock**。AgenticID、
  TEEDataVerifier、VerifiedFeedbackRegistry 均为 `Ownable2Step`（1.2.0，审计
  FIND-16）：`transferOwnership(x)` 只设置 `pendingOwner`（事件
  `OwnershipTransferStarted`），`x` 调 `acceptOwnership()` 后 ownership 才转移。
  owner 专属的管理操作——attestor 白名单、framework hash 白名单、
  `setVerifier` / `setTeeOracleAddress`、`setPauser`、`setMaxProofAge`（只能调大）——都是
  直接调用，不走 timelock；只有 beacon 升级经过 Timelock（mainnet `minDelay`
  1 天，testnet / dev 为 0）。这两个替换 setter 拒绝 `address(0)`
  （`AgenticIDZeroAddress` / `TEEDataVerifierZeroAddress`），并 emit
  `VerifierUpdated` / `TeeOracleUpdated`（旧值、新值），与 `PauserUpdated` 一致
  （FIND-12）。各环境的角色持有者见 [`DEPLOYMENT.md`](DEPLOYMENT.md) §1 / §6。
- **agentSeal / sealId：set-once 永久绑定**。一个 agentId 的 seal 只能设一次，转让也不清除。换硬件时 attestor 给新 Agent TEE provision 同一个 `agentSeal_priv` 即可。
- **转让按 seal 分叉**。seal 绑定 agent 走标准 `transferFrom` 只转 ownership（数据始终锁在 TEE）；无 seal agent 走 proof 门禁的 `iTransferFrom`（dataKey 重加密给买家）。`iCloneFrom` 仅限无 seal。
- **mint 对称性**：`register` 和 `registerWithSeal` 都 emit `ITransferred(0x0, to, agentId, entries[])`，indexer 对 mint 和 transfer 统一处理。
- **dataKey 只在 TEE 内流动**：attestor 生成后丢弃、Agent TEE 持有、Oracle TEE 转让时短暂持有后丢弃。链上只见 sealedKey 密文。
- **Oracle 加密 pubkey 在 TappRegistry**：通过 0g-Tapp 的 `TappRegistry` 合约（外部依赖、已上线）的 `getNode` / `getNodeList` 视图发布，不进 `TEEDataVerifier` 存储，保持 verifier 简洁。Agent TEE 转让时直接查 registry。
- **8004 兼容在两条轴上都是 canonical 的**。身份托管绑定 canonical Identity Registry（0x8004… 单例），8004 身份工具原生看到 AgenticID agent。Feedback 由 client **直接提交到 canonical Reputation Registry**（per-client 归因原生、所有 8004 工具可读），本地 `VerifiedFeedbackRegistry` 叠加 TEE 层：给有 ServeProof 背书的 canonical 条目盖章并存审计数据。在乎真伪的读方做交集；不在乎的读方照常拿标准 8004 声誉。身份的无参 `register()` overload 仍**有意禁用**（注册必须携带 IntelligentData）。先前的私有声誉分叉（`AgenticIDReputationRegistry`）**已废弃**——存量环境仍在运行，新部署不再包含；它仍接受旧的 ServeProof digest，必须暂停（§5）。目标 ERC-8004 修订版：**2026-01-25**。

---

## 9. 测试

290 个 Foundry tests / 28 suites（288 通过，2 个 fork 测试未设 `FORK_RPC`
时跳过），`forge test` 全绿。覆盖每个 `external` / `public` 函数和每条文档化
的 error 路径。

| Suite | Cases | 覆盖 |
|---|---|---|
| `AgenticID.t.sol` | 10 | register / registerWithSeal / 禁用 overload / attestor 白名单 |
| `AgentSeal.t.sol` | 6 | mint 时绑定 / sealId 冲突 / seal 地址复用（FIND-08）/ 零值 / 非 attestor |
| `TransferFlow.t.sol` | 30 | iTransferFrom eth + 自定义模式、delegate、签名/nonce/deadline/pubkey 全面攻击面；token 与动作绑定——仿冒 token 兑现不了复制来的 proof、两种 proof 各自绑定、`from` 也绑定、克隆 proof 不能用来转让（FIND-05）；access nonce 按签名者区分（FIND-06）、ownership nonce 按 token 区分；access + ownership digest 已知答案向量 |
| `Clone.t.sol` | 11 | iCloneFrom + 源保留 + 新 token 无 seal + Cloned vs ITransferred + 仿冒 token 兑现不了源 token 的 proof + 转让 proof 不能用来克隆 |
| `TransferHook.t.sol` | 4 | `_update` 清 agentWallet / authorizedUsers，保留 seal/data/URI/metadata |
| `VerifiedFeedback.t.sol` | 47 | attestFeedback ServeProof 验签 / canonical 条目绑定 / 防自评（owner、operator、收款钱包、agentSeal）/ 值范围 ±1e9、decimals ≤ 18（FIND-04）/ proof 时间戳（FIND-15）/ maxProofAge 只能调大，含 cleanup 重放场景（FIND-07）/ 对着 canonical mock 的 verified summary / task-receipt 开箱，含 statusCode 100..999 边界、status-0 错位切分伪造与空 endpoint 过滤（FIND-09）/ 注册表绑定 digest：旧 personal_sign、EIP-712 包装、其他 validator 的 proof 均被拒（且注册表绑定 proof 在已废弃分叉上被拒），外加跨实现 digest 已知答案向量（inner + 签名 digest + 旧格式），以及 sealed proxy 钉住的 taskHash 向量经 attestFeedbackWithTask 兑现 |
| `FeedbackBatcher.t.sol` | 8 | EIP-7702 委托批处理（7702 cheatcode）：原子写+盖章、坏 proof 回滚、自调门禁 vs 直调/外人调用、已委托 EOA 仍能收 ETH / safeMint 的 NFT |
| `Reputation.t.sol` | 24 | 已废弃分叉：giveFeedback ServeProof 验签（旧 personal_sign digest）+ revoke / appendResponse 全路径（含 inner hash 已知答案向量）|
| `DataStorage.t.sol` | 13 | update / updateAt + 空 / 越界 / 非 owner |
| `Authorize.t.sol` | 9 | 授权增删查清 + 重复 / 零址 / 非 owner |
| `AgentWallet.t.sol` | 8 | setAgentWallet EIP-712 + 过期 / 重放 / 非 owner / unset |
| `AgentURIAndMetadata.t.sol` | 9 | setAgentURI / setMetadata + 覆写 / nonexistent |
| `VerifierAdmin.t.sol` | 11 | oracle 轮换（拒绝零地址、`TeeOracleUpdated`）/ pause（pauser 角色）/ maxProofAge（只能调大、initialize 范围）/ onlyOwner |
| `AgenticIDAdmin.t.sol` | 11 | attestor 增删 / frameworkHash / setVerifier（拒绝零地址、`VerifierUpdated`）/ onlyOwner / 暂停覆盖范围——URI（owner 与 attestor）、metadata、钱包、授权写入被拦，撤销与解绑钱包放行（FIND-11）|
| `TwoStepOwnership.t.sol` | 6 | AgenticID / TEEDataVerifier / VerifiedFeedbackRegistry：提议后 owner 不变、只有 pending owner 能接受、接受后权限转移；再次提议覆盖、`address(0)` 取消 |
| `Upgradeable.t.sol` | 9 | Timelock 升级 beacon（非 Timelock 拒绝 / 延时前拒绝 / 延时后成功+state 保留）+ pauser 角色（非 pauser 拒绝 / 暂停阻断写路径 / view 正常 / 解锁 / setPauser 轮换）|
| `CanonicalBinding.t.sol` | 10 | canonical 托管（token 由合约持有、本地转让后不动）/ 全局 agentId 计数器 / URI + metadata 的 canonical 可见性 / mint 时 agentWallet 清空 / agentId-0 sealId 哨兵 / clone 注册新 canonical id / 第三方 canonical agent 的 metadata、钱包 view 会 revert（FIND-14）|
| `UpgradeReputation.t.sol` | 2 | 声誉 beacon 归 Timelock 所有 + feedback 存储在 beacon 升级后保留 |
| `UpgradeVerifiedFeedback.t.sol` | 5 | VerifiedFeedbackRegistry 经 Timelock 从 1.1.0 升到 1.2.0（升级前 impl = `test/mocks/` 里冻结的 1.1.0 源码）：章 / 审计数据 / 接口 / 配置 / nonce 均保留；切换后旧格式 proof 被拒、注册表绑定 proof 通过；owner 保留，之后为两步转移；升级前盖章的超范围条目被 summary 跳过，不再让它 revert |
| `UpgradeGovernance.t.sol` | 7 | AgenticID + TEEDataVerifier 从冻结的 1.1.0 源码（及其在 `test/mocks/v1_1_0/` 的冻结基类）经 1 天 Timelock（仿 mainnet 的延时、owner 作 proposer、开放执行）升到 1.2.0：seal 绑定 / iData / URI / metadata / 白名单 / verifier / oracle / nonce 均保留；升级后两步 ownership、零地址校验与 seal 地址唯一性生效；1.1.0 格式的转让 proof 被拒、token 绑定的通过；只升级其中一个会让非 seal 转让全部失败；升级前的 seal 作为其源 agent 的克隆 seal 会被 CloneGate 拒绝 |
| `CloneGate.t.sol` | 21 | policy 模式克隆卫星合约：setCloneAuthorizer 门禁 / cloneFrom 正常路径 + 全部 revert（attestor、无/拒绝/自身 revert 的 authorizer、arity、sealId、复用源 seal、暂停）/ 转让时按 owner-at-set 失效 / lineage |
| `StandardCloneAuthorizer.t.sol` | 10 | 官方按买家开关的克隆 policy：仅卖家可 grant/revoke、按 agent 隔离、转让后 grant 失效且收回后复活、经 gate 克隆 |
| `Eip170Size.t.sol` | 1 | 每个上链 impl 都在 EIP-170 运行时字节码上限内 |
| `InitializerGuard.t.sol` | 3 | proxy + impl 都不可 reinit |
| `StorageLayout.t.sol` | 3 | 每个 ERC-7201 槽常量与其 namespace 推导一致（+ BaseDataVerifier 有意为之的字面量）；OZ `Ownable2Step` 槽固定且与我们所有槽不相交 |
| `DeployScript.t.sol` | 8 | 部署脚本治理规则（`script/MainnetGovernance.sol`），库级 + 端到端。`Deploy.s.sol`：链 16661 上 Timelock `minDelay` 默认且至少 86400、无外部 admin，且不可用或有歧义的 PROPOSERS / EXECUTORS（为空、含 `0x0` proposer、OWNER 不是 proposer、`0x0` 与具名 executor 混用、具名 executor 里没有 OWNER）在 broadcast 前 revert；其余链 delay 0、OWNER 为 admin、不检查角色集合。`DeployVerifiedFeedback.s.sol` / `DeployCloneGate.s.sol`：链 16661 上拒绝弱或无代码的 `TIMELOCK`，接受 ≥ 1 天的；其余链不限 |
| `ERC165.t.sol` | 2 | 9 个声明接口正、`0xffffffff` / unknown 负 |
| `CanonicalForkIntegration.t.sol` | 2 | 对着线上 canonical 注册表 self-mint + verified-feedback attest（仅设了 `FORK_RPC` 才跑，否则跳过）|

共享 scaffolding 在 `test/AgenticIDTestBase.sol`：三种 EIP-191 变体
（hex-encoded 用于 transfer proof；raw-32-byte `personal_sign` 用于已废弃分叉的
ServeProof，也作为被拒的旧格式；version `0x00` intended-validator 用于
`VerifiedFeedbackRegistry` 的 ServeProof）、
proxy 部署、proof / mint helpers。新增 suite 通常只需要继承 + 写业务断言。


## 10. 进一步阅读

- **[`DEPLOYMENT.md`](DEPLOYMENT.md)** —— 部署 / 升级 / Etherscan verify 全套
  runbook（15 合约一次部署、Timelock 两阶段升级、`verify.sh` 工作原理、0g
  Galileo testnet 与 0G mainnet 参考地址 + 各环境治理）。
