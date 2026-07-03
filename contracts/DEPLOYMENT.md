# AgenticID 合约:部署 / 升级 / Verify / ERC-8004 绑定

> 命令里反复出现的 `--priority-gas-price 2000000000 --gas-price 5000000000` 是 0G
> testnet 的硬编码 workaround,**不是建议参数**——背景见
> [`../QUIRKS.md`](../QUIRKS.md)。(forge 1.6 下常被节点拒,实测改用
> `--legacy --gas-price 5000000000 --slow` 更稳,见 §4。)

## 1. 架构

每个可升级合约(`AgenticID` / `TEEDataVerifier` / `AgenticIDReputationRegistry`)走
**BeaconProxy + UpgradeableBeacon + Implementation** 三层。三个 Beacon 的 owner
共享同一个 **TimelockController**,升级必须 `schedule → wait → execute` 两阶段。

`AgenticID` 不再自己实现 ERC-8004,而是 **custody-bind 到官方 ERC-8004 Identity
Registry**(绑定语义见 §2)。`AgenticIDReputationRegistry` 扩展 ERC-8004 reputation,
`giveFeedback` 要求 TEE 签名的 ServeProof(见 §2.2)。

每个合约都有 `string public constant VERSION`,每次改 impl 应当同步 bump——**版本号规范
+ 升级流程见 [`UPGRADING.md`](UPGRADING.md)**,当前各合约版本与 changelog 见 §7。
**注意:VERSION 是编译期常量,改源码后必须重新部署 impl + 升级 beacon 才会在链上体现。**

暂停独立于升级:每个合约有 `pauser` 角色(**不**走 Timelock),`pause()` 秒级生效,
阻断所有 `whenNotPaused` 写路径(`register` / `setAgentWallet` / `iTransferFrom` /
`giveFeedback` 等),view 不受影响。`owner` 可随时 `setPauser` 更换。

| 角色 | 身份 | 受 Timelock 保护 |
|---|---|---|
| Timelock | 所有 Beacon 的 owner,唯一能调 `beacon.upgradeTo` | — |
| Owner(`OwnableUpgradeable`)| attestor 白名单 / verifier 切换 / pauser 轮换 | 否(直接生效)|
| Pauser | 紧急开关 | 否(紧急路径不能延时)|

## 2. ERC-8004 绑定 + proof 域分离

> 本节说明合约层如何绑定官方 ERC-8004、以及 TEE proof 的域分离(原
> `CANONICAL_BINDING.md`,已并入)。若干**链下**组件必须同步跟改——不一致会静默失败
> (所有签名都验不过)。

### 2.1 Canonical binding(托管绑定)

- AgenticID 不再重实现 ERC-8004。`ERC8004CanonicalBoundUpgradeable` 每个 agent 托管
  一个官方 canonical token:在官方 registry 上 `register()` 把 canonical token 铸给
  AgenticID 合约,AgenticID 再用**相同的 agentId** 把本地 token 铸给真实 owner。
  URI / metadata / agentWallet 读透传、写授权转发到 canonical 合约——canonical 记录
  是生态 8004 indexer 读取的唯一真相。
- **agentId 是 canonical 的全局计数器**:从 0 开始,和所有其他注册方共享,不要假设是
  干净区间。0G Galileo 上官方 registry
  (`0x8004a818bfb912233c491871b3d84c89a494bd9e`, v2.0.0)已有 agent 0–9。
- **哨兵修复**:新增 `sealIdBound` 存在标志支撑 sealId 唯一性检查(因为
  `sealIdToAgentId == 0` 有歧义——agentId 0 是真实 agent)。`isSealIdBound(bytes32)`
  用于消除 `getAgentIdBySealId` 返回 0 的歧义。
- **`initialize` 多了 `canonical_` 参数**(最后一个),缺省按 chainId 选官方地址,可用
  `CANONICAL_8004` env 覆盖。
- **setAgentWallet 改为官方 4 参数形式**(无 nonce):由 `newWallet` 对
  `AgentWalletSet(uint256 agentId,address newWallet,address owner,uint256 deadline)`
  在域 `"ERC8004IdentityRegistry"/"1"` 下签名,`owner` = AgenticID 合约,
  `deadline <= now + 5 min`。SDK/客户端按 **canonical registry 的** EIP-712 域签。

### 2.2 Proof 域分离(安全)

TEE 签的**转移** proof 绑定 `chainId` + 调用的 token 合约(否则一个部署的 proof 可在
另一个部署重放)。链下转移签名方必须完全对齐:

| Proof | 签名方(链下)| 原像(EIP-191 前)|
|---|---|---|
| **AccessProof** | 买家钱包 | `keccak256(abi.encodePacked(chainId, erc7857, dataHash, targetPubkey, nonce, deadline))` 再 hex 编码 EIP-191 |
| **OwnershipProof** | oracle TEE | `keccak256(abi.encodePacked(chainId, erc7857, dataHash, sealedKey, targetPubkey, nonce, deadline))` 再 hex 编码 EIP-191 |

`erc7857` = AgenticID 合约地址(调用 verifier 的 token 合约)。

**ServeProof 故意不做 envelope 域分离**,且**不带 `client`**(归属由 giveFeedback 时的
`msg.sender` 决定;签名摘要 =
`keccak256(abi.encode(agentId, timestamp, deadline, taskHash, keccak256(abi.encodePacked(dataHashes)), frameworkHash))`)。
跨链/跨合约重放在**密钥层**防:agentSeal(计划)按 `(chainId, agenticID, sealId)` 派生,
同一 agentId 在别的部署解析出不同 agentSeal,recover 出的签名者对不上——这样链下
`sealed` 签名方的 envelope 不需要 chainId/合约字段。密钥层 scoping 追踪在 KMS 阈值派生
issue(#7);落地前 ServeProof 无跨部署保护。

链下需同步(仅转移 proof):Oracle TEE + 买家 SDK 在 hash 前加 `chainId ‖ erc7857`;
`sealed` runtime 不变。

### 2.3 agentSeal 派生(attestor,建议,纯链下)

与链上改动独立。当前 `agent_seal_priv = HKDF(master, seal_id)` 不绑 chain/合约 → 同一
key 跨部署存在。建议:`HKDF(master, info = chainId ‖ agenticID_proxy_addr ‖ seal_id)`。
attestor 铸造前就知道两者;兼容换硬件恢复。仅当"跨链统一 agent 身份"是明确目标时才不
这么做(那时 §2.2 的 envelope 域分离从纵深防御变成必须)。

### 2.4 转移 / clone —— seal-bound vs 非-seal

`iTransferFrom` / `iCloneFrom` 按 `getAgentSeal(tokenId) != 0` 分支:

- **Seal-bound agent** = 运行实体。iData 在不可变 agentSeal 下 TEE 锁定,转移就是纯所有权
  交接:重新启用 ERC-721 `transferFrom` / `safeTransferFrom`,`iTransferFrom` **revert**
  (`AgenticIDSealedAgentUseTransfer`);`iCloneFrom` **revert**
  (`AgenticIDCannotCloneSealedAgent`)。运营权链下随所有权走(attestor owner-gating)。
  分叉必须走 attestor 中介的 re-key(`/clone` 端点)。
- **非-seal agent** = 数据 blob。普通转移仍禁用,只能走 proof-gated `iTransferFrom`(把
  `dataKey` 重加密给买家);`iCloneFrom` 照常。

**铸造时清 agentWallet:** `_incrementTokenId` 清掉 canonical `register()` 种给 AgenticID
合约的 `agentWallet`,所以 register / registerWithSeal / iCloneFrom 都以空支付钱包起步
(`CanonicalBinding.t.sol` 断言锁定)。

## 3. 部署

`script/Deploy.s.sol` 通过环境变量一次性部署 10 个合约(Timelock + 3 × (impl + beacon +
proxy)),reputation/verifier 绑到新铸的 AgenticID,AgenticID 绑到 `CANONICAL_8004`
(按 chainId 缺省):

```bash
export OWNER=0x...
export PAUSER=0x...
export TEE_ORACLE=0x...           # TEE 内生成的 oracle 签名地址
export TIMELOCK_DELAY=172800      # prod 建议 ≥ 2 天;dev 可设 0
# 可选: CANONICAL_8004、PROPOSERS/EXECUTORS、NFT_NAME/NFT_SYMBOL、MAX_PROOF_AGE
forge script script/Deploy.s.sol \
  --rpc-url <RPC> --private-key <PK> --broadcast \
  --priority-gas-price 2000000000 --gas-price 5000000000
```

`PROPOSERS`/`EXECUTORS` 默认 proposers=[OWNER],executors=[0x0]=开放执行。输出会打印 10
个合约地址——记进 §6。

**部署后必做(新合约 = 空白名单):** owner 要 `addTrustedAttestor(<attestor>)`(否则 mint
revert `AgenticIDNotTrustedAttestor`)+ `addValidFrameworkHash(<sealed image hash>)`
(否则 `image_hash not in validFrameworkHashes`)。

## 4. 升级

**升级流程 + 版本号规范见 [`UPGRADING.md`](UPGRADING.md)**:小/中版本走 beacon 两阶段
(`schedule → wait → execute`,proxy 地址/storage 不变);大版本(storage 不兼容)重部署 +
迁移。升级机制对三个合约通用,`test/Upgradeable.t.sol`(AgenticID + TEEDataVerifier)与
`test/UpgradeReputation.t.sol`(reputation,含 storage 存活 + 升级后行为)覆盖。

## 5. Verify

`script/verify.sh` 是 proxy 驱动的幂等 verify 工具——唯一输入是 **BeaconProxy 地址**,永远
不变;工具自动发现 beacon 和 impl,逐个 check-then-verify:

```bash
script/verify.sh <proxy-address>

# dev 三个 proxy(当前地址见 §6.2):
script/verify.sh 0x5BB50987521A3fb7Da6Cd6aCC0ad1061D975B24A   # AgenticID
script/verify.sh 0x5e5BD9bB230cA70d813FeC9166a2b4F5b5Da75c7   # TEEDataVerifier
script/verify.sh 0x884c2809888Bfd789919331eA1fB2DA9C31363d2   # Reputation
```

流程:读 ERC-1967 beacon slot → `beacon.implementation()` → 对 `(impl, beacon, proxy)`
各自 check-then-verify(已 verify 跳过;从 creation/runtime bytecode 反推 constructor args;
`forge verify-contract` 不带 `--watch`,见 `../QUIRKS.md`)。新增 impl 类型时在
`IMPL_CANDIDATES` 加一行,或 `script/verify.sh <proxy> src/X.sol:X`。Proxy/Beacon 一次性
verify;每次升级后重跑一次即可(已 verify 的自动 skip)。浏览器 "Read as Proxy" 需
proxy+beacon+impl 三者都 verify 才能展开业务 ABI。

## 6. 部署记录(0G Galileo testnet, chain 16602)

> 部署日志——只追加,不覆盖。本地 `broadcast/Deploy.s.sol/16602/run-latest.json` 是最新一次
> 部署的真相。下面地址/接线 **2026-07-03 已链上核对**(`VERSION` / `canonical()` /
> `getIdentityRegistry()` / `beacon.implementation()` 全部一致)。
>
> **两套 canonical-bound 环境并行** —— 按用途选合约集:
> - **test**(§6.1)— AgenticID `0x3449…`, owner `0xea69…`。
> - **dev**(§6.2)— AgenticID `0x5BB5…`, owner `0xB831…`。**dev-host attestor 指向它**
>   (`ATTESTOR_AGENTIC_ID_ADDR`)。
>
> §6.3 是废弃部署(不要用),含 canonical-binding 之前的自实现旧部署。

### 6.1 test 环境 —— 2026-06-18(active)

从 merged `main`(PR #10 之后)部署,deployer `0xea69…`。canonical 按 chainId 自动选,
部署时 `getVersion() == "2.0.0"` 校验通过。

| 合约 | 地址 | VERSION |
|---|---|---|
| **AgenticID proxy** | `0x34493302287308f565CF3409DAAdEDF4C8895648` | 1.0.0 |
| AgenticID impl | `0x852D34434AE4C3aD28e58272ab9fa871ebeE24c9` | |
| AgenticID beacon | `0x201E35B8566EDC26057348D8419Bc8cBCa609c0E` | |
| **ReputationRegistry proxy** | `0xeDe70197313d0b603612dfC9801162D1aDA3D196` | 1.0.0(client-bound,尚未升级)|
| ReputationRegistry impl | `0x731273A04D123B22aCd650FA7529831F4F1331A4` | |
| ReputationRegistry beacon | `0x309AfEca706659e415FCb0CcF53B25F18859BB99` | |
| **TEEDataVerifier proxy** | `0x9D48FCce51b4B39fcB6e4Bd0840F75A987Cef980` | 1.0.0 |
| TEEDataVerifier impl | `0x306d12BA4b2A3862AdEe45a12C97376a889d937f` | |
| TEEDataVerifier beacon | `0x6AD0a30c8d9142F8eDCA196e61164f6d671b227b` | |
| TimelockController | `0x111b6c32fb3e04AC6ec2E1B38E7CC8e6fCa787F9` | |
| Canonical ERC-8004 | `0x8004A818BFB912233c491871b3d84c89A494BD9e` | v2.0.0 |
| owner / pauser / oracle / deployer | `0xea695C312CE119dE347425B29AFf85371c9d1837` | |

> ⚠️ test 的 reputation 仍是 **1.0.0(带 client)**,还没跟 dev 一样升到 1.1.0。要一致的话按 [`UPGRADING.md`](UPGRADING.md) 升 `0x309Afe…` beacon。

**治理仅测试网:** owner=pauser=oracle=deployer EOA,`timelockDelay=0`,开放执行。主网需真
多签 + 非 0 delay + 真 TEE oracle。

### 6.2 dev 环境 —— 2026-06-17(active)

**dev-host attestor 指向它**(`ATTESTOR_AGENTIC_ID_ADDR = 0x5BB5…`), owner `0xB831…`。

| 合约 | 地址 | VERSION |
|---|---|---|
| AgenticID proxy | `0x5BB50987521A3fb7Da6Cd6aCC0ad1061D975B24A` | 1.0.0 |
| AgenticID impl | `0x1E2AD04C5c9BbE2e5Dd3c257ac6fd82985461C54` | |
| AgenticID beacon | `0x2c60DAF0c41A9FABB8Be1F452F1DD6AE0266F431` | |
| ReputationRegistry proxy | `0x884c2809888Bfd789919331eA1fB2DA9C31363d2` | **1.1.0**(client-less)|
| ReputationRegistry impl | `0xC93DAF00e08B4C086629aEd75387805A41f55321` | |
| ReputationRegistry beacon | `0xd85172b48E824D8168E95f9D70E33091e5e1f9e2` | |
| TEEDataVerifier proxy | `0x5e5BD9bB230cA70d813FeC9166a2b4F5b5Da75c7` | 1.0.0 |
| TEEDataVerifier impl | `0xD5F7602a4a690846cF7D6315d14BCd7535388EE0` | |
| TEEDataVerifier beacon | `0xD4304fD6640047Df1183F54c31f113999a83AC66` | |
| TimelockController | `0x9715F9ffEa7d01552657CE9C6B115Ee6B32aA696` | |
| owner / pauser / oracle / deployer | `0xB831371eb2703305f1d9F8542163633D0675CEd7` | |

### 6.3 废弃 / 不要用

- **canonical-binding 之前的自实现**(旧的自实现 AgenticID,不绑官方 8004,已弃):
  dev `AgenticID 0xf952e7dD046779f34C0Ca0c058e1D940B7B9d525` / `Rep 0x4AAbc18962C2Bb5E451a0FDfa39c0C47a51bD971`;
  testnet `AgenticID 0xbea77c9aBd0aA46e812444583947718593bBD139` / `Rep 0x8bC1E129aEb0Baa306715BC1CBB720Eb2A4324AA`。
- **2026-06-18 interim**(owner `0xB831…`, 误用旧 key 重跑, 弃):AgenticID
  `0x5046060D8eBD281EDdF837f8Bf2578086a14a51D`; Rep `0xb2043F7C06dF8086cd27F0C34E0B8fB009dEaAE4`;
  verifier `0xdB76512f25dE745A95900a7eC8E136EBE69b7328`; Timelock `0x8048C341CD31c422c51525f5179C573EAEb3e4B9`。
- **UUPS-only trial**(`DeployAndMint.s.sol`, agent id 10):AgenticID
  `0x375316a8f05206fBFC1E76Ad8D7C6647F7bAc409`, TEEDataVerifier `0xcD2D0Cfa6f6DC559B5BAdc0E47DcC66A3DD3ae1D`。

## 7. 合约版本与变更记录

当前 impl 版本(链上核对,2026-07-03):

| 合约 | dev VERSION | test VERSION |
|---|---|---|
| AgenticID | 1.0.0 | 1.0.0 |
| TEEDataVerifier | 1.0.0 | 1.0.0 |
| AgenticIDReputationRegistry | **1.1.0** | 1.0.0 |

变更记录:

- **AgenticIDReputationRegistry**
  - `1.1.0`(dev impl `0xC93DAF00…`, 2026-07-03, PR #28)—— **中版本**(ABI/行为变、storage
    兼容、beacon 原地升级):`ServeProof` 去掉 `client`,归属改为 `giveFeedback` 时的
    `msg.sender`;签名摘要与 `giveFeedback` ABI 随之改变。(此前 dev 上有两个已被取代的
    client-less 中间 impl:`0x9dbC80…`(VERSION 未 bump)、`0x110e36Fe…`(一度误标 1.0.1);
    test 尚未升级,仍 `1.0.0` client-bound。)
  - `1.0.0`(impl `0xf053cF29…` dev / `0x731273A0…` test)—— 初版,client-bound ServeProof。
- **AgenticID** `1.0.0` —— canonical-bound 初版。
- **TEEDataVerifier** `1.0.0` —— 初版。

> **版本号规范 + 升级流程见 [`UPGRADING.md`](UPGRADING.md)。** 改了 impl 必须 bump `VERSION`
> (编译期常量,需重部署 + 升级 beacon 才在链上生效)并在此追加一条 changelog。

## 8. 备注 / 后续

- AgenticID 仍继承 `NonceRegistryUpgradeable`(暴露 `setMaxProofAge` / `cleanExpiredNonces`)
  以保持 storage 布局/管理面稳定,但因 `setAgentWallet` 转发到 canonical 合约,它在
  AgenticID 上已退化,将来清理时可移除。
- 测试用 `CanonicalIdentityRegistryMock`;`CanonicalForkIntegration.t.sol` 在设了 `FORK_RPC`
  时对真 registry 跑。
- **主网清单:** `TEE_ORACLE` = 真 TEE 签名地址;`TIMELOCK_DELAY` ≥ 2 天;
  `OWNER`/`PAUSER`/`PROPOSERS`/`EXECUTORS` = 多签。

### 追踪的后续(GitHub issues)

- **#6**(epic)seal-bound agent 转移不携带独占运营权
- **#3** [contracts] seal-bound agent 需要专门的 transfer/clone 路径
- **#4** [attestor] `/provision` 按链上实时 owner 门控
- **#5** [sealed] fail-safe 所有权心跳(self-kill)
- **#7** [security/kms] KMS 阈值派生(移除单点通用解密器)
