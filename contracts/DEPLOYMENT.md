# AgenticID 合约:部署 / 升级 / Verify / ERC-8004 绑定

> 后面命令里反复出现的 `--priority-gas-price 2000000000 --gas-price 5000000000`
> 是 0G testnet 的硬编码 workaround，**不是建议参数**——背景见
> [`../QUIRKS.md`](../QUIRKS.md)。(forge 1.6 下常被节点拒,实测改用
> `--legacy --gas-price 5000000000 --slow` 更稳,见 §3。)

## 1. 架构

每个可升级合约（`AgenticID` / `TEEDataVerifier` / `AgenticIDReputationRegistry`）走
**BeaconProxy + UpgradeableBeacon + Implementation** 三层。三个 Beacon 的 owner
共享同一个 **TimelockController**，升级必须 `schedule → wait → execute` 两阶段。

`AgenticID` 不再自己实现 ERC-8004,而是 **custody-bind 到官方 ERC-8004 Identity
Registry**(绑定语义见 §2)。`AgenticIDReputationRegistry` 扩展 ERC-8004 reputation,
`giveFeedback` 要求 TEE 签名的 ServeProof(见 §2.2 / SDK)。

暂停独立于升级：每个合约有 `pauser` 角色（**不**通过 Timelock），`pause()` 秒级生效，
阻断所有 `whenNotPaused` 写路径（`register` / `setAgentWallet` / `iTransferFrom` /
`giveFeedback` 等），view 不受影响。`owner` 可随时 `setPauser` 更换。

| 角色 | 身份 | 受 Timelock 保护 |
|---|---|---|
| Timelock | 所有 Beacon 的 owner，唯一能调 `beacon.upgradeTo` | — |
| Owner（`OwnableUpgradeable`）| attestor 白名单 / verifier 切换 / pauser 轮换 | 否（直接生效）|
| Pauser | 紧急开关 | 否（紧急路径不能延时）|

## 2. ERC-8004 canonical binding + proof domain separation

> 本节说明合约层如何绑定官方 ERC-8004、以及 TEE proof 的域分离(原
> `CANONICAL_BINDING.md`,已并入本文)。Contract layer is done; `forge test` green.
> Several **off-chain** components must move in lockstep — a mismatch fails
> silently (every signature stops verifying).

### 2.1 Canonical binding

- AgenticID no longer reimplements ERC-8004. `ERC8004CanonicalBoundUpgradeable`
  custodies one canonical token per agent: `register()` on the canonical registry
  mints the canonical token to the AgenticID contract, and AgenticID mints a local
  token with the **same agentId** to the real owner. URI / metadata / agentWallet
  are read-through and authorized-write-forward to the canonical contract — the
  canonical record is the single source of truth ecosystem 8004 indexers read.
- **agentId is the canonical global counter**: starts at 0, shared with all other
  registrants. Never assume a clean range. On 0G Galileo the live registry
  (`0x8004a818bfb912233c491871b3d84c89a494bd9e`, v2.0.0) already has agents 0–9.
- **Sentinel fix**: a `sealIdBound` existence flag backs the sealId-uniqueness
  check (`sealIdToAgentId == 0` is ambiguous — agentId 0 is real). Use
  `isSealIdBound(bytes32)` to disambiguate `getAgentIdBySealId`'s 0 return.
- **`initialize` has a `canonical_` param** (last arg), defaults to the live 0G
  address; override with `CANONICAL_8004` env var.
- **setAgentWallet is the official 4-arg form** (no nonce): signature from
  `newWallet` over `AgentWalletSet(uint256 agentId,address newWallet,address owner,uint256 deadline)`
  under domain `"ERC8004IdentityRegistry"/"1"`, `owner` = the AgenticID contract,
  `deadline <= now + 5 min`. SDK/clients sign against the **canonical registry's**
  EIP-712 domain. Identity reads (URI/metadata/wallet) can hit the canonical
  registry directly by agentId.

### 2.2 Proof domain separation (security)

TEE-signed **transfer** proofs bind `chainId` + the calling token contract
(without it a proof minted for one deployment replays against another). Off-chain
transfer signers MUST mirror these exactly:

| Proof | Signer (off-chain) | Preimage (pre-EIP-191) |
|---|---|---|
| **AccessProof** | buyer wallet | `keccak256(abi.encodePacked(chainId, erc7857, dataHash, targetPubkey, nonce, deadline))` then hex-encoded EIP-191 |
| **OwnershipProof** | oracle TEE | `keccak256(abi.encodePacked(chainId, erc7857, dataHash, sealedKey, targetPubkey, nonce, deadline))` then hex-encoded EIP-191 |

`erc7857` = the AgenticID contract address (the token contract calling the verifier).

**ServeProof is deliberately NOT envelope-domain-separated**, and carries **no
`client`** (attribution is `msg.sender` at `giveFeedback`; signed payload =
`keccak256(abi.encode(agentId, timestamp, deadline, taskHash, keccak256(abi.encodePacked(dataHashes)), frameworkHash))`).
Cross-chain / cross-contract replay is prevented at the **key layer**: agentSeal
is (to be) derived per `(chainId, agenticID, sealId)`, so the same agentId on
another deployment resolves to a different agentSeal and the recovered signer
won't match — keeping the off-chain `sealed` signer's envelope free of
chainId/contract fields. Key-layer scoping is tracked in the KMS threshold issue
(#7); until it lands, ServeProof has no cross-deployment protection.

Off-chain changes (transfer proofs only): Oracle TEE + Buyer SDK prepend
`chainId ‖ erc7857`; `sealed` runtime unchanged.

### 2.3 agentSeal derivation (attestor — recommended, off-chain)

Independent of the on-chain change. Today `agent_seal_priv = HKDF(master, seal_id)`
binds neither chain nor contract → the same key exists across deployments.
Recommended: `HKDF(master, info = chainId ‖ agenticID_proxy_addr ‖ seal_id)`. The
attestor knows both before minting; compatible with hardware-swap recovery. Skip
only if cross-chain unified agent identity is an explicit goal (then §2.2 envelope
domain separation becomes mandatory rather than defense-in-depth).

### 2.4 Transfer / clone — seal-bound vs non-seal

`iTransferFrom` / `iCloneFrom` branch on `getAgentSeal(tokenId) != 0`:

- **Seal-bound agent** = an operating entity. iData stays TEE-locked under the
  immutable agentSeal, so transfer is a plain ownership handover: ERC-721
  `transferFrom` / `safeTransferFrom` is **re-enabled**, `iTransferFrom` **reverts**
  (`AgenticIDSealedAgentUseTransfer`); `iCloneFrom` **reverts**
  (`AgenticIDCannotCloneSealedAgent`). Operation rights follow ownership off-chain
  (attestor owner-gating). Forking must go through an attestor-mediated re-key
  (the `/clone` endpoint).
- **Non-seal agent** = a data blob. Plain transfers stay disabled; ownership moves
  only via proof-gated `iTransferFrom` (re-encrypts `dataKey` to the buyer);
  `iCloneFrom` works as before.

**agentWallet cleanup at mint:** `_incrementTokenId` clears the `agentWallet` that
canonical `register()` seeds to the AgenticID contract, so register /
registerWithSeal / iCloneFrom start the agent with an empty payment wallet (locked
by a `CanonicalBinding.t.sol` assertion).

## 3. 部署

`script/Deploy.s.sol` 通过环境变量一次性部署 10 个合约（Timelock + 3 × (impl +
beacon + proxy)），reputation/verifier 绑定到新铸的 AgenticID，AgenticID 绑定到
`CANONICAL_8004`(按 chainId 缺省):

```bash
export OWNER=0x...
export PAUSER=0x...
export TEE_ORACLE=0x...           # TEE 内生成的 oracle 签名地址
export TIMELOCK_DELAY=172800      # prod 建议 ≥ 2 天；dev 可设 0
# 可选: CANONICAL_8004（默认按 chainId）、PROPOSERS/EXECUTORS、NFT_NAME/NFT_SYMBOL、MAX_PROOF_AGE
forge script script/Deploy.s.sol \
  --rpc-url <RPC> --private-key <PK> --broadcast \
  --priority-gas-price 2000000000 --gas-price 5000000000
```

`PROPOSERS`/`EXECUTORS` 默认 proposers=[OWNER]，executors=[0x0]=开放执行。输出会
打印 10 个合约地址——记进 §6。

**部署后必做(新合约 = 空白名单):** owner 要 `addTrustedAttestor(<attestor>)`
(否则 mint revert `AgenticIDNotTrustedAttestor`)+ `addValidFrameworkHash(<sealed
image hash>)`(否则 `image_hash not in validFrameworkHashes`)。

## 4. 升级

两阶段流程（dev 下 `TIMELOCK_DELAY=0` 也保持同样步骤，与 prod 一致）:

```bash
# Step 1: 部署新 impl（单独部署，最后统一 verify）
forge create src/AgenticIDReputationRegistry.sol:AgenticIDReputationRegistry \
  --rpc-url <RPC> --chain 16602 --private-key <PK> \
  --legacy --gas-price 5000000000 --broadcast

# Step 2: Proposer 排期
export TIMELOCK=0x...
export BEACON=0x<要升级的 beacon>    # 注意不是 proxy
export NEW_IMPL=0x<上一步 forge create 输出的>
forge script script/ScheduleUpgrade.s.sol \
  --rpc-url <RPC> --chain 16602 --private-key <PROPOSER_PK> \
  --legacy --gas-price 5000000000 --broadcast --slow

# Step 3: 等 Timelock delay（delay=0 也建议轮询确认 ready）
ZERO=0x0000000000000000000000000000000000000000000000000000000000000000
OP=$(cast call $TIMELOCK \
  "hashOperation(address,uint256,bytes,bytes32,bytes32)(bytes32)" \
  $BEACON 0 $(cast calldata "upgradeTo(address)" $NEW_IMPL) $ZERO $ZERO --rpc-url <RPC>)
until [ "$(cast call $TIMELOCK 'isOperationReady(bytes32)(bool)' $OP --rpc-url <RPC>)" = "true" ]; do sleep 5; done

# Step 4: Executor 执行（TIMELOCK/BEACON/NEW_IMPL 必须与 Step 2 完全一致）
forge script script/ExecuteUpgrade.s.sol \
  --rpc-url <RPC> --chain 16602 --private-key <EXECUTOR_PK> \
  --legacy --gas-price 5000000000 --broadcast --slow
```

`ExecuteUpgrade` 内置 `require(beacon.implementation() == newImpl)` 自校验。升级后
proxy 地址不变、storage 完全保留、impl 切到新地址。(reputation 去-client 升级即走
此流程,见 §6.2 的 2026-07-02 记录。)

## 5. Verify

`script/verify.sh` 是 proxy 驱动的幂等 verify 工具——唯一输入是 **BeaconProxy 地址**，
永远不变；工具内部自动发现 beacon 和 impl，逐个 check-then-verify:

```bash
script/verify.sh <proxy-address>

# dev 三个 proxy 链（当前地址见 §6.2）:
script/verify.sh 0x5BB50987521A3fb7Da6Cd6aCC0ad1061D975B24A   # AgenticID
script/verify.sh 0x5e5BD9bB230cA70d813FeC9166a2b4F5b5Da75c7   # TEEDataVerifier
script/verify.sh 0x884c2809888Bfd789919331eA1fB2DA9C31363d2   # Reputation
```

流程:读 ERC-1967 beacon slot → `beacon.implementation()` → 对 `(impl, beacon,
proxy)` 各自 check-then-verify(已 verify 跳过;从 creation/runtime bytecode 反推
constructor args;`forge verify-contract` 不带 `--watch`,见 `../QUIRKS.md`)。新增
impl 类型时在 `IMPL_CANDIDATES` 加一行,或 `script/verify.sh <proxy> src/X.sol:X`。
Proxy/Beacon 一次性 verify;每次升级后重跑一次即可(已 verify 的自动 skip)。浏览器
"Read as Proxy" 需 proxy+beacon+impl 三者都 verify 才能展开业务 ABI。

## 6. 部署记录（0G Galileo testnet, chain 16602）

> Deployment log — append new entries, do not overwrite. 本地
> `broadcast/Deploy.s.sol/16602/run-latest.json` 是最新一次部署的真相。
>
> **两套 canonical-bound 环境并行运行** —— 按用途选合约集:
> - **test**（§6.1）— AgenticID `0x3449…`, owner `0xea69…`。
> - **dev**（§6.2）— AgenticID `0x5BB5…`, owner `0xB831…`。**dev-host attestor 指向它**
>   (`ATTESTOR_AGENTIC_ID_ADDR`)。
>
> §6.3 是废弃部署（不要用），含 canonical-binding 之前的自实现旧部署。

### 6.1 Test environment — 2026-06-18 (active)

Deployed from merged `main` (post PR #10), deployer `0xea69…`. canonical address
auto-selected by chainId, deploy-time `getVersion() == "2.0.0"` passed.

| Contract | Address |
|---|---|
| **AgenticID proxy** | `0x34493302287308f565CF3409DAAdEDF4C8895648` |
| AgenticID impl | `0x852D34434AE4C3aD28e58272ab9fa871ebeE24c9` |
| AgenticID beacon | `0x201E35B8566EDC26057348D8419Bc8cBCa609c0E` |
| **ReputationRegistry proxy** | `0xeDe70197313d0b603612dfC9801162D1aDA3D196` |
| ReputationRegistry impl | `0x731273A04D123B22aCd650FA7529831F4F1331A4` |
| ReputationRegistry beacon | `0x309AfEca706659e415FCb0CcF53B25F18859BB99` |
| **TEEDataVerifier proxy** | `0x9D48FCce51b4B39fcB6e4Bd0840F75A987Cef980` |
| TEEDataVerifier impl | `0x306d12BA4b2A3862AdEe45a12C97376a889d937f` |
| TEEDataVerifier beacon | `0x6AD0a30c8d9142F8eDCA196e61164f6d671b227b` |
| TimelockController (beacon owner) | `0x111b6c32fb3e04AC6ec2E1B38E7CC8e6fCa787F9` |
| Canonical ERC-8004 (bound target) | `0x8004A818BFB912233c491871b3d84c89A494BD9e` |
| owner / pauser / oracle / deployer | `0xea695C312CE119dE347425B29AFf85371c9d1837` |

Wiring verified on-chain: `AgenticID.canonical()` = `0x8004…`,
`Reputation.getIdentityRegistry()` = AgenticID proxy, `beacon.owner()` = Timelock.
**Governance is TESTNET-ONLY** (owner=pauser=oracle=deployer EOA, `timelockDelay=0`,
open executor). Post-deploy: `addTrustedAttestor` + `addValidFrameworkHash` needed.

### 6.2 Dev environment — 2026-06-17 (active)

**dev-host attestor 指向它** (`ATTESTOR_AGENTIC_ID_ADDR = 0x5BB5…`), owner `0xB831…`。

| Contract | Address |
|---|---|
| AgenticID proxy | `0x5BB50987521A3fb7Da6Cd6aCC0ad1061D975B24A` |
| AgenticID impl | `0x1E2AD04C5c9BbE2e5Dd3c257ac6fd82985461C54` |
| AgenticID beacon | `0x2c60DAF0c41A9FABB8Be1F452F1DD6AE0266F431` |
| ReputationRegistry proxy | `0x884c2809888Bfd789919331eA1fB2DA9C31363d2` |
| ReputationRegistry impl | `0x9dbC8045c1D32aDbc604C2d85942F0733B48732A` |
| ReputationRegistry beacon | `0xd85172b48E824D8168E95f9D70E33091e5e1f9e2` |
| TEEDataVerifier proxy | `0x5e5BD9bB230cA70d813FeC9166a2b4F5b5Da75c7` |
| TEEDataVerifier impl | `0xD5F7602a4a690846cF7D6315d14BCd7535388EE0` |
| TEEDataVerifier beacon | `0xD4304fD6640047Df1183F54c31f113999a83AC66` |
| TimelockController | `0x9715F9ffEa7d01552657CE9C6B115Ee6B32aA696` |
| owner / pauser / oracle / deployer | `0xB831371eb2703305f1d9F8542163633D0675CEd7` |

> **Reputation beacon upgrade (2026-07-02):** impl `0xf053cF29…` → `0x9dbC8045c1D32aDbc604C2d85942F0733B48732A`
> — drops `client` from `ServeProof` (attribution is now `msg.sender`; PR #28).
> proxy `0x884c28…` + storage unchanged. Verified live e2e (giveFeedback → read → respond → revoke).

### 6.3 Superseded / do not use

- **Pre-canonical-binding self-implemented** (旧的自实现 AgenticID,不绑官方 8004,已弃):
  dev `AgenticID 0xf952e7dD046779f34C0Ca0c058e1D940B7B9d525` / `Rep 0x4AAbc18962C2Bb5E451a0FDfa39c0C47a51bD971`;
  testnet `AgenticID 0xbea77c9aBd0aA46e812444583947718593bBD139` / `Rep 0x8bC1E129aEb0Baa306715BC1CBB720Eb2A4324AA`。
  迁移 out of scope(testnet);新部署一律 canonical-bound。
- **2026-06-18 interim** (owner `0xB831…`, accidental old-key re-run, abandoned):
  AgenticID `0x5046060D8eBD281EDdF837f8Bf2578086a14a51D`; Reputation `0xb2043F7C06dF8086cd27F0C34E0B8fB009dEaAE4`;
  verifier `0xdB76512f25dE745A95900a7eC8E136EBE69b7328`; Timelock `0x8048C341CD31c422c51525f5179C573EAEb3e4B9`.
- **UUPS-only trial** (`DeployAndMint.s.sol`, agent id 10): AgenticID
  `0x375316a8f05206fBFC1E76Ad8D7C6647F7bAc409`, TEEDataVerifier `0xcD2D0Cfa6f6DC559B5BAdc0E47DcC66A3DD3ae1D`.

## 7. Notes / follow-ups

- AgenticID still inherits `NonceRegistryUpgradeable` for storage-layout/admin
  stability, but it is vestigial since `setAgentWallet` forwards to the canonical
  contract. Safe to remove in a future clean-up.
- A faithful `CanonicalIdentityRegistryMock` backs the suite;
  `CanonicalForkIntegration.t.sol` runs against the real registry when `FORK_RPC`
  is set.
- **Prod checklist:** `TEE_ORACLE` = real TEE signer; `TIMELOCK_DELAY` ≥ 2 days;
  `OWNER`/`PAUSER`/`PROPOSERS`/`EXECUTORS` = multisig.

### Tracked follow-ups (GitHub issues)

- **#6** (epic) seal-bound agent transfer conveys no exclusive operation rights
- **#3** [contracts] seal-bound agents need a dedicated transfer/clone path
- **#4** [attestor] gate `/provision` on current on-chain owner
- **#5** [sealed] fail-safe ownership heartbeat (self-kill)
- **#7** [security/kms] KMS threshold derivation (removes single-point universal-decryptor)
