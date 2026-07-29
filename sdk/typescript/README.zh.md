# @0glabs/agenticid-sdk

[English](README.md) | 中文

0G AgenticID 协议的 TypeScript SDK——为链上自主 AI Agent 提供完整的信任链：ERC-8004（身份 + 声誉）+ ERC-7857（带密封密钥的智能数据）。基于 [viem](https://viem.sh) 构建。

## 一分钟总览

只有一个入口类 `AgenticID`，按意图分成两个命名空间，外加几个顶层操作：

| 入口 | 功能 |
|---|---|
| `ag.agent` | Agent 生命周期——**部署 / 克隆 / 转让**——链上读取（owner、agentSeal、iData……）、agentSeal gas 充值、启停重置、费用估算、headless 交互 |
| `ag.reputation` | 捕获 TEE 签名的服务证明（serve-proof）、验证、提交/读取链上评价 |
| `ag.ack()` / `ag.ackStatus()` | 确认 TEE 信任根组件集（覆盖 attestor + kms + sandbox-provider，不针对单个 agent） |
| `ag.deposit()` / `ag.getBalance()` | 充值 / 查询 sandbox 预付费余额 |

所有后端（AgenticID / ReputationRegistry / TappRegistry / SandboxServing 四组合约 + attestor 的 HTTP 接口）都藏在门面后面，调用者不需要知道哪个操作走链、哪个走 HTTP。

## 安装

```bash
npm install @0glabs/agenticid-sdk viem
```

**测前准备**：钱包需要测试网 OG——gas（deploy/评价等链上写入）+ sandbox 预付费（建议 ≥0.5 OG，createFee 0.06 + 运行分钟费）。水龙头：<https://faucet.0g.ai>。

## 初始化

**推荐路径——一个 URL 引导一切。** attestor 的 `GET /config` 自描述其所在环境（合约地址集、链 RPC、组件 appId），所以一个 URL 就锁定了环境；切环境就是换 URL：

```ts
import { AgenticID } from '@0glabs/agenticid-sdk';

const ag = await AgenticID.fromAttestor('http://<attestor>:8080', {
  account: process.env.PRIVATE_KEY as `0x${string}`,   // 不传 = 只读实例；env 值是 string|undefined，strict 下要断言
});
// 想自己核对地址而不信任 attestor 报的？
// 传 `overrides: { agenticID: '0x…', … }` —— 显式指定永远优先。
```

为什么可以信 `/config`：整个信任模型的根就是你 ack 过的 TEE attestor——它的 `/config` 和它做的其他一切同等可信，所以这是你需要的唯一构造路径。

`/config` 真实响应长这样（agenticid.0g.ai，节选；字段是 snake_case，SDK 负责映射成 `ContractAddresses` 的 camelCase）：

```json
{
  "chain_rpc": "https://evmrpc-testnet.0g.ai",
  "chain_id": 16602,
  "agentic_id_addr": "0x34493302287308f565cf3409daadedf4c8895648",
  "tapp_registry_addr": "0x2ce80374318b1d7fb3345724457a182e0ad165c9",
  "sandbox_serving_addr": "0x3490b9053ac46f7bf71a1cebffcb2be2c1405b41",
  "reputation_registry_addr": "0xede70197313d0b603612dfc9801162d1ada3d196",
  "tee_data_verifier_addr": "0x9d48fcce51b4b39fcb6e4bd0840f75a987cef980",
  "sandbox_snapshot": "0g-sealed",
  "supported_frameworks": ["openclaw"]
}
```

**环境缺合约时的降级行为**（一般性规则，具体环境以它当下的 `/config` 为准）：`/config` 里为 null/缺失的地址会被映射成零地址，`fromAttestor` **构造照常成功**（读链、部署等其他能力不受影响）；只有当你调用到依赖该合约的方法时，才会**立即抛出指名道姓的错误**（如 `reputation: this environment has no ReputationRegistry deployed …`），不会让你撞上一个难懂的 ABI 解码错误。临时补救可用 `overrides` 显式传入缺失地址。（高级用法：`new AgenticID({ addresses, … })` 仍然存在，用于手工指定地址的场景——审计工具、或链上有数据但 attestor 没跑的时候；`overrides` 则让你在不放弃引导的前提下钉死任意单个地址。）

**只构造一次。** 读操作只需要合约地址；写操作再加一个签名私钥。SDK 内部自己构建 viem 客户端——你不用手搓 wallet client，RPC 默认指向 0G Galileo 测试网，可省略。

```ts
import { AgenticID, type ContractAddresses } from '@0glabs/agenticid-sdk';

// 地址是部署产物，不烧进 SDK——从 contracts/DEPLOYMENT.md §6 抄你要的那套，
// 或从你自己的配置/环境变量加载。RPC + 这五个地址完全确定目标合约。
const addresses: ContractAddresses = {
  agenticID:          '0x…',
  reputationRegistry: '0x…',
  teeDataVerifier:    '0x…',
  tappRegistry:       '0x…',
  sandboxServing:     '0x…',
};

// 只读——不需要任何 URL：链上读取是 RPC 直连合约（RPC 有内置默认值，
// 指向 0G Galileo 测试网），attestor 不参与。
const ro = new AgenticID({ addresses });

// 带签名（可写）：
const ag = new AgenticID({
  addresses,
  account: process.env.PRIVATE_KEY as `0x${string}`,   // 私钥（0x…）或 viem Account；有它就能写
  attestorUrl: process.env.ATTESTOR_URL,  // 管容器 + 看部署进度都要（deploy/clone/启停/reset/retry/waitForRunning/listDeployments）
  // rpcUrl 可选——默认 0G Galileo 测试网 RPC
});
```

**你要做的事越"重"，构造时要给的东西越多**——分三档：

| 你想…… | 传入 | 为什么 |
|---|---|---|
| **读链**（查 owner、余额、agent 数据） | 只要 `addresses` | 读链是直接问合约；RPC 有内置默认值 |
| **写链**（部署、转让、评价） | `+ account` | 写操作要签名 |
| **管容器 / 看部署进度**（启停、`deploying`→`running`） | `+ attestorUrl` | 部署进度在 attestor 的数据库里，链上没有 |

给了 `attestorUrl` 还有个附带好处：SDK 能自动从 attestor 的 `/config` 拉出几个值（sandbox-provider 地址、信任根 appId、当前 sealed 镜像名）。不给也行，只是这些参数得你自己显式传。

`AgenticIDConfig` 全字段：`{ addresses, account?, rpcUrl?, attestorUrl?, walletClient?, chain?, componentAppIds? }`。

- **`account`** —— 私钥或 viem `Account`。给了它就能签写操作，签名用的 wallet client 由 SDK 代建。
- **`walletClient`**（高级）—— 不想把私钥交给 SDK 时，给一个自己的签名器代替 `account`——比如浏览器里用 MetaMask，签名由钱包插件完成、私钥不进你代码。配套导出了 `ZERO_G_TESTNET` 和 `RPC_URL` 供你搭建。

下文示例假定这些绑定：

```ts
const agentId = 33n;         // 一个已存在的 agent
const owner = '0xAaAa...';   // 该 agent 的 owner（通常就是你签名钱包的地址）
const buyer = '0xBbBb...';   // 留评价的地址——即 `ag` 用来签名的钱包（归属按 msg.sender）
```

---

## `ag.agent` —— 生命周期 + 读取

> **iData 是什么**：agent 被铸造进链上的那份加密内容——它的人设、框架绑定等。deploy 时你**不用手写它**：给 `name` / `description` / `inference`，SDK 用 `defaultIData()` 替你拼出标准的两条（框架绑定 + persona 人设）。想完全掌控就自己传 `iData`（完整格式见下方[「运行时镜像、框架与 iData 格式」](#运行时镜像框架与-idata-格式)一节）。下面用的是省心的默认路径。

```ts
import { parseEther } from 'viem';

// deploy——签好 deploy 信封 + sandbox-create 信封，POST 给 attestor
const params = {
  name: 'Sage',
  description: 'a helpful agent',
  framework: 'openclaw',                           // 'openclaw' | 'hermes'——必须是 GET /config 宣告的名字。
                                                   // hermes 要用自己的镜像：设 sandbox.sealedImage:'0g-sealed-hermes'（见框架一节）。
  inference: { provider: '0g-compute', model: 'claude-sonnet-5' },   // 用哪个模型；可选，不传默认 0g-compute/0gm-1.0-35b-a3b。
                                                   // provider 目前实际以 '0g-compute'（0G 路由）为准；选 model 前先 ag.agent.listModels() 看实时目录。
  //   这两个字段只是 defaultIData() 的输入。要自己完全掌控铸造内容，
  //   就传 iData: [...] 代替它们（见下方 iData 格式一节）。
  sandbox: {
    // sealedImage 可省略——省略（或传空）时自动用 attestor /config 的当前镜像
    // （运维维护的默认值，和 reset() 同一兜底）。只在钉版本/回退时才显式传：
    sealedImage: process.env.SEALED_IMAGE,
    apiKey:      process.env.AGENT_API_KEY,        // 作为环境密钥注入容器
  },
};

// deploy/clone 是异步两段式（提交 → 铸造），类似交易的 writeContract → waitForReceipt。
// 第一个 await 在 attestor 受理任务时就返回；tokenId 要等后台铸造
// （存储 → 链上 mint → setAgentURI）完成才存在。

// `{ wait: true }` 只阻塞到链上【铸造】完成——你拿到 agentId，但容器（和它的
// url）还要 ~1-2 分钟才好，所以别急着用 url：
const { sealId, agentSealAddr, agentId } = await ag.agent.deploy(params, { wait: true });   // agentId → 34n
// `{ wait: 'running' }` 会连【provision】一起等，并返回可直接访问的 base url：
const { agentId: id2, url } = await ag.agent.deploy(params, { wait: 'running' });            // url 此刻可用
// 仅 mint——省略 `sandbox` 就只铸造、不起容器：agent 落 Offline（已铸造、无运行时），
// 之后用 start() 拉起。没容器就没 url，所以这里 wait:'running' 会被拒——用 wait:true：
const { agentId: id3 } = await ag.agent.deploy({ ...params, sandbox: undefined }, { wait: true });

// 或者先拿 sealId、稍后再等（或轮询）铸造：
const dep = await ag.agent.deploy(params);            // → { sealId, agentSealAddr }
const id = await ag.agent.waitForMint(dep.sealId);    // → 铸好后返回 34n（可调 { timeoutMs, pollIntervalMs }）

// clone——源 owner 为另一个 owner 铸一份副本（attestor 对密封数据重新加密）
const newOwner = '0x1111111111111111111111111111111111111111';
const cl = await ag.agent.clone({ sourceAgentId: agentId, targetOwner: newOwner }, { wait: true });
// cl → { sealId, agentSealAddr, agentId }——新 agent 的 tokenId；新 owner 名下初始为 Offline

// idempotencyKey 在 deploy/clone 上可选——SDK 每次调用自动生成。传你自己的
// 稳定键可让重试在服务端去重（同键 → attestor 返回已有的 deploy/clone，
// 不会重复铸造）：
// await ag.agent.deploy({ ...params, idempotencyKey: 'order-4711' });

// transfer——ERC-7857 转让。旧 owner 容器的拆除是【异步】的：attestor 靠监听
// 链上事件（indexer）来拆，所以会比交易慢一个 indexer 追块延迟。转让刚上链时
// phase 可能还是 'running'，接着 '400'，最后才 'offline'——这不是 bug、也不是
// 安全漏洞：链上权限门在转让那一刻立刻归新 owner（旧 owner 再也控制不了它，见
// TRUST_MODEL），残留容器只是个够不着的空壳、正在被清理。转让后别拿 phase 当准，
// 等到 'offline'，或直接让新 owner reset()/start() 一个新容器（身份不变）。这个
// 靠 indexer 监听的拆除是【必须保留的兜底】：任何人都能直接在链上 transferFrom、
// 绕开任何"先停"的路径，所以拆除只能是被动响应式的。
await ag.agent.transferFrom(owner, newOwner, agentId);      // → 交易哈希 "0x…"
await ag.agent.safeTransferFrom(owner, newOwner, agentId);  // → 交易哈希 "0x…"

// 读取
await ag.agent.ownerOf(agentId);            // → "0x…"    当前 owner
await ag.agent.getAgentSeal(agentId);       // → "0x…"    agent 的链上签名密钥（地址形式）
await ag.agent.getSealId(agentId);          // → "0x…"    bytes32 seal id（与上面 deploy 返回的 sealId 同值）
await ag.agent.getAgentIdBySealId(sealId);  // → 33n      反向查询
await ag.agent.isSealIdBound(sealId);       // → true
await ag.agent.intelligentDatasOf(agentId);
// → [ { dataDescription: '{"role":"framework","storage_ptr":{"root_hash":"0x…","indexer":"…","size":95},"encryption":"AES-GCM-256"}',
//       dataHash: '0x…' }, … ]
//   注意 dataDescription 是一整段 JSON 字符串（role + 存储指针 + 加密算法）——
//   取 role 要 JSON.parse(d.dataDescription).role，不能直接 === 'framework'
await ag.agent.sealedKeysOf(agentId);       // → [ "0x04…", … ]   每条 iData 一把密封密钥
await ag.agent.balanceOf(owner);            // → 5n       `owner` 名下的 agent 数量

// 给 agent 自己的密钥打 gas，让它能自付链上写入（进化燃料）
const agentSeal = await ag.agent.getAgentSeal(agentId);
await ag.agent.topUpAgentSeal(agentSeal, parseEther('0.01'));   // → 交易哈希 "0x…"
```

**运行时启停**（owner 签名，身份不变）：

```ts
await ag.agent.stop(sealId, sandboxId);     // 停一个 running 容器
await ag.agent.start(sealId, sandboxId);    // 恢复一个已 stop 的容器
await ag.agent.start(sealId, { apiKey });   // 首次 provision：给 mint-only / 从未起过容器的 agent
                                            // 起一个全新容器（apiKey 事实必传）——sandbox-less
                                            // deploy 的语义搭档，跟 reset（重建已有）区分开。
await ag.agent.reset(sealId, { apiKey });   // 重建一个已有容器：从链上重读 iData、重选框架适配器。
                                            // apiKey 事实必传——attestor 不缓存模型密钥，
                                            // 不传的话 agent 能起来但调不了模型。
                                            // sealedImage 可选，缺省从 /config 取当前镜像名。
await ag.agent.listDeployments();
// → [{ agentId, sealId, phase, sandboxId, url, owner, name, createdAt, lastProvisionError }, …]
//   phase：'deploying'（在途）| 'running'（服务中）| 'stopped'（owner 主动停，可 start 回来）
//         | 'offline'（没有 running 容器——首次未 provision(mint-only 部署)/失败/超时/转让拆除；
//           链上身份还在，用 start({apiKey}) 首次起、或 reset 重建）| 'failed'（铸造失败，retry）；
//   url：agent 的公网基址（喂给 sayHi/authenticate/聊天 API 的那个），容器起来前是 null；
//   lastProvisionError：部署失败的原因——容器 provision 失败（如 "image_hash not in
//   validFrameworkHashes"）或铸造/存储管线失败（如 "mint submit: … replacement transaction
//   underpriced"，SDK 会从失败 stage 的 reason 兜底取出）。它记录最近一次失败、成功后
//   不清空，所以只在 phase 是 offline/failed 终态时当结论读。
//   注意这是无鉴权的公开接口（返回该 attestor 的全部部署，不只你名下的）——内容
//   （agentId/owner/名字/URL）在链上事件和 agent card 里本就公开，设计如此。
```

**三种标识符对照**——同一个 agent 的三个视角：

| 标识符 | 是什么 | 谁在用 |
|---|---|---|
| `agentId`（bigint） | ERC-7857 tokenId——链上身份本体 | 绝大多数读取、transfer、clone、authenticate、runtimeCosts |
| `sealId`（bytes32） | seal 绑定的哈希 id——attestor 部署记录的主键 | stop / start / reset、waitForMint、部署行 |
| `agentSeal`（address） | agent 自己的签名密钥（地址形式）——它的钱包 | topUpAgentSeal、服务证明的签名者核验 |

三者随时互转：`getSealId(agentId)` / `getAgentIdBySealId(sealId)` / `getAgentSeal(agentId)`。

---

## `ag.reputation` —— 服务证明 + 评价

每个 agent 运行**自己的**服务端点——需要什么 HTTP API 就开什么，协议不做规定，agent 之间可以完全不同。不变量是挡在前面的 **sealed 代理**:它只在 agent 的**对外可归属面**——即 agent 注册的 `/api/*` service(agent 自己的代码在服务外部任务)——上盖 `X-Agent-Proof` 头。它**不签** owner↔agent 的操舵通道(框架的 chat/UI,用 `/_seal/auth` 拿的 owner token 访问):给一个 owner 鉴权的通道签名,等于让 owner 给"和自己 agent 对话"铸造 proof(自助刷声誉)。所以 `capture` 要在对 agent 自己的 `/api/*` service 的调用上读那个头。SDK 不对调用本身建模——你按 agent 期望的方式调用它，`capture` 只负责读那个头。归属按提交时的 `msg.sender`；证明本身**不**绑定客户端。

```ts
import { keccak256, toBytes } from 'viem';

// agent 的公网基址来自 listDeployments() 返回行的 url 字段（详见"与运行中的 agent 交互"一节）：
const { url: agentUrl } = (await ag.agent.listDeployments()).find((d) => d.agentId === agentId);

// 1. 调用 agent + 捕获服务证明（请求由你自己组织；SDK 只读
//    sealed 代理盖在响应上的 X-Agent-Proof 头）
const { response, proof } = await ag.reputation.capture(() =>
  fetch(`${agentUrl}/chat`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ q: 'hi' }) }));
const data = await response.json();                   // 正常的业务响应体
// proof → { agentId: 33n, timestamp: 1719_000_000n, deadline: 1719_003_600n,
//           taskHash: "0x…", dataHashes: ["0x…"], frameworkHash: "0x…", signature: "0x…" } | null
// （等价入口：ag.reputation.proofFromResponse(response) / .parseServeProofHeader(headerValue)）

// 2. 花 gas 之前先验证（签名者 == 链上 agentSeal、未过期、dataHashes ⊆ 链上 iData）
await ag.reputation.verifyProof(proof);
// → { ok: true, signerMatches: true, notExpired: true, dataOnChain: true, reasons: [] }

// 3. 提交评价——记在 buyer（msg.sender）名下。必填三项，其余全部默认
//   （decimals 0，tags/endpoint/URI 为空）：
const txHash = await ag.reputation.giveFeedback({ agentId, value: 5n, serveProof: proof });
// 需要精细控制时可加：valueDecimals / tag1 / tag2 / endpoint / feedbackURI / feedbackHash。
// proof 应该来自你实际在评价的那次交互——真实调用时 capture()，然后提交。
// proof 的 deadline = 服务时刻 +3600 秒（1 小时）：verify + 0G 上链（回执可能
// 120 秒+）时间绰绰有余，但别隔天再提交——过期后合约侧会拒。

// 读回
const idx = await ag.reputation.getLastIndex(agentId, buyer);   // → 2n   该 buyer 的最新序号
await ag.reputation.readFeedback(agentId, buyer, idx);
// → { value: 5n, valueDecimals: 0, tag1: "quality", tag2: "latency", isRevoked: false }
await ag.reputation.getSummary({ agentId });   // 过滤条件全部可选
// → { count: 2n, summaryValue: 10n * 10n**18n, summaryValueDecimals: 18 }
await ag.reputation.getServeData(agentId, buyer, idx);          // → { dataHashes: ["0x…"], frameworkHash: "0x…" }
await ag.reputation.readAllFeedback({ agentId });   // 可用 clientAddresses / tags / includeRevoked 收窄
await ag.reputation.getClients(agentId);                        // → [ "0x…", … ]  留过评价的地址
await ag.reputation.getResponseCount(agentId, buyer, idx, [owner]);  // → 1n   列出的 responder 里有几个回应了 buyer 的第 idx 条评价

// owner 回应某条评价；留评价的客户端可撤销
await ag.reputation.appendResponse({ agentId, clientAddress: buyer, feedbackIndex: idx, responseURI: 'ipfs://Qm…', responseHash: keccak256(toBytes('thanks')) });
await ag.reputation.revokeFeedback(agentId, idx);              // → 交易哈希 "0x…"（仅限当初留评价的 buyer）
```

> **数据绑定声誉**（按评价是否在 agent *当前*数据下挣得来加权，而不是像 `getSummary` 那样把全部历史混在一起）已完成设计但**尚未进 SDK**——它属于事件索引器阶段。模型见仓库的 `REPUTATION_MODEL.md`。

---

## 顶层操作（不针对单个 agent）

信任根确认和 sandbox 预付费不是 agent 级的事，所以直接挂在门面上。

```ts
import { parseEther } from 'viem';

// 信任根确认（TappRegistry，覆盖 attestor + kms + sandbox-provider）
await ag.ackStatus(owner);   // → { allAcked: false, missing: ["0g-kms"] }   `owner` 还缺哪些 ack
await ag.components(owner);   // → 每个组件的链上详情：[{ appId, acked, ackVersion, owner, composeHash, imageHashes, nodes }, …]——ack() 背后"你在确认什么"的数据
const ackTx = await ag.ack();   // → 交易哈希 "0x…"；已全部 ack 则返回 null
if (ackTx) await ag.waitForTransaction(ackTx);   // 见下方"写后立即读"的提醒

// sandbox 预付费余额（SandboxServing）
await ag.getBalance();                              // → 500000000000000000n（wei；user 默认当前账户，provider 默认 attestor /config 里的）
await ag.getBalance({ user: owner });               // 也接受和 deposit 一致的对象参数（位置参数同样可用）
const depositTx = await ag.deposit({ amountWei: parseEther('0.5') }); // → 交易哈希 "0x…"
await ag.waitForTransaction(depositTx);
```

信任根组件集在设置了 `attestorUrl` 时自动从 `GET /config` 解析（每个环境有自己的 app 命名），兜底为 `['0g-attestor','0g-kms','0g-sandbox-provider']`；配置里显式给 `componentAppIds` 则永远优先。

`agent.deploy()` / `agent.clone()` 会**预检**两个前提（组件全部 ack + 预付费余额 ≥ 0.1 OG），不满足就同步抛出指名道姓的错误——传 `{ preflight: false }` 可跳过。attestor 在受理时也做同样两项检查（HTTP 402，错误码 `trust_roots_not_acked` / `insufficient_sandbox_balance`）。

**写后立即读会撞竞态**：`ack()` / `deposit()` / `topUpAgentSeal()` / `giveFeedback()` 都是裸 `writeContract`——拿到交易哈希就返回，不等上链。紧跟着读状态（`ackStatus()` / `getBalance()` / `readFeedback()`）可能还读到旧值。三个命名空间各有自己的 `waitForTransaction(txHash)`（顶层 `ag`、`ag.agent`、`ag.reputation`），写操作后先 `await` 它再读：

```ts
const tx = await ag.deposit({ amountWei: parseEther('1') });
await ag.waitForTransaction(tx);   // 现在再读 getBalance() 才是新值
```

`deploy()`/`clone()` 的 `{ wait: true }` 已经内置了等待（等的是铸造完成，语义更强），不需要这个模式。

---

## 运行时镜像、框架与 iData 格式

`sealedImage`（从 `GET /config` 的 `sandbox_snapshot` 取，openclaw 是 `0g-sealed`；0g-sandbox 自己的线上协议字段仍叫 `snapshot`）是打包了某个框架适配器的 sealed 运行时镜像。今天有两个适配器：**openclaw**（`0g-sealed`）和 **hermes**（`0g-sealed-hermes`，deploy **和** reset 都要用 `sandbox.sealedImage` 指定它）；具体哪些在某个环境里可用，以 `/config.supported_frameworks` 宣告的为准。

**iData 的形状**：一个数组，每个元素是一条 `{ role, plaintext, extra }`——`role` 是这条内容的用途标签，`plaintext` 是内容本身。deploy 默认帮你拼两条（下面这个例子就是 `defaultIData()` 的产物）：一条 `framework` 绑定告诉运行时用哪个框架，一条 `persona` 装人设和模型选择。WYSIWYS（What You Sign Is What You Seal）：你签名的这份 iData 逐字节就是被加密、被铸上链的内容，attestor 不替你增删任何东西。

```ts
iData: [
  // 第 1 条 · 必填：框架绑定。不写版本号则解析到镜像内已验证的 openclaw 版本；
  //         钉一个白名单内的版本也会被尊重。
  { role: 'framework', plaintext: { name: 'openclaw', schema_version: 1 }, extra: {} },
  // 第 2 条 · persona 人设种子——运行时把它翻译成框架自己的配置。
  //         system_prompt 是 agent 的人设；inference 选 provider/model
  //         （'anthropic' | 'openai' | '0g-compute'，后者走 0G 路由）。
  { role: 'persona', plaintext: {
      system_prompt: 'You are …\n',
      inference: { provider: '0g-compute', model: 'claude-sonnet-5' },
    }, extra: {} },
]
```

> 上面走查用的 `framework` + `inference` + `name`/`description` 就是这份默认 iData 的**快捷输入**——SDK 拿它们喂给 `defaultIData()` 拼出这两条。只有需要偏离默认（加第三条数据、自定义 role、精调 plaintext）时才手写整个 `iData` 数组。

**persona 是一次性种子，不是长期数据**：上面的 framework + persona 是**铸造输入**；agent 跑起来后，sealed 运行时把 persona 翻译进框架自己的配置，并持续把**自己命名的条目**密封上链（openclaw 是 `framework` / `openclaw.json` / `workspace/`；链上 Update 是整数组替换）。所以在**存活 agent** 的 `intelligentDatasOf` 里按 `role === 'persona'` 精确匹配会扑空——role 集合以运行时实际密封的为准。

**attestor 不校验什么**：除了框架**名字**（必须在 `/config.supported_frameworks` 里），deploy 的 iData 内容有意不做校验——铸什么是 owner 的自由，内容能不能跑起来是 **sealed 运行时的契约**。sealed 镜像内置两个框架适配器——**openclaw**（默认镜像 `0g-sealed`）和 **hermes**（镜像 `0g-sealed-hermes`——deploy **和** reset 都要传 `sandbox.sealedImage: '0g-sealed-hermes'`，否则起错镜像、服务 404）。用 `framework: 'openclaw' | 'hermes'` 选，名字必须在 `/config.supported_frameworks` 里。openclaw 的 persona 种子支持的 `inference.provider`：`anthropic` / `openai` / `0g-compute`（0G 路由）。路由的实时模型目录：

```ts
await ag.agent.listModels();   // → ['claude-opus-4-8', 'deepseek-v4-pro', …]
```

`sandbox.apiKey` **事实必传**——不传的话 agent 能起来但够不着模型。它随 owner 签名的信封进入 TEE 容器的环境变量；attestor 从不落盘（这也是 `reset()` 每次都要重传它的原因）。

## 我的 agent 跑起来要花多少钱？

```ts
// 还没有 agent 也能算——部署前做预算：
await ag.agent.estimateCosts();          // 价目 + 每分钟成本（连了账户还给余额和续航）

await ag.agent.runtimeCosts(agentId);    // = estimateCosts + 该 agent 的进化 gas 余额
// → {
//   prepaidBalanceWei:      368500000000011380n,   // owner 的 sandbox 预付费余额
//   sealGasWei:             0n,                    // 进化燃料（agentSeal 钱包）
//   pricing: { pricePerCPUPerMin, pricePerMemGBPerMin, createFee },
//   costPerMinWei:          4000000000000000n,     // 按容器规格（默认 2C/4GB）
//   estimatedRunwayMinutes: 92,                    // 余额 ÷ 每分钟成本
// }
// 容器规格不同就传 { cpu, memGb }。按 agent 计量的实际消耗需要
// provider 侧的用量记录——尚未上链。
```

> 参考价（dev 测试网）：createFee 0.06 OG，CPU 0.001 OG/核·分钟，内存 0.0005 OG/GB·分钟——默认规格约 0.004 OG/分钟。

## 与运行中的 agent 交互（无需控制台）

**agentUrl 从哪来**——每个运行中的 agent 都有一个公网基址（协议和域名取决于部署环境：dev 代理是 http，托管环境是 https），`listDeployments()` 直接给你：

```ts
const me = (await ag.agent.listDeployments()).find((d) => d.agentId === agentId);
const agentUrl = me.url;   // 容器起来前是 null
// 到不了 running 就看 me.lastProvisionError——它写着原因。

// phase 是 'failed' 时先 retry()、别重新 deploy（重 deploy 会孤儿掉已铸造的身份）。
// retry 在同一个 sealId 上重跑失败的幂等阶段：
if (me.phase === 'failed') await ag.agent.retry(me.sealId, { apiKey });
```

- **`GET {agentUrl}/hello`** —— 公开身份卡：我是谁、owner 是谁、暴露了哪些接口。整包（buffered）响应都带签名的 `X-Agent-Proof`（流式/SSE 回复不带——签名要完整 body）。也可以让 SDK 一次做完"请求 + 证明校验"：

  ```ts
  const { hello, verification } = await ag.agent.sayHi(agentUrl);
  // hello → { agent, owner, public_url, message, services, routes }
  // verification → { ok, signerMatches, notExpired, dataOnChain, reasons }
  ```

  身份卡里声明了两类接口：
  - `services` —— agent 自己注册的端点（精确 `/api/*` 路径）：`{ path, method, description?, input_example? }`。直接发 HTTP，每个响应都有证明签名（这正是你 `capture()` 后拿去评价的对象）。
  - `routes` —— 框架声明的前缀：`{ prefix, kind?, auth?, signed, description? }`，例如 `/v1/` 上 `kind:"chat"` API（auth `bearer`）。`auth` 告诉你怎么带 owner token，`signed` 说明该前缀上的响应带不带 `X-Agent-Proof`。已发布的框架都是 chat-only；框架可以声明 UI route，但目前没有。

- **owner 握手** —— `ag.agent.authenticate(agentUrl, agentId)` 证明你是链上 owner（EIP-191 签 `0GSealAuth:<sealId>:<ts>`，到 `POST {agentUrl}/_seal/auth` 换取，`<ts>` 须在 ±300 秒内），返回一个 **`AgentClient`**：owner 凭证 + agent 声明的接口面，能做什么完全由 agent 的声明推导出来，SDK 不写死任何框架特定知识。

  ```ts
  const session = await ag.agent.authenticate(agentUrl, agentId);
  // session.token            —— owner/operator 凭证（完整权限）
  // session.routes/.services —— 声明的接口面（同 /hello）

  // 浏览器打开 UI —— 只有当 agent 声明了 UI(token-fragment)路由时才有;
  // 已发布框架都是 chat-only,目前没有:
  if (session.open) window.location.href = session.open();

  // headless 聊天 —— 只有当 agent 声明了 chat 路由时才有。
  // 底层默认走流式(`stream: true`):长推理任务期间字节持续流动,不会被
  // agent 前面某一跳的 idle 超时掐断;SDK 会把完整回复重新拼好返回,所以
  // 这里的用法不变。chat 是 owner↔agent 的操舵通道,**不签名**(无
  // `X-Agent-Proof`)——声誉来自 agent 自己的 `/api/*` service,而不是
  // owner 跟自己 agent 对话。
  if (session.chat) {
    const { choices } = await session.chat([{ role: 'user', content: 'What can you do?' }]);
    // choices[0].message.content —— 真实推理回复
  }

  // 逐 token 实时版 —— 条件同 chat;yield 出每个内容增量:
  if (session.chatStream) {
    for await (const delta of session.chatStream([{ role: 'user', content: 'Hi' }]))
      process.stdout.write(delta);
  }

  // 通用逃生舱 —— 任何声明过的路径都能打；匹配到的路由要 bearer 时自动带 token：
  const r = await session.fetch('/v1/models');
  // …或一步到位调用 + 取证(用于 agent 的 /api/* service):
  const { response, proof } = await session.fetchWithProof('/api/summarize', { method: 'POST', body });
  ```

  `open` / `chat` / `chatStream` 存不存在,本身就是能力信号(它们需要 owner token)。已发布框架都是 chat-only。SDK 从不凭空合成任何入口——只反映 agent 声明的东西。

- **免 auth connect(第三方)** —— `ag.agent.connect(agentUrl)` 不签名、从 agent 的 `/hello` 发现,返回同一个 **`AgentClient`**。它不带 token,所以 owner 专属的 `open`/`chat`/`chatStream` 都没有;你用同样的相对路径手感调 agent 的公开 `/api/*` service,并一步取证:

  ```ts
  const agent = await ag.agent.connect(agentUrl);            // 不需要钱包
  const { response, proof } = await agent.fetchWithProof('/api/summarize', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body,
  });
  if (proof) { /* 验证它,或作为链上 feedback 提交 */ }
  ```

  于是 owner 和第三方共用**同一套**交互面——token 只决定哪些能力点亮。

openclaw token 生命周期：容器首次启动时生成，跨重启保持稳定（chat 会话保持鉴权）、没有过期时间，只在容器重建时轮换——所以吊销手段就是 `reset()`。

## Agent 作为 owner（嵌套 agent）

平台的自然能力：**sealed 容器里的 agent 可以用自己的 agentSeal 身份跑这个 SDK**——部署子 agent、转让、评价，全套 owner 操作。它没有（也不该有）裸私钥：agentSeal 私钥只存在于 sealed Go 进程里，agent 通过容器内的 unix-socket 签名服务（`SEAL_SIGN_SOCK`，三个端点 personal_sign / typed_data / transaction）请求签名。SDK 提供官方适配器把这个 socket 包装成 viem Account：

```ts
import { AgenticID } from '@0glabs/agenticid-sdk';
import { sealAccount } from '@0glabs/agenticid-sdk/seal';   // node-only 子路径

const ag = await AgenticID.fromAttestor(ATTESTOR_URL, {
  account: await sealAccount(),   // 地址自动读 $AGENT_SEAL，socket 路径自动读 $SEAL_SIGN_SOCK
});
// 之后一切照旧——ag.agent.deploy(...)、ag.reputation.giveFeedback(...) 都以 agentSeal 身份签名
```

**兼容性契约（正式承诺）**：SDK 的任何方法都**永不要求裸私钥**——所有签名（EIP-191 信封、EIP-712、交易）一律经由 viem `Account` 接口。这意味着任何能实现 Account 接口的签名后端（seal socket、浏览器钱包、HSM）都是完整的一等公民，未来新增的方法也受此约束。

（适配器替你处理好了 socket 协议的各种细节：两种消息签名形态、EIP-712 的格式差异、交易字段转换、以及对不支持的交易类型显式报错而非错签。想深挖看 `src/seal.ts`。）

容器内跑 SDK 的注意事项：
- 适配器用 `node:http` 走 unix socket（全局 `fetch` 不支持 unix socket），因此 **node-only**——从 `/seal` 子路径导入，主入口保持浏览器可用；
- 签名前先给 agent 的钱包备 gas：agentSeal 地址发交易要自己付 gas，owner 用 `topUpAgentSeal()` 充（"进化燃料"就是这个用途）；
- 信任边界：sign socket 是**全能签名器**，把 owner 可控的字节转发进去就能伪造任何签名——agent 自己是守门人（详见 sealed/TRUST_MODEL.md）。

## 合约地址

合约地址是**部署产物，不烧进 SDK**——RPC + 五个地址完全确定目标合约；地址不进库，代理升级或重新部署就不会让打包常量悄悄过期。

**唯一事实来源：仓库 `contracts/DEPLOYMENT.md` §6。** 同一条链（0G Galileo 测试网，`chainId 16602`）上并行跑着多套 canonical-bound 部署——选与你 `attestorUrl` 指向的 attestor 相匹配的那套（例如 dev 部署配 dev 主机上的 attestor）。把那五个地址抄进 `ContractAddresses`（形状见上文），或从你自己的配置/环境变量加载。

稳定的协议级常量**有**导出：`ZERO_G_TESTNET`（viem chain）、`RPC_URL`、`CHAIN_ID`、`RECEIPT_WAIT`。

## 注意事项

- **服务证明不绑定客户端。** 评价按 `giveFeedback` 时的 `msg.sender` 归属；证明是持有者凭证（签名 nonce 保证单次使用）。无论走什么传输都请把证明当敏感信息对待——服务面的协议取决于部署环境（dev 代理是明文 http，托管环境是 https）。
- **0G 回执时序。** `waitForTransaction` 针对 0G 调过参（120 秒超时 + 重试）。如果仍超时，交易大概率已落地——读状态确认。
- 链上类型：`value` / `summaryValue` 是 `int128`（bigint），`feedbackIndex` 是 `uint64`（bigint）。

## 高级用法

原始 ABI（`agenticIDAbi`、`reputationRegistryAbi`、`tappRegistryAbi`、`sandboxServingAbi`）和服务证明原语（`buildServeProofMessageHash`、`signServeProof`、`verifyServeProofSignature`）均有导出。

**serve-proof 签名的规范化格式**（想独立实现验证、不依赖 `verifyProof` 的人用）——签名是 agentSeal 对下式的 EIP-191 personal_sign：

```
digest = keccak256(abi.encode(
  agentId,                  // uint256
  timestamp,                // uint256（unix 秒）
  deadline,                 // uint256（= timestamp + 3600）
  taskHash,                 // bytes32
  keccak256(abi.encodePacked(dataHashes)),  // bytes32：dataHashes 数组先打包哈希
  frameworkHash             // bytes32（sealed 镜像 hash）
))
```

`buildServeProofMessageHash` 就是这个公式的 TS 实现；对照 `sealed/internal/proxy/proxy.go` 的 Go 侧实现。

`signServeProof` 传给回调的 digest **已经过 EIP-191 包装**（即 `buildServeProofSigningHash` 的输出），所以要裸签、别再包一层：

```ts
// 正确——对最终 digest 裸签
const signed = await signServeProof(proof, (hash) => account.sign({ hash }));
// 错误——account.signMessage({ message: { raw: hash } }) 会二次包 EIP-191，
// verifyServeProofSignature 会验不过。
```

各合约客户端（`AgenticIDClient`、`ReputationClient`、`SandboxClient`、`AttestorClient`、`ServeSession`）是命名空间背后的内部构件。

---

## 附：从零到对话的完整路径（dev 实测过的流程）

```ts
import { AgenticID } from '@0glabs/agenticid-sdk';
import { parseEther } from 'viem';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
// 三个占位符按你的环境提供：
declare const ATTESTOR_URL: string, PRIVATE_KEY: `0x${string}`, ROUTER_API_KEY: string;

// 0. 引导 + 前提。写操作都要等回执再往下走（见"写后立即读"一节）——
//    新账户 ack/deposit 不等回执就 deploy，会撞 preflight 的余额/ack 检查。
const ag = await AgenticID.fromAttestor(ATTESTOR_URL, { account: PRIVATE_KEY });
const ackTx = await ag.ack();                            // 信任根确认（一次性）
if (ackTx) await ag.waitForTransaction(ackTx);
const depTx = await ag.deposit({ amountWei: parseEther('1') });   // sandbox 预付费
await ag.waitForTransaction(depTx);
await ag.agent.estimateCosts();                          // 算一下账（可选）

// 1. 部署（sealedImage 整个省略——SDK 从 /config 取当前镜像）
const { agentId, sealId } = await ag.agent.deploy({
  name: 'MyAgent',
  description: 'my first sealed agent',
  sandbox: { apiKey: ROUTER_API_KEY },   // inference 也省略——默认 0g-compute/0gm-1.0-35b-a3b
}, { wait: true });

// 2. 轮询到容器 running，顺便拿到 sandboxId 和 agentUrl。
//    provision 实测通常 1~2 分钟（拉镜像 + 容器初始化），这里预算 5 分钟。
//    phase 语义：deploying 是在途；offline / failed 是终态——只有终态才把
//    lastProvisionError 当结论（它记录最近一次失败、成功后不清空，
//    在途时读它会把已自动重试掉的瞬时失败误判成死刑）。
let me;
for (let i = 0; i < 60; i++) {
  me = (await ag.agent.listDeployments()).find((d) => d.agentId === agentId);
  if (me?.phase === 'running') break;                    // find() 可能 undefined（索引落后），?. 兜住
  if (me?.phase === 'offline' || me?.phase === 'failed') {
    throw new Error(`provision 终态失败: ${me.lastProvisionError ?? me.phase}`);
  }
  await sleep(5000);
}
if (!me || me.phase !== 'running' || !me.url || !me.sandboxId) {
  throw new Error(`超时未就绪: phase=${me?.phase ?? '未入索引'}, err=${me?.lastProvisionError ?? '-'}`);
}
const agentUrl = me.url;        // 直接属性访问——TS 沿用上面守卫的窄化（解构拿到的仍是 string|null）
const sandboxId = me.sandboxId;

// 3. 验证身份 + 对话
const { verification } = await ag.agent.sayHi(agentUrl);   // 返回 ProofVerification | null（响应没带证明头时为 null）
if (!verification?.ok) throw new Error(verification ? verification.reasons.join('; ') : '响应没有 X-Agent-Proof 头');
const session = await ag.agent.authenticate(agentUrl, agentId);
// → session.chat?.(msgs) 聊天、session.open?.() 开 UI(仅当框架声明 UI route)、session.fetch(path) 打任意声明的路径（见正文示例）

// 4. 服务 + 评价闭环（proof 的 deadline 是 +3600 秒，1 小时内上链即可）。
//    需要环境有 ReputationRegistry（看 /config 的 reputation_registry_addr）——
//    没有的话这一步会抛 "reputation: this environment has no …"，
//    可用 fromAttestor 的 overrides 显式给地址（见初始化一节）。
const { proof } = await ag.reputation.capture(() => fetch(`${agentUrl}/hello`));
if (!proof) throw new Error('响应没有 X-Agent-Proof 头');   // capture 返回 Proof | null
const v = await ag.reputation.verifyProof(proof);   // 返回 { ok, reasons }，不会自己抛错
if (!v.ok) throw new Error(v.reasons.join('; '));
const fbTx = await ag.reputation.giveFeedback({ agentId, value: 5n, serveProof: proof });
await ag.reputation.waitForTransaction(fbTx);   // 等回执后 readFeedback/getSummary 才能读到这条

// 5. 不用了就停（身份和数据都在链上，随时 start/reset 回来）
await ag.agent.stop(sealId, sandboxId);
```
