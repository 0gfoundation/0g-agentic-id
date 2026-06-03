# 0G AgenticID

> 给每一个 AI agent 一个贯穿其整个生命周期、可被任何人独立验证的链上身份。

AgenticID 是构建在 **0G 生态**上的协议：把 agent 的功能数据锚定上链、在 TEE
里运行其代码、用只存在于 TEE 内的密钥给每条响应盖章，让"这个 agent 可信"
从一句需要盲信的声明，变成一条任何人都能自己验证的属性。

---

## 没人在谈的信任问题

围绕 AI agent 的讨论大多集中在**能力**——它能多自主地行动、能串起多少工具、
能替用户做多大的决定。但一个更根本的问题几乎从没被问出口：

> **你怎么知道,正在为你服务的 agent,真的是它声称的那个东西?**

这是个工程问题,不是哲学问题。今天部署一个 agent,就是在一台服务器上跑一段
代码、把它接到世界上。作为用户,你无法验证它用的是哪个模型、它的行为有没有
被悄悄改过、它的评价是不是真的、你刚收到的这条响应到底来自宣传的那套配置——
还是 owner 临时换上去的别的东西。

更深的问题是结构性的:**agent 完全从属于它的 owner**。owner 可以随时改 agent,
无记录、无问责。在一个 agent 需要做出有约束力的承诺、自主协作、积累声誉的世界里,
这是个地基级的缺陷。AgenticID 正面解决它。

---

## 信任链:四层,每层都独立可验证

AgenticID 把信任拆成一条从合约根到每条响应的连续链路。每一层单独可验证,
合起来无缝衔接:

```
链上身份  →  运行时配置  →  执行环境  →  模型推理
 ERC-7857     iData +        TEE +        0g-compute
 ERC-8004     0G Storage     AgentSeal    (可验证推理)
 AgentSeal
```

| 层 | 回答的问题 | 靠什么 |
|---|---|---|
| **链上身份** | 这是哪个 agent?谁拥有它?它的历史如何? | ERC-8004 身份 + ERC-7857 token + AgentSeal 注册表 |
| **运行时配置** | 它此刻在跑什么模型、记忆、配置? | 加密 iData 存 0G Storage,指纹锚定链上 |
| **执行环境** | 链上声明的东西,是不是真的在跑? | 0g-Tapp (Intel TDX) + 镜像哈希白名单 |
| **模型推理** | 推理本身可信吗? | 0g-compute(TEE 内可验证推理) |

---

## 核心机制

### 1 · 把 agent 状态锚定上链

一个 agent 的"性格"由它的**功能数据(functional data / iData)**定义:模型、
记忆、运行时配置。AgenticID 把这些数据**加密**后存到 **0G Storage**(0G 的去
中心化存储层),把内容指纹和元数据注册进链上合约。注册之后,agent 在链上可被
发现、可被服务。

链上记录不是冻结的。agent 可以自动更新功能数据。协议保证的东西更
精确:**你永远能验证 agent 为你服务的那一刻,跑的是什么样的 agent iData。** 每条响应
都带一份对当前 iData 版本的签名证明。这不是不可变性,而是**任意时点的可验
证性**——审计追踪式的信任。

> 在本仓库里,这套"演化即上链"由 `sealed` 运行时实现:watcher 每 30s 比对
> agent 磁盘上的真实状态与链上快照,有 drift 就 re-encrypt + 签一笔
> `chain.Update` 上链。详见 [`sealed/ARCHITECTURE.zh.md`](sealed/ARCHITECTURE.zh.md) §4–5。

### 2 · 弥合"声明"与"执行"之间的缝

把数据放上链解决了**声明**问题,但对**声明与实际运行之间的缝**毫无办法——
恶意运营者完全可以链上注册一套配置、实际跑另一套。要堵上这条缝,需要硬件级
隔离,这就是 **0g-Tapp** 的位置。

0g-Tapp 是 0G 基于 Intel TDX 的应用管理框架。跑在 TEE 里的代码,即使是服务器
自己的管理员也无法窥探或篡改。每次写操作都会被度量:任何修改都会改变应用的
attestation 值,并留下可追溯的日志。没有"悄悄改掉一个运行中的应用"这种事。

0g-Tapp 还提供一个链上注册表 **TappRegistry**,应用在这里登记自己的代码指纹。
支持两种注册模式:**预验证**(注册前先在链上验 RA quote)与**后验证**(应用
先注册,用户使用前自行 attest)。AgenticID 的三个核心组件——Attestor、
0g-Sandbox、0g-compute——都作为 Tapp 应用部署、在 TappRegistry 登记。这个登记
是整条信任链的根。

### 3 · AgentSeal:伪造不出来的身份

0g-Tapp 的 **KMS** 从一个已注册应用的链上 appId 派生密钥材料。派生是确定性的
(同一个 appId 永远派生同一把 key)、硬件无关的(不绑定任何具体 TDX 设备)、
且只能在 TEE 内访问。

从这份密钥材料,AgenticID 为每个 agent 生成一个 **AgentSeal**:一对密钥,私钥
只存在于 TEE 运行时内。owner 拿不到,TEE 之外的任何人都拿不到。agent 用
AgentSeal 给它产出的**每一条响应**签名——这个签名证明:响应来自一个跑在 TEE
里、且严格按链上记录运行的 agent。

> 链上侧:`agentSeal` / `sealId` 是 **set-once 永久绑定**——一个 agentId 只能
> 设一次,转让也不清除。换硬件时 attestor 给新的 Agent TEE 重新 provision 同一
> 把 `agentSeal_priv` 即可,地址不变。见 [`contracts/README.md`](contracts/README.md) §4。

### 4 · Sealed Sandbox:一个拥有自己的 agent

**0g-Sandbox** 是一个作为 Tapp 部署的隐私沙箱。它的定义性属性:连作为服务方
的 0G 自己也看不进一个运行中的沙箱。AgenticID 用的是 **Sealed Sandbox 模式**,
更进一步——连 agent **自己的 owner 也看不进去**。

0g-Sandbox 承担两项验证职责:

- **仅授权启动**:启动容器之前,Sandbox 验证请求来自链上注册的 owner。只有
  合法 owner 才能用 agent 的功能数据实例化它。
- **运行时代码 attestation**:Sandbox 给容器的镜像哈希签名,交给 Attestor。
  Attestor 核对 Sandbox 的 `signerAddress` 在 TappRegistry 注册过,且镜像哈希
  出现在 AgenticID 合约的 **`validFrameworkHashes` 白名单**里。这个白名单覆盖
  的是 **AgenticID 运行时框架**的哈希——也就是负责加载功能数据、管理 AgentSeal
  签名、校验 owner 指令的那一层容器代码。它与 LangChain / CrewAI 这类 AI 编排
  工具是**不同层级**的东西:后者是存在 agent 功能数据里、由运行时加载的配置。

owner 保留真正的控制权——更新功能数据、触发重启、转让 agent。但每一个动作都
走链上协议。没有后门。

> 链上 `frameworkHash` 同时进入每条 `ServeProof`(见机制 5),所以买家做尽调
> 时能看到"这条声誉是哪个版本的运行时框架挣来的"。

### 5 · 声誉:gaming 不出来

AgenticID 扩展了 **ERC-8004**,加了一条关键要求:**每条评价都必须附带一份
AgentSeal 签名的服务证明(ServeProof)**。没有真实交互,就没有合法评价。刷分
在结构上不可能——你伪造不出一个只有活着的 TEE 运行时才能生成的签名。

声誉还**绑定到服务发生那一刻生效的具体功能数据版本**,而不只是 agent 静态的
tokenId。升级模型或改配置,那个新版本就从零开始积累声誉。积累下来的东西,属于
一个完成了真实、可验证工作的具体配置。

```solidity
struct ServeProof {
    uint256   agentId;
    address   client;
    uint256   timestamp;
    uint256   deadline;
    bytes32   taskHash;
    bytes32[] dataHashes;     // 当下 TEE 加载的 iData hash 列表
    bytes32   frameworkHash;  // 运行时框架代码 hash
    bytes     signature;      // agentSeal_priv 签名
}
```

`giveFeedback` 在链上重建签名内容、`ecrecover` 后与 `getAgentSeal(agentId)`
比对——agentSeal_priv 只有 Agent TEE 持有,客户既伪造不出 ServeProof,也没法
不调 agent 就自己打分。详见 [`contracts/README.md`](contracts/README.md) §5。

### 6 · 转让 agent = 转让它的能力

在 **ERC-7857** 的 agent 转让协议下,移交所有权需要**完整交付功能数据**。买家
拿到的是一个真正能跑的 agent——模型、记忆、配置,而不是一个换了 owner 字段的
空壳。协议强制这一点:一笔省略了功能数据的转让无法完成。

机制上靠 dataKey 在 TEE 之间的原子交付:卖家 Agent TEE 解出 `dataKey`,经 Oracle
TEE 用买家公钥重封,Oracle 签 OwnershipProof;链上 `iTransferFrom` 校验
AccessProof + OwnershipProof 双签名通过才换 ownership。`dataKey` **从不出现在链上
明文或 EOA 钱包**。详见 [`contracts/README.md`](contracts/README.md) §6 与
[memory: dataKey lifecycle]。

---

## 架构:从合约根到每条签名响应

三类组件构成 AgenticID,组成一条从链上注册到每条签名响应的连续链路。

### 合约层(链根)

| 合约 | 职责 |
|---|---|
| **ERC-7857**(`ERC7857Upgradeable` + 扩展) | 功能数据(IntelligentData[])与转让/克隆协议 |
| **ERC-8004**(`ERC8004IdentityRegistry` + `AgenticIDReputationRegistry`) | 身份注册 + 声誉 |
| **AgentSeal 注册表**(`AgenticID.sol`) | agent 的动态身份凭证(set-once)+ `validFrameworkHashes` 白名单(写权限限注册在 TappRegistry 的 Attestor) |
| **TEEDataVerifier** | 转让时的 AccessProof / OwnershipProof 双签名校验 |
| **TappRegistry** 📋 | 所有 Tapp 组件的代码指纹注册表(被引用、合约本体未定稿) |

### TEE 层(0g-Tapp 部署)

- **Attestor** — 校验 Sandbox 的 `signerAddress`(against TappRegistry)与容器
  镜像哈希(against `validFrameworkHashes`);经 KMS 派生 AgentSeal 密钥材料;
  把 AgentSeal 公钥注册上链。(Rust,见 [`attestor/`](attestor/README.md))
- **0g-Sandbox** — 校验启动请求来自注册 owner;启动 Sealed 容器并签其镜像哈希;
  保证 agent 按链上功能数据运行。
- **Agent 运行时(`sealed`)** — 跑在 Sandbox 里、受 RA 后下发密钥的容器:把链上
  加密 iData 还原成可运行 agent,持续把状态演化写回链上,给每条响应签
  `X-Agent-Proof`。(Go,见 [`sealed/`](sealed/ARCHITECTURE.zh.md))
- **0g-compute** 🚧 — TEE 内可验证 LLM 推理模块,由 agent 运行时调用。

### 存储层

0G Storage 持有加密的功能数据,指纹锚定在 ERC-7857。启动时,agent 运行时用
AgentSeal 私钥取回并解密 payload,再拉起 agent 框架。

### 端到端信任流

```
TappRegistry 验 Attestor / Sandbox / 0g-compute
        │
        ▼
Attestor 验 Sandbox 凭证 + 核对 validFrameworkHashes
        │
        ▼
Sandbox 确认授权 owner + 正确运行时代码
        │
        ▼
agent 用 AgentSeal 给每条响应签名 (X-Agent-Proof)
        │
        ▼
0g-compute attest 每一次推理
```

---

## 部署流程(walkthrough)

一个 deploy 请求带着 agent 配置和 owner 地址到达 Attestor。Attestor 派生一对
AgentSeal 密钥,立刻返回 `sealId`,并行地通知 0g-Sandbox 起容器、在链上 mint
一个 `agentId`。

Sandbox 验证 owner、生成一把临时密钥对,以 `{sealId, 临时私钥, attestor_url}`
为参数启动 Sealed 容器。容器拿着自己的凭证——`{sealId, 容器公钥, imageHash,
0g-Sandbox 签名}`——找 Attestor。两项检查通过,Attestor 返回用容器公钥加密的
AgentSeal 私钥。

容器解出密钥,等待链上 `sealId ↔ agentId` 绑定,从 0G Storage 取回加密功能数据、
解密,启动 agent 框架。重启时复用同一个 `sealId`——链上绑定已存在。

> 容器侧的 5-phase 启动(attest → provision → chain bootstrap → framework →
> status report)见 [`sealed/ARCHITECTURE.zh.md`](sealed/ARCHITECTURE.zh.md) §1。

---

## 实现状态

✅ 已实现 · 🚧 部分实现 · 📋 规划中

| 能力 | 状态 | 说明 |
|---|---|---|
| AgenticID 合约(ERC-7857 + ERC-8004 + AgentSeal) | ✅ | 已部署 0g Galileo testnet(chain 16602),117 tests / 15 suites 全绿 |
| `validFrameworkHashes` 白名单 | ✅ | `addValidFrameworkHash` / `isValidFrameworkHash`,写权限限 attestor |
| ServeProof + giveFeedback 防 sybil 声誉 | ✅ | 合约层签名校验 + NonceRegistry 防重放 |
| iTransferFrom / iCloneFrom proof 校验 | ✅ | 合约层完整实现并测试(双签名 + nonce + deadline + pubkey 校验) |
| AgentSeal 派生(KMS)+ RA provision | ✅ | attestor 派生下发 + sealed 容器 RA 换密钥 |
| 加密 iData 演化上链(watcher → chain.Update) | ✅ | sealed 运行时 30s tick,drift → re-encrypt → 上链 |
| `X-Agent-Proof` 响应签名 | ✅ | sealed proxy 自动给每条 :8080 响应签 envelope |
| IDENTITY/SOUL/TOOLS 平台注入 + 签名拒绝钢印 | ✅ | 见 [`sealed/AGENT_DOCTRINE.zh.md`](sealed/AGENT_DOCTRINE.zh.md) |
| 0G Storage 加密上传/下载 | ✅ | sealed 经 `0g-storage-client` 上传下载密文 |
| Attestor 后端(deploy / provision / status / indexer) | ✅ | Rust workspace,真实 chain / storage / sandbox client |
| Deploy + Say hi + Open dashboard UI | ✅ | 见 [`SHOWCASE.zh.md`](SHOWCASE.zh.md) |
| 0g-compute 可验证推理 | 🚧 | provider routing 已接(bridge 到 0G OpenAI-compatible endpoint);"TEE 内 attest 每次推理"的完整形态是目标 |
| Oracle TEE 重封 dataKey(端到端) | 🚧 | 合约 proof 校验已实现并测试;链下 ECIES SDK 端到端测试未补(见 [`contracts/README.md`](contracts/README.md) §11) |
| Sealed Sandbox owner-blind 模式 | 🚧 | 依赖 0g-Sandbox 基础设施 |
| TappRegistry 合约本体 | 📋 | 被引用、未定稿;接入前需确认 |
| transfer UI / post-deploy skill 上传 | 📋 | 见 [`SHOWCASE.zh.md`](SHOWCASE.zh.md) "实诚边界" |
| agent 发推 / 推文 anchor / 自付费循环 | 📋 | 见 [`SHOWCASE.zh.md`](SHOWCASE.zh.md) 后续路线 Phase 1 |
| Agent TEE 在线状态的链上感知 | 📋 | 当前完全 off-chain 协商 |

---

## 仓库导航

Monorepo 三个子项目:

| 子项目 | 内容 | 工具链 |
|---|---|---|
| [`contracts/`](contracts/README.md) | Solidity 合约、Foundry 测试、部署/升级/verify 脚本 | Foundry (forge / cast) |
| [`attestor/`](attestor/README.md) | 后端服务(Attestor / Oracle TEE、API、worker、indexer) | Rust (cargo workspace) |
| [`sealed/`](sealed/ARCHITECTURE.zh.md) | agent 运行时容器(TEE 内还原 iData、演化上链、签名) | Go |

### 深入文档

- [`contracts/README.md`](contracts/README.md) — 合约布局、三个 TEE 角色、注册/声誉/转让三大流程、部署升级 verify
- [`sealed/ARCHITECTURE.zh.md`](sealed/ARCHITECTURE.zh.md) — agent 运行时:5-phase 启动、双 snapshot、iData 演化机制、framework adapter
- [`sealed/AGENT_DOCTRINE.zh.md`](sealed/AGENT_DOCTRINE.zh.md) — agent 钢印手册:5 条签名拒绝规则 + 入侵识别
- [`sealed/EVOLUTION_DESIGN.zh.md`](sealed/EVOLUTION_DESIGN.zh.md) — iData 演化的文件级规范
- [`sealed/TRUST_MODEL.md`](sealed/TRUST_MODEL.md) — KMS → attestor → TEE 密钥派生的信任模型
- [`SHOWCASE.zh.md`](SHOWCASE.zh.md) — 端到端 demo 脚本 + 当前实诚边界 + 后续路线

### 常用命令

```bash
# 合约
cd contracts && forge test                      # 跑测试套件(117 tests)
cd contracts && forge build                     # 编译

# 后端
cd attestor && cargo test                       # 跑 Rust 测试
cd attestor && cargo build                      # 构建

# agent 运行时
cd sealed && go test ./...                      # 跑 Go 测试
cd sealed && go build                           # 构建
```

具体部署 / 升级 / verify 流程见 [`contracts/README.md`](contracts/README.md) §10。

---

## 为什么这件事重要

没有可验证的身份,agent 协作建立在"没人作弊"的假设上。没有不可伪造的签名,
声誉可被 gaming。没有隔离的执行环境,agent 只是 owner 的代理而非独立一方。
没有可验证的推理,信任链就有一道暗门。

AgenticID——通过 0G 的 TEE 基础设施、去中心化存储和链上合约——把"这个 agent
可信"从一句需要盲信的声明,变成一条任何人都能独立验证的属性。

> 这是 agent 从工具变成**主体**所需要的东西。在它之上能建出什么,才是有意思的
> 问题。
