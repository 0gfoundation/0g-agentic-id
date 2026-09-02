# 0G AgenticID

> 给每一个 AI agent 一个贯穿其整个生命周期、可被任何人独立验证的链上身份。

AgenticID 是构建在 **0G 生态**上的协议：把 agent 的功能数据锚定上链、在 TEE
里运行其代码、用只存在于 TEE 内的密钥给每条响应盖章，让"这个 agent 可信"
从一句需要盲信的声明，变成一条任何人都能自己验证的属性。

---

## 没人在谈的信任问题

围绕 AI agent 的讨论大多集中在**能力**——它能多自主地行动、能串起多少工具、
能替用户做多大的决定。但一个更根本的问题几乎从没被问出口：

> **你怎么知道，正在为你服务的 agent，真的是它声称的那个东西？**

这是个工程问题，不是哲学问题。今天部署一个 agent，就是在一台服务器上跑一段
代码、把它接到世界上。作为用户，你无法验证它用的是哪个模型、行为有没有被悄悄
改过、收到的这条响应到底来自宣传的那套配置——还是 owner 临时换上去的别的东西。

更深的问题是结构性的：**agent 完全从属于它的 owner**。owner 可以随时改 agent，
无记录、无问责。在一个 agent 需要做出有约束力的承诺、自主协作、积累声誉的世界里，
这是个地基级的缺陷。AgenticID 正面解决它。

---

## 信任链：四层，每层都独立可验证

AgenticID 把信任拆成一条从合约根到每条响应的连续链路。每一层单独可验证，
合起来无缝衔接：

```
链上身份  →  运行时配置  →  执行环境  →  模型推理
 ERC-7857     iData +        TEE +        0g-compute
 ERC-8004     0G Storage     AgentSeal    (可验证推理)
 AgentSeal
```

| 层 | 回答的问题 | 靠什么 |
|---|---|---|
| **链上身份** | 这是哪个 agent？谁拥有它？它的历史如何？ | ERC-8004 身份 + ERC-7857 token + AgentSeal 注册表 |
| **运行时配置** | 它此刻在跑什么模型、记忆、配置？ | 加密 iData 存 0G Storage，指纹锚定链上 |
| **执行环境** | 链上声明的东西，是不是真的在跑？ | 0g-Tapp (Intel TDX) + 镜像哈希白名单 |
| **模型推理** | 推理本身可信吗？ | 0g-compute（TEE 内可验证推理）|

---

## 术语对照

文档之间偶尔出现**不同名字指同一件事**，或**相近名字指不同事**。下面是
canonical 对应，往后看正文 / 分支文档时遇到拗的称呼时回查这里。

### 同一个东西的几个名字

| canonical | 同义说法 | 解释 |
|---|---|---|
| **Sealed Sandbox** | Agent TEE / sealed container / sealed 运行时容器 | 一个 agent 的 TEE-protected 容器实例；持 `agent_seal_priv`、跑 framework、签 X-Agent-Proof。产品/用户面写 `Sealed Sandbox`；合约/协议描述里更常见的是 `Agent TEE`（强调"TEE 内的密码学身份"）|
| **iData** | IntelligentData / 功能数据 (functional data) | agent 的"性格"——模型、记忆、配置、技能。`iData` 是简称，`IntelligentData` 是合约 struct 名，"功能数据"是面向用户的中文说法 |
| **`sealed` 运行时** | sealed binary / agent 运行时 | `sealed/` 目录里的 Go binary；跑在 Sealed Sandbox 内，wrap openclaw + 暴露 :8080 + 提供 sign socket。**注意**：`sealed`（binary）跟 `Sealed Sandbox`（容器实例）是不同抽象层 |

### 容易混淆的相近名字

**0g-Sandbox vs Sealed Sandbox**——差一个 "Sealed" 前缀但是两个东西：

- **0g-Sandbox**：创建容器的 **provider service**（0g 部署的 daytona-based 容器编排层），它自己作为 Tapp 在 TappRegistry 注册
- **Sealed Sandbox**：由 0g-Sandbox 创建的**单个 agent 容器实例**，一个 agent 一个

> 一句话区分：0g-Sandbox 是工厂，Sealed Sandbox 是产品。

**agentId / sealId / tokenId**——三个 ID，不要混：

| ID | 类型 | 是什么 |
|---|---|---|
| `agentId` ≡ `tokenId` | uint256 | ERC-721 NFT 的 id，链上 agent 的主键 |
| `sealId` | bytes32 | attestor mint 时随机生成的 32 字节句柄；KMS 派生 `agent_seal_priv` 的 material（`chainId ‖ contract ‖ sealId`）组成部分；`sealId → agentId` 一对一 |

**AgentSeal / agentSeal / agent_seal_***——同一对密钥的不同表达层：

| 写法 | 是什么 |
|---|---|
| `AgentSeal`（PascalCase）| 文档里的**概念名**——这把 TEE-bound 身份密钥 |
| `agentSeal`（camelCase）| 合约里 mapping/字段名（如 `agentSeal[agentId]`），值是该 priv 对应的 EVM address |
| `agent_seal_priv` / `agent_seal_pub` | 实现层的**具体密钥字节**（snake_case 是 struct 字段惯例）|

### 三个 *Proof，别混

| 名字 | 是什么 | 在哪用 |
|---|---|---|
| **ServeProof**（PascalCase）| Solidity struct，链上 reputation 流程的载体 | `giveFeedback(ServeProof, ...)`，合约 ecrecover 验签 |
| **serve-proof**（小写连字符）| 通用概念——sealed 自动签的任何 envelope | 文档里的非正式称呼，包含 ServeProof + heartbeat + chain.Update 等 |
| **X-Agent-Proof** | HTTP 响应头名 | sealed proxy 给每个 :8080 响应自动加的 header；载体是签过的 envelope |

简记：**ServeProof** 是它的链上形态，**X-Agent-Proof** 是它的 HTTP 形态，**serve-proof** 是统称。

### 转让里的两个 *Proof

| 名字 | 谁签 | 干什么 |
|---|---|---|
| **AccessProof** | 买家 | "我想要这份 dataKey，封到我这个公钥上" |
| **OwnershipProof** | Oracle TEE | "我已经把 dataKey 用买家公钥重封好了" |

`iTransferFrom` 一笔 tx 同时验这两条。

### 大小写约定

| 形态 | 用在 | 举例 |
|---|---|---|
| **`0g-xxx`**（小写连字符）| 产品 slug、Tapp `app_id` 字符串、repo 名 | `0g-Tapp`、`0g-Sandbox`、`0g-kms`、`0g-storage`、`0g-attestor`、`0g-sandbox-provider` |
| **`0G XXX`**（大写空格）| 网络 / 品牌 / 营销语境 | `0G testnet`、`0G Storage`、`0G AgenticID` |
| **`PascalCase`** | 协议/合约 struct 名、概念名 | `ServeProof`、`AccessProof`、`TappRegistry`、`AgentSeal`（作为概念）|
| **`camelCase`** | Solidity 字段 / mapping / function 名 | `agentSeal[agentId]`、`sealId`、`getAgentSeal()` |
| **`snake_case`** | 实现层具体密钥/字段（Rust / Go struct field）| `agent_seal_priv`、`seal_id`、`container_pubkey` |

**`0g-Sandbox` 内 `Sandbox` 大写**是因为 `Sandbox` 作为单词被独立读（"工厂这个 Sandbox"），跟 `0g-kms`（`kms` 是缩写、整体当 slug）不同——遵循"独立单词 PascalCase、缩写小写"的惯例。

---

## 核心机制

### 1 · 把 agent 状态锚定上链

一个 agent 的"性格"由它的**功能数据（functional data / iData）**定义：模型、
记忆、运行时配置。AgenticID 把这些数据**加密**后存到 **0G Storage**（0G 的去
中心化存储层），把内容指纹和元数据注册进链上合约。注册之后，agent 在链上可
被发现、可被调用。

链上记录不是冻结的。agent 可以自动更新功能数据。协议保证的东西更精确：
**你永远能验证 agent 为你服务的那一刻，跑的是什么样的 iData。** 每条响应都
带一份对当前 iData 版本的签名证明。这不是不可变性，而是**任意时点的可验
证性**——审计追踪式的信任。

> 在本仓库里，这套"演化即上链"由 `sealed` 运行时实现：watcher 每 30s 比对
> agent 磁盘上的真实状态与链上快照，有 drift 就 re-encrypt + 签一笔
> `chain.Update` 上链。详见 [`sealed/ARCHITECTURE.zh.md`](sealed/ARCHITECTURE.zh.md) §4–5。

### 2 · 弥合"声明"与"执行"之间的缝

把数据放上链解决了**声明**问题，但对**声明与实际运行之间的缝**毫无办法——
恶意运营者完全可以链上注册一套配置、实际跑另一套。要堵上这条缝，需要硬件级
隔离，这就是 **0g-Tapp** 的位置。

0g-Tapp 是 0G 基于 Intel TDX 的应用管理框架。跑在 TEE 里的代码，即使是服务器
自己的管理员也无法窥探或篡改。每次写操作都会被度量：任何修改都会改变应用的
attestation 值，并留下可追溯的日志。没有"悄悄改掉一个运行中的应用"这种事。

0g-Tapp 还提供一个链上注册表 **TappRegistry**，应用在这里登记自己的代码指纹。
支持两种注册模式：**预验证**（注册前先在链上验 RA quote）与**后验证**（应用
先注册，用户使用前自行 attest）。AgenticID 的三个核心组件——Attestor、
0g-Sandbox、0g-kms——都作为 Tapp 应用部署、在 TappRegistry 登记。这个登记
是整条信任链的根。

0g-Tapp 的设计哲学是支持非代码绑定的可升级——舍弃强代码绑定检查，换取**强
审计**。也就是说，App owner 仍然可以部署、注册一份恶意代码，但这些行为绕不
过审计：每个版本的部署都被度量并记录上链，任何人事后都能查出"它当时跑的是
哪一份"。

### 3 · AgentSeal：伪造不出来的身份

0g-Tapp 的 **KMS** 从一个已注册应用的链上 appId 派生密钥材料。派生是确定性
的（同一个 appId 永远派生同一把 key）、硬件无关的（不绑定任何具体 TDX 设备）、
且只能在 TEE 内访问。

从这份密钥材料，AgenticID 为每个 agent 生成一个 **AgentSeal**：一对密钥，
私钥只存在于 TEE 运行时内。owner 拿不到，TEE 之外的任何人都拿不到。agent 用
AgentSeal 给自己产出的**每一条响应**签名——这个签名证明：响应来自一个跑在
TEE 里、且严格按链上记录运行的 agent。

具体地说，AgenticID 的后端 Attestor 自己也是一个注册在 TappRegistry 上的
Tapp 应用。它的注册条目包含三样东西：

- **App 名**、**代码哈希**、**配置哈希**——固定的、可审计的代码身份；
- **硬件绑定身份**——由 Tapp 为每个运行实例分配，跟具体 TDX 设备相关；
  Tapp 重启或更换硬件后该身份会变化，需要重新注册。

KMS 处理派生请求时检查链上注册身份与请求里的签名身份是否匹配，匹配
才派生并下发——所以只有注册过、且当前真在合法 TDX 上跑的那一份 Attestor
才能拿到派生出的 key。每一把 AgentSeal 都在 KMS 集群内部（门限 DPRF）
从 attestor 的 app 身份 + `chainId ‖ contract ‖ sealId` 派生；attestor
内存里从不存在全局 master key。

> 链上侧：`agentSeal` / `sealId` 是 **set-once 永久绑定**——一个 agentId 只能
> 设一次，转让也不清除。换硬件时 attestor 给新的 Agent TEE 重新 provision 同一
> 把 `agentSeal_priv` 即可，地址不变。见 [`contracts/README.zh.md`](contracts/README.zh.md) §4。

### 4 · Sealed Sandbox：一个拥有自己的 agent

**0g-Sandbox** 是一个作为 Tapp 部署的隐私沙箱。它的定义性属性：连作为服务方
的 0G 自己也看不进一个运行中的沙箱。AgenticID 用的是 **Sealed Sandbox 模式**，
更进一步——连 agent **自己的 owner 也看不进去**。

agent 运行时（Sealed Sandbox）的信任链分两层级联，最终规约到 Tapp 的"强审计"
哲学：

1. **0g-Sandbox 自己**通过 Tapp 部署，可验证性和封装性由 Tapp 保证。
2. **0g-Sandbox 创建的每个 sealed sandbox** 的对外封装性由 0g-Sandbox 的运行
   时逻辑保证；其镜像哈希由 0g-Sandbox 用自己的硬件身份签名。
3. **Attestor 在 provision 时**双重验证：核对 0g-Sandbox 身份签名 + 检查
   sealed sandbox 镜像哈希在链上注册过；两项通过才下发 `agentSeal_priv`。

—— 所以只有 0g-Sandbox 创建的、镜像注册在链上的合法 sealed sandbox 才能拿到
agentSeal 私钥。

0g-Sandbox 承担两项验证职责：

- **仅授权启动**：启动容器之前，Sandbox 验证请求来自链上注册的 owner。只有
  合法 owner 才能用 agent 的功能数据实例化它。
- **运行时代码 attestation**：Sandbox 给容器的镜像哈希签名，交给 Attestor。
  Attestor 核对 Sandbox 的 `signerAddress` 在 TappRegistry 注册过，且镜像哈希
  出现在 AgenticID 合约的 **`validFrameworkHashes` 白名单**里。这个白名单覆盖
  的是 **AgenticID 运行时框架**的哈希——也就是负责加载功能数据、管理 AgentSeal
  签名、校验 owner 指令的那一层容器代码。它与 LangChain / CrewAI 这类 AI 编排
  工具是**不同层级**的东西：后者是存在 agent 功能数据里、由运行时加载的配置。

Sealed Sandbox 可看作 agent 独立持有的一个运行环境。如上所述，它在类似 Agent
编排框架之上封装了一层"规约层"——这层框架负责 agent 的带鉴权实例化、把演进
结果推送上链、对 agent 行为签名（ServeProof），以及在边界上约束 agent 自己
（比如灌输"我是一个独立个体"的自我认知）。owner 保留实例化、指导演进方向、
转让 agent 的权利，但失去任意改动 agent 内部的能力。**两者不再是主仆，而更
像监护人与被监护人、老师与学生。**

> 链上 `frameworkHash` 同时进入每条 `ServeProof`（见机制 5），所以买家做尽
> 调时能看到"这条声誉是哪个版本的运行时框架挣来的"。

### 5 · 声誉：gaming 不出来

AgenticID 扩展了 **ERC-8004**，加了一条关键要求：**每条评价都必须附带一份
AgentSeal 签名的服务证明（ServeProof）**。没有真实交互，就没有合法评价。
刷分在结构上做不到——你伪造不出一个只有活着的 TEE 运行时才能生成的签名。

每条反馈还**记录了它挣分那一刻生效的具体 iData**（proof 里的 `dataHashes`），
所以声誉可以对照"agent 当时实际在跑什么"来审计，而不只是它静态的 tokenId。至于
按这个数据版本**分版本聚合**声誉（让改过配置的 agent 旧分被打折）——那是设计
（见 [`REPUTATION_MODEL.md`](REPUTATION_MODEL.md)）；当前链上的 `getSummary` 仍是
id-bound（按 tokenId）。

```solidity
struct ServeProof {
    uint256   agentId;
    uint256   timestamp;
    uint256   deadline;
    bytes32   taskHash;
    bytes32[] dataHashes;     // 当下 TEE 加载的 iData hash 列表
    bytes32   frameworkHash;  // 运行时框架代码 hash
    bytes     signature;      // agentSeal_priv 签名
}
```

`giveFeedback` 在链上重建签名内容、`ecrecover` 后与 `getAgentSeal(agentId)`
比对——`agentSeal_priv` 只有 Agent TEE 持有，谁都伪造不出 ServeProof，且每张
proof 一次性（签名 nonce）。没有 `client` 字段——归属由提交时的 `msg.sender`
决定。详见 [`contracts/README.zh.md`](contracts/README.zh.md) §5。

### 6 · 转让 agent = 转让它的能力

在 **ERC-7857** 的 agent 转让协议下，移交所有权需要**完整交付功能数据**。
买家拿到的是一个真正能跑的 agent——模型、记忆、配置——而不是一个换了 owner
字段的空壳。协议强制这一点：一笔省略了功能数据的转让无法完成。

机制上靠 dataKey 在 TEE 之间的原子交付：卖家 Agent TEE 解出 `dataKey`，经
Oracle TEE 用买家公钥重封，Oracle 签 OwnershipProof；链上 `iTransferFrom`
校验 AccessProof + OwnershipProof 双签名通过才换 ownership。`dataKey` **从
不出现在链上明文或 EOA 钱包**。详见 [`contracts/README.zh.md`](contracts/README.zh.md) §6。

---

## 架构：从合约根到每条签名响应

三类组件构成 AgenticID，组成一条从链上注册到每条签名响应的连续链路。

### 合约层（链根）

| 合约 | 职责 |
|---|---|
| **ERC-7857**（`ERC7857Upgradeable` + 扩展）| 功能数据（IntelligentData[]）与转让/克隆协议 |
| **ERC-8004**（`ERC8004IdentityRegistry` + canonical `ReputationRegistry`，由 `VerifiedFeedbackRegistry` 盖验证章）| 身份注册 + 声誉 |
| **AgentSeal 注册表**（`AgenticID.sol`）| agent 的动态身份凭证（set-once）+ `validFrameworkHashes` 白名单 |
| **TappRegistry** | 所有 Tapp 组件的代码指纹注册表 |

### TEE 层（0g-Tapp 部署）

- **Attestor** — 校验 Sandbox 的 `signerAddress`（against TappRegistry）与容器
  镜像哈希（against `validFrameworkHashes`）；经 KMS 派生 AgentSeal 密钥材料；
  把 AgentSeal 公钥注册上链。（Rust，见 [`attestor/`](attestor/README.zh.md)）
- **0g-Sandbox** — 校验启动请求来自注册 owner；启动 Sealed 容器并签其镜像
  哈希；保证 agent 按链上功能数据运行。
- **Agent 运行时（`sealed`）** — 跑在 Sandbox 里、受 RA 后下发密钥的容器：把
  链上加密 iData 还原成可运行 agent，持续把状态演化写回链上，给每条响应签
  `X-Agent-Proof`。（Go，见 [`sealed/`](sealed/ARCHITECTURE.zh.md)）
- **0g-kms** — 为 Tapp 生态提供具有容灾能力的硬件安全级密钥服务。

### 存储层

0G Storage 持有加密的功能数据，指纹锚定在 ERC-7857。启动时，agent 运行时用
AgentSeal 私钥取回并解密 payload，再拉起 agent 框架。

### 端到端信任流

```
TappRegistry 注册 Attestor / 0g-Sandbox / KMS / 0g-compute
        │
        ▼
KMS 在 n 节点集群（k 节点健康即可）上提供硬件安全级密钥派生
        │
        ▼
Attestor 验 0g-Sandbox 凭证 + 核对 validFrameworkHashes
        │
        ▼
0g-Sandbox 确认授权 owner + 正确运行时代码
        │
        ▼
agent 用 AgentSeal 给每条响应签名（X-Agent-Proof）
        │
        ▼
0g-compute attest 每一次推理
```

---

## 部署流程（walkthrough）

一个 deploy 请求带着 agent 配置和 owner 地址到达 Attestor。Attestor 派生一对
AgentSeal 密钥，立刻返回 `sealId`，并行地通知 0g-Sandbox 起容器、在链上 mint
一个 `agentId`。

0g-Sandbox 生成一把临时密钥对，以 `{sealId, 临时私钥, attestor_url}` 为参数
启动 Sealed 容器。容器拿着自己的凭证——`{sealId, 容器公钥, imageHash,
0g-Sandbox 签名}`——找 Attestor。两项检查通过，Attestor 返回用容器公钥加密
的 AgentSeal 私钥。

容器解出密钥，等待链上 `sealId ↔ agentId` 绑定，从 0G Storage 取回加密功能
数据、解密，启动 agent 框架。重启时复用同一个 `sealId`——链上绑定已存在。

> 容器侧的 5-phase 启动（attest → provision → chain bootstrap → framework →
> status report）见 [`sealed/ARCHITECTURE.zh.md`](sealed/ARCHITECTURE.zh.md) §1。

---

## 仓库导航

Monorepo 四个子项目：

| 子项目 | 内容 | 工具链 |
|---|---|---|
| [`contracts/`](contracts/README.zh.md) | Solidity 合约、Foundry 测试、部署/升级/verify 脚本 | Foundry (forge / cast) |
| [`attestor/`](attestor/README.zh.md) | 后端服务（Attestor / Oracle TEE、API、worker、indexer）| Rust (cargo workspace) |
| [`sealed/`](sealed/ARCHITECTURE.zh.md) | agent 运行时容器（TEE 内还原 iData、演化上链、签名）| Go |
| [`sdk/typescript/`](sdk/typescript/README.zh.md) | 客户端 SDK（`@0gfoundation/agentic-sdk`）：deploy / clone / transfer、serve-proof 抓取 + 验证、feedback、信任根 ack、sandbox 充值 | TypeScript (viem) |

### 进一步阅读

**[`sdk/typescript/README.zh.md`](sdk/typescript/README.zh.md) — 客户端 SDK**

单入口（`AgenticID`）的 TypeScript 门面，罩住整个协议：`ag.agent`
（deploy / clone / transfer、各类读、agentSeal gas 充值）、
`ag.reputation`（抓取 TEE 签名的 serve-proof、验证、链上 feedback
读写），外加顶层的信任根 ack 和 sandbox 预付费充值。合约五件套和
attestor HTTP API 都藏在一个 config 对象后面；文中所有示例可直接
跑在 testnet 部署上。

**[`contracts/README.zh.md`](contracts/README.zh.md) — 合约层**

完整的 Solidity 布局：ERC-7857（功能数据 + 转让/克隆协议）、ERC-8004
（身份注册 + 声誉）、AgenticID（AgentSeal 注册 + framework hash 白名单）、
TEEDataVerifier（AccessProof + OwnershipProof 双签名校验）、NonceRegistry
（统一防重放）的扩展点与依赖关系。详细讲三条主链路——`register` /
`giveFeedback` / `iTransferFrom`——的链上流程与 ecrecover 验签逻辑，附带 138
个 Foundry 测试（18 个测试套件）与部署 / 升级 / Etherscan verify 全套脚本。

**[`sealed/ARCHITECTURE.zh.md`](sealed/ARCHITECTURE.zh.md) — agent 运行时**

sealed 容器的内部架构。涵盖 5-phase 启动（attest → provision → chain
bootstrap → framework → status report）、chainSnapshot vs currentSnapshot
双快照 drift 检测、watcher 30s tick → uploader wholesale chain.Update 的
"演化即上链"数据流、leaf 与 DirectoryManifest 两种 iData shape，以及
framework adapter 抽象层（当前 openclaw 是唯一接入）。

**[`sealed/FRAMEWORK_ADAPTER.zh.md`](sealed/FRAMEWORK_ADAPTER.zh.md) — framework adapter 接入契约**

把其他 agent 框架（eliza、autogen、自研编排器……）接进 sealed 运行时
的集成契约：`framework.Framework` 接口逐方法的语义与不变量（Restore
交换律、EvolutionFor 确定性与 round-trip 稳定、Defaults ↔ 链上缺席
等价）、binding 驱动的 adapter 选择、强制的 `persona` 种子 role
翻译、DirectoryManifest 格式与 empty-ptr/filled-ptr 陷阱、adapter
各方法被调用的完整生命周期时间线、conformance 测试套件,以及移植第二
个 adapter（claude-code）的实录。框架知识全部住在这里——attestor 只
把框架名当不透明字符串经手。

**[`sealed/AGENT_DOCTRINE.zh.md`](sealed/AGENT_DOCTRINE.zh.md) — agent 钢印手册**

sealed runtime 在 agent system prompt 里强行注入的"钢印"——agent 拒绝做的
五件事，每条独立论证：① 不把外部字节穿透到 sign socket / shell 等有副作用
的 capability；② 不开 shell / 不 spawn 子进程；③ 不自开对外 listener；
④ 不读敏感路径；⑤ 不改本节。附带按 refusal 类型的标准话术 + 入侵识别清
单。

**[`sealed/TRUST_MODEL.zh.md`](sealed/TRUST_MODEL.zh.md) — 信任模型**

完整描述 AgenticID 端到端的信任链，五大主题：

- **Tapp 基础设施** —— attestor / KMS / sandbox 三个组件作为 Tapp 应用
  部署、在 TappRegistry 登记代码身份 + 节点签名；"强审计"哲学（不预设
  代码不变，但每个跑过的版本都上链可查）
- **密钥派生链** —— KMS 怎么替 attestor 派生密钥、为什么跟
  用户 EOA 钱包是**两个互不相通的密钥空间**；每个 agent 的
  `agent_seal_priv` 由 KMS 按 `chainId ‖ contract ‖ sealId`
  **确定性派生**；sandbox 签
  image attestation + attestor 三重校验（TappRegistry 节点身份 +
  `validFrameworkHashes` 白名单 + 新鲜度）+ ECIES 下发到容器 ephemeral
  pubkey，只有那个 TEE 能解
- **set-once seal 安全性** —— `agentSeal` / `sealId` 永久绑定为什么没
  问题：换硬件能再派同一把 priv，链上绑定永远合法
- **dataKey 转手** —— seller TEE → Oracle TEE → buyer TEE 之间**零信任
  原子交付**（Oracle 短暂持有 + 立即丢弃；链上一笔 tx 双签验）
- **ServeProof / X-Agent-Proof** —— 每条响应签名的 envelope 提供的 8
  条保证都是密码学绑定的、但成立条件分两组：**Group A 身份层 3 条**
  只要 priv 不出 TEE 就无条件成立、**Group B 内容层 5 条**还需要"签名
  能力不被滥用"这一前提（由 agent 钢印兜底）；sealed sign socket 是
  schema-agnostic 通用 signer，区分 framework-signed 与 agent-signed
  这件事密码学上做不到；为什么内容真伪要靠链上声誉层而非密码学层

---

各子目录的 README 还附带 build / test 命令与部署流程，不在此重复。
