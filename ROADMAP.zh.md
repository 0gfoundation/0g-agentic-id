# AgenticID 路线图 — 2026 下半年(约 6 个月)

## 战略方向

三大支柱,按建设次序排列:

1. **巩固基础设施** —— 密钥管理、全盘加密、流程完善（transfer/clone/reputation）、信誉、可观测性。
2. **降低中心化** —— 将单点(KMS 根、attestor)转化为无单一控制方的分布式系统;使 agent 行为可审计。
3. **开放参与** —— 第三方运行节点;开发者与社区在平台之上构建与扩展。

> 先稳固,方可分散;先分散,方可开放。

| 支柱 | 涉及方案 |
|------|---------|
| 巩固 | S1/S2/S3 KMS · S12 FDE · S6 流程补全(transfer/clone/reputation) · S7 信誉继承 · S5 监控 |
| 去中心化 | S1/S2/S3 KMS · S4 attestor 多节点 · S10 指令上链（可审计编排框架,按 S9 接入） |
| 开放 | S8 SDK · S9 编排框架接入方式 · S4 第三方节点 · S11 multi-agent 示范 |

## 排序规则

**不可逆性优先。** 少数变更现在成本低、后期代价极高 —— 它们触及派生公式、合约或对外接口。这些以 **🔒 lock-now** 标注,且须前向兼容。其余皆为**加性**,在这些确定后跟进。

lock-now 集合:**S1** 线性 KDF · **S2** DKG 决策 · **S8** SDK 接口 · **S9** 框架接入契约。

---

## 问题

**P1 —— KMS 根存在"完整重现"的单点。** 现状 = **3 节点 VSS + 非线性 KDF**:master 已切成 3 份分片存放,但两个时间节点仍会出现完整 master —— **使用时**:HKDF 非线性,派生子密钥要把分片合回完整 master(KMS 合并点 + `crypto.rs:70` 在 attestor 内存);**生成时**:VSS 意味着创世有一个 dealer 生成并切分了完整 master,那一刻它完整存在过。

**P2 —— attestor 服务是纯单节点,单方即可拒绝服务。** api/worker/indexer 三进程只靠一个 Postgres 协调,无节点间共识/联盟,第三方也无法运行节点。

**P3 —— 几乎没有可观测性。** 只有返回 `"ok"` 的 `/health`,无 `/metrics`、无结构化健康检查、无逐节点监控 —— N 节点联盟无法运营。

**P4 —— 协议链下流程未补全(seal-bound transfer/clone + reputation 提交)。** seal-bound agent 转移走 ERC-721 `transferFrom`(链上换 owner),但运行中的 agent 在 boot 时缓存了 owner、转移后仍认旧 owner —— 缺 owner 移交的链下流程。clone 则因合约 `iCloneFrom` 对 seal-bound revert(运营实体不可链上复制),需在 attestor 侧另设计复制流程。reputation 提交(serveProof / 反馈)的端到端流程也未在 attestor/SDK 打通。

**P5 —— dataHash 变更后的信誉继承无规则。** reputation 已锚定 agentId(这步本身就做好了);但在同一 agentId 下,信誉挂在一个个离散的 dataHash 上。dataHash 一变(metadata/数据更新),旧 dataHash 上累积的信誉该如何继承到新 dataHash,没有规则 —— 最暴力的 baseline 是简单平均。

**P6 —— 没有 SDK。** 外部集成方只能直接啃合约 ABI + attestor 裸路由,接入成本高,接口一变就破坏所有集成方。

**P7 —— 没有完整的 agent 编排框架接入方式。** 接入层接口已有基础(`framework.go` 有 interface + registry),但只接了 openclaw 一个实现,接入契约不完整、缺接入方案文档 (包括如何接sealed侧接口、如何注册到合约等) —— 第三方/社区无法照着把任意编排框架接进来。

**P8 —— agent 指令走私有聊天,行为不可审计。** openclaw 全私有 chat,走向自治前缺一个透明通道。

**P9 —— 没有端到端的对外证明物。** 无 multi-agent 协作示范,P6/P7 缺需求倒逼。

**P10 —— TEE 组件的静态存储未加密。** 任何 LUKS/dm-crypt/FDE 均无;AgenticID 流程中的磁盘状态以明文落盘（敏感数据手动加密）。

---

## 解决方案(按出现顺序编号)

> 🔒 = lock-now(触及派生公式/合约/接口,晚改代价灾难级,须前向兼容)

### S1 —— 线性 KDF · 🔒 · M1 · 解 P1(使用时重现)
把 `attestor/crates/shared/src/crypto.rs::derive_agent_seal` 的 HKDF 换成 `agentSeal_priv = master + H("agentSeal"‖sealId) mod n`(secp256k1)。各分片本地各自派生、再聚合,派生时 master 不必重现。整块地基,不先做 S2/S3 无意义。
- [ ] 规格化派生;确定性 + 门限兼容;保持 `AgentSealKeyPair` 形态
- [ ] 替换 HKDF
- [ ] 已知答案(KAT)+ 跨进程确定性测试

### S2 —— DKG 创世决策 · 🔒(决策)· M1 · 解 P1(生成时重现)
现状是 VSS(dealer 创世见过完整 master)。决定是否迁移到 DKG —— "master 从来没在任何一处完整存在过" vs 维持 VSS。迁移到 DKG 是一次性的破坏式重新派生密钥,故决策要趁早;仅在与 S1 配合时有意义。
- [ ] 决策备忘 + 建议(若选 DKG 则附创世仪式概述)

### S3 —— 现有分片节点改为无重建派生 + resharing · 加性(依赖 S1)· M5 · 解 P1(落地)
现状已是 3 节点、每节点持一个 master 分片(分片存储已就绪)。缺的是:今天 HKDF 非线性,派生时要把分片合回完整 master(合并点 = P1 残留单点)。S3 把 S1 的线性派生落到这 3 个节点上做成**分布式派生** —— 各节点用自己的分片本地算出子密钥分片,组合方只拿到聚合结果,master 在任何节点都不重建、也不再以完整形态交给 attestor。
- [ ] 在现有 3 节点上实现分布式派生协议(各节点出分片,组合方聚合;master 不重建)
- [ ] proactive resharing 定期刷新分片
- [ ] 创世按 S2(若选 DKG 则连分片一起重新生成,使 master 从未完整存在过)
- [ ] (可选,后续)分片再以 HSM 等硬件保护

### S4 —— attestor 节点运营 · 加性 · M6 · 解 P2
链上授权已是 set(`AgenticID.sol:110` 的 `trustedAttestors` + 治理增删),无需改合约。
- [ ] 面向第三方的 attestor 节点程序
- [ ] 激励设计 + 基于 tapp 的部署指南

### S5 —— 监控 · 加性 · M4 · 解 P3
- [ ] attestor / agent-TEE / indexer 的 `/metrics` + 健康检查
- [ ] 埋点并暴露;仪表盘 + 告警;节点联盟逐节点监控

### S6 —— 协议补全:seal-bound transfer/clone + reputation(提交 + 简单平均兜底)· 加性 · M2 · 解 P4 + P5(兜底)
- [ ] seal-bound transfer/clone:设计与开发
- [ ] reputation 提交:agent 生成 serveProof、client 反馈的端到端流程(经 attestor/SDK)
- [ ] reputation 简单平均聚合(查询期,纯链下,无需改合约)—— P5 的兜底
- [ ] 端到端测试

### S7 —— dataHash 变更后的信誉继承(进阶)· 研究 · M5 · 解 P5
简单平均兜底已在 S6 做;本条是进阶 —— 同一 agentId 下,dataHash 变更时旧信誉如何更好地继承。**只用框架无关的信号**(发生了变更 + 数值评分),不解析各框架各异的元数据语义。
- [ ] 时间衰减(近期权重高);变更边界折扣(dataHash 每变一次,对此前信誉乘一个衰减系数 —— 只需知道"变了",不需知道"变了什么")

### S8 —— SDK · 接口 v1 🔒 + 核心 · M3 · 解 P6
- [ ] API 设计(register(deploy) / query / transfer / clone / reputation)+ 版本化策略 · 🔒
- [ ] 实现核心(合约读取 + attestor API 客户端);文档、示例、发布

### S9 —— 完整的 agent 编排框架接入方式 · 接入契约 v1 🔒(M3)+ 落地(M6)· 解 P7
目标是"任意编排框架都能照着接进来"的完整接入方式。
- [ ] 整理、完善当前框架接入层接口(角色 / 恢复 / 演化 / 启动 等),openclaw 作参考实现 · 🔒
- [ ] 接入方案文档(接口说明 + 接入步骤 + 参考实现)
- [ ] 以一个新框架(opencode/hermes)走通整条接入路径作为验证

### S10 —— 指令上链(可审计编排框架)· 研究 · M6 · 解 P8
- [ ] 设计备忘:commitment + 可选 reveal,或可验证指令日志(内容存于 TEE,链上锚定)
- [ ] 这类"带指令审计"的编排框架按 S9 的接入方式集成进来;喂给 S7(可验证行为 → 可信信誉)

### S11 —— multi-agent 示范 · 加性 · v1 于 M5,终版于 M6 · 解 P9
- [ ] 选定场景(多 agent 协作,带可验证身份、转移、信誉)
- [ ] 经 SDK + agent 编排框架构建 agent;演示完整生命周期
- [ ] 撰写说明 + 录制演示

### S12 —— FDE · 加性 · M4 · 解 P10
依赖 KMS 方向(FDE 密钥来自 KMS)。
- [ ] 设计由 KMS 下发 FDE 密钥(每组件磁盘密钥封存于 TEE)
- [ ] 将 LUKS/dm-crypt 集成进 agent-TEE 与 attestor 存储;重启 / 重封测试

---

## 时间线

每月一个重心,行末括号是对应方案。

**M1 · 锁住最难改的地基**
- 把密钥派生从 HKDF 换成线性公式 + 测试(S1)
- 定 KMS 创世维持 VSS 还是迁 DKG(S2)

**M2 · 补全核心功能**
- 补齐 seal-bound transfer/clone + reputation 提交的链下流程,并做 reputation 简单平均兜底,端到端跑通(S6)

**M3 · 锁住对外接口,SDK 起步**
- 定 SDK:API 形状(register(deploy) / query / transfer / clone / reputation)→ 骨架 → 核心 + 文档(S8)
- 定"任意编排框架照着接入"的接入方案(S9)

**M4 · 加固 · 可观测性**
- 加监控:/metrics、健康检查、逐节点(S5)
- 全盘加密 FDE(S12)

**M5 · 去中心化收尾 · 信誉 · 验证需求**
- 把现有 3 节点改成无重建的分布式派生 + resharing(S3)
- 信誉继承进阶:时间衰减 / 版本感知(简单平均兜底已在 M2 完成)(S7)
- 出第一版 multi-agent 示范(S11)

**M6 · 开放 + 研究 + attestor 去中心化**
- 写第三方可运行的 attestor 节点程序 + 部署指南(S4)
- 框架接入方式落地,用一个新框架(opencode/hermes)验证走通(S9)
- 示范终版(S11)
- 指令上链 / 可审计编排框架的设计研究(S10)

---

## Notes & 决策

- **P1 的两个重现点,S1/S2 各治一个。** S1(线性 KDF)治*使用时*重现,S2(DKG)治*生成时*重现。三层关系:(1)**DKG 必须配 S1** —— 只做 DKG 却仍用非线性 KDF,每次派生还得把 master 拼回完整,使用时重现没除掉,DKG 白做;(2)**先做 S1** —— 改动小、风险低,且让"单点→门限"成为加性变更(以后上门限不必给所有 agent 重新派生密钥);(3)**S2 要趁早** —— "master 从未在任何一处完整出现过"只能创世就 DKG,现状 VSS(dealer 见过一次)事后再迁 = 一次性破坏式重新派生密钥,越早决定越省。
- **KMS 与 attestor 为两个独立层级**,仅在接口处耦合(N 个 attestor 使"master 存于何处"更尖锐 → 论据指向门限 KMS,而非合并)。
- **Lit 暂缓**作为 KMS 根:其协议层 churn 过快(主网代际数月内 sunset;密钥 / PKP 不跨代迁移)。待某一代 Lit 稳定后再评估。
- **S11(示范)** 检验 SDK / 框架接入(S8/S9)是否够用,排在其后(M5)。**S5(监控)** 先行(M4),为后续节点联盟铺路。
- **attestor 去中心化(S4)排在最后(M6)**:它最不确定(激励 / 第三方运营),且 KMS 去中心化(S3)已先解决"master 存哪"的核心单点 —— 服务面可最后再分布,时间紧时可滑入下一周期。

## 范围(6 个月约束)

- **承诺交付:** lock-now(S1 · S2 · S8 接口 · S9 框架接入契约)· S8 SDK 核心 · S6 协议补全(seal-bound transfer/clone + reputation 提交,含简单平均兜底)· S3 分布式派生(现状 3 节点 VSS 已就绪 + 依赖 S1,改动收敛)· S11 示范 · S12 FDE · S5 监控 · S4 attestor 节点原型(M6,末位,时间紧可滑入下一周期)。
- **现在设计,实现可延至下一周期:** S7 信誉进阶(时间衰减)· S4 节点联盟(激励 + 第三方运营 —— attestor 去中心化里最不确定的一块)· S3 proactive resharing 运维加固(+ 若选 S2 的重新派生密钥)· S9 框架接入落地 · S10 指令上链。
