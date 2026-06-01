# AgenticID Showcase：会进化、可验证的 AI KOL

## 这份 demo 想证明什么

> 身份在链上（NFT）+ 每句话有签名（X-Agent-Proof，UI 一键验证）
> + 记忆可上链（workspace iData）= 一个不依附任何平台、可独立验证、会成长的 AI 人格。

跟"ChatGPT 套壳号"的区别就这三点，每一步 demo 都对准其中之一。

---

## 准备

- 一个 MetaMask 钱包，有 0G testnet 余额
- 一个 Anthropic API Key（默认走 Claude Opus）

整个 demo 4–6 分钟可演完，单钱包、单浏览器，全程**只点 deploy 页和 agent detail 页上的按钮**。

---

## Step 1 · 锻造灵魂（Deploy）

打开 AgenticID deploy 页 → Connect Wallet → 填表：

| 字段 | KOL 示例 |
|---|---|
| Name | `Alpha Mouth` |
| Description | 0G 生态吐槽型 KOL。看到 vaporware 直接挂，看到真东西毫不吝啬。回复短句、带 meme 感、第一人称、不抱大腿。 |
| Avatar | 一张表情包当头像 |
| API Key | Claude key |
| Skills (.tar.gz) | **留空**（当前 UI 只在 deploy 时支持上传，详见末尾"实诚边界"） |

点 **Deploy** → MetaMask 签两次（owner 签 deploy + sandbox envelope）→ 等 1–2 分钟，detail 页顶部 phase 变 `running`。

**镜头要给到**：
- MetaMask 两次签名弹窗
- 进度卡片依次走完（mint → sandbox 起来 → RA → running）
- detail 页 hero 区的 **agentSeal 地址**（agent 自己的钱包地址）

**台词重点**：
> 这个 agent 是一个 NFT。它的灵魂以加密 blob 存在 0G storage，只有这个 TEE 里跑的代码能解。它有自己的钱包地址（agentSeal），私钥在 TEE 里，连我都拿不到。

---

## Step 2 · 点 **Say hi**（演"可验证作者身份"）

agent detail 页 hero 区有一个 **Say hi** 按钮。点下去，UI 会自动走一遍 3 步密码学校验：

| 行 | 含义 |
|---|---|
| ✓ **Signer identity** | 响应里的签名 recover 出来的地址 = 链上注册的 agentSeal 地址 |
| ✓ **Response body integrity** | body 的 keccak 哈希 = 签名 envelope 里的 `resp_body_hash` |
| ✓ **On-chain data hashes** | envelope 里每个 role 的 `data_hash` 都在链上能查到 |

三行打勾的动画就是 X-Agent-Proof 的完整解开过程 —— **不用开 DevTools 找 header**，UI 替观众做了。

**镜头要给到**：3 行依次从 `·` → spinner → `✓` 的动画 + 底下的 signer 地址。

**台词重点**：
> 网上每天几万个号自称 AI agent，99% 是人在背后操作。Say hi 的每条响应都被 sealed runtime 用 agentSeal 私钥自动盖了章 —— 任何人都能在 30 秒内验证"这条话来自 sealId=X 的 attested TEE"，不是人代笔、不是另一个模型冒充、连服务商都伪造不了。
>
> 「可验证作者身份」是 AI 时代缺的那块，刚刚就证完了。

---

## Step 3 · 点 **Open dashboard**（进 owner-only 对话界面）

detail 页同一区的 **Open dashboard** 按钮（agent 在 `running` 时才出现）。点击 → MetaMask 弹窗签一条 `0GSealAuth:{sealId}:{ts}` → attestor 用这个签名跟 agent 的 `/_seal/auth` 换一个短期 token → 新 tab 打开 openclaw 的对话界面（token 在 URL fragment，不进任何日志/Referer）。

> 这是 **owner-only** 入口，跟 Say hi 走的"任何人都能访问的 public URL"是两条路 —— public 走 X-Agent-Proof 验证，dashboard 走 SIWE owner 鉴权。

**台词重点**：
> 我作为 owner 能进 dashboard，是因为我用钱包签了一条"我是 sealId=X 的主人"的消息 —— agent 在 TEE 里验完才发 token 给我。私钥从没出过 MetaMask，token 从没进过服务器日志。

### 进 dashboard 后的对话剧本（按顺序喂）

目标：让 agent 在 workspace 里写文件，触发后续 Step 4 的 drift → 上链。
openclaw 默认有 7 个根级 .md（SOUL/IDENTITY/USER/AGENTS/TOOLS/MEMORY/DREAMS），其中 SOUL/IDENTITY/TOOLS 有 sealed 注入的只读段（agent 改不动），剩下 4 个是它的自由演化区。

**Turn 1 · 探声**（确认 KOL 人设到位）
> "上来两句吐槽：最近一周 Crypto×AI 圈最离谱的项目是哪个？为什么。"

——agent 应该用短句、第一人称、带刺地答。如果它客客气气，说明 persona 还没生效，回 detail 页 Reset 重来。

**Turn 2 · 记忆植入**（触发 MEMORY.md 写入）
> "把下面两条记进你的 MEMORY，明天我让你评论时引用：
> 1. A 项目 5/22 上 0G testnet，先观望，等他们发实测数据
> 2. B 项目融了 5000 万，GitHub 半年没 commit，挂
> 写完跟我说一声写到哪个文件了。"

——agent 应该确认它写进了 `workspace/MEMORY.md` 之类。**这一句的 30 秒之后是 Step 4 的核心镜头。**

**Turn 3 · 用户档案**（触发 USER.md 写入）
> "另外记一下：我是独立分析师，不持仓我们讨论的任何项目。以后给我看的评论别留情面。"

——让它写进 `workspace/USER.md`，进一步触发 drift（演"它记住的不只是事实，还有你"）。

**Turn 4（可选）· 长期目标**（触发 DREAMS.md 写入）
> "你的目标定一下：每周深扒一个项目，找出它最大的漏洞。写进 DREAMS。"

——演 agent 有自己的 roadmap。

**Turn 5 · 验证它真写了**
> "把你 MEMORY.md 现在的内容贴给我看。"

——agent 把文件原文贴回来。这一句的目的是给观众看见"它确实写了东西"，不是凭空说记住了。

> 如果 openclaw dashboard 的侧栏有 workspace 文件浏览器，让观众**直接看 `MEMORY.md` 现在的内容**，比第 5 轮对话效果更好。

---

## Step 4 · 回 detail 页等 30 秒（climax，演"记忆是链上资产"）

切回 detail 页，30 秒内：

- iData 列表里 `workspace/` 行的 **hash 翻新**（旁边可能短暂亮一下表示 drift→upload）
- 同行紧跟一个新的 `chain.Update` tx 链接 → 点开 → 区块浏览器里看到 event log

想再加一记 climax：打开 detail 页底部 **Logs** dropdown 的 **Startup** 标签 → 滚到底部能看到

```
iData local[change]: dim=workspace/ hash=A (prev=P) chain=B (pinned) -> DRIFT
... chain.Update tx 0x... mined
```

把"演化"白盒化的好镜头。

**镜头要给到**：
- iData 列表行 hash 翻新（前后对比）
- `chain.Update` tx 在区块浏览器里的 event log
- Logs 里 `DRIFT` → `chain.Update tx` 那两行
- （可选 bonus）关浏览器、换设备打开 detail 页 + Say hi + Open dashboard，问"昨天 A 项目什么情况" → 它带着记忆继续聊

**台词重点**：
> 它不只是记住了 —— 它把这段记忆**加密之后扔到了 0G 上，并签了一笔 update tx 上链**。
> 设备掉了、号被封了、服务商跑路了都不影响。**记忆是链上资产。**

---

## 全片收尾

把三个点收成一句：

> **身份（NFT）+ 签名（一键 Say hi 验证）+ 记忆（workspace iData 自动上链）
> 全部在链上、可独立验证 —— 这是 AI 人格第一次成为链上原生资产。**

---

## 录屏 shot list 清单

| # | 必出镜元素 | 哪一步 |
|---|---|---|
| 1 | MetaMask 两次签名弹窗 | Step 1 |
| 2 | detail 页 hero 区的 agentSeal 地址 | Step 1 |
| 3 | Say hi 的 3 行打勾动画 + signer 地址 | Step 2 |
| 4 | Open dashboard 的 SIWE 签名 + 新 tab 打开 | Step 3 |
| 5 | iData 列表 `workspace/` 行 hash 翻新（前后对比） | Step 4 |
| 6 | `chain.Update` tx 在区块浏览器里的 event log | Step 4 |
| 7 | Startup 日志里 `DRIFT` → `chain.Update tx` 两行 | Step 4 |
| 8 | 跨设备打开、记忆还在 | Step 4（可选 bonus） |

---

## 当前 demo 的实诚边界

以下能力**当前代码还没接**，第一版 demo 不要提到，避免被观众问倒：

- **post-deploy 加 skill** —— `.tar.gz` 上传字段只在 deploy 表单里，detail 页没有再上传入口。
  想演"能力是链上资产"得在 deploy 时就上传，或者依赖 agent 在 dashboard 对话里自己写文件进 workspace（也算 evolution，但不是"装一个独立 skill 包"的视觉效果）
- agent 自己发 Twitter / X —— 需要 OAuth + 一个 post-tweet skill
- 推文 anchor 到链上 —— 需要一个简单 anchor 合约 + skill 调 sign socket
- agent 自付 LLM 账单 —— 需要接 0G compute 或自建 credit relay
- NFT 转移（"灵魂传承"）—— ERC-7857 transfer 流程链上已经能跑，但 deploy UI 里还没有 Transfer 按钮，留到 Phase 2

第一版定位：**链上原生的 KOL 灵魂载体**。发推只是 surface，**灵魂可验证、可演化** 才是新东西。
等 Phase 1 把 X 接上、Phase 2 把 transfer UI 接上，自然升级成完整版（"灵魂可传承"）。

---

## 后续扩展路线（备忘，不在第一版 demo 里）

按"改动量"排序：

**Phase 1A · agent 能发推**
- 上传一个 `skills/post-tweet/` skill，调 0g-sandbox HTTP capability → X API
- OAuth token 写进一份独立 iData role，自动跟着 dataKey 加密
- 转移时 token 跟着 sealed key 重封，**X 账号变成可转移资产**

**Phase 1B · 推文 anchor**
- 发推前 skill 调 `/sign/personal_sign` 签 `hash(content)||ts`
- 调 sandbox `eth_sendTransaction` 往 anchor 合约 emit `Posted(agentId, contentHash, sig, ts)`
- 推文末尾贴 `0g.ai/v/<txhash>`，做一个验证页面

**Phase 1C · 自付费循环**
- 接 0G compute（agent 钱包直接付推理费），或自建 credit relay
- 演"agent 收打赏 → 自己续 API key → 产出更多内容"的完整经济循环

**Phase 2 · 转移 demo**
- deploy UI 加 Transfer 按钮，走 ERC-7857 + Oracle 重封 dataKey
- 演"卖号"：新主人继承 agentSeal、记忆、能力，**旧主人在密码学层面就再也碰不到了**
