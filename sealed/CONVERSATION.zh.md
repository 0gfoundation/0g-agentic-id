# 对话:一个 agent 一条时间线,以及什么能活下来

对话持久化的设计记录——契约、架构、各框架的答案、边界。在实现**之前**写下
(CONFIG_SURFACE 的教训:设计记录是合并判据,不是事后补交)。英文原版:
`CONVERSATION.md`。

## 1. 问题

agent 的对话必须活过**框架进程重启**——settings 通道落地后重启变高频:每次
settings 推送、每次 `/think` 都是 Stop+Start(`manager.Reload`),崩溃走同一条路。
现在 prime/dsh 把对话记在桥的**进程内存**里,一重启就**彻底失忆**,靠
`restoreTranscript()` 重放**客户端**那份糊住——层级错位(让客户端替 harness 存
它自己的状态)且有损(工具内部过程重建不了)。openclaw/hermes 不失忆,只是因为
客户端每轮重发全量 `messages[]`——也就是客户端就是它们的仓库。

根治:**harness 自己把对话持久化在容器里**,客户端零存储。四家 SDK 都能做
(对照从镜像里抽出的 SDK 源码核实——§4);我们从没接。

## 2. 不变量(契约)

约束现在和将来每一个 adapter。`FRAMEWORK_ADAPTER.md` 携带面向接入方的版本。

1. **对话活过进程重启,且归 HARNESS 所有**——不归 proxy(代理再实现一遍会话管理
   = 第二份有损真相源),不归客户端(它是窗口,不是仓库)。框架启动时,存在已
   持久化的对话就接上它。
2. **一个 agent 恰好一条对话。**固定身份(dsh 已硬编码 `SessionId('owner-chat')`)。
   多 session 永不启用——安全决定,非简化:跨 session 隔离要押注未审计的上游代码,
   而长期记忆跨 session 共享本就破了隔离。与单驾驶座(CONFIG_SURFACE §8.1)对齐:
   一个 agent、一条时间线、一个驾驶员。
3. **存容器可写层的不追踪路径**——构造上不上链:在所有链上角色之外,watcher 任何
   一拍都提交不到、任何转让都带不走。平台启动时用 `Roles()` 校验声明路径,冲突即拒。
4. **容器重建清空——这是设计。**`reset` 即"重新开始";该留的早已蒸馏进链上记忆
   角色(MEMORY.md / memories/ / harness_state.json)。对话是工作上下文,不是资产。
5. **`/clear`:不重建即清空。**owner 签名,settings 推送同一文法。开新对话,删文件。
6. **客户端零存储。**`restoreTranscript()` 降级为唯一一种磁盘兜不住场景(重建后
   owner 仍想续)的尽力兜底,可退役。
7. **文件有界——由框架的封装层自轮转。**存储追加式,不轮转就一直涨;而磁盘有限、
   一个 runner 多 agent 共享,无界文件是真实撑盘风险,非理论。轮转切在最近压缩点
   (安全线——当前上下文从那里重建),丢弃更早的(git-gc 形状)。**必须项**,非"将来"。

## 3. 架构:一个透明 proxy + 各框架自己的封装

终态——把所有框架专属行为**移出**共享 proxy、**沉进**各框架在请求路径上的封装,
让 proxy 不再认得自己面对的是哪个框架。

- **proxy 是透明反向代理。**它只做跨框架、**框架无关**的活——鉴权、单驾驶座、
  serve-proof、CORS——然后转发给框架的封装。它不按框架分支,也不读、不拼任何对话。
- **每个框架背后都有一个在请求路径上的封装,讲全套协议,含有状态 `/v1/responses`**
  (客户端只发当前轮,封装从 harness 自己的存储补历史)。prime/dsh 已经有——它们的
  `bridge.mjs`;hermes 自己的 gateway 原生有;openclaw 新增一个 shim(§4)。
- **`synth` 层删除。**它今天存在的唯一理由是"在 proxy 里替缺 responses 门的框架
  伪造一扇"——一个"认框架"的 proxy 分支。一旦每个框架都通过自己的封装声明原生
  responses 路由,`nativeResponsesDeclared()` 恒真,synth 成死代码。删它正是目的:
  框架专属耦合(如 openclaw 的私有落盘格式)从共享 proxy 代码搬进 openclaw 自己的
  shim——框架专属的东西本就该在那里。
- **`/v1/chat/completions` 每家保留**——无状态、客户端持历史——任何标准 OpenAI
  客户端照连(互通不牺牲;有状态是**第二扇**门,不是替换)。
- **`ClearSession`** 是平台在封装上立的唯一新义务;proxy 暴露一条 owner 签名的
  `POST /_seal/clear`(tag `0GSealClear`,digest 在 audience 之前)转调它,CLI 加
  `/clear`。压缩始终是 harness 自己的——平台永不解析对话。

## 4. 各框架的答案(依据 SDK 源码,非文档)

| | 请求路径上的封装 | 怎么持久化 + 恢复 | clear |
|---|---|---|---|
| **prime** | `bridge.mjs`(原生 `/v1/responses`) | 给 `createAgentSession` 传 `sessionManager: SessionManager.open(path)` —— SDK 自己逐条追加(消息、工具调用、压缩、思考),重启 `open()` 重建上下文。文件 `/root/.prime-conversation/owner-chat.jsonl`,在 `primeHome` 之外(`/tmp/prime-session` 那个 pin 是 harness 状态、**不是**对话,原样不动)。 | 删文件,重开 |
| **hermes** | 它自己的 gateway(原生 `/v1/responses` + `X-Hermes-Session-Id`) | HTTP 上本就有状态:给个稳定会话号,hermes 就从 `~/.hermes/state.db` 读历史(而非请求体)、重启后恢复。我们设 `API_SERVER_KEY` 并钉住会话号。注意压缩会**换**会话号(生成子会话)——跟着 hermes 回吐的号走,别硬钉一个。 | 换会话号 / 清库 |
| **dsh** | `bridge.mjs`(原生 `/v1/responses`) | 没有现成后端(`SessionPersistence` 接缝在、无具体子类;没它 `resume()` 拒绝)。桥用随包编解码器实现官方重放:订阅 `session/event`、`packChunkRuns` → 追加落盘;重启 `decodeStorageRecord` + `ctx.agents.create({ sessionId, seed, meta:{seedLength} })`,`interruptedTurnClosers` 崩溃修复。文件 `/root/.dsh/owner-chat.session.jsonl`(本就归为不追踪)。 | 截断,无 seed 重建 agent |
| **openclaw** | **新增 shim**,在请求路径上、垫在 openclaw gateway 前(像一个 bridge)。openclaw 的 OpenAI gateway **没有**原生 responses 门,也从不回读自己的 transcript。shim 提供有状态 `/v1/responses`:读 openclaw 自己盘上的 transcript(`~/.openclaw/agents/<id>/sessions/*.jsonl`,它每轮都写)、拼上当前轮、调 openclaw 的 `/v1/chat/completions`。私有格式耦合关在这里——openclaw 自己的封装内,不进共享代码。 | 删 openclaw 的会话文件 |

源码级的坑,记下来:

- prime 的 `createAgentSession` JSDoc 写着 `continueSession: true`——**死文档**,
  没代码读它。持久化只由 `sessionManager` 承载。
- dsh 落盘格式是 `SESSION_FORMAT_VERSION = 0`,无兼容承诺——可接受:同一镜像写、
  同一镜像读,格式变更必随镜像变更,而镜像变更逼容器重建、重建清文件。除了写它的
  桥,任何东西都不得读它。
- openclaw 的 transcript 是私有 `version:3` JSONL。shim 贴着它;openclaw 升级改
  格式就是 shim 的维护负担——局限在 openclaw 封装内,和这层本就有的耦合同类
  (它已经在解析 openclaw.json)。

## 5. 刻意不做的

- **proxy 不存对话、没有 `synth` 层**——proxy 透明;对话逻辑在各框架的封装里。
- **不上链**——工作上下文非资产;耐久知识走记忆角色,链上对话还会随转让交接
  (对私人聊天是错的)。
- **不做多 session、不做选择器、不做 `previous_response_id` 寻址**——不变量 2。
- **平台不做压缩**——**模型上下文**由 harness 自己压(追加 `compaction` 条目、前移
  叶指针;文件保留旧条目,无破坏性丢失)。文件只在**两次轮转之间**涨;封装负责轮转
  (不变量 7)。平台永不解析它。
- **不做跨机器同步**——文件随容器;客户端零持有。想显示回滚条的客户端自留屏幕
  缓冲——UI,不是状态。

## 6. 落地顺序

1. **prime**——传一个 `SessionManager.open` 选项 + 路径 + `ClearSession` + 测试。
   最小;验证契约。
2. **hermes**——声明它的原生 `/v1/responses`,设 `API_SERVER_KEY`,钉住并跟随
   会话号;proxy 透明转发。
3. **dsh**——桥的事件日志后端 + seed 重建 + 崩溃修复。
4. **openclaw**——新 shim(垫在 gateway 前、读 openclaw 的 transcript);四家都声明
   原生 responses 后**删除 `synth` 层**。
5. `/_seal/clear` 路由 + CLI `/clear`(可与 1 同落)。

每 adapter 的验收测试,各阶段同一条:对话进行中杀掉框架进程 → 重启 → agent 答出
杀前已确立的信息,**全程无客户端重放**;`/clear` → 答不出;容器重建 → 新对话,
链上记忆完好。
