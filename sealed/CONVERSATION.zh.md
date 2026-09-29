# 对话:一个 agent 一条时间线,以及什么能活下来

对话持久化的设计记录——每个框架 adapter 必须满足的契约、各框架的答案、边界。
在实现**之前**写下(CONFIG_SURFACE 的教训:设计记录是合并判据,不是事后补交)。
英文原版:`CONVERSATION.md`。

## 1. 问题

agent 的对话必须活过**框架进程重启**——而 settings 通道落地后,进程重启变成了
高频事件:每次 settings 推送、每次 `/think` 都是一次 Stop+Start
(`manager.Reload`),崩溃重启走同一条路。现状:

| | 对话活在哪 | 进程重启后 |
|---|---|---|
| openclaw / hermes | 客户端(无状态聊天门;客户端每轮重发全量 `messages[]`) | 无感——客户端把历史再送来 |
| prime / dsh | 桥的**进程内存**(一个 SDK 会话对象 + `const responses = new Map()`) | **彻底失忆** |

prime/dsh 现在靠 `restoreTranscript()` 糊:新进程的第一回合,把**客户端**手里
那份历史当框定文本重放。这是双重的层级错位——让客户端替 harness 保管它自己的
状态,而且重放有损(工具内部过程无法重建),还只在"下一个开口的恰好是存了历史
的客户端"时才起效。

根治就是最显然的那条:**harness 自己把对话持久化在容器里**。两家 SDK 都支持
(对照从镜像里抽出的 SDK 源码核实,非文档——见 §4);我们只是从来没接。

## 2. 不变量(契约)

约束现在和将来的每一个 adapter。`FRAMEWORK_ADAPTER.md` 携带面向接入方的版本。

1. **对话活过进程重启,且归 HARNESS 所有。**不归 proxy(代理再实现一遍会话管理
   = 第二份有损真相源),不归客户端(客户端是窗口,不是仓库)。`Start` 语义:
   框架启动时,存在已持久化的对话就必须接上它。
2. **一个 agent 恰好一条对话。**固定身份(dsh 已硬编码
   `SessionId('owner-chat')`;其余同型)。多 session 永不启用——这是安全决定,
   不是简化:跨 session 隔离要押注在未经审计的上游代码上,而 agent 的长期记忆
   本就跨 session 共享,上游再完美隔离也不密。这也与单驾驶座
   (CONFIG_SURFACE §8.1)对齐:一个 agent、一条时间线、同时一个驾驶员。
3. **存容器可写层的不追踪路径。**构造上就不上链:对话文件必须在所有链上角色
   之外,watcher 任何一拍都提交不到它,任何转让都带不走它。平台在启动时用
   adapter 的 `Roles()` 校验声明路径,冲突即拒。
4. **容器重建清空——这是设计。**`reset` 就是"重新开始"。该带过重建的东西,
   agent 早已蒸馏进链上记忆角色(MEMORY.md / memories/ / harness_state.json)。
   对话是工作上下文,不是资产。
5. **`/clear`:owner 可以不重建容器地清空对话。**owner 签名,与 settings 推送
   同一文法。框架开新对话;持久化文件删除。
6. **客户端零存储。**`restoreTranscript()` 从"恢复机制"降级为唯一一种磁盘
   兜不住的场景(容器重建后 owner 仍想续)的尽力兜底,那个场景若判定不值得保,
   可整体退役。
7. **文件有界——adapter 自轮转。**持久化对话是追加式的(见下方不变量与 §4),
   所以文件会一直涨到被轮转为止。它**必须**在尺寸上限处轮转:磁盘有限,一个 runner
   会把多个 agent 挤在同一块共享盘上(实测 ~4 个/runner;当年转让僵尸就是盘压力),
   所以无界追加文件是真实的撑爆盘风险,不是理论风险。轮转切在最近一个压缩点——天然的安全切割线,因为当前上下文正是
   从那里重建的——丢弃之前的内容(git-gc 形状)。这是 adapter 的义务(§3),
   不是平台的;而且是**必须项**,不是"将来":"纯文本涨得慢"不构成上界。众多
   agent 撑爆整盘是沙盒层的配额/驱逐问题,不归这个文件管——但这个文件不能当
   元凶,自轮转就是它保持清白的方式。

## 3. 接口(落进 `framework.Framework` 的东西)

刻意做薄——平台立义务,方言留在 adapter(`RenderSettings` 模式):

- **`ClearSession(ctx) error`**(新增,进接口或先作可选能力、四家齐后转正):
  清掉持久化对话,下一回合呈现新对话。proxy 加一条 owner 签名路由
  (`POST /_seal/clear`,tag `0GSealClear`,digest 在 audience 之前的既有文法)
  调它,CLI 加 `/clear`。
- **`ConversationPath() string`**(声明,对话在客户端侧的 adapter 可为空):
  平台在启动时断言该路径在所有声明角色之外。除此之外平台代码不碰这个文件。
  adapter 同时对文件**尺寸**负责:必须在上限处自轮转(切在最近压缩点、丢弃更早
  的——见不变量 7),因为 runner 的共享有限磁盘上,无界追加文件是真实的撑盘风险。平台
  不轮转它(它从不读这个文件),只校验路径。
- **`Start` 的文档契约**:"若你的框架持久化了对话,Start 必须接上它"——对既有
  方法的语义要求,不是新方法。

proxy 明确**不**获得对话存储、压缩逻辑、或对文件的任何读取。压缩始终是
harness 自己的(prime 原生压缩并记录 `compaction` 条目;dsh 挂载
`dsh-compaction-basic`)。

## 4. 各框架的答案(依据 SDK 源码,非文档)

| | 机制 | 文件 | clear |
|---|---|---|---|
| **prime** | `createAgentSession({ …, sessionManager: SessionManager.open(path) })` —— SDK 自己逐条追加(完整消息树:消息、工具调用、压缩、思考档位变更),重启时 `open()` 重建上下文。只多传一个选项;追加与重放都是上游代码。 | `/root/.prime-conversation/owner-chat.jsonl` —— 在 `primeHome` 之外,任何被追踪角色永远够不到(与 `/tmp/prime-session` 那个 pin 同一"构造上防上链"论证;那份是 harness 状态,**不是**对话,原样不动) | 删文件,重开一个新 `SessionManager` |
| **dsh** | 没有现成存储后端(`SessionPersistence` 接缝存在但全树无任何具体子类;没有它 `ctx.agents.resume()` 直接拒绝)。桥用随包发行的编解码器实现官方重放路径:订阅 `ctx.on('session/event')`,`packChunkRuns` 序列化追加落盘;重启时 `decodeStorageRecord` + `ctx.agents.create({ sessionId, seed, meta: { seedLength } })`。seed 规则(从 seq 0 连续、无悬空轮次)用随包的 `interruptedTurnClosers` 崩溃修复保证。 | `/root/.dsh/owner-chat.session.jsonl` —— `paths.go` 本就把"任何 session-persistence 后端的输出"归为刻意不追踪 | 截断文件,dispose 后无 seed 重建 agent |
| **openclaw / hermes** | **第三阶段,刻意推迟。**它们今天没有失忆(无状态门 + 客户端全量重发),没有坏的东西;给它们容器持有的对话 = "有状态 `/v1/responses` 接它们的原生会话存储(hermes `state.db`、openclaw 会话存储)"那项工作,规格化之前需要单独一轮 SDK 级调研。在那之前它们的 `ConversationPath()` 为空,`ClearSession` 只清 synth 环。 | — | — |

两个源码级的坑,记下来免得再踩:

- prime 的 `createAgentSession` JSDoc 写着 `continueSession: true`;**那是死
  文档**——没有任何代码读这个选项。持久化只由 `sessionManager` 对象承载。
- dsh 的落盘格式是它的 `SESSION_FORMAT_VERSION = 0`,无兼容承诺。此处可接受:
  文件由同一个镜像写、同一个镜像读——格式变更必随镜像变更到来,而镜像变更
  要求容器重建,重建本来就清文件。此文件永远不得被写它的桥之外的任何东西读。

## 5. 刻意不做的

- **proxy 不存对话**——已否:对每家 harness 都已拥有的东西做一份有损的二次
  实现。
- **不上链**——对话是工作上下文;耐久知识已经走记忆角色。且链上对话会随转让
  交接,对私人聊天恰好是错的。
- **不做多 session、不做会话选择器、不做 `previous_response_id` 寻址**——
  不变量 2。
- **平台不做压缩/摘要**——**模型上下文**长度由 harness 自己的压缩处理(它追加一条
  `compaction` 条目、把叶指针前移;文件保留压缩前的条目,所以没有破坏性丢失,分支
  仍够得到它们)。这也是为什么文件只在**两次轮转之间**增长——"只增"从不等于无界:
  adapter 在上限处轮转(不变量 7 / §3)。平台既不解析对话,也不轮转它。
- **不做跨机器/跨客户端同步**——文件随容器;客户端什么都不持有,也就没有
  可同步的东西。想显示回滚条的客户端自己留屏幕缓冲,那是 UI,不是状态。

## 6. 落地顺序

1. **prime**(最小:一个选项 + 路径声明 + ClearSession + 测试);
2. **dsh**(桥的事件日志后端 + seed 重建 + 崩溃修复 + 测试);
3. `/_seal/clear` 路由 + CLI `/clear`(可与 1 同落);
4. **openclaw/hermes** 有状态门——单独调研、在本文档追加设计,然后实现。

每 adapter 的验收测试,各阶段同一条:对话进行中杀掉框架进程 → 重启 → agent
能答出杀前已确立的信息,全程无客户端重放;`/clear` → 答不出了;容器重建 →
新对话,链上记忆完好。
