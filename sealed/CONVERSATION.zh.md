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
   一拍都提交不到、任何转让都带不走。由构造保证而非运行时校验:每个存储路径都是 adapter 里的编译期常量、保持在其角色树之外(`RoleSpec` 刻意不携带文件系统路径,平台层的通用校验根本不可表达)——各 adapter 的 `paths.go` 记录归类。
4. **容器重建清空——这是设计。**`reset` 即"重新开始";该留的早已蒸馏进链上记忆
   角色(MEMORY.md / memories/ / harness_state.json)。对话是工作上下文,不是资产。
5. **`/clear`:不重建即清空。**owner 签名,settings 推送同一文法。开新对话,删文件。
6. **客户端零存储。**`restoreTranscript()` 降级为"磁盘没兜住"的那些场景的尽力
   兜底:容器重建,以及**任何存储没恢复出内容的 boot**(全新、被隔离、被归档)——
   门禁按"这次 boot 真的从盘上恢复了"判定,不按"配置了持久化"判定。
7. **文件有界——由框架的封装层自轮转。**存储追加式,不轮转就一直涨;而磁盘有限、
   一个 runner 多 agent 共享,无界文件是真实撑盘风险,非理论。轮转切在最近压缩点
   (安全线——当前上下文从那里重建),丢弃更早的(git-gc 形状)。**必须项**,非"将来"。
   轮转在**打开时**(boot)执行——活的写入者手下不能改写文件——所以单次超长 boot 会
   涨到下次重启为止;settings 推送让重启足够高频,上限在实践中经常被执行。

## 3. 架构:通用 proxy + 各框架自己的封装

按设计,所有框架专属的会话知识都住在各框架自己的封装里;共享 proxy 永不按框架名
分支。这一原则的**落地方式**在实现中做了精化(最初草案写的是"给 openclaw 新建
shim 进程、然后删除 synth 层"):不为每个框架再起一个进程,而是让 proxy 的有状态
门通过**三个可选能力接口**问 adapter——`RenderSettings` 模式——各 adapter 在
自己的包里用自己的方言作答。所有权结果相同(共享代码里零框架知识),少一个进程。
synth 层**保留**,但只剩共享的 responses 协议外壳(SSE/续传/环);它曾隐含的所有
框架专属内容都移到能力接口之后:

- **`framework.ConversationSession`** —— adapter 命名把每次有状态上游调用绑定到
  该 agent 唯一对话的 header,并观察每个上游响应(hermes 在压缩时轮换会话 id;
  不跟随回吐就会在每次压缩处分叉对话)。
- **`framework.ConversationHistory`** —— 框架持久化了 transcript 但它自己的网关
  从不回读(openclaw)时,adapter 从那份存储供给历史;有状态门随即忽略客户端发的
  历史,只取客户端的当前轮。历史读取失败**响亮地**降级为客户端输入——坏存储
  不能杀掉这一轮。
- **`framework.SessionClearer`** —— 清掉存储;main.go 在成功清除后重启进程。
  proxy 暴露一条 owner 签名的 `POST /_seal/clear`(tag `0GSealClear`,settings
  推送文法,占座门控),CLI 加 `/clear`;历史在客户端侧的 adapter 答 501,CLI
  只清本地回显。

透明的 `/v1/chat/completions` 门**永远**不带会话 header、不用存储历史——在那扇门
上做有状态会悄悄改变标准 OpenAI 客户端看到的行为。有状态是第二扇门,不是替换。
压缩始终归 harness 自己;平台永不解析对话。

## 4. 各框架的答案(as built,对照 SDK 源码核实)

| | 封装 | 持久化 + 恢复 | clear |
|---|---|---|---|
| **prime** | `bridge.mjs` + `sessionstore.mjs`(原生 `/v1/responses`) | `createAgentSession({ …, sessionManager: SessionManager.open(SEAL_CONVERSATION_FILE) })` —— SDK 自己逐条追加(消息、工具调用、压缩、思考),重启 `open()` 重建上下文。文件 `/root/.prime-conversation/owner-chat.jsonl`,在 `primeHome` 外,`privsep` 交接属主。自轮转切在最近压缩条目(保留 header、压缩条目重挂根、丢弃更早行);损坏文件隔离(`.corrupt-<ts>`)后开新。真 SDK 验证:轮转 9209B→729B 且上下文可重建;断尾行可容忍。 | 删文件+残留,重启 |
| **hermes** | 它自己的网关,经 `ConversationSession` 绑定 | 网关在 HTTP 上本就有状态:`X-Hermes-Session-Id`(Bearer `API_SERVER_KEY`,早已设置)让历史从 `~/.hermes/state.db` 读、body 最后一条为当前轮。adapter 铸造并持久化唯一 id(`~/.hermes/.seal-conversation-id`)并**跟随**回吐的 id——压缩会结束父会话、在子 id 上续。不安全回吐(路径形、控制字符)永不落盘。不变量 7 注:transcript 存储是 hermes 自己的 `state.db`——它的存储、它的压缩;自轮转不适用于 harness 自有的文件。 | 铸新 id(旧行留在 hermes 的 db,无引用),重启 |
| **dsh** | `bridge.mjs` + `sessionstore.mjs`(原生 `/v1/responses`) | 无现成后端(`SessionPersistence` 接缝无具体子类;没它 `resume()` 拒绝)。桥即后端:`owner-chat` 会话每个已提交 `session/event` 经 `packChunkRuns` 追加;boot 时 `decodeStorageRecord` 解码后作 `ctx.agents.create({ seed, meta:{seedLength} })` 的种子;`interruptedTurnClosers` 闭合中途崩溃(closer 也落盘,文件自平衡);seq 守卫跳过重发的种子事件。轮转必然更粗:seed 必须从 seq 0 连续,砍不了头——到上限就归档、响亮地重开新对话。文件 `/root/.dsh/owner-chat.session.jsonl`(本就归为不追踪)。真 SDK 验证:追加→装载→`Session.fromRestore`(create 的校验器)通过;崩溃修复平衡。 | 删日志+残留,重启 |
| **openclaw** | `ConversationSession` + `ConversationHistory`,在 adapter 包内 | openclaw 把每轮网关对话都落盘(`~/.openclaw/agents/main/sessions/<id>.jsonl`,`sessions.json` 存 key→session 映射)但它的 OpenAI 门从不回读。adapter 钉一个会话 key(`x-openclaw-session-key`,存 `~/.openclaw/.seal-conversation-key`)让有状态门的所有轮次落进同一份 transcript,并把它读回作历史(文本轮次;工具记录跳过——synth 门一贯记录的限制)。私有 `version:3` 格式耦合关在 openclaw 包内——和这个 adapter 已有的耦合同类(它本就解析 openclaw.json)。不变量 7:openclaw 自己的压缩会**重写**落盘 transcript,harness 自己封顶了文件。 | 轮换 key + 尽力删被替换的 transcript(openclaw 的 `sessions.json` 是它自己的存储——绝不从外部改写),重启 |

源码级的坑,记录在案:

- prime 的 `createAgentSession` JSDoc 写着 `continueSession: true`——**死文档**,
  没代码读它。持久化只由 `sessionManager` 承载。
- dsh 落盘格式 `SESSION_FORMAT_VERSION = 0`,无兼容承诺——可接受:同镜像写读,
  格式变更必随镜像变更,而那要求重建、重建清文件。只有写它的桥可以读它。
- dsh 事件文法:`user/message` 的 data **就是**消息本体(不包 `{message:}`),
  surface 事件**必须**带 `surfaceOp` 标记,消息必须有 id——`Session.fromRestore`
  三样都校验,这正是存储冒烟要驱动真校验器、不用仿制品的原因。
- dsh 的 Session **构造器**在 seed 未以 `session/end-seed` 结尾时,会在
  `seq = seed.length` 处自行追加该标记——且从不发布到 `session/event`,firehose
  持久器收不到,**第二次重启**就撞连续性校验砖死(评审 #169 blocker,跨代实证)。
  `loadSeed` 预先把标记同时写入文件和返回的 seed,构造器便不再追加。
- openclaw 的 `sessions.json` 是 **agent 可写的**(privsep 把 openclawHome 交给
  框架用户),所以它命名的 `sessionFile` 在 root 进程打开前必须被词法约束在
  sessionsDir() 内,且打开走 `os.OpenRoot`——词法检查拦不住目录**内部**栽的符号链接——否则对抗性 agent 可让 root 把任意文件读进它自己的上游请求
  (评审 #169)。
- hermes 在压缩时**轮换**会话 id——钉死一个 id 会分叉对话;必须跟随回吐。

## 5. 刻意不做的

- **proxy 不存对话、共享代码里零框架知识**——synth 层只作为共享的 responses
  协议外壳存活;一切框架专属事实(header、存储格式、clear 语义)都在三个能力
  接口之后、各框架自己的包里。
- **不上链**——工作上下文非资产;耐久知识走记忆角色,链上对话还会随转让交接
  (对私人聊天是错的)。
- **不做多 session、不做选择器、不做 `previous_response_id` 寻址**——不变量 2。
- **平台不做压缩**——**模型上下文**由 harness 自己压(追加 `compaction` 条目、前移
  叶指针;文件保留旧条目,无破坏性丢失)。文件只在**两次轮转之间**涨;封装负责轮转
  (不变量 7)。平台永不解析它。
- **不做跨机器同步**——文件随容器;客户端零持有。想显示回滚条的客户端自留屏幕
  缓冲——UI,不是状态。

## 6. 落地 —— 已完成并通过 T2 真机验证(2026-09-29,dev)

演练覆盖四框架(agent 436/449/450/452,镜像 cd547ec),每一问都由**全新
client(零历史)**发出——连续性只可能来自容器:

| 腿 | openclaw 436 | hermes 449 | dsh 450 | prime 452 |
|---|---|---|---|---|
| 同 boot 读回(全新 client) | ✓ | ✓ | ✓ | ✓ |
| 重启#1(settings 推送)→ 记得 | ✓ | ✓ | ✓ | ✓ |
| 重启#2 → 记得(dsh blocker 的咬点) | ✓ | ✓ | ✓ | ✓ |
| /clear → unknown | ✓ | ✓ | ✓ | ✓ |
| 容器重建 → unknown、链上记忆完好 | ✓(MEMORY.md 验证完好) | ✓ | ✓ | ✓ |

演练中值得记录的:
- openclaw 第一次 /clear "失败"是因为 agent 被要求 "remember" 时**自己把暗号写
  进了 MEMORY.md**——即 /clear 行为分毫不差(清对话、留记忆),是测试语句混淆了
  两个存储。这次意外恰好把"对话 vs 记忆"的设计区分做了真机演示,是这条设计线
  最有力的证据。
- 投毒 sessions.json 的收容**未能 live 执行**:agent 两次拒绝破坏自己的会话
  存储,即使以 owner 名义的演练说明——这本身值得记录。收容依据单测(5 例词法 +
  os.OpenRoot 符号链接),驱动同一代码路径。
- openclaw persist 时序:问第 N+1 轮时 transcript 已含第 N 轮(全新 client 的
  同 boot 读回证明了回读路径)。
- hermes 压缩轮换未在演练中触发(需要长对话);跟随逻辑有单测,回吐语义读自
  网关源码。

原清单(全部完成):


1. ✅ prime —— SessionManager 接线 + 自轮转 + 损坏隔离 + ClearSession
2. ✅ dsh —— 桥事件日志后端 + seed 重建 + 崩溃修复 + ClearSession
3. ✅ hermes —— 会话 id 钉住 + 轮换跟随 + ClearSession
4. ✅ openclaw —— 会话 key 钉住 + transcript 作历史 + ClearSession
5. ✅ `/_seal/clear` + SDK `clearConversation` + CLI `/clear`

每条存储路径都对照**从已 build 镜像抽出的真 SDK** 验证(prime SessionManager
往返+轮转;dsh 追加→seed→`fromRestore`;hermes/openclaw 的 header 语义读自网关
源码)。距离"真正完成"还欠:T2 真机演练——每个框架对话中杀进程 → 重启 → agent
无客户端重放答出杀前信息;`/clear` → 答不出;容器重建 → 新对话、链上记忆完好
——这需要四个镜像重建。按 #169 评审:演练必须对**同一对话重启两次**(dsh 的 end-seed 洞只在第二次重启
咬人——一次重启证明不了什么),并断言 openclaw 的历史读取被收容(投毒的
`sessions.json` sessionFile 在日志中被拒、历史降级为空、该轮存活)。有一项 openclaw 专属检查只能在演练里做、静态定不了:
问第 N+1 轮时 transcript 必须已含第 N 轮(按源码 openclaw 在 turn 管线内持久化,
但若持久化滞后于响应,我们的回读就会比对话慢一轮)。
