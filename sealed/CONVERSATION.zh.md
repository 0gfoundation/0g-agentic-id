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
2. **一个 agent 恰好一条对话。**固定身份(dsh 硬编码 `SessionId('owner-chat')`)。
   第二条对话永不启用——安全决定,非简化:跨 session 隔离要押注未审计的上游代码,
   而长期记忆跨 session 共享本就破了隔离。与单驾驶座(CONFIG_SURFACE §8.1)对齐:
   一个 agent、一条时间线、一个驾驶员。dsh 的子 agent(owner 开关)跑在各自的
   session 里,不算第二条对话:它们是同一个 owner 的一次性工作者,只在内存里,
   不落盘,客户端也找不到它们,工具只有读。它们查到的东西以通知的形式回到这唯一
   一条对话,再由 agent 自己的轮次转告 owner。
3. **存容器可写层的不追踪路径**——构造上不上链:在所有链上角色之外,watcher 任何
   一拍都提交不到、任何转让都带不走。由构造保证而非运行时校验:每个存储路径都是 adapter 里的编译期常量、保持在其角色树之外(`RoleSpec` 刻意不携带文件系统路径,平台层的通用校验根本不可表达)——各 adapter 的 `paths.go` 记录归类。
4. **容器重建清空——这是设计。**`reset` 即"重新开始";该留的早已蒸馏进链上记忆
   角色(MEMORY.md / memories/ / harness_state.json)。对话是工作上下文,不是资产。
5. **`/clear`:不重建即清空。**owner 签名,settings 推送同一文法。开新对话,删文件。
   它温和的兄弟 **`/compact`** 保留对话:由 harness 自己的压缩把较早的历史换成
   摘要,不重启(§3,`framework.SessionCompactor`)。
6. **客户端零存储。**`restoreTranscript()` 降级为"磁盘没兜住"的那些场景的尽力
   兜底:容器重建,以及**任何存储没恢复出内容的 boot**(全新、被隔离、被归档)——
   门禁按"这次 boot 真的从盘上恢复了"判定,不按"配置了持久化"判定。
7. **文件有界——由框架的封装层自轮转。**存储追加式,不轮转就一直涨;而磁盘有限、
   一个 runner 多 agent 共享,无界文件是真实撑盘风险,非理论。轮转切在最近压缩点
   (安全线——当前上下文从那里重建),丢弃更早的(git-gc 形状)。**必须项**,非"将来"。
   轮转在**打开时**(boot)执行——活的写入者手下不能改写文件——所以单次超长 boot 会
   涨到下次重启为止;settings 推送让重启足够高频,上限在实践中经常被执行。

## 3. 架构:通用 proxy + 各框架自己的封装

所有框架专属的会话知识都住在各框架自己的封装里;共享 proxy 永不按框架名分支。
proxy 的有状态门通过四个可选能力接口问 adapter——`RenderSettings` 模式——各
adapter 在自己的包里用自己的方言作答。

**与已批准设计的偏离(未关闭)。** 已批准的设计是:hermes 声明它网关自带的
`/v1/responses`,openclaw 放到请求路径上的 shim 后面,然后删除 synth 层。本 PR
两件都没做:hermes 和 openclaw 仍在 synth 后面(`internal/proxy/responses.go`,
#155 引入),下面前两个能力接口就是给它用的。synth 服务所有没声明
`kind:"responses"` 路由的框架——目前是 hermes 和 openclaw——把 `/v1/responses`
翻译成框架的 chat 接口,并提供长任务机制(`starting_after` 续传、取消、事件记录)。
和 prime 的桥、dsh 的 harness 不同,它不串行任务。两家网关其实都自带 `/v1/responses`
(hermes `api_server.py`;openclaw `handleOpenResponsesHttpRequest`,认
`x-openclaw-session-key`),但都没有实现 `starting_after` 续传。后续(独立 PR):
先在真容器里验证两扇原生门(重启后能否延续、流格式与 CLI/SDK 是否兼容、断线和
取消时的行为),再把 hermes/openclaw 改为直接转发过去,并删除 synth 以及它所需的
补偿机制——hermes 的 id 文件及其比较交换(§4)、openclaw 的"只发当前轮"历史钩子。

四个能力接口:

- **`framework.ConversationSession`** —— adapter 命名把每次有状态上游调用绑定到
  该 agent 唯一对话的 header,并连同本轮发出时的 header 一起观察每个上游响应
  (hermes 在压缩时轮换会话 id;不跟随回吐会分叉对话,跟随了过期的回吐会让已
  清除的对话复活)。
- **`framework.ConversationHistory`** —— 有状态门忽略客户端发的历史,只取客户端的
  当前轮,前面接上 adapter 返回的历史。网关自己会重放会话的框架返回空:openclaw
  就是这样,在它的重放之上再叠客户端的历史,模型会看到两遍(实测,§4)。网关不重放
  的框架则从 harness 自己的存储返回历史。历史读取失败**响亮地**降级为客户端
  输入——坏存储不能杀掉这一轮。
- **`framework.SessionClearer`** —— 清掉存储;main.go 在成功清除后重启进程。
  proxy 暴露一条 owner 签名的 `POST /_seal/clear`(tag `0GSealClear`,settings
  推送文法,占座门控),CLI 加 `/clear`;历史在客户端侧的 adapter 答 501,CLI
  只清本地回显。
- **`framework.SessionCompactor`** —— 按需运行 harness **自己的**压缩:较早的
  历史变成摘要,最新的部分原样保留(保留多少由 harness 决定:dsh 只留最新的一项,
  openclaw 约 20K token),进程不重启。proxy 暴露一条 owner 签名的
  `POST /_seal/compact`(tag `0GSealCompact`,clear 同一文法,占座门控),CLI 加
  `/compact`。有三道 clear 不需要的闸:同一时间只跑一个压缩(第二个答 409);
  一个签名请求只接受一次——压缩要做一次或多次模型调用、不幂等,所以不同于 clear,它
  在新鲜度窗口内不能被重放(以签名的消息为键,换个写法或可塑变形的签名仍算同一
  请求);压缩和 synth 门上的一轮永不重叠——后到的那个被拒(答 409)——因为
  openclaw 的压缩会中止会话里正在运行的那一轮。框架自己的"现在不行"(已有压缩
  在排队、会话仍忙)也答 409(`framework.ErrCompactRefused`),不算失败。压缩与
  请求解耦:连接断开不会中止它,结果写进日志。这一点有实际意义:长的摘要会比客户端
  等得更久——Node 的 fetch 等 300 秒没有回应就放弃——所以 CLI 把"没等到回应"报成
  "仍在压缩,看 /startuplog",而不是失败。
  dsh 让 harness 执行(`POST /v1/compact` → 组合里的 `compactNow`,排在正在跑的
  轮次之后、等 agent 空闲,同一时间只挂一个;摘要由 harness 当前运行的模型来写,输出上限 16384,低于一轮的
  32768——目录没给预算时用引擎自己的 8192,见 `CONFIG_SURFACE.zh.md` §3.2);
  openclaw 对正在运行的网关执行它自己的
  `openclaw sessions compact <key>`,网关地址和 token 走环境变量(它的边界情况见
  下方 openclaw 的坑)。两者在引擎认为没有可折叠的内容时都答"无可压缩"(200,不算
  失败)。上次 `/compact` 之后还没聊过时,dsh 的 harness 也直接答"无可压缩",不调用模型:
  离线实测,紧接着再按一次、或重启后马上按,都会再做一次摘要调用,把摘要再压一遍。
  hermes 和 prime 暂时答 501。

透明的 `/v1/chat/completions` 门**永远**不带会话 header、不用存储历史——在那扇门
上做有状态会悄悄改变标准 OpenAI 客户端看到的行为。有状态是第二扇门,不是替换。
压缩始终归 harness 自己;平台永不解析对话——`/compact` 只是触发它。

## 4. 各框架的答案(as built,对照 SDK 源码核实)

| | 封装 | 持久化 + 恢复 | clear |
|---|---|---|---|
| **prime** | `bridge.mjs` + `sessionstore.mjs`(原生 `/v1/responses`) | `createAgentSession({ …, sessionManager: SessionManager.open(SEAL_CONVERSATION_FILE) })` —— SDK 自己逐条追加(消息、工具调用、压缩、思考),重启 `open()` 重建上下文。文件 `/root/.prime-conversation/session/owner-chat.jsonl`,在 `primeHome` 外,交给 agent 用户(`privsep.OwnTree`);放在交接目录下一层,是因为 SDK 把每个会话的 artifacts 放在会话目录**旁边**,于是它们落在同一棵树里的 `/root/.prime-conversation/session-artifacts/`(早先的 sealed 把文件直接放在 `/root/.prime-conversation`,artifacts 会落到 root 的家目录 `/root/session-artifacts/<id>`;在升级后的容器里,启动时会把那个目录移到 `/root/.prime-conversation/session-artifacts`——`privsep.DeclareRelocation`,由 `ReclaimHome` 执行——Start 再把文件及其轮转产物移进 `session/`,于是恢复的对话既找得到 transcript,也找得到它的会话 artifacts,包括 RLM 会话状态和本地 harness 状态)。自轮转切在最近压缩条目(保留 header、压缩条目重挂根、丢弃更早行);损坏文件隔离(`.corrupt-<ts>`)后开新。真 SDK 验证:轮转 9209B→729B 且上下文可重建;断尾行可容忍。 | 删文件+残留+会话 artifacts,重启 |
| **hermes** | 它自己的网关,经 `ConversationSession` 绑定 | 网关在 HTTP 上本就有状态:`X-Hermes-Session-Id`(Bearer `API_SERVER_KEY`,早已设置)让历史从 `~/.hermes/state.db` 读、body 最后一条为当前轮。adapter 铸造并持久化唯一 id(存在 sealed 仅 root 可访问的状态目录 `/var/lib/sealed/hermes-conversation-id`,不在 agent 可写的家目录里)并**跟随**回吐的 id——压缩会结束父会话、在子 id 上续。不安全回吐(路径形、控制字符)永不落盘。不变量 7 注:transcript 存储是 hermes 自己的 `state.db`——它的存储、它的压缩;自轮转不适用于 harness 自有的文件。 | 铸新 id(旧行留在 hermes 的 db,无引用),重启 |
| **dsh** | 0g-harness `src/store/sessionstore.mjs`(原生 `/v1/responses`) | 无现成后端(`SessionPersistence` 接缝无具体子类;没它 `resume()` 拒绝)。harness 即后端:`owner-chat` 会话每个已提交 `session/event` 经 `packChunkRuns` 追加,在 agent 创建之前就挂好,所以创建瞬间开启的轮次(过期的提醒)也会写进去;boot 时 `decodeStorageRecord` 解码后作 `ctx.agents.create({ seed })` 的种子,按"续上"恢复,不带 `seedLength`——这个字段是分叉边界,DSH 只从它之后的事件里恢复待处理的收件箱任务和定时提醒;轮次记录(收件箱、任务)以 `<日志>.records.jsonl` 放在日志旁边;`interruptedTurnClosers` 闭合中途崩溃(closer 也落盘,文件自平衡);seq 守卫跳过重发的种子事件。轮转必然更粗:seed 必须从 seq 0 连续,砍不了头——到上限就归档、响亮地重开新对话。文件 `/root/.dsh/owner-chat.session.jsonl`(本就归为不追踪)。真 SDK 验证:追加→装载→`Session.fromRestore`(create 的校验器)通过;崩溃修复平衡;定时提醒和待处理通知跨重启保留。 | 删日志及所有 `<日志>.*` 文件(归档、轮次记录),重启 |
| **openclaw** | `ConversationSession` + `ConversationHistory`,在 adapter 包内 | openclaw 把每轮网关对话都落盘(`~/.openclaw/agents/main/sessions/<id>.jsonl`,`sessions.json` 存 key→session 映射),它的网关会把钉住的会话**重放**进每一轮——而且始终是同一个会话,因为 render 把 `session.reset` 设成了永不过期的策略(openclaw 默认每天开一个新会话;见下方的坑)。adapter 钉一个会话 key(`x-openclaw-session-key`,存在 sealed 仅 root 可访问的状态目录 `/var/lib/sealed/openclaw-conversation-key`)让有状态门的所有轮次落进同一个会话,并让门只发当前轮(`ConversationHistory` 返回空——见下方的坑)。私有格式耦合(`sessions.json` 结构、文件命名)关在 openclaw 包内——和这个 adapter 已有的耦合同类(它本就解析 openclaw.json)。不变量 7(2026-10-19 复核,见下方的坑):openclaw 的压缩是**追加**一条 `compaction` 记录、保留所有消息行——会轮转文件的 `truncateAfterCompaction` 需显式开启、默认关——所以这里 harness 并没有给文件封顶;待解决。 | 轮换 key + 删掉被替换会话的文件——transcript 和 trajectory 记录(openclaw 的 `sessions.json` 是它自己的存储——绝不从外部改写),重启 |

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
  框架用户),而 `/clear` 时 **root** 进程会删掉它命名的文件。所以它里面的内容一律
  不当路径用——只保留直接位于 sessions 目录下的纯文件名——并且读这个存储、删这些
  文件都经过 `internal/privsep`:任何路径分量都不跟随链接,只打开普通文件、打开时
  绝不阻塞,某个名字处的链接只删链接本身。目录内部栽的链接,或替换其上层目录的
  链接,都没法让 root 碰到这棵树之外的文件(评审 #169 的收容,现在用在删除路径上;
  它最初保护的那次读取已经删掉)。
- openclaw 的网关会把钉住的会话**重放**进每一轮(2026-10-19 在 2026.7.1 上离线
  验证):单独发出的一轮,到达模型时前面带着之前的各轮;**附带**客户端历史发出的
  一轮,到达模型时那段历史出现了两遍——网关的重放,加上客户端那份被折进新消息,
  写成 `[Chat messages since your last reply - for context] …`。所以门只能发当前
  轮,`ConversationHistory` 返回空正是让它这么做。#169 让 adapter 把 transcript
  读回来当历史发出去,依据是"门不读自己的存储";这次读取从没命中过——2026.7.1 在
  `sessions.json` 里把会话记在 `agent:main:<key>` 下,而不是 `<key>`——所以它一直
  是死代码,现已删除(假如它命中了,之前的每一轮都会到达模型两遍)。
  `ClearSession` 也因同样的原因从没删掉过任何东西;现在它按 `agent:main:<key>`
  (再退到裸 key)找到旧会话,删掉它的 transcript **和** trajectory 记录——每轮
  完整的提示和回复,openclaw 每个会话封顶 10 MiB——已在网关写出的真实文件上验证,
  网关在删除后能正常重启。这个重放遵循压缩(先摘要,再保留的尾部),`/compact` 正是
  因此生效。**手动**压缩只有在设置了 `agents.defaults.compaction.keepRecentTokens`
  时才保留这段尾部——不设的话,openclaw 会改写记录,让重放从摘要开始,而那段从未
  被总结的尾部就丢了(离线实测)——所以 render 会写入 openclaw 自己的默认值
  20000,除非 openclaw.json 里那里已经是一个正整数(owner 的 overlay,或磁盘上的
  修改)。
- openclaw 上的 `/compact` 还有三个边界情况(2026-10-19 离线发现)。
  `sessions compact` 是 2026.7.1 才有的命令。白名单里的 2026.5.6/5.7 有网关的
  `sessions.compact` RPC,但没有 adapter 调用的那条 CLI 命令,所以低于 2026.7.1 时
  `CompactSession` 答 `ErrCompactUnsupported`(501),render 也不写下面这些压缩
  配置:在那些版本上它们只会改变自动压缩(2026.5.x 给压缩 900 秒,不是 180 秒)。
  openclaw 用会话**最后一次**用的模型写摘要,除非 `agents.defaults.compaction.model`
  指定了一个。离线实测:刚换完模型就 `/compact`,摘要用的是旧模型;换模型同时换了
  接口格式时,直接报 "Unknown model"。所以对走路由的 pin,render 在那里写上这个
  pin(实测:两种格式下摘要都发给了新模型),除非 owner 的 overlay 指定了模型。
  框架自带 provider 的 pin 交给 openclaw 自己处理——它可能是 openclaw 会解析的
  别名(anthropic/sonnet → claude-sonnet-5),而指定模型这一做法只对走路由的 pin
  验证过——所以在那里,刚换完模型时的 `/compact` 仍可能用旧模型、或因旧模型失败,
  直到新模型上跑过一轮。openclaw 的压缩期限默认 180 秒
  (`EMBEDDED_COMPACTION_TIMEOUT_MS`),远在 sealed 自己的 11–15 分钟之内,所以
  render 把 `agents.defaults.compaction.timeoutSeconds` 设为 600,除非那里已经是
  一个正整数(用一个每次摘要调用都在 200 秒后才回复的桩模型:默认设置下 180 秒时报
  "Compaction timed out",设为 600 后完成,用时 402 秒)。
  还有,openclaw 的 "Already compacted" / "Nothing to compact (session too small)"
  在它的 CLI 里报的是失败,这里回成"无可压缩"。
- openclaw 默认的会话策略是**按天**:每天 04:00(本地时间)之后的第一轮,会给同一个
  key 开一个新会话。在 2026.7.1 上离线实测(把会话的时间倒拨过边界):下一轮到达
  模型时之前的各轮一条都没有,前一天的 transcript 和 trajectory 成了孤儿——`/clear`
  只跟着 key 当前的那一条记录走,所以它们留在了磁盘上。在此之前,openclaw agent 的
  对话会在每个 04:00(容器本地时间)之后的第一轮这样重新开始。render 现在把 `session.reset` 设为 `{mode: "idle"}`
  且不设 `idleMinutes`,永不过期(reset-policy:idle 没有时间窗就不设过期;实测:
  第二天那轮带上了第一天的内容)——除非 owner 的 overlay 自己设了 `session.reset`。
- `/clear` 在 openclaw 上仍会留下的东西(只在容器磁盘上,绝不上链;容器重建即消失):
  openclaw 在自己 `sessions.json` 里为旧 key 保留的压缩摘要(`compactionCheckpoints`,
  网关运行时 sealed 不改写这个存储);在上面这个策略之前被按天重置弄成孤儿的会话
  文件;以及清除到随后重启之间、旧 key 上仍在进行的一轮重新写出的文件——这样重写
  出的 trajectory 是被清除对话的完整副本。
- hermes 在压缩时**轮换**会话 id——钉死一个 id 会分叉对话;必须跟随回吐。
  跟随用的是对本轮**发出时** id 的比较交换:synth 不串行任务,一个跨过 `/clear`
  (或落在更新一轮的轮换之后)仍在飞的旧轮,否则会把旧 id 写回、让已清除的对话
  复活(#169 stale-copy 审计)。

## 5. 刻意不做的

- **proxy 不存对话、共享代码里零框架知识**——proxy 不持有 transcript,也不按
  框架名分支。但它还不是纯转发:synth 为没声明原生门的框架保留着(§3)。
- **不上链**——工作上下文非资产;耐久知识走记忆角色,链上对话还会随转让交接
  (对私人聊天是错的)。
- **不做多 session、不做选择器、不做 `previous_response_id` 寻址**——不变量 2。
- **平台不做压缩**——**模型上下文**由 harness 自己压(追加 `compaction` 条目、前移
  叶指针;文件保留旧条目,无破坏性丢失)。文件只在**两次轮转之间**涨;封装负责轮转
  (不变量 7;openclaw 尚未做到,见 §4)。平台永不解析它。`/compact` 不改变这一点:它只是让 harness 现在就跑
  一次它自己的压缩。
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
  存储,即使以 owner 名义的演练说明——这本身值得记录。收容依据单测(收容用例,
  以及删除路径上不跟随链接的测试:会话文件名处的链接,以及替换其上层目录的链接),
  驱动同一代码路径。
- openclaw persist 时序:问第 N+1 轮时 transcript 已含第 N 轮(全新 client 的
  同 boot 连续性)。2026-10-19 复核:起作用的是网关自己的重放——回读在 2026.7.1
  上从没命中过 key。
- hermes 压缩轮换未在演练中触发(需要长对话);跟随逻辑有单测,回吐语义读自
  网关源码。

可重复的回归护栏(评审跟进 2):每个 store 都有一个 `sessionstore_regression.mjs`
——dsh 的在 0g-harness 里(`test/regression/`,由它的 `npm test` 在 harness 锁定的
SDK 树上运行),重放完整四代场景(finding-1 不变量)、崩溃修复与残根;prime 的在它
桥的 store 旁边,覆盖往返、压缩点轮转与残根隔离。真 SDK 取自 `$DSH_SDK_ROOT` /
`$PRIME_SDK_ROOT`(构建好的镜像里的 node_modules 或 docker cp 抽出的树);prime 的
在缺席时干净 SKIP——仓库对环境门控测试的既有惯例。

原清单(全部完成):


1. ✅ prime —— SessionManager 接线 + 自轮转 + 损坏隔离 + ClearSession
2. ✅ dsh —— 桥事件日志后端 + seed 重建 + 崩溃修复 + ClearSession
3. ✅ hermes —— 会话 id 钉住 + 轮换跟随 + ClearSession
4. ✅ openclaw —— 会话 key 钉住 + transcript 作历史 + ClearSession
   (2026-10-19:transcript 作历史已移除——网关自己重放会话;ClearSession 现在能
   找到并删掉旧会话的文件)
5. ✅ `/_seal/clear` + SDK `clearConversation` + CLI `/clear`

之后新增:`/_seal/compact` + SDK `compactConversation` + CLI `/compact`,覆盖
dsh 和 openclaw,用真实模型验证过(glm-5.3 经 0G 路由,2026-10-19):dsh —— 一段
约 26.6K token 的历史被总结,下一轮靠摘要正确作答,压缩结果在桥重启后仍然有效;
openclaw 2026.7.1 —— `sessions compact` 用 73 秒把一个 269,717 token 的会话压到
3,559(那时还没设 `keepRecentTokens`,所以那次也丢掉了约 20K token 的尾部——见上面
openclaw 的坑)。离线(桩模型)验证:dsh 桥在已有压缩挂起时拒绝第二个,摘要调用以
16384 发出,报告引擎的真实原因(包括上游 400),摘要不会更小时答"无可压缩";设了
`keepRecentTokens` 后,openclaw 压缩后的下一轮,模型收到的是摘要加六轮中的第 4–6
轮,不设则只有摘要。换模型之后,dsh 的摘要调用发给了新模型(在桥指定摘要模型之前,
同样的步骤会以 500 失败);openclaw 也一样,用的是 render 自己生成的配置,覆盖了
openai 格式内换模型和换到 anthropic 两种情况(不设 `compaction.model` 时:分别是
旧模型,和 "Unknown model");`timeoutSeconds` 设为 600 后,openclaw 完成了一次
摘要调用耗时 200 秒的压缩。dsh 在一次 `/compact` 之后、或重启后马上再按
`/compact`,现在答"无可压缩",不调用模型(以前:每次都多一次摘要调用,把摘要
再压一遍)。

每条存储路径都对照**从已 build 镜像抽出的真 SDK** 验证(prime SessionManager
往返+轮转;dsh 追加→seed→`fromRestore`;hermes/openclaw 的 header 语义读自网关
源码)。距离"真正完成"还欠:T2 真机演练——每个框架对话中杀进程 → 重启 → agent
无客户端重放答出杀前信息;`/clear` → 答不出;容器重建 → 新对话、链上记忆完好
——这需要四个镜像重建。按 #169 评审:演练必须对**同一对话重启两次**(dsh 的 end-seed 洞只在第二次重启
咬人——一次重启证明不了什么),并断言 openclaw 的 `/clear` 删除被收容(投毒的
`sessions.json` sessionFile 在日志中被忽略、sessions 目录之外什么都不碰、清除
照样成功)。
