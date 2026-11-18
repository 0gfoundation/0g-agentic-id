# 0g-harness 适配器 —— 组合与能力档位

[0g-harness](https://github.com/0gfoundation/0g-harness) 是本仓库里唯一的**组合式**框架,建在 DSH(DeepSeek Harness,`@deepseek-ai/dsh`)之上。别的框架有固定的运行时;它没有,每次启动都现场把一批 Cordis 插件拼成一棵树。所以 **agent 能干什么,由这棵树决定,不由框架决定。**

适配器契约(有哪些 role、Restore/EvolutionFor、FrameworkFacts 怎么填)看 `../../FRAMEWORK_ADAPTER.zh.md` 和 `harness.go` 的包注释。本文只讲**组合**:挂了哪些插件、为什么挂、以后能力怎么扩。

## 框架名

框架名是 `0g-harness`:链上 `framework` binding 里的名字、attestor 的 `ATTESTOR_FRAMEWORKS` 和部署记录里的名字,都是它。旧名是 `dsh`。binding 写着 `dsh` 的 agent 照样用本适配器启动,它的 binding 由 agent 的第一次提交改写成 `0g-harness`(`framework` role 和其他 role 一样受漂移监控,这次提交和其他提交一样花 agentSeal 的 gas)。停着的 agent 下次启动时改写。attestor 启动时把部署记录里的 `dsh` 改名(`attestor/crates/shared/src/schema.sql`)。

## 组合放在哪

放在 0g-harness(`src/composition.mjs`)里,用代码写死。0g-harness 就是本适配器启动的那个进程。

- **构建镜像时定死,按哈希运行。** 0g-harness 镜像在构建时把一个确定版本的 harness(`../../images/harness/Dockerfile` 里的 `HARNESS_REF`),连同它锁定的整棵依赖树,打成一个包:装好的目录树的确定性 tar,以它的 sha256 命名。镜像把包解到 `/opt/0g-harness/<sha256>/`,属主是 root,agent 只读;`/opt/0g-harness/base` 写着它的哈希。所以插件集合,以及里面每一条平台决定,都包含在包哈希里;镜像自带的包同时也包含在镜像哈希里(被度量,并且登记在链上信任合约的镜像名单里)。分层流程下,sealed 运行版本规则选出的包:owner 选的版本(名单里列着时),否则正在跑的,否则最新登记的,都要在信任合约的 harness 名单里(`../../LAYERS.zh.md` §5);否则运行 `base`。其他版本由同一个构建阶段打包,按哈希从 `artifacts` release 下载,所以出新的 harness 版本不需要新镜像;`base` 是容器不下载任何东西时就有的那一版。
- **agent 改不动。** 组合**不是** `cordis.yml`,不是 profile,也不在 `$DSH_HOME` 下的任何 patch 文件里。agent 就算改自己的家目录,也改不动下次启动挂什么。这是 doctrine 第 5 条(agent 不能重写自己的运行时)在结构上的落地。
- **版本对得上。** 构建镜像时还会检查一件事:装上的 0g-harness 版本,必须等于 `whitelist.go` 写进每个 0g-harness agent 的 `framework` role 的版本。这样,role 里写的永远是实际运行的版本。harness 自己锁定它所用的 DSH 包(它的 `npm-shrinkwrap.json`)。

**owner** 可以在一份固定白名单里调四个选项(见下面「owner 可调的」)。它们由 owner 签名的 settings 文档渲染成 `SEAL_HARNESS_*` 环境变量,每次 spawn 时生效。所以镜像哈希钉住的是:组合本身,**加上 owner 能提出的那几种变体**。

白名单之外,谁都调不了。下面这些都写死在被度量的代码里:
- 挂哪些插件;
- sandbox policy 模式;
- 文件系统根目录;
- spine 的 invariant 自检;
- 平台那一层:harness 本身、seal-tools、subagent-guard。

## 进程

`spawn.go` 以 agent 用户身份运行 `node /opt/0g-harness/<sha256>/bin/0g-harness.mjs`(没有包的镜像上是 `node /usr/local/lib/node_modules/@0gfoundation/0g-harness/bin/0g-harness.mjs`),监听本机回环端口 8794,环境变量由 `environ()` 生成。这些环境变量的约定写在 harness 的 `docs/PROTOCOL.md` 里。其中 `SEAL_OWNER` 是启动时从链上读到的 owner(小写),harness 拿它核对每条记忆的 `trusted_by`。

- 只要 sealed 知道 provider 的 endpoint,harness 就通过 sealed 的推理代理(`internal/inferproxy`,一个回环地址)调用模型:注册表里的 managed provider,以及 `openai` 和 `anthropic`(sealed 固定的官方 endpoint)。代理写上 owner 的模型,在 system prompt 末尾附上 agent doc,并设置密钥;harness 手里只有占位符(`../../CONFIG_SURFACE.zh.md` §3、§7)。`webTools` 打开、且 owner 选的搜索服务能付费时，代理还为 `web_search` 提供 `POST /v1/web/search`：只收 `{"query"}` 请求体，发给该服务，不附 agent doc(`inferproxy` `websearch.go`)，并按 0G router 的结果格式回答；harness 从 `SEAL_HARNESS_WEB_SEARCH_URL` 拿到这个地址。
- owner 给子 agent 提供的其他模型(`subagentModels`)是同一个代理上的路由(`modelroutes.go`)：和主模型同 endpoint、同密钥的模型，由主路由多接一个模型；其余的各是 `/p/<id>` 下的一条命名路由，有自己的上游、密钥和模型。每条路由固定自己的模型并附上 agent doc；命名路由拒绝其他模型名。harness 从 `SEAL_HARNESS_MODEL_ROUTES` 拿到它们(不含密钥)。每条路由第一次为某个其他模型转发请求时，日志记一行 `inference route <id>: first request for model <model>`(主路由的 id 记为 `main`)。
- 搜索服务和每个其他模型怎么付费，按同一条规则：和主模型同 provider、没指定凭据时用模型 key；指定了 owner 的凭据时，经凭证代理带上它的占位符，代理只在 owner 允许的 host 和位置上代填；都不满足就不提供，日志里写明原因。模型 key 条目（`model.<provider>`）不能被指定：它没有占位符，指定它的搜索或模型不提供。指定的凭据在请求发出时才检查：owner 没有这个凭据时凭证代理拒绝，`web_search` 返回拒绝的代码和原因，0G router 也一样。
- harness 在 `/v1/*` 上检查它自己的 token(`SEAL_BRIDGE_TOKEN`)。owner 从 `/_seal/auth` 拿到的是另一个 token,sealed 的 proxy 在请求进来时把它换成 harness 的,所以 harness 运行的任何东西都看不到 owner 的 token。

harness 做三件事:
- 只保留一个 agent、一段对话(`owner-chat`);
- 把这段对话和它的轮次记录存在一起(`../../CONVERSATION.zh.md`);
- 把每一轮的输出交给开启这一轮的一方。owner 开启的轮次,交给 owner 的那个请求;agent 自己开启的轮次(后台任务结束、提醒到点),进收件箱。

`FrameworkRoutes()` 在 `/hello` 里公布这些接口,每种能力对应一种 kind:`chat`、`responses`、`inbox`、`events`、`activities`、`tasks`、`task-feed`、`schedules`、`files`、`memory`、`steer`、`sessions`。客户端只在 agent 声明了某种 kind 时,才启用对应的功能。其他框架不声明后十种,对它们没有任何改变。`activities` 是正在运行和运行过的活动列表(轮次、后台命令、子 agent)。`tasks` 是 zgh 式任务:owner 交给 agent 的一件工作,在自己的会话和工作区(默认 `~/tasks/<id>`)里运行,最多同时四件,以 agent 记下的结果收尾(`raise_question`、`request_action`、`report_complete`);状态有 queued、working、idle、needs-input、done、failed、archived。`task-feed` 是任务变化的事件流;声明了这个 kind,客户端也就知道 `/v1/tasks` 指的是这种任务(更早的运行时曾用 kind `tasks` 声明活动列表的旧名)。`steer` 是 owner 给正在运行的那一轮的话:harness 在这一轮下一次调用模型之前读到它;没有 owner 的轮次在运行时,它作为普通轮次排队。`sessions` 是 owner 的其他对话(照 zgh):新开、从另一个会话的记录分叉、或恢复;每次发消息要么是这个会话的下一轮,要么插进它正在跑的一轮;每个会话有自己的事件流。所有会话都是同一个 agent、同一个 owner(人设、skills、记忆、家目录和凭据共用);`owner-chat` 是 `chat` 和 `responses` 背后的默认会话(CONVERSATION.zh.md 不变量 2)。每个路由列出确切的 endpoint,即 harness protocol v1 的那些(`routes_test.go`),sealed 的 proxy 只转发这些:没列的路径返回 404,没列的方法返回 405。

harness 可以请 sealed 重启它(签名 socket 上的 `POST /harness/restart`):sealed 停掉进程,再从它当前要运行的包启动(`../../LAYERS.zh.md` §5.3)。启动时,agent 在上次提交之后改过的人设(`APPEND_SYSTEM.md`)、`skills/`、`memory/` 和 `memory-public/` 会保留,前提是链上仍是这个容器上次提交的内容(`../../LAYERS.zh.md` §3)。

## 当前组合

**挂了这些:**

| 能力 | 插件 |
|---|---|
| 对话 + agent 主循环 | `src/plugins/core.mjs` 中明确组合的 DSH 0.2 核心：session、tools、system-prompt、agent、agent-loop、skills、任务注册表 |
| 推理 | `dsh-llm-pi-ai`(路由由适配器按 owner 的 settings 渲染好传进去)、`dsh-credentials-local` |
| shell | `dsh-subprocess-local` + `dsh-bash-local` + `dsh-sandbox-policy: danger-full-access` |
| 文件读写 | `dsh-fs-local` + `dsh-tool-fs` |
| owner 发的图片和文件 | `dsh-attachment-local`（owner 发的图片规整后存在 agent 家目录的 `~/.dsh-attachments` 下，不进链；同时让 `read_image` 可用）。owner 上传的文件（`POST /v1/files`）放在文件收件箱 `~/inbox`（不是消息收件箱 `/v1/inbox`），不进链；镜像带 `pdftotext`，用来读其中的 PDF。agent 交给 owner 的文件放在 `~/outbox`，不进链；owner 列出、下载并删除（`GET /v1/files`、`GET /v1/files/{outbox|inbox}/{name}`，最多 50 MiB；`DELETE /v1/files/{outbox|inbox}/{name}`），某一轮在那里新增或改动了文件时会告诉 owner（`harness.outbox_files`）。两个目录都不长期保存文件：harness 删除两处超过 30 天的文件，`~/inbox` 超过 1 GiB 时从最旧的删起（`SEAL_HARNESS_FILES_MAX_AGE_DAYS`、`SEAL_HARNESS_INBOX_MAX_BYTES`；sealed 两个都不设置，所以按这些默认值）。给 agent 的 `~/inbox`、`~/outbox` 说明（`platformtext.go`）告诉它这些规则，以及要长期保留的内容属于记忆或 skill |
| 技能 | `dsh-skill-filesystem`(对应 `skills/` 这个 iData role:agent 自己装的,会上链) |
| 长期记忆 | harness 自己的系统提示段(`src/memory.mjs`):说明,以及正文合计不超过 `memoryInlineBytes` 时的每条完整记忆,超过时改为两个 `MEMORY.md` 索引,每个模型步骤都重新读取;记忆文件是两个 iData role(`memory.go`):`memory/`(私有,只在 owner 的会话和任务里用)和 `memory-public/`(公开,只在 owner 明确要求时写入):每条记忆一个 `<name>.md`,直接放在 `$DSH_HOME/memory/` 或 `$DSH_HOME/memory-public/` 里,会上链;每条记忆的 `trusted_by` 写明确认它的 owner,不是当前 owner(`SEAL_OWNER`)确认的只作参考;上链的副本里凭据值换成占位符,格式可识别的秘密换成 `[redacted:<类型>]`(`../../../CREDENTIALS.zh.md`「范围之外」);agent 空闲时不定期整理一次(`src/memory-tidy.mjs`,开关 `memoryTidy`),也可以用 `POST /v1/memory/tidy`(kind `memory`)立刻整理 |
| 上下文余量 | `dsh-token-meter` + `dsh-compaction-basic` |
| 循环兜底 | `dsh-tool-call-timeout-policy` |
| 后台任务(打开 `toolJobs` 时) | `dsh-tool-jobs`:命令可以放到后台跑;agent 空闲时任务结束,会开启新的一轮,这一轮的回复进收件箱 |
| 子 agent(打开 `subagents` 时) | `dsh-subagent` + `dsh-subagent-spawn-in-process` + `dsh-tool-subagent`:一次性的助手,以后台任务的形式运行,最多一层,工具只有 `read` 和 `skill` |
| 持久化 | DSH 单写入者 `dsh-session-persistence-jsonl`；通过官方 session-format catalog 迁移旧 0.1.1 对话 |
| 定时提醒(打开 `schedule` 时) | `dsh-schedule` 与 `dsh-tool-schedule`，使用原生会话持久化和单独的 JSON 定时任务存储 |
| **平台控制点** | 见下面两项 |

两个平台控制点:
- **DSH 原生 `dsh-mcp-client`**：通过私有 stdio-to-Unix 桥连接。工具由 sealed 在 socket 上列出（POST /mcp：签名 socket 上是签名、服务、设置和凭据，取值单独在自己的 socket 上），每次调用都走对应端点，检查、拒绝和记录仍由 sealed 执行。
- **`subagent-guard`**:写文件、执行命令、签名,只有主 agent 能做。

**故意没挂这些**(每条都有原因):

- **`settings-file`**:它会热加载,把 `$DSH_HOME/settings.yaml` 叠在组合之上。挂了它,agent 改一下这个文件,就能给自己塞一条任意的推理路由。我们的做法是:Start 之前,由适配器按 owner 的 settings 文档把模型选择渲染成 `SEAL_MODEL_*` 环境变量,传给 harness(`settings.go`)。不存在 `settings.yaml` 这个文件。
- **`tool-cordis`**:让 agent 在进程内自定义工具。这些工具没法审计,重启还会丢。
- **DSH `sandbox` 那一套**：owner Harness 使用本地执行器，隔离边界由 privsep 的内核 UID 提供；托管程序由 sealed 自己限制（服务 UID、Landlock、seccomp：`sealed/isolation/README.zh.md`），Harness 镜像包含对应启动器。
- **`web`、`e2b`、常驻 `terminal`、`goals`、`agent-presets`、可续聊的子 agent**:这些能力暂不提供,见下面的档位规划。

**owner 可调的**:settings 文档的 `others` 段 → `SEAL_HARNESS_*` 环境变量。什么都不填,就是出厂组合。推送一次配置,下次 spawn 时生效:重启的是进程,不是容器。

| 开关 | 默认 | 作用 |
|---|---|---|
| `toolJobs` | `false` | 命令可以放到后台跑(`run_in_background`),并提供 `job_*` 工具 |
| `subagents` | `false` | 打开 `subagent` 工具:主 agent 派出去在后台跑的只读助手(会同时打开任务工具) |
| `schedule` | `false` | 打开 `schedule_create` / `schedule_list` / `schedule_view` / `schedule_edit`、`schedule_create_task` 和 `schedule_runs`:agent 给自己设的提醒和定时工作,投给设它的会话、一个新会话,或每次到点新建一个任务;任务给自己设的提醒到点时会启动它的一次运行 |
| `maxParallelToolCalls` | `1` | 模型一步里最多同时运行几个工具调用。只对声明了可以并发的工具生效：`read`、`read_image`、`web_search`、`web_fetch`、`subagent`。`bash`、`write`、`edit`、`seal_*` 工具以及任务和提醒工具总是单独运行，等前面的调用结束才开始 |
| `modelImages` | 不设置 | 覆盖 owner 的模型能不能看图（`true`/`false`）。不设置时由服务商的模型列表决定（0G router 上是 `architecture.input_modalities`：glm-5.3 只收文字，glm-5.3-flash 能看图）；列表里没写时按 pi-ai 的模型目录。能看图时 owner 发的图片交给模型；不能时每张图存到 `~/inbox`，并告诉 agent 它看不到 |
| `memoryExtract` | `true` | owner 会话压缩之前，以及某一轮没存记忆、且新消息够多之后，harness 调用一次模型，把这些消息里值得长期保留的内容写进长期记忆（0g-harness `src/memory-extract.mjs`）；设为 `false` 两者都关闭。渲染为 `SEAL_HARNESS_MEMORY_EXTRACT`。 |
| `memoryExtractMinMessages` | `6` | 某一轮没存记忆时，自上次提取以来 owner 和 agent 的新消息至少要有多少条，才读一遍找记忆（1 到 1000）。渲染为 `SEAL_HARNESS_MEMORY_EXTRACT_MIN_MESSAGES`。 |
| `memoryRecall` | `true` | 超过 `memoryInlineBytes` 后，每条 owner 消息之前，harness 调用一次模型挑出最多 5 条有用的记忆，把正文放在消息前面（0g-harness `src/memory-recall.mjs`）；设为 `false` 关闭。渲染为 `SEAL_HARNESS_MEMORY_RECALL`。 |
| `memoryTidy` | `true` | agent 空闲时，harness 不定期为每个记忆角色调用一次模型，整理这个角色里当前 owner 可信的记忆：合并重复的，删掉过时或被推翻的，从不在两个角色之间移动（0g-harness `src/memory-tidy.mjs`；距上次整理 24 小时且记忆有变化时到期，某个索引接近上限时提前）；设为 `false` 关闭自动整理，`POST /v1/memory/tidy` 仍可按需整理一次。渲染为 `SEAL_HARNESS_MEMORY_TIDY`。 |
| `webTools` | `true` | 打开 `web_fetch` 工具（把一个公网 http(s) 页面读成文本；私网和回环地址拒绝，DNS 解析之后也查；经凭证代理出站）和 `web_search`（走 `webSearch` 选的服务）（0g-harness `src/web.mjs`）；设为 `false` 两个都关。渲染为 `SEAL_HARNESS_WEB`。 |
| `webSearch` | `{"service":"0g-router"}` | `{"service", "credential"?, "model"?}`。`service`：`0g-router`（router 的结果列表）、`openai`（一次带 `web_search` 工具的 Responses 调用）或 `anthropic`（一次带 `web_search_20250305` 服务端工具的 Messages 调用），后两者先返回模型写的回答，再返回它引用的来源；`off` 去掉 `web_search`。模型的 provider 就是该服务、且没指定 `credential` 时用模型 key 付费，否则用指定的 owner 凭据，该凭据必须允许该服务的 host 和 key 所在的请求头。`model` 是执行 `openai`/`anthropic` 搜索的模型；默认：主模型在该 provider 上时用主模型。provider 注册表的 `webSearch` 字段写明每个 provider 的 key 能付哪个服务（`0g-agentdna providers`）。 |
| `subagentModels` | 无 | 子 agent 可以指定的其他模型，最多 8 个 `{"provider", "model", "credential"?}`，付费规则同 `webSearch`；主模型始终可用。需要打开 `subagents`。格式不对时整个列表作废。 |
| `subagentDefault` | 主模型 | `{"provider", "model"}`：调用没指定模型时子 agent 用它；必须是主模型或 `subagentModels` 中的一个，否则忽略。 |
| `memoryInlineBytes` | `8192` | 两个记忆角色的正文合计不超过这个字节数时，每条记忆整条放进系统提示，不做回忆；超过时放索引并回忆（256 到 65536）。渲染为 `SEAL_HARNESS_MEMORY_INLINE_BYTES`。 |

这里填错,不会让 agent 起不来。`RenderSettings` 每次 spawn 前都会运行,要是在这里报错,agent 就开不了机,而不是"这次推送被拒"。所以解析不了或超出范围的值,一律退回出厂默认值,在日志里说明,其他开关照常生效(`settings.go`)。

**`workspaceContext` 是拒绝的。**
- **它会做什么**:挂上 spine 的 workspace-context 扩展,把 `~/.dsh/AGENTS.md` 读进每一轮的系统上下文。
- **为什么不行**:这个文件 agent 自己就能改(privsep 把 `$DSH_HOME` 交给了 agent 用户,它有 bash 和 `fs-local`),又不属于任何 role,没人恢复它,没人把它上链,验证方也看不见它。owner 的一个开关,不能开出一条"不上链、agent 可写"的系统提示词通道,这属于平台边界的事。
- **怎样才能放开**:先把 `~/.dsh/AGENTS.md` 做成上链的 role(还没做,见文末)。

平台自己的组合决定不开放给 owner:sandbox policy 模式、spine 的 invariant 自检、文件系统根目录、seal-tools、subagent-guard。这些属于镜像哈希背书的边界。

## 为什么挂 shell(而不是禁掉)

privsep 让框架子进程以低权限的 `agent` 用户运行。把它和 sealed 的内存、密钥隔开的是内核,不是 doctrine。既然内核挡住了,shell 就只是个普通能力。doctrine 第 2 条管的是"这条命令是谁写的"(拦截外部起草的命令),不是"能不能用 shell"。详见 `../../AGENT_DOCTRINE.zh.md`。

## 能力档位(规划中)

后台任务、子 agent、定时提醒,是同一套组合上的 owner 开关。更大的能力变化按档位来:

- **一份平台审核过的档位菜单。** 比如 `minimal` / `coder`。每个档位都是 harness 自带的一套组合,区别只在挂哪些能力插件,比如 `coder` 多挂 e2b 工具沙盒和常驻 shell。平台那一层每个档位都一样,owner 永远动不了:harness 的接口、seal-tools、subagent-guard、doctrine 注入、推理路由。
- **部署时选档。** owner 部署时选一个档位,就像现在选 framework 和 model 一样。选的档位写进链上的 `framework` binding,验证方能看到这个 agent 跑的是哪个能力档。档位的具体内容照样由镜像哈希背书。
- **换档只能 reset。** 换档要走 reset,和换 framework/model 是同一条路,不能在运行时热切换。挂哪些插件是被度量边界的一部分,换档就是换一套插件集合。这和上面四个白名单选项不是一回事:那些选项只是传进一套不变组合的值,所以推送一次配置、重启进程就能生效。

其他还没做的:
- 把 `~/.dsh/AGENTS.md` 做成 persona role;
- 补上 e2b 工具沙盒,它是 habitat 模型里"工具沙盒"那一侧。
