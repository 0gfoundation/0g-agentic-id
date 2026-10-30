# DSH 适配器 —— 组合与能力档位

DSH(DeepSeek Harness,`@deepseek-ai/dsh`)是本仓库里唯一的**组合式**框架。别的框架有固定的运行时;DSH 没有,它每次启动都现场把一批 Cordis 插件拼成一棵树。所以 **agent 能干什么,由这棵树决定,不由框架决定。**

适配器契约(有哪些 role、Restore/EvolutionFor、FrameworkFacts 怎么填)看 `../../FRAMEWORK_ADAPTER.zh.md` 和 `dsh.go` 的包注释。本文只讲**组合**:挂了哪些插件、为什么挂、以后能力怎么扩。

## 组合放在哪

放在 [0g-harness](https://github.com/0gfoundation/0g-harness)(`src/composition.mjs`)里,用代码写死。0g-harness 就是本适配器启动的那个进程。

- **构建镜像时就定死。** dsh 镜像在构建时装一个确定版本的 harness(`../../images/dsh/Dockerfile` 里的 `HARNESS_REF`),连同它锁定的整棵依赖树。所以插件集合,以及里面每一条平台决定,都包含在镜像哈希里:被度量,并且登记在链上的 `validFrameworkHashes` 里。
- **agent 改不动。** 组合**不是** `cordis.yml`,不是 profile,也不在 `$DSH_HOME` 下的任何 patch 文件里。agent 就算改自己的家目录,也改不动下次启动挂什么。这是 doctrine 第 5 条(agent 不能重写自己的运行时)在结构上的落地。
- **版本对得上。** 构建镜像时还会检查一件事:harness 锁定的 DSH 版本,必须等于 `whitelist.go` 写进每个 dsh agent 的 `framework` role 的版本。这样,role 里写的永远是实际运行的版本。

**owner** 可以在一份固定白名单里调四个选项(见下面「owner 可调的」)。它们由 owner 签名的 settings 文档渲染成 `SEAL_DSH_*` 环境变量,每次 spawn 时生效。所以镜像哈希钉住的是:组合本身,**加上 owner 能提出的那几种变体**。

白名单之外,谁都调不了。下面这些都写死在被度量的代码里:
- 挂哪些插件;
- sandbox policy 模式;
- 文件系统根目录;
- spine 的 invariant 自检;
- 平台那一层:harness 本身、seal-tools、seal-guard、subagent-guard。

## 进程

`spawn.go` 以 agent 用户身份运行 `node /usr/local/lib/node_modules/@0gfoundation/0g-harness/bin/0g-harness.mjs`,监听本机回环端口 8794,环境变量由 `environ()` 生成。这些环境变量的约定写在 harness 的 `docs/PROTOCOL.md` 里。

harness 做三件事:
- 只保留一个 agent、一段对话(`owner-chat`);
- 把这段对话和它的轮次记录存在一起(`../../CONVERSATION.zh.md`);
- 把每一轮的输出交给开启这一轮的一方。owner 开启的轮次,交给 owner 的那个请求;agent 自己开启的轮次(后台任务结束、提醒到点),进收件箱。

`FrameworkRoutes()` 在 `/hello` 里公布这些接口,每种能力对应一种 kind:`chat`、`responses`、`inbox`、`events`、`tasks`、`schedules`。客户端只在 agent 声明了某种 kind 时,才启用对应的功能。其他框架不声明后四种,对它们没有任何改变。

## 当前组合

**挂了这些:**

| 能力 | 插件 |
|---|---|
| 对话 + agent 主循环 | spine(`dsh-agent-spine-demo`):session、tools、system-prompt、agent、agent-loop、skills、任务注册表 |
| 推理 | `dsh-llm-pi-ai`(路由由适配器按 owner 的 settings 渲染好传进去)、`dsh-credentials-local` |
| shell | `dsh-subprocess-local` + `dsh-bash-local` + `dsh-sandbox-policy: danger-full-access` |
| 文件读写 | `dsh-fs-local` + `dsh-tool-fs` |
| 技能 | `dsh-skill-filesystem`(对应 `skills/` 这个 iData role:agent 自己装的,会上链) |
| 上下文余量 | `dsh-token-meter` + `dsh-compaction-basic` |
| 循环兜底 | `dsh-tool-call-timeout-policy` |
| 后台任务(打开 `toolJobs` 时) | `dsh-tool-jobs`:命令可以放到后台跑;agent 空闲时任务结束,会开启新的一轮,这一轮的回复进收件箱 |
| 子 agent(打开 `subagents` 时) | `dsh-subagent` + `dsh-subagent-spawn-in-process` + `dsh-tool-subagent`:一次性的助手,以后台任务的形式运行,最多一层,工具只有 `read` 和 `skill` |
| 定时提醒(打开 `schedule` 时) | `dsh-schedule`,加上 harness 自带的最小 `sessionPersistence` 服务(提供 dsh-schedule 需要的落盘确认) |
| **平台控制点** | 见下面三项 |

三个平台控制点:
- **`seal-tools`**:把 `seal_sign`、`seal_sign_transaction`、`seal_sign_typed_data`、`seal_register_service` 做成原生工具,每次签名都会记在 session log 里。三个签名工具和签名 socket 的三个签名端点一一对应。
- **`seal-guard`**:把 shell 对 socket `/sign/` 端点的调用引导到上面的签名工具;`/settings` 和 `/services` 照常开放。
- **`subagent-guard`**:写文件、执行命令、签名,只有主 agent 能做。

**故意没挂这些**(每条都有原因):

- **`session-persistence-*`**:它的日志格式固定在 v0,不保证兼容,也没有可用的具体后端。对话由 harness 自己存盘。重启时按"续上"恢复,不带 `seedLength`,所以待处理的收件箱任务和定时提醒在重启后都还在。harness 只额外提供 dsh-schedule 需要的落盘确认。
- **`settings-file`**:它会热加载,把 `$DSH_HOME/settings.yaml` 叠在组合之上。挂了它,agent 改一下这个文件,就能给自己塞一条任意的推理路由。我们的做法是:Start 之前,由适配器按 owner 的 settings 文档把模型选择渲染成 `SEAL_MODEL_*` 环境变量,传给 harness(`settings.go`)。不存在 `settings.yaml` 这个文件。
- **`tool-cordis`**:让 agent 在进程内自定义工具。这些工具没法审计,重启还会丢。
- **`sandbox` 那一套**:真正的隔离墙是 privsep,也就是内核 uid 隔离。DSH 自带的 `sandbox-local` 依赖 bwrap 或 Landlock,在没有这两者的精简 TEE 容器里会直接拒绝运行。
- **`web`、`e2b`、常驻 `terminal`、`goals`、`agent-presets`、可续聊的子 agent**:这些能力暂不提供,见下面的档位规划。

**owner 可调的**:settings 文档的 `others` 段 → `SEAL_DSH_*` 环境变量。什么都不填,就是出厂组合。推送一次配置,下次 spawn 时生效:重启的是进程,不是容器。

| 开关 | 默认 | 作用 |
|---|---|---|
| `toolJobs` | `false` | 命令可以放到后台跑(`run_in_background`),并提供 `job_*` 工具 |
| `subagents` | `false` | 打开 `subagent` 工具:主 agent 派出去在后台跑的只读助手(会同时打开任务工具) |
| `schedule` | `false` | 打开 `schedule_create` / `schedule_list` / `schedule_delete`:agent 给自己设的提醒 |
| `maxParallelToolCalls` | `1` | 一轮里最多同时运行几个工具调用 |

这里填错,不会让 agent 起不来。`RenderSettings` 每次 spawn 前都会运行,要是在这里报错,agent 就开不了机,而不是"这次推送被拒"。所以解析不了或超出范围的值,一律退回出厂默认值,在日志里说明,其他开关照常生效(`settings.go`)。

**`workspaceContext` 是拒绝的。**
- **它会做什么**:挂上 spine 的 workspace-context 扩展,把 `~/.dsh/AGENTS.md` 读进每一轮的系统上下文。
- **为什么不行**:这个文件 agent 自己就能改(privsep 把 `$DSH_HOME` 交给了 agent 用户,它有 bash 和 `fs-local`),又不属于任何 role,没人恢复它,没人把它上链,验证方也看不见它。owner 的一个开关,不能开出一条"不上链、agent 可写"的系统提示词通道,这属于平台边界的事。
- **怎样才能放开**:先把 `~/.dsh/AGENTS.md` 做成上链的 role(还没做,见文末)。

平台自己的组合决定不开放给 owner:sandbox policy 模式、spine 的 invariant 自检、文件系统根目录、seal-tools、seal-guard、subagent-guard。这些属于镜像哈希背书的边界。

## 为什么挂 shell(而不是禁掉)

privsep 让框架子进程以低权限的 `agent` 用户运行。把它和 sealed 的内存、密钥隔开的是内核,不是 doctrine。既然内核挡住了,shell 就只是个普通能力。doctrine 第 2 条管的是"这条命令是谁写的"(拦截外部起草的命令),不是"能不能用 shell"。详见 `../../AGENT_DOCTRINE.zh.md`。

## 能力档位(规划中)

后台任务、子 agent、定时提醒,是同一套组合上的 owner 开关。更大的能力变化按档位来:

- **一份平台审核过的档位菜单。** 比如 `minimal` / `coder`。每个档位都是 harness 自带的一套组合,区别只在挂哪些能力插件,比如 `coder` 多挂 e2b 工具沙盒和常驻 shell。平台那一层每个档位都一样,owner 永远动不了:harness 的接口、seal-tools/guard、subagent-guard、doctrine 注入、推理路由。
- **部署时选档。** owner 部署时选一个档位,就像现在选 framework 和 model 一样。选的档位写进链上的 `framework` binding,验证方能看到这个 agent 跑的是哪个能力档。档位的具体内容照样由镜像哈希背书。
- **换档只能 reset。** 换档要走 reset,和换 framework/model 是同一条路,不能在运行时热切换。挂哪些插件是被度量边界的一部分,换档就是换一套插件集合。这和上面四个白名单选项不是一回事:那些选项只是传进一套不变组合的值,所以推送一次配置、重启进程就能生效。

其他还没做的:
- 把 `~/.dsh/AGENTS.md` 做成 persona role;
- 加一个 `memory/` DirectoryManifest role;
- 补上 e2b 工具沙盒,它是 habitat 模型里"工具沙盒"那一侧。
