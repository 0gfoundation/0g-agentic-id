# DSH 适配器 —— 组合与能力档位

DSH(DeepSeek Harness,`@deepseek-ai/dsh`)是本仓库里唯一的**组合式**框架。
别的框架有固定运行时;DSH 没有——它每次启动都现场把一批 Cordis 插件拼成一棵树。
这棵树由本适配器负责拼。所以 **agent 能干什么,是这里说了算,不是框架说了算。**

适配器契约(有哪些 role、Restore/EvolutionFor、FrameworkFacts 怎么填)看
`../../FRAMEWORK_ADAPTER.md` 和 `dsh.go` 的包注释。本文只讲**组合**这件事:
挂了哪些插件、为什么挂、以及能力档位以后怎么扩。

## 组合放在哪

放在 `bridge/bridge.mjs` 里,用代码写死,`go:embed` 编进 sealed 二进制,
Start 时才落到磁盘。它**不是** `cordis.yml`、不是 profile、也不是 `$DSH_HOME`
下的任何 patch 文件。这么做的结果:插件集合和里面每一条平台决定都跟着 sealed
镜像哈希走(被度量、上链进 `validFrameworkHashes`),agent 就算改自己家目录,
也改不动下次启动挂什么。这就是 doctrine 第 5 条(agent 不能重写自己的运行时)
在结构上的落地。

**owner** 可以在一份固定白名单里动两个 spine 选项(见下面「owner 可调的」):
它们由 owner 签名的 settings 文档渲染成 `SEAL_DSH_*` 环境变量,在每次 spawn 时
生效。所以镜像哈希钉住的是组合**加上 owner 能提出的那几种变体**,不是一棵绝对
不动的树。白名单之外谁都调不了:挂哪些插件、sandbox policy 模式、文件系统根
目录、spine 的 invariant 自检、平台那一层(桥、seal-tools、seal-guard),
全在这段被度量的代码里定死。

## 当前档位:`minimal`(目前就这一个)

一个固定组合,配到"够用"为止,不多给。

**挂了这些:**

| 能力 | 插件 |
|---|---|
| 对话 + agent 主循环 | spine(`dsh-agent-spine-demo`):session、tools、system-prompt、agent、agent-loop、skills |
| 推理 | `dsh-llm-pi-ai`(路由由适配器按 owner 的 settings 渲染好传进去)、`dsh-credentials-local` |
| shell | `dsh-subprocess-local` + `dsh-bash-local` + `dsh-sandbox-policy: danger-full-access` |
| 文件读写 | `dsh-fs-local` + `dsh-tool-fs` |
| 技能 | `dsh-skill-filesystem`(对应 `skills/` 这个 iData role —— agent 自己装的、会上链) |
| 上下文余量 | `dsh-token-meter` + `dsh-compaction-basic` |
| 循环兜底 | `dsh-tool-call-timeout-policy` |
| **平台控制点** | `seal-tools.mjs`(把 seal_sign / seal_register_service 做成原生工具,签名会留在 session log 里)、`seal-guard.mjs`(拦住想碰签名 socket 的 shell 调用) |

**故意没挂这些**(每条都有原因):

- `session-persistence-*` —— 会话日志只增不改,watcher 每 30 秒会把它当成漂移;
  而且格式钉死在 v0、不保证兼容。所以改成:进程内常驻一个 Agent 对象,不落盘。
- `settings-file` —— 它会热加载、把 `$DSH_HOME/settings.yaml` 叠在组合之上。挂了
  它,agent 改一下这个文件就能给自己塞一条任意的推理路由。现在的做法是:模型钉
  选(pin)由适配器在 Start 之前按 owner 的 settings 文档渲染成 `SEAL_MODEL_*`
  环境变量传给桥(`settings.go`)。`settings.yaml` 这个文件已经没有了 —— 它原本
  只是本适配器自己存 pin 的上链 role,settings 文档把它替掉了。
- `tool-cordis` —— 让 agent 在进程内自定义工具,没法审计,重启还会丢。
- `sandbox` 那套 —— 真正的隔离墙是 privsep(内核 uid 拆分);DSH 自带的
  `sandbox-local` 在没有 bwrap/Landlock 的精简 TEE 容器里会直接罢工。
- `web`、`e2b`、`subagent`、常驻 `terminal`、`goals`、`agent-presets` ——
  这些能力先不做,见下面档位规划。

**owner 可调的**(settings 文档的 `framework` 段 → `SEAL_DSH_*` 环境变量 →
spine 的选项;默认值就是桥原来写死的那几个,所以什么都不填 = 出厂组合原样)。
推一次配置下次 spawn 生效 —— 重启的是进程,不是容器:

| 开关 | 默认 | 作用 |
|---|---|---|
| `toolJobs` | `false` | spine 的后台 job 工具 |
| `maxParallelToolCalls` | `1` | 一轮里最多并发几个工具调用 |

这里填错不会让 agent 起不来。`RenderSettings` 每次 spawn 前都要跑一遍,所以在
这儿报错等于"agent 开不了机",而不是"这次推送被拒";解析不了或超范围的值一律
退回出厂默认、在日志里说清楚,旁边的开关照常生效(`settings.go`)。

`workspaceContext` 原来在这张表里,现在是**拒绝**的。它会挂上 spine 的
workspace-context 扩展,把 `~/.dsh/AGENTS.md` 读进每一轮的系统上下文 —— 而这个
文件 agent 自己写得动(privsep 把家目录交给 agent 用户,它有 bash 和
`fs-local`),又不属于任何 role:没人恢复它、没人上链、验证方也看不见它。
owner 的一个开关不该能捅开一条"不上链、agent 可写"的系统提示词通道,这是平台
边界的事。要让它回来成为一个选项,先得把 `~/.dsh/AGENTS.md` 做成上链 role(还
欠着,见文末)。

平台自己的组合决定不开放给 owner:sandbox policy 模式、spine 的 invariant
自检、文件系统根目录、seal-tools 和 seal-guard —— 这些属于镜像哈希背书的边界。

## 为什么挂 shell(而不是禁掉)

privsep 让框架子进程以低权 `agent` 用户跑,把它和 sealed 的内存、密钥隔开的是
内核,不是 doctrine。既然内核挡住了,shell 就是个普通能力,没必要禁。doctrine
第 2 条管的是"这条命令是谁写的"(拦外部起草的命令),不是"能不能用 shell"。
详见 `../../AGENT_DOCTRINE.zh.md`。

## 能力档位(还没做,二期规划)

现在只有 `minimal` 一个档,owner 也没得选。想做成这样:

- 一份**平台审核过的档位菜单** —— 比如 `minimal` / `standard` / `coder`。
  每个档都是适配器自带的一套组合,区别只在挂哪些能力插件(比如 `coder` 多挂
  e2b 工具沙盒、subagent、常驻 shell)。平台那一层(桥、seal-tools/guard、
  doctrine 注入、推理路由)每个档都一样,owner 永远动不了。
- owner 部署时选一个档(跟现在选 framework、model 一样);选的档写进链上的
  `framework` binding,买家能看到这个 agent 跑的是哪个能力档 —— 具体内容照样
  由镜像哈希背书。
- 换档要走 reset(跟换 framework/model 同一条路),不能运行时热切 —— 挂哪些插件
  是被度量边界的一部分,换档就是换一套插件集合,不能活着换。这和上面那两个白
  名单里的 spine 选项是两回事:后者只是传进一套不变组合的值,所以推一次配置、
  重启进程就生效。

其他先欠着的(记在 DSH PR 里):把 `~/.dsh/AGENTS.md` 做成 persona role、加一个
`memory/` DirectoryManifest role、把 e2b 工具沙盒补上(它是 habitat 模型里
"tool sandbox"的那一侧)。
