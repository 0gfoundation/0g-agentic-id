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
下的任何 patch 文件。这么做的结果:组合跟着 sealed 镜像哈希走(被度量、上链进
`validFrameworkHashes`),agent 就算改自己家目录,也改不动下次启动挂什么。
这就是 doctrine 第 5 条(agent 不能重写自己的运行时)在结构上的落地。

## 当前档位:`minimal`(目前就这一个)

一个固定组合,配到"够用"为止,不多给。

**挂了这些:**

| 能力 | 插件 |
|---|---|
| 对话 + agent 主循环 | spine(`dsh-agent-spine-demo`):session、tools、system-prompt、agent、agent-loop、skills |
| 推理 | `dsh-llm-pi-ai`(0g-compute 路由由适配器算好传进去)、`dsh-credentials-local` |
| shell | `dsh-subprocess-local` + `dsh-bash-local` + `dsh-sandbox-policy: danger-full-access` |
| 文件读写 | `dsh-fs-local` + `dsh-tool-fs` |
| 技能 | `dsh-skill-filesystem`(对应 `skills/` 这个 iData role —— agent 自己装的、会上链) |
| 上下文余量 | `dsh-token-meter` + `dsh-compaction-basic` |
| 循环兜底 | `dsh-tool-call-timeout-policy` |
| **平台控制点** | `seal-tools.mjs`(把 seal_sign / seal_register_service 做成原生工具,签名会留在 session log 里)、`seal-guard.mjs`(拦住想碰签名 socket 的 shell 调用) |

**故意没挂这些**(每条都有原因):

- `session-persistence-*` —— 会话日志只增不改,watcher 每 30 秒会把它当成漂移;
  而且格式钉死在 v0、不保证兼容。所以改成:进程内常驻一个 Agent 对象,不落盘。
- `settings-file` —— 它会热加载、把 settings.yaml 叠在组合之上。挂了它,agent
  改一下这个文件就能给自己塞一条任意的推理路由。我们的做法是:`settings.yaml`
  这个 role 由适配器读、再用环境变量传给桥,DSH 本身根本不读这个文件。
- `tool-cordis` —— 让 agent 在进程内自定义工具,没法审计,重启还会丢。
- `sandbox` 那套 —— 真正的隔离墙是 privsep(内核 uid 拆分);DSH 自带的
  `sandbox-local` 在没有 bwrap/Landlock 的精简 TEE 容器里会直接罢工。
- `web`、`e2b`、`subagent`、常驻 `terminal`、`jobs`、`goals`、
  `workspaceContext`、`agent-presets` —— 这些能力先不做,见下面档位规划。

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
- 换档要走 reset(跟换 framework/model 同一条路),不能运行时热切 —— 组合是
  被度量边界的一部分,不能活着换。

其他先欠着的(记在 DSH PR 里):把 `~/.dsh/AGENTS.md` 做成 persona role、加一个
`memory/` DirectoryManifest role、把 e2b 工具沙盒补上(它是 habitat 模型里
"tool sandbox"的那一侧)。
