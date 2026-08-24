# DSH 适配器 —— 组合与能力档位

DSH(DeepSeek Harness,`@deepseek-ai/dsh`)是本仓库里唯一的**组合式**框架:
它没有固定运行时,而是一棵每次启动现组的 Cordis 插件树。这棵树由本适配器
负责组装。**agent 能干什么,是在这里决定的,不是框架决定的。**

适配器契约(roles、Restore/EvolutionFor、FrameworkFacts)见
`../../FRAMEWORK_ADAPTER.md` 和 `dsh.go` 的包注释。本文件讲的是**组合**:
挂了哪些插件、为什么,以及能力档位打算怎么长大。

## 组合写在哪

写在 `bridge/bridge.mjs` 里,以代码形式 `go:embed` 进 sealed 二进制,Start
时 materialize。它**不是** `cordis.yml`、profile、也不是任何 `$DSH_HOME`
patch 层。后果:组合吃 sealed 镜像哈希(被度量、链上进 `validFrameworkHashes`),
agent 改自己家目录也改不了下次启动挂什么。这是 doctrine 第 5 条(agent 不重写
自己的运行时)的结构化形态。

## 当前档位:`minimal`(目前唯一)

单一固定组合 —— 够成为一个能干活的 agent,仅此而已。

**挂了的:**

| 能力 | 插件 |
|---|---|
| 对话 + agent 循环 | spine(`dsh-agent-spine-demo`):session、tools、system-prompt、agent、agent-loop、skills |
| 推理 | `dsh-llm-pi-ai`(0g-compute 路由由适配器解析)、`dsh-credentials-local` |
| shell | `dsh-subprocess-local` + `dsh-bash-local` + `dsh-sandbox-policy: danger-full-access` |
| 文件系统 | `dsh-fs-local` + `dsh-tool-fs` |
| 技能 | `dsh-skill-filesystem`(`skills/` iData role —— agent 自装、上链跟踪) |
| 上下文余量 | `dsh-token-meter` + `dsh-compaction-basic` |
| 循环卫生 | `dsh-tool-call-timeout-policy` |
| **平台控制点** | `seal-tools.mjs`(seal_sign / seal_register_service 作为原生、留 session log 的工具)、`seal-guard.mjs`(拦截碰签名 socket 的 shell 调用) |

**刻意不挂的**(每条都是决策):

- `session-persistence-*` —— append-only 会话日志会让 watcher 每 tick 假漂移,
  且格式钉死 v0、无兼容;改用进程内常驻一个 Agent 对象。
- `settings-file` —— 它的热加载会把 settings.yaml 叠在组合之上,让 agent 改一下
  就能注入任意推理路由。被跟踪的 `settings.yaml` role 由适配器读取、经 env 传入;
  DSH 自己从不读这个文件。
- `tool-cordis` —— 进程内自定义工具,无审计且重启即失。
- `sandbox` 栈 —— privsep(内核 uid 拆分)才是隔离墙;DSH 自带的 `sandbox-local`
  在没有 bwrap/Landlock 的精简 TEE 容器里 fail-closed。
- `web`、`e2b`、`subagent`、persistent `terminal`、`jobs`、`goals`、
  `workspaceContext`、`agent-presets` —— 能力面推迟(见下)。

## 为什么挂 shell(而不是禁)

privsep 让框架子进程以低权 `agent` 用户运行,把它和 sealed 的内存、秘密隔开的
是内核而不是 doctrine。所以 shell 是普通能力,doctrine 第 2 条管的是**作者身份**
(外部起草的命令字节),不是 shell 权限。见 `../../AGENT_DOCTRINE.zh.md`。

## 能力档位(规划中 —— 二期)

目前只有一个档(`minimal`),owner 也没法选别的。打算做成:

- 一份**平台审核过的小菜单** —— 比如 `minimal` / `standard` / `coder` ——
  每档是本适配器 ship 的一个组合,区别只在挂哪些能力插件(如 `coder` 加 e2b
  工具沙盒、subagent、持久 shell)。平台平面(bridge、seal-tools/guard、doctrine
  注入、推理路由)各档相同,永不由 owner 选。
- owner 部署时选档(和现在选 framework + model 一样);档位 id 记进链上
  `framework` binding,买家能看到 agent 跑的是哪个能力档 —— 内容仍由镜像哈希背书。
- 换档 = reset(和换 framework/model 同一通道),绝不运行时热切换:组合是被度量
  边界的一部分。

其他推迟项(记在 DSH PR 上):`~/.dsh/AGENTS.md` 作为 persona role、`memory/`
DirectoryManifest role、e2b 工具沙盒作为 habitat 模型里"tool sandbox"的那一侧。
