# zgh 后端

zgh 镜像使用 `zghonly` 标签选择 `harness.NewZGH`，保留 AgenticID 的
`0g-harness` framework 名称及 `dsh` 别名。上链格式、包路径、进程隔离和
证明协议沿用现有机制。集成包版本为 0.3.0，`runtime.json` 记录 zgh commit。
缺少正确元数据的旧 DSH 包会被拒绝，由现有回退机制选择镜像的固定基础包。

## 恢复与存储

- 未演化的 `persona` JSON 种子仍由适配器读取：人设恢复到
  `APPEND_SYSTEM.md`，模型 pin 通过 owner settings 恢复。
- 演化后的 `APPEND_SYSTEM.md` 和 `skills/` 沿用原 role，保留原始明文内容。
  同时存在旧种子时，以恢复的人设为准。扁平 `.md` skill 由 zgh 兼容读取。
- 旧 `settings.yaml` role 仅用于恢复模型设置，不新增为核心数据。
- 旧数据没有记忆 role 时，开始使用空的本地记忆，不从聊天记录推导。

旧容器的本地 DSH 聊天日志不会自动转换为 zgh session；此次迁移覆盖链上身份数据。

仍只允许 `framework`、`APPEND_SYSTEM.md`、`skills/` 进入 iData。zgh 的
session、task、聊天、工作目录和提炼的记忆仅落盘，不自动上链。密钥继续走
sealed 原有通道。引导流程完成恢复、兼容和设置恢复后才启动正常上传。
迁移依据 role 和格式，不依据交易次数或 migrated 标记。`/clear` 删除本地
zgh 运行状态，保留人设和技能。

## Owner 接口与 CLI

新增能力 kind 为 `zgh-sessions-v1`、`zgh-tasks-v1`，保留 zgh 原生 JSON
及 SSE 语义，不占用旧 turn/job tasks 或 Responses 类型。sealed 继续负责
鉴权、bearer 转换、owner 锁和路由；原生 owner 接口遵守框架路由的签名规则。
SDK 只有发现相应 `/hello.routes` 才挂载 nativeSessions/nativeTasks。

- `/sessions`，`/session new|resume|fork|show|prompt|cancel|events`；
- `/tasks`，`/task new|input|answer|start|cancel|archive|events`；
- `/task show|cancel <id>` 明确操作原生 task。同时声明 Responses 时，
  `/result` 和 `/cancel` 保留原有聊天 turn 语义；否则作为原生 task 别名。

`/session prompt <id> <text>` 提交输入并报告接受，events 查询进度，Esc
停止观察。普通聊天仍使用常驻 owner session。CLI 不复制权威任务状态。
OpenClaw、Hermes、Prime 和 DSH 后端保持原命令路径。原生任务运行在 owner
权限下，不承担雇主隔离。

## 临时服务

通用 MCP 服务托管机制保持不变。request 模式每次 MCP POST 使用独立 UID、
沙箱和 tmpfs。zgh 包提供最小 runServiceAgent 和发布 skill，由 owner 决定
人设、工具、模型路由和业务。依赖 DSH 插件的配置需要用 ctx.registerTool
重发；zgh 不接受 Cordis 插件。

雇主通过 X-Seal-Runtime-Input 提供的字节仅转为临时进程的私有 stdin，
不进入 owner 常驻进程或 sealed 凭证库。受信任的任务代码能看到明文，工具
按需使用，框架不会自动写进模型请求。响应结束、取消、超时、停止和转移时
结束进程。此 helper 不提供跨响应存活的异步任务；也不使用原生 worker join。

## 构建与发布

在 zgh 私有仓库的 products/sealed 构建和测试，专用 workflow 生成 Linux
x64 包。下载 runtime.tgz 及 SHA-256，验证后置于被忽略的
sealed/images/zgh/runtime.tgz，从 sealed/ 执行：

```sh
docker build -f images/zgh/Dockerfile --build-arg ZGH_PACKAGE_SHA256=<sha256> -t <image> .
```

公共仓库和 Dockerfile 不包含私有源码下载或 GitHub token。发布仍需既有
镜像、sealed 和 harness 哈希白名单。证明及推理强制注入逻辑不变。通过显式
镜像选择或更新环境的 0g-harness 镜像映射切换；本改动不自动重置运行部署。
