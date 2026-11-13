# 托管 MCP 服务

owner Harness 连接签名 socket 上 sealed 的私有 MCP server，发现
`seal_service_publish`、`seal_service_start`、`seal_service_stop`、
`seal_service_list` 和 `seal_service_logs`。配套的 0g-harness 改动使用 DSH
原生 MCP 客户端，内置 `publish-mcp-service` skill 负责编写和发布工作流。
原有签名和凭证工具仍由 sealed 定义。

## 发布契约

发布 manifest：必填 `id`、`command`、`args`、`files`，可选 `description`、
`env`、`network`、`memory_mb`、`processes`、`request_timeout_seconds`。
`env` 是持久化的非敏感配置。文件包含相对 `path` 和标准 base64
`data`。命令指定可信镜像 PATH 中的解释器，例如 `node`；服务代码只在降权并
进入沙箱后运行。参数通常指定 `/app/server.mjs`。文件是普通只读源码和依赖，
运行时不解压归档、不接收链接。依赖安装由低权限 agent 完成。

服务监听 `$MCP_SOCKET`，即 `/run/service.sock` 的 Unix socket，收到原始公共
请求路径。公共 MCP 地址是 `<sandbox-url>/api/mcp/<id>`，由 `/hello` 公布。
每个 MCP HTTP POST 都在全新的隔离临时进程中处理，包括 `initialize` 和 `tools/list`。
sealed 保持服务入口可用，请求之间没有专属共享服务进程。`start` 开启接收请求；
`stop` 关闭接收并取消现有 worker。停止的服务返回 503。`seal_service_list` 的
`running` 表示允许接收请求，业务是否可用仍须用真实 MCP 调用验证。

`/app` 是不可变发布版本，`/work` 和 `/tmp` 是每次请求私有的 tmpfs。更新前先停止服务。
发布返回规范化 manifest 的 SHA-256 版本，保留最近八个源码版本；重新发布旧 bundle
即可回滚。仅 root 可读的注册表绑定 owner 与 sealed 身份；链上启动流程验证绑定后
才恢复已启用入口。停止状态跨重启保留。中断的 worker、输入和工作目录均不恢复，
失败的 worker 不自动重启。owner 转移时关闭服务管理器、取消全部 worker，
同时沿用代理已有的 owner 锁定规则。

最多 16 个服务，每版最多 512 个文件。bundle 解码后最多 16 MiB，发布 JSON
最多 24 MiB，持久化注册表合计最多 8 MiB。内部 MCP 请求上限为 1 MiB；更大的
bundle 可由 owner 将 `{action:"publish",manifest:...}` 写入本地 JSON 文件，
经同一私有 socket POST `/service-host`。GET `/service-host` 列出服务；POST
的 `start`、`stop`、`logs` 动作接收 `id`。公共 TCP 监听器不增加管理入口。

## 隔离与限制

每个活跃请求分配保留范围 210000–210031 中的独立宿主 UID/GID。可信的
`sealed-service-launcher` 在调用 bubblewrap 前清除附加组并降权。每个 worker 使用
独立的 PID、user、IPC、UTS 命名空间、最小环境、零 capabilities、no-new-privs，
仅挂载镜像运行时和自身 app/work/run。sealed 状态、owner home、管理/签名/reveal
socket、其他 worker 的文件均不挂载。存在时，镜像自带的不可变 Harness 包以只读方式
挂载，并通过 `HARNESS_RUNTIME_ROOT` 指定；不共享常驻 Harness 的可写 diff 或状态。
源码版本仅 root 可写、owner 可读，不得打包凭证；注册表保存在 sealed 私有状态目录。
worker 的 stdout/stderr 直接丢弃，`seal_service_logs` 返回空日志，避免向 owner 暴露
雇主输出。

镜像运行环境须支持非特权 user/mount 命名空间。隔离不可用时启动失败，不降级为
无隔离执行。Harness 镜像携带 bubblewrap、util-linux 和可信启动器。

默认 `network:"none"` 创建私有网络命名空间。`network:"host"` 明确授予容器
网络访问，包括 loopback；它不提供租户网络隔离。服务不继承签名/凭证 socket
或代理凭证。host 网络服务被信任具有该网络权限；进程隔离不隔离共享的 host 网络流量。

限制包括：每进程虚拟地址空间（默认 8192 MiB，范围 128–16384）、每 worker UID
进程数（默认 64，范围 1–256）、256 个文件描述符、单文件 64 MiB。这些是 rlimit，
不是 CPU/内存/磁盘总量配额；总资源边界仍由外层 sandbox 提供。

## 临时任务进程与直接运行时注入

所有托管 MCP 服务均为无状态服务。每个 HTTP POST 创建独立 UID/GID、
PID/挂载沙箱和私有 run 目录。`/work` 与 `/tmp` 使用 tmpfs，共享的仅是不可变源码。
所有服务合计最多同时运行 32 个请求 worker。`request_timeout_seconds` 限制整个
生命周期（默认 300 秒，范围 1–3600）。EOF、客户端取消、超时、停止服务或 owner
转移都会结束进程命名空间，释放挂载和 UID。worker 崩溃不重启；开机在 loader
清除遗留进程后清理上次的 run 目录。

调用者可以通过可选 HTTP 头 `X-Seal-Runtime-Input`，直接向自己的 worker 注入
JSON 字符串映射：使用标准 base64，解码后最多 16 KiB。应通过 HTTPS 发送，并避免
客户端或代理记录此请求头。这是 sealed 扩展，不是 MCP 凭据或 sampling 机制；客户端
需要支持自定义 HTTP 头，普通 MCP JSON-RPC 保持原样。格式错误的输入在接收执行前
拒绝。该头在进入后端 HTTP handler 前移除；解码后的字节只进入选定程序的匿名 stdin
管道，不进入命令行参数或 owner 常驻 Harness。

sealed 只转交输入，不创建雇主凭据条目、reveal 审批、续期、写回或持久化记录。
调用者授权任务程序读取明文；仍需要信任服务代码，因为拿到明文的程序可以将其泄露。
OS 隔离的是不同进程，不是程序与它自己的输入。私有输入不会自动进入模型消息；程序
应把值直接提供给工具执行层，不得返回或记录它们。sealed 的 owner 凭据遮盖器不会
登记或遮盖这种临时输入。现有 ServeProof 覆盖方法、URI 和请求/响应体，不覆盖此私有头。

配套 Harness 提供 `runServiceAgent`、`readRuntimeInput`、`serveServiceMcp` 和
`skills/publish-mcp-service/loop-server.mjs`。owner 在 `agent-config.mjs` 中定义人设、
技能目录、模型 adapter 和明确的工具集合。每次调用创建全新 DSH 会话，默认不挂载
owner 记忆、特权 MCP 连接、shell、定时任务或委派。模型 adapter 与付费方式属于服务
策略，不会隐式要求雇主提供模型 API key。

托管服务拒绝 GET/DELETE 及通过 `Mcp-Session-Id` 恢复会话。小型 loop
server 只声明 tools，在 POST 内返回结果，不提供异步进度存储或客户端 sampling。
不要声明尚未实现的有状态或跨请求协商能力。

## MCP 转发与归属证明

托管入口接受无状态 POST 交换，SSE 立即刷新。现有外部注册的 MCP 后端仍支持
POST/GET/DELETE 转发、MCP 会话/协议头及客户端对服务端请求的响应。这些通用转发
能力不会让每次新建的托管 worker 自动获得有状态会话、sampling 或 elicitation；
附带的任务 server 只声明 tools。

有限 JSON 响应沿用 ServeProof。SSE 初始响应头发出时没有完整响应体可哈希，
因此明确标记 `X-Agent-Proof-Mode: stream-unsigned`，不附带 `X-Agent-Proof`。
上游自带证明头会被移除；签名的 `/hello` 仍提供身份与发现。这里不修改任何
ServeProof 摘要，也不声称未结束的流已有完整交互证明或付款交付保证。

业务工具、模型选择、sampling、进度查询、鉴权和收费由 owner 的服务实现。雇主
凭据直接注入任务进程，不采用 sealed 托管或 owner reveal 审批。sampling 是模型生成，
不代表取得雇主任意凭证的访问权限。

## 验证

在 Linux/root 环境分别以无 agent 用户、有 agent 用户运行 sealed 测试；在支持
命名空间的容器中设置 `SEALED_SERVICE_TESTS=1`。服务测试覆盖发布、身份绑定、
真实 UID/挂载隔离、源码不可写、停止和开机仅恢复接收请求；代理测试覆盖实时
sampling 请求 SSE、会话头、DELETE 和伪造证明头清除。
request 测试覆盖并发 UID、私有 stdin 输入、不进入 argv/env/后端头、不持久化凭据
或日志、全新工作目录，以及取消/超时/停止后的清理。设置 `SEALED_LOOP_TESTS=1`
进一步验证公共 MCP → 真实隔离 Node/DSH loop → 原生工具 → 带归属证明结果；
Linux 测试容器需挂载 `/opt/0g-harness/<hash>` 下的配套包、`base` 指针和镜像 Node。
