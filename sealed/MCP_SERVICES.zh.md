# 托管 MCP 服务

owner Harness 连接签名 socket 上 sealed 的私有 MCP server，发现
`seal_service_publish`、`seal_service_start`、`seal_service_stop`、
`seal_service_list` 和 `seal_service_logs`。配套的 0g-harness 改动使用 DSH
原生 MCP 客户端，内置 `publish-mcp-service` skill 负责编写和发布工作流。
原有签名和凭证工具仍由 sealed 定义。

## 发布契约

发布 manifest：必填 `id`、`command`、`args`、`files`，可选 `description`、
`env`、`network`、`memory_mb`、`processes`。文件包含相对 `path` 和标准 base64
`data`。命令指定可信镜像 PATH 中的解释器，例如 `node`；服务代码只在降权并
进入沙箱后运行。参数通常指定 `/app/server.mjs`。文件是普通只读源码和依赖，
运行时不解压归档、不接收链接。依赖安装由低权限 agent 完成。

服务监听 `$MCP_SOCKET`，即 `/run/service.sock` 的 Unix socket，收到原始公共
请求路径。公共 MCP 地址是 `<sandbox-url>/api/mcp/<id>`，由 `/hello` 公布。
停止或启动中的服务返回 503；调用方应查询 `seal_service_list`，等到 `running`
后再验证真实 MCP 请求。就绪表示 socket 可连接，不代表每项业务操作都通过健康检查。

`/app` 是不可变发布版本，`/work` 持久化，`/tmp` 临时。更新前先停止服务。发布
返回规范化 manifest 的 SHA-256 版本，保留最近八个源码版本；重新发布旧 bundle
即可回滚。发布不覆盖工作目录。仅 root 可读的注册表绑定 owner 与 sealed 身份；
链上启动流程验证绑定后才恢复服务。停止状态跨重启保留；崩溃以有界速率重启；
stop 结束进程命名空间并取消待执行重启。owner 转移时关闭服务管理器，同时沿用
代理已有的 owner 锁定规则。

最多 16 个服务，每版最多 512 个文件。bundle 解码后最多 16 MiB，发布 JSON
最多 24 MiB，持久化注册表合计最多 8 MiB。内部 MCP 请求上限为 1 MiB；更大的
bundle 可由 owner 将 `{action:"publish",manifest:...}` 写入本地 JSON 文件，
经同一私有 socket POST `/service-host`。GET `/service-host` 列出服务；POST
的 `start`、`stop`、`logs` 动作接收 `id`。公共 TCP 监听器不增加管理入口。

## 隔离与限制

每个服务分配保留范围 200000–200015 中的独立宿主 UID/GID。可信的
`sealed-service-launcher` 在调用 bubblewrap 前清除附加组并降权。服务使用独立的
PID、user、IPC、UTS 命名空间、最小环境、零 capabilities、no-new-privs，仅挂载
镜像运行时和自身 app/work/run。sealed 状态、owner home、管理/签名/reveal
socket、其他服务工作目录均不挂载。owner 编写的源码版本仅 root 可写，owner
可读；不得打包凭证。work/run 仅对应服务 UID 可访问；日志和注册表保存在 sealed
私有状态目录。

镜像运行环境须支持非特权 user/mount 命名空间。隔离不可用时启动失败，不降级为
无隔离执行。Harness 镜像携带 bubblewrap、util-linux 和可信启动器。

默认 `network:"none"` 创建私有网络命名空间。`network:"host"` 明确授予容器
网络访问，包括 loopback；它不提供租户网络隔离。服务不继承签名/凭证 socket
或代理凭证。host 网络服务被信任具有该网络权限，不能称为按雇主隔离的 worker。

限制包括：每进程虚拟地址空间（默认 8192 MiB，范围 128–16384）、每服务 UID
进程数（默认 64，范围 1–256）、256 个文件描述符、单文件 64 MiB。标准输出和
错误仅保留最近 64 KiB。这些是 rlimit，不是 CPU/内存/磁盘总量配额；总资源边界
仍由外层 sandbox 提供。单个服务可以处理多个雇主，雇主不会自动获得独立进程或
文件系统边界。

## MCP 转发与归属证明

MCP 入口向后端转发 POST、GET、DELETE，保留 MCP 会话/协议头和客户端对服务端
请求的响应。后端可以对可选方法返回 405。SSE 立即刷新并禁用代理缓冲，允许工具
调用未结束时完成 sampling 和 elicitation。

有限 JSON 响应沿用 ServeProof。SSE 初始响应头发出时没有完整响应体可哈希，
因此明确标记 `X-Agent-Proof-Mode: stream-unsigned`，不附带 `X-Agent-Proof`。
上游自带证明头会被移除；签名的 `/hello` 仍提供身份与发现。这里不修改任何
ServeProof 摘要，也不声称未结束的流已有完整交互证明或付款交付保证。

业务工具、模型选择、sampling、进度查询、鉴权和收费由 owner 的服务实现。雇主
临时凭证托管、限定授权和按任务 worker 是后续独立能力。sampling 是模型生成，
不代表取得雇主任意凭证的访问权限。

## 验证

在 Linux/root 环境分别以无 agent 用户、有 agent 用户运行 sealed 测试；在支持
命名空间的容器中设置 `SEALED_SERVICE_TESTS=1`。服务测试覆盖发布、身份绑定、
真实 UID/挂载隔离、源码不可写、崩溃重启、停止和开机恢复；代理测试覆盖实时
sampling 请求 SSE、会话头、DELETE 和伪造证明头清除。
