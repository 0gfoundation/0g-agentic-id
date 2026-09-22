# 原生 Studio 运行时 API

> English: [STUDIO.md](STUDIO.md)。

Studio 通过 sealed 直接管理 adapter 声明的文本资源,不依赖模型报告。
adapter 实现 `studio.Provider` 和 `StudioLayout()` 后,discovery 声明
`{"prefix":"/_seal/studio/","kind":"studio","auth":"bearer","signed":false}`。

每次管理请求都校验现有 owner bearer,并把实时链上 owner 与启动时 owner
比较。无法读取 owner 时返回 503;转移后返回 409 `ownership_changed`,直到
sandbox 以新 owner 重启。不提供通用 shell 接口或调用者指定的文件系统根目录。

## 原生资源

| Adapter | 原生资源 | 生效方式 |
| --- | --- | --- |
| OpenClaw | `SOUL.md`、自定义 skills、Markdown memory、canvas 文本文件 | `active`:下次 prompt / watcher 刷新 |
| Hermes | `SOUL.md`、memory、非内置 skills | persona/memory 为 `next_session`;固定版本缓存 skill prompt 索引,因此 skills 为 `restart_required` |
| Prime | `APPEND_SYSTEM.md`、Python skill bundles | `next_session`,或空闲 session reload |
| DSH | `APPEND_SYSTEM.md`、目录 skill bundles | persona 下次 prompt 为 `active`;skills 为 `restart_required` |

`active` 不会修改正在执行的 prompt。此 API 不安装 Cordis plugins,也不虚构
未支持的 schedules、subagents 或持久 memory。

`GET /_seal/studio/state` 返回 `schema:"0g.studio.state.v1"`、framework、
resources。每项包含 `kind,format,activation` 和 `{id,revision}` 列表。
下列简写路径均相对于 `/_seal/studio/`。`POST /state/read` 接受 `{kind,id}`,
返回真实 files、revision、activation 和 checkpoint。

`POST /state/mutate` 接受 `operation:"put"|"delete"`、`kind`、`id`、
`if_revision` 和 UUID `idempotency_key`。put 另带 `files:[{path,content}]`;
delete 不带 files。persona 的 id 固定为 `main`,文件名必须使用 adapter 的
实际单文件名。`if_revision:null` 只创建不存在的项;更新或删除必须提供最后
读取的 revision。skills 需要 `SKILL.md`;Prime 还需要 `pyproject.toml`
及 `src/` 下的文件。每项最多 64 个 UTF-8 文件、合计 1 MiB。

路径穿越、符号链接、平台保留标记和凭证/配置路径会被拒绝;不能替换 Hermes
内置 skills。写入保留平台注入内容,返回实际读回结果及 `mutation_id`。
`GET /state/receipts/:mutation_id` 对精确 `EvolutionFor` role 内容哈希返回
`pending`、`confirmed` 或 `superseded`。只有匹配的链上条目才确认 checkpoint;
持久化仍由现有 watcher/upload 交易负责。重试 key 和 receipt 只在进程内存
保留最近 256 项。重建或淘汰后先重新读取状态,不能把本地写入当成链上成功。

## Prime 对话

Prime 声明 bearer `/v1/sessions`,kind 为 `sessions`。POST `{id}` 的 id
是规范小写 UUID;首次创建返回 201,已有项返回 200。GET
`/v1/sessions/:id` 返回 `{id,object:"session",status}`。Chat 和 Responses
接受 `session_id`;指定不存在的 id 返回 404。每个 session 有独立的内存
SDK session manager、本地 Python 目录和队列。task 的 follow/cancel 绑定
原 session。

POST `/v1/sessions/:id/reload` 调用固定 SDK 的 `session.reload()` 并保留
历史。reload 和 DELETE `/v1/sessions/:id` 对繁忙 session 返回 409。
删除等待 disposal;最多 50 个 session,不自动淘汰。未指定 `session_id`
仍使用旧的单例。重启丢失进程内对话;客户端保存内容不等于恢复运行时。

## 已连接账号操作

owner 通过 PUT `/_seal/studio/connections/:grant_id` 安装
`{engine_origin,capability,operation}`。engine 必须是公网 HTTPS;拒绝
私网目标、重定向及不安全 DNS 解析。GET `/_seal/studio/connections`
只返回 `{connections:[{id,operation}]}`;DELETE 移除本地权限。最多 50 项,
capability 只在 sealed 内存,不进入 agent prompt、文件、环境或链状态。

agent 私有 Unix socket 提供 GET `/connections` 和 POST
`/connections/invoke`,参数 `{grant_id,invocation_id,input}`。sealed 使用
Authorization capability 请求 engine 的
`/connections/runtime/agent-grants/:grant_id/invoke`。OAuth token 留在 engine。
DSH 使用 `seal_connections` 和 `seal_connection_call`,保留 shell guard;
其他框架可使用文档中的 Unix socket。

支持 Calendar availability (`timeMin,timeMax`) 和 Notion shared-title
search (`query`)。engine 每次重新检查 owner、账号及撤销状态,invocation id
只准入一次。已经准入的操作可能在撤销后完成。未知结果不得自动换 id 重试。
唯一明确例外是 503 `connection_refresh_in_progress`,同时包含
`retryWithNewInvocationId:true` 和 `Retry-After:1`,证明工具尚未执行。
sandbox 重建后,owner 需要恢复并轮换 capability。

本地测试覆盖文件/restore、bridge 序列化、私有 socket 及授权。真实模型执行、
镜像 measurement、链上传/恢复及真实 OAuth 仍需独立部署验收。
