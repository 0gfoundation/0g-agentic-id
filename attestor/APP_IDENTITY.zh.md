# 应用身份迁移

生产 API 和 worker 启动时通过本地 tapp `GetAppSigner(app_id)` 取得共享稳定签名密钥。
固定 KMS material 为 `70726f7669646572`，直接将 secret 作为 secp256k1 标量，兼容旧
sandbox provider 地址。它与节点 signer（`GetAppSecretKey`）、空 material 加密密钥、
每个 agent 的 agentSeal 相互独立。稳定 signer 需要交易与存储 gas。
API/worker 广播交易时使用按 signer 共享的 Postgres advisory transaction lock；存储
上传使用同一锁，并等待此前 pending 交易打包。所有副本必须使用同一数据库。
Indexer 仍只读取链与派生 agentSeal。

生产必须设置 `ATTESTOR_TAPP_SOCKET`、`ATTESTOR_APP_ID`、
`ATTESTOR_SANDBOX_APP_ID`、`ATTESTOR_TAPP_REGISTRY_ADDR`、
`ATTESTOR_SANDBOX_SERVING_ADDR` 及链范围。`ATTESTOR_PUBLIC_URL` 继续作为本 attestor
的 HTTPS 业务 locator。手配 sandbox endpoint/provider 只供 `MOCK_TEE=true` 开发模式；
生产自动发现并且失败时不回退。

本地 `ResolveAppIdentity(chain_id,registry_address,app_id)` 使用 tapp 当前 claim 的
Scan anchors。生产要求经过验证的 prod 镜像、各节点一致的稳定 app signer 与应用
TLS pin。读取 `SandboxServing.services(app_signer)` 后校验 appId、active、registry、
KMS appIdHash 和注册 epoch。连接要求 HTTPS、校验应用 SPKI、拒绝 redirect，且核对
`/api/info` 的 app/provider。缓存过期前 single-flight 刷新并重新验证链上授权；每次请求
使用同一 snapshot 绑定签名中的 provider 和 HTTP 连接。`GET /config` 同样刷新 snapshot，
保持原 SDK 字段名。
每次出站操作的所有重试都使用同一 snapshot，其绝对 lease deadline 同时限制连接建立
和响应 body 读取；到期即取消操作。响应 body 失败不会重发可能已被处理的 create。

仅有 node identity，或已有合法 TLS metadata、尚未获取 `app_signer` 的 current 节点可保留为 standby，
但不贡献服务 TLS pins，也不决定服务 lease；至少一个 current 节点必须具备完整服务身份。
非法 metadata 仍会导致发现失败，所有已声明的非空 app signer 必须一致；runtime 还会
核对其固定的预期 signer。
对于其他验证均通过的旧 schema 节点，只有 Scan 未报告身份错误，且明确清空 typed
identities、commitments 和 app signer 时，才视为 pending。

API 和 worker 只初始化一次 `GetAppSigner`，随后并发验证自身身份和 AgenticID 实例授权，
以及 sandbox 身份、链上授权及 pinned `/api/info`。两边查询均完成后，统一检查两边的
lease 都还剩五秒以上。这一启动流程共用 180 秒预算，
包含首次拿 key；每次就绪查询都受同一 deadline 限制，失败后间隔两秒重试。因此 Scan
缓存尚未观察到新身份，或 operator 还在完成绑定时，不必立即重启进程。静态配置错误
在拿 key 前拒绝；超时则启动失败，不使用过期身份、未授权 key 或手配地址回退。
只有两方身份都就绪后才开放 HTTP、消费任务。显式 mock 模式继续跳过生产身份发现。

## AgenticID 1.2 合约迁移

沿用 beacon/timelock 升级流程。Owner 随后：

1. 查询当前 app 注册实例与稳定 service signer。
2. 调用 `bindTrustedAttestorApp(signer, registry, appId, registeredAt)`。
3. 绑定其他需要保留的生产 attestor；CloneGate 自身也要绑定到它服务的 attestor app 实例，
   因为它会作为调用者执行 `registerWithSeal`。这是业务委托绑定，不声称 gate 是 KMS 公钥。
4. 调用单向开启的 `requireInstanceBoundAttestors()`。
5. 移除废弃的旧地址白名单项。

存储字段追加在原 ERC-7201 namespace。步骤 4 之前保留旧白名单兼容，但生产 API/worker
拒绝在旧模式启动。步骤 4 之后，仅添加地址不会产生权限，必须有有效实例绑定。
所有 trusted-attestor 检查（包括 URI 写入）统一使用这一规则。注销、注册 epoch 改变、
registry 查询失败或 app owner 改变都会让绑定失效；新实例必须由 owner 明确授权，
仅持有被复用的 KMS key 无法继承旧实例权限。

`registeredAt` 沿用 TappRegistry 的时间戳语义，并非唯一 generation。额外绑定 app owner
可阻止不同 owner 同时间戳重注册继承授权；同 owner、同时间戳重注册仍受现有 registry
模型限制，完全解决需要 registry generation 迁移。

## TEE 内 HTTPS 部署

在同一 tapp app 内执行 `docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d`。
配置 `ATTESTOR_PUBLIC_URL=https://<locator>:8443`（或公开 443），确保
`ATTESTOR_TLS_CERT_DIR` 位于 `/run` 且每个 app 使用独立目录。tls-init 为相同 appId 调用
`GetAppTlsCert`，将 key/cert 写入 TEE tmpfs；API/worker 等待 TLS-init 完成后才解析自身
Scan 身份。nginx 在 TEE 内终止 TLS，再代理私有 API。
普通 HTTP 端口仅绑定 loopback。tapp TLS key 改变后重新运行 tls-init 并重建 nginx。
生产应在受测量 compose 中固定 tls-init/nginx image digest。

首次部署时，先注册节点并启动 app，使其能请求并度量 TLS key 和 app signer。通过已验证
evidence 或 Scan 读取公开 app signer，完成上述 AgenticID 绑定及 sandbox KMS service
注册，启动等待即可继续。这些查询认证的是类型化 key acquisition 事件，不要求成功的
`start_app` reconciliation，也不要求 attestor HTTP API 已监听。保留 TLS-init 完成依赖，
不要反过来让 tapp 的 app 启动依赖 API 业务就绪。

创建 sandbox 时，在所有其他环境变量之后强制覆盖 `ATTESTOR_TLS_DESCRIPTOR`、
`ATTESTOR_URL` 和 `ATTESTOR_ALLOW_UNPINNED_DEV`。生产仅传递公开 scope、app 实例、
app signer、TLS pins、过期时间及 claim 中的 Scan URL/SPKI trust anchor，并强制关闭 dev
bypass。Sealed runtime 保留现有 attestor locator，对 `/provision` 与 `/status` 使用 pinned
HTTPS，并独立通过 pinned Scan 刷新身份；appId、chain/registry、注册 epoch、app signer
和 locator 不可改变，不接受 app 自己声明的续租。Scan trust anchor 或 app 实例改变后
需要重建 runtime。不会给 workload 挂载 tapp socket 或开放通用 secret API。显式 mock
模式会设置 `ATTESTOR_ALLOW_UNPINNED_DEV=true` 并删除调用者提供的 descriptor。

Typed 公钥绑定是受测量 tapp 程序按实际派生规则与来源计算的认证声明，不是 ZK proof，
也不证明独占保管；尚未实现的 `evidence.extensions` proof 不会被当作已有能力。
