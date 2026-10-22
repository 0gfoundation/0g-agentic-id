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
