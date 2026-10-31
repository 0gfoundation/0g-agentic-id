# 应用身份迁移

生产 API 和 worker 启动时通过本地 tapp `GetAppSigner(app_id)` 取得共享稳定签名密钥。
固定 KMS material 为 `70726f7669646572`，直接将 secret 作为 secp256k1 标量，兼容旧
sandbox provider 地址。它与节点 signer（`GetAppSecretKey`）、每个 agent 的 agentSeal
相互独立。稳定 signer 需要交易与存储 gas。
API/worker 广播交易时使用按 signer 共享的 Postgres advisory transaction lock；存储
上传使用同一锁，并等待此前 pending 交易打包。所有副本必须使用同一数据库。
Indexer 仍只读取链与派生 agentSeal。
Nonce 协调具有明确期限：RPC 连接 5 秒、单请求 30 秒；业务提交总预算为 120 秒，
包含连接池/锁获取和广播。PostgreSQL 等锁和语句期限使用操作剩余总预算，
避免健康上传超过单次 RPC 期限后，使并行 mint 提前失败。存储总预算为 750 秒，
其中等待此前 pending 交易最多 120 秒，SDK 上传及其重试最多 600 秒。
取消会释放事务级锁。提交开始后超时会报告结果未知，不自动重发；重试前应先核对
交易/合约或存储状态。

Mint 收据 RPC 失败会保留 `Submitted` 和原交易 hash。`/retry` 先查询 seal 的链上映射，
尚无映射时继续查询原交易，clone 同样如此；不会重新提交已知的 mint 或 clone。
收据仍不可达或缺少 hash 时保留 `Submitted` 并返回错误；只有已确定回滚或无效的
收据才会将阶段标为失败。
恢复后的 clone 还会继续完成尚未生成的 AgentCard 和 URI，无需先有 sandbox；已有
卡片的 clone 保持原有上线流程。

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
两个 app identity 缓存的每次 snapshot 查询都受 180 秒总预算限制，包含等待其他刷新、local tapp
解析和授权检查；链 RPC 连接超时为 5 秒，单请求超时为 30 秒。超时会释放缓存锁，
不发布替换结果，也不延长此前 identity 的 lease。

每次出站操作的所有重试都使用同一 snapshot，其绝对 lease deadline 同时限制连接建立
和响应 body 读取；到期即取消操作。响应 body 失败不会重发可能已被处理的 create。

仅有 node identity，或已有合法 TLS metadata、尚未获取 `app_signer` 的 current 节点可保留为 standby，
但不贡献服务 TLS pins，也不决定服务 lease；至少一个 current 节点必须具备完整服务身份。
非法 metadata 仍会导致发现失败，所有已声明的非空 app signer 必须一致；runtime 还会
核对其固定的预期 signer。
对于其他验证均通过的旧 schema 节点，只有 Scan 未报告身份错误，且明确清空 typed
identities、commitments 和 app signer 时，才视为 pending。

API 和 worker 只初始化一次 `GetAppSigner`，随后并发验证自身身份和 AgenticID 实例授权，
以及 sandbox 身份、链上授权及 pinned `/api/info`。一边查询失败时，会在同一启动
deadline 内等待另一边查询结束后再重试，避免取消 Scan 已接受的观测请求。
两边查询均完成后，统一检查两边的 lease 都还剩五秒以上。这一启动流程共用 180 秒预算，
包含首次拿 key；每次就绪查询都受同一 deadline 限制，失败后间隔两秒重试。因此 Scan
缓存尚未观察到新身份，或 operator 还在完成绑定时，不必立即重启进程。静态配置错误
在拿 key 前拒绝；超时则启动失败，不使用过期身份、未授权 key 或手配地址回退。
只有两方身份都就绪后才开放 HTTP、消费任务。显式 mock 模式继续跳过生产身份发现。

## AgenticID 1.3 合约迁移

AgenticID 链接无状态的 `AttestorAppBindingLib`；库没有 owner 或独立配置，绑定状态
仍留在 proxy。使用固定的合约工具链部署并链接库和实现，再沿用 beacon/timelock
升级流程。库代码变更同样需要新的链接后实现并走原升级流程，无需迁移状态。
部署和验证约束见 [`contracts/UPGRADING.md`](../contracts/UPGRADING.md)。Owner 随后：

1. 查询当前 app 注册实例与稳定 service signer。
2. 调用 `bindTrustedAttestorApp(signer, registry, appId, registeredAt)`。
3. 绑定其他需要保留的生产 attestor；CloneGate 自身也要绑定到它服务的 attestor app 实例，
   因为它会作为调用者执行 `registerWithSeal`。这是业务委托绑定，不声称 gate 是 KMS 公钥。
4. 调用单向开启的 `requireInstanceBoundAttestors()`。
5. 移除废弃的旧地址白名单项。

AgenticID 1.3.0 保留 1.2.0 的治理与 proof 规则。新字段追加在原 ERC-7201 namespace
已有的 `agentSealBound` mapping 之后，保留它的槽位和终身 seal 地址绑定。
步骤 4 之前保留旧白名单兼容，但生产 API/worker
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

创建 sandbox 时，在 owner 签名的环境变量之后始终覆盖 `ATTESTOR_URL`（HTTPS locator，
去掉末尾 `/`）、`SEAL_BOOT_TICKET` 以及链/indexer 配置；不再把 TLS 信任写进环境变量。
owner 签名的环境变量中如有键不是合法变量名（`[A-Za-z_][A-Za-z0-9_]*`），attestor 拒绝
create：运行时按 `KEY=VALUE` 拼接条目，含 `=` 的键可能给 attestor 设置的变量多加一条。
这些覆盖只作用于 attestor 自己创建的容器；直接在 provider 创建的 sealed sandbox 可以带任意
环境变量，因此 `/provision`（见下文）只接受 attestor 自己 create 出的那个容器的首次启动。
provider 返回任何 sandbox 时都会删除 `SEAL_BOOT_TICKET`，与 `SANDBOX_SEAL_KEY` 相同。
每次 create 前 attestor 都会重新确认 AgenticID 仍信任它自己的 app 实例。在 sealed create
（attestor 发起的每次 create 都是）中，sandbox provider 在写入自己的 `SANDBOX_SEAL_KEY`
与 v3 证书之前，会从调用方环境变量中删除 `ATTESTOR_TLS_DESCRIPTOR`、
`ATTESTOR_ALLOW_UNPINNED_DEV`、`TEE_SIGNER_ADDRESS` 以及所有 `SANDBOX_*` 键，因此 provider
签发证书的容器无法打开 dev bypass。

provider 用与证书相同的 key，把本 attestor app 的 TLS SPKI pin（来自它自己的 attestor
身份解析，每份声明最长 300 秒）签成 EIP-712 `AttestorTLS`，并在 `GET /api/attestor-tls`
提供。attestor 通过 sandbox discovery snapshot 的固定 TLS 连接取得最新声明，在
`GET /attestor-tls?provider=0x…` 原样（逐字节）转发。转发前检查 provider 签名、租期，
以及它自己的 app TLS 公钥（本地 tapp `GetAppCsr` 返回的 SPKI hash）在 pin 中；到期前
60 秒刷新，没有有效声明时返回 503。缓存中的声明直接返回，不询问 sandbox discovery；只有
刷新时才询问 discovery，此时若 discovery 失败，缓存的声明继续返回，直到到期前 15 秒
（sealed 在剩余超过 5 秒时接受）。每份新声明都会打日志，api 启动时取一次并记录结果。sealed 不做 CA 校验地获取声明，只有当签名者是它自己
证书的签名者、chain 与 registry 与证书一致、租期不超过 300 秒，且声明所经连接的 SPKI
在 pin 中时才接受；之后对 `/provision`、`/status`、settings 和 provider registry 的请求
都钉在这些公钥上。不会给 workload 挂载 tapp socket 或开放通用 secret API。

Typed 公钥绑定是受测量 tapp 程序按实际派生规则与来源计算的认证声明，不是 ZK proof，
也不证明独占保管；尚未实现的 `evidence.extensions` proof 不会被当作已有能力。

## Workload 配置与重启恢复（v3）

sandbox provider 在 sealed create 时写入 `SANDBOX_SEAL_ATTESTATION`：version 3 证书，覆盖
chain、TappRegistry、appId、registeredAt、sealId、压缩容器公钥、镜像 hash 与签发时间。
它是 EIP-712 `ImageAttestation`，domain 为 `0G Sandbox ImageAttestation`、version `3`，
chainId 为链 id，`verifyingContract` 为 TappRegistry；provider key 直接签原始 digest，
不加 `personal_sign`。known-answer 向量
`crates/shared/testdata/image-attestation-v3.json` 与 provider、sealed 逐字节共用。

`GET /provision` 返回已启用的启动代次和 `certificate_required`。容器的首次 provision
原样携带证书。除启动授权（票据、启动代次、严格递增的 `boot_started_at`、链上实时
owner、已落库的 sandbox）外，attestor 还要求：恢复出的签名者以及证书的 chain、registry、
appId、registeredAt 等于 sandbox discovery 认证的 provider 实例；签发时间不早于启动票据
签发前 300 秒、不晚于当前时间 + 300 秒；镜像在 `validFrameworkHashes` 中；boot claim
由证书中的公钥签名。证书中的公钥还必须是 provider 为本 attestor 在当前票据下创建的
sandbox 所报告的公钥：provider 返回 sealed sandbox 时附带其证书（私钥已删除），worker
把这把公钥与新 sandbox ID 一起保存。直接在 provider 创建的 sealed sandbox 同样有证书，
甚至可能带着票据，但公钥不同，会以 `401 certificate is not for the sandbox this
attestor created; reset required` 拒绝（create 响应中没有证书时为 `401 the sandbox
provider reported no container key for this sandbox at create; reset required`）。随后在
与启动绑定相同的事务里记录容器公钥、镜像 hash 和 provider 实例（chain、registry、
appId、registeredAt、signer）。

同一容器之后的启动不带证书。必须由已记录的公钥签 boot claim，已记录的 provider 实例
必须仍是当前发现的实例（否则 `403 provider instance no longer trusted; reset required`；
discovery 不可用时 503），已记录的镜像必须仍在白名单中（否则 `401 recorded image_hash
not in validFrameworkHashes; reset required`）。证书对应已记录的公钥时按之后的启动处理，
覆盖首次响应丢失的情况；对应另一把公钥则返回 `403 container key differs from record;
reset required`；没有记录也没有证书返回 `409 certificate_required`。新的启动票据
（create 或 recreate）、reset 与所有权撤销都会清除记录，因此每个新容器都要出示自己的
证书。同一 provider 实例内的节点轮换不影响已记录的容器；registeredAt 或 provider
signer 改变则需要 owner 执行 reset。

每次被接受的 provision 都返回一个加密给容器公钥的全新不透明状态令牌。attestor 只保存
它的 SHA-256，旁边记录实际下发的配置版本和摘要，`/status` 只依据这条记录确认配置。
令牌和记录都不含 attestor MAC。不兼容 v2：provider、attestor 与 sealed 镜像需同时发布，
并重建所有 agent（升级步骤见 [`README.zh.md`](README.zh.md#升级到-agentdna-14)）。只有当前启动票据
为其签发的 sandbox 才能 `start`（resume）；attestor 在该次 create 的 sandbox 落库时记录它，
每次签发新票据时清除。其他 sandbox 一律返回 409，因为它们无法 provision：v3 之前创建的
sandbox（没有启动票据，或票据没有签发时间），以及 reset 的 create 失败后仍留在记录上的
旧 sandbox（它持有的是被该次 reset 取代的票据）。

对已授权启动（票据、代次、更新的尝试、已落库的 sandbox 与链上实时 owner 均已校验）的
401 或 403 会以 `provision rejected` 打日志。在该代次仍是启用代次时，记为
`last_provision_error`，并把容器 stage 置为 `failed`、以此为原因，同时发布
`container_failed`，owner 立即看到原因，而不是五分钟后的 provision timeout。其他拒绝
不写任何东西。
