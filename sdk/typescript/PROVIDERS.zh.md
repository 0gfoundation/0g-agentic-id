# 推理 provider

attestor 通过 `GET /inference/providers` 提供平台注册表，运维通过
`PUT /admin/inference/providers` 发布更新。配置存入 Postgres，API 多实例共享，
重启后保留。发布配置无需 SSH、替换服务器文件、OSS 或重启进程。
公开注册表仅包含路由和模型信息，不包含用户推理 key。

## 首次上线

SDK/CLI、attestor 与所有已配置 sealed 镜像统一升级。按本次版本更新已有的
`ATTESTOR_SANDBOX_SNAPSHOT` / `ATTESTOR_FRAMEWORKS`，开启已有的加密凭据开关：

```bash
ATTESTOR_SECRET_ENV_ENABLED=true
```

先构建并上传全部 sealed 镜像，再统一升级 attestor API、worker、indexer 并启用对应镜像。
已有 agent 用 reset 换到新镜像。worker 会内部注入 `SEAL_BOOT_TICKET`，不用运维手配；
新镜像不接受缺少票据的启动。stop/start 保留票据和已授权 provider 路由，轮换启动代次；
reset 使用新票据并可重新授权 provider。拒绝的 provision 请求不会修改或删除容器。

不新增管理员或镜像能力 ENV。运维写入由 **attestor 对应 Tapp 的当前 owner** 授权，
使用已有的 `ATTESTOR_APP_ID`、`ATTESTOR_TAPP_REGISTRY_ADDR` 调用 `getAppInfo`
实时查询；不使用 attestor 的 TEE 签名身份、agent owner 或 sandbox 管理员名单。
Tapp 未配置、未注册或 RPC 查询失败时，拒绝发布。

`GET /config` 根据本版本与已配置的框架、snapshot 名称自动声明能力。Hermes
声明 managed OpenAI，其余内置 adapter 声明 managed OpenAI 和 Anthropic；
native 接线与凭据版本也自动声明。未配置的显式镜像不在能力名单中。
部署约定是整套运行时同版发布，不混用新旧镜像。

主包和旧名兼容包发布后，旧用户可用 `0g-agenticid update` 升级。旧 key 原子迁移到
`inferenceKeys["0g-compute"]`，保留钱包、其他 provider 的 key、proof tickets 和
secret-env 降级保护记录，见 [升级说明](./MIGRATION.zh.md)。

## 发布 provider

provider 更新属于 attestor 运维操作，通过 HTTP API 或 SDK 在运维脚本、后台中
执行。CLI 只读注册表，不提供 provider 发布命令。

先读取当前版本及配置：

```bash
curl -fsS "$ATTESTOR_URL/inference/providers" > providers.json
# 修改 providers，保留 version 原值。
```

运维脚本通过配置了 attestor Tapp owner 钱包的 SDK 客户端签名并提交修改：

```typescript
import { readFileSync } from 'node:fs';
import { AgentDNA } from '0g-agentdna';

const ag = await AgentDNA.fromAttestor(attestorUrl, { account });
const edited = JSON.parse(readFileSync('providers.json', 'utf8'));
await ag.admin.updateProviders(edited.providers, { baseVersion: edited.version });
```

只上传配置及签名，私钥留在签名钱包中。文件里的原始版本保护读取、编辑到发布期间的
并发修改。发布会替换完整名单，因此要保留现有条目。外部签名器也可以按下文准备并
提交签名 HTTP 请求。

例如，向导出的名单追加一个托管 provider：

```json
{
  "id": "partner",
  "name": "Partner",
  "formats": ["openai"],
  "defaultFormat": "openai",
  "endpoints": {"openai": "https://partner.example/v1"},
  "models": [{
    "id": "model-id",
    "supported_formats": ["openai"],
    "supported_parameters": ["tools"],
    "context_length": 128000,
    "max_completion_tokens": 16000
  }]
}
```

域名为占位符。可用静态列表，或返回 `{ "data": [...] }` 的公开 `modelCatalog`。
仅返回 ID 的目录表示模型能力未知。协议限于已实现的 OpenAI/Anthropic 接线；
其他协议或特殊鉴权仍需改代码发版。endpoint 和目录必须为 HTTPS，不含内嵌凭据、
query 或 fragment。兼容参数仅作用于对应 provider；新增托管服务不继承 compute
的元数据或路由猜测。名单必须保留 `0g-compute`。仅 `openai`、`anthropic` 可标记
native，使用框架自身接线，不设置自定义 endpoint。

## 发布 API

`PUT /admin/inference/providers` 接收：

```json
{"document":"<原始JSON字符串>","signature":"0x<EIP-191签名>"}
```

文档包含 `schema:1`、`chain_id`、`agentic_id_addr`、`tapp_registry_addr`、
`attestor_app_id`、`base_version`、`expires_at`（Unix 秒）和 `providers`。签名消息为
`AgentDNA.ProviderRegistry.v1:<document UTF-8 字节的 sha256，小写hex，不含0x>`。
签名覆盖提交的原始字节，不重新序列化。请求须在未来 300 秒内过期，SDK 使用 180 秒。
这是发布请求的有效期，已接受配置不会因此过期。

服务端校验精确的链/合约/Tapp 范围、实时 Tapp owner 授权、结构和版本后才提交。
EOA 使用 EIP-191 签名，合约钱包 owner 通过
[EIP-1271](https://eips.ethereum.org/EIPS/eip-1271) 验证。成功返回 `{ok:true,version}`。
并发、过期版本或重放更新返回 HTTP 409 及当前 `version`；SDK 返回该失败，
不会自动重试，应重新读取再应用修改。回滚内容也作为
新版本发布，旧版本保留在历史表中。

`GET /inference/providers` 返回 `version`、`providers`；已发布版本还带原始
`document` 和 `signature`。`/config` 已声明注册表能力时，包括 404 在内的读取失败
都会在封装凭据、签名前终止，不回退到内置名单。版本 0 是 `sealed/internal/inference/providers.json`
提供的内置初始名单，SDK 构建时也打包它以兼容旧 attestor、支持离线查询。
已发布配置不编进 SDK 或镜像。API 使用 KMS 派生的密钥，对环境、Tapp、版本、
发布者及完整签名原文生成接受凭据 MAC，数据库修改无法伪造该凭据。
Tapp owner 转让或合约钱包策略变化后，已接受配置仍可读取；新写入始终重新查询
当前 owner，旧 owner 不能继续发布。

受信任 attestor 的 `/config` 仅从已验证的接受凭据生成并提供
`provider_registry_version`、`provider_registry_digest`。SDK 与 sealed 使用它核对
配置指纹、原始文档及范围，再使用注册表。这里沿用合约地址、snapshot 发现的
attestor 信任边界，不额外构成独立信任根。SDK 实例会拒绝低于已见版本、或同版本
内容冲突的注册表。

`/config` 本身不可读时也直接终止，不会当作旧 attestor；首次发现的能力会保留，
后续响应不能撤回已声明的注册表能力。并发刷新仅在版本、摘要及全部环境条件相同时
合并请求，否则分别校验各自的发现结果。

## 使用 provider

在 `0g-agentdna` 交互管理界面中执行：

```text
login partner
settings 42 provider=partner model=model-id
reset 42
```

CLI 在选择 provider 前刷新名单。`login` 保留其他 key，设置以后 deploy/login
的默认 provider。已有 agent 的 reset 从 owner settings 读取 provider，不取全局
默认值；读取失败则停止。`whoami` 仅显示是否登记 key。模型补全按 provider 区分。

跨 provider 修改先保存并提示等待 reset，不把旧凭据推给新服务。同 provider 的
模型、thinking 修改仍可即时应用。凭据与 provider 或路由不匹配时提示 reset。
reset 使用已有的兼容镜像重建容器，会中断当前工作，无需重新构建镜像。
owner 授权创建新容器时，worker 在创建前清零当前未确认配置的尝试计数，
让 reset 在启动失败后用对应 key 重新尝试当前文档；内容、版本及 last-known-good
均保留。自动重启继续使用原有回退规则和凭据校验。
发布 provider 本身不会重启已有 agent。

旧 `AGENTIC_API_KEY` / `API_KEY` 仅属于 compute。按 provider 覆盖环境变量时，
同时设置 `AGENTDNA_API_KEY_PROVIDER`、`AGENTDNA_API_KEY`，无归属的新变量被拒绝。
key 通过遮罩输入或环境变量提供，不进 argv，本地按 `inferenceKeys[provider]`
保存在权限为 0600 的凭据文件内。

## 查询 agent 当前配置

owner 的 `0g-agentdna settings <agent>` / `ag.agent.getSettings(sealId)` 读取的是
attestor 在 Postgres 保存的文档，可能包含等待 reset 的修改。agent 自查当前已采用的
配置，应走容器内部接口：

```bash
curl --unix-socket "$SEAL_SIGN_SOCK" http://localhost/settings
```

结果来自 sealed 已成功渲染的运行状态，包含 `source: "runtime"`、provider、model、
thinking，以及托管路由的 `base_url`、`format`、`registry_version` 和 `route_hash`。
原生 framework 路由不返回 `base_url`。不返回 API key 或任意 framework 配置；不查询
attestor 的最新 settings。启动尚未准备好时返回 503。此接口只在 0600 内部 socket 上
免签可读，公开 HTTP 的 `/_seal/settings` 仍需 owner 签名。

## SDK

```typescript
const ag = await AgentDNA.fromAttestor(attestorUrl, { account });
ag.agent.listProviders();                    // 读缓存；fromAttestor 会加载新注册表
await ag.agent.refreshProviders();           // 取得新的已验证快照
await ag.agent.listModels({ provider: 'partner' });

const { settings, version } = await ag.agent.getSettings(sealId);
await ag.agent.setSettings(sealId, {
  ...(settings ?? {}), provider: 'partner', model: 'model-id',
}, { baseVersion: version });
await ag.agent.reset(sealId, { provider: 'partner', apiKey: partnerKey });

// 仅 attestor Tapp owner 钱包：
const current = await ag.agent.getProviderRegistry();
await ag.admin.updateProviders(updatedProviders, { baseVersion: current.version });
```

owner 为合约钱包时，只读客户端可以准备精确消息，在外部取得 owner 钱包的
EIP-1271 签名，再转发提交，无需持有 owner 私钥：

```typescript
const request = await ag.admin.prepareProviderUpdate(updatedProviders, {
  baseVersion: current.version,
});
// 在请求过期前，取得 owner 钱包对 request.message 的 signature。
await ag.admin.publishSignedProviders({ document: request.document, signature });
```


无参数模型查询仍默认 compute。原生 provider 无目录时允许手动输入模型 ID。
首次部署非 compute agent，或 compute 路由已改动时，不传 `sandbox`，等待 mint，
保存 provider/model 设置，再携带 provider/key/framework 调用 start。CLI 向导在
询问完成后重新读取当前注册表，并执行此流程。只有未改动的内置 compute 路由
支持一步部署，其他一步部署请求会在签名前拒绝。

## 凭据及运行时绑定

动态路由沿用现有 ECIES 加密，明文使用 v3：

```json
{"v":3,"owner":"0x...","provider":"partner","route_hash":"0x...","registry":{"version":1,"digest":"0x..."},"env":{"API_KEY":"..."}}
```

路由 hash 覆盖 provider ID、native/managed 类型、协议集合、默认协议和固定地址，
SDK/Go 使用固定字段顺序编码并共享跨语言测试向量，不包含模型元数据。
v3 需要对应镜像声明支持，不允许回退到明文。`sealApiKey` 同样支持服务端加密，
提交其不透明结果时传相同 provider。

v3 凭据还绑定已接受注册表的 `registry.version` 和 `registry.digest`。sealed 用实时
owner 验证凭据，通过 `GET /inference/providers?version=N` 读取该历史版本，并在
查询模型目录或写框架配置前验证文档摘要和路由 hash。Postgres 保留已接受的历史版本；
stop/start 使用原凭据和原版本，更新地址或从最新名单删除 provider 都不会重定向旧 key。
签名后、首次启动前发生发布，也仍读取已授权版本。owner 通过 reset 携带新 key 绑定新
版本与路由。历史版本缺失、被篡改或不可读取时失败关闭，不改用最新地址。
如果 owner 已把 agent settings 改成另一个 provider，则仍需要 reset；stop/start 不会
为新 provider 提供凭据。
旧明文/v1 key 仅属于 compute；v2 继续兼容内置原生定义。无效密文不回退到另一份
明文 key；注册表获取或接受凭据校验失败不代用 compute。这些约束覆盖平台渲染的路由及
凭据，不是框架所有网络行为的出口限制。

English: [PROVIDERS.md](PROVIDERS.md).
