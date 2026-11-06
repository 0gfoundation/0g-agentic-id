# owner 凭据

[English](CREDENTIALS.md)

owner 把第三方凭据（API key、token、refresh token、签名密钥、MCP 服务器的登录）交给 agent，但不交给模型驱动的框架。值保存在 sealed 里。agent 在需要密钥的地方写占位符 `[[credential:<名字>]]`，sealed 在请求出网时代填，只对 owner 允许的域名和请求位置生效，并把值从返回内容里去掉。值只有在 owner 允许时才离开 sealed（*交出*）。

各方能看到什么：

| 角色 | 能看到 |
|---|---|
| owner（客户端） | 自己设置的全部内容；agent 的申请和使用记录 |
| attestor | 签名的凭据集和定义；值只以加密给 agent 的密文形式出现 |
| sealed | 值，在内存中 |
| 框架 / agent | 名字、域名、位置、占位符；只有交出后才看到值 |

## 条目与签名凭据集

条目的**定义**是 JSON，由客户端序列化一次，按原字节计算 hash（`def_hash = keccak256(bytes)`）：

| 字段 | 含义 |
|---|---|
| `v`、`name` | `1`；占位符里使用的名字（`[a-z0-9][a-z0-9._-]{0,62}`；前缀 `derived:` 和 `sealed:` 归 sealed 自己使用） |
| `hosts` | 允许发往的域名；规范化后精确匹配（小写、去掉末尾的点、省略 `:443`） |
| `positions` | 占位符可以出现的位置：`header`（`name`，`template` 中含一个 `{v}`）、`basic`（固定 `username`，值作为密码）、`query`（`param`）、`path`（完整的一段）、`body`（JSON 或表单的顶层 `field`） |
| `use` | `inject`（代填，默认）、`token_only`（只能用于换 token）、`sign`（由 sealed 用来签名的密钥） |
| `value_hash` | 值的密文的 keccak256；只有登录条目为空 |
| `token_request` | 换 token 模板（见下文） |
| `signer` | `use: sign` 时必填：`sigv4`、`hmac`、`jwt` 或 `wallet`（见下文） |
| `mcp` | 登录条目：`url`，需要时还有 `client_id`、`client_secret_entry`、`scopes`（见下文） |
| `allow_reveal` | agent 无需每次申请即可读取值 |
| `writeback` | 允许 sealed 把自己获得的值（轮换、登录）存下来供下次启动使用 |
| `expires_at`、`description` | Unix 秒：过期后不再代填、代签、交出，也不用于换 token；给 agent 看的自由文本 |

一个条目是一个值，可以用在多个地方：条目的填写位置对它的每个域名都生效。例如一个 GitHub token，条目同时写上两个域名和两种位置，就既能用于 API（`api.github.com`，`Authorization: Bearer`），也能用于 git（`github.com`，Basic）。预设（CLI 里的 `preset=<名字>`；`cred presets` 列出全部预设及各自的密钥创建地址）是快捷方式，由客户端展开成域名、位置和说明；sealed 看不到预设。

**值**（最大 16 KiB，sealed 获得的值也一样）在客户端用 ECIES 加密给 agent 的 agentSeal 公钥。明文绑定了归属：`{"v":1,"type":"credential","owner","seal_id","chain_id","name","value"}`；绑定到其他 owner、agent、链或名字的值，sealed 一律拒绝。

owner 对整个凭据集签一次名，EIP-712：

```
domain   {name: "AgentDNA Credentials", version: "1", chainId, verifyingContract: AgenticID}
CredentialSet(bytes32 sealId,uint64 ownerEpoch,uint64 version,Entry[] entries)
Entry(string name,bytes32 defHash)
```

同一个 digest 在 sealed（`TestDigestVectors`）、attestor 和 SDK 中用同一组向量固定。

- **版本号**：每次写入为 `version + 1`，在 attestor 处做比较并交换。sealed 按（所有权纪元，版本号）记住加载过的最新凭据集（存在状态目录，stop/start 后保留），拒绝更旧的；新 owner 的第一个凭据集比前任 owner 的所有凭据集都新。
- **所有权纪元**：agent 最近一次转让所在的区块号。为更早纪元签名的凭据集在各处都被拒绝，前任 owner 的凭据集无法被恢复。转让时 attestor 删除凭据集，sealed 清空所有条目、待办、授权和使用记录，以及它保管的框架推理 key。sealed 每 10 秒查一次链上 owner；交出、换 token、钱包签名、登录之前，如果距上次确认 owner 已超过 10 秒，会先再查一次（查询失败则拒绝）；新 owner 的凭据集或决定，先清掉前任 owner 的状态再处理。状态被清空时，或 owner 给条目设了新值时，仍在进行的换 token、刷新、登录的结果一概不保留。
- **逐条检查**：定义与签名 hash 不符、值与 `value_hash` 不符、或者代理无法使用的条目会被跳过并给出原因，其余条目照常加载。
- **owner 客户端**：每次修改都会重新签名整个凭据集，所以 SDK 只在存储的凭据集由当前钱包为这个 agent 按存储的版本号签名、每个定义和存储的值都与签名一致、并且不比这个客户端见过的最新凭据集旧（先比所有权纪元，再比版本号；CLI 把它记在配置目录的 `credential-marks.json` 里，所以同一台机器上跨次运行也会拒绝重新送来的旧凭据集）时才使用它；否则什么都不签（`CredentialsUnverifiedError`）。

## agent 如何使用凭据

每个 adapter 都把 `RuntimeContext.CredentialEnv()` 追加到框架的环境变量：

| 变量 | 值 |
|---|---|
| `HTTPS_PROXY`、`https_proxy` | `http://agent:<令牌>@127.0.0.1:<端口>`（令牌每次启动生成，放在密码位置） |
| `NO_PROXY`、`no_proxy` | `localhost,127.0.0.1,::1` |
| `SEAL_CRED_PROXY` | `http://127.0.0.1:<端口>/<令牌>`；不认 `HTTPS_PROXY` 的客户端使用显式形式 `$SEAL_CRED_PROXY/https/<host>/<path>` |
| `NODE_EXTRA_CA_CERTS` | `/etc/seal/credential-ca.pem`（只含代理的根证书） |
| `SSL_CERT_FILE`、`CURL_CA_BUNDLE`、`REQUESTS_CA_BUNDLE`、`GIT_SSL_CAINFO`、`AWS_CA_BUNDLE`、`CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE` | `/etc/seal/credential-ca-bundle.pem`（系统根证书 + 代理的根证书） |
| `SEAL_CRED_SOCKET` | `/run/seal-cred.sock` |
| `SEAL_CRED_REVEAL_SOCKET` | `/run/seal-cred-reveal.sock` |
| `GIT_CONFIG_SYSTEM` | `/etc/seal/credential-gitconfig`：先包含镜像的 `/etc/gitconfig`，再设置 git 的 credential helper，由 `GET /credentials/git` 应答 |

根证书每次启动生成，私钥只在 sealed 内存中。系统证书库不做改动。

**代理。** 对条目中出现的域名发起的 `CONNECT`，代理用该根证书签发的证书终止 TLS（HTTP/1.1 和 HTTP/2）；其他域名原样转发通道。对终止的请求和显式请求，代理：

- 要求每次启动的令牌；要求 CONNECT 目标、TLS SNI（IP 地址没有 SNI）和 `Host` 三者一致；显式形式中含控制字符、空格或格式字符的域名一律拒绝；同时最多服务 512 个连接（之后的连接等待），所有连接合计同时最多处理 128 个请求，其中 32 个留给只代填 `sealed:` 条目的请求，框架的工具也可以发这类请求（超出时返回 503 `busy` 和 `Retry-After: 1`；CONNECT 通道只算作连接）；终止的连接上最多 16 个并发 HTTP/2 流，请求头最大 64 KiB；连接空闲 2 分钟后关闭，CONNECT 通道或 WebSocket 中继双向 10 分钟没有数据时关闭；
- 拒绝连接私网、回环、链路本地、组播、未指定、NAT64 和元数据地址；不跟随重定向；
- 只在允许的域名和位置代填占位符，否则拒绝整个请求；从不往 `Host`、`Content-Length`、`Transfer-Encoding`、`Cookie`、`Proxy-*` 里填写；
- 只在有条目可以填写请求体字段或需要签名的域名上读取请求体。在这些域名上，代理最多缓冲 64 KiB 用于代填，须在 30 秒内到达（否则返回 408 `bad_request`）；更大的请求体边转发边扫描到结尾，遇到占位符就停止上传（之前的部分已经发往上游），并以 413 `body_too_large` 应答。其他域名的请求体原样转发，其中的占位符文字也原样发出，因为那里没有可以填写的地方；
- 请求体里出现占位符（原样出现，或解开百分号编码、JSON 转义后出现）时，只有满足以下条件才代填：只有一个 `Content-Type`，是 JSON 或表单；占位符原样书写，单独作为某个顶层字段的值；其他情况一律拒绝。表单请求体在代填后必须整体是 url 编码（占位符本身可以原样书写：`token=[[credential:x]]`）。JSON 请求体发出时，其中的 `&` 和 `;` 写成 `\u0026` 和 `\u003b`：JSON 内容不变，按表单解析它的服务器找不到字段分隔符。解开百分号编码后是占位符的路径段会被代填；
- 先设置自己添加的请求头再签名，签名覆盖实际发出的请求；只有 `X-Amz-Date` 与当前时间相差 15 分钟以内、且 `host` 在签名头中时，才对 AWS 已签的请求重签；查询参数里有 `X-Amz-Signature`、`X-Amz-Credential` 或 `X-Amz-Algorithm` 的请求拒绝签名（`sign_failed`）；丢弃上游返回的 `X-Seal-Credential-Filled` 和 `X-Seal-Credential-Error`；
- 要求上游不压缩，响应带任何 `Content-Encoding` 时拒绝；从响应头（名字里含值的响应头整个丢弃，不分大小写）和流式响应体中去掉它持有的每个值，以及本次请求里填进去的每个值和它设置的签名、session token：原文、百分号编码（大小写均可）、常见编码器写法的 JSON 转义（HTML 转义，`+` `'` `=` 和反引号的转义，大小写两种 `\u` 十六进制，非 ASCII 转义，`/` 写作 `\/`）、带引号字符串的转义、三种对齐的 base64；短于 6 字节的值、跨 WebSocket 分片的值、换行的 base64 或 hex 不做遮盖。并尽力把它不持有、但格式常见的 token（GitHub、GitLab、Slack、Stripe、`sk-` 开头的密钥、Hugging Face、Google API key、npm、Notion）替换成 `[[redacted]]`。WebSocket 逐帧读取（每帧载荷最多 1 MiB）并原位遮盖，长度不变，控制帧也一样（ping、pong 的整个载荷，close 帧状态码之后的原因）；设置了 RSV 位的帧会结束中继；`101` 响应和其他响应一样遮盖。sealed 自己往外发的内容（注册的服务、上链数据，见下文）只去掉它持有的值。

代理填写过值的请求，其响应带 `X-Seal-Credential-Filled: <条目名>`：回显请求的服务会把占位符显示回来（值在返回途中被遮住），agent 靠这个响应头区分"填了"和"没填"。没有条目的域名走通道，那里什么都不填，也不报错，响应里不会有这个头。

拒绝时返回 HTTP 错误，带 `X-Seal-Credential-Error: <代码>` 和 JSON 正文 `{code, message}`，其中不含值。代码：`unknown_entry`、`expired`（410）、`busy`（503）、`token_only`、`position_not_allowed`、`host_not_allowed`、`forbidden_header`、`body_too_large`、`private_address`、`bad_request`（请求体未按时到达时为 408）、`bad_target`、`target_mismatch`、`proxy_auth`、`not_allowed`、`sign_failed`、`upstream_error`、`internal`。

**凭据 socket**（`$SEAL_CRED_SOCKET`，属于 agent 用户，JSON）：

| 路由 | |
|---|---|
| `GET /credentials` | 条目列表：`name`、`description`、`source`（`owner` 或 `derived`）、`use`、`hosts`、`positions`、`signer`、`expires_at`、`logged_in_at`（登录条目）、`allow_reveal`、`placeholder`；owner 还没完成登录的登录条目带 `status: awaiting_login`，暂时不能用 |
| `GET /credentials/git?host=` | git helper 的应答：该域名下允许 Basic 的条目的 `username=…` 和 `password=[[credential:…]]`；没有则 404 |
| `POST /credentials/token` | `{name, params}`：执行条目的换 token 模板，返回换出的条目 |
| `POST /credentials/sign` | `{name, personal_sign \| typed_data \| transaction}`：用钱包条目签名 |
| `POST /credentials/request` | `{op: "add" \| "login", name, preset?, url?, reason}`：向 owner 申请；202 `{auth_req_id, expires_at}` |
| `DELETE /credentials/{name}` | 删除换出的条目（owner 的条目由 owner 管理） |
| `GET /events?after=&wait=` | 长轮询：`entry_added`、`entry_removed`、`pending_opened`、`pending_decided`、`cleared`、`writeback_failed` |

等待 owner 的申请有上限：同时最多 32 条（超出返回 429 `too_many_requests`），理由最多 512 个字符且只占一行（超出部分截掉；控制字符、格式字符、行分隔符以及普通空格以外的空白字符换成空格），参数最多 4 个、每个最多 512 个字符（`url` 为 2048，且必须是不含 userinfo 的普通 https URL），不能含控制字符、格式字符、行分隔符或普通空格以外的空白字符。这些参数以 agent 的名义展示给 owner；申请的 facts 只包含 sealed 自己知道的事实。sealed 自己发起的申请（需要重新登录）不计入 32 条。

**交出**（`$SEAL_CRED_REVEAL_SOCKET`）：`POST /credentials/reveal {name, reason}`。设置了 `allow_reveal` 时返回 `{value}`。否则返回 403 `authorization_pending` 和 `auth_req_id`；owner 决定后，agent 原样重发请求。403 `access_denied` 表示被拒绝。批准只针对 agent 申请时的那个值：之后换出或轮换得到的 token 需要重新申请。对换出的 token，owner 看到的是它自己的域名、过期时间，以及换取时用的参数。签名密钥（`use: sign`）从不交出（403 `not_allowed`）。登录条目交出的是 access token，不是存储的登录状态。这个 socket 和上面的 socket 分开，是为了让以另一个用户运行工具的 harness 可以不让工具访问它；两个 socket 都属于 agent 用户，现有框架的工具也以这个用户运行。

## 框架的推理 key

框架调用模型用的 key（owner 的 `SEAL_SECRET_ENV`，加密给 agentSeal、provision 之后由 sealed 解开；或旧的明文 `API_KEY`），对**走平台路由的模型（0g-compute）上的 0g-harness**由 sealed 保管：它成为条目 `sealed:inference`，只以 `Authorization: Bearer {v}` 或 `x-api-key: {v}` 填写，只发往路由的域名。0g-harness 拿到的是 `SEAL_MODEL_API_KEY=[[credential:sealed:inference]]`，`SEAL_MODEL_BASE_URL` 是经代理显式形式访问的路由地址，因此它和它运行的任何工具都读不到 key。这个条目不能交出。owner 变更时和其他条目一起清掉，之后框架重启也不会再保管它：0g-harness 在没有 key 的情况下启动，直到新 owner reset 这个 agent。adapter 通过 `RuntimeContext.CredHold` 做到这一点。

其他情况下框架仍然直接拿到 key，它的工具也能读到：使用框架内置 provider（`openai`、`anthropic`）的 0g-harness，openclaw 和 hermes（`OPENAI_API_KEY` / `ANTHROPIC_API_KEY`；hermes 还会写进自己的配置文件），以及 prime（`SEAL_MODEL_API_KEY`）。

## 换 token 与轮换

`token_request` 是 sealed 执行的模板；agent 看不到请求和响应。

| 字段 | |
|---|---|
| `url`、`encoding` | token 地址；`form`（默认）或 `json` |
| `fields` | 字段 → 模板：`{v}` 是本条目的值，`{cred:<名字>}` 是其他条目的值（`jwt` 条目代表一个现签的令牌；其他签名密钥被拒绝） |
| `basic_auth` | `{username_entry, password_entry}` |
| `params` | agent 可以额外传的参数（如 `scope`）：只能是模板没有设置的字段，模板已设置的字段会被拒绝（403 `not_allowed`）。最多 512 个字符，不能含控制字符、格式字符、行分隔符或普通空格以外的空白字符 |
| `take` | 从响应中取出、存成换出条目的字段：`field`、`name`、`hosts`、`positions`、`expires_in_field`（秒数，数字或数字字符串）；未命名时名为 `derived:<条目>.<字段>`。换出的条目不会晚于来源条目的 `expires_at` 过期 |
| `rotate_field` | 如 `refresh_token`：响应中的新值替换条目的值 |

同一条目的换 token 一次只执行一个。失败时返回 `token_request_failed`，只带 OAuth 错误码；执行期间条目发生变化（见*所有权纪元*）时返回 409 `changed`。模板字段只填写一遍：形如 `{cred:<名字>}` 的值原样发送。登录条目不能带模板。

**在 CLI 里设置。** `preset=oauth2-refresh`（值是 refresh token，会轮换并写回）和 `preset=oauth2-client`（值是 client secret）用 `token_url=`、`client_id=`、`api_host=` 生成标准的 OAuth 2.0 模板，可选 `scope=`（设置了就固定；不设置时 agent 可以传）；refresh token 所属的 client 有 secret 时，再加 `client_secret=<条目>`。agent 对该条目执行 `POST /credentials/token`，然后在 `api_host` 上用 `[[credential:derived:<条目>]]` 作为 Bearer token。其他模板用 `token=<json>` 设置。

**写回。** sealed 自己获得的值（轮换得到的 refresh token、登录结果）加密给 agentSeal 后提交给 attestor，并由 agentSeal 对下面的消息签名：

```
CredentialWriteback.v2:<seal_id>:<name>:<binding>:<boot_id>:<keccak256(ciphertext)>
```

（keccak256，不加 EIP-191 前缀；sign socket 签不出这种签名。）binding 表示这个值对应的是什么：有 owner 值的条目为 `value:<value_hash>`，登录条目为 `mcp:<服务器 URL、client_id、client_secret_entry、scopes 的 keccak256>`。只要条目的 binding 不变，写回就一直有效：owner 修改说明、域名、位置、过期时间或 `allow_reveal`，轮换结果和登录都保留；换了新值或换成另一个登录则失效。写回加密时绑定获得它时的 owner，换了 owner 打不开。attestor 只接受来自当前启动的容器、凭据集中带 `writeback: true` 的条目的写回，并在新凭据集里保留它，只要上述条件仍成立；开机时 sealed 对 binding 与定义一致的写回，优先于 owner 的值使用。写回失败会在后台重试；重试成功前容器重启，该值丢失。

## 签名密钥

`use: sign` 的条目从不写进请求。

| `signer.method` | 参数 | 用法 |
|---|---|---|
| `sigv4` | `access_key_id`、`region`、`service`、`session_token_entry?` | 请求带 `X-Seal-Sign: <名字>` 时由代理签名；AWS 工具用这个 `access_key_id` 和占位符作为 secret 签过的请求，代理用真值重签（只对条目的域名）。用 aws-sdk-go 签名器的输出做了对照。 |
| `hmac` | `message`（可用 `{method}` `{path}` `{query}` `{body}` `{timestamp}` `{header:<名字>}`）、`header` 或 `param`、`algorithm`（`sha256`、`sha512`、`sha1`）、`encoding`（`hex`、`base64`）、`prefix`、`timestamp_header` | 请求带 `X-Seal-Sign: <名字>` 时由代理签名。 |
| `jwt` | `alg`（`RS256`、`ES256`、`HS256`）、`kid`、`claims`、`ttl`（≤ 86400） | 占位符代表用密钥现签的令牌，可用于请求和换 token 模板（如服务账号的 `jwt-bearer` assertion）。填进请求的现签令牌和值一样会被遮盖，并在过期前一直从上链数据和响应中去掉（最近 256 个）。 |
| `wallet` | — | `POST /credentials/sign`，形状与 sign socket 相同（personal message、EIP-712、交易）；只返回签名。使用记录写明签了什么：交易的链、接收方、金额和函数选择器；typed data 的主类型、domain 名称、链和合约；消息的长度。持有 owner 自己私钥的钱包条目会被跳过：否则 agent 可以以 owner 的身份签名。 |

## MCP 登录

登录条目有 `mcp.url`，没有 owner 提供的值。

1. owner 发起登录：`POST /_seal/credentials/login {name}`（owner 签名）。
2. sealed 读取 MCP 服务器的受保护资源元数据（RFC 9728，来自 401 的 `WWW-Authenticate` 或 well-known 路径），再读取授权服务器元数据（RFC 8414 或 OpenID）。条目没有给 `client_id` 时，sealed 以 public client 身份动态注册（RFC 7591），然后返回授权链接，链接带 PKCE（S256）、`resource` 和一次性的 `state`。
3. owner 打开链接并同意。浏览器回到 agent 的 `<公开地址>/_seal/oauth/callback`；`state`（10 分钟内有效，只能用一次）把 code 绑定到这次登录。sealed 用只有它持有的 verifier 换取 token。
4. 之后条目在 owner 允许的位置提供 access token（该服务器域名上的 Bearer）。在此之前，`GET /credentials` 列出该条目时带 `status: awaiting_login`；从这时起改为带 `logged_in_at`，agent 的事件里出现 `entry_added`，针对它的 `login` 待办也随之结案。sealed 在过期前一分钟刷新（有效期不到两分钟时在一半处刷新，最早 10 秒后），保存轮换后的 refresh token，并写回登录状态。refresh token 被拒绝时（包括以状态码 200 返回的拒绝），或刷新一直失败时，转为一条给 owner 的 `login` 待办。
5. 断开时，owner 调用 `POST /_seal/credentials/disconnect {name}`：如果授权服务器的元数据给出了 `revocation_endpoint`，sealed 先请它作废 refresh token，再作废 access token（RFC 7009）；无论是否作废成功，sealed 都会丢掉这些 token，条目回到等待登录的状态。如果这期间条目变了（新的凭据集或新的登录），sealed 什么都不丢，返回 409 `changed`，并说明服务器是否作废了之前持有的 token。之后由客户端删除该条目。CLI 里对应的命令是 `cred <agent> connect` 和 `disconnect`。

agent 在 MCP 配置中给该服务器加请求头 `Authorization: Bearer [[credential:<名字>]]`。

登录条目在凭据集加载时就按登录后的使用方式检查，代理无法使用时跳过。

- **发现。** 元数据只通过 https 读取。受保护资源元数据里的 `resource` 必须指向这个服务器（同一 origin；路径为服务器本身的路径，或按完整路径段计的前缀，RFC 9728 §3.3）；授权服务器元数据中的 `issuer` 与预期不同时不使用（RFC 8414 §3.3）。只有作废地址与 token 地址在同一域名时才使用作废。
- **client secret。** `client_secret_entry` 在每次使用时（换 code、每次刷新、作废）重新读取，不随登录状态保存：它必须已加载、未过期且不是签名密钥；该条目列了域名时，token 地址的域名必须在其中。不再满足时停止刷新，并给 owner 一条 `login` 待办。
- **回跳。** 先检查 `state`。授权服务器的回跳带了 issuer（`iss`，RFC 9207）时，必须是 owner 被引导去的那个服务器；服务器元数据声明总会带上时，必须带；否则不换取 code。
- **顺序。** 同一条目正在刷新时，登录等刷新结束后才完成，所以较新的登录生效。断开只使用登录时保存的作废地址，即使 owner 的客户端中途放弃也会请服务器作废完，并把断开写回，容器重启后登录不会恢复。
- **scope。** 条目没有 `scopes` 时，sealed 申请服务器元数据列出的 scope；owner 在授权页面上能看到。

## owner 一侧

agent 上的 owner 路由（`/_seal/*`，经 `:8080`）使用 `X-Auth-Message` / `X-Auth-Signature`（链上现任 owner 的 EIP-191 签名），格式为 `<tag>:0x<sealId>:<unix 秒>[:<sha256(body)>]:<audience>`。签名的 `POST` 只接受一次：在有效时间窗内再次发送同一条消息返回 409。每个请求都把签名者记为 owner，所以新 owner 的第一个请求（包括读取）会先清掉前任 owner 的状态，再返回任何内容；owner 查询被更晚开始的查询超越、且结果是另一个人时，请求返回 503。

| 路由 | Tag | |
|---|---|---|
| `GET` / `POST /_seal/credentials` | `0GSealCredentials` | 列出已加载条目 / 加载签名凭据集（更旧的版本返回 409 `stale_version`） |
| `GET /_seal/credentials/pending` | `0GSealCredPending` | 待办：sealed 记录的 `facts` 与 agent 给出的 `reason` 分开展示 |
| `POST /_seal/credentials/decide` | `0GSealCredDecide` | `{auth_req_id, decision: "once" \| "deny", approval?, signature?}` |
| `GET /_seal/credentials/audit?after=` | `0GSealCredAudit` | agent 做了什么（代填、换 token、签名、交出、登录、写回），以及凭据集里哪些条目被跳过、原因是什么，不含值。按时间从旧到新，分三份各保留最近 1000 条：代理使用；钱包签名；其余记录（owner 的决定、登录、断开、加载、sealed 自己做的事），所以 agent 能引发的记录不会把 owner 的记录挤掉。从某份里挤出的记录按类（操作、条目、域名、结果）计数，不会不留痕迹地丢掉。agent 可以随意重复的操作（换 token、刷新、写回、失败的签名、预先允许的交出）以及 sealed 自己提供的值（`sealed:` 条目，如框架的推理 key）的成功使用，每类合并为一条记录，带 `count`、`first` 和最近一次的 `ts`；每种操作的每种结果（冒号之前的部分）各有 32 类的额度，再多的只按结果合并计数，所以对一种结果的大量请求只会让这种结果之后的记录变模糊；总数超过 1024 类后，所有操作的新类别都只按结果合并计数。域名和条目名截到有限长度，控制字符和格式字符显示为 `?`，标准 HTTP 方法以外的方法记为 `OTHER`。stop/start 后保留，并记下属于哪个 owner，只为同一个 owner 恢复；启动时读不了的已保存记录原样保留，不会被覆盖 |
| `POST /_seal/credentials/login` | `0GSealCredLogin` | 发起 MCP 登录；返回 `{authorize_url}` |
| `POST /_seal/credentials/disconnect` | `0GSealCredDisconnect` | 结束 MCP 登录：服务器支持时请它作废 token，并丢掉 token；返回 `{revoked, note}`，期间条目变了时返回 409 `{code: "changed", revoked}` |
| `GET /_seal/oauth/callback` | 无 | 登录后浏览器的回跳 |

**授权。** "只允许这一次"是链上现任 owner 签的 EIP-712 `Approval(bytes32 sealId,bytes32 bootId,bytes32 authReqId,bytes32 requestDigest,uint64 expiresAt)`（同一个 domain），绑定本次启动、这条申请及其摘要，只能使用一次（SDK 给 1 小时，不超过申请本身的过期时间）。sealed 只对仍在等待的申请接受决定，所以用过之后再次提交的批准会被拒绝。待办保留 72 小时，容器重启后丢失，agent 重新申请即可。新增凭据和登录的申请，通过实际去新增、去登录来应答。不表态即视为不允许。

**attestor 路由**（owner 消息为 EIP-191；见 `attestor/README.zh.md`）：

| 路由 | 消息 | |
|---|---|---|
| `GET` / `POST /credentials` | `AgenticID.Credentials.v1:0x<seal>:<ts>:<base version>[:<sha256(body)>]` | 读取 / 比较并交换写入；写入时保留仍在凭据集中、带 `writeback: true` 的条目的写回 |
| `POST /credentials/writeback` | agentSeal 签名（见上文） | 只接受当前启动的容器 |
| `GET /credentials/pending` | `AgenticID.CredentialsPending.v1:<owner>:<ts>` | 签名者名下所有 agent 的待办数量 |
| `GET` / `POST /credentials/notify` | `AgenticID.CredentialsNotify.v1:<owner>:<ts>[:<sha256(body)>]` | owner 的通知地址 |

`/provision` 在每次启动时交给容器 `{document, owner_epoch}` 及其写回，用 ECIES 加密给容器。状态上报（`StatusReport.v3`）带待办数量；数量上升时，attestor 给 owner 的地址发邮件（每个 agent 在 `ATTESTOR_NOTIFY_COOLDOWN_SECONDS` 内最多一封），只写明是哪个 agent、有几条，不包含 agent 写的内容。每小时检查一次，在条目 `expires_at` 前一周提醒 owner。

SDK 为 `ag.credentials`（`sdk/typescript/src/Credentials.ts`）；CLI 为 `0g-agentdna cred`（`docs/cli-reference.md`）。

## 范围之外

- **响应与上链数据。** 经 `:8080` 转发的 HTTP 响应（已注册的服务、框架路由、事件流、合成的 `/v1/responses` 及其保存的结果、`/hello` 的服务列表）在计算 serve-proof 之前去掉 sealed 持有的每个值（名字里含值的响应头整个丢弃，不分大小写）；对升级请求返回的非 `101` 响应和其他响应一样处理（trailer 也一样），接受了的 WebSocket 升级原样转发。框架对压缩上下文（`/_seal/compact`）的说明，在 owner 或公开日志看到之前也会去掉这些值。模型分段流式输出的值，在保存的结果中会被去掉，在流式输出的各段中不会。sealed 上链的内容同样去掉这些值（leaf 角色、manifest 中的文件、目录归档里的文件），漂移判断也基于去掉值之后的内容。从 sealed 删除的值（新凭据集不再包含、owner 变更）仍会被去掉，但不再代填，直到 sealed 重启（owner 条目和 sealed 条目的最近 1024 个值，另外换出条目的最近 1024 个值；每个名字最多 32 个）。
- **不经过代理的工具。** 不认 `HTTPS_PROXY` 或钉死证书的工具会带着占位符直连目标并失败；可以改用显式形式，或使用交出的值。
- **普通 API 返回的 token。** 普通 API 调用（不是换 token）返回的 token 原样到达 agent；如果它属于代理遮盖的常见格式，agent 拿到的是 `[[redacted]]`，无法使用，要拿这类 token 需用换 token。
- **不限制用途。** 在密钥本身的权限范围内，agent 可以做任何事，包括派生新密钥、用签名条目签任意内容。
- **reset 之后的回滚。** sealed 在 stop/start 后拒绝更低的凭据集版本，但 reset 或新建 sandbox 之后，依赖 attestor 提供最新的凭据集。删除密钥时，也要在服务商那边吊销。
- **其他通道。** 非 HTTP 协议和浏览器登录态需要交出值；响应遮盖是尽力而为。
- **转让后前任 owner 的容器。** 转让后几秒内 sealed 就清空所有凭据，但容器会一直运行到 attestor 将其拆除，在此之前新 owner 可以访问它的框架路由。前任 owner 交给 agent 的值，这时可能仍在 agent 的内存或文件里。
- **框架自己的流量。** 框架的环境变量里也有 `HTTPS_PROXY`。没有条目的域名原样转发通道，但代理拒绝连接私网地址，所以 HTTP 客户端遵循 `HTTPS_PROXY` 的框架，连不上私网地址上的模型（或其他服务）。
