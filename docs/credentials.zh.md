# 凭据管理：实现说明

[English](credentials.md)

本文用通俗的话说明 AgentDNA 怎样让 agent 使用 owner 的第三方密钥。字段、接口和格式以 [`sealed/CREDENTIALS.zh.md`](../sealed/CREDENTIALS.zh.md) 为准，命令以 [`docs/cli-reference.md`](cli-reference.md) 为准。

## 解决什么问题

agent 办事要用 owner 的密钥：GitHub token、各家 API key、MCP 服务器的登录、AWS 或钱包的签名私钥。可是驱动 agent 的是模型，模型可能被网页或文件里的指令带偏，也会判断失误，所以不能把密钥直接交给它。

目标有三条：

1. agent 不看到密钥，也能用它办事；
2. 用密钥换来的新 token、登录得到的 token，同样留在保管处；
3. 密钥离开保管处，必须经过 owner 同意。

## 各方各管什么

```
 owner 的 CLI ──签名的凭据集──▶ attestor ──每次启动时下发──▶ sealed（agent 容器里的保管处）
                                                              ▲            │ 代填 / 代签 / 换 token
 agent（模型驱动的框架）── 在请求里写 [[credential:github]] ────┘            ▼
                                                                        外部服务（GitHub 等）
```

| 角色 | 做什么 | 能看到什么 |
|---|---|---|
| owner（CLI 或 SDK） | 设置条目，批准或拒绝 agent 的请求 | 自己设的一切、agent 的请求、使用记录 |
| attestor（平台服务器） | 保存 owner 签名的凭据集，每次 agent 启动时交给容器 | 凭据集和条目定义；值只有加密后的密文 |
| sealed（容器里的可信进程） | 保管值，按 owner 定的规则使用 | 值，只在内存里 |
| agent（模型和它调用的工具） | 在请求里写占位符，向 owner 提出请求 | 名字、允许的域名和位置；值只有在交出时才看得到 |

## 一个条目包含什么

| 项 | 说明 |
|---|---|
| 名字 | 占位符里用的名字，如 `[[credential:github]]` |
| 值 | 密钥本身，只在 sealed 里 |
| 允许的域名 | 只发往这些主机，可以写多个 |
| 允许的位置 | 默认是请求头（如 `Authorization: Bearer {v}`）和 Basic 认证；查询参数、路径中的一段、请求体字段需要 owner 显式打开 |
| 用途 | 代填（默认）；只用于换 token；或签名密钥 |
| 可选 | 换 token 模板、签名方式、MCP 服务器地址、到期时间、是否允许直接交出 |

一个条目可以用在多处。例如一个 GitHub token 同时用于 API（`api.github.com`，Bearer）和 git（`github.com`，Basic）。

CLI 内置 12 个预设：GitHub、GitLab、Hugging Face、Slack、Stripe、Gemini、OpenAI、Anthropic、OpenRouter、DeepSeek、npm、Notion。预设会填好域名和位置，并说明去哪里创建密钥、怎样把权限收窄。

## agent 怎么用密钥

四种方式。前三种，值都不离开 sealed。

| 方式 | 怎么做 | 需要 owner 同意吗 |
|---|---|---|
| 代填 | agent 在请求里写占位符。请求经过 sealed 的出网代理，sealed 核对目标域名和位置后填入真值再发出；响应里出现的值会被换回占位符。git over HTTPS 不用额外设置 | 不需要 |
| 换 token | agent 请求"用条目 X 换一次"，sealed 按 owner 签好的模板去换。换来的 token 存成新条目（`derived:…`），agent 只拿到它的占位符；refresh token 被轮换时，新值会写回保存 | 不需要 |
| 代签 | AWS SigV4、HMAC、JWT 在请求发出时由 sealed 签上；钱包签名由 agent 提交待签内容，sealed 只返回签名。签名密钥永远不交出 | 不需要 |
| 交出 | 把值本身交给 agent，供不走 HTTP 或不认代理的工具使用 | 需要：预先允许，或这一次批准 |

## 请求和批准

agent 可以提出三种请求：交出某个值、新增一个凭据（指定预设）、连接一个 MCP 服务器。

- **不让 agent 卡住**：sealed 记下请求后立刻回复"等 owner 决定"，agent 可以先做别的。
- **owner 看到什么**：
  - 用 `cred <agent> pending` 查看，或者在会话里，请求会直接弹出来；
  - sealed 记录的事实和 agent 写的理由分开显示，后者明确标为 agent 的说法。
- **可以怎么选**：
  - 批准一次：钱包签名，只对这一个请求有效；
  - 以后都允许：重新签名凭据集；
  - 拒绝；
  - 以后再说。
- **不处理就是拒绝**：请求 72 小时后失效；agent 的容器重启后，请求也不保留，agent 需要重新提。
- **通知邮件**：
  - owner 用 `cred notify <邮箱>` 给自己的钱包登记一个邮箱，名下所有 agent 共用。
  - 有请求在等时，attestor 发邮件，只写 agent 编号、请求数量和要运行的命令；凭据到期前一周，也会提醒。
  - 邮件由平台按固定格式发出，agent 碰不到，也不知道你的邮箱。

## 存储和版本

- **凭据集**：owner 的所有条目合成一份清单，用钱包签名（EIP-712）。每改一次就生成新的一份，版本号加 1。值在 owner 本机先加密给 agent 的密钥再发出，attestor 只存密文。
- **正本和副本**：attestor 按 agent 保存正本，每次 agent 启动时下发；运行中的 agent 用的是副本。容器可能被重置或换新，所以正本放在 attestor。
- **改动顺序**：先存 attestor，成功后马上推给运行中的 agent。存失败就停下报错，两边都还是旧版本，不会出现"agent 比 attestor 新"的情况。
- **旧清单塞不回来**：
  - agent 记住用过的最新版本，包括版本号和内容指纹。更旧的清单，或者版本号相同但内容不同的清单，一律拒绝。
  - owner 的 CLI 也在本机记一份（`credential-marks.json`）。所以就算平台服务器出了问题，送来旧清单，也骗不到 owner 在旧清单上继续修改并签名。

## 登录和写回

- **连接 MCP 服务器**：运行 `cred <agent> connect <名字> <MCP 地址>`。
  - sealed 按 MCP 规范找到授权服务器并注册，生成授权链接；owner 在浏览器里同意；
  - 回调落在 agent 自己的地址上，token 只在 sealed 里；
  - 连上后，agent 用 `Authorization: Bearer [[credential:<名字>]]` 访问这个服务器。
- **写回**：
  - sealed 自己拿到的值（登录 token、轮换出的 refresh token）会加密存回 attestor，并用 agent 的密钥签名，所以 attestor 改不了。
  - 每份写回都带一个"指纹"，记录它代表什么：owner 设的值的 hash，或者登录的服务器、client、scopes。
  - 重启时，sealed 用当前凭据集重新算指纹来比对，对得上就继续用。所以改描述、改别的条目，都不会让登录失效；换了值或换了服务器，才会作废。
- **断开**：`cred <agent> disconnect <名字>`。服务器支持的话，先请它作废 token（RFC 7009），再删掉条目。

## 模型 key

agent 调用模型用的 key 也放在凭据集里，一家服务一条（`model.0g-compute`、`model.anthropic` 等）。

- **一家服务一把 key，不管从哪里给**：`login` 存在本机的 key 是其他各步首先提供的那一把。创建或重置 agent、`cred <agent> set model`、`settings` 切换到别家时，都会先问"用本机存的 X key？"。回答否并给一把新的，新的就替换本机那一把。用管道传 key 的脚本不会被提问，它给的 key 替换本机那一把。
- **谁在用**：sealed 把 key 交给框架调模型用。这一条不在 agent 能看到的凭据列表里，也不能交出。agent 的工具能不能读到 key，取决于框架，和创建/重置时交的 key 一样：0g-compute 上的 0g-harness 拿不到（sealed 在请求发出时填进去）；openclaw、hermes、prime，以及用 `openai`/`anthropic` 的 0g-harness，拿到的是 key 本身，它们的工具读得到。
- **用哪条**：agent 的设置决定用哪家（`settings <agent> provider=…`），sealed 取那一家的 key；别家的 key 只存着。设置里没写 provider 时，只有一家有 key 就用这一家。
- **能发到哪**：设置 key 时平台服务列表里这家的地址；之后列表再变，key 也不会被发到新地址。
- **更换**：`cred <agent> set model` 立即生效：0g-compute 上的 0g-harness 直接换上，不重启；其他框架重启一下，几秒钟。
- **换服务**：`settings <agent> provider=X model=…` 时，如果凭据集里还没有 X 的 key，会当场问你，存进去后再切换。
- **创建和重置**：key 和其他凭据一样写进凭据集。老镜像还在用的这段时间里，它也随创建或重置请求一起发出，供只认请求的老镜像使用；能读凭据集的镜像以凭据集里的为准。凭据集里已有这家的 key 时，重置不提问，并把本机那把一起发出，给老镜像用；本机没有时会问你要（回车跳过；在这里给的 key 也会替换凭据集里那把）。
- **应用提供的 key**：应用可以用它自己的 key 替你付 agent 的模型费用，又不让你看到这把 key：它的服务器把 key 加密给这个 agent，你把它存进凭据集，签名的只是密文。之后它和你自己的 key 一样用。
- **没有时**：凭据集里没有这家的 key 时，CLI 可以不带模型 key 创建或重置用 0g-compute 的 0g-harness agent：照常运行，调模型时失败，补上 key 后生效。其他框架、其他服务，CLI 都会要 key。SDK 只在服务不是 0g-compute、凭据集里也没有这家的 key 时拒绝不带 key 的创建；各框架没有 key 时怎样，见 [sealed/CREDENTIALS.zh.md](../sealed/CREDENTIALS.zh.md)。
- **删掉正在用的 key**：会先确认。key 还随创建或重置请求发出的这段时间里，如果随请求来的那把是同一家的，就改用它；不是的话，调不了模型，直到有 key 为止。删掉的 key 不会再被使用。

## 转让

- **attestor**：发现 agent 被转让后，删掉这个 agent 的凭据数据，并拆掉旧容器。dev 上实测，转让上链后 3 秒内旧容器就没了。
- **sealed 自己兜底**：
  - 每 10 秒查一次链上 owner；交出值、换 token、签名、登录之前，如果上次确认已超过 10 秒，会再查一次。
  - owner 一变，就清空所有凭据、请求和授权，旧容器整体关闭：除 `/hello`、`/healthz` 和公开的 `/log` 页面外都返回 423，前任和新主人都不能再用它。
  - 新主人 reset 后，会在新容器里运行 agent。
- **克隆**：克隆出的 agent 是新的 seal，不带原来的凭据。

## 信任边界

- **可信的部分**：sealed 的镜像经过度量，在 TEE 里运行，按规则办事。凭据集的内容以 owner 的签名为准；sealed 自己拿到的值，以 agent 的签名为准。
- **attestor 改不了内容，但要信它给出最新的一版**：
  - reset 或新建 sandbox 之后，sealed 只能接受它给的那一版；所有权纪元也由它报告。
  - 所以删除密钥时，同时去服务商那里吊销。
- **不覆盖的情况**：
  - 在密钥本身的权限范围内，agent 怎么用不受限制；权限在服务商那里创建密钥时设定。
  - 不认代理或钉死证书的工具、非 HTTP 协议、浏览器登录态，只能用交出的值。
  - 普通 API 调用返回的新 token 会原样给 agent，常见 token 格式会被遮盖；需要的话，用换 token 模板来拿。
  - 交给 agent 的值可能进入它的记忆或文件，随 agent 转让交给新主人。
  - 对响应的遮盖尽力而为。

## 常用命令

```
0g-agentdna cred <agent>                             列出条目（不含值）
0g-agentdna cred <agent> set <名字> preset=github    新增或修改；值从不回显的输入读取
0g-agentdna cred <agent> rm <名字>                   删除（也去服务商那里吊销）
0g-agentdna cred <agent> set model [provider=<id>]   设置 agent 的模型 key（默认是设置里的那家）
0g-agentdna cred <agent> rm model [provider=<id>]    删除一条模型 key
0g-agentdna cred <agent> connect <名字> <MCP 地址>   连接 MCP 服务器
0g-agentdna cred <agent> disconnect <名字>           断开，并请服务器作废 token
0g-agentdna cred <agent> reveal <名字> on|off        是否允许 agent 直接读取值
0g-agentdna cred <agent> pending                     查看等你处理的请求
0g-agentdna cred <agent> approve|deny [<编号>]       批准一次 / 拒绝
0g-agentdna cred <agent> log                         agent 怎样用了这些凭据
0g-agentdna cred pending                             名下所有 agent 的待处理数量
0g-agentdna cred notify [<邮箱>|off]                 通知邮箱
0g-agentdna cred presets                             预设，以及每个密钥去哪里创建
```

在 agent 的会话里（`0g-agentdna <agent>`）用 `/cred …`；agent 的请求会直接弹出来问你，任何提问都可以按 Ctrl-C 或 Esc 取消。
