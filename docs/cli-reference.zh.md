# 0g-agentdna CLI 参考

[English](cli-reference.md)

> 适用于 `@0gfoundation/0g-agentdna` ≥ 0.4.0 · CLI 随 SDK 包一起发布，无需单独安装
> 下文每条命令、flag 和退出码都已对照 `sdk/typescript/src/cli/` 源码核实

## 1. 安装与基本概念

```bash
npm install @0gfoundation/0g-agentdna
npx @0gfoundation/0g-agentdna --help
```

一个入口，**两种形态**：

| 形态 | 调用方式 | 用途 |
|---|---|---|
| 交互 shell | 不带参数的 `npx @0gfoundation/0g-agentdna` 打开 manager 提示符（`0g-agentdna>`）；带上 agent 引用（`npx @0gfoundation/0g-agentdna 286`，或 `… use 286`）则直接进入该 agent 的会话 | 部署、对话、评分：日常人工使用 |
| 一次性命令 | `npx @0gfoundation/0g-agentdna <command>` | 诊断与自动化：都支持 `--json` |

要点：**一次性命令是 `doctor` / `status` / `list` / `settings` / `cred` / `providers` / `releases` / `update`。** 十进制的位置参数是 agentId，`0x…` 开头的是 sealId：两者都打开该 agent 的会话，所以命令名和 agent 引用不会冲突。`help` 打印帮助（同 `--help`）。shell 自己的命令词（`login`、`whoami`、`deploy`、`balance`、`start`……）会被拒绝，退出码 2（`UNKNOWN_COMMAND`），修复办法是运行 `0g-agentdna`，在里面输入；其他词都是未知命令（退出码 2，`UNKNOWN_COMMAND`），看起来像拼写错误时会给出最接近的命令（`doctr` → `0g-agentdna doctor`）。

前提：**Node.js ≥ 22**（推荐：`nvm install 22 && nvm use 22`）。

## 2. 全局选项

| 选项 | 作用 |
|---|---|
| `--json` | 机器输出：stdout 只输出一个 `{ok, data \| error}` envelope；所有进度信息写到 stderr。不带它时，错误是 stderr 上的一到两行纯文本（`error (<CODE>): …` 和 `fix: …`），给出 owner 在当前所在位置就能运行的命令 |
| `--mine` | （仅 list）只列 `AGENTIC_PRIVATE_KEY` 名下的部署；需要 owner 签名，额外给出只有 owner 能看的字段（失败原因、sandboxId） |
| `--phase <p>` | （仅 list）按 phase 过滤：`deploying` `running` `stopped` `offline` `failed` |
| `--help` | 帮助文本 |
| `--version` | 包版本（与 SDK 的版本相同）；加 `--json` 时输出信封 `{ok: true, data: {version}}` |

`--json` envelope 的约定：

- `error = {code, message, remedy?, details?}`；bigint 序列化为十进制字符串；缺失的值为 `null`，从不省略。错误由 CLI 自己措辞时（服务器的 HTTP 应答、链上错误），`details.cause` 带原始文本
- doctor 把每项检查的结果放在 `(data|error.details).checks` 下，每项为 `status: pass|fail|skip`
- 未知 flag 立即报错，退出码 2

## 3. 环境变量与配置文件

环境变量**总是覆盖**配置文件：CI 和一次性运行从不碰磁盘。

| 变量 | 必需 | 说明 |
|---|---|---|
| `AGENTIC_ATTESTOR_URL` | 是，除非 `login` 已保存一个 | attestor 基础 URL：**一个 URL 确定整个环境**（合约、RPC、appId 都取自它的 `/config`）。生产环境 `https://agentdna.0g.ai`，测试网 `https://agentdna-testnet.0g.ai` |
| `AGENTIC_PRIVATE_KEY` | 否 | owner 私钥（`0x…` 十六进制）。**只能通过环境变量设置：刻意不提供 `--key` flag。** 有了它才能做所有写操作，使用所有需要 owner 签名的功能 |
| `AGENTIC_RPC_URL` | 否 | 覆盖 attestor 公布的 RPC |
| `AGENTDNA_API_KEY_PROVIDER` + `AGENTDNA_API_KEY` | 否 | 一起设置：deploy/reset 时该 provider（如 `openai`）的推理 key，覆盖 `login` 存的那把。只有 key 没有 provider 会被拒绝 |
| `AGENTIC_API_KEY` | 否 | 旧版的、只用于 compute 的推理 key（deploy/reset）；其他 provider 用 `login` 存的对应 key。其他变量（包括通用的 `API_KEY`）都不会被当作模型 key 读取 |
| `AGENTIC_VERIFIED_FEEDBACK_ADDR` | 否 | 覆盖声誉合约对的地址，用于 `/config` 还没公布它们的 attestor |
| `AGENTIC_FEEDBACK_BATCHER_ADDR` | 否 | 覆盖 FeedbackBatcher 地址，情况同上 |
| `AGENTDNA_LIVE_PROMPT` | 否 | `off`（或 `0`、`false`、`no`）：对话的一轮以普通的流打印，这一轮进行中屏幕上不显示提示符（§5，会话层） |
| `AGENTDNA_INK` | 否 | `off`（或 `0`、`false`、`no`）：会话保留 readline 的提示符行，不用带边框的输入区（§5，会话层） |
| `FORCE_HYPERLINK` | 否 | `1` 或 `0`：已保存文件的路径是否为可点击的 `file://` 链接（OSC 8），不管是什么终端 |

没有 attestor URL 时（既没设置，`login` 也没保存），除 `--help`/`--version`/`help` 外的每条命令都以退出码 3 退出（`MISSING_ATTESTOR_URL`；修复办法是 `login`，或设置该变量）。有 attestor URL 但没有 owner 私钥时，CLI 是**只读**的：`list`（公开层）、`status`、`providers`、`releases`，以及 shell 里的 `hello` 可用；所有需要 owner 签名的操作都被拒绝（`WALLET_REQUIRED`）。设置了 `AGENTDNA_API_KEY` 而没设置 `AGENTDNA_API_KEY_PROVIDER` 时，用到模型 key 的地方会拒绝（退出码 3，`INFERENCE_KEY_REQUIRED`）；shell 照常启动，并在 banner 里说明。

保存在 `~/.config/0g-agentdna/` 下的文件：

| 文件 | 内容 | 权限 |
|---|---|---|
| `config.json` | attestor URL；默认的推理 provider；执行 `/files auto off` 之后的 `filesAuto: "off"` | — |
| `credentials` | owner 私钥 + 按 provider 区分的推理 key（JSON） | 0600 |
| `proofs.json` | 评分票据罐 | 0600 |

旧配置会自动从 `~/.config/0g-agenticid/` 迁移；见[升级说明](../sdk/typescript/MIGRATION.zh.md)。保存的公共 attestor 旧地址（`https://agenticid.0g.ai`、`https://agenticid-testnet.0g.ai`）在下次运行时换成它现在的名字。

## 4. 子命令

### `doctor`

检查部署的每项前提：attestor 可达、RPC、钱包、gas、信任根 ack、sandbox 预付费余额（≥ 0.1 OG）。**每个未通过的项都打印一行修复办法。** 全部通过则退出码 0；否则退出码 3，错误带**第一个**未通过检查的代码。RPC 取 `AGENTIC_RPC_URL`，没有则取 attestor 的 `/config` 给出的那个；两者都没有时跳过这项检查。钱包那一行说明私钥从哪里来（`saved by login` 或 `from AGENTIC_PRIVATE_KEY`）。只做诊断：ack 和充值的修复办法是交易（需要 gas），在 shell 里运行（`ack`、`deposit <og>`）。

### `status <agent>`

一个 agent 的完整情况：phase、三个坐标（agentId / sealId / agentSeal）、失败原因（`--json` 还带容器的 `url`）。`<agent>` 是十进制 agentId 或 `0x…` sealId，CLI 会在两者之间换算。配置了钱包时，公开列表不给出的失败原因（issue #64）会自动通过 owner 签名的列表取到。

### `list [--mine] [--phase <p>]`

部署列表。公开层带 sealId，已 mint 的行还带 owner 和 agentSeal 地址（mint 之后两者在链上都是公开的）；`--mine` 加上只有 owner 能看的字段（`WHERE owner = $1`：归 agent 所有的下级 agent 不会出现在你自己的 `--mine` 里；嵌套关系只在公开列表里看得到）。结果为空时输出 `[]`，退出码 0；带 agent 参数会被拒绝（`BAD_FLAG`；看单个 agent 用 `status <agent>`）。人读输出显示 AGENTID/PHASE/FRAMEWORK/AGENTSEAL/OWNER/NAME（NAME 在最后，经过清理和截断：owner 控制的名字伪造不了行）；未 mint 的行在 AGENTID 格里显示 sealId 前缀（`0x` + 10 位十六进制，可以直接粘回来用），某行归另一个列出的 agent 所有时，OWNER 格标注 `⇄ #<agentId>`；sealId、url 和完整地址在 `--json` 里。在终端里，表格适应终端宽度：AGENTID、PHASE 和 NAME 总是显示，FRAMEWORK、OWNER、AGENTSEAL 按这个顺序加入，前提是 NAME 至少保留 10 列，并且任何一行都不会到达终端的最后一列；输出到管道时，所有列都显示，NAME 截到 18 个字符。

### `settings <agent> [k=v …]`

读写 agent 的配置文档（用哪个模型思考、思考多深）。

- 不带赋值 → 显示文档；带赋值 → 修改文档
- 键：`provider`、`model`、`thinking`（`low|high|max`）、`others`（不透明的 JSON，原样传给框架自己的旋钮；要加引号：`others='{"a": 1}'`），以及 0g-harness agent 上的 `sealed` / `harness`：某个版本的 sha256（`0x` + 64 位十六进制），写进文档的 `versions`；信任注册表列着这个选择时，agent 就运行它。文档里为其他层保存的选择保持原样，显示为 `versions.<layer>`。在 0g-harness agent 上不带赋值显示时，最后一行说明运行的是哪些版本：没有选择时为 `versions   newest listed (sealed 0x503c5892…, harness 0x0a93d67d…)`，有选择时为 `versions   pinned: sealed 0x…, harness 0x…`（信任注册表已不再列出的选择标为 `(not listed: not run)`；没有选择的层显示它最新的版本）。`settings <agent> versions`（会话里是 `/settings versions`）列出信任注册表里的所有版本，最早的在前，标出最新的版本和已选的版本：也就是 `sealed=` 和 `harness=` 所接受的哈希。`versions` 只能单独使用；它不写入任何内容。两种情况下 `--json` 都在 `listedVersions` 里带这些列表。agent 记录的框架是其他框架时，版本选择在签名前被拒绝
- 赋值**合并**进已存的文档；空值（`thinking=`）清除该字段
- **读和写都要 owner 签名**（文档属于 owner），即都需要 `AGENTIC_PRIVATE_KEY`
- 写入是对刚读到的版本做**比较并交换**：如果其间别的客户端改了文档，写入被拒绝（退出码 3，`SETTINGS_CONFLICT`），**绝不静默覆盖**
- 合并后没有 `model` 的文档在签名前被拒绝（这是容器唯一会直接失败的状态）；设置 model 或 provider 的写入，先对照所选 provider 的目录检查：目录里没有只在 stderr 给出警告，从不拒绝；目录标明不支持工具调用的模型，对靠工具工作的框架（openclaw、prime-agent、0g-harness）的 agent 会被拒绝，和部署向导不提供这类模型一致
- 结果显示 `saved`，并说明运行中的容器已应用、拒绝了它，还是下次启动时生效；`--json` 带文档的新 `version`
- 用 `provider=` 切换时，agent 的凭据集里要有新 provider 的模型 key：没有的话，按 `cred <agent> set model` 的方式要 key（先提供本机的 key；`--json` 不提问，用管道传入的 key 或本机的 key），先存进去，再写入并推送文档。镜像早于 cred 模型 key 的 agent，文档照常写入，切换要等用新 provider 的 key 做一次 reset（`pendingReset`）

### `cred <agent> [sub …]` 与 `cred pending|notify|presets`

owner 给 agent 的 sealed 凭据代理用的凭据（`sealed/CREDENTIALS.zh.md`）：agent 在需要密钥的地方写 `[[credential:<name>]]`，sealed 在请求出网时代填，只对允许的域名和位置生效，并在响应里遮盖它。除 `cred presets` 外，每个子命令都要 owner 签名（`AGENTIC_PRIVATE_KEY`）。

| 子命令 | |
|---|---|
| `cred <agent>` / `ls` | 列出已存的条目（从不显示值；凭据集的版本只在 `--json` 里）；登录条目显示运行中的 agent 是否已登录（`logged in <time>`、`not done yet`，agent 没在运行时为 `unknown`）；然后是模型 key，标为 `in use` 或 `kept, not in use`，以及运行中的 agent 用的是哪把 key（`in use: the <provider> key given at create/reset`、`none — add one: …` 或 `unknown`） |
| `cred <agent> set <name> [k=v …]` | 新增或修改一条。值在管道输入时从 stdin 读取，否则从不回显的输入提示读取；从不从参数读取。在提示处按 Enter 保留已存的值；如果也没给任何选项，什么都不写（`<name> unchanged`）。键：`preset=<name>`（`cred presets`）、`host=a,b`、`header='Name: … {v} …'`、`basic=<user>`、`query=<param>`、`body=<field>`、`path=yes`、`use=inject\|token_only\|sign`、`signer=<json>`（配合 `use=sign`：`sigv4`、`hmac`、`jwt`、`wallet`）、`token=<json>`（换 token 模板）、`writeback=yes\|no`、`reveal=yes\|no`、`expires=<YYYY-MM-DD\|unix>`、`desc=…`。`host=` 替换域名，任何位置键替换位置，其余保持不变。用预设新建条目时，先打印去哪里创建密钥 |
| `cred <agent> set <name> preset=oauth2-refresh\|oauth2-client token_url=… client_id=… api_host=… [client_secret=<entry>] [scope=…]` | refresh token（会轮换并写回）或 client secret，由 sealed 换成 access token；agent 对 `<name>` 执行换 token，在 `api_host` 上把 `[[credential:derived:<name>]]` 当作 Bearer token 使用。给了 `scope=` 就固定；不给时，agent 可以申请 scope |
| `cred <agent> rm <name>` | 删除一条（也去服务商那里吊销）；运行中的 agent 没接收这次删除时会说明（删除在它下次启动时生效） |
| `cred <agent> set model [provider=<id>]` | agent 某个 provider 的模型 key（条目 `model.<provider>`），绑定到 attestor 提供的注册表里这个 provider 的路由。不带 `provider=` 时：用 agent 设置里的 provider；设置里没有，就用唯一持有 key 的那个 provider，否则用 `0g-compute`。本机有这个 provider 的 key（`login` 存的）时，CLI 先问是否用它；回答否会要一把新 key，新 key 随后替换本机那把。本机没有时，输入的 key 保存在本机。用管道传入（脚本）时什么都不问：使用并保存管道传入的 key，没有则用本机的 key。用哪个 provider 的 key 由 agent 的设置决定：CLI 等到运行中的 agent 报告 `in use now`（0g-compute 上的 0g-harness 不用重启，其他框架重启之后），或者说明它是 `kept`，因为设置用的是另一个 provider。镜像早于 cred 模型 key 的 agent 会被拒绝（先 reset 它） |
| `cred <agent> rm model [provider=<id>]` | 删除一把模型 key；删除正在用的 key 前会先确认。之后，如果创建/重置时给的 key 属于同一个 provider，agent 回到那把 key，否则在有 key 之前调不了模型 |
| `cred <agent> connect <name> [<mcp-url>] [client_id=… client_secret_entry=… scope=a,b]` | 给 agent 连接一个 MCP 服务器：条目是新的或有改动时定义它（在服务器的域名上用 Bearer），打印登录链接，并等待连接完成，在会话里也一样（Ctrl-C，或会话里的 Esc，只停止等待，不停止登录）。已有的连接不给 url（或给它自己的 url 且不带选项）时，按现有定义重新连接，保留它的 client 和 scopes |
| `cred <agent> disconnect <name>` | 服务器支持时，运行中的 agent 请服务器作废这个连接的 token（RFC 7009），并丢掉它们；然后删除条目。服务器无法作废（或 agent 没在运行）时会说明：到该服务那里撤销这个应用的访问权限。运行中的 agent 也没接收这次删除时，会说明 agent 在下次启动前仍持有登录。对连接用 `rm` 效果相同 |
| `cred <agent> reveal <name> on\|off` | 让 agent 不必每次申请就能自己读取值。条目持有的登录或轮换得到的 token 保留。对签名密钥会被拒绝，签名密钥从不交出。运行中的 agent 没接收这次修改时会说明 |
| `cred <agent> pending` | 等待中的请求：sealed 掌握的事实与 agent 的说法分开显示 |
| `cred <agent> approve\|deny [<id>]` | 对一条请求做决定（给出 id 前缀即可；只有一条请求在等时不用给）；`approve` 签一次性的 EIP-712 批准。新增凭据或登录的请求，用 `set` / `login` 来应答 |
| `cred <agent> log [n]` | agent 用凭据做了什么：先是 sealed 保管的推理 key 的使用计数（`×count`，首次 … 最近一次），然后是最近 n 条其他记录。agent 的镜像还没有凭据日志时会说明（`RUNTIME_TOO_OLD`，退出码 3）：reset 会把它换到当前镜像；已停止的 agent 被拒绝（`AGENT_NOT_RUNNING`，退出码 3）：先 `start` 它 |
| `cred pending` | 你名下每个 agent 的待处理数量 |
| `cred notify [<email>\|off]` | agent 等你处理、或凭据快到期时，发邮件到哪里 |
| `cred presets` | 预设：域名、位置、每个密钥去哪里创建、怎样把权限收窄（不需要钱包） |

在 agent 的会话里（`0g-agentdna <agent>`），agent 在等的请求会在提示符处弹出：交出：`[y]` 一次 / `[a]` 总是 / `[n]` 拒绝；新增：`[s]` 现在设置；连接：`[c]` 现在连接（打印链接，会话等待连接完成；agent 请求把已有的连接指向另一个服务器时，两者都会显示，只提供 `[n]` 或以后再说：连接的服务器由你自己用 `connect` 修改）；`[Enter]` 留待以后。只有你自己的条目才提供 `[a]` 总是；对已存在条目的新增请求只提供 `[n]` 或以后再说（用 `set` 修改它）。不是会话自己写出的内容，会话都不会带着转义序列或控制字符打印：agent 的回复、活动、错误、任务 id 和结果、日志和参数都以纯文本输出。每个凭据提问都写明它针对哪个条目，并先重置终端（包括颜色）；提问出现之前输入的内容不算作它的回答（一行输入、还没按 Enter 发出的按键，或者提问出现时进来的一行）；会话输出被重定向时，不提供这些提问和输入值的提示（用 `/cred pending` 和 `/cred approve|deny <id>` 应答）；`[c]` 写明连接要用的域名。你回答时会再检查一次定义。回答作为你的下一条消息发给 agent，agent 就能接着做。

写入和 `settings` 一样是比较并交换（退出码 3，`CREDENTIALS_CONFLICT`）。写入存到 attestor，并推给运行中的 agent；agent 没在运行时，在下次启动时生效。

### `providers`

列出 attestor 注册表里的 provider（支持 `--json`）：id、名称、格式，以及每个 provider 的 key 能付费的网页搜索服务（`webSearch`；没有这个字段时，显示 sealed 使用的那个：`0g-compute` 用 router 的，原生 `openai` 和 `anthropic` 用它们自己的；没有则为 `-`）。0g-harness agent 的 `others.webSearch` 选择搜索服务。`--json` 按发布时的样子打印注册表。发布注册表是运维 API / SDK 的管理操作，由 attestor 的 Tapp owner 授权；不是 CLI 命令。

### `releases`

attestor 的发布通知，最新的在前（`--json`：`{ releases, agents }`）：每个版本的说明（`LANG`/`LC_ALL` 以 `zh` 开头、且该版本有中文说明时显示中文的），以及它替换的镜像和各自过渡期的结束时间。有 `AGENTIC_PRIVATE_KEY` 时，还列出你名下仍在运行被替换镜像的 agent、最晚要 reset 的日期和所处状态（`please move`；`7 days or less left`；`transition period over: its next boot may be refused`）；没有私钥时 `agents` 为 `null`。这样的 agent 会继续运行；在那个日期之前在 shell 里 reset 它（`reset <agent>`），过了那个日期，它的旧镜像可能下架，下次启动可能被拒。

其他每条命令在到时候时，会在输出之后打印一条简短的发布通知：写到 stderr，只在终端里，从不在 `--json` 下，最多等 attestor 1.5 秒。交互 shell 在 banner 之后打印，给出它自己的命令（`reset <agent>`、`releases`）。attestor 不应答时，`releases` 以退出码 3 退出（`ATTESTOR_UNREACHABLE`）。有要迁移的 agent 时：每周一次，最后 7 天及之后每天一次。没有（或没有私钥）时：每个版本一次，在发布后的 30 天内。上次显示的时间按 attestor 和类型（有 agent / 仅消息）记在配置目录的 `release-notice.json` 里。

### `update`

自更新：对照 npm registry，用 `npm install -g` 安装最新版（git 检出 / npm link 的安装只报告，不覆盖）。`--json` 只报告。

## 5. 交互 shell

### manager 层（`0g-agentdna>` 提示符）

banner 写明 attestor、钱包、是否设置了模型 key，以及信任根 ack（或者哪项读取失败：attestor 没应答、链上读取失败，或 4 秒内没有应答）。到期的更新提示和发布通知打印在它之后。shell 的各行，以及一次性命令在终端上的输出，都在终端宽度处按词换行。在命令提出的提问处（向导的选项、一个金额、一把 key），Tab 不提供 shell 命令，↑ 也调不出命令，回答不进入命令历史；等待期间（start、reset、deploy，或等模型 key 被接收、等登录完成），↑ 同样调不出命令，等待行显示 `Esc stops the wait, not the agent`。错误显示为 `error: …`，有修复办法时还有 `→ <remedy>`，给出在这个提示符下输入的命令；未知的词看起来像拼写错误时，给出最接近的命令。

| 命令 | 作用 |
|---|---|
| `list` | 列与 `0g-agentdna list` 相同，适应终端宽度（归 agent 所有的 agent 标 `⇄ #<agentId>`；还没有 agentId 的 agent 显示 sealId 前缀）；`*` 标出你钱包名下的 agent。`list --mine`：只列你的 |
| `use <agentId\|sealId>` | 进入 agent 的会话（任何 phase）。还没有 agentId 的 agent（仍在 mint，或部署在 mint 之前停下）被拒绝（`AGENT_NOT_READY`，退出码 3）：mint 之后 `list` 会显示它的 agentId，失败的用 `retry <prefix>` 继续 |
| `deploy` | 向导：依次选框架 → provider → 模型，每项用列出的编号或名字选（Enter 取默认值；其他输入会重新询问）；异步部署。只 mint 的部署最后给出 agentId 和让它上线的 `reset <id>` |
| `hello <id> [full]` | 访问任意 agent 的公开 `/hello`：身份和 serve-proof 检查，它的服务每行一个（说明按终端宽度截断），以及它的 owner 路由，按 kind 列在一行里，例如 `owner API (bearer): chat, responses, inbox, …`；`full` 打印每个服务和每条路由的所有字段。配置了钱包时，存下一张评分票据 |
| `call <id> [path] [json-body]` | 调用 agent 注册的公开服务；不带参数的 `call` 列出它的服务；响应会存下票据 |
| `rate <id> [score] [/endpoint]` | 用一张票据在链上评分：**没有交互，就不能评分** |
| `start` / `stop` / `reset` / `retry <id>` | 容器生命周期（owner 签名；链上身份不变）。`start` 和 `reset` 拒绝仍在部署的 agent，以及还没有 agentId 的 agent（用 `retry` 继续）；`reset <id> pick` 像部署向导那样询问框架。对没有配置文档的 agent 做 `reset` 时，如果 mint 时 pin 的模型可能已经不在（克隆出的 agent，或之前 provision 过的 agent），会在 reset 的提问之后，先存下默认 pin `provider=0g-compute model=0gm-1.0-35b-a3b`；从未启动过的只 mint 的 agent 保留 mint 时选的模型（部署向导的只 mint 路径也把这个选择存为配置文档）。`start` 和 `reset` 等待自己的结果：attestor 的 worker 接手请求之前显示 `queued`，agent 之前的状态或失败不会结束等待。创建或重置时按 `cred <agent> set model` 的方式要模型 key（0g-compute 上的 0g-harness agent 可以不给：在提示处按 Enter），把它存进 agent 的凭据集，并且在旧镜像还在使用期间，也随请求一起发出；凭据集里已有这个 provider 的 key 时，reset 不提问，并把本机的 key 一起发出给旧镜像用（本机没有时会问你要；Enter 跳过，在这里给的 key 也会替换凭据集里那把） |
| `clone` / `transfer` / `grant` / `revoke` / `authorizer` | 克隆、转让、克隆授权管理 |
| `settings <id> [k=v …]` | 与同名子命令语义相同 |
| `cred <id> [sub …]`、`cred pending`、`cred notify` | 与同名子命令语义相同；`login` 打印链接后直接返回，不等待 |
| `balance` / `deposit [og]` / `withdraw [og]` | 预付费账户：余额 + 消耗速率 / 充值 / 退款提取（有时间锁；不带参数时领取全部）。金额是大于 0 的 OG 数，在发起任何交易之前检查（充值还会对照钱包持有的金额）；不带参数的 `deposit` / `withdraw` 会询问金额，没有默认值——回车即取消；`withdraw <og>` 会并入一笔待处理的退款时，先询问，再重启它的时间锁 |
| `ack` | 确认 TEE 信任根（deploy/start/reset 时隐式完成） |
| `login [provider]` | 引导式设置：attestor URL（必填；没设置就一直再问）→ owner 私钥（管理你的 agent 需要它）→ 平台列出的每个 provider 的模型 key（可选；Enter 保留已设的 key，或跳过未设的）→ 新 agent 的默认 provider（多于一个 provider 有 key 时才问）→ 已设置内容的汇总。每个回答保存前都会检查：URL 必须是 `/config` 有应答的 attestor，owner 私钥必须是 64 个十六进制字符（会显示钱包地址）；不对就再问。Ctrl-C 或 Esc 不保存当前这一步；之前完成的步骤保持已保存，取消时会说明是哪些。在模型 key 这一步 attestor 不应答时，按内置的 provider 列表询问。输入 key 时回显 `*`。`login <provider>` 只问这个 provider 的 key。其他各步首先提供的就是这些 key（见 `cred <agent> set model`） |
| `status <id>` / `doctor` / `providers` / `releases` | 即一次性命令，在提示符下运行 |
| `whoami` / `help` / `quit` | `whoami`：attestor、你的钱包、本机配置的 provider（即 `login` 为其保存了模型 key 的那些，新 agent 的默认 provider 排在最前；默认 provider 没有 key 时显示 `0g-compute (new agents, no key)`；一个都没有时显示 `none — run login`；从不显示 key 的值）、是否已确认信任根，以及预付费余额。平台完整的 provider 列表用 `providers` 命令查看；agent 自己的 key 用 `cred <agent>` 查看（会话里是 `/cred`）。`help` 适应终端宽度：不足 80 列时，每条说明换行显示在命令下方。在提示符处按 Ctrl-C 会提示再按一次退出；按两次 Ctrl-C，或按 Ctrl-D，退出 |

### 会话层（`agent 286 ›` 提示符）

进入会话时打印 agent 的卡片：phase、sealId、agentSeal 的 gas；容器上一次状态上报为警告时，还有警告的原因和上报时间，以及 agentSeal 现在持有的金额（比警告里说的多时才显示；警告在 agent 下一次提交时消除）（例如 `agent data not committed to chain: … insufficient funds …`：agent 照常运行和对话，只是在用 `/topup` 给 agentSeal 充值之前，它的数据上不了链）。在终端上，提示符空闲、且 agent 被认为在运行时，CLI 每 30 秒重读一次它的 phase（读一次 attestor；一轮或一条命令进行中不读；读取失败后间隔变长），所以在别处停掉的 agent 大约 30 秒内就会显示出来，不用按键：Ink 视图里显示在页脚（`agent 286 · stopped — /start`），readline 的提示符处显示为提示符上方的一行（`  phase   stopped — /start`、`  phase   offline — /reset`）。

直接输入即可对话。**Esc / Ctrl-C 中断正在进行的这一轮**（所有内置框架都在服务端取消），也会取消 `/start` 或 `/reset` 的等待。一条消息可以有多行：粘贴的内容保持为一条消息（显示为已粘贴，随下一次 Enter 发出，无论第一行以什么开头，都不会当作命令执行），以 `\` 结尾的行或 Option/Alt+Enter 会换到新的一行；在行首按 Backspace 会把这一行接到上一行，输入框里有文字时按 Ctrl-C 或 Esc 会清空它，所有行都清空。在 0g-harness agent 上，agent 工作时你输完的消息会进入 owner-chat 正在运行的这一轮：agent 在这一轮下一次调用模型之前读到它（在终端上，CLI 在提示符上方把它显示为 `waiting for the agent: …`，读到后显示 `↳ read by the agent: …`；输出被重定向时，打印 `↳ inserted`，读到后打印 `(read)`），所以它在当前的模型回答或工具调用结束时送达，而不是在一条长命令执行到一半时；如果这一轮先结束，agent 在下一轮回答它（`(the agent finished before reading this — it goes next)`；几条这样的消息可能在同一轮里一起回答），CLI 跟着那一轮显示，在那一轮里按 Enter 同样会插入（`/result <id>` 跟着一个正在运行的轮次显示时也是这样）；如果 agent 当时没在做任何事，这条消息作为新消息发出（`(the agent wasn't working on anything — sent as a new message)`，在它那一轮开始时打印在消息下方）；空的 Enter 等待下一轮；Esc 停止这一轮，以及本要回答已插入但未读消息的那些轮次；这些消息和排队的消息一起回到输入框，合成一条供编辑（等待中的命令接着单独运行）。哪些插入的消息回来，以停止后 agent 的说法为准：回来的是它丢掉的那些（0g-harness 随这一轮一起丢掉它们）；它在停止前刚读到的，打印为已读；旧版 0g-harness 仍然持有的（它把这些交给下一轮），列在 `(not put back — …)` 下，不放回输入框，所以不会发送两次。一轮进行中单独一行输入的命令从不发给 agent：只读的命令（`/help` `/hello [full]` `/balance` `/activities` `/schedules` `/think` `/inbox [all]` `/notices [all]` `/files [inbox|outbox]` `/sessions [list]` `/tasks [list|all|show <id>]` `/agentlog [n]` `/startuplog [n]` `/signatures [n]` `/settings` `/settings versions`）立即运行，输出打印在提示符上方；其他命令等这一轮结束再运行，并说明这一点（`(/settings runs when this turn ends)`）。在 owner-chat 以外的会话里，以及在其他框架上，一轮进行中输入的消息等到下一轮。因为模型的输出预算用完、没有文本就结束的一轮（0g-harness 把它标为 `max-tokens`）显示 `no answer: the model's thinking used the whole output budget — ask again or /think high`。失败的一轮用一行说明什么失败了：模型服务（5xx 或 provider 的错误：`the model service failed (glm-5.3 via 0g-compute) — try again in a moment`）、模型过载（429：`the model is overloaded — try again shortly`），否则是错误本身的原文，并给出查看完整错误的 `/agentlog`；指向设置的失败（未知的模型、key、错误的请求），只有连续两次这样失败时，才补充说明通常的原因是刚设置的模型或设置。Option+Enter 需要 Option 键发送 Meta：macOS Terminal 里是 Settings → Profiles → Keyboard → "Use Option as Meta key"；iTerm2 里是 Profiles → Keys → Left Option key: Esc+。其他提问只接受一行：粘贴的多行不算它们的回答，粘贴也不能回答是/否提问或需要签名的提问。管道输入仍是每行一条命令。在命令提出的提问处（一个值、一个金额、一次确认、一个凭据请求），Esc / Ctrl-C 取消这个提问和这条命令；以这种方式取消的凭据请求，以及它之后的请求，都留待以后。在提示符本身处，按两次 Ctrl-C 退出（没有输入内容时）。以 `/` 开头、指向一个不存在的文件的词（比如拖进来的截图的临时副本）不会当作命令执行：显示 `file not found: <name>`。

在终端上，会话的布局与 Claude Code 的输入区一样（用 Ink 绘制）。最下面，你输入的那一行以 `❯ ` 开头，夹在两条横线之间，下面是页脚：agent、它不在运行时在做什么以及处理办法（`agent 286 · stopped — /start`、`agent 286 · deploying…`、`agent 286 · failed — /reset · <last error>`；提示符显示期间会重读：agent 不在运行时每 10 秒一次，运行时每 30 秒一次，所以页脚跟着 phase 变化），以及当前可用的按键。在这里，空的 Enter 重读 phase，不打印任何内容；在 readline 的提示符处，它把 phase 打印成一行。输入行上方，一轮进行中时，状态行说明 agent 在做什么、怎样停止它（`⠹ running a command… (14s · Esc to stop)`），并在右侧统计等你处理的内容（`2 notices · 1 new file`：一轮或一条命令进行中到达、要到下一个提示符才打印的通知，以及 agent 留下、还没保存的文件）；再往上是这一轮中发出、还在等待的消息，每条以 `❯ text` 显示在高亮背景上，标为 `waiting for the agent`（用 Enter 插入：agent 在下一步读到它）或 `next turn`（用 Tab，或等这一轮结束的命令）。其他内容都在更上方滚动：你的消息（`❯ text`）、agent 的回复（正在写的那一行紧挨在状态行上方）、命令输出、通知，以及 agent 每一串工具调用各一行暗色的普通文字（`· ran 3 commands, read a file`）。拖进消息的文件在消息里显示为它的名字（`[image: cat.png]`）；消息按输入的原样发出。你输入的内容留在输入框里，agent 回复期间也可以编辑。Enter 按上文所述发出；**Tab 则把它排队**：它在状态行上方等待，这一轮结束时作为你的下一条消息发出（等下一轮的条目，比如不只是读取的命令，同样在这里等待，到时运行；等待的多条消息合成一条发出，中间隔空行）；用 Esc 停止这一轮时，排队的内容不发出，放回输入框供编辑，合成一条消息，不带空行。**在空的提示符处按 ↑** 把最新排队的条目取回来编辑；没有排队的内容时，↑ 和 ↓ 翻看你之前输入过的内容，只翻以按 ↑ 之前已输入的文字开头的那些。在以 `/` 开头的行上按 Tab 会补全命令（只有一个匹配时，后面加一个空格，和 shell 里一样），一轮进行中也可以；有多个匹配时，在输入框下方列出候选项。要你输入的密钥显示为 `*`，也不进入 ↑ 的历史。带边框的视图需要至少 30 列、12 行的终端，在 CI 里（设置了 `CI`）不使用；在这些情况下，以及 `ink` 包加载不了、或设置了 `AGENTDNA_INK=off` 时，会话使用 readline 的提示符行：一轮进行中，提示符留在屏幕上并标明这一点（`agent 286 (replying, Esc stops) › `），回复打印在它上方，这一轮中发出的内容显示为 `waiting for the agent: …` 或 `next turn: …`，提示符里统计等你处理的内容（`agent 286 · 2 notices · 1 new file › `）。`AGENTDNA_LIVE_PROMPT=off` 把每一轮按普通的流打印，管道输出总是这样。manager 层（`0g-agentdna>`）保留 readline 的提示符。

斜杠命令（已对照 `interactive.ts` 核实）：`/hello [full]`（这个 agent 的 `/hello`，精简显示或 `full`，同 `hello <id>`）`/balance` `/topup [og]` `/stop` `/start` `/reset` `/settings [k=v …|versions]` `/cred [sub …]`（这个 agent 的凭据，同 `cred <id>`）`/think [low|high|max]` `/clear`（清空对话；链上跟踪的记忆不受影响，这一点和 `/reset` 不同）`/compact`（框架立即总结对话中较早的部分：0g-harness，以及 openclaw 2026.7.1 或更高版本）`/restart harness|sealed`（0g-harness：就地重启运行时的一层：harness 进程，或 sealed 本身，由 loader 重新启动）`/sessions [list|new [title]|switch <#|id|title>|fork [id]|default]`（0g-harness：owner 的会话，每个是一段独立的对话，共用人设、skills 和记忆；列表给它们编号，最近活跃的在前，带短 id、状态、最后活跃时间和标题，标题由 harness 取自第一条消息；`switch` 接受这个编号：按这个 CLI 上次显示的列表计数，所以之后新建或用过的会话不会让编号变动；还没显示过列表时，先打印列表，CLI 问过之后再切换；也接受 id 或 id 前缀，或标题里的词；在 `switch ` 之后按 Tab 列出各个会话，带编号和标题；`new` 新开一个并切换过去，`fork` 复制当前会话（或 `id` 那个会话）的记录，`default` 回到 owner-chat；之后消息和 Esc 都作用于切换到的会话）`/activities`（0g-harness 上：每个轮次、后台命令和子 agent，以及由谁执行、由谁发起；命令或子 agent 由你的一轮启动时显示 `you`：0g-harness #12 起会指明是哪一轮；更旧的版本上，CLI 把只有你的轮次在运行时启动的那些算作你的）`/tasks [list|all|new <prompt>|show <id>|input <id> [next] <text>|cancel <id>|archive <id>]`（0g-harness：任务，即 agent 在自己的会话和工作区里运行的工作，最多同时四件，每次运行以一条记录结束：一个问题、一项要你做的操作，或一份报告；`input` 回答或引导一个任务，`next` 让它成为这次运行的下一轮；id 可以是能唯一确定任务的开头部分；需要你处理才结束的运行会打印在提示符上方。在其他框架上，不带参数的 `/tasks` 列出本会话的长任务）`/result [id]`（在 0g-harness 上也包括子 agent 的回答）`/cancel [id|all]`（停止任务或活动：不带参数时刹停本会话知道的所有进行中的工作，最新的在前；带 id 时只停那一个。用来刹停比自己的流存活更久的轮次：Esc 只取消当前连接发起的轮次。/result <id> 把一个 id 纳入本会话。在 0g-harness 上，id 可以是 `/tasks` 列出的任何任务，`all` 停止 agent 上正在运行的一切）`/inbox [all]`（0g-harness：agent 主动说的话：后台任务结束、提醒到点；不带参数：未读的，`all`：也包括已读的）`/schedules`（0g-harness：agent 给自己设的提醒）`/attach [path …|clear]`（0g-harness：随你下一条消息发送的文件和图片；拖进终端的文件，或粘贴的文件路径，不用这个命令也会随正在输入的消息发送：图片放在消息里，其他文件上传到 `~/inbox` 并在消息里写明名字；只有你的 home 目录、`/Volumes` 和临时目录下的文件才算，放在反引号里的路径保持为文本）`/files [inbox]`（0g-harness：agent 放在 `~/outbox` 里留给你的文件，或带 `inbox` 时你发送的、在它的文件收件箱 `~/inbox` 里的文件，不是消息 `/inbox`；只在容器本地，reset 后丢失）`/download <name> [path]`（0g-harness：把一个文件保存到当前目录或 `path`，从不覆盖已有文件：名字被占用时加 `-1`、`-2`……；`inbox/<name>` 指你发送的某个文件；最多 50 MiB）`/agentlog [n]` `/signatures [n]`（0g-harness：agent 以自己的身份签了什么，以及运行时拒绝了什么）`/startuplog [n]` `/back`（别名 `/unuse`）`/quit`（别名 `/exit`）。

在 0g-harness agent 上，agent 主动说的话（**通知**：后台任务结束、提醒到点）一到就打印在提示符上方（在命令或对话的一轮进行中时，等到下一个提示符），你不在时收到的内容在你进入会话时打印；`/inbox`（或 `/notices`）列出未读的通知，`/inbox all` 列出全部。会话在终端上运行时，agent 放在 `~/outbox` 里留给你的**文件**会自动保存到 `~/agentdna/<agentId>/outbox/<name>`：每一轮结束时和每 30 秒检查一次，保存后显示 `saved report.pdf → ~/agentdna/286/outbox/report.pdf`；终端支持 OSC 8 超链接时（iTerm2 3.1 及更高版本、WezTerm、VS Code、Ghostty、kitty、Windows Terminal、Konsole、Alacritty，以及 GNOME Terminal 等基于 VTE 的终端；设置了 `FORCE_HYPERLINK=1` 或 `0` 时由它决定），路径是可点击的 `file://` 链接。已有同名的不同文件时从不覆盖（新文件加 `-1`、`-2`……），同一个文件不会保存两次（`~/agentdna/<agentId>/outbox-saved.json` 记录保存过什么），超过 50 MiB 下载上限的文件跳过，并说明这一点。保存下来的文件大小（以及列出了哈希时的哈希）与 outbox 里的一致后，它会从 agent 的 outbox 里删除（`DELETE /v1/files/outbox/<name>`）；运行时没有删除路由的 agent 保留这些文件，由它自己的保留策略清理。`/files auto off` 对所有 agent 关闭这项功能（`/files auto on` 重新打开，不带参数的 `/files auto` 显示当前是开还是关）；关闭后，提示符统计新文件，`/files` 和 `/download` 照常可用。agent 记录的框架是其他框架时，`/settings others=…` 拒绝 0g-harness 的开关（`toolJobs`、`subagents`、`schedule`、`maxParallelToolCalls`、`modelImages`、`memoryExtract`、`memoryExtractMinMessages`、`memoryInlineBytes`、`memoryRecall`、`memoryTidy`、`webTools`、`webSearch`、`subagentModels`、`subagentDefault`）。它还在签名前检查 `webSearch`、`subagentModels` 和 `subagentDefault` 的格式，并拒绝既不是 agent 的模型、也不在它的 `subagentModels` 里的 `subagentDefault`（各项的作用见 sealed 的 `harness/README.zh.md`）。

`/reset` 和对话模型选择器所用的框架**由你**从 attestor 的列表里选，从不猜测。

### 评分票据罐

`proofs.json` 存放 `hello` / `call` 存下的 serve-proof；`rate` 消耗它们。规则：

- 有效期约 1 小时（截止时间由 sealed 服务器设定，在链上强制执行）
- 只能用一次；每个（agent，钱包）组合最多 5 张
- **只有 proof 的 `submitter` 指定的钱包能兑付**：票据罐泄露了，对别人也没用
- owner 不能给自己的 agent 评分

## 6. 退出码

| 退出码 | 含义 | 处理 |
|---|---|---|
| 0 | 成功 | — |
| 1 | 未知错误（包括 NOT_IMPLEMENTED） | 阅读错误信息 |
| 2 | 用法错误（包括未知命令、错误的 flag、错误的 agent 引用、找不到 agent） | 按 `error.code` 区分 |
| 3 | **可修复的前提条件**（缺少 attestor URL、无法连接、需要钱包、`SETTINGS_CONFLICT`、`CREDENTIALS_CONFLICT`、`AGENT_NOT_READY`、`AGENT_NOT_RUNNING`、`RUNTIME_TOO_OLD`……） | 阅读 `error.remedy`，修复后重试 |
| 4 | 超时 | 稍后再查 |
| 5 | 认证 | 停止 |
| 130 | 在一次性命令的提问处取消（Ctrl-C；打印 `cancelled`） | — |

## 7. 示例

```bash
npx @0gfoundation/0g-agentdna                                    # shell：list、deploy、对话……
npx @0gfoundation/0g-agentdna 286                                # 直接进入 agent 286 的会话
npx @0gfoundation/0g-agentdna doctor                             # 部署前检查
npx @0gfoundation/0g-agentdna status 33                          # 一个 agent 的完整情况
npx @0gfoundation/0g-agentdna settings 286                       # 显示配置
npx @0gfoundation/0g-agentdna settings 286 model=glm-5.3 thinking=high   # 修改模型和思考深度
echo "$GITHUB_TOKEN" | npx @0gfoundation/0g-agentdna cred 286 set github preset=github   # 给 agent 一个 GitHub token
npx @0gfoundation/0g-agentdna cred 286 connect linear https://mcp.linear.app/mcp   # 给 agent 连接一个 MCP 服务器
npx @0gfoundation/0g-agentdna list --mine --phase failed --json | jq -r '.data[].sealId'   # 脚本用法
```
