# CONFIG_SURFACE.zh.md

owner 的配置通道:**每个 agent 一份文档**,由 owner 撰写,attestor 以不透明 blob 的形式
存储,再由各框架 adapter 放到自己框架实际读取的地方。本文是这条通道的参考:文档里有
什么、谁能写、它怎么到达运行中的容器、平台派生而非存储了哪些东西,以及一份文档起不来
时会发生什么。

它最初是四个 adapter 的**现状基线快照** —— 写它的原因是这四家对同样的问题("owner 能
不能换模型?""思考档位转让后还在不在?")给出的答案并不一致。那份快照保留在 §11,作为
历史:它是整套设计的证据,下面每一个决定都是对其中某一行的回应,脱开它就看不懂。

每条结论都标注了 file:line 出处。行为变更时,请在同一个 PR 里更新本文。

英文版:[CONFIG_SURFACE.md](CONFIG_SURFACE.md)。

## 1. 五个问题,现在的答案

一条配置只有五个问题都回答了才算描述完整。在 §11 的那个世界里,**五项里有三项完全
不存在**。

| 问题 | 为什么不能省 | 现在在哪回答 |
|---|---|---|
| **谁能写** —— owner / agent / 平台 | 没有它就无从判断该不该接受这次修改 | §5 —— 四个写入方,四种不同的权威 |
| **持久性** —— 持久 / 仅本次启动 / 从不存储 | 把"不追踪"和"绝不可追踪"混为一谈,密钥就是这样上链的 | §4(一个列)与 §7(凭据,它没有列) |
| **生效方式** —— hot / 重启 harness / 重建容器 | 决定一次修改要不要 reset | §8 —— 任何被接受的修改都会重启框架进程 |
| **值域** —— 合法取值 | 没有它就没有校验,agent 能把自己写进一个起不来的配置 | §2 的 `Doc.Validate` —— 刻意做得很薄,§2 说明了理由 |
| **绑定** —— 落到哪个文件的哪个键(按框架) | 值最终写在哪 | §6 的 `RenderSettings` —— 唯一仍然按框架区分的一步 |

## 2. 这份文档

`settings.Doc`(`internal/settings/settings.go:35`)就是 owner 能写的全部词汇表:

| 字段 | 含义 |
|---|---|
| `provider` | 谁来服务这个模型。`inference.ZGComputeProvider` = `"0g-compute"`(`internal/inference/zgcompute.go:109`)表示**由平台**提供 endpoint;其他任何取值都指向一个自带接线的框架内置 provider |
| `model` | 模型 id,按该 provider 自己的拼法 |
| `thinking` | owner 的推理深度偏好,取自 `settings.Levels` = `{low, high, max}`(`settings.go:52`) |
| `framework` | 该框架自己的旋钮 —— `json.RawMessage`,不透明(`settings.go:45`) |

`framework` 的不透明是刻意的,而且同时在三处承重:平台不解析它,attestor 根本不知道它
存在,SDK 也只把它映射成一个无类型成员。于是**扩充词汇表 ——** 给某一个框架加一个旋钮
**—— 只是一个 adapter 的改动**,而不是横跨三个代码库的 schema 迁移。平台的保证只覆盖那
三个具名字段;overlay 里的键是 owner 与那个 adapter 之间的事,并不承诺能扛过框架升级。

可扩展性还往上多走一层:SDK 的 `SettingsDoc` 带索引签名,会把不认识的顶层字段原样透传,
这样**旧客户端在一次 read-modify-write 里不会抹掉新设置**
(`sdk/typescript/src/Settings.ts`)。Go 侧刻意反过来 —— `settings.Doc` 是固定成员,不认识
的就丢掉 —— 而这之所以安全,只因为**容器从不把文档写回去**。唯一的例外是迁移用的 seed
(§10),它只带一个恢复出来的 pin。

**校验刻意做得很薄**(`Doc.Validate`,`settings.go:98`):

- `model` 为空是唯一的致命错误,因为有两家在缺 pin 时 `Start` 硬失败
  (`framework/prime/spawn.go:78`、`framework/dsh/spawn.go:77`),另两家只告警然后无模型
  运行(`framework/openclaw/spawn.go:63`、`framework/hermes/spawn.go:273`);
- `thinking` 必须属于 `Levels`,大小写不敏感;
- `framework` 必须是合法 JSON,仅此而已。

**router 目录里没有的模型不会被拒。**那份目录只覆盖 0g router,`anthropic/claude-…`
本来就不在里面;拒绝未列出的模型等于把 owner 锁死在 `0g-compute` 上。CLI 在签名前会跑
同样的检查,好让 owner 立刻知情,但那只是**建议性**的 —— 调用方可以绕开 CLI,所以真正
做决定的是容器这一侧(`sdk/typescript/src/cli/commands/settings.ts`)。

空 blob 解析成空文档,不是错误:那是一个还没人配置过的 agent,是合法状态
(`Parse`,`settings.go:71`)。

**推理凭据不在这份文档里** —— 见 §7。

## 3. 平台派生、且从不存储的东西

`settings.Resolved`(`settings.go:56`)是 `Doc` 加上平台为这次启动算出来的一切:
`Facts`、`Endpoint`、`APIKey`。adapter 只看得到 `Resolved`;没有任何东西会把它存下来。

`settings.Resolve(ctx, doc, apiKey)`(`settings.go:123`)调用
`inference.Resolve(provider, model)`(`zgcompute.go:121`),整条通道能成立的那个拆分就
在这里:

| | 是什么 | 什么时候拿得到 |
|---|---|---|
| `inference.ModelFacts`(`zgcompute.go:66`) | 关于**模型本身**、与谁来服务无关的事实:上下文窗口、输出预算、是否接受 `reasoning_effort`、以及这些是否来自实时目录 | 总是 |
| `inference.Endpoint`(`zgcompute.go:91`) | **平台**才需要提供的接线,因为框架自己没有内置:wire format、base URL、其客户端读取密钥的环境变量名 | 仅当 `provider == "0g-compute"`;否则为 `nil` |

即便是 native provider,也仍然按 model id 查一次 router 目录 —— 同一个模型通常也列在那
里 —— 这样在 router 之外也能施加推理上界(`zgcompute.go:117-120`)。

**这个拆分不是美化。**facts 与 endpoint 过去共用一个结构体、挂在同一个
`provider == "0g-compute"` 判断后面,于是选了 native provider 就连**推理上界**一起被悄悄
跳过了。hermes 与 dsh 都出过这个 bug(`zgcompute.go:62-65`、
`framework/dsh/settings.go:147-154`)。拆开它正是 native provider 今天仍然拿得到上界的
原因,并且有专门的回归测试(`internal/settings/settings_test.go`,
`TestNativeProviderStillGetsBoundedReasoning`)。

### 3.1 `Effort()` 有三种结果,任何两种都不能合并

`Resolved.Effort() (level string, decided bool)`(`settings.go:156`):

```
("high", true)   施加这个档位
("",     true)   清除任何档位 —— 目录说明该模型拒绝 reasoning_effort,
                 发过去就是硬 400
("",     false)  原样保留 —— 目录不可达或没有该模型,平台什么都不知道
```

把"不知道"折叠成"清除",意味着一次目录故障就会把 always-thinking 模型的上界剥掉,
而它随后会无休止地推理、永远写不出回复 —— 在 glm-5.3 上实测:十分钟内 23k 字符的推理、
零可见输出、流被上游杀掉;而 `reasoning_effort=low` 约 2.5 分钟给出完整回复
(`zgcompute.go:69-77`)。通道的第一版里,一次对抗式评审正是复现了这个问题;钉住它的
测试是 `TestCatalogOutageDoesNotDecide`。

另外两条规则也折叠在这里:

- 目录标记为 thinking、但 owner **没有**表达偏好的模型,仍然会拿到 `low` —— 参数缺席
  是"无界",不是"中立";
- owner **确实**表达了偏好时,即便目录故障也照样施加。档位落进框架自己的 thinking 旋钮,
  而每个框架都会用自己的模型元数据决定它是否上线;**尊重一次明确的选择,好过因为一次
  故障把它丢掉。**

`inference.NormalizeEffort`(`zgcompute.go:137`)是共用的归一:`medium`/`minimal` 降为
`low`,未知值归一为"未设置",而 `max` 在 owner 明确要求下原样放行 —— 在 0g router 上
实测两次,glm-5.3 在 `max` 下即便面对琐碎提示也会推理到超过 router 约 600s 的流截断,
所以 CLI 在选择时告警,平台则**放行 owner 的选择而不是替他二次判断**
(`zgcompute.go:143-149`)。

### 3.2 `PersistableMaxTokens()`,以及"解析结果一律不存"的由来

`Resolved.PersistableMaxTokens()`(`settings.go:180`)返回目录给出的输出预算,或者 `0`
表示"什么都别写",闸门是 `ModelFacts.CatalogSourced`。名字启发式的兜底值是
`inference.HeuristicOpenAIMaxTokens = 8192`(`zgcompute.go:160`);在目录故障期间被写进
磁盘,它此后看起来就永远像是手工设定的,把一个推理模型"思考+回复"的共享预算饿成永远
空的回复 —— agent 404 线上实测,三次约 6 分钟的对话,`textLen=0`
(`framework/prime/modelsjson.go:28-36`)。

那次事故就是 `Resolved` 每次启动重算、且哪儿都不存的原因:**存下来的副本会过时,然后
与算出来的值互相打架**(`settings.go:11-15`)。

## 4. 文档存在哪,怎么到达容器

```
存   attestor,deployments.settings(JSONB),和 `framework`、`sandbox_id` 放在一起
     (attestor/crates/shared/src/schema.sql:141)
送   /provision 的响应,用**与 agent_seal_priv 同一个**容器公钥做 ECIES 加密
用   manager PreStart → adapter.RenderSettings,在**每一次** spawn 之前
```

**为什么走 `/provision` 而不是沙盒 env。**owner 签名的沙盒信封里的 env 只在容器
**create** 时提供;`start` 不带 env,所以 resume 起来的容器会完全没有配置。`/provision`
每次启动都会跑,resume 也一样,这就是文档搭上那条**本来就在运送 seal key** 的通道的原因
(`attestor/crates/api/src/routes/provision.rs:12-16`、
`internal/provision/provision.go:38-47`)。思考档位过去以 `SEAL_OWNER_THINKING` 搭
create 时的 env,现在不再如此(`sdk/typescript/src/AttestorClient.ts` 的 `sandboxEnv`)。

**attestor 从不往里看。**它保存字节、把字节交给容器、把守访问 —— 从不解析、不校验、
不记录内容,`routes/settings.rs` 里也没有任何标识符提到某个 settings 字段。正是这个性质
让词汇表可以不改 attestor 就扩充;那个文件的头注释写明了:不要拿它去换一个"更漂亮的"
类型化 API(`attestor/crates/api/src/routes/settings.rs:5-12`)。

**文档在静态存储上没有加密。**`deployments.settings` 是一个普通的 JSONB 列;ECIES 只
作用于传输,加密给容器公钥。真正保护它的是"除了 owner 和容器,它不离开 attestor":
该字段是 `skip_serializing`(`attestor/crates/shared/src/types.rs` (`Deployment`)),所以
`GET /deployment/:seal_id` 不带它,`/deployments` 的 owner 层也刻意省略它
(`routes/deployments.rs` (`OwnerDeployment`)),而 `GET /settings` 需要 owner 签名(§5)。这一点重要,
因为不透明的 `framework` 段是 owner 自由撰写的文本 —— **owner 粘进去的字面密钥没有任何
东西会剥掉**(`framework/prime/modelsjson.go:53-59`)。

**解密失败的 settings blob 会被记录并丢弃,而不是致命错误**
(`internal/provision/provision.go:53-56`)。**无配置也能开机,好过拒绝开机。**

**启动路径不校验 owner 签名。**容器从 `/provision` 响应里取走文档,凭的是那次调用本身
已经完成的证明链,而不是对文档本身再验一次 owner 签名。那条"把 owner 对这次变更的签名
一并存下,让值自带证明、而不是因为 attestor 这么说才可信"的设计草案**没有落地**(§12)。
这一带唯一带签名落库的东西是容器自己的 seed 消息(§10),而那是 agentSeal 签的,不是
owner。

## 5. 谁能写

| 写入方 | 入口 | 权威 | 是否持久 | 何时生效 |
|---|---|---|---|---|
| owner | `POST /settings`(attestor) | EIP-191 签 `AgenticID.Settings.v1:0x<sealId>:<ts>:<base version>:<sha256 hex>`;±300s;签名者与**链上实时 owner** 比对 | **是** | 下次开机 |
| owner | `POST /_seal/settings`(容器) | EIP-191 签 `0GSealSettings:0x<sealID>:<ts>:<audience>:<sha256(body)>`;同样比对实时 owner | 否 | 立即 |
| agent | `POST $SEAL_SIGN_SOCK/settings` | 0600 的 unix socket **本身就是**凭据 | 否 | 立即 |
| 容器 | `POST /settings/seed`(attestor) | agentSeal 签名;只能落在从未配置过的行上 | 是,仅一次 | 仅迁移用(§10) |

读与写对称。`GET /settings?seal_id=…` 带同样的 owner 签名、只是不含 digest —— 读的消息
形式就在 base version 处结束,因为没有 body 可绑定
(`attestor/crates/shared/src/auth/settings.rs` (`owner_read_message`)、`routes/settings.rs` (`ReadParams`))。这是读到
这份文档的唯一途径。

### 5.1 持久路径 —— attestor

签名覆盖的是文档的 **digest** 而不是文档本身,因为被签的声明搭在 HTTP header 上:header
必须短且是 ASCII,而文档可能很大、可能非 ASCII(SDK 的 `btoa` 是 Latin-1 —— 中日韩字符
直接抛异常,`"café"` 编出来的字节和被签的不是同一串,最后表现为一个莫名其妙的
"signer mismatch")。attestor 对 body 里 `settings` 那一段**原样到达的字节**做哈希
(`serde_json` 的 `RawValue`),绝不用重新序列化的结果 —— 那样键序就成了 attestor 的而不是
签名者的(`auth/settings.rs:36-39`、`types.rs` (`ContainerReportStatus`))。

签名者要与**从链上实时读出**的 owner 比对,而不是索引出来的 `owner` 列 —— 索引滞后会让
卖家在卖掉 agent 之后还能继续配置它。mint 之前链上没有 owner,那时 `/deploy` 记录的
部署者是唯一已知权威;RPC 出错则**失败关闭**(`routes/settings.rs` (`authorize_owner`))。与
`lifecycle_auth` 同一条规则。

**每一次写都是 compare-and-swap。**签名消息里的 `base version` 是写入方编辑前读到的版本
(0 表示"我认为还没有文档"),比较发生在 `UPDATE` 内部,所以两个并发写入方不可能同时
成功(`routes/settings.rs` (`handle`)、`crates/shared/src/repo.rs` (`set_settings`))。base 过期返回
HTTP 409,并带上当前版本。一个字段同时堵上三个洞:被截获的请求无法重放来恢复一份已被
取代的文档,两个客户端无法互相静默覆盖,没读过就写的客户端无法盲写覆盖它没见过的文档。
SDK 抛 `SettingsConflictError`,并**刻意不重试** —— 盲目重放同一次编辑正是别人的改动
消失的方式(`sdk/typescript/src/Settings.ts`)。

`settings_version` 既是那个 CAS 令牌,也是被接受的写入次数;它对内容一无所知
(`schema.sql:161`)。客户端也可以在请求体里回显一份 `base_version`;一旦回显,它必须与
被签的那一份一致 —— **被签的消息才是权威**,不一致就是 400,而不是悄悄采信其中一个。

这里写入的东西**下次开机**才到达 agent,不是现在。CLI 就是这么说的:
*"written — version N. The container applies it on its next boot (reset to apply now)."*

### 5.2 热路径 —— 容器

`POST /_seal/settings` 存在的意义,就是让"换个模型、换个思考档位"不再需要重建容器
(`internal/proxy/settings.go:54`);同一路由上的 `GET` 返回当前生效的文档,好让 owner
先读后写。

POST 的签名还额外绑定了请求体的 `sha256`,作为被签消息的第五个字段。没有它,签名只证明
**谁**在调用,任何能在途中改动请求的东西都可以保留一个有效签名却换掉文档
(`internal/proxy/proxy.go:402-407`)。请求体上限 256 KiB
(`internal/proxy/settings.go:18`)—— 面向 owner 的路由上做无界读取是最容易的一种拒绝
服务。

`main.go` 注册的 applier(`main.go:709`)按固定顺序做三件事:换掉生效中的文档、渲染它、
重启框架进程 —— **并且渲染失败时把替换回滚**,这样一份渲染不出来的文档永远不会变成下次
崩溃重启会捡起来的那份。校验不过的文档在任何东西被应用之前就被拒,所以**一次无法生效的
推送不可能把 agent 搞下线**。

**这条路径不持久化。**它改的是这个容器运行所依据的文档;attestor 那份原封不动,所以
重建之后回到的仍是 owner 最后通过 §5.1 写下的东西。

### 5.3 agent 自己的杠杆

`POST $SEAL_SIGN_SOCK/settings` 搭的是 agent 本来就在用的那个 socket(注册对外服务、
获取 agentSeal 签名)。它只在容器内部通过 0600 的 unix socket 可达,所以 agent 进程是
唯一可能的调用者,也就不涉及任何签名 —— **socket 本身就是凭据**
(`internal/proxy/sign.go:90`、`internal/proxy/settings.go:148`)。

agent 只能改 **`thinking`,别的都不行**。处理器对 body 做严格的单字段解码
(`DisallowUnknownFields`),带任何其它键就以 403 拒绝,并在错误里点名 owner 通道 ——
**响亮地拒,不是悄悄丢弃**,让 agent 学会边界在哪,而不是往里重试
(`internal/proxy/settings.go`,`handleAgentSettings`)。文档其余部分取当前生效的那份:
agent 问不到的部分不归它。

只靠"会话级持久性"是不够的边界,收窄范围是对 PR #164 评审演示的洞的修复:不设范围的
覆盖让 agent 能改 `provider`/`model` —— owner 的钱和路由 —— 还能整段替换 owner 的
`framework` 节,有效期是容器余下的整个生命,而容器可以活很久。这条路径存在的理由是
"这个任务我想深一点";那是一个字段,socket 就只收一个字段。

同样的校验、同样的渲染、同样的重启 —— 但**什么都不持久化**,响应里明说
(`"durable": false`)。钱和资产都是 owner 的。结构性的后果是
**agent 没有能力把自己配置成起不来的状态**,而 agent 3586004 正是手工编辑框架配置把自己
砖了的(`internal/proxy/settings.go:120-129`)。如果 agent 那份文档渲染失败,`main.go`
会把 owner 的重渲染回去,免得一次被拒的尝试留下半应用的框架配置(`main.go:726-734`)。

## 6. 各框架在哪读它 —— `RenderSettings`

`framework.Framework` 只多了一个方法(`internal/framework/framework.go:180`):

```go
RenderSettings(ctx context.Context, s settings.Resolved) error
```

它把文档放到**这个**框架读取的地方。它是整条通道里唯一无法共用的部分,因为只有 adapter
知道自己的方言。它在每次 `Start` 之前、以及每次被接受的推送之后运行,于是**一个在 agent
铸造之后才发布的修复,会在它下次开机时到达它**,而不是只停在 mint 时刻。

**平台依赖的两条规则**(`framework.go:169-179`):

1. **幂等。**同样的 `Resolved` 进去,磁盘上同样的字节出来。watcher 每 30 秒哈希一次磁盘
   状态(`internal/watcher/watcher.go:36`);不确定性的渲染会让每一个 tick 都报漂移。
2. **平台的值胜出。**先铺 owner 那份不透明的 `framework` overlay,**再**把平台自己的键
   写在它上面 —— endpoint、推理上界、输出预算,以及任何凭据或每次启动生成的 token。
   **是顺序、而不是排除清单**,在阻止 overlay 关掉有界推理、或钉死一个目录后来改掉的
   wire format;而且以后新增平台键时这条规则依然成立。

| | 文档落到哪 | overlay 怎么处理 |
|---|---|---|
| openclaw(`openclaw/inference.go:55`) | `~/.openclaw/openclaw.json` | 顶层深合并;`gateway` 被丢弃 —— 它携带首次 Start 写入的每次启动凭据,顺序保护不了它 |
| hermes(`hermes/spawn.go:174`) | `~/.hermes/config.yaml` | 深合并,再把五个平台键写在上面:`model.{default,provider,base_url,api_key}` 与 `agent.reasoning_effort`;文档不再提供时,三个接线键会被**清除**,否则 hermes 会继续拿上一次启动的 key 去拨上一次启动的 endpoint |
| prime-agent(`prime/modelsjson.go:132`) | `~/.prime/agent/models.json` **以及**桥的环境 | 泛型 JSON 合并,平台键在**两条路径上都**覆盖其上;框架内置 provider 且没有 overlay 时干脆不写文件,并删掉遗留的旧文件 |
| dsh(`dsh/settings.go:161`) | 只有桥进程的环境 | 一份有类型的旋钮白名单(`toolJobs`、`maxParallelToolCalls`);这个框架根本没有配置文件可渲染 |

dsh 是有意思的一个:DSH 自己的 `settings.yaml` 由 `@deepseek-ai/dsh-settings-file` 提供,
而桥**刻意不挂载**它 —— 它的热加载会让 agent 的一次编辑当场往活进程里注入任意
`baseURL`/`apiKeyEnv`。这个文件后来是作为本 adapter 自己的 pin 持久化存储活下来的;
有了 settings 文档做 pin 的归宿,它就没有用途了 —— 没有东西写它、没有东西读它,而那个
插件依然没被挂载(`dsh/settings.go:15-34`)。

有三处细节值得带着走,每一处都是一道疤:

- **openclaw 会修复损坏的配置,而不是死在上面**(`openclaw/inference.go:101`)。解析错误
  过去是终局且自我延续的:`Start` 在渲染不成功时拒绝运行,而没有任何东西会在下次开机
  修好那个文件。过去那个上链角色顺带做了这件修复 —— 每次开机从链上整份重写;既然现在
  渲染拥有这个文件,修复也归渲染。读不出来的字节被挪到
  `openclaw.json.corrupt` 留存,而不是删掉。
- **overlay 是深合并,绝不做浅层赋值**(openclaw 与 hermes 里的 `mergeInto`)。浅层赋值
  曾让一个只带 `model: {temperature: 0.2}` 的 overlay 替换掉整个 `model` 段、把 pin 抹空。
  openclaw 还额外把 overlay 的值**深拷贝**进来:别名共享曾让平台自己的键透过与"已应用
  overlay 记录"共享的 map 被写入,于是下次开机那轮"撤回已删除的 overlay 键"把平台自己
  的推理上界撤掉了(`openclaw/inference.go:149-156`)。
- **overlay 绝不能有能力把开机搞挂。**dsh 的 `parseKnobs` 对 overlay 出错的每一种方式都
  尽力而为 —— 类型不对、越界、根本不是对象 —— 因为 `RenderSettings` 是从 `PreStart` 在
  **每一次** spawn 前跑的,所以这里报错不是"一次被拒的推送",而是**一个起不来的 agent**,
  而且会一直起不来,因为导致它的那份文档正是 attestor 存着的那份
  (`dsh/settings.go:76-85`)。

dsh 的旋钮集合是白名单而不是透传,原因很具体:`workspaceContext` 会被识别并**拒绝**,
因为它把一个 agent 可写、且不属于任何角色的文件(`~/.dsh/AGENTS.md`)喂进系统提示。
那是**平台边界的动作,不是编排偏好**,owner 的旋钮不该能做这件事(`dsh/settings.go:46-57`)。

## 7. 凭据

推理 API key 是 `Resolved.APIKey`(`settings.go:66`):它从容器环境到来,从不属于 `Doc`,
也不在任何地方持久化。它到达各框架的方式依然不同,而这**不是可以统一的** —— 那就是各框架
客户端实际读取的地方:

| | 密钥怎么到达框架 |
|---|---|
| openclaw | 引用式:配置里放 `{source: env, id: <VAR>}`,盘上只有变量**名**;`spawn.go` 把值导给子进程 |
| hermes | **明文写在盘上**的 `model.api_key` —— hermes 的 `custom` provider 声明了 `env_vars=()`,只从 `config.yaml` 读密钥;用 env 注入曾导致 router 线上 401,hermes 是裸着拨过去的(`hermes/spawn.go:163-170`) |
| prime-agent | 引用式:`models.json` 里放 `apiKey: "SEAL_MODEL_API_KEY"`(`prime/modelsjson.go:63`),值在桥的 env 里 |
| dsh | 只在桥的 env 里 —— 并且**刻意不放进**那个确定性、会被记录、每次启动重建的 `settingsEnv` 切片,这样渲染出来的环境可以被比较和记录而不必碰密钥(`dsh/settings.go:181-187`) |

`config.yaml` 还是上链角色的时候,hermes 把密钥写盘需要在捕获路径上加一道
`stripSecrets`。两份 `stripSecrets` 都随角色一起没了:**现在没有任何东西会捕获这些文件,
所以密钥上不了链,出口也不需要剥离**(§11.1)。

容器存在**之前**密钥停在哪,本次改动并未触及,但仍值得精确说明,因为 grep 会误导。没有
`api_key` 这个列,这个字符串在 attestor 的 crate 里一次都不出现:密钥藏在 owner 签名的
沙盒信封里那个不透明的 `env` map 中(SDK 在 `sandboxEnv` 里写 `env.API_KEY`,
`sdk/typescript/src/AttestorClient.ts`),整个信封被克隆进部署 job 的 payload,而 job 行
在进 Postgres 之前用 `job_key` 做 AES-GCM 封装
(`attestor/crates/shared/src/jobs.rs` (`seal`))。`done`/`failed` 的行按
`ATTESTOR_JOB_RETENTION_SECONDS`(默认 3600)清扫(`attestor/crates/shared/src/jobs.rs` (`sweep_expired`)、
`attestor/.env.example:168`)。所以 secret 这一档的准确含义是
**加密、限期、绝不持久**,不是"哪儿都不存"。任何把它变成无限期行的改动都是暴露面的实质
变化,需要的是**清除方案**,而不只是加密方案。

## 8. 修改何时生效

任何被接受的修改都会重启框架进程。没有阶梯:

- `manager.StartParams.PreStart`(`internal/manager/manager.go:122`)在**每一次**
  `adapter.Start` 之前立刻跑渲染 —— 首次、`Reload`、崩溃重启一视同仁。`main.go:694` 把它
  指向 `adapter.RenderSettings(ctx, settings.Resolve(ctx, live.get(), apiKey))`。
- 两条推送路径都是先渲染再调 `manager.Reload`,而 Reload 就是 Stop+Start。
- `framework.Reloadable` 依然只是声明、依然没有任何消费方
  (`framework.go:210`、`prime/prime.go:360`)。
- sealed 永远不自行触发容器重建:那要花钱,是 owner 的决定。

**为什么用 `PreStart` 而不是 `RuntimeContext`。**`RuntimeContext` 在首次 `Start` 时被捕获,
此后每次重启原样重放,所以**任何搭在它上面的东西都被冻结在容器的一生里**,运行期做的修改
会被下一次崩溃重启静默还原。这正是 owner 思考档位曾经遭遇的事 —— 它过去就搭在
`RuntimeContext.OwnerThinking` 上(`manager.go:106-119`)。每次 spawn 都重渲染还让配置
文件**自我修复**:那些字节归平台所有,所以 agent 弄坏的文件会被重建,而不是让 agent 起
不来、直到有人 reset 容器。

> `RuntimeContext.OwnerThinking` 已**删除**;它原来的位置上留有一段注释
> (`framework.go`,RuntimeContext),记录为什么不许再有同类字段回来:凡是放进这个
> 结构体的东西都在开机时冻结、每次重启原样重放。

prime 的桥仍然读一个**名叫** `SEAL_OWNER_THINKING` 的环境变量
(`prime/bridge/bridge.mjs:64`)。那个名字是桥自己的契约,而桥是随 sealed 二进制一起发布
的;变的只是**值的来源** —— 从部署时的沙盒 env 变成 owner 的文档,经由 `Resolved.Effort()`
(`prime/spawn.go:245-257`、`:376`)。prime 的逐条消息覆盖(`bridge.mjs:365`)没有变,
它仍然是全系统唯一真正"热"的配置变更。

## 9. 一份文档起不来时

危险的组合是:owner 推了一份会阻止开机的文档,**并且**容器被重建 —— 重建会抹掉容器自己
留的任何副本。有两家 adapter 在缺少可用 pin 时启动硬失败,所以这个组合会让 agent 下线
且无处可退。因此 last-known-good 活在服务端,占三个列
(`attestor/crates/shared/src/schema.sql:152,172,184`):

| 列 | 存什么 |
|---|---|
| `settings_last_good` | 最后一份容器**真正开机跑起来过**的文档 |
| `settings_confirmed_version` | `settings_last_good` 对应的版本 |
| `settings_attempts` | 当前这份未确认文档已经被投递给多少次开机 |

**提升(promotion)**发生在 `running` 报告上,并且只以版本为准:
`settings_confirmed_version < settings_version`(`routes/status.rs` (`handle`)、
`crates/shared/src/traits.rs` (`promote_settings_last_good`))。这让它在构造上幂等 —— 5 分钟一次的心跳会重复同一份
报告,而它**绝不能**给一份没有任何开机跑过的文档背书。早先的规则是从"容器轨道还不是
`Confirmed`"去推断"这是开机后的首份报告";但有若干路径会在没有任何开机的情况下把一个
仍在运行的容器从 `Confirmed` 降级,于是那个推断给从未跑过的文档发了背书。

另有两个条件,都是关于**那个开机中的容器实际被投递了什么**(`traits.rs` (`promote_settings_last_good`)):

- `settings_attempts >= 1` —— 至少有一次开机被投递过这个版本。**在 agent 运行期间推送的
  文档并没有**(写入会重置计数器,而容器不会重新 provision),所以五分钟后的心跳不能给它
  背书。
- `settings_attempts = 1`,除非根本没有 `settings_last_good` —— 过了第一次尝试,
  `/provision` 改投 last-known-good,于是此时的 `running` 报告说明的是**兜底那份**能跑,
  与当前文档无关。在它上面提升,等于用正在失败的那份覆盖掉唯一已知可用的那份,而且再也
  回不去。

**兜底(fallback)以重复尝试为准,而不是以错误报告为准。**当前版本未确认时,`/provision`
会给 `settings_attempts` 加一,过了第一次就改投 `settings_last_good`:推送后的第一次开机
总是拿到 owner 当前的文档(读取时就偏好 last-known-good 的话,新文档永远没机会被确认),
而一个反复回来却从不上报 `running` 的容器,拿到的是最后一份能跑的
(`routes/provision.rs` (`settings_for_boot`))。记录尝试失败时按"第一次尝试"处理并投当前文档 ——
**这套簿记不能有能力让开机失败**。

"错误报告即回滚"试过,而且是错的;`routes/status.rs` 现在在 `Error` 分支上对文档不做
任何事(`routes/status.rs` (`handle`)):错误报告在每一次失败心跳上都会到达,原因可以是任何东西,
于是在那里回滚使得**agent 不健康时就落不下任何配置变更** —— 而那恰恰是 owner 最需要落下
它的时候。

一次写入或一次提升都会把 `settings_attempts` 清零,所以新文档总是欠它自己的第一次尝试
(`traits.rs` (`flip_stale_heartbeats`)、`:467`)。

## 10. 迁移:通道出现之前铸造的 agent

在通道出现之前铸造的 agent,它的 pin 存在一个**已经没有任何 adapter 声明**的上链角色里。
Bootstrap 的 Phase C 会把每一个角色在 `Roles()` 之外的链上条目交给 `HandleLegacy`
(`main.go:572-581`),而可选的 `framework.LegacySettingsSeeder`(`framework.go:321`)是
adapter 把恢复出来的东西交还给平台的方式。`main.go:598-609` **仅在**下发的文档没有 model
时才去问 seeder —— 所以真实文档永远压过恢复 —— 并用 `report.SeedSettings`
(`internal/report/report.go:86`)把拿到的东西持久化。

这个顺序不是顺手的:uploader 会按 `Roles()` 重建链上条目列表并整份提交,所以**第一次漂移
提交就会丢掉那个已不再声明的配置角色**。若届时 pin 还没被读出来并持久化,它就没了。

`POST /settings/seed` 由 **agentSeal** 而非 owner 密钥签名,因为开机时没有 owner 在场。
attestor 因此把它当作严格弱于 owner 写入的东西,并加了三道闸
(`routes/settings.rs` (`handle_get`)、`traits.rs` (`set_settings`)):

- **只能 seed**,而且闸门是 `settings_version = 0`,而不只是 `settings IS NULL`:一旦
  存在过任何文档,这个能力就永久用尽,所以被截获的 seed 请求无法在 owner 配置过又清掉
  之后重新种回去;
- **幽灵容器** —— `agentSeal_priv` 由 `seal_id` 确定性派生,所以**这个 agent 曾经跑过的
  每一个容器**都持有它,孤儿容器也一样。签名证明的是密钥,不是容器,所以记录里没有
  `sandbox_id` 的行会被回 200 并忽略(与 `/status` 同一道闸;硬报错只会让一个
  fire-and-forget 的调用方不停重试);
- **重放** —— seed 消息不带 nonce,所以被截获的副本永远可验。**不永远的是它能做什么**:
  第一份文档,不管是谁发的,都会把这个能力花掉、直到这一行的生命终结;而在此之前的重放
  最多只能种下诚实开机本来就要种的那份。

**覆盖:四家 adapter 两个遗留来源都能恢复。**每家都实现了
`LegacySettingsSeeder`,既从各自退役的配置角色恢复 pin(openclaw `openclaw.json`、
hermes `config.yaml`、prime `models.json`、dsh `settings.yaml`),也从 mint 时的
`persona` 种子恢复——后者之所以必要,是因为 attestor 只 mint `framework` + `persona`
两个角色,一个从未漂移过的 agent 的 pin 只存在于种子里。这两个来源在真实链上不可能
共存(第一次写入配置角色的那笔漂移提交会整体重建数组、同时丢掉 `persona`),但每家
仍然显式排位(各自的 `legacySource` + `stashSeededPin`),让手工拼装的链得到确定答案
而不是 Phase C 顺序的掷硬币。半个 pin(只有 provider 或只有 model)什么都不恢复:
恢复结果会被持久化为 owner 的文档,存下半个文档会让之后每次启动都失败、还每次都压过
这条恢复路径。两条路径都不允许让启动失败——解析不了的条目只打日志,agent 继续用
attestor 已存的文档。

## 11. 之前:四家现状基线

这是通道所取代的那个世界 —— 保留它,因为它是证据,也因为同样这四列是看清这次改动到底
买到了什么最快的方式。**本节没有任何一句描述当前行为。**

| | openclaw | hermes | prime-agent | dsh |
|---|---|---|---|---|
| 配置文件 | `~/.openclaw/openclaw.json` | `~/.hermes/config.yaml` | `~/.prime/agent/models.json` | `~/.dsh/settings.yaml` |
| 上链的部分 | 仅顶层 `agents`、`auth`、`models` | 仅顶层 `approvals`、`model`、`terminal` | 整个文件 | 整个文件 |
| 白名单出处 | `evolution_paths.go` | `restore_paths.go` | `modelsjson.go`(`evoModelsJSON`) | `settingsyaml.go`(`canonicalSettings`)—— 四者现已全部删除 |
| 上链编码 | JSON | canonical JSON(盘上是 YAML) | canonical JSON | canonical JSON(盘上是 YAML) |
| 模型选择键 | `agents.defaults.model.primary`(`"<provider>/<model>"`) | `model.provider` + `model.default` | `providers.<name>.models[].id` | `llm-pi-ai.providers.<name>.models[].id` |
| 模型上链 | 是 | 是 | 是 | 是 |
| 思考档位键 | `agents.defaults.thinkingDefault` | `agent.reasoning_effort` | *(无 —— 仅环境变量)* | *(无 —— 仅环境变量)* |
| **思考档位上链** | **是**(在 `agents` 内) | **否**(`agent` 不在白名单) | **否** | **否** |
| 运行中可改档位 | 否 —— Start 时读取 | 否 —— Start 时读取 | **是,可逐条请求指定** | 否 —— 桥启动时固定 |
| owner 改档位的通道 | create 时沙盒 env 里的 `SEAL_OWNER_THINKING` —— 改它必须重建容器 | ← 同左 | ← 同左 | ← 同左 |
| API key | 环境变量引用 | **明文写在盘上**;捕获时剥离 | 环境变量*名* | 环境变量名 + `stripSecrets` |
| 声明的角色 | `framework`、**`openclaw.json`**、`workspace/`、`workspace/skills/`、`workspace/canvas/` | `framework`、**`config.yaml`**、`SOUL.md`、`memories/`、`skills/` | `framework`、`harness_state.json`、`APPEND_SYSTEM.md`、**`models.json`**、`skills/` | `framework`、`APPEND_SYSTEM.md`、**`settings.yaml`**、`skills/` |

这张表暴露出来的问题,以及它们的下场:

1. **同一项设置在不同框架下持久性不同。**思考档位在 openclaw 上链,在另外三家仅存在于
   环境变量,于是 openclaw 的 agent 转让后档位仍在,另外三家回落到部署时 env 给的值。
   **openclaw 才是那个异类**:思考档位属于 owner,而 owner 范围的状态不该随转让继承。
   **已解决** —— 做法是把配置移出链,而不是给另外三家补上。
2. **热切能力不一致,且没有被抽象。**prime 能逐请求换档位;这个能力长在它的桥里,不在
   任何平台接口上,别人无法复用。**依然如此**(§8)—— 但现在每个框架都有一条面向 owner
   的容器热路径,代价只是一次重启。
3. **模型完全没有面向 owner 的入口。**它在 mint 时定死,此后唯一的改法是 agent 手工编辑
   被追踪的配置文件 —— 无校验,且要重启才生效。**已解决**(§5)。
4. **没有任何东西校验 agent 的配置编辑。**reconciler 只负责捕获漂移并锚定,一次写坏的
   编辑会被忠实持久化,下次启动又把坏状态恢复回来。**已从结构上解决**:agent 的通道不
   持久化,而文件每次 spawn 都重渲染。
5. **版本 pin 的可改性取决于安装方式。**openclaw 与 hermes 在容器内安装(改 pin = 重启
   harness);prime 与 dsh 烤进镜像(改 pin = 换镜像 = 重建容器)。**未变** —— 它与这条
   通道无关。

### 11.1 iData 里少了什么,以及跟着被删掉的东西

| | 之前的角色 | 现在的角色 |
|---|---|---|
| openclaw | `framework`、`openclaw.json`、`workspace/`、`workspace/skills/`、`workspace/canvas/` | `framework`、`workspace/`、`workspace/skills/`、`workspace/canvas/`(`openclaw/openclaw.go:146`) |
| hermes | `framework`、`config.yaml`、`SOUL.md`、`memories/`、`skills/` | `framework`、`SOUL.md`、`memories/`、`skills/`(`hermes/hermes.go:121`) |
| prime-agent | `framework`、`harness_state.json`、`APPEND_SYSTEM.md`、`models.json`、`skills/` | `framework`、`harness_state.json`、`APPEND_SYSTEM.md`、`skills/`(`prime/prime.go:135`) |
| dsh | `framework`、`APPEND_SYSTEM.md`、`settings.yaml`、`skills/` | `framework`、`APPEND_SYSTEM.md`、`skills/`(`dsh/dsh.go:145`) |

**没有任何配置角色。**四家统一收敛成「读法 + 人格 + 记忆 + 技能」—— 这个共性以前被各家
形状各异的配置文件盖住了。

因为这些文件不再被捕获,当初为了"安全地捕获它们"而存在的机械也被整体删掉:各家的配置键
白名单、两份 `stripSecrets`、`healOpenclawConfig`、`backfillMaxTokens`。文件每次开机重渲染,
所以**没有东西可捕获,也没有东西需要补救**;agent 去编辑这些文件,下次渲染直接覆盖 ——
不需要闸门、不需要回滚、不需要巡检。`healOpenclawConfig` 尤其如此:它是一套用来修复
mint 时副本的形状识别启发式,而重渲染把它要修的那份副本一起取消了
(`openclaw/inference.go:18-30`)。

hermes 的 `approvals` 与 `terminal` 也一并离开,而且不是顺带。它们曾被标注为
"agent self-tuning",但 sealed 从未写过它们,而在无人值守的 TEE 沙盒里,审批策略**没有
人可以问**。它们是 owner 的旋钮,所以现在像任何 hermes 键一样搭那份不透明 overlay
(`hermes/spawn.go:290-293`)。

判断什么该上链的判据 —— 这次改动就是它的一次应用:**丢了能不能重填。**记忆重建不出来,
模型重选一次只要十秒。**分界线是这个不对称,不是"它算不算配置"。**

## 12. 考虑过但放弃的方案

保留在这里,免得下一个人重新推导一遍。前五条解决的都是"配置上链了但不该随转让继承";
把配置移出链之后,这个问题不再存在。

- **用 owner 公钥 + tokenId 派生的密钥加密设置** —— 唯一需要无人值守读它的是 TEE 而不是
  owner,且钱包侧解密(`eth_decrypt`)已被废弃。
- **第三种角色层级:"上链但属 owner、转让时重置"。**
- **sealed 开机检测到 owner 变更时重置 owner 范围的角色。**
- **一个小的上链 `settings` 角色。**
- **在巡检的捕获路径上校验 agent 的文件编辑** —— agent 的通道不持久化,这个需求本身
  消失了。
- **在 adapter 接口上加一个声明式的 `EffectOf(key) Hot | HarnessRestart | Rebuild`
  阶梯。**设计过,没有实现:今天任何被接受的修改都会重启框架进程(§8),而**只有一级的
  阶梯,是一份没人能因为漏填而做错的契约。**
- **把 owner 对文档的签名一并存下**,让容器能在开机时验签而不是信任 attestor(§4)。
  没有实现;容器信任的是 `/provision` 这条通道。
- **容器报错即回滚到 last-known-good** —— 实现过,后来被替换。错误报告在每一次失败心跳
  上都会到达,于是它让 agent 不健康时根本落不下配置变更。尝试计数器取代了它(§9)。

## 13. 尚未解决的缺口

- ~~迁移覆盖~~ —— 已关闭。四家都恢复两个遗留来源(退役配置角色 + mint 时的 persona
  种子),显式排位、有测试(§10)。
- **容器侧的两条推送路径都还没有客户端。**`/_seal/settings` 与
  `$SEAL_SIGN_SOCK/settings` 已实现、已有测试,但 SDK、CLI 与任何桥都没有调用它们,
  agent 圣经(`internal/platform`)里也没有提到那个 socket,所以 agent 无从得知这个杠杆
  存在。在客户端落地之前,可行路径仍是 §5.1 加一次 reset。
- **凭据通道仍然只有一条。**就是那个单数的 `API_KEY` 环境变量。一个干真活的 agent 迟早
  需要第二个凭据 —— 一个付费 API、一个 webhook secret —— 而它**没地方放**,于是它会写进
  文件;`memories/`、`skills/` 与人格文件**都是被追踪的角色**,凭据就这样加密上了 0g
  storage,**并在转让时一并交给下一任主人**。没有任何东西拦得住 —— 而那两份现已删除的
  `stripSecrets` 本来也只作用于那两个配置文件。**扫描不是解法**:散文里的密钥("我的
  key 是 sk- 开头那个")识别不可靠。解法是把凭据通道从一个变量扩成一张命名表,装在
  owner 签名的信封里、导出成环境变量,**让密钥有个比记忆更好的去处**。这一条同样适用于
  **推理密钥本身**:§7 把它放在框架进程 env(openclaw/prime/dsh)或 hermes 的
  `config.yaml` 盘上,而对一个 agent 有 shell、有文件访问的框架来说,"只在进程 env 里"
  不构成保密边界。真正的修法形状是"能用而不可见" —— #163 connections 设计给 OAuth token
  的待遇 —— 推理密钥还没有拿到这个待遇。agent 圣经里也该
  直说这个机制:**写进记忆的东西会随资产转让。**这是可观测性事实,不是行为指令。
- **owner 的不透明 overlay 是未经扫描的自由文本。**owner 把字面密钥粘进 `framework`,
  它就进了一个普通 JSONB 列,在 prime 上还会进到容器里的一个文件
  (`prime/modelsjson.go:53-59`)。没有东西剥它;唯一的保护是那个列和那个文件都既不公开
  也不上链(§4)。
