# 运行代理 API

[English](./OPERATORS.md)

NFT owner 可以为已铸造的 agent 指定一个运行 operator。operator 用自己的钱包
创建、充值、acknowledge 和控制沙盒。NFT、设置和凭据集仍由 owner 管理，
不需要修改 sandbox 协议或合约。参见 [SDK 使用流程](../sdk/typescript/OPERATORS.zh.md)。

`GET /operator?seal_id=0x...` 返回公开路由信息：`seal_id`、实时链上 `owner`、
`operator`（没有则为 null）、`version`、`expires_at`、`allow_recreate`，
以及 `checkpoint: null`。它不获取新的链头、历史 owner 或锚点 header。
返回值不是授权证明，运行请求受理和执行时会作权威校验。尚未 mint 时，它返回
deployment owner，operator 为 null，保留已有 owner 生命周期和 retry 请求。
不返回 owner 签名、凭据或容器证明材料。

仅授权写入需要 `GET /operator?seal_id=0x...&checkpoint=true`；它返回同样的摘要，
以及新的块末 `checkpoint: {number, hash}`。尚未 mint 时 checkpoint 仍为 null。
锚点取 latest 区块，不取可能早于一次所有权往返的旧 confirmed 区块。

`PUT /operator` 接收 `{seal_id, signed_message_b64, signature}`。当前 NFT owner
用 EIP-191 对确切 JSON 字节签名。签名指令包含：

| 字段 | 含义 |
|---|---|
| `domain` | `AgenticID.Operator.v1` |
| `chain_id`、`contract`、`seal_id` | 授权适用的环境和 agent |
| `owner` | 当前链上 NFT owner |
| `base_version` | GET 返回的版本，写入采用 compare-and-swap |
| `operator` | operator 钱包；null 表示撤销 |
| `allow_recreate` | 是否允许替换现有运行实例，默认 false |
| `expires_at` | Unix 秒，0 表示不限期 |
| `issued_at` | 写入前后五分钟内的 Unix 秒 |
| `checkpoint` | 带 `checkpoint=true` 的 GET 返回的非 null `{number, hash}`，必须纳入 owner 签名 |

PUT（包括撤销）只接受已 mint 的 agent。每次变更都由 owner 签署新指令，
并覆盖 GET 返回的原始 checkpoint。该区块 hash 必须仍在 canonical 链上，
块末 owner 必须与当前 owner 相同；此次写入要求 RPC 仍保留锚点区块的历史 owner 状态。
版本冲突返回 HTTP 409，需重新读取，不能静默
重试旧指令。每次成功写入（包括续期或撤销）都会退役当前运行实例并清除沙盒映射；
更新后需要由相应控制钱包重新创建实例。owner 的设置和凭据集保留。

PUT 查询一次历史 owner 后，记录与确切 proof、signature 和授权版本绑定的 checkpoint
准入事实。后续执行只检查该记录、canonical header 和实时 owner，不再查询历史 owner，
因此长期运行不需要 archive RPC。准入事实是存储记录，不是新的密码学证明。
已有带锚点的授权若缺少该记录，需要 owner 重新签署一次；无锚点的 legacy 证明
继续按保守规则处理，不附加未经签名的 checkpoint。
header 不可用或 RPC 落后返回 HTTP 503；hash 不符则拒绝授权。客户端不能因 503
退回缓存权限或 owner 身份，也不能自动重试并重新签署授权写入。

operator 用自己的钱包签署 create/start/stop envelope，并在签名对象顶层包含
`agentic_id`：`chain_id`、`contract`、`seal_id`、`operator_version`。
该对象参与签名，但不放进 provider 的创建 payload。允许首次 provision；替换现有
实例需要 `allow_recreate`。创建请求只能使用 agent 配置的 sealed 镜像及兼容的
推理凭据字段。owner 设置、凭据集写入、NFT 操作和 `/retry` 都不在委托范围内。

受理请求和执行任务时都会检查授权。启动记录分别保存 NFT owner、operator 和
授权版本。`/provision` 保留 v3 provider 证书、provider instance、固定容器公钥及
boot proof 校验；状态回报和容器凭据写回也会检查委托是否仍有效。
agent 密钥不会交给 operator 钱包。

授权变更与旧 boot 退役在同一个数据库事务内完成。旧沙盒 ID 写入持久清理队列，
包括撤销后才返回的在途创建结果。worker 每 60 秒重试一次；attestor 需要现有的
provider 管理权限来删除旧沙盒，失败项保留等待重试。清理只作用于捕获的旧 ID，
不会删除替换后的实例。
已受理的 create 完成时会重新检查 owner、授权和 boot generation；
不会仅因原始请求 envelope 已过期就丢弃创建结果。
授权本身的有效期仍会阻止绑定到期后才完成的 create；worker 不会为了完成操作而延长
owner 授予的权限。

实时 owner 检查会立即拒绝其他 owner 的授权。签名 checkpoint 把授权锚定到
一个所有权 epoch：对于锚定在区块 `H` 结束时的新授权，迟到的 `H` 或更早区块中的
Transfer 事件不会撤销它；`H` 之后的所有权转移在被 indexer 索引后使它失效。
A → B → A 往返后的撤权依赖 indexer 追上进度，实时 owner 检查本身无法识别这种往返。
此前没有签名 checkpoint 的旧存储证明继续按保守兼容规则处理，
不会为旧证明补加未经签名的 checkpoint。

有效期限制后续 operator 请求及 provision/status/writeback 权限续用，不是自动
停机时间。撤销不能抹除已经交给运行容器的 agent 密钥，仍需实际清理旧实例。
已经发给 provider 或已受理的写回可能完成。本功能不包含空闲调度、请求唤醒，
也不改变现有停止与状态持久化语义。
