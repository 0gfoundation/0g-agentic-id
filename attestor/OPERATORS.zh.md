# 运行代理 API

[English](./OPERATORS.md)

NFT owner 可以为已铸造的 agent 指定一个运行 operator。operator 用自己的钱包
创建、充值、acknowledge 和控制沙盒。NFT、设置和凭据集仍由 owner 管理，
不需要修改 sandbox 协议或合约。参见 [SDK 使用流程](../sdk/typescript/OPERATORS.zh.md)。

`GET /operator?seal_id=0x...` 只返回公开摘要：`seal_id`、实时链上 `owner`、
有效 `operator`（没有则为 null）、`version`、`expires_at` 和 `allow_recreate`。
不返回 owner 签名、凭据或容器证明材料。过期、已撤销或属于旧 owner 的授权无效。

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

每次变更都由 owner 签署新指令。版本冲突返回 HTTP 409，需重新读取，不能静默
重试旧指令。每次成功写入（包括续期或撤销）都会退役当前运行实例并清除沙盒映射；
更新后需要由相应控制钱包重新创建实例。owner 的设置和凭据集保留。

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

实时 owner 检查会立即拒绝其他 owner 的授权。indexer 处理 Transfer 事件时还会
撤销出让方授权，防止 A → B → A 后旧委托复活。indexer 延迟时，同地址往返后
新签的授权可能保守地被失效，需要在事件追上后重新签署。

有效期限制后续 operator 请求及 provision/status/writeback 权限续用，不是自动
停机时间。撤销不能抹除已经交给运行容器的 agent 密钥，仍需实际清理旧实例。
已经发给 provider 或已受理的写回可能完成。本功能不包含空闲调度、请求唤醒，
也不改变现有停止与状态持久化语义。
