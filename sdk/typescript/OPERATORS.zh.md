# 运行代理方

[English](./OPERATORS.md)

NFT owner 可以为一个 agent 指定一个 operator，由它提供沙盒并支付费用。
operator 使用自己的钱包创建沙盒、向自己的 provider 余额充值、acknowledge provider，
并签署运行环境的生命周期请求。NFT、settings 和 credential set 仍由 owner 控制。
这不需要修改 sandbox 协议，也不授予 NFT approval 或全局管理员权限。

## Owner 配置与 operator 托管

```ts
import { AgentDNA } from '@0gfoundation/0g-agentdna';
import { parseEther } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

const owner = await AgentDNA.fromAttestor(attestorUrl, { account: ownerKey });
const operatorAccount = privateKeyToAccount(operatorKey);
const operator = await AgentDNA.fromAttestor(attestorUrl, { account: operatorAccount });

const ownerAck = await owner.ack();
if (ownerAck) await owner.waitForTransaction(ownerAck);
const { sealId } = await owner.agent.deploy(
  { name: 'Sage', description: 'a hosted agent' }, { wait: 'minted' },
);

// 模型和凭证由 owner 配置，operator 没有编辑权。
const { version } = await owner.agent.getSettings(sealId);
await owner.agent.setSettings(sealId, { provider: '0g-compute', model: modelName }, { baseVersion: version });
await owner.credentials.setModelKey(sealId, '0g-compute', inferenceKey, { push: false });
await owner.agent.setOperator(sealId, operatorAccount.address);

// operator 使用自己的 acknowledgement 和预充值余额提供计算资源。
const operatorAck = await operator.ack();
if (operatorAck) await operator.waitForTransaction(operatorAck);
await operator.waitForTransaction(await operator.deposit({ amountWei: parseEther('0.5') }));
await operator.agent.start(sealId); // 首次 provision，使用 owner 存储的 settings 和 credentials
await operator.agent.stop(sealId);
await operator.agent.start(sealId); // 恢复当前沙盒
```

mint-only deploy 不要求 owner 钱包持有沙盒预充值余额。
一次性 `deploy({ ..., sandbox })` 保持原有的 owner 付费行为；
operator 托管流程从 owner 已铸造的身份开始。

`start(sealId)` 会查询当前 sandbox ID。只要映射存在，就尝试恢复，即使实例未就绪
或显示 offline；遇到 `NOT_RESUMABLE` 会报错，不会隐式 reset 或再创建一个付费沙盒。
只有映射为空时才选择首次 provision。`start(sealId, sandboxId)` 仍可以显式指定沙盒，
`stop(sealId)` 也可以自动查询 ID。

operator 的 start/reset 可以传入 `sealedImage`、`framework` 等计算环境选项，
并遵守 attestor 的既有检查。它拒绝 `apiKey`、`sealedModelKey`、`sealedSecretEnv`、
`provider` 和 `keepStoredModelKey`：模型应先由 owner 通过 settings 与 credential API
配置。operator 调用不会补写默认 settings，也不会读写 owner 的 credential set。
owner 调用保留原有的模型密钥存储和默认 settings 初始化行为。

## 授权范围与更新

`getOperator(sealId)` 是公开查询，返回 `owner`、有效 `operator`、`version`、
`expiresAt`、`allowRecreate`，以及包含区块高度和 hash 的块末 `checkpoint`。
授权过期或 NFT 转移后，`operator` 为 `null`。尚未 mint 时，GET 返回 deployment
owner，operator 与 checkpoint 均为 `null`；已有 owner stop/reset/retry 流程仍然可用，
但写入 operator 授权必须等 agent mint 完成并获得 checkpoint。

```ts
const grant = await owner.agent.getOperator(sealId);
await owner.agent.setOperator(sealId, operatorAccount.address, {
  baseVersion: grant.version, // 可选；省略时先读取当前版本再签名
  expiresAt: Math.floor(Date.now() / 1000) + 86400, // 省略或 0：直到更换或撤销
  allowRecreate: true, // 默认 false
});
await operator.agent.start(sealId); // 更新授权会使原运行实例退役
await operator.agent.reset(sealId); // 替换已有运行环境需要 allowRecreate
await owner.agent.revokeOperator(sealId);
```

每次成功更新授权，包括续期、更换和撤销，都会使当前运行实例退役、清除 sandbox
映射，并通过持久化 outbox 安排清理旧沙盒。新 operator 不能接管旧 operator 的沙盒
或余额。更新后需要重新 provision。

写入会比较签名中的基础版本。并发修改会抛出 `OperatorConflictError`，SDK 不会
自动重试。operator 的生命周期签名还绑定 agent、chain、合约和授权版本，旧排队
请求不会因同一钱包被重新授权而恢复有效。执行前会再次检查授权；已经发送给
provider 的操作仍可能完成。

更新或撤销授权时，owner 的签名覆盖 GET 返回的原始 checkpoint。SDK 会拒绝不安全的
JavaScript 区块整数、格式不正确的 hash 和缺失 checkpoint，不会自行补造。
这需要 RPC 能提供 canonical 区块 hash 和历史 owner 查询。
锚定在区块 `H` 结束时的授权，不会被迟到的 `H` 或更早区块中的 indexer 事件删除；
`H` 之后的所有权转移在被 indexer 索引后使它失效。转出后又转回同一钱包的撤权
依赖 indexer 追上进度，实时 owner 检查本身无法识别这种往返。
没有签名 checkpoint 的旧存储证明按保守规则处理，不会给旧证明附加未经签名的锚点。

每次生命周期调用只解析一次 operator 身份和 deployment，并在该次请求内复用这些
数据来选择沙盒、规划仅 owner 可执行的模型操作。下一次调用会重新读取，
不跨调用缓存授权；API 和 worker 仍各自执行授权检查。

默认授权允许首次 provision 和正常起停；替换已有运行环境需要 `allowRecreate`。
NFT 转移、owner settings、credentials、clone、retry 和 operator 管理仍归 owner。
NFT 转移会使原 owner 的委托和启动授权失效。

## 容器证明与功能边界

operator 签署运行请求并支付沙盒费用，启动授权仍记录真正的 NFT owner。
`/provision` 保留 provider v3 certificate、已绑定容器身份与启动证明等检查，
operator 钱包签名不能替代这些证明。agent 密钥只加密给验证过的容器，owner 的
credentials 仍通过既有 provision 通道交付。

已受理的 create 完成时，worker 会重新检查 owner、授权和 boot generation；
不会仅因原始请求 envelope 已过期就丢弃创建结果。

本功能增加委托授权，不增加空闲调度或常驻唤醒网关。stop 保持现有语义，
不增加停机前最终状态同步，也不保证没有任务正在运行。应用需要在请求停机前
自行作出这些判断。
