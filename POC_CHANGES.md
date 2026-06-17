# POC: PlatformContext 重构变更摘要

## 目标

将 sealed 平台注入内容（身份、主权规则、能力机制、运行时约束）从三个独立 adapter 文件中的硬编码实现，重构为：
- **汇聚层**：`platform/context.go` — 框架无关的单一生成源
- **分散层**：`framework/openclaw/*.go` — OpenClaw 适配器，从 PlatformContext 取段写入对应文件

架构模式：Hexagonal Architecture (Ports & Adapters)

## 文件变更

### 新增

| 文件 | 说明 |
|---|---|
| `sealed/internal/platform/context.go` | **框架无关的 PlatformContext builder**（~350行）。定义 `RuntimeSnapshot`、`PlatformContext`、`Build()` 入口。生成 5 个段：Identity、Sovereignty、Capabilities、Constraints、Runtime |

### 修改

| 文件 | 变更 | 说明 |
|---|---|---|
| `framework/framework.go` | 扩展 `RuntimeContext` | 新增 9 个字段：AgentID、Owner、ChainRPC、ContractAddr、AttestorURL、Provider、Model、ZGComputeRouted、SealedVersion |
| `framework/openclaw/identitymd.go` | 重构 | 从硬编码 `buildIdentityFile(agentSeal)` → 接收 `identitySection string`（由 platform.Build 生成）。保留 header 保护和 marker 机制 |
| `framework/openclaw/soulmd.go` | 重构 | 从硬编码 `buildSoulSovereignty(agentSeal)` → 接收 `sovereigntySection string`。删除 ~180 行内容模板代码 |
| `framework/openclaw/toolsmd.go` | 重构 | 从 `upsertToolsMD(path, platformCaps)` → `upsertToolsMD(path, PlatformContext)`。合并 Capabilities + Constraints + Runtime 三段。删除旧 `platformCaps` 结构体 |
| `framework/openclaw/spawn.go` | 重构调用点 | 构建 `RuntimeSnapshot` → `platform.Build()` → 三个 upsert 调用。whitelist 数据从 `supportedOpenclawVersions` 填充 |
| `framework/openclaw/inference.go` | 新增 `isZGComputeRouted()` | 判断 provider 是否为 "0g-compute"（spawn.go 用于 RuntimeSnapshot） |
| `main.go` | 扩展 RuntimeContext 构造 | 传入 chain bootstrap 数据（agentID、owner、ChainRPC、ContractAddr、AttestorURL）+ `sealedVersion` build var |

### 测试更新

| 文件 | 说明 |
|---|---|
| `openclaw_test.go` | 用 `platform.Build(rs)` 替换 `platformCaps{}`；新增 `TestUpsertPlatformSection_IncludesConstraints` 和 `TestUpsertPlatformSection_IncludesRuntimeSnapshot` |
| `identitymd_test.go` | 用 `testIdentitySection()` helper 替换直接 `buildIdentityFile` 调用 |
| `soulmd_test.go` | 用 `testSovereigntySection()` helper 替换直接 `buildSoulSovereignty` 调用 |

## 解决的基因认知缺口

| 缺口 | 严重度 | 修复方式 |
|---|---|---|
| 1. 版本白名单未知 | 高 | Constraints 段注入 whitelist 列表 + whitelistMax + reconciler 行为描述 |
| 2. 诊断端点未用 | 中 | 砍掉（RUNTIME.md 已覆盖） |
| 3. 链上信息渠道缺失 | 中 | Runtime snapshot 段注入 agentID、owner、chainRPC、contractAddr |
| 4. sealed 自动纠正行为未知 | 高 | Constraints 段注入 drift auto-commit 行为 + config allowlist |
| 5. 三文件注入机制不透明 | 低 | 每个适配文件顶部注释明确标注「内容来自 platform.Build()」 |
| 6. 推理后端路由未知 | 中 | Runtime snapshot 段注入 provider/model + ZGComputeRouted 标记 |

## 编译 & 测试

```
go build ./...     ✅ 通过
go test ./...      ✅ 全部通过（0 失败）
```

## 架构验证

**之前**：
```
spawn.go → upsertIdentityMD(path, agentSeal string)
         → upsertSoulMD(path, agentSeal string)
         → upsertToolsMD(path, platformCaps{publicURL, signSock, agentSeal})
```
每个函数内部硬编码全部内容模板。

**之后**：
```
spawn.go → rs := platform.RuntimeSnapshot{...全部运行时数据...}
         → pc := platform.Build(rs)
         → upsertIdentityMD(path, pc.Identity)      // delivery only
         → upsertSoulMD(path, pc.Sovereignty)       // delivery only
         → upsertToolsMD(path, pc)                   // delivery only
```
内容生成在 `platform.Build()`，文件写入在 adapter。

## 新增注入内容预览

agent 的 TOOLS.md 将多出两个新段（在 Capabilities 之后）：

### Runtime constraints（静态约束）
- Framework version whitelist + reconciler 行为
- Config allowlist（哪些 openclaw.json keys 被 watcher 跟踪）
- Drift auto-commit 行为描述

### Runtime snapshot（per-boot 动态表）
| Field | Value |
|---|---|
| sealed runtime | `<git hash>` |
| framework version | `<probed version>` |
| framework whitelist max | `2026.6.8` |
| agent seal | `0xEEAD...8984` |
| agent ID (on-chain) | `<token ID>` |
| owner | `0x...` |
| provider / model | `openai/glm-5.2` |
| 0g-compute routing | `yes/no` |
| boot time | `<RFC3339>` |
| watcher tick | `30s` |
| heartbeat interval | `5min` |
