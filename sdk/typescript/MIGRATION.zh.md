# 升级到 0G AgentDNA

npm 包名现为 `@0gfoundation/0g-agentdna`，发布在 0gfoundation 组织下；
CLI 命令为 `0g-agentdna`。SDK 提供 `AgentDNA` 和 `AgentDNAConfig`，原有
`AgenticID` 和 `AgenticIDConfig` 导出继续兼容。合约名称和签名消息域沿用协议标识符。

## 已有 CLI 用户

在主包和对应兼容包发布后，退出交互 CLI，在系统终端执行：

```bash
0g-agenticid update
0g-agentdna --version
0g-agentdna
```

旧 updater 查询旧 npm 包的 `latest` 标签；兼容版本会安装对应版本的主 SDK，
并提供新旧两个命令。此后使用 `0g-agentdna update` 更新。通过兼容入口启动时，
updater 会更新该兼容包，保证全局命令链接仍由原包管理。

新安装使用 `npm install -g @0gfoundation/0g-agentdna`。开发检出使用仓库的
构建流程，不通过 npm 自更新命令覆盖。

不带组织前缀的 `0g-agentdna` 包曾短暂发布，现已弃用。装过它的用户需要替换，
因为两个包都提供 `0g-agentdna` 命令：

```bash
npm uninstall -g 0g-agentdna
npm install -g @0gfoundation/0g-agentdna
```

## 本地配置

首次访问时，如果新目录尚不存在，CLI 会将 `~/.config/0g-agenticid/` 移动到
`~/.config/0g-agentdna/`；设置 `XDG_CONFIG_HOME` 时以该目录替代 `~/.config`。
迁移保留所有文件及权限，包括凭据、proof tickets、secret-env 降级保护记录和
更新提示记录，无需重新登录。

如果新旧目录同时存在，使用 AgentDNA 目录，保留旧目录。如果移动失败，明确报告
迁移错误，不创建空配置替代。已有的 `AGENTIC_*` 环境变量继续支持。


旧凭据字段 `apiKey` 会原子转换为 `inferenceKeys["0g-compute"]`，保留钱包及
其他 provider 的 key。旧 `AGENTIC_API_KEY` / `API_KEY` 覆盖仅属于 compute。
在 manager 内通过 `login <provider>` 登记新 key，再用 `settings`、`reset`
切换已有 agent，见 [provider 说明](./PROVIDERS.zh.md)。

## SDK 应用

```typescript
import { AgentDNA, type AgentDNAConfig } from '@0gfoundation/0g-agentdna';
import { sealAccount } from '@0gfoundation/0g-agentdna/seal';
```

原有 `@0gfoundation/0g-agenticid-sdk` 及其 `/seal` 导入路径通过兼容包继续可用；
应用可以在更新依赖时改用新包名。

## 发布顺序

1. 同步主包版本、lockfile、`SDK_VERSION`，以及兼容包版本和精确依赖版本。
2. 执行 SDK 类型检查和测试，检查两个 npm 包的打包内容。
3. 从 `sdk/typescript` 发布 `@0gfoundation/0g-agentdna`。
4. 主包对应版本可用后，从 `sdk/typescript/compat/legacy` 发布同版本的
   `@0gfoundation/0g-agenticid-sdk`；在支持旧更新入口期间，每次发版均发布兼容包。
5. 两个包均可用后再更新 attestor 的 `ATTESTOR_CLI_LATEST` 和
   `ATTESTOR_CLI_NOTES`，在说明中告知旧客户端改名事项。

只发布新包，无法升级仍查询旧包的客户端。修改仓库本身不会发布任何 npm 包。

English: [MIGRATION.md](MIGRATION.md).
