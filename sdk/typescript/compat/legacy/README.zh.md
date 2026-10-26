# AgentDNA 兼容包

SDK 和 CLI 现已统一命名为 `0g-agentdna`。本包将旧 SDK 导入路径及新旧两个 CLI
命令转发到对应版本的 `0g-agentdna`。

已有 CLI 用户可在终端执行 `0g-agenticid update`，然后启动 `0g-agentdna`。
当新目录尚不存在时，旧配置会自动迁移到 `~/.config/0g-agentdna/`，并遵循
`XDG_CONFIG_HOME`。钱包私钥、推理 API key、proof tickets 和 secret-env 降级
保护记录会连同原有权限一起迁移。

新用户应使用 `npm install -g 0g-agentdna`。SDK 应用可以使用
`import { AgentDNA } from '0g-agentdna'`；原有的 `AgenticID` 导出继续可用。

维护时，在支持旧更新入口期间，每次发版均先发布对应版本的主包，再发布本兼容包。
兼容包版本及其精确的 `0g-agentdna` 依赖版本必须与主包一致。

English: [README.md](README.md).
