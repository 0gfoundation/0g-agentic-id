# AgentDNA compatibility package

The SDK and CLI are now named `0g-agentdna`. This package forwards the legacy
SDK imports and both CLI commands to the matching `0g-agentdna` release.

Existing CLI users can run `0g-agenticid update` in their terminal, then start
`0g-agentdna`. Existing configuration is moved to `~/.config/0g-agentdna/`
automatically when that directory does not already exist. `XDG_CONFIG_HOME`
is respected. The owner key, inference key, proof tickets, and secret-env
downgrade pins move together with their existing permissions.

Fresh installations should use `npm install -g 0g-agentdna`. SDK applications
can use `import { AgentDNA } from '0g-agentdna'`; the existing `AgenticID`
export remains available.

For maintenance, publish this package after the matching canonical release
on every release while the legacy update path is supported. Keep its version
and exact `0g-agentdna` dependency aligned with the canonical package.

中文：[README.zh.md](README.zh.md)。
