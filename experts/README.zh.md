[English](README.md) | 中文

# 专家库

现成的专家 agent，任何人都可以 clone。所有专家跑在同一个通用的 0g-harness 上，让它成为专家的是三样东西：一些可写的自定义 harness 数据、persona 和一组 skill。

| 专家 | 网络 | 模版 agent | 能做什么 |
| --- | --- | --- | --- |
| [PM Expert](pm-expert/clone.sh) | testnet | 637 | 产品调研：桌面调研、用户口碑、用浏览器上手体验并截图；交付 HTML + PDF 报告 |

## clone PM Expert

1. 安装 testnet 版 CLI：`npm install -g @0gfoundation/0g-agentdna@next`（0.5.2 及以上；`latest` 标签是主网版）。运行 `0g-agentdna`，输入 `login`，填 attestor `https://agentdna-testnet.0g.ai`、钱包私钥和 0g-compute 模型 key。之后 `0g-agentdna doctor` 应该全绿。
2. 请模版 owner 给你的钱包授权：对方在 `0g-agentdna` 里输入 `grant 637 <你的钱包>`。
3. 运行：

   ```bash
   curl -fsSL https://raw.githubusercontent.com/0gfoundation/0g-agentic-id/dev/experts/pm-expert/clone.sh | bash
   ```

   它会 clone agent 637，套用模版的设置（设置不随 clone 复制），用 `reset` 启动（clone 出来是 offline），给 agent 钱包充 3 OG（要多充用 `... | GAS=5 bash`），最后打印新的 agentId。
4. `0g-agentdna <新 id>` 打开对话，写清楚产品或主题，以及你想了解什么。

gas：testnet 上（目前约 2,000 gwei），agent 每次把自己的数据写上链约花 0.9 OG；更新一次 skill 在写上链之前花掉过约 6 OG。agent 钱包没钱时照常工作，但改动不会保存到链上。
