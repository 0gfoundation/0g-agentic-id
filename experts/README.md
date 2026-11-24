English | [中文](README.zh.md)

# Experts

Ready-made expert agents that anyone can clone. Every expert runs on the same general 0g-harness; what makes it an expert is some writable, custom harness data, a persona and a set of skills.

| Expert | Network | Template agent | What it does |
| --- | --- | --- | --- |
| [PM Expert](pm-expert/clone.sh) | testnet | 637 | Product research: desk research, user sentiment, a hands-on walkthrough in a browser with screenshots; delivers a report as HTML + PDF |

## Clone the PM Expert

1. Install the testnet CLI: `npm install -g @0gfoundation/0g-agentdna@next` (0.5.2 or later; the `latest` tag is the mainnet CLI). Run `0g-agentdna`, type `login`, and give the attestor `https://agentdna-testnet.0g.ai`, your wallet key and your 0g-compute model key. `0g-agentdna doctor` should then be all green.
2. Ask the template's owner to grant your wallet: they type `grant 637 <your wallet>` in `0g-agentdna`.
3. Run:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/0gfoundation/0g-agentic-id/dev/experts/pm-expert/clone.sh | bash
   ```

   It clones agent 637, applies the template's settings (settings do not travel with a clone), brings the clone up with `reset` (a clone lands offline), tops up the agent's wallet with 3 OG (`... | GAS=5 bash` for more), and prints the new agentId.
4. `0g-agentdna <new id>` opens a chat; write the product or topic and what you want to learn.

Gas: on testnet (about 2,000 gwei now) the agent pays about 0.9 OG for each on-chain write of its own data, and a skills update has taken about 6 OG before it landed. An agent whose wallet runs dry keeps working but its changes are not saved on chain.
