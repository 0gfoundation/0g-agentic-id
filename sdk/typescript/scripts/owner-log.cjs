#!/usr/bin/env node
// Read a test agent's startup log through the same owner authentication as
// the CLI. Used by verify-agent.sh; never send an unauthenticated log request.
'use strict';
const { AgentDNA } = require('../dist/index.js');
(async () => {
  const attestor = process.env.ATTESTOR_URL || process.env.API;
  if (!attestor || !process.env.OWNER_PRIV || !process.env.AGENT_ID) {
    throw new Error('set ATTESTOR_URL (or API), OWNER_PRIV and AGENT_ID');
  }
  const sdk = await AgentDNA.fromAttestor(attestor, { account: process.env.OWNER_PRIV });
  const client = await sdk.agent.authenticate(BigInt(process.env.AGENT_ID));
  const { response } = await client.fetchWithProof('/log');
  if (!response.ok) throw new Error(`startup log returned HTTP ${response.status}`);
  process.stdout.write(await response.text());
})().catch((error) => {
  console.error(String(error.message).split(process.env.OWNER_PRIV || '\0').join('<redacted>'));
  process.exitCode = 1;
});
