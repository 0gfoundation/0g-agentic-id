# @0g/agenticid-sdk

TypeScript SDK for the [0G AgenticID](https://github.com/0gfoundation/0g-agentic-id) protocol — a trust chain for autonomous AI agents built on ERC-8004 (identity registry) and ERC-7857 (intelligent data with sealed keys).

## Features

- **Agent registration** — Register agents with or without TEE seal binding
- **Seal management** — Bind agents to agentSeal addresses and seal IDs
- **Intelligent transfers** — Transfer agents with cryptographic proofs (TEE/ZKP)
- **Agent cloning** — Clone agents with proof-based key re-encryption
- **Metadata & URI** — Manage agent metadata and URIs
- **Agent wallet** — Set/update agent wallet addresses with signature verification
- **Authorization** — Manage usage authorizations and access delegates
- **Reputation system** — Submit feedback with ServeProofs, append responses, query summaries
- **ServeProof utilities** — Build, sign, and verify ServeProof payloads

## Installation

```bash
npm install @0g/agenticid-sdk viem
```

## Quick Start

```typescript
import {
  AgenticIDClient,
  ReputationClient,
  ZERO_G_GALILEO_TESTNET,
  getAddresses,
} from '@0g/agenticid-sdk';
import { createWalletClient, http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

// Setup wallet
const account = privateKeyToAccount('0xYOUR_PRIVATE_KEY');
const walletClient = createWalletClient({
  account,
  chain: ZERO_G_GALILEO_TESTNET,
  transport: http(),
});

// Create AgenticID client
const agenticId = new AgenticIDClient({
  environment: 'testnet',
  walletClient,
  account,
});

// Create Reputation client
const reputation = new ReputationClient({
  environment: 'testnet',
  walletClient,
  account,
});
```

## Usage Examples

### Register an Agent

```typescript
const txHash = await agenticId.register({
  agentURI: 'ipfs://QmYourAgentMetadata',
  metadata: [
    { metadataKey: 'name', metadataValue: '0x...' },
  ],
  intelligentDatas: [
    { dataDescription: 'model weights', dataHash: '0x...' },
  ],
  sealedKeys: [
    { dataHash: '0x...', sealedKey: '0x...' },
  ],
});

const receipt = await agenticId.waitForTransaction(txHash);
console.log('Agent registered:', receipt);
```

### Register with TEE Seal Binding

```typescript
const txHash = await agenticId.registerWithSeal({
  to: account.address,
  agentURI: 'ipfs://QmYourAgentMetadata',
  metadata: [],
  intelligentDatas: [
    { dataDescription: 'model weights', dataHash: '0x...' },
  ],
  sealedKeys: [
    { dataHash: '0x...', sealedKey: '0x...' },
  ],
  agentSeal: '0xAgentSealAddress',
  sealId: '0xSealIdBytes32',
});
```

### Query Agent Information

```typescript
// Get agent seal address
const seal = await agenticId.getAgentSeal(1n);

// Get seal ID
const sealId = await agenticId.getSealId(1n);

// Check if seal ID is bound
const isBound = await agenticId.isSealIdBound(sealId);

// Get intelligent data
const datas = await agenticId.intelligentDatasOf(1n);
console.log('Intelligent data:', datas);

// Get sealed keys
const keys = await agenticId.sealedKeysOf(1n);

// Get owner
const owner = await agenticId.ownerOf(1n);

// Get metadata
const value = await agenticId.getMetadata(1n, 'name');
```

### Update Agent Data

```typescript
// Update all intelligent data and sealed keys
const txHash = await agenticId.update(1n, [
  { dataDescription: 'updated model', dataHash: '0x...' },
], [
  { dataHash: '0x...', sealedKey: '0x...' },
]);

// Update at specific index
await agenticId.updateAt(1n, 0n, {
  dataDescription: 'patched model',
  dataHash: '0x...',
}, {
  dataHash: '0x...',
  sealedKey: '0x...',
});
```

### Manage Authorizations

```typescript
// Authorize a user
await agenticId.authorizeUsage(1n, '0xUserAddress');

// Batch authorize
await agenticId.batchAuthorizeUsage(1n, [
  '0xUser1',
  '0xUser2',
  '0xUser3',
]);

// List authorized users
const users = await agenticId.authorizedUsersOf(1n);

// Revoke authorization
await agenticId.revokeAuthorization(1n, '0xUser1');

// Clear all
await agenticId.clearAuthorizedUsers(1n);
```

### Transfer an Agent

```typescript
// Standard transfer (seal-bound agents only)
await agenticId.transferFrom(account.address, '0xRecipient', 1n);

// Safe transfer
await agenticId.safeTransferFrom(account.address, '0xRecipient', 1n, '0x');

// Intelligent transfer with proofs
await agenticId.iTransferFrom(
  account.address,
  '0xRecipient',
  1n,
  [{
    accessProof: {
      dataHash: '0x...',
      targetPubkey: '0x...',
      nonce: '0x...',
      deadline: 1700003600n,
      proof: '0x...',
    },
    ownershipProof: {
      oracleType: 0, // OracleType.TEE
      dataHash: '0x...',
      sealedKey: '0x...',
      targetPubkey: '0x...',
      nonce: '0x...',
      deadline: 1700003600n,
      proof: '0x...',
    },
  }],
);
```

### Reputation: Give Feedback

```typescript
import { buildServeProofSigningHash, signServeProof } from '@0g/agenticid-sdk';

// Build and sign a ServeProof
const serveProof = await signServeProof(
  {
    agentId: 1n,
    client: account.address,
    timestamp: BigInt(Math.floor(Date.now() / 1000)),
    deadline: BigInt(Math.floor(Date.now() / 1000) + 3600),
    taskHash: '0xTaskHash',
    dataHashes: ['0xDataHash1', '0xDataHash2'],
    frameworkHash: '0xFrameworkHash',
  },
  async (hash) => account.signMessage({ message: { raw: hash } }),
);

// Submit feedback
await reputation.giveFeedback({
  agentId: 1n,
  value: 5n,
  valueDecimals: 0,
  tag1: 'quality',
  tag2: 'general',
  endpoint: 'https://agent.example.com',
  feedbackURI: 'ipfs://QmFeedback',
  feedbackHash: '0xFeedbackHash',
  serveProof,
});
```

### Reputation: Query Feedback

```typescript
// Read a single feedback
const feedback = await reputation.readFeedback(1n, '0xClient', 0n);
console.log('Value:', feedback.value);
console.log('Tag:', feedback.tag1);
console.log('Revoked:', feedback.isRevoked);

// Read all feedback
const allFeedback = await reputation.readAllFeedback({
  agentId: 1n,
  clientAddresses: [],
  tag1: 'quality',
  tag2: '',
  includeRevoked: false,
});

// Get summary
const summary = await reputation.getSummary({
  agentId: 1n,
  clientAddresses: [],
  tag1: 'quality',
  tag2: '',
});
console.log(`Count: ${summary.count}, Avg: ${summary.summaryValue}`);

// Get all clients who gave feedback
const clients = await reputation.getClients(1n);
```

### Reputation: Append Response

```typescript
await reputation.appendResponse({
  agentId: 1n,
  clientAddress: '0xClientAddress',
  feedbackIndex: 0n,
  responseURI: 'ipfs://QmResponse',
  responseHash: '0xResponseHash',
});
```

### ServeProof Utilities

```typescript
import {
  buildServeProofMessageHash,
  buildServeProofSigningHash,
  buildServeProof,
  signServeProof,
} from '@0g/agenticid-sdk';

// Compute the message hash (as the contract does)
const msgHash = buildServeProofMessageHash({
  agentId: 1n,
  client: '0xClient',
  timestamp: 1700000000n,
  deadline: 1700003600n,
  taskHash: '0xTaskHash',
  dataHashes: ['0xDataHash1', '0xDataHash2'],
  frameworkHash: '0xFrameworkHash',
});

// Compute the EIP-191 signing hash
const signingHash = buildServeProofSigningHash({
  agentId: 1n,
  client: '0xClient',
  timestamp: 1700000000n,
  deadline: 1700003600n,
  taskHash: '0xTaskHash',
  dataHashes: ['0xDataHash1', '0xDataHash2'],
  frameworkHash: '0xFrameworkHash',
});

// Build proof without signature
const proof = buildServeProof({
  agentId: 1n,
  client: '0xClient',
  timestamp: 1700000000n,
  deadline: 1700003600n,
  taskHash: '0xTaskHash',
  dataHashes: ['0xDataHash1'],
  frameworkHash: '0xFrameworkHash',
});
```

## API Reference

### AgenticIDClient

| Method | Type | Description |
|--------|------|-------------|
| `register(params)` | write | Register a new agent |
| `registerWithSeal(params)` | write | Register with TEE seal binding |
| `setAgentSeal(agentId, seal, sealId)` | write | Set agent seal |
| `getAgentSeal(agentId)` | read | Get agent seal address |
| `getSealId(agentId)` | read | Get seal ID |
| `getAgentIdBySealId(sealId)` | read | Get agent ID by seal ID |
| `isSealIdBound(sealId)` | read | Check if seal ID is bound |
| `addTrustedAttestor(addr)` | write | Add trusted attestor |
| `removeTrustedAttestor(addr)` | write | Remove trusted attestor |
| `isTrustedAttestor(addr)` | read | Check if attestor is trusted |
| `addValidFrameworkHash(hash)` | write | Add valid framework hash |
| `removeValidFrameworkHash(hash)` | write | Remove valid framework hash |
| `isValidFrameworkHash(hash)` | read | Check if framework hash is valid |
| `transferFrom(from, to, id)` | write | Transfer agent (seal-bound) |
| `safeTransferFrom(...)` | write | Safe transfer (seal-bound) |
| `iTransferFrom(from, to, id, proofs)` | write | Intelligent transfer with proofs |
| `iCloneFrom(from, to, id, proofs)` | write | Clone agent with proofs |
| `update(tokenId, datas, keys)` | write | Update all intelligent data |
| `updateAt(tokenId, idx, data, key)` | write | Update single data entry |
| `intelligentDatasOf(tokenId)` | read | Get all intelligent data |
| `sealedKeysOf(tokenId)` | read | Get all sealed keys |
| `setAgentURI(agentId, uri)` | write | Set agent URI |
| `getMetadata(agentId, key)` | read | Get metadata value |
| `setMetadata(agentId, key, value)` | write | Set metadata value |
| `setAgentWallet(...)` | write | Set agent wallet |
| `getAgentWallet(agentId)` | read | Get agent wallet |
| `unsetAgentWallet(agentId)` | write | Unset agent wallet |
| `authorizeUsage(tokenId, user)` | write | Authorize user |
| `batchAuthorizeUsage(tokenId, users)` | write | Batch authorize |
| `revokeAuthorization(tokenId, user)` | write | Revoke authorization |
| `clearAuthorizedUsers(tokenId)` | write | Clear all authorizations |
| `authorizedUsersOf(tokenId)` | read | Get authorized users |
| `setAccessDelegate(delegate)` | write | Set access delegate |
| `getAccessDelegate(user)` | read | Get access delegate |
| `ownerOf(tokenId)` | read | Get token owner |
| `balanceOf(owner)` | read | Get balance |
| `pause()` / `unpause()` | write | Pause/unpause contract |
| `pauser()` | read | Get pauser address |
| `setPauser(addr)` | write | Set new pauser |
| `setVerifier(addr)` | write | Set new verifier |

### ReputationClient

| Method | Type | Description |
|--------|------|-------------|
| `giveFeedback(params)` | write | Submit feedback with ServeProof |
| `revokeFeedback(agentId, idx)` | write | Revoke feedback |
| `appendResponse(params)` | write | Append response to feedback |
| `readFeedback(agentId, client, idx)` | read | Read single feedback |
| `readAllFeedback(params)` | read | Read all feedback |
| `getSummary(params)` | read | Get feedback summary |
| `getResponseCount(...)` | read | Get response count |
| `getClients(agentId)` | read | Get all clients |
| `getLastIndex(agentId, client)` | read | Get last feedback index |
| `getServeData(agentId, client, idx)` | read | Get serve data |

### ServeProof Utilities

| Function | Description |
|----------|-------------|
| `buildServeProofMessageHash(params)` | Compute keccak256 of abi.encode payload |
| `buildServeProofSigningHash(params)` | Compute EIP-191 wrapped hash |
| `buildServeProof(params)` | Build proof object without signature |
| `signServeProof(params, signFn)` | Build and sign proof |
| `verifyServeProofSignature(proof, addr)` | Verify signature (stub) |

## Contract Addresses

### Testnet (0G Galileo Testnet, Chain ID: 16602)

| Contract | Address |
|----------|---------|
| AgenticID | `0xbea77c9aBd0aA46e812444583947718593bBD139` |
| TEEDataVerifier | `0x1b6bba3db8a04B20702Feb62E30Caa831ca1e1f1` |
| ReputationRegistry | `0x8bC1E129aEb0Baa306715BC1CBB720Eb2A4324AA` |

### Dev

| Contract | Address |
|----------|---------|
| AgenticID | `0xf952e7dD046779f34C0Ca0c058e1D940B7B9d525` |
| TEEDataVerifier | `0x2EAa6fcB9847A5A4B25acCdeca3C957a1732C23F` |
| ReputationRegistry | `0x4AAbc18962C2Bb5E451a0FDfa39c0C47a51bD971` |

## License

MIT
