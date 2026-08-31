/**
 * @file abi.ts
 * @description Contract ABIs for the 0G AgenticID protocol, manually authored from Solidity source.
 */

/**
 * ABI for the AgenticID contract.
 * Inherits ERC-8004 and ERC-7857.
 */
export const agenticIDAbi = [
  // ── Registration ──
  {
    type: 'function',
    name: 'register',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'agentURI', type: 'string' },
      { name: 'metadata', type: 'tuple[]', components: [
        { name: 'metadataKey', type: 'string' },
        { name: 'metadataValue', type: 'bytes' },
      ] },
      { name: 'intelligentDatas', type: 'tuple[]', components: [
        { name: 'dataDescription', type: 'string' },
        { name: 'dataHash', type: 'bytes32' },
      ] },
      { name: 'sealedKeys', type: 'tuple[]', components: [
        { name: 'dataHash', type: 'bytes32' },
        { name: 'sealedKey', type: 'bytes' },
      ] },
    ],
    outputs: [{ name: 'agentId', type: 'uint256' }],
  },
  {
    type: 'function',
    name: 'registerWithSeal',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'to', type: 'address' },
      { name: 'agentURI', type: 'string' },
      { name: 'metadata', type: 'tuple[]', components: [
        { name: 'metadataKey', type: 'string' },
        { name: 'metadataValue', type: 'bytes' },
      ] },
      { name: 'intelligentDatas', type: 'tuple[]', components: [
        { name: 'dataDescription', type: 'string' },
        { name: 'dataHash', type: 'bytes32' },
      ] },
      { name: 'sealedKeys', type: 'tuple[]', components: [
        { name: 'dataHash', type: 'bytes32' },
        { name: 'sealedKey', type: 'bytes' },
      ] },
      { name: 'agentSeal_', type: 'address' },
      { name: 'sealId', type: 'bytes32' },
    ],
    outputs: [{ name: 'agentId', type: 'uint256' }],
  },

  {
    type: 'function',
    name: 'tokenURI',
    stateMutability: 'view',
    inputs: [{ name: 'tokenId', type: 'uint256' }],
    outputs: [{ name: '', type: 'string' }],
  },
  {
    type: 'function',
    name: 'getAgentSeal',
    stateMutability: 'view',
    inputs: [{ name: 'agentId', type: 'uint256' }],
    outputs: [{ name: '', type: 'address' }],
  },
  {
    type: 'function',
    name: 'getSealId',
    stateMutability: 'view',
    inputs: [{ name: 'agentId', type: 'uint256' }],
    outputs: [{ name: '', type: 'bytes32' }],
  },
  {
    type: 'function',
    name: 'getAgentIdBySealId',
    stateMutability: 'view',
    inputs: [{ name: 'sealId', type: 'bytes32' }],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    type: 'function',
    name: 'isSealIdBound',
    stateMutability: 'view',
    inputs: [{ name: 'sealId', type: 'bytes32' }],
    outputs: [{ name: '', type: 'bool' }],
  },

  // ── Trusted Attestors ──
  {
    type: 'function',
    name: 'addTrustedAttestor',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'attestor', type: 'address' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'removeTrustedAttestor',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'attestor', type: 'address' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'isTrustedAttestor',
    stateMutability: 'view',
    inputs: [{ name: 'attestor', type: 'address' }],
    outputs: [{ name: '', type: 'bool' }],
  },

  // ── Framework Hashes ──
  {
    type: 'function',
    name: 'addValidFrameworkHash',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'frameworkHash', type: 'bytes32' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'removeValidFrameworkHash',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'frameworkHash', type: 'bytes32' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'isValidFrameworkHash',
    stateMutability: 'view',
    inputs: [{ name: 'frameworkHash', type: 'bytes32' }],
    outputs: [{ name: '', type: 'bool' }],
  },

  // ── Transfer (seal-bound only) ──
  {
    type: 'function',
    name: 'transferFrom',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'from', type: 'address' },
      { name: 'to', type: 'address' },
      { name: 'tokenId', type: 'uint256' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'safeTransferFrom',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'from', type: 'address' },
      { name: 'to', type: 'address' },
      { name: 'tokenId', type: 'uint256' },
      { name: 'data', type: 'bytes' },
    ],
    outputs: [],
  },

  // ── Intelligent Transfer ──
  {
    type: 'function',
    name: 'iTransferFrom',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'from', type: 'address' },
      { name: 'to', type: 'address' },
      { name: 'tokenId', type: 'uint256' },
      { name: 'proofs', type: 'tuple[]', components: [
        { name: 'accessProof', type: 'tuple', components: [
          { name: 'dataHash', type: 'bytes32' },
          { name: 'targetPubkey', type: 'bytes' },
          { name: 'nonce', type: 'bytes' },
          { name: 'deadline', type: 'uint256' },
          { name: 'proof', type: 'bytes' },
        ] },
        { name: 'ownershipProof', type: 'tuple', components: [
          { name: 'oracleType', type: 'uint8' },
          { name: 'dataHash', type: 'bytes32' },
          { name: 'sealedKey', type: 'bytes' },
          { name: 'targetPubkey', type: 'bytes' },
          { name: 'nonce', type: 'bytes' },
          { name: 'deadline', type: 'uint256' },
          { name: 'proof', type: 'bytes' },
        ] },
      ] },
    ],
    outputs: [{ name: '', type: 'tuple[]', components: [
      { name: 'dataHash', type: 'bytes32' },
      { name: 'sealedKey', type: 'bytes' },
    ] }],
  },
  {
    type: 'function',
    name: 'iCloneFrom',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'from', type: 'address' },
      { name: 'to', type: 'address' },
      { name: 'tokenId', type: 'uint256' },
      { name: 'proofs', type: 'tuple[]', components: [
        { name: 'accessProof', type: 'tuple', components: [
          { name: 'dataHash', type: 'bytes32' },
          { name: 'targetPubkey', type: 'bytes' },
          { name: 'nonce', type: 'bytes' },
          { name: 'deadline', type: 'uint256' },
          { name: 'proof', type: 'bytes' },
        ] },
        { name: 'ownershipProof', type: 'tuple', components: [
          { name: 'oracleType', type: 'uint8' },
          { name: 'dataHash', type: 'bytes32' },
          { name: 'sealedKey', type: 'bytes' },
          { name: 'targetPubkey', type: 'bytes' },
          { name: 'nonce', type: 'bytes' },
          { name: 'deadline', type: 'uint256' },
          { name: 'proof', type: 'bytes' },
        ] },
      ] },
    ],
    outputs: [{ name: 'newTokenId', type: 'uint256' }],
  },

  // ── Update Agent Data ──
  {
    type: 'function',
    name: 'update',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'tokenId', type: 'uint256' },
      { name: 'newDatas', type: 'tuple[]', components: [
        { name: 'dataDescription', type: 'string' },
        { name: 'dataHash', type: 'bytes32' },
      ] },
      { name: 'sealedKeys', type: 'tuple[]', components: [
        { name: 'dataHash', type: 'bytes32' },
        { name: 'sealedKey', type: 'bytes' },
      ] },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'updateAt',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'tokenId', type: 'uint256' },
      { name: 'index', type: 'uint256' },
      { name: 'newData', type: 'tuple', components: [
        { name: 'dataDescription', type: 'string' },
        { name: 'dataHash', type: 'bytes32' },
      ] },
      { name: 'sealedKey', type: 'tuple', components: [
        { name: 'dataHash', type: 'bytes32' },
        { name: 'sealedKey', type: 'bytes' },
      ] },
    ],
    outputs: [],
  },

  // ── Read Agent Data ──
  {
    type: 'function',
    name: 'intelligentDatasOf',
    stateMutability: 'view',
    inputs: [{ name: 'tokenId', type: 'uint256' }],
    outputs: [{ name: '', type: 'tuple[]', components: [
      { name: 'dataDescription', type: 'string' },
      { name: 'dataHash', type: 'bytes32' },
    ] }],
  },
  {
    type: 'function',
    name: 'sealedKeysOf',
    stateMutability: 'view',
    inputs: [{ name: 'tokenId', type: 'uint256' }],
    outputs: [{ name: '', type: 'bytes[]' }],
  },

  // ── Agent URI ──
  {
    type: 'function',
    name: 'setAgentURI',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'newURI', type: 'string' },
    ],
    outputs: [],
  },

  // ── Metadata ──
  {
    type: 'function',
    name: 'getMetadata',
    stateMutability: 'view',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'key', type: 'string' },
    ],
    outputs: [{ name: '', type: 'bytes' }],
  },
  {
    type: 'function',
    name: 'setMetadata',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'key', type: 'string' },
      { name: 'value', type: 'bytes' },
    ],
    outputs: [],
  },

  // ── Agent Wallet ──
  {
    type: 'function',
    name: 'setAgentWallet',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'newWallet', type: 'address' },
      { name: 'deadline', type: 'uint256' },
      { name: 'signature', type: 'bytes' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'getAgentWallet',
    stateMutability: 'view',
    inputs: [{ name: 'agentId', type: 'uint256' }],
    outputs: [{ name: '', type: 'address' }],
  },
  {
    type: 'function',
    name: 'unsetAgentWallet',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'agentId', type: 'uint256' }],
    outputs: [],
  },

  // ── Authorization ──
  {
    type: 'function',
    name: 'authorizeUsage',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'tokenId', type: 'uint256' },
      { name: 'user', type: 'address' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'batchAuthorizeUsage',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'tokenId', type: 'uint256' },
      { name: 'users', type: 'address[]' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'revokeAuthorization',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'tokenId', type: 'uint256' },
      { name: 'user', type: 'address' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'clearAuthorizedUsers',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'tokenId', type: 'uint256' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'authorizedUsersOf',
    stateMutability: 'view',
    inputs: [{ name: 'tokenId', type: 'uint256' }],
    outputs: [{ name: '', type: 'address[]' }],
  },

  // ── Access Delegate ──
  {
    type: 'function',
    name: 'setAccessDelegate',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'delegate', type: 'address' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'getAccessDelegate',
    stateMutability: 'view',
    inputs: [{ name: 'user', type: 'address' }],
    outputs: [{ name: '', type: 'address' }],
  },

  // ── ERC-721 Standard ──
  {
    type: 'function',
    name: 'ownerOf',
    stateMutability: 'view',
    inputs: [{ name: 'tokenId', type: 'uint256' }],
    outputs: [{ name: '', type: 'address' }],
  },
  {
    type: 'function',
    name: 'balanceOf',
    stateMutability: 'view',
    inputs: [{ name: 'owner', type: 'address' }],
    outputs: [{ name: '', type: 'uint256' }],
  },

  // ── Pause ──
  {
    type: 'function',
    name: 'pause',
    stateMutability: 'nonpayable',
    inputs: [],
    outputs: [],
  },
  {
    type: 'function',
    name: 'unpause',
    stateMutability: 'nonpayable',
    inputs: [],
    outputs: [],
  },
  {
    type: 'function',
    name: 'pauser',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address' }],
  },
  {
    type: 'function',
    name: 'setPauser',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'newPauser', type: 'address' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'setVerifier',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'newVerifier', type: 'address' }],
    outputs: [],
  },

  // ── Events ──
  {
    type: 'event',
    name: 'AgentRegistered',
    inputs: [
      { name: 'agentId', type: 'uint256', indexed: true },
      { name: 'owner', type: 'address', indexed: true },
      { name: 'agentURI', type: 'string', indexed: false },
    ],
  },
  {
    type: 'event',
    name: 'AgentSealSet',
    inputs: [
      { name: 'agentId', type: 'uint256', indexed: true },
      { name: 'agentSeal', type: 'address', indexed: false },
      { name: 'sealId', type: 'bytes32', indexed: false },
    ],
  },
  {
    type: 'event',
    name: 'AgentUpdated',
    inputs: [
      { name: 'tokenId', type: 'uint256', indexed: true },
    ],
  },
  {
    type: 'event',
    name: 'Transfer',
    inputs: [
      { name: 'from', type: 'address', indexed: true },
      { name: 'to', type: 'address', indexed: true },
      { name: 'tokenId', type: 'uint256', indexed: true },
    ],
  },
  {
    type: 'event',
    name: 'Paused',
    inputs: [{ name: 'account', type: 'address', indexed: false }],
  },
  {
    type: 'event',
    name: 'Unpaused',
    inputs: [{ name: 'account', type: 'address', indexed: false }],
  },
] as const;

/**
 * Official canonical ERC-8004 ReputationRegistry (the fixed 0x8004B… singleton;
 * v2.0.0). Feedback STORAGE lives here — clients call `giveFeedback` directly,
 * so attribution is native msg.sender and every 8004 reader sees it. It has no
 * ServeProof parameter and no custom errors (plain require strings).
 * TEE verification marks live in the separate VerifiedFeedbackRegistry
 * (`verifiedFeedbackAbi` below).
 */
export const canonicalReputationAbi = [
  // ── Give Feedback (canonical 8-arg form, attribution = msg.sender) ──
  {
    type: 'function',
    name: 'giveFeedback',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'value', type: 'int128' },
      { name: 'valueDecimals', type: 'uint8' },
      { name: 'tag1', type: 'string' },
      { name: 'tag2', type: 'string' },
      { name: 'endpoint', type: 'string' },
      { name: 'feedbackURI', type: 'string' },
      { name: 'feedbackHash', type: 'bytes32' },
    ],
    outputs: [],
  },

  // ── Revoke Feedback ──
  {
    type: 'function',
    name: 'revokeFeedback',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'feedbackIndex', type: 'uint64' },
    ],
    outputs: [],
  },

  // ── Append Response ──
  {
    type: 'function',
    name: 'appendResponse',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'clientAddress', type: 'address' },
      { name: 'feedbackIndex', type: 'uint64' },
      { name: 'responseURI', type: 'string' },
      { name: 'responseHash', type: 'bytes32' },
    ],
    outputs: [],
  },

  // ── Read Feedback ──
  {
    type: 'function',
    name: 'readFeedback',
    stateMutability: 'view',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'clientAddress', type: 'address' },
      { name: 'feedbackIndex', type: 'uint64' },
    ],
    outputs: [
      { name: 'value', type: 'int128' },
      { name: 'valueDecimals', type: 'uint8' },
      { name: 'tag1', type: 'string' },
      { name: 'tag2', type: 'string' },
      { name: 'isRevoked', type: 'bool' },
    ],
  },

  // ── Read All Feedback ──
  {
    type: 'function',
    name: 'readAllFeedback',
    stateMutability: 'view',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'clientAddresses', type: 'address[]' },
      { name: 'tag1', type: 'string' },
      { name: 'tag2', type: 'string' },
      { name: 'includeRevoked', type: 'bool' },
    ],
    outputs: [
      { name: 'clients', type: 'address[]' },
      { name: 'feedbackIndexes', type: 'uint64[]' },
      { name: 'values', type: 'int128[]' },
      { name: 'valueDecimals', type: 'uint8[]' },
      { name: 'tag1s', type: 'string[]' },
      { name: 'tag2s', type: 'string[]' },
      { name: 'revokedStatuses', type: 'bool[]' },
    ],
  },

  // ── Get Summary ──
  {
    type: 'function',
    name: 'getSummary',
    stateMutability: 'view',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'clientAddresses', type: 'address[]' },
      { name: 'tag1', type: 'string' },
      { name: 'tag2', type: 'string' },
    ],
    outputs: [
      { name: 'count', type: 'uint64' },
      { name: 'summaryValue', type: 'int128' },
      { name: 'summaryValueDecimals', type: 'uint8' },
    ],
  },

  // ── Get Response Count ──
  {
    type: 'function',
    name: 'getResponseCount',
    stateMutability: 'view',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'clientAddress', type: 'address' },
      { name: 'feedbackIndex', type: 'uint64' },
      { name: 'responders', type: 'address[]' },
    ],
    outputs: [{ name: 'count', type: 'uint64' }],
  },

  // ── Get Clients ──
  {
    type: 'function',
    name: 'getClients',
    stateMutability: 'view',
    inputs: [{ name: 'agentId', type: 'uint256' }],
    outputs: [{ name: '', type: 'address[]' }],
  },

  // ── Get Last Index ──
  {
    type: 'function',
    name: 'getLastIndex',
    stateMutability: 'view',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'clientAddress', type: 'address' },
    ],
    outputs: [{ name: '', type: 'uint64' }],
  },

  // ── Environment sanity reads ──
  {
    type: 'function',
    name: 'getIdentityRegistry',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address' }],
  },
  {
    type: 'function',
    name: 'getVersion',
    stateMutability: 'pure',
    inputs: [],
    outputs: [{ name: '', type: 'string' }],
  },

  // ── Events (canonical v2.0.0 shapes) ──
  {
    type: 'event',
    name: 'NewFeedback',
    inputs: [
      { name: 'agentId', type: 'uint256', indexed: true },
      { name: 'clientAddress', type: 'address', indexed: true },
      { name: 'feedbackIndex', type: 'uint64', indexed: false },
      { name: 'value', type: 'int128', indexed: false },
      { name: 'valueDecimals', type: 'uint8', indexed: false },
      { name: 'indexedTag1', type: 'string', indexed: true },
      { name: 'tag1', type: 'string', indexed: false },
      { name: 'tag2', type: 'string', indexed: false },
      { name: 'endpoint', type: 'string', indexed: false },
      { name: 'feedbackURI', type: 'string', indexed: false },
      { name: 'feedbackHash', type: 'bytes32', indexed: false },
    ],
  },
  {
    type: 'event',
    name: 'FeedbackRevoked',
    inputs: [
      { name: 'agentId', type: 'uint256', indexed: true },
      { name: 'clientAddress', type: 'address', indexed: true },
      { name: 'feedbackIndex', type: 'uint64', indexed: true },
    ],
  },
  {
    type: 'event',
    name: 'ResponseAppended',
    inputs: [
      { name: 'agentId', type: 'uint256', indexed: true },
      { name: 'clientAddress', type: 'address', indexed: true },
      { name: 'feedbackIndex', type: 'uint64', indexed: false },
      { name: 'responder', type: 'address', indexed: true },
      { name: 'responseURI', type: 'string', indexed: false },
      { name: 'responseHash', type: 'bytes32', indexed: false },
    ],
  },
] as const;

/**
 * VerifiedFeedbackRegistry — the local TEE-verification layer over the
 * canonical ERC-8004 ReputationRegistry. `attestFeedback` marks a canonical
 * entry as backed by a ServeProof; the `getVerified*` reads expose the marks
 * so readers can intersect them with canonical entries.
 */
export const verifiedFeedbackAbi = [
  // Custom errors — so viem decodes reverts instead of showing a 4-byte selector.
  {"type":"error","name":"ECDSAInvalidSignature","inputs":[]},
  {"type":"error","name":"ECDSAInvalidSignatureLength","inputs":[{"name":"length","type":"uint256"}]},
  {"type":"error","name":"ECDSAInvalidSignatureS","inputs":[{"name":"s","type":"bytes32"}]},
  {"type":"error","name":"EnforcedPause","inputs":[]},
  {"type":"error","name":"ExpectedPause","inputs":[]},
  {"type":"error","name":"InvalidInitialization","inputs":[]},
  {"type":"error","name":"NonceAlreadyUsed","inputs":[{"name":"key","type":"bytes32"}]},
  {"type":"error","name":"NonceDeadlineTooFar","inputs":[{"name":"deadline","type":"uint256"},{"name":"maxDeadline","type":"uint256"}]},
  {"type":"error","name":"NonceExpired","inputs":[{"name":"deadline","type":"uint256"},{"name":"nowTimestamp","type":"uint256"}]},
  {"type":"error","name":"NotInitializing","inputs":[]},
  {"type":"error","name":"OwnableInvalidOwner","inputs":[{"name":"owner","type":"address"}]},
  {"type":"error","name":"OwnableUnauthorizedAccount","inputs":[{"name":"account","type":"address"}]},
  {"type":"error","name":"VerifiedFeedbackAlreadyVerified","inputs":[{"name":"agentId","type":"uint256"},{"name":"clientAddress","type":"address"},{"name":"feedbackIndex","type":"uint64"}]},
  {"type":"error","name":"VerifiedFeedbackClientsRequired","inputs":[]},
  {"type":"error","name":"VerifiedFeedbackInvalidProofSignature","inputs":[]},
  {"type":"error","name":"VerifiedFeedbackNoAgentSeal","inputs":[]},
  {"type":"error","name":"VerifiedFeedbackNoSuchEntry","inputs":[{"name":"agentId","type":"uint256"},{"name":"clientAddress","type":"address"},{"name":"feedbackIndex","type":"uint64"},{"name":"lastIndex","type":"uint64"}]},
  {"type":"error","name":"VerifiedFeedbackNotPauser","inputs":[]},
  {"type":"error","name":"VerifiedFeedbackNotVerified","inputs":[{"name":"agentId","type":"uint256"},{"name":"clientAddress","type":"address"},{"name":"feedbackIndex","type":"uint64"}]},
  {"type":"error","name":"VerifiedFeedbackProofAgentMismatch","inputs":[{"name":"agentId","type":"uint256"},{"name":"proofAgentId","type":"uint256"}]},
  {"type":"error","name":"VerifiedFeedbackProofSubmitterMismatch","inputs":[{"name":"submitter","type":"address"},{"name":"sender","type":"address"}]},
  {"type":"error","name":"VerifiedFeedbackSelfFeedback","inputs":[{"name":"agentId","type":"uint256"},{"name":"submitter","type":"address"}]},
  {"type":"error","name":"VerifiedFeedbackSummaryOverflow","inputs":[]},
  {"type":"error","name":"VerifiedFeedbackTaskMismatch","inputs":[{"name":"expected","type":"bytes32"},{"name":"actual","type":"bytes32"}]},
  {"type":"error","name":"VerifiedFeedbackInvalidTaskReveal","inputs":[]},

  // ── Attest ──
  {
    type: 'function',
    name: 'attestFeedback',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'feedbackIndex', type: 'uint64' },
      { name: 'proof', type: 'tuple', components: [
        { name: 'agentId', type: 'uint256' },
        { name: 'submitter', type: 'address' },
        { name: 'timestamp', type: 'uint256' },
        { name: 'deadline', type: 'uint256' },
        { name: 'taskHash', type: 'bytes32' },
        { name: 'dataHashes', type: 'bytes32[]' },
        { name: 'frameworkHash', type: 'bytes32' },
        { name: 'signature', type: 'bytes' },
      ] },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'attestFeedbackWithTask',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'feedbackIndex', type: 'uint64' },
      { name: 'proof', type: 'tuple', components: [
        { name: 'agentId', type: 'uint256' },
        { name: 'submitter', type: 'address' },
        { name: 'timestamp', type: 'uint256' },
        { name: 'deadline', type: 'uint256' },
        { name: 'taskHash', type: 'bytes32' },
        { name: 'dataHashes', type: 'bytes32[]' },
        { name: 'frameworkHash', type: 'bytes32' },
        { name: 'signature', type: 'bytes' },
      ] },
      { name: 'task', type: 'tuple', components: [
        { name: 'method', type: 'string' },
        { name: 'uri', type: 'string' },
        { name: 'reqBodyHash', type: 'bytes32' },
        { name: 'respBodyHash', type: 'bytes32' },
        { name: 'statusCode', type: 'uint16' },
      ] },
    ],
    outputs: [],
  },

  // ── Reads ──
  {
    type: 'function',
    name: 'isVerified',
    stateMutability: 'view',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'clientAddress', type: 'address' },
      { name: 'feedbackIndex', type: 'uint64' },
    ],
    outputs: [{ name: '', type: 'bool' }],
  },
  {
    type: 'function',
    name: 'getServeData',
    stateMutability: 'view',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'clientAddress', type: 'address' },
      { name: 'feedbackIndex', type: 'uint64' },
    ],
    outputs: [
      { name: 'dataHashes', type: 'bytes32[]' },
      { name: 'frameworkHash', type: 'bytes32' },
    ],
  },
  {
    type: 'function',
    name: 'getVerifiedIndexes',
    stateMutability: 'view',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'clientAddress', type: 'address' },
    ],
    outputs: [{ name: '', type: 'uint64[]' }],
  },
  {
    type: 'function',
    name: 'getVerifiedClients',
    stateMutability: 'view',
    inputs: [{ name: 'agentId', type: 'uint256' }],
    outputs: [{ name: '', type: 'address[]' }],
  },
  {
    type: 'function',
    name: 'getVerifiedEndpoint',
    stateMutability: 'view',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'clientAddress', type: 'address' },
      { name: 'feedbackIndex', type: 'uint64' },
    ],
    outputs: [{ name: '', type: 'string' }],
  },
  {
    type: 'function',
    name: 'getVerifiedSummaryForEndpoint',
    stateMutability: 'view',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'clientAddresses', type: 'address[]' },
      { name: 'uri', type: 'string' },
    ],
    outputs: [
      { name: 'count', type: 'uint64' },
      { name: 'summaryValue', type: 'int128' },
      { name: 'summaryValueDecimals', type: 'uint8' },
    ],
  },
  {
    type: 'function',
    name: 'getVerifiedSummary',
    stateMutability: 'view',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'clientAddresses', type: 'address[]' },
      { name: 'tag1', type: 'string' },
      { name: 'tag2', type: 'string' },
    ],
    outputs: [
      { name: 'count', type: 'uint64' },
      { name: 'summaryValue', type: 'int128' },
      { name: 'summaryValueDecimals', type: 'uint8' },
    ],
  },
  {
    type: 'function',
    name: 'getIdentityRegistry',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address' }],
  },
  {
    type: 'function',
    name: 'getCanonicalReputation',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address' }],
  },

  // ── Events ──
  {
    type: 'event',
    name: 'FeedbackVerified',
    inputs: [
      { name: 'agentId', type: 'uint256', indexed: true },
      { name: 'clientAddress', type: 'address', indexed: true },
      { name: 'feedbackIndex', type: 'uint64', indexed: true },
      { name: 'dataHashes', type: 'bytes32[]', indexed: false },
      { name: 'frameworkHash', type: 'bytes32', indexed: false },
      { name: 'taskHash', type: 'bytes32', indexed: false },
      { name: 'uri', type: 'string', indexed: false },
    ],
  },
] as const;

/**
 * FeedbackBatcher — EIP-7702 delegate target. A client EOA attaches this code
 * to itself (type-4 authorization) and self-calls to execute the canonical
 * giveFeedback + attestFeedback pair atomically, with msg.sender = the EOA
 * for both inner calls.
 */
export const feedbackBatcherAbi = [
  {"type":"error","name":"BatcherNotSelf","inputs":[]},
  {
    type: 'function',
    name: 'giveFeedbackAndAttest',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'value', type: 'int128' },
      { name: 'valueDecimals', type: 'uint8' },
      { name: 'tag1', type: 'string' },
      { name: 'tag2', type: 'string' },
      { name: 'endpoint', type: 'string' },
      { name: 'feedbackURI', type: 'string' },
      { name: 'feedbackHash', type: 'bytes32' },
      { name: 'proof', type: 'tuple', components: [
        { name: 'agentId', type: 'uint256' },
        { name: 'submitter', type: 'address' },
        { name: 'timestamp', type: 'uint256' },
        { name: 'deadline', type: 'uint256' },
        { name: 'taskHash', type: 'bytes32' },
        { name: 'dataHashes', type: 'bytes32[]' },
        { name: 'frameworkHash', type: 'bytes32' },
        { name: 'signature', type: 'bytes' },
      ] },
      { name: 'task', type: 'tuple', components: [
        { name: 'method', type: 'string' },
        { name: 'uri', type: 'string' },
        { name: 'reqBodyHash', type: 'bytes32' },
        { name: 'respBodyHash', type: 'bytes32' },
        { name: 'statusCode', type: 'uint16' },
      ] },
    ],
    outputs: [{ name: 'feedbackIndex', type: 'uint64' }],
  },
  {
    type: 'function',
    name: 'canonicalReputation',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address' }],
  },
  {
    type: 'function',
    name: 'verifiedFeedback',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address' }],
  },
] as const;


/**
 * CloneGate — policy-mode cloning SATELLITE of AgenticID (the core contract
 * sits at the EIP-170 bytecode ceiling; clone policy + lineage live here).
 * The owner opts in with setCloneAuthorizer; the attestor mints through
 * cloneFrom, which consults the policy atomically. cloneAuthorizerOf returns
 * the EFFECTIVE authorizer: 0 when unset, cleared, or auto-invalidated by an
 * ownership transfer since it was set.
 */
export const cloneGateAbi = [
  {"type":"error","name":"CloneGateNotTrustedAttestor","inputs":[]},
  {"type":"error","name":"CloneGateNotTokenOwner","inputs":[{"name":"caller","type":"address"},{"name":"tokenId","type":"uint256"},{"name":"owner","type":"address"}]},
  {"type":"error","name":"CloneGateDenied","inputs":[{"name":"sourceAgentId","type":"uint256"},{"name":"authorizer","type":"address"}]},
  {"type":"error","name":"CloneGateDataHashMismatch","inputs":[{"name":"index","type":"uint256"},{"name":"onChain","type":"bytes32"},{"name":"submitted","type":"bytes32"}]},
  {"type":"error","name":"CloneGateArityMismatch","inputs":[{"name":"expected","type":"uint256"},{"name":"got","type":"uint256"}]},
  {
    type: 'function',
    name: 'setCloneAuthorizer',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'tokenId', type: 'uint256' },
      { name: 'authorizer', type: 'address' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'cloneAuthorizerOf',
    stateMutability: 'view',
    inputs: [{ name: 'tokenId', type: 'uint256' }],
    outputs: [{ name: '', type: 'address' }],
  },
  {
    type: 'function',
    name: 'cloneSourceOf',
    stateMutability: 'view',
    inputs: [{ name: 'agentId_', type: 'uint256' }],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    type: 'function',
    name: 'cloneFrom',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'sourceAgentId', type: 'uint256' },
      { name: 'to', type: 'address' },
      { name: 'dataHashes', type: 'bytes32[]' },
      { name: 'sealedKeys', type: 'bytes[]' },
      { name: 'newAgentSeal', type: 'address' },
      { name: 'newSealId', type: 'bytes32' },
      { name: 'caller', type: 'address' },
      { name: 'authData', type: 'bytes' },
    ],
    outputs: [{ name: 'agentId_', type: 'uint256' }],
  },
  {
    type: 'event',
    name: 'CloneAuthorizerSet',
    inputs: [
      { name: 'tokenId', type: 'uint256', indexed: true },
      { name: 'authorizer', type: 'address', indexed: true },
      { name: 'owner', type: 'address', indexed: false },
    ],
  },
  {
    type: 'event',
    name: 'ClonedFrom',
    inputs: [
      { name: 'sourceAgentId', type: 'uint256', indexed: true },
      { name: 'newAgentId', type: 'uint256', indexed: true },
      { name: 'to', type: 'address', indexed: true },
      { name: 'caller', type: 'address', indexed: false },
    ],
  },

  {
    type: 'function',
    name: 'agenticId',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address' }],
  },
] as const;

/**
 * StandardCloneAuthorizer — the OFFICIAL stock clone policy: purchases keyed
 * (sourceAgentId, purchaseId) → buyer, grant/revoke gated on the source's
 * current owner. The SDK's grantPurchase/revokePurchase/purchaseOf helpers
 * speak this ABI to whatever authorizer the token has configured — they only
 * work when that policy IS the standard one (a custom policy has its own
 * management surface).
 */
export const standardCloneAuthorizerAbi = [
  {
    type: 'function',
    name: 'grant',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'sourceAgentId', type: 'uint256' },
      { name: 'purchaseId', type: 'uint256' },
      { name: 'buyer', type: 'address' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'revoke',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'sourceAgentId', type: 'uint256' },
      { name: 'purchaseId', type: 'uint256' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'purchaseOf',
    stateMutability: 'view',
    inputs: [
      { name: 'sourceAgentId', type: 'uint256' },
      { name: 'purchaseId', type: 'uint256' },
    ],
    outputs: [
      { name: 'buyer', type: 'address' },
      { name: 'grantor', type: 'address' },
      { name: 'effective', type: 'bool' },
    ],
  },
  {
    type: 'function',
    name: 'canClone',
    stateMutability: 'view',
    inputs: [
      { name: 'sourceAgentId', type: 'uint256' },
      { name: 'targetOwner', type: 'address' },
      { name: 'caller', type: 'address' },
      { name: 'data', type: 'bytes' },
    ],
    outputs: [{ name: '', type: 'bool' }],
  },
  {
    type: 'error',
    name: 'StdCloneAuthNotSeller',
    inputs: [
      { name: 'caller', type: 'address' },
      { name: 'sourceAgentId', type: 'uint256' },
      { name: 'seller', type: 'address' },
    ],
  },
  {
    type: 'event',
    name: 'PurchaseGranted',
    inputs: [
      { name: 'sourceAgentId', type: 'uint256', indexed: true },
      { name: 'purchaseId', type: 'uint256', indexed: true },
      { name: 'buyer', type: 'address', indexed: true },
      { name: 'seller', type: 'address', indexed: false },
    ],
  },
  {
    type: 'event',
    name: 'PurchaseRevoked',
    inputs: [
      { name: 'sourceAgentId', type: 'uint256', indexed: true },
      { name: 'purchaseId', type: 'uint256', indexed: true },
      { name: 'seller', type: 'address', indexed: false },
    ],
  },
] as const;

/**
 * TappRegistry — trust-root acknowledgement. `ack` acknowledges the set of
 * TEE components (attestor, kms, sandbox) the deploy/sandbox flow depends on.
 */
export const tappRegistryAbi = [
  {
    type: 'function',
    name: 'acknowledgeApps',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'appIds', type: 'string[]' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'isAcknowledged',
    stateMutability: 'view',
    inputs: [
      { name: 'user', type: 'address' },
      { name: 'appId', type: 'string' },
    ],
    outputs: [{ name: '', type: 'bool' }],
  },
  {
    type: 'function',
    name: 'getAckVersion',
    stateMutability: 'view',
    inputs: [{ name: 'appId', type: 'string' }],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    type: 'function',
    name: 'getAppInfo',
    stateMutability: 'view',
    inputs: [{ name: 'appId', type: 'string' }],
    outputs: [{
      name: '', type: 'tuple', components: [
        { name: 'composeHash', type: 'bytes' },
        { name: 'volumesHash', type: 'bytes' },
        { name: 'imageHashes', type: 'bytes[]' },
        { name: 'owner', type: 'address' },
        { name: 'registeredAt', type: 'uint256' },
      ],
    }],
  },
  {
    type: 'function',
    name: 'getNodeList',
    stateMutability: 'view',
    inputs: [{ name: 'appId', type: 'string' }],
    outputs: [{ name: '', type: 'address[]' }],
  },
] as const;

/**
 * SandboxServing — prepaid sandbox balance. `deposit` funds the caller's (or a
 * recipient's) balance held against a provider; `getBalance` reads it.
 */
export const sandboxServingAbi = [
  {
    type: 'function',
    name: 'deposit',
    stateMutability: 'payable',
    inputs: [
      { name: 'recipient', type: 'address' },
      { name: 'provider', type: 'address' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'requestRefund',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'provider', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'withdrawRefund',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'provider', type: 'address' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'getBalance',
    stateMutability: 'view',
    inputs: [
      { name: 'user', type: 'address' },
      { name: 'provider', type: 'address' },
    ],
    outputs: [
      { name: 'balance', type: 'uint256' },
      { name: 'pendingRefund', type: 'uint256' },
      { name: 'refundUnlockAt', type: 'uint256' },
    ],
  },
  {
    type: 'function',
    name: 'services',
    stateMutability: 'view',
    inputs: [{ name: 'provider', type: 'address' }],
    outputs: [
      { name: 'url', type: 'string' },
      { name: 'appId', type: 'string' },
      { name: 'pricePerCPUPerMin', type: 'uint256' },
      { name: 'pricePerMemGBPerMin', type: 'uint256' },
      { name: 'createFee', type: 'uint256' },
    ],
  },
  {
    type: 'function',
    name: 'isTEEAcknowledged',
    stateMutability: 'view',
    inputs: [
      { name: 'user', type: 'address' },
      { name: 'provider', type: 'address' },
    ],
    outputs: [{ name: '', type: 'bool' }],
  },
] as const;
