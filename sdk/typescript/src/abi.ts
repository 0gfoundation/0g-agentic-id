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

  // ── Seal Management ──
  {
    type: 'function',
    name: 'setAgentSeal',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'agentSeal_', type: 'address' },
      { name: 'sealId', type: 'bytes32' },
    ],
    outputs: [],
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
 * ABI for the ReputationRegistry contract.
 */
export const reputationRegistryAbi = [
  // ── Give Feedback ──
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
      { name: 'ServeProof', type: 'tuple', components: [
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

  // ── Get Serve Data ──
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

  // ── Events ──
  {
    type: 'event',
    name: 'FeedbackGiven',
    inputs: [
      { name: 'agentId', type: 'uint256', indexed: true },
      { name: 'client', type: 'address', indexed: true },
      { name: 'feedbackIndex', type: 'uint64', indexed: true },
    ],
  },
  {
    type: 'event',
    name: 'FeedbackRevoked',
    inputs: [
      { name: 'agentId', type: 'uint256', indexed: true },
      { name: 'feedbackIndex', type: 'uint64', indexed: true },
    ],
  },
  {
    type: 'event',
    name: 'ResponseAppended',
    inputs: [
      { name: 'agentId', type: 'uint256', indexed: true },
      { name: 'clientAddress', type: 'address', indexed: true },
      { name: 'feedbackIndex', type: 'uint64', indexed: true },
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
    name: 'getBalance',
    stateMutability: 'view',
    inputs: [
      { name: 'user', type: 'address' },
      { name: 'provider', type: 'address' },
    ],
    outputs: [{ name: '', type: 'uint256' }],
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
