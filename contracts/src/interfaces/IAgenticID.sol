// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC8004IdentityRegistry, MetadataEntry} from "./IERC8004IdentityRegistry.sol";
import {IERC7857} from "./IERC7857.sol";
import {IntelligentData} from "./IERC7857Metadata.sol";

/// @title AgenticID
/// @notice Combined interface for the AgenticID protocol token.
///
///         AgenticID merges two standards:
///
///           • ERC-8004 Identity Registry — agent registration, metadata, and wallet
///             management. Each agent is an ERC-721 token identified by agentId.
///
///           • ERC-7857 — the token also carries IntelligentData (model weights,
///             configs, etc.) and enforces cryptographic proof on every transfer so
///             the data key is atomically delivered to the new owner.
///
///         Both standards inherit ERC-721; Solidity resolves the diamond via C3
///         linearization. There is exactly one token per agent.
///
///         AgenticID additionally introduces agentSeal: a TEE-derived identity whose
///         private key never leaves TEE memory. agentSeal signs ServeProofs that
///         attest real service interactions, enabling sybil-resistant reputation.
///
///         Seal registration is gated by the trustedAttestors whitelist. Attestors
///         perform remote attestation off-chain and read the validFrameworkHashes
///         registry to decide whether to provision the agentSeal private key.
///
///         sealId is a stable identifier for the TEE instance. agentSeal and sealId
///         are bound to an agentId exactly once and are immutable for the token's
///         lifetime — they persist across transfers and cannot be rotated or replaced.
///
/// @dev Implementors must also deploy an IAgenticIDReputationRegistry that accepts
///      ServeProofs signed by the agentSeal registered here.
interface IAgenticID is IERC8004IdentityRegistry, IERC7857 {

    // ── Events ────────────────────────────────────────────────────────────────

    /// @notice Emitted exactly once per agentId, when its agentSeal / sealId are first set.
    /// @dev agentSeal and sealId are immutable after this event and persist across transfers.
    event AgentSealSet(
        uint256 indexed agentId,
        address indexed agentSeal,
        bytes32 indexed sealId
    );

    event TrustedAttestorAdded(address indexed attestor);
    event TrustedAttestorRemoved(address indexed attestor);

    event ValidFrameworkHashAdded(bytes32 indexed frameworkHash);
    event ValidFrameworkHashRemoved(bytes32 indexed frameworkHash);

    // ── Registration ──────────────────────────────────────────────────────────

    /// @notice Register a new agent with IntelligentData. Mints to msg.sender.
    /// @dev sealedKeys[i] corresponds to intelligentDatas[i].dataHash. The contract
    ///      does NOT verify the encryption — the caller chooses a target pubkey
    ///      they control. Losing access to the unsealing key makes future
    ///      iTransferFrom impossible (no valid OwnershipProof can be produced).
    ///      Emits ITransferred(address(0), msg.sender, agentId, entries).
    function register(
        string calldata agentURI,
        MetadataEntry[] calldata metadata,
        IntelligentData[] calldata intelligentDatas,
        bytes[] calldata sealedKeys
    ) external returns (uint256 agentId);

    /// @notice Register a new agent with IntelligentData, sealedKeys, and agentSeal.
    /// @dev Only a trusted attestor may call this. Off-chain, the attestor has
    ///      generated dataKey_i per IntelligentData, encrypted the plaintext data,
    ///      and produced sealedKeys[i] = E(dataKey_i, agentSeal_pub). The Agent TEE
    ///      will later receive agentSeal_priv from the attestor and unseal dataKey_i
    ///      on demand. Emits ITransferred(address(0), to, agentId, entries).
    /// @param to           Address that will own the minted token.
    /// @param sealedKeys   sealedKeys[i] targets agentSeal_pub for intelligentDatas[i].
    /// @param agentSeal_   TEE-derived signing address for this agent.
    /// @param sealId       Stable identifier for the TEE instance derivation path.
    function registerWithSeal(
        address to,
        string calldata agentURI,
        MetadataEntry[] calldata metadata,
        IntelligentData[] calldata intelligentDatas,
        bytes[] calldata sealedKeys,
        address agentSeal_,
        bytes32 sealId
    ) external returns (uint256 agentId);

    // ── agentSeal ─────────────────────────────────────────────────────────────

    /// @notice Set the agentSeal for an agent whose seal has not yet been set.
    /// @dev Only a trusted attestor may call this. One-time only: reverts if the agent
    ///      already has an agentSeal, or if sealId is already bound to another agent.
    ///      Use registerWithSeal to bind the seal at registration time in a single call.
    function setAgentSeal(
        uint256 agentId,
        address agentSeal_,
        bytes32 sealId
    ) external;

    /// @notice Returns the current agentSeal address for an agent.
    /// @dev Returns address(0) if no seal has been registered.
    function getAgentSeal(uint256 agentId) external view returns (address agentSeal);

    /// @notice Returns the stable sealId for an agent.
    /// @dev Returns bytes32(0) if no seal has been registered.
    function getSealId(uint256 agentId) external view returns (bytes32 sealId);

    /// @notice Returns the agentId bound to a given sealId.
    /// @dev Returns 0 if the sealId is not registered.
    function getAgentIdBySealId(bytes32 sealId) external view returns (uint256 agentId);

    // ── Trusted attestors ─────────────────────────────────────────────────────

    /// @notice Add an address to the trusted attestor whitelist.
    function addTrustedAttestor(address attestor) external;

    /// @notice Remove an address from the trusted attestor whitelist.
    function removeTrustedAttestor(address attestor) external;

    function isTrustedAttestor(address attestor) external view returns (bool);

    // ── Valid framework hashes ────────────────────────────────────────────────

    /// @notice Add a framework hash to the registry. Read off-chain by attestors.
    function addValidFrameworkHash(bytes32 frameworkHash) external;

    /// @notice Remove a framework hash from the registry.
    function removeValidFrameworkHash(bytes32 frameworkHash) external;

    function isValidFrameworkHash(bytes32 frameworkHash) external view returns (bool);
}
