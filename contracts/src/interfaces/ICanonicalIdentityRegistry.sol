// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ICanonicalIdentityRegistry
/// @notice External surface of the **fixed, unmodifiable** official ERC-8004
///         Identity Registry that AgenticID binds to.
///
///         On 0G Galileo testnet (chain 16602) this is the UUPS proxy at
///         0x8004a818bfb912233c491871b3d84c89a494bd9e (impl v2.0.0,
///         name "AgentIdentity", symbol "AGENT", EIP-712 domain
///         "ERC8004IdentityRegistry"/"1"). It is a live, permissionless,
///         shared registry — agentIds are a single global counter starting
///         at 0, assigned across all projects that register here.
///
///         AgenticID does NOT reimplement ERC-8004. It custodies one canonical
///         token per agent (the canonical token is owned by the AgenticID
///         contract) and proxies reads/writes here, so any tool that indexes
///         the canonical registry sees 0G agents natively.
///
/// @dev Only the subset AgenticID actually calls is declared. Signatures match
///      the live contract exactly — notably the 4-argument `setAgentWallet`
///      (no nonce; the official contract caps the deadline at 5 minutes
///      instead) and the 0-based, globally-shared `agentId` numbering.
interface ICanonicalIdentityRegistry {
    /// @notice Mint a new agent token to msg.sender. Returns the global agentId.
    /// @dev Numbering starts at 0 (`agentId = _lastId++`) and is shared across
    ///      every registrant. The official contract also seeds
    ///      `agentWallet = msg.sender`; AgenticID clears it right after mint so
    ///      the agent starts with an empty payment wallet.
    function register() external returns (uint256 agentId);

    function setAgentURI(uint256 agentId, string calldata newURI) external;

    function tokenURI(uint256 agentId) external view returns (string memory);

    function getMetadata(uint256 agentId, string calldata metadataKey)
        external view returns (bytes memory);

    function setMetadata(uint256 agentId, string calldata metadataKey, bytes calldata metadataValue)
        external;

    function getAgentWallet(uint256 agentId) external view returns (address);

    /// @notice Official 4-arg form. `signature` is an EIP-712 consent signature
    ///         from `newWallet` over
    ///         `AgentWalletSet(uint256 agentId,address newWallet,address owner,uint256 deadline)`
    ///         under the canonical registry's own EIP-712 domain. `owner` is the
    ///         canonical token holder — i.e. the AgenticID contract address.
    ///         The official contract requires `deadline <= block.timestamp + 5 minutes`.
    function setAgentWallet(
        uint256 agentId,
        address newWallet,
        uint256 deadline,
        bytes calldata signature
    ) external;

    function unsetAgentWallet(uint256 agentId) external;

    function ownerOf(uint256 agentId) external view returns (address);
}
