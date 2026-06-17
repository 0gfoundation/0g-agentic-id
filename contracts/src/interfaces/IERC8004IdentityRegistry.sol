// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC721} from "@openzeppelin/contracts/interfaces/IERC721.sol";

/// @notice Key-value metadata entry for agent registration.
struct MetadataEntry {
    string metadataKey;
    bytes  metadataValue;
}

/// @title ERC-8004 Identity Registry
/// @notice Agent registration using ERC-721. Each agent is identified by a
///         unique `agentId` which is the minted token ID.
interface IERC8004IdentityRegistry is IERC721 {

    // ── Events ────────────────────────────────────────────────────────────────

    event Registered(uint256 indexed agentId, string agentURI, address indexed owner);

    event URIUpdated(uint256 indexed agentId, string newURI, address indexed updatedBy);

    event MetadataSet(
        uint256 indexed agentId,
        string  indexed indexedMetadataKey,
        string  metadataKey,
        bytes   metadataValue
    );

    // ── Registration ──────────────────────────────────────────────────────────

    function register(string calldata agentURI, MetadataEntry[] calldata metadata)
        external returns (uint256 agentId);

    function register(string calldata agentURI)
        external returns (uint256 agentId);

    function register()
        external returns (uint256 agentId);

    // ── URI ───────────────────────────────────────────────────────────────────

    function setAgentURI(uint256 agentId, string calldata newURI) external;

    // ── Metadata ──────────────────────────────────────────────────────────────

    function getMetadata(uint256 agentId, string memory metadataKey)
        external view returns (bytes memory);

    function setMetadata(
        uint256 agentId,
        string memory metadataKey,
        bytes memory metadataValue
    ) external;

    // ── Agent wallet ──────────────────────────────────────────────────────────

    /// @notice Set the wallet that receives service payments for this agent.
    /// @dev Forwarded to the canonical ERC-8004 registry, which enforces the
    ///      official consent scheme: an EIP-712 signature from `newWallet` over
    ///      AgentWalletSet(uint256 agentId,address newWallet,address owner,uint256 deadline)
    ///      under domain "ERC8004IdentityRegistry"/"1", where `owner` is the
    ///      canonical token holder (the AgenticID contract). The canonical
    ///      contract caps `deadline` at `block.timestamp + 5 minutes`; replay is
    ///      moot because the call idempotently overwrites the stored wallet.
    function setAgentWallet(
        uint256 agentId,
        address newWallet,
        uint256 deadline,
        bytes calldata signature
    ) external;

    function getAgentWallet(uint256 agentId) external view returns (address);

    /// @notice Clear the agent wallet. Must be called automatically on token transfer.
    function unsetAgentWallet(uint256 agentId) external;
}
