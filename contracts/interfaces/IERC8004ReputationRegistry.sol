// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ERC-8004 Reputation Registry
/// @notice Records feedback and reputation scores for agents.
///         Only addresses pre-authorised by the agent owner may submit feedback.
interface IERC8004ReputationRegistry {

    // ── Events ────────────────────────────────────────────────────────────────

    event NewFeedback(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64  feedbackIndex,
        int128  value,
        uint8   valueDecimals,
        string  indexed indexedTag1,
        string  tag1,
        string  tag2,
        string  endpoint,
        string  feedbackURI,
        bytes32 feedbackHash
    );

    event FeedbackRevoked(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64  indexed feedbackIndex
    );

    event ResponseAppended(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64  feedbackIndex,
        address indexed responder,
        string  responseURI,
        bytes32 responseHash
    );

    // ── Write ─────────────────────────────────────────────────────────────────

    /// @notice Submit feedback for an agent.
    /// @dev Caller must be pre-authorised by the agent owner.
    ///      `value` is a fixed-point number with `valueDecimals` decimals (0–18).
    ///      `endpoint`, `feedbackURI`, and `feedbackHash` are emitted but not stored on-chain.
    function giveFeedback(
        uint256 agentId,
        int128  value,
        uint8   valueDecimals,
        string calldata tag1,
        string calldata tag2,
        string calldata endpoint,
        string calldata feedbackURI,
        bytes32 feedbackHash
    ) external;

    /// @notice Revoke a previously submitted feedback entry.
    /// @dev Only the original submitter may revoke.
    function revokeFeedback(uint256 agentId, uint64 feedbackIndex) external;

    /// @notice Append an agent's response to a feedback entry.
    /// @dev Only the agent owner may append a response.
    function appendResponse(
        uint256 agentId,
        address clientAddress,
        uint64  feedbackIndex,
        string calldata responseURI,
        bytes32 responseHash
    ) external;

    // ── Read ──────────────────────────────────────────────────────────────────

    function getIdentityRegistry() external view returns (address);

    /// @notice Aggregate feedback summary filtered by client addresses and tags.
    function getSummary(
        uint256 agentId,
        address[] calldata clientAddresses,
        string calldata tag1,
        string calldata tag2
    ) external view returns (uint64 count, int128 summaryValue, uint8 summaryValueDecimals);

    /// @notice Read a single feedback entry.
    function readFeedback(
        uint256 agentId,
        address clientAddress,
        uint64  feedbackIndex
    ) external view returns (
        int128  value,
        uint8   valueDecimals,
        string memory tag1,
        string memory tag2,
        bool    isRevoked
    );

    /// @notice Read all feedback entries matching the given filters.
    function readAllFeedback(
        uint256 agentId,
        address[] calldata clientAddresses,
        string calldata tag1,
        string calldata tag2,
        bool includeRevoked
    ) external view returns (
        address[] memory clients,
        uint64[]  memory feedbackIndexes,
        int128[]  memory values,
        uint8[]   memory valueDecimals,
        string[]  memory tag1s,
        string[]  memory tag2s,
        bool[]    memory revokedStatuses
    );

    function getResponseCount(
        uint256 agentId,
        address clientAddress,
        uint64  feedbackIndex,
        address[] calldata responders
    ) external view returns (uint64 count);

    function getClients(uint256 agentId) external view returns (address[] memory);

    function getLastIndex(uint256 agentId, address clientAddress) external view returns (uint64);
}
