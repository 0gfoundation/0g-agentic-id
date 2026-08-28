// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ICanonicalReputationRegistry
/// @notice External surface of the **fixed, unmodifiable** official ERC-8004
///         Reputation Registry that {VerifiedFeedbackRegistry} anchors to.
///
///         On 0G Galileo testnet (chain 16602) this is the UUPS proxy at
///         0x8004B663056A597Dffe9eCcC1965A193B7388713 (v2.0.0); on 0G mainnet
///         it is 0x8004BAa17C55a88189AE136b182e5fdA19dE9b63 (v2.0.0). Both are
///         bound to the same canonical Identity Registry that AgenticID
///         custody-binds to, so the agentId space is shared.
///
///         The canonical registry is permissionless: feedback is attributed to
///         `msg.sender` (the client), with no delegation or signature scheme.
///         AgenticID therefore does NOT proxy writes here — clients submit
///         feedback to the canonical registry directly, then attest it in
///         {VerifiedFeedbackRegistry} with a TEE-signed ServeProof.
///
/// @dev Only the subset VerifiedFeedbackRegistry actually calls is declared
///      (plus the deploy-time sanity checks). Signatures match the live
///      contract exactly — 1-based feedbackIndex, uint64 indexes.
interface ICanonicalReputationRegistry {
    /// @notice Submit feedback, attributed to msg.sender (the client).
    /// @dev Called by {FeedbackBatcher} while executing AS the client's EOA
    ///      (EIP-7702 delegation) — never by protocol contracts directly.
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

    /// @notice 1-based index of the most recent feedback from `clientAddress`
    ///         for `agentId`; 0 when there is none. Equals the entry count.
    function getLastIndex(uint256 agentId, address clientAddress) external view returns (uint64);

    /// @notice Read a single feedback entry (1-based index; reverts out of range).
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

    /// @notice The canonical Identity Registry this reputation registry is bound to.
    function getIdentityRegistry() external view returns (address);

    function getVersion() external view returns (string memory);
}
