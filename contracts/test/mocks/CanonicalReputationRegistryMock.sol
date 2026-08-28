// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Stand-in for the official ERC-8004 Reputation Registry (the fixed
///         0x8004B… singleton on 0G). Mirrors the v2.0.0 semantics the
///         VerifiedFeedbackRegistry relies on: feedback attributed to
///         msg.sender, 1-based per-(agentId, client) indexes, revoke flag,
///         getLastIndex == entry count. No self-feedback or bounds checks —
///         tests exercise those in the contract under test, not here.
contract CanonicalReputationRegistryMock {
    struct Entry {
        int128 value;
        uint8  valueDecimals;
        string tag1;
        string tag2;
        bool   isRevoked;
    }

    // agentId → client → entries (index i holds 1-based feedbackIndex i+1)
    mapping(uint256 => mapping(address => Entry[])) internal entries;

    function giveFeedback(
        uint256 agentId,
        int128  value,
        uint8   valueDecimals,
        string calldata tag1,
        string calldata tag2,
        string calldata, // endpoint — emitted only by the real contract
        string calldata, // feedbackURI
        bytes32          // feedbackHash
    ) external {
        entries[agentId][msg.sender].push(Entry(value, valueDecimals, tag1, tag2, false));
    }

    function revokeFeedback(uint256 agentId, uint64 feedbackIndex) external {
        Entry[] storage list = entries[agentId][msg.sender];
        require(feedbackIndex > 0 && feedbackIndex <= list.length, "index out of bounds");
        list[feedbackIndex - 1].isRevoked = true;
    }

    function getLastIndex(uint256 agentId, address clientAddress) external view returns (uint64) {
        return uint64(entries[agentId][clientAddress].length);
    }

    function readFeedback(
        uint256 agentId,
        address clientAddress,
        uint64  feedbackIndex
    ) external view returns (int128, uint8, string memory, string memory, bool) {
        Entry[] storage list = entries[agentId][clientAddress];
        require(feedbackIndex > 0 && feedbackIndex <= list.length, "index out of bounds");
        Entry storage e = list[feedbackIndex - 1];
        return (e.value, e.valueDecimals, e.tag1, e.tag2, e.isRevoked);
    }

    function getIdentityRegistry() external pure returns (address) {
        return address(0); // unused by the contract under test
    }

    function getVersion() external pure returns (string memory) {
        return "2.0.0";
    }
}
