// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ERC-8004 Validation Registry
/// @notice Records independent third-party validator checks for agents.
///         Response values range 0–100 and may be used as binary (0 = fail,
///         100 = pass) or as a spectrum for graded outcomes.
interface IERC8004ValidationRegistry {

    // ── Events ────────────────────────────────────────────────────────────────

    event ValidationRequest(
        address indexed validatorAddress,
        uint256 indexed agentId,
        string  requestURI,
        bytes32 indexed requestHash
    );

    event ValidationResponse(
        address indexed validatorAddress,
        uint256 indexed agentId,
        bytes32 indexed requestHash,
        uint8   response,
        string  responseURI,
        bytes32 responseHash,
        string  tag
    );

    // ── Write ─────────────────────────────────────────────────────────────────

    /// @notice Request a validation check from a specific validator.
    function validationRequest(
        address validatorAddress,
        uint256 agentId,
        string calldata requestURI,
        bytes32 requestHash
    ) external;

    /// @notice Submit a validation response. Only callable by the designated validator.
    /// @param response Score 0–100.
    function validationResponse(
        bytes32 requestHash,
        uint8   response,
        string calldata responseURI,
        bytes32 responseHash,
        string calldata tag
    ) external;

    // ── Read ──────────────────────────────────────────────────────────────────

    function getIdentityRegistry() external view returns (address);

    function getValidationStatus(bytes32 requestHash)
        external view returns (
            address validatorAddress,
            uint256 agentId,
            uint8   response,
            bytes32 responseHash,
            string memory tag,
            uint256 lastUpdate
        );

    /// @notice Aggregate validation summary filtered by validators and tag.
    function getSummary(
        uint256 agentId,
        address[] calldata validatorAddresses,
        string calldata tag
    ) external view returns (uint64 count, uint8 averageResponse);

    function getAgentValidations(uint256 agentId)
        external view returns (bytes32[] memory requestHashes);

    function getValidatorRequests(address validatorAddress)
        external view returns (bytes32[] memory requestHashes);
}
