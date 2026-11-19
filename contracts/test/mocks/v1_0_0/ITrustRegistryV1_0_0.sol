// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// TEST FIXTURE — FROZEN copy of ITrustRegistry as TrustRegistry 1.0.0
// implements it (git df03be6:contracts/src/interfaces/ITrustRegistry.sol).
// Only the interface name differs. Never edit.

/// @title ITrustRegistry
/// @notice The deployer's trust decisions, in one contract: who may act for
///         the platform (the trusted attestors and the Tapp app instances
///         they are bound to) and what code may run an agent (code lists by
///         kind: the image, the sealed program, the official harness).
///
///         AgenticID keeps none of this itself. Its trust reads
///         (`isTrustedAttestor`, `isValidFrameworkHash`, …) forward here, and
///         `AgenticID.trustRegistry()` is how sealed, the loader, the attestor
///         and the SDK find this contract.
interface ITrustRegistryV1_0_0 {
    // ── Events ────────────────────────────────────────────────────────────────

    event TrustedAttestorAdded(address indexed attestor);
    event TrustedAttestorRemoved(address indexed attestor);
    event TrustedAttestorAppBound(
        address indexed attestor, address indexed registry, string appId, uint256 registeredAt
    );
    event InstanceBoundAttestorsRequired();

    /// @notice `hash` joined the `kind` list and is now its latest entry.
    event Listed(bytes32 indexed kind, bytes32 indexed hash);
    /// @notice `hash` left the `kind` list.
    event Delisted(bytes32 indexed kind, bytes32 indexed hash);

    // ── Attestors ─────────────────────────────────────────────────────────────

    /// @notice Trust an attestor that is not bound to an app instance. Such an
    ///         attestor stops being trusted once instance binding is required.
    function addTrustedAttestor(address attestor) external;

    /// @notice Stop trusting an attestor and clear its app binding.
    function removeTrustedAttestor(address attestor) external;

    /// @notice Trust an attestor bound to one live Tapp app instance: the
    ///         registry's current (owner, registeredAt) for `appId` must match
    ///         `registeredAt`, and the trust lasts only while it still does.
    function bindTrustedAttestorApp(address attestor, address registry, string calldata appId, uint256 registeredAt)
        external;

    /// @notice One-way switch: from now on only instance-bound attestors are
    ///         trusted. Bind every production attestor first.
    function requireInstanceBoundAttestors() external;

    function isTrustedAttestor(address attestor) external view returns (bool);

    function instanceBoundAttestorsRequired() external view returns (bool);

    function trustedAttestorAppBinding(address attestor)
        external
        view
        returns (address registry, string memory appId, uint256 registeredAt, address appOwner);

    // ── Code lists ────────────────────────────────────────────────────────────

    /// @notice Add `hash` to the `kind` list, as its latest entry. Effective
    ///         immediately.
    function list(bytes32 kind, bytes32 hash) external;

    /// @notice Remove `hash` from the `kind` list. Effective immediately.
    function delist(bytes32 kind, bytes32 hash) external;

    function isListed(bytes32 kind, bytes32 hash) external view returns (bool);

    /// @notice The last hash added to the `kind` list that is still on it;
    ///         zero when the list is empty.
    function latest(bytes32 kind) external view returns (bytes32);

    /// @notice The whole `kind` list, oldest first.
    function listed(bytes32 kind) external view returns (bytes32[] memory);
}
