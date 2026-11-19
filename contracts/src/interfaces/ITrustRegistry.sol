// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

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
///
///         Adding trust and removing it have different keys. The owner — the
///         environment's TimelockController — lists versions, trusts and binds
///         attestors and sets the guardian, each a scheduled operation that
///         can be cancelled before it runs. The guardian removes trust at
///         once: `delist` and `removeTrustedAttestor` (the owner can too).
interface ITrustRegistry {
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

    /// @notice The guardian changed (zero: none).
    event GuardianSet(address indexed previous, address indexed guardian);

    // ── Guardian ──────────────────────────────────────────────────────────────

    /// @notice Owner only. The account that may remove trust at once
    ///         (`delist`, `removeTrustedAttestor`) besides the owner; zero
    ///         for none.
    function setGuardian(address guardian) external;

    function guardian() external view returns (address);

    // ── Attestors ─────────────────────────────────────────────────────────────

    /// @notice Trust an attestor that is not bound to an app instance. Such an
    ///         attestor stops being trusted once instance binding is required.
    function addTrustedAttestor(address attestor) external;

    /// @notice Stop trusting an attestor and clear its app binding. The owner
    ///         or the guardian.
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

    /// @notice Add `hash` to the `kind` list, as its latest entry. Owner only;
    ///         effective when the call runs.
    function list(bytes32 kind, bytes32 hash) external;

    /// @notice Remove `hash` from the `kind` list. The owner or the guardian;
    ///         effective when the call runs.
    function delist(bytes32 kind, bytes32 hash) external;

    function isListed(bytes32 kind, bytes32 hash) external view returns (bool);

    /// @notice The last hash added to the `kind` list that is still on it;
    ///         zero when the list is empty.
    function latest(bytes32 kind) external view returns (bytes32);

    /// @notice The whole `kind` list, oldest first.
    function listed(bytes32 kind) external view returns (bytes32[] memory);
}
