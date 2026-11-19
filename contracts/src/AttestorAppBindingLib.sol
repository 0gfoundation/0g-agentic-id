// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

error AgenticIDInvalidAttestorBinding();
error AgenticIDAppInstanceMismatch();

/// @dev Inherited by TrustRegistry so its ABI carries the errors the binding
///      code reverts with.
interface IAttestorAppBindingErrors {
    error AgenticIDInvalidAttestorBinding();
    error AgenticIDAppInstanceMismatch();
}

interface IAttestorAppRegistry {
    struct AppInfo {
        bytes composeHash;
        bytes volumesHash;
        bytes[] imageHashes;
        address owner;
        uint256 registeredAt;
    }

    function getAppInfo(string calldata appId) external view returns (AppInfo memory);
}

/// @dev Keep this field order: AgenticID 1.3.0 stored bindings in this shape in
///      its namespaced storage, and TrustRegistry stores them the same way.
struct AttestorAppBinding {
    address registry;
    string appId;
    uint256 registeredAt;
    address appOwner;
}

/// @notice Binding an attestor to one live Tapp app instance, and checking
///         that the instance is still the one it was bound to. Internal
///         helpers for TrustRegistry; the caller emits the events.
library AttestorAppBindingLib {
    /// @dev Records the binding after checking that the registry's current
    ///      instance of `appId` is the one registered at `registeredAt`.
    function bind(
        AttestorAppBinding storage binding,
        address attestor,
        address registry,
        string memory appId,
        uint256 registeredAt
    ) internal {
        if (attestor == address(0) || registry == address(0) || bytes(appId).length == 0) {
            revert AgenticIDInvalidAttestorBinding();
        }
        (address appOwner, uint256 epoch) = _appInstance(registry, appId);
        if (registeredAt == 0 || epoch != registeredAt || appOwner == address(0)) {
            revert AgenticIDAppInstanceMismatch();
        }
        binding.registry = registry;
        binding.appId = appId;
        binding.registeredAt = registeredAt;
        binding.appOwner = appOwner;
    }

    /// @dev An unbound attestor is current only while instance binding is not
    ///      required; a bound one only while its app instance (registeredAt
    ///      and owner) is unchanged.
    function isCurrent(AttestorAppBinding storage binding, bool instanceRequired)
        internal
        view
        returns (bool)
    {
        if (binding.registeredAt == 0) return !instanceRequired;
        (address appOwner, uint256 epoch) = _appInstance(binding.registry, binding.appId);
        return
            epoch == binding.registeredAt && appOwner != address(0) && appOwner == binding.appOwner;
    }

    /// Read only the two authorization fields. Dynamic compose, volume and
    /// image bodies are not copied. Reverts and malformed heads fail closed.
    function _appInstance(address registry, string memory appId)
        private
        view
        returns (address appOwner, uint256 epoch)
    {
        bytes memory input = abi.encodeWithSelector(IAttestorAppRegistry.getAppInfo.selector, appId);
        assembly ("memory-safe") {
            let head := mload(0x40)
            mstore(0x40, add(head, 0xc0))
            let ok := staticcall(gas(), registry, add(input, 0x20), mload(input), head, 0xc0)
            if and(ok, iszero(lt(returndatasize(), 0xc0))) {
                let ownerWord := mload(add(head, 0x80))
                if and(eq(mload(head), 0x20), iszero(shr(160, ownerWord))) {
                    appOwner := ownerWord
                    epoch := mload(add(head, 0xa0))
                }
            }
        }
    }
}
