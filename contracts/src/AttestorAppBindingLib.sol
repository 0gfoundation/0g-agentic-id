// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

error AgenticIDInvalidAttestorBinding();
error AgenticIDAppInstanceMismatch();

/// @dev Inherit this on the facade so its ABI keeps the errors whose reverts
/// are now produced by linked library code.
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

/// @dev Keep this field order: bindings already occupy the AgenticID proxy's
/// namespaced storage. Public library calls receive a storage slot and execute
/// through DELEGATECALL; the library has no owner, configuration or own state.
struct AttestorAppBinding {
    address registry;
    string appId;
    uint256 registeredAt;
    address appOwner;
}

library AttestorAppBindingLib {
    event TrustedAttestorAppBound(
        address indexed attestor, address indexed registry, string appId, uint256 registeredAt
    );
    event TrustedAttestorRemoved(address indexed attestor);

    function bind(
        mapping(address => AttestorAppBinding) storage bindings,
        mapping(address => bool) storage trustedAttestors,
        address attestor,
        address registry,
        string memory appId,
        uint256 registeredAt
    ) public {
        if (attestor == address(0) || registry == address(0) || bytes(appId).length == 0) {
            revert AgenticIDInvalidAttestorBinding();
        }
        (address appOwner, uint256 epoch) = _appInstance(registry, appId);
        if (registeredAt == 0 || epoch != registeredAt || appOwner == address(0)) {
            revert AgenticIDAppInstanceMismatch();
        }
        AttestorAppBinding storage binding = bindings[attestor];
        binding.registry = registry;
        binding.appId = appId;
        binding.registeredAt = registeredAt;
        binding.appOwner = appOwner;
        trustedAttestors[attestor] = true;
        emit TrustedAttestorAppBound(attestor, registry, appId, registeredAt);
    }

    function remove(
        mapping(address => AttestorAppBinding) storage bindings,
        mapping(address => bool) storage trustedAttestors,
        address attestor
    ) public {
        delete trustedAttestors[attestor];
        delete bindings[attestor];
        emit TrustedAttestorRemoved(attestor);
    }

    function isCurrent(AttestorAppBinding storage binding, bool instanceRequired)
        public
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
