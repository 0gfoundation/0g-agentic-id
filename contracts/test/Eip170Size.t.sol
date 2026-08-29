// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

/// @title Eip170SizeTest
/// @notice Deploy-size gate. Local test EVMs do NOT enforce the EIP-170
///         runtime-bytecode limit, so a green suite can hide an undeployable
///         contract — that is exactly how AgenticID 1.2.0 (26,722 bytes)
///         reached dev before its upgrade tx reverted on chain. This test
///         makes the limit a suite failure instead of a deploy-time surprise.
///         (Second occurrence; the first was fixed in eeec9ab.)
contract Eip170SizeTest is Test {
    uint256 internal constant EIP170_LIMIT = 24576;

    function _assertDeployable(string memory artifact) internal view {
        uint256 size = vm.getDeployedCode(artifact).length;
        assertLe(size, EIP170_LIMIT, string.concat(artifact, " exceeds the EIP-170 runtime-size limit"));
    }

    function test_allDeployedImplsFitEip170() public view {
        // Every contract we actually put on chain (beacon impls + the
        // non-upgradeable 7702 delegate). Add new deployables here.
        _assertDeployable("AgenticID.sol:AgenticID");
        _assertDeployable("VerifiedFeedbackRegistry.sol:VerifiedFeedbackRegistry");
        _assertDeployable("CloneGate.sol:CloneGate");
        _assertDeployable("FeedbackBatcher.sol:FeedbackBatcher");
        _assertDeployable("TEEDataVerifier.sol:TEEDataVerifier");
    }
}
