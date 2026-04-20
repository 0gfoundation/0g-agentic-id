// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {AgenticID} from "../contracts/AgenticID.sol";
import {TEEDataVerifier} from "../contracts/verifiers/TEEDataVerifier.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/// @notice Guards against:
///           • Re-initializing a proxy (once it has been initialized)
///           • Initializing the implementation contract directly (disabled via _disableInitializers)
contract InitializerGuardTest is AgenticIDTestBase {
    function test_proxy_cannotReinitialize() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        agenticId.initialize("x", "x", address(verifier), owner, pauser, MAX_PROOF_AGE);
    }

    function test_verifier_cannotReinitialize() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        verifier.initialize(owner, pauser, oracleAddr, MAX_PROOF_AGE);
    }

    function test_implementation_initializeDisabled() public {
        // Deploy a fresh impl — constructor calls _disableInitializers.
        AgenticID impl = new AgenticID();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize("x", "x", address(verifier), owner, pauser, MAX_PROOF_AGE);

        TEEDataVerifier vImpl = new TEEDataVerifier();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        vImpl.initialize(owner, pauser, oracleAddr, MAX_PROOF_AGE);
    }
}
