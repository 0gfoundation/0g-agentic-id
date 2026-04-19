// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgenticIDTestBase} from "./AgenticIDTestBase.sol";
import {IAgenticID} from "../contracts/interfaces/IAgenticID.sol";
import {IERC8004IdentityRegistry} from "../contracts/interfaces/IERC8004IdentityRegistry.sol";
import {IERC7857} from "../contracts/interfaces/IERC7857.sol";
import {IERC7857Authorize} from "../contracts/interfaces/IERC7857Authorize.sol";
import {IERC7857Cloneable} from "../contracts/interfaces/IERC7857Cloneable.sol";
import {IERC7857Delegate} from "../contracts/interfaces/IERC7857Delegate.sol";
import {IERC7857Updatable} from "../contracts/interfaces/IERC7857Updatable.sol";
import {IERC721} from "@openzeppelin/contracts/interfaces/IERC721.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

contract ERC165Test is AgenticIDTestBase {
    function test_supportsInterface_declaredInterfaces() public view {
        assertTrue(agenticId.supportsInterface(type(IERC165).interfaceId), "IERC165");
        assertTrue(agenticId.supportsInterface(type(IERC721).interfaceId), "IERC721");
        assertTrue(agenticId.supportsInterface(type(IAgenticID).interfaceId), "IAgenticID");
        assertTrue(
            agenticId.supportsInterface(type(IERC8004IdentityRegistry).interfaceId),
            "IERC8004IdentityRegistry"
        );
        assertTrue(agenticId.supportsInterface(type(IERC7857).interfaceId), "IERC7857");
        assertTrue(
            agenticId.supportsInterface(type(IERC7857Updatable).interfaceId),
            "IERC7857Updatable"
        );
        assertTrue(
            agenticId.supportsInterface(type(IERC7857Authorize).interfaceId),
            "IERC7857Authorize"
        );
        assertTrue(
            agenticId.supportsInterface(type(IERC7857Cloneable).interfaceId),
            "IERC7857Cloneable"
        );
        assertTrue(
            agenticId.supportsInterface(type(IERC7857Delegate).interfaceId),
            "IERC7857Delegate"
        );
    }

    function test_supportsInterface_returnsFalseForUnknown() public view {
        // Invalid interfaceId per ERC-165 spec (0xffffffff must return false).
        assertTrue(!agenticId.supportsInterface(0xffffffff), "invalid id");
        // Arbitrary unrelated bytes4.
        assertTrue(!agenticId.supportsInterface(0xdeadbeef), "unknown id");
    }
}
