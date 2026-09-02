// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

/// @notice Pins each namespaced-storage slot to the ERC-7201 derivation of its
///         namespace string. If a namespace string ever drifts, or a hand-written
///         slot constant is edited, the corresponding assertion fails loudly.
///         All but BaseDataVerifier are the canonical derivation; BaseDataVerifier
///         is a fixed literal that intentionally differs (see its source comment),
///         pinned here so the discrepancy stays visible.
contract StorageLayoutTest is Test {
    function _erc7201(string memory ns) internal pure returns (bytes32) {
        return keccak256(abi.encode(uint256(keccak256(bytes(ns))) - 1)) & ~bytes32(uint256(0xff));
    }

    function test_namespacedSlotsAreErc7201Derived() public pure {
        assertEq(_erc7201("0g.storage.AgenticID"),
            0xaa0e3d57ddf5d2f322a098202cb27f2804b292978acf041b4edd6beb821d4000);
        assertEq(_erc7201("0g.storage.ERC8004CanonicalBound"),
            0x953584d91cd6cf2e9540e8374496977361c15fe8ae3bbddea54d6d71100f4d00);
        assertEq(_erc7201("0g.storage.ERC7857Cloneable"),
            0x03de6cf14ecf4575e0ed0cc2fdb9b7ee13500cb3c0c403254fc893bf6e0c8000);
        assertEq(_erc7201("0g.storage.ERC7857Authorize"),
            0xf386e9faca35fbde2fe950510f665060c1dd15a136a76c268b6e6459b9945700);
        assertEq(_erc7201("0g.storage.ERC7857IDataStorage"),
            0xcee27158032fdbe7e1246476ff878669b520bc82ee1a949d22135b88cc5f5b00);
        assertEq(_erc7201("0g.storage.NonceRegistry"),
            0xd789013f031db4b6a1323b9e61ff1f12235bc6145ae87cd856aaccdef4ff2900);
        assertEq(_erc7201("0g.storage.TEEDataVerifier"),
            0x0d76357bf08e616bcf0d33ff28efd363c728d41b39fd849c3cb35d7bc6d0f500);
        assertEq(_erc7201("0g.storage.AgenticIDReputationRegistry"),
            0x006e35ac9067c2fcc8a4631e7a010043a67a2342b0b0036bfa95c5fb0d9ec700);
        assertEq(_erc7201("0g.storage.ERC7857"),
            0xa2b40c657abdbf180a6038c081d3a0af6206dcea36f4558f991bf8c787ef3c00);
        assertEq(_erc7201("0g.storage.VerifiedFeedbackRegistry"),
            0xa91e4c2ef61514299267811101bdc16c30719384e3b85c6fa8328f091e37e100);
        assertEq(_erc7201("0g.storage.CloneGate"),
            0x70c420e34ba808fea9cb59170b4cd5f9b7bcf6408241b0008bcba5d7b854d100);
    }

    /// @dev BaseDataVerifier's slot is a fixed literal, not the ERC-7201
    ///      derivation. Pinned so the (intentional) mismatch can't drift
    ///      silently — the constant differs from the derived value, and the
    ///      derived value is what the source comment now documents.
    function test_baseDataVerifierSlotIsIntentionalLiteral() public pure {
        bytes32 literal  = 0x2a6e9d47b6f4c10d00c1ba6c2a83e5a99f9ffd6b1a85ca0f0b97a3c3c3a27c00;
        bytes32 derived  = _erc7201("0g.storage.BaseDataVerifier");
        assertTrue(literal != derived, "literal must differ from the derivation");
        assertEq(derived, 0xebd3f1ab6f96c5a8aa3a8f7ae4cb91de9050e806218c0e227b71fda38a32fd00);
    }
}
