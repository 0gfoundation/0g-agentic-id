// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ─────────────────────────────────────────────────────────────────────────────
// TEST FIXTURE — the 1.1.0 IERC7857DataVerifier entrypoint, verbatim from
// src/interfaces/IERC7857DataVerifier.sol at git a417c65. The proof structs
// are unchanged and imported from src, so the frozen 1.1.0 mocks keep the
// same struct types (and iTransferFrom / iCloneFrom selectors) as src. Only
// the interface name (V1_1_0 suffix) differs. Never edit.
// ─────────────────────────────────────────────────────────────────────────────

import {TransferValidityProof, TransferValidityProofOutput} from "../../../src/interfaces/IERC7857DataVerifier.sol";

interface IERC7857DataVerifierV1_1_0 {
    function verifyTransferValidity(
        TransferValidityProof[] calldata proofs
    ) external returns (TransferValidityProofOutput[] memory);
}
