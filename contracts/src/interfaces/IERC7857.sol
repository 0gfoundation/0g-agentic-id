// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC721} from "@openzeppelin/contracts/interfaces/IERC721.sol";
import {IERC7857Metadata, IntelligentData} from "./IERC7857Metadata.sol";
import {IERC7857DataVerifier, TransferValidityProof} from "./IERC7857DataVerifier.sol";

/// @notice Pairs a data hash with the sealed key delivered to the new owner.
/// @dev Using a named struct rather than parallel arrays avoids index-ordering
///      ambiguity when correlating sealedKeys with IntelligentData entries.
struct SealedKeyEntry {
    bytes32 dataHash;
    bytes   sealedKey;
}

/// @title ERC7857 — Intelligent NFT Standard
/// @notice Extends ERC721 with cryptographically verified data-key transfer.
///
///         Every ERC7857 token carries IntelligentData. There is no notion of a
///         "plain NFT" within this standard — if a token has no IntelligentData
///         it should simply be an ERC721.
///
///         ERC7857 inherits ERC721 for ownership semantics and ecosystem
///         compatibility (wallets, explorers, indexers). However, the standard
///         ERC721 transfer functions are DISABLED: transferFrom and
///         safeTransferFrom always revert. All ownership transfers must go
///         through iTransferFrom so that the data key is atomically re-encrypted
///         and delivered to the new owner in the same transaction.
///
///         This follows the precedent of EIP-5192 (Soulbound Tokens), which
///         inherits ERC721 while intentionally restricting its transfer functions.
///         Implementations MUST revert transferFrom and safeTransferFrom with
///         ERC7857UseITransferFrom. Enforcement is at the implementation level.
///
/// @dev ERC-165: implementors MUST register both type(IERC7857).interfaceId and
///      type(IERC721).interfaceId in supportsInterface.
interface IERC7857 is IERC721, IERC7857Metadata {

    // ── Errors ────────────────────────────────────────────────────────────────

    /// @notice Raised when a proof submitted to iTransferFrom fails validation.
    /// @dev Implementations may use finer-grained internal errors for debugging,
    ///      but this is the canonical "proof rejected" signal at the interface level.
    error ERC7857InvalidProof();

    /// @notice Raised when transferFrom or safeTransferFrom is called directly.
    ///         All transfers must go through iTransferFrom.
    error ERC7857UseITransferFrom();

    // ── Events ────────────────────────────────────────────────────────────────

    /// @notice Emitted when a complete intelligent transfer succeeds.
    /// @dev This is the authoritative record of an ERC7857 transfer.
    ///      The standard ERC721 Transfer event is also emitted (as required by
    ///      ERC721), but ITransferred is the only event that carries sealedKeys
    ///      and unambiguously identifies the operation as a full ERC7857 transfer.
    ///      Indexers SHOULD use ITransferred (not ERC721 Transfer) to distinguish
    ///      iTransferFrom calls from any other ownership changes (e.g. mint/burn).
    /// @param from    Previous owner.
    /// @param to      New owner.
    /// @param tokenId Token identifier.
    /// @param entries One SealedKeyEntry per IntelligentData, ordered identically
    ///                to intelligentDatasOf(tokenId) at the time of transfer.
    event ITransferred(
        address indexed from,
        address indexed to,
        uint256 indexed tokenId,
        SealedKeyEntry[] entries
    );

    // ── View ──────────────────────────────────────────────────────────────────

    /// @notice Returns the verifier contract used to validate transfer proofs.
    function verifier() external view returns (IERC7857DataVerifier);

    // ── Transfer ──────────────────────────────────────────────────────────────

    /// @notice Transfer token ownership and atomically deliver the data key to `to`.
    ///
    /// @dev Authorization is checked BEFORE proof verification so that unauthorised
    ///      callers fail cheaply without spending gas on proof validation.
    ///      The caller must be the token owner or an ERC721-approved operator.
    ///
    ///      Proof ordering: proofs[i] must correspond to the i-th entry returned
    ///      by intelligentDatasOf(tokenId). The caller is responsible for ordering.
    ///
    ///      On success:
    ///        - Token ownership transfers (ERC721 Transfer event emitted).
    ///        - ITransferred is emitted with the full sealed-key set.
    ///        - Sealed keys are returned for on-chain composability.
    ///
    /// @param from    Current owner.
    /// @param to      Recipient. Must not be address(0).
    /// @param tokenId Token to transfer.
    /// @param proofs  One proof per IntelligentData entry, in intelligentDatasOf order.
    /// @return entries The sealed key for each IntelligentData entry.
    function iTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        TransferValidityProof[] calldata proofs
    ) external returns (SealedKeyEntry[] memory entries);
}
