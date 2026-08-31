// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ICloneAuthorizer} from "./interfaces/ICloneAuthorizer.sol";

interface IERC721OwnerOf {
    function ownerOf(uint256 tokenId) external view returns (address);
}

/// @notice grant/revoke caller is not the source token's current owner.
error StdCloneAuthNotSeller(address caller, uint256 sourceAgentId, address seller);

/// @title StandardCloneAuthorizer
/// @notice The OFFICIAL stock clone policy (issue #133): "a purchase is an
///         entitlement to fork THIS agent". Publishers who want marketplace
///         fork flows without writing a policy contract point their token at
///         this one (`CloneGate.setCloneAuthorizer(id, address(this))`) and
///         manage purchases themselves — no platform admin involved.
///
///         What it fixes over the DevCloneAuthorizer example:
///           - **per-agent scoping**: a purchase is keyed by
///             (sourceAgentId, purchaseId) — buying agent A never unlocks
///             agent B, even though many publishers share this one contract;
///           - **seller-managed**: `grant`/`revoke` are gated on the CURRENT
///             owner of the source token (read live), not a global admin;
///           - **transfer invalidation**: each grant records its grantor and
///             is honored only while that grantor still owns the source —
///             the same lazy owner-at-set semantics as the CloneGate policy
///             config itself (dormant when the token changes hands, revives
///             if the grantor re-acquires it).
///
///         One-time consumption is deliberately NOT enforced on chain — per
///         ICloneAuthorizer's trust model (`canClone` is a STATICCALL view;
///         replay protection = the attestor's idempotency key + the seller's
///         own records). A seller who wants hard one-shot semantics revokes
///         the purchase after seeing the `ClonedFrom` event; a consuming
///         (state-writing) authorizer variant is planned for when the
///         attestor trust model weakens (multi-node roadmap).
///
///         Not upgradeable, no owner, no privileged roles: sellers only ever
///         control their own token's purchases.
contract StandardCloneAuthorizer is ICloneAuthorizer {
    /// @notice The AgenticID deployment whose token owners act as sellers.
    IERC721OwnerOf public immutable agenticId;

    struct Purchase {
        address buyer;
        address grantor; // seller at grant time; stale once the token moves
    }

    /// @dev (sourceAgentId, purchaseId) → purchase. purchaseId is seller-chosen
    ///      (e.g. their order id); ids are scoped per agent, so two sellers
    ///      (or two agents) reusing the same number never collide.
    mapping(uint256 => mapping(uint256 => Purchase)) private _purchases;

    event PurchaseGranted(uint256 indexed sourceAgentId, uint256 indexed purchaseId, address indexed buyer, address seller);
    event PurchaseRevoked(uint256 indexed sourceAgentId, uint256 indexed purchaseId, address seller);

    constructor(address agenticId_) {
        require(agenticId_ != address(0), "agenticId=0");
        agenticId = IERC721OwnerOf(agenticId_);
    }

    /// @notice Record that `buyer` holds purchase `purchaseId` for
    ///         `sourceAgentId`. Caller must be the source's current owner.
    ///         Re-granting an id overwrites it (fix a fat-fingered buyer).
    function grant(uint256 sourceAgentId, uint256 purchaseId, address buyer) external {
        address seller = _requireSeller(sourceAgentId);
        require(buyer != address(0), "buyer=0");
        _purchases[sourceAgentId][purchaseId] = Purchase({buyer: buyer, grantor: seller});
        emit PurchaseGranted(sourceAgentId, purchaseId, buyer, seller);
    }

    /// @notice Delete a purchase (sold-out rollback, refund, or manual
    ///         one-shot consumption after the clone mints).
    function revoke(uint256 sourceAgentId, uint256 purchaseId) external {
        address seller = _requireSeller(sourceAgentId);
        delete _purchases[sourceAgentId][purchaseId];
        emit PurchaseRevoked(sourceAgentId, purchaseId, seller);
    }

    /// @notice The purchase record, plus whether it is currently effective
    ///         (grantor still owns the source). Zero buyer = no such purchase.
    function purchaseOf(uint256 sourceAgentId, uint256 purchaseId)
        external
        view
        returns (address buyer, address grantor, bool effective)
    {
        Purchase storage p = _purchases[sourceAgentId][purchaseId];
        buyer = p.buyer;
        grantor = p.grantor;
        effective = p.buyer != address(0) && agenticId.ownerOf(sourceAgentId) == p.grantor;
    }

    /// @inheritdoc ICloneAuthorizer
    /// @dev `data` = abi.encode(uint256 purchaseId). Allowed iff the purchase
    ///      exists for THIS source, was granted by the source's CURRENT owner,
    ///      is being minted to the recorded buyer, and the buyer initiated the
    ///      request themself.
    function canClone(
        uint256 sourceAgentId,
        address targetOwner,
        address caller,
        bytes calldata data
    ) external view returns (bool) {
        if (data.length != 32) return false;
        uint256 purchaseId = abi.decode(data, (uint256));
        Purchase storage p = _purchases[sourceAgentId][purchaseId];
        return p.buyer != address(0)
            && p.buyer == targetOwner
            && caller == targetOwner
            && agenticId.ownerOf(sourceAgentId) == p.grantor;
    }

    function _requireSeller(uint256 sourceAgentId) private view returns (address seller) {
        seller = agenticId.ownerOf(sourceAgentId); // reverts on nonexistent token
        if (msg.sender != seller) revert StdCloneAuthNotSeller(msg.sender, sourceAgentId, seller);
    }
}
