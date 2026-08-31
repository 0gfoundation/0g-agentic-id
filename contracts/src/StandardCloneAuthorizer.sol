// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ICloneAuthorizer} from "./interfaces/ICloneAuthorizer.sol";

interface IERC721OwnerOf {
    function ownerOf(uint256 tokenId) external view returns (address);
}

/// @notice grant/revoke caller is not the source token's current owner.
error StdCloneAuthNotSeller(address caller, uint256 sourceAgentId, address seller);

/// @title StandardCloneAuthorizer
/// @notice The OFFICIAL stock clone policy (issue #133): the seller opens the
///         door per buyer — `grant(sourceAgentId, buyer)` — and that buyer may
///         fork that agent (self-initiated) until the seller revokes. No
///         platform admin: publishers who want marketplace fork flows without
///         writing a policy contract point their token at this one
///         (`CloneGate.setCloneAuthorizer(id, address(this))`) and manage
///         their own buyer list.
///
///         Deliberately a pure permission SWITCH, keyed (sourceAgentId, buyer):
///         under ICloneAuthorizer's trust model `canClone` is a STATICCALL
///         view, so on-chain per-ticket consumption cannot exist — N grants
///         would equal 1 grant — and order bookkeeping (which sale this was)
///         belongs in the seller's own records, not on chain. `authData` is
///         ignored for the same reason: there is nothing for the buyer to
///         present. A consuming (state-writing) authorizer variant is planned
///         for when the attestor trust model weakens (multi-node roadmap).
///
///         Grants carry the same owner-at-set lazy invalidation as the
///         CloneGate policy config itself: each grant records its grantor and
///         is honored only while that grantor still owns the source (dormant
///         when the token changes hands, revives if the grantor re-acquires).
///
///         Not upgradeable, no owner, no privileged roles.
contract StandardCloneAuthorizer is ICloneAuthorizer {
    /// @notice The AgenticID deployment whose token owners act as sellers.
    IERC721OwnerOf public immutable agenticId;

    /// @dev (sourceAgentId, buyer) → grantor (the seller at grant time).
    ///      address(0) = not granted.
    mapping(uint256 => mapping(address => address)) private _grantors;

    event CloneGranted(uint256 indexed sourceAgentId, address indexed buyer, address seller);
    event CloneRevoked(uint256 indexed sourceAgentId, address indexed buyer, address seller);

    constructor(address agenticId_) {
        require(agenticId_ != address(0), "agenticId=0");
        agenticId = IERC721OwnerOf(agenticId_);
    }

    /// @notice Allow `buyer` to fork `sourceAgentId`. Caller must be the
    ///         source's current owner. Idempotent.
    function grant(uint256 sourceAgentId, address buyer) external {
        address seller = _requireSeller(sourceAgentId);
        require(buyer != address(0), "buyer=0");
        _grantors[sourceAgentId][buyer] = seller;
        emit CloneGranted(sourceAgentId, buyer, seller);
    }

    /// @notice Close the door for `buyer` (refund, or one-shot consumption
    ///         after the seller sees the clone's `ClonedFrom` event).
    function revoke(uint256 sourceAgentId, address buyer) external {
        address seller = _requireSeller(sourceAgentId);
        delete _grantors[sourceAgentId][buyer];
        emit CloneRevoked(sourceAgentId, buyer, seller);
    }

    /// @notice The grant's recorded seller and whether it is currently
    ///         effective (that seller still owns the source). (0, false) = no grant.
    function grantOf(uint256 sourceAgentId, address buyer)
        external
        view
        returns (address grantor, bool effective)
    {
        grantor = _grantors[sourceAgentId][buyer];
        effective = grantor != address(0) && agenticId.ownerOf(sourceAgentId) == grantor;
    }

    /// @inheritdoc ICloneAuthorizer
    /// @dev `data` is ignored (see the contract natspec). Allowed iff the
    ///      buyer being minted to was granted by the source's CURRENT owner
    ///      and initiated the request themself.
    function canClone(
        uint256 sourceAgentId,
        address targetOwner,
        address caller,
        bytes calldata /* data */
    ) external view returns (bool) {
        address grantor = _grantors[sourceAgentId][targetOwner];
        return grantor != address(0)
            && caller == targetOwner
            && agenticId.ownerOf(sourceAgentId) == grantor;
    }

    function _requireSeller(uint256 sourceAgentId) private view returns (address seller) {
        seller = agenticId.ownerOf(sourceAgentId); // reverts on nonexistent token
        if (msg.sender != seller) revert StdCloneAuthNotSeller(msg.sender, sourceAgentId, seller);
    }
}
