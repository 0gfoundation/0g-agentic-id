// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ICloneAuthorizer} from "../interfaces/ICloneAuthorizer.sol";

/// @title DevCloneAuthorizer
/// @notice EXAMPLE ICloneAuthorizer — the skeleton of a marketplace policy,
///         used for live testing on dev and as the reference implementation
///         for issue #133 integrators (Ghast-style: "a purchase is an
///         entitlement to one fork"). NOT part of the protocol; deploy your
///         own policy with your own listing/payment/supply rules.
///
///         Model: an admin (the marketplace) records purchases off- or
///         on-chain payment aside — `grant(purchaseId, buyer)` — and the
///         policy allows a clone iff the submitted purchaseId belongs to the
///         buyer being minted to (and the buyer initiated the request).
///         One-time consumption is deliberately NOT enforced here (canClone
///         is view — see ICloneAuthorizer's natspec on the trust model).
contract DevCloneAuthorizer is ICloneAuthorizer {
    address public immutable admin;
    mapping(uint256 => address) public purchases;

    event PurchaseGranted(uint256 indexed purchaseId, address indexed buyer);

    constructor(address admin_) {
        admin = admin_;
    }

    /// @notice Record that `buyer` holds purchase `purchaseId` (admin = the
    ///         marketplace backend / seller flow).
    function grant(uint256 purchaseId, address buyer) external {
        require(msg.sender == admin, "not admin");
        purchases[purchaseId] = buyer;
        emit PurchaseGranted(purchaseId, buyer);
    }

    /// @inheritdoc ICloneAuthorizer
    function canClone(
        uint256, /* sourceAgentId — a real market would scope purchases per listing */
        address targetOwner,
        address caller,
        bytes calldata data
    ) external view returns (bool) {
        if (data.length != 32) return false;
        uint256 purchaseId = abi.decode(data, (uint256));
        address buyer = purchases[purchaseId];
        return buyer != address(0) && buyer == targetOwner && caller == targetOwner;
    }
}
