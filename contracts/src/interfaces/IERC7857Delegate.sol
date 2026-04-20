// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Optional extension: allows a user to nominate a delegate that may sign
///         AccessProofs on their behalf when they are the intended receiver.
///
/// @dev This is intentionally separate from the core IERC7857 interface because
///      delegation is not required by all implementations. A receiver that always
///      signs their own AccessProofs does not need to implement this extension.
///
///      Detect support via ERC-165: type(IERC7857Delegate).interfaceId.
interface IERC7857Delegate {
    /// @notice Emitted when a user updates their AccessProof-signing delegate.
    /// @param user     The user whose delegation setting changed.
    /// @param delegate The new delegate. address(0) means delegation is revoked.
    event DelegateUpdated(address indexed user, address indexed delegate);

    /// @notice Nominate `delegate` to sign AccessProofs on behalf of msg.sender.
    /// @param delegate Set to address(0) to revoke an existing delegation.
    function setAccessDelegate(address delegate) external;

    /// @notice Returns the AccessProof-signing delegate for `user`.
    /// @return address(0) if no delegate is set.
    function getAccessDelegate(address user) external view returns (address);
}
