// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @notice Deploy-time governance rules shared by the deploy scripts
///         (Deploy / DeployVerifiedFeedback / DeployCloneGate).
///
///         0G mainnet (chain 16661) is strict: the TimelockController that owns
///         the beacons must have minDelay >= 1 day, so every beacon upgrade is
///         publicly scheduled a day before it can execute; a fresh Timelock
///         gets no external admin (role changes take the same 1-day path), so
///         its constructor role sets must be usable (requireMainnetTimelockRoles).
///         Every other chain (0G Galileo testnet, local) stays lightweight:
///         minDelay defaults to 0 and OWNER is the Timelock admin, as on the
///         existing testnet / dev Timelocks (DEPLOYMENT.md §6.1 / §6.2).
///
///         Scope: the delay covers beacon upgrades only. Owner-only admin calls
///         (attestor allowlist, framework hashes, verifier / oracle, pauser,
///         params) are direct calls by each contract's owner on every chain —
///         see DEPLOYMENT.md §1 / §6.2m.
library MainnetGovernance {
    uint256 internal constant ZG_MAINNET_CHAIN_ID = 16661;
    uint256 internal constant MAINNET_MIN_TIMELOCK_DELAY = 1 days; // 86400

    /// @notice minDelay for a fresh Timelock.
    /// @param chainId    block.chainid of the deploy.
    /// @param overridden whether TIMELOCK_DELAY is set in the environment.
    /// @param requested  its value (ignored when not overridden).
    /// @return 0G mainnet: `requested` if set (reverts below 1 day), else 1 day.
    ///         Other chains: `requested` if set, else 0.
    function timelockDelay(uint256 chainId, bool overridden, uint256 requested)
        internal pure returns (uint256)
    {
        if (chainId != ZG_MAINNET_CHAIN_ID) return overridden ? requested : 0;
        if (!overridden) return MAINNET_MIN_TIMELOCK_DELAY;
        require(
            requested >= MAINNET_MIN_TIMELOCK_DELAY,
            "TIMELOCK_DELAY below 86400 (1 day) is not allowed on 0G mainnet (chain 16661)"
        );
        return requested;
    }

    /// @notice `admin` argument for a fresh TimelockController.
    /// @return 0G mainnet: address(0) — no external admin. OZ TimelockController
    ///         always grants DEFAULT_ADMIN_ROLE to itself, so role changes go
    ///         through schedule → minDelay → execute like any upgrade.
    ///         Other chains: `owner`, so role changes stay one direct grantRole
    ///         (with minDelay 0 the proposer could schedule + execute them back
    ///         to back anyway; dropping the admin there adds friction, not safety).
    function timelockAdmin(uint256 chainId, address owner) internal pure returns (address) {
        return chainId == ZG_MAINNET_CHAIN_ID ? address(0) : owner;
    }

    /// @notice Role sets for a fresh Timelock, checked before broadcast. On 0G
    ///         mainnet the Timelock has no external admin (timelockAdmin), so the
    ///         constructor's proposers / executors are the only accounts that
    ///         can ever schedule / execute, including the role changes that
    ///         would repair a bad set: an unusable set freezes every beacon for
    ///         good. Rules on chain 16661:
    ///         - proposers: non-empty, no address(0) (a role nobody can use),
    ///           and OWNER among them. OWNER is the account the mandatory
    ///           post-deploy admin calls (DEPLOYMENT.md §3) exercise right after
    ///           the deploy, so a stack whose proposer can't sign is caught
    ///           before anything depends on it; a proposer first used at the
    ///           first upgrade could prove unreachable only then. Extra
    ///           proposers are allowed.
    ///         - executors: non-empty, and either exactly [address(0)] (open
    ///           execution) or only non-zero accounts. address(0) next to named
    ///           executors would still open execution to anyone, contradicting
    ///           the restricted set the list suggests.
    ///         No-op on other chains: OWNER is the Timelock admin there and can
    ///         grant any missing role directly.
    function requireMainnetTimelockRoles(
        uint256 chainId,
        address owner,
        address[] memory proposers,
        address[] memory executors
    ) internal pure {
        if (chainId != ZG_MAINNET_CHAIN_ID) return;
        require(proposers.length != 0, "PROPOSERS is empty on 0G mainnet (chain 16661): nobody could schedule");
        bool ownerProposes;
        for (uint256 i; i < proposers.length; ++i) {
            require(proposers[i] != address(0), "PROPOSERS contains address(0) on 0G mainnet (chain 16661)");
            if (proposers[i] == owner) ownerProposes = true;
        }
        require(ownerProposes, "PROPOSERS must include OWNER on 0G mainnet (chain 16661)");
        require(executors.length != 0, "EXECUTORS is empty on 0G mainnet (chain 16661): nobody could execute");
        if (executors.length == 1 && executors[0] == address(0)) return; // open execution
        for (uint256 i; i < executors.length; ++i) {
            require(
                executors[i] != address(0),
                "EXECUTORS mixes address(0) with named executors on 0G mainnet (chain 16661): use exactly 0x0 or only non-zero addresses"
            );
        }
    }

    /// @notice Incremental deploys hand a new beacon to an EXISTING Timelock.
    ///         On 0G mainnet, refuse one that is not a TimelockController with
    ///         minDelay >= 1 day (an EOA or a zero-delay Timelock as beacon
    ///         owner would make that contract instantly upgradeable). No-op on
    ///         other chains.
    function requireMainnetTimelock(uint256 chainId, address timelock) internal view {
        if (chainId != ZG_MAINNET_CHAIN_ID) return;
        require(timelock.code.length != 0, "TIMELOCK has no code (0G mainnet needs a TimelockController)");
        require(
            TimelockController(payable(timelock)).getMinDelay() >= MAINNET_MIN_TIMELOCK_DELAY,
            "TIMELOCK minDelay below 86400 (1 day) on 0G mainnet (chain 16661)"
        );
    }
}
