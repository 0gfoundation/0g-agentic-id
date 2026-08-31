// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ICanonicalReputationRegistry} from "./interfaces/ICanonicalReputationRegistry.sol";
import {IVerifiedFeedbackRegistry, TaskReveal} from "./interfaces/IVerifiedFeedbackRegistry.sol";
import {ServeProof} from "./interfaces/IAgenticIDReputationRegistry.sol";

/// @dev The routine may only be self-called: it is designed to run AS the
///      client's EOA via an EIP-7702 delegation, where the EOA calling itself
///      makes `msg.sender == address(this)`. Any other caller is an outsider
///      trying to submit feedback in the delegated user's name.
error BatcherNotSelf();

/// @title FeedbackBatcher
/// @notice EIP-7702 delegate target that makes the two-step feedback flow
///         atomic. A client EOA attaches this code to itself (type-4
///         transaction authorization) and self-calls `giveFeedbackAndAttest`,
///         which executes IN THE EOA'S ACCOUNT CONTEXT:
///
///           1. canonical.giveFeedback(…)   — msg.sender = the EOA, so the
///              canonical ERC-8004 registry attributes the entry natively;
///           2. canonical.getLastIndex(…)   — the entry's index, read inside
///              the same transaction (no off-chain race);
///           3. verifiedFeedback.attestFeedback(…) — msg.sender = the EOA, so
///              the submitter binding and self-feedback guard see the client.
///
///         Either everything lands or nothing does: a failed attest (bad
///         proof, expired deadline, self-feedback) rolls back the canonical
///         write too — the non-atomic saga's "entry without a mark" tail
///         state cannot occur on this path.
///
/// @dev Stateless and permissionless by construction: it holds no storage,
///      no funds, and no privileges — it only aggregates calls the EOA could
///      make itself, so there is nothing to upgrade or govern (replace by
///      deploying a new one and re-delegating). The registry pair is fixed at
///      deploy time so crafted calldata can't point a delegated user at a
///      fake registry. NOT deployed behind a beacon — record the address in
///      DEPLOYMENT.md §6 like the other contracts.
contract FeedbackBatcher {
    ICanonicalReputationRegistry public immutable canonicalReputation;
    IVerifiedFeedbackRegistry public immutable verifiedFeedback;

    constructor(address canonicalReputation_, address verifiedFeedback_) {
        require(canonicalReputation_ != address(0), "canonicalReputation=0");
        require(verifiedFeedback_ != address(0), "verifiedFeedback=0");
        canonicalReputation = ICanonicalReputationRegistry(canonicalReputation_);
        verifiedFeedback = IVerifiedFeedbackRegistry(verifiedFeedback_);
    }

    /// @dev A delegated EOA executes THIS code when asked "can you receive
    ///      this NFT?" (ERC-721 safeMint/safeTransfer probe the receiver once
    ///      the account has code). Answer yes — without this, a wallet that
    ///      ever used the atomic feedback path could no longer be the target
    ///      of a clone mint or a safe transfer (ERC721InvalidReceiver).
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    /// @dev A delegated EOA executes THIS code on every incoming call — a
    ///      plain value transfer included (empty calldata resolves to
    ///      receive()). Without it, faucets/exchanges/friends sending ETH to a
    ///      delegated user would revert. The value lands in the EOA's own
    ///      balance; the batcher itself holds nothing by design.
    receive() external payable {}

    /// @notice Submit canonical feedback and attest it with a ServeProof, in
    ///         one atomic transaction. See the contract natspec for the
    ///         execution model; parameters mirror the two underlying calls.
    ///         An empty `task.method` skips the receipt opening (plain
    ///         attest); a non-empty one routes to attestFeedbackWithTask,
    ///         recording `task.uri` as the entry's TEE-verified endpoint.
    /// @return feedbackIndex The 1-based canonical index the entry landed at.
    function giveFeedbackAndAttest(
        uint256 agentId,
        int128  value,
        uint8   valueDecimals,
        string calldata tag1,
        string calldata tag2,
        string calldata endpoint,
        string calldata feedbackURI,
        bytes32 feedbackHash,
        ServeProof calldata proof,
        TaskReveal calldata task
    ) external returns (uint64 feedbackIndex) {
        if (msg.sender != address(this)) revert BatcherNotSelf();

        canonicalReputation.giveFeedback(
            agentId, value, valueDecimals, tag1, tag2, endpoint, feedbackURI, feedbackHash
        );
        // address(this) IS the client EOA under delegation, so this reads the
        // index canonical just assigned to the entry above.
        feedbackIndex = canonicalReputation.getLastIndex(agentId, address(this));
        if (bytes(task.method).length == 0) {
            verifiedFeedback.attestFeedback(agentId, feedbackIndex, proof);
        } else {
            verifiedFeedback.attestFeedbackWithTask(agentId, feedbackIndex, proof, task);
        }
    }
}
