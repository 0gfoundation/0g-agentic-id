//! WebSocket events. Broadcast via `EventBus`; api-server relays to
//! subscribed WS clients keyed by `seal_id`.

use crate::types::{AgentId, DeploymentPhase, SealId};
use alloy::primitives::TxHash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum WsEvent {
    // ── accept ────────────────────────────────────────
    DeployAccepted { seal_id: SealId },

    // ── storage track ────────────────────────────────
    StorageSubmitted { seal_id: SealId, tx_hash: TxHash },
    StorageConfirmed { seal_id: SealId },
    StorageFailed { seal_id: SealId, reason: String },

    // ── mint track ───────────────────────────────────
    MintSubmitted { seal_id: SealId, tx_hash: TxHash },
    MintConfirmed { seal_id: SealId, agent_id: AgentId },
    MintFailed { seal_id: SealId, reason: String },

    // ── container track ──────────────────────────────
    ContainerStarting { seal_id: SealId },
    ContainerRunning { seal_id: SealId },
    ContainerStopped { seal_id: SealId, reason: String },
    ContainerFailed { seal_id: SealId, reason: String },

    // ── derived phase ────────────────────────────────
    PhaseChanged { seal_id: SealId, phase: DeploymentPhase },

    // ── indexer-observed chain state ─────────────────
    SealedKeysUpdated { seal_id: SealId, agent_id: AgentId },
    EntryUpdated { seal_id: SealId, index: u64 },
    /// `URIUpdated(agentId, newURI, updatedBy)` observed on chain.
    /// Emitted by both the attestor's own `setAgentURI` second-phase write
    /// and by any owner-initiated URI rewrite; subscribers can use the
    /// `agent_uri` payload to re-fetch the AgentCard without a poll.
    AgentURIUpdated {
        seal_id: SealId,
        agent_id: AgentId,
        agent_uri: String,
    },
}

impl WsEvent {
    pub fn seal_id(&self) -> SealId {
        match self {
            Self::DeployAccepted { seal_id }
            | Self::StorageSubmitted { seal_id, .. }
            | Self::StorageConfirmed { seal_id }
            | Self::StorageFailed { seal_id, .. }
            | Self::MintSubmitted { seal_id, .. }
            | Self::MintConfirmed { seal_id, .. }
            | Self::MintFailed { seal_id, .. }
            | Self::ContainerStarting { seal_id }
            | Self::ContainerRunning { seal_id }
            | Self::ContainerStopped { seal_id, .. }
            | Self::ContainerFailed { seal_id, .. }
            | Self::PhaseChanged { seal_id, .. }
            | Self::SealedKeysUpdated { seal_id, .. }
            | Self::EntryUpdated { seal_id, .. }
            | Self::AgentURIUpdated { seal_id, .. } => *seal_id,
        }
    }
}
