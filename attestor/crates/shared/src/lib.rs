//! Shared types, traits, implementations for the Attestor backend.

pub mod agent_card;
pub mod agent_profile;
pub mod auth;
pub mod chain;
pub mod config;
pub mod crypto;
pub mod error;
pub mod events;
pub mod events_bus;
pub mod i_data_derive;
pub mod jobs;
pub mod kms;
pub mod mocks;
pub mod oss;
pub mod repo;
pub mod sandbox;
pub mod storage_zg;
pub mod tapp_grpc;
pub mod tee;
pub mod traits;
pub mod types;

pub use config::Config;
pub use error::{AttestorError, Result};
pub use events::WsEvent;
pub use traits::{
    ChainClient, CryptoModule, DeploymentRepo, EventBus, EventSubscription, IdempotencyStore,
    JobQueue, SandboxClient, StorageClient,
};
pub use types::*;

/// Embedded bootstrap schema. Executed by `repo::connect()` on startup.
pub const SCHEMA_SQL: &str = include_str!("schema.sql");
