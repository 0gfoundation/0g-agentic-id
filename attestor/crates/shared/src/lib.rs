//! Shared types, traits, implementations for the Attestor backend.

pub mod chain;
pub mod config;
pub mod crypto;
pub mod error;
pub mod events;
pub mod events_bus;
pub mod jobs;
pub mod kms;
pub mod mocks;
pub mod repo;
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
