//! Error types used across layers.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttestorError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("idempotency conflict: {0}")]
    IdempotencyConflict(String),

    #[error("invalid stage transition: {0}")]
    InvalidStageTransition(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("chain error: {0}")]
    Chain(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("sandbox error: {0}")]
    Sandbox(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("internal: {0}")]
    Internal(String),
}

pub type Result<T, E = AttestorError> = std::result::Result<T, E>;
