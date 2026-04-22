//! Route registration.

use crate::state::AppState;
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

mod deploy;
mod deployment;
mod provision;
mod restart;
mod status;
mod ws;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/deploy", post(deploy::handle))
        .route("/provision", post(provision::handle))
        .route("/status", post(status::handle))
        .route("/restart", post(restart::handle))
        .route("/deployment/:seal_id", get(deployment::handle))
        .route("/ws/subscribe", get(ws::handle))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}
