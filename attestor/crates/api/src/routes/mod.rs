//! Route registration.

use crate::state::AppState;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

mod avatar;
mod config;
mod deploy;
mod deployment;
mod deployments;
mod provision;
mod reset;
mod retry;
mod start;
mod status;
mod stop;
mod ws;

// Static assets — embedded into the binary at compile time so deployment
// is one-file-and-go (mirrors `0g-sandbox/web/static.go`'s `//go:embed`).
const INDEX_HTML: &[u8] = include_bytes!("../../web/index.html");
const ETHERS_JS: &[u8] = include_bytes!("../../web/ethers.umd.min.js");

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/static/ethers.js", get(serve_ethers))
        .route("/avatar/default.svg", get(avatar::default_avatar))
        .route("/avatar/:seed", get(avatar::keyed_avatar))
        .route("/health", get(health))
        .route("/config", get(config::handle))
        .route("/deploy", post(deploy::handle))
        .route("/provision", post(provision::handle))
        .route("/status", post(status::handle))
        .route("/start", post(start::handle))
        .route("/stop", post(stop::handle))
        .route("/retry", post(retry::handle))
        .route("/reset", post(reset::handle))
        .route("/deployment/:seal_id", get(deployment::handle))
        .route("/deployments", get(deployments::handle))
        .route("/ws/subscribe", get(ws::handle))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn serve_index() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], INDEX_HTML)
}

async fn serve_ethers() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        ETHERS_JS,
    )
}
