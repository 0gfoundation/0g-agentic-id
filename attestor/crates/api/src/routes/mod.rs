//! Route registration.

use crate::state::AppState;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

mod avatar;
mod clone;
mod config;
mod deploy;
mod deployment;
mod deployments;
mod lifecycle_auth;
mod preflight;
mod probe;
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
// Vendored fonts (latin subsets, variable) — replaces the Google Fonts CDN
// link so first paint doesn't depend on an external host (blocked/slow in
// CN deployments) and the console stays zero-third-party.
const FONTS_CSS: &[u8] = include_bytes!("../../web/fonts/fonts.css");
const FONT_BRICOLAGE: &[u8] = include_bytes!("../../web/fonts/bricolage-grotesque-var.woff2");
const FONT_FRAUNCES: &[u8] = include_bytes!("../../web/fonts/fraunces-var.woff2");
const FONT_FRAUNCES_I: &[u8] = include_bytes!("../../web/fonts/fraunces-italic-var.woff2");
const FONT_GEIST_MONO: &[u8] = include_bytes!("../../web/fonts/geist-mono-var.woff2");

pub fn router(state: AppState) -> Router {
    // Headless mode (ATTESTOR_CONSOLE_ENABLED=false): the web console is
    // simply not routed — "/" and /static (incl. fonts) 404, the whole
    // HTTP API below stays up for SDK users. One switch, all or nothing.
    let mut r = Router::new();
    if state.cfg.console_enabled {
        r = r
            .route("/", get(serve_index))
            .route("/static/ethers.js", get(serve_ethers))
            .route("/static/fonts.css", get(|| static_asset("text/css; charset=utf-8", FONTS_CSS)))
            .route("/static/fonts/bricolage-grotesque-var.woff2", get(|| static_asset("font/woff2", FONT_BRICOLAGE)))
            .route("/static/fonts/fraunces-var.woff2", get(|| static_asset("font/woff2", FONT_FRAUNCES)))
            .route("/static/fonts/fraunces-italic-var.woff2", get(|| static_asset("font/woff2", FONT_FRAUNCES_I)))
            .route("/static/fonts/geist-mono-var.woff2", get(|| static_asset("font/woff2", FONT_GEIST_MONO)));
    }
    r
        .route("/avatar/default.svg", get(avatar::default_avatar))
        .route("/avatar/:seed", get(avatar::keyed_avatar))
        .route("/health", get(health))
        .route("/config", get(config::handle))
        .route("/deploy", post(deploy::handle))
        .route("/clone", post(clone::handle))
        .route("/provision", post(provision::handle))
        .route("/probe", post(probe::handle))
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

/// Immutable embedded asset with a long-lived cache header (contents only
/// change with a binary rebuild, so aggressive caching is safe).
async fn static_asset(content_type: &'static str, body: &'static [u8]) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        body,
    )
}
