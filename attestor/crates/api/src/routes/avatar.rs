//! GET /avatar/default.svg + GET /avatar/:seed_hex.svg
//!
//! Same Pretty SHA pixel-art algorithm a real agent's avatar uses,
//! seeded from either a fixed branded constant (`default`) or any caller-
//! supplied 32-byte hex string. Used for the deploy preview placeholder
//! and the home-page avatar showcase. Avatars are deterministic, so we
//! serve them with `immutable` 1-day caching.

use alloy::primitives::keccak256;
use attestor_shared::avatar::seed_to_svg;
use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::body::Body;

const DEFAULT_AVATAR_SEED_TAG: &[u8] = b"0g-agenticid-default-avatar";

pub async fn default_avatar() -> impl IntoResponse {
    let seed = keccak256(DEFAULT_AVATAR_SEED_TAG).0;
    serve(seed)
}

/// `/avatar/:hex.svg` — caller picks the seed. Hex must be exactly 64
/// characters (32 bytes), with or without `0x` prefix; anything else is
/// rejected with 400. Falls back to keccak256(input) on parse failure to
/// stay forgiving when the frontend wants to hash a short label like
/// `keccak256("scribe")` server-side instead of computing it client-side.
pub async fn keyed_avatar(Path(seed_hex): Path<String>) -> Response {
    let trimmed = seed_hex.strip_suffix(".svg").unwrap_or(&seed_hex);
    let raw = trimmed.strip_prefix("0x").unwrap_or(trimmed);

    let seed: [u8; 32] = match (raw.len(), hex::decode(raw)) {
        (64, Ok(bytes)) if bytes.len() == 32 => bytes.try_into().unwrap(),
        // Permissive fallback: hash whatever string came in.
        _ => keccak256(trimmed.as_bytes()).0,
    };
    if trimmed.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty seed").into_response();
    }
    serve(seed)
}

fn serve(seed: [u8; 32]) -> Response {
    let svg = seed_to_svg(&seed);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "image/svg+xml; charset=utf-8")
        .header(header::CACHE_CONTROL, "public, max-age=86400, immutable")
        .body(Body::from(svg))
        .unwrap()
}
