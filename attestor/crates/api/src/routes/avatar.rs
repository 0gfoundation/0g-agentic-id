//! GET /avatar/default.svg — placeholder avatar for the deploy form.
//!
//! Same Pretty SHA pixel-art algorithm a real agent's avatar uses, just
//! seeded from a fixed branded constant so the deploy preview shows the
//! right *style* of artwork (the actual avatar is seeded from `seal_id`
//! once the user mints).

use alloy::primitives::keccak256;
use attestor_shared::avatar::seed_to_svg;
use axum::http::header;
use axum::response::IntoResponse;

const DEFAULT_AVATAR_SEED_TAG: &[u8] = b"0g-agenticid-default-avatar";

pub async fn default_avatar() -> impl IntoResponse {
    let seed = keccak256(DEFAULT_AVATAR_SEED_TAG).0;
    let svg = seed_to_svg(&seed);
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml; charset=utf-8"),
            // Cache for 1 day — image is deterministic, never changes.
            (header::CACHE_CONTROL, "public, max-age=86400, immutable"),
        ],
        svg,
    )
}
