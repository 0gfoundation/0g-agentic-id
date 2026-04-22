//! GET /ws/subscribe?seal_id=0x... — stream deployment events to the frontend.

use crate::state::AppState;
use alloy::primitives::B256;
use attestor_shared::SealId;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Params {
    seal_id: String,
}

pub async fn handle(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> axum::response::Response {
    let seal_id: SealId = match params.seal_id.parse::<B256>() {
        Ok(x) => x,
        Err(_) => return bad_seal_id().into_response(),
    };
    ws.on_upgrade(move |socket| handle_socket(socket, state, seal_id))
}

async fn handle_socket(mut socket: WebSocket, state: AppState, seal_id: SealId) {
    let mut sub = match state.events.subscribe(seal_id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "ws: subscribe failed");
            let _ = socket
                .send(Message::Text(format!(
                    r#"{{"error":"subscribe failed: {}"}}"#,
                    e
                )))
                .await;
            return;
        }
    };

    while let Some(event) = sub.recv().await {
        let text = match serde_json::to_string(&event) {
            Ok(t) => t,
            Err(_) => continue,
        };
        if socket.send(Message::Text(text)).await.is_err() {
            break;
        }
    }
}

fn bad_seal_id() -> (axum::http::StatusCode, &'static str) {
    (
        axum::http::StatusCode::BAD_REQUEST,
        "seal_id must be 0x-prefixed 32-byte hex",
    )
}
