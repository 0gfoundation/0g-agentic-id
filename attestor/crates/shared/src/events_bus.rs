//! Postgres LISTEN/NOTIFY-backed event bus.
//!
//! - Producers: worker / indexer / api-server all publish via `publish()`
//!   which issues a `NOTIFY attestor_events, '<json>'` on the pool.
//! - Consumer: api-server (for WebSocket fan-out). `PostgresEventBus::new`
//!   spawns a dedicated LISTEN task that receives notifications, broadcasts
//!   locally via a tokio broadcast channel; `subscribe(seal_id)` spawns a
//!   filter task that forwards matching events to an mpsc receiver.

use crate::events::WsEvent;
use crate::traits::{EventBus, EventSubscription};
use crate::types::SealId;
use async_trait::async_trait;
use sqlx::postgres::PgListener;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

const CHANNEL: &str = "attestor_events";
const BROADCAST_CAP: usize = 512;
const SUBSCRIBER_CAP: usize = 64;

pub struct PostgresEventBus {
    pool: PgPool,
    tx: broadcast::Sender<WsEvent>,
}

impl PostgresEventBus {
    /// Connect and start the LISTEN task. Only one of these per process is
    /// needed; subscribers inside the process share its broadcast.
    pub async fn connect(pool: PgPool) -> anyhow::Result<Arc<Self>> {
        let (tx, _rx) = broadcast::channel(BROADCAST_CAP);
        let bus = Arc::new(Self { pool: pool.clone(), tx: tx.clone() });

        // spawn listen loop
        let listen_pool = pool;
        tokio::spawn(async move {
            loop {
                match listen_loop(&listen_pool, &tx).await {
                    Ok(()) => break, // graceful
                    Err(e) => {
                        tracing::warn!(error = %e, "event bus listen loop error; retrying in 2s");
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                }
            }
        });

        Ok(bus)
    }
}

async fn listen_loop(pool: &PgPool, tx: &broadcast::Sender<WsEvent>) -> anyhow::Result<()> {
    let mut listener = PgListener::connect_with(pool).await?;
    listener.listen(CHANNEL).await?;
    tracing::info!(channel = CHANNEL, "event bus listening");
    loop {
        let notification = listener.recv().await?;
        let payload = notification.payload();
        match serde_json::from_str::<WsEvent>(payload) {
            Ok(event) => {
                // If no subscribers, err is harmless.
                let _ = tx.send(event);
            }
            Err(e) => {
                tracing::warn!(error = %e, payload = %payload, "malformed event payload");
            }
        }
    }
}

#[async_trait]
impl EventBus for PostgresEventBus {
    async fn publish(&self, event: WsEvent) -> anyhow::Result<()> {
        let payload = serde_json::to_string(&event)?;
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(CHANNEL)
            .bind(&payload)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn subscribe(&self, seal_id: SealId) -> anyhow::Result<EventSubscription> {
        let mut rx = self.tx.subscribe();
        let (mpsc_tx, mpsc_rx) = mpsc::channel(SUBSCRIBER_CAP);
        tokio::spawn(async move {
            while let Ok(event) = rx.recv().await {
                if event.seal_id() == seal_id {
                    if mpsc_tx.send(event).await.is_err() {
                        break;
                    }
                }
            }
        });
        Ok(mpsc_rx)
    }
}
