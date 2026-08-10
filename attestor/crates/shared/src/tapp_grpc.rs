//! Local gRPC channel to tapp-server. Shared between `tee.rs`
//! (`GetAppSecretKey` for the attestor's EOA) and `kms.rs`
//! (`GetSecretResource` for the app-scoped KMS secret).
//!
//! Both RPCs are "LOCAL ACCESS ONLY" on tapp-server: the attestor must
//! reach it over localhost or same-host Docker network (in docker compose,
//! via `host.docker.internal` → `host-gateway`, see `docker-compose.yml`).

use crate::Config;
use anyhow::{anyhow, Result};
use tonic::transport::{Channel, Endpoint, Uri};

pub mod proto {
    tonic::include_proto!("tapp_service");
}

pub fn tapp_url(cfg: &Config) -> String {
    format!("http://{}:{}", cfg.tapp_ip, cfg.tapp_port)
}

pub async fn connect(cfg: &Config) -> Result<Channel> {
    // A unix socket, when configured, keeps GetAppSecretKey/GetSecretResource
    // off any TCP port. The placeholder URI is ignored by the connector; only
    // the socket path matters. tonic 0.12 rides hyper 1.x, so the tokio stream
    // is wrapped in hyper-util's TokioIo.
    if let Some(sock) = cfg.tapp_socket.clone() {
        return Endpoint::try_from("http://[::]:50051")
            .map_err(|e| anyhow!("bad placeholder uri: {}", e))?
            .connect_with_connector(tower::service_fn(move |_: Uri| {
                let path = sock.clone();
                async move {
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                        tokio::net::UnixStream::connect(&path).await?,
                    ))
                }
            }))
            .await
            .map_err(|e| anyhow!("cannot connect to tapp-server socket: {}", e));
    }
    let url = tapp_url(cfg);
    Channel::from_shared(url.clone())
        .map_err(|e| anyhow!("invalid tapp-server URL {}: {}", url, e))?
        .connect()
        .await
        .map_err(|e| anyhow!("cannot connect to tapp-server at {}: {}", url, e))
}

pub fn require_app_id(cfg: &Config) -> Result<String> {
    cfg.app_id
        .clone()
        .ok_or_else(|| anyhow!("ATTESTOR_APP_ID must be set when mock_tee=false or mock_kms=false"))
}
