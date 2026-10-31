//! `GET /attestor-tls?provider=0x…` — relays, byte-identical, the latest
//! provider-signed statement of this attestor's TLS pins. sealed fetches it
//! over unverified TLS, checks the provider signature against the key that
//! signed its own certificate, and pins every later attestor connection to
//! it. Public and unauthenticated: the statement carries only public keys'
//! hashes and is useless without the provider signature.

use crate::error::ApiError;
use crate::state::AppState;
use alloy::primitives::Address;
use attestor_shared::attestor_tls::{RelayError, RETRY_AFTER_SECS};
use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

#[derive(serde::Deserialize)]
pub struct ProviderQuery {
    pub provider: String,
}

fn parse_provider(raw: &str) -> Option<Address> {
    let hex = raw.strip_prefix("0x")?;
    (hex.len() == 40).then(|| hex.parse().ok()).flatten()
}

pub async fn handle(
    State(state): State<AppState>,
    query: Result<Query<ProviderQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let provider = query
        .ok()
        .and_then(|Query(query)| parse_provider(&query.provider));
    let mut response = match provider {
        None => {
            ApiError::bad_request("provider must be a 0x-prefixed 20-byte address").into_response()
        }
        Some(provider) => match state.sandbox.attestor_tls_statement(provider).await {
            Ok(body) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                body.0,
            )
                .into_response(),
            Err(RelayError::UnknownProvider) => {
                ApiError::not_found("unknown provider").into_response()
            }
            Err(RelayError::Unavailable) => {
                let mut response =
                    ApiError::unavailable("attestor tls unavailable").into_response();
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from(RETRY_AFTER_SECS));
                response
            }
        },
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::B256;
    use alloy::signers::local::PrivateKeySigner;
    use attestor_shared::attestor_tls::AttestorTlsRelay;
    use attestor_shared::mocks::{
        signed_attestor_tls, ConfigurableSandbox, InMemoryDeploymentRepo, InMemoryEventBus,
        InMemoryIdempotencyStore, InMemoryJobQueue, MockChain, StaticStatementSource,
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    const REGISTRY: [u8; 20] = [0x79; 20];

    fn provider_key() -> PrivateKeySigner {
        PrivateKeySigner::from_bytes(&B256::repeat_byte(0x55)).unwrap()
    }

    fn state(source: Option<Arc<StaticStatementSource>>) -> AppState {
        let sandbox = Arc::new(ConfigurableSandbox::new());
        if let Some(source) = source {
            *sandbox.attestor_tls.lock().unwrap() = Some(Arc::new(AttestorTlsRelay::new(
                source,
                16602,
                Address::from(REGISTRY),
            )));
        }
        let mut cfg = crate::routes::provision::tests::test_config();
        cfg.chain_id = 16602;
        AppState {
            providers: Arc::new(
                attestor_shared::provider_registry::MemoryProviderRegistry::default(),
            ),
            cfg,
            crypto: Arc::new(attestor_shared::crypto::RealCrypto::new_for_test([0; 32])),
            chain: Arc::new(MockChain::new()),
            sandbox,
            deployments: Arc::new(InMemoryDeploymentRepo::new()),
            idempotency: Arc::new(InMemoryIdempotencyStore::new()),
            jobs: Arc::new(InMemoryJobQueue::new()),
            events: Arc::new(InMemoryEventBus::new()),
        }
    }

    fn source(own: B256, issued: u64, expires: u64) -> (Arc<StaticStatementSource>, Vec<u8>) {
        let body = signed_attestor_tls(
            &provider_key(),
            16602,
            Address::from(REGISTRY),
            &[B256::repeat_byte(1), B256::repeat_byte(2)],
            issued,
            expires,
        );
        (
            Arc::new(StaticStatementSource::new(
                provider_key().address(),
                body.clone(),
                own,
            )),
            body,
        )
    }

    async fn get(state: AppState, query: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let response = crate::routes::router(state)
            .oneshot(
                axum::http::Request::get(format!("/attestor-tls{query}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec();
        (status, headers, body)
    }

    fn now() -> u64 {
        chrono::Utc::now().timestamp() as u64
    }

    #[tokio::test]
    async fn relays_the_provider_statement_byte_identically() {
        let (source, body) = source(B256::repeat_byte(1), now(), now() + 288);
        let query = format!("?provider={:#x}", provider_key().address());
        let (status, headers, got) = get(state(Some(source)), &query).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got, body);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
    }

    #[tokio::test]
    async fn an_unknown_provider_is_404() {
        let (source, _) = source(B256::repeat_byte(1), now(), now() + 288);
        let query = format!("?provider={:#x}", Address::repeat_byte(0x42));
        let (status, headers, _) = get(state(Some(source)), &query).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn no_valid_statement_is_503_with_retry_after() {
        let query = format!("?provider={:#x}", provider_key().address());
        // This attestor's own TLS key is not among the pins.
        let (unpinned, _) = source(B256::repeat_byte(9), now(), now() + 288);
        // Expired.
        let (expired, _) = source(B256::repeat_byte(1), now() - 290, now() + 5);
        for state in [state(Some(unpinned)), state(Some(expired)), state(None)] {
            let (status, headers, _) = get(state, &query).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(headers[header::RETRY_AFTER], "5");
            assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        }
    }

    #[tokio::test]
    async fn the_provider_must_be_a_full_hex_address() {
        let (source, _) = source(B256::repeat_byte(1), now(), now() + 288);
        let address = format!("{:x}", provider_key().address());
        for query in [
            String::new(),
            format!("?provider={address}"),
            format!("?provider=0x{}", &address[..38]),
            "?provider=0xzz".to_string(),
        ] {
            let (status, _, _) = get(state(Some(source.clone())), &query).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        }
    }
}
