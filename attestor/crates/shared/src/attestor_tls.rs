//! Attestor TLS statement v3. The sandbox provider signs, with the same key
//! as the container certificate, the TLS SPKI pins of this attestor's app
//! (EIP-712 `AttestorTLS`) and serves them at `GET /api/attestor-tls`. The
//! attestor relays the latest statement byte-identical at
//! `GET /attestor-tls?provider=0x…`; sealed pins its attestor connections to
//! it. Known-answer vector: `testdata/attestor-tls-v3.json`.
use crate::crypto::recover_prehash_signer;
use crate::image_attestation::{lower_hex32, signature65};
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::sol_types::{Eip712Domain, SolStruct};
use async_trait::async_trait;
use serde::Deserialize;
use std::borrow::Cow;
use std::sync::Arc;

pub const VERSION: u64 = 3;
pub const DOMAIN_NAME: &str = "0G Sandbox AttestorTLS";
pub const DOMAIN_VERSION: &str = "3";
pub const MAX_PINS: usize = 16;
pub const MAX_LEASE_SECS: u64 = 300;
pub const MAX_BODY_BYTES: usize = 16 * 1024;
/// sealed accepts a statement only while `expires_at > now + 5`.
const ACCEPT_MARGIN_SECS: u64 = 5;
const CLOCK_SKEW_SECS: u64 = 30;
const REFRESH_AHEAD_SECS: u64 = 60;
/// After a failed refresh, wait this long before asking the provider again.
pub const RETRY_AFTER_SECS: u64 = 5;

alloy::sol! {
    struct AttestorTLS {
        bytes32[] tlsSpkiSha256;
        uint64 issuedAt;
        uint64 expiresAt;
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    version: u64,
    chain_id: u64,
    registry_address: Address,
    tls_spki_sha256: Vec<String>,
    issued_at: u64,
    expires_at: u64,
    signature: String,
}

/// A statement whose formats and lease invariants are valid. Its signature is
/// checked by [`Statement::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub chain_id: u64,
    pub registry_address: Address,
    /// Strictly ascending, 1..=16 entries.
    pub tls_spki_sha256: Vec<B256>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: [u8; 65],
}

pub fn domain(chain_id: u64, registry_address: Address) -> Eip712Domain {
    Eip712Domain::new(
        Some(Cow::Borrowed(DOMAIN_NAME)),
        Some(Cow::Borrowed(DOMAIN_VERSION)),
        Some(U256::from(chain_id)),
        Some(registry_address),
        None,
    )
}

impl Statement {
    pub fn parse(body: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            body.len() <= MAX_BODY_BYTES,
            "attestor TLS statement too large"
        );
        let wire: Wire = serde_json::from_slice(body)?;
        anyhow::ensure!(
            wire.version == VERSION,
            "unsupported attestor TLS statement version {}",
            wire.version
        );
        anyhow::ensure!(
            wire.chain_id > 0 && wire.registry_address != Address::ZERO,
            "invalid attestor TLS statement scope"
        );
        anyhow::ensure!(
            (1..=MAX_PINS).contains(&wire.tls_spki_sha256.len()),
            "attestor TLS statement must carry 1..={MAX_PINS} pins"
        );
        let pins = wire
            .tls_spki_sha256
            .iter()
            .map(|pin| lower_hex32(pin))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| anyhow::anyhow!("TLS pins must be 64 lowercase hex"))?;
        anyhow::ensure!(
            pins.windows(2).all(|pair| pair[0] < pair[1]),
            "TLS pins must be strictly ascending"
        );
        anyhow::ensure!(
            wire.issued_at > 0
                && wire.issued_at < wire.expires_at
                && wire.expires_at - wire.issued_at <= MAX_LEASE_SECS,
            "attestor TLS statement lease is invalid"
        );
        Ok(Self {
            chain_id: wire.chain_id,
            registry_address: wire.registry_address,
            tls_spki_sha256: pins,
            issued_at: wire.issued_at,
            expires_at: wire.expires_at,
            signature: signature65(&wire.signature)?,
        })
    }

    pub fn message(&self) -> AttestorTLS {
        AttestorTLS {
            tlsSpkiSha256: self.tls_spki_sha256.clone(),
            issuedAt: self.issued_at,
            expiresAt: self.expires_at,
        }
    }

    pub fn signing_digest(&self) -> B256 {
        self.message()
            .eip712_signing_hash(&domain(self.chain_id, self.registry_address))
    }

    pub fn recover_signer(&self) -> anyhow::Result<Address> {
        recover_prehash_signer(&self.signing_digest().0, &self.signature)
    }

    pub fn pins(&self, spki_sha256: &B256) -> bool {
        self.tls_spki_sha256.binary_search(spki_sha256).is_ok()
    }

    /// The acceptance rules sealed applies, except the SPKI of the connection
    /// the statement arrived over, which only the container observes.
    pub fn verify(
        &self,
        signer: Address,
        chain_id: u64,
        registry_address: Address,
        now: u64,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.chain_id == chain_id && self.registry_address == registry_address,
            "attestor TLS statement is for another chain or registry"
        );
        anyhow::ensure!(
            self.recover_signer()? == signer,
            "attestor TLS statement is not signed by the provider"
        );
        anyhow::ensure!(
            self.issued_at <= now + CLOCK_SKEW_SECS,
            "attestor TLS statement is issued in the future"
        );
        anyhow::ensure!(
            self.expires_at > now + ACCEPT_MARGIN_SECS,
            "attestor TLS statement has expired"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayError {
    /// The requested address is not the provider this attestor discovered.
    UnknownProvider,
    /// No valid statement is available right now; retry later.
    Unavailable,
}

/// Where the relay reads the provider statement and this attestor's own TLS key.
#[async_trait]
pub trait StatementSource: Send + Sync {
    /// The provider signer discovery currently authenticates.
    async fn provider(&self) -> anyhow::Result<Address>;
    /// The raw statement body served by `provider`, at most `MAX_BODY_BYTES`.
    async fn fetch(&self, provider: Address) -> anyhow::Result<Vec<u8>>;
    /// SHA-256 of this attestor's current app TLS SubjectPublicKeyInfo.
    async fn own_tls_spki(&self) -> anyhow::Result<B256>;
}

#[derive(Clone)]
struct Cached {
    provider: Address,
    body: Bytes,
    issued_at: u64,
    expires_at: u64,
}

#[derive(Default)]
struct RelayState {
    cached: Option<Cached>,
    retry_at: u64,
}

impl RelayState {
    /// No refresh is due before `expires_at - 60`.
    fn fresh(&self, provider: Address, now: u64) -> Option<Bytes> {
        self.cached
            .as_ref()
            .filter(|c| c.provider == provider && now + REFRESH_AHEAD_SECS < c.expires_at)
            .map(|c| c.body.clone())
    }

    /// Still acceptable to sealed, even though a refresh is due.
    fn servable(&self, provider: Address, now: u64) -> Option<Bytes> {
        self.cached
            .as_ref()
            .filter(|c| c.provider == provider && now + ACCEPT_MARGIN_SECS < c.expires_at)
            .map(|c| c.body.clone())
    }
}

/// Serves the latest verified statement of the discovered provider. A cached
/// statement is served from the cache alone; sandbox discovery is consulted
/// only to refresh it, so a discovery renewal or outage never holds or fails a
/// request that the cache can answer. One refresh runs at a time; other
/// callers keep getting the cached statement while it is still acceptable.
pub struct AttestorTlsRelay {
    source: Arc<dyn StatementSource>,
    chain_id: u64,
    registry_address: Address,
    state: std::sync::Mutex<RelayState>,
    refresh: tokio::sync::Mutex<()>,
}

fn unix_now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

impl AttestorTlsRelay {
    pub fn new(source: Arc<dyn StatementSource>, chain_id: u64, registry_address: Address) -> Self {
        Self {
            source,
            chain_id,
            registry_address,
            state: Default::default(),
            refresh: tokio::sync::Mutex::new(()),
        }
    }

    pub async fn statement(&self, provider: Address) -> Result<Bytes, RelayError> {
        // Only a provider discovery named when the statement was loaded has a
        // cache entry, and the statement verified against that provider.
        if let Some(body) = self.state.lock().unwrap().fresh(provider, unix_now()) {
            return Ok(body);
        }
        let _refresh = match self.refresh.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                if let Some(body) = self.state.lock().unwrap().servable(provider, unix_now()) {
                    return Ok(body);
                }
                self.refresh.lock().await
            }
        };
        let now = unix_now();
        {
            let state = self.state.lock().unwrap();
            if let Some(body) = state.fresh(provider, now) {
                return Ok(body);
            }
            if now < state.retry_at {
                return state.servable(provider, now).ok_or(RelayError::Unavailable);
            }
        }
        let current = match self.source.provider().await {
            Ok(current) => current,
            Err(error) => {
                tracing::warn!(%error, "attestor tls: sandbox discovery unavailable");
                let mut state = self.state.lock().unwrap();
                state.retry_at = now + RETRY_AFTER_SECS;
                return state
                    .servable(provider, unix_now())
                    .ok_or(RelayError::Unavailable);
            }
        };
        if provider != current {
            return Err(RelayError::UnknownProvider);
        }
        let previous = self.state.lock().unwrap().cached.clone();
        match self.load(provider, previous.as_ref(), now).await {
            Ok(fresh) => {
                let body = fresh.body.clone();
                // A provider that has not re-signed yet returns the same
                // statement; do not ask it again on every request.
                let unchanged = previous
                    .is_some_and(|p| p.provider == provider && p.issued_at == fresh.issued_at);
                let mut state = self.state.lock().unwrap();
                state.cached = Some(fresh);
                state.retry_at = if unchanged { now + RETRY_AFTER_SECS } else { 0 };
                Ok(body)
            }
            Err(error) => {
                tracing::warn!(%provider, %error, "attestor tls: provider statement rejected or unavailable");
                let mut state = self.state.lock().unwrap();
                state.retry_at = now + RETRY_AFTER_SECS;
                state
                    .servable(provider, unix_now())
                    .ok_or(RelayError::Unavailable)
            }
        }
    }

    async fn load(
        &self,
        provider: Address,
        previous: Option<&Cached>,
        now: u64,
    ) -> anyhow::Result<Cached> {
        let body = self.source.fetch(provider).await?;
        let statement = Statement::parse(&body)?;
        statement.verify(provider, self.chain_id, self.registry_address, now)?;
        if let Some(previous) = previous.filter(|p| p.provider == provider) {
            anyhow::ensure!(
                statement.issued_at >= previous.issued_at,
                "provider served an older statement than the cached one"
            );
        }
        let own = self.source.own_tls_spki().await?;
        anyhow::ensure!(
            statement.pins(&own),
            "provider statement does not pin this attestor's TLS key"
        );
        Ok(Cached {
            provider,
            body: body.into(),
            issued_at: statement.issued_at,
            expires_at: statement.expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocks::{signed_attestor_tls, StaticStatementSource};
    use alloy::signers::local::PrivateKeySigner;
    use std::sync::atomic::Ordering;

    fn vector() -> serde_json::Value {
        serde_json::from_str(include_str!("../testdata/attestor-tls-v3.json")).unwrap()
    }

    fn hex32(value: &serde_json::Value) -> B256 {
        value.as_str().unwrap().parse().unwrap()
    }

    fn provider_key() -> PrivateKeySigner {
        vector()["test_only_provider_key"]["private_key"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap()
    }

    #[test]
    fn known_answer_vector_matches_eip712_hashes_signature_and_signer() {
        let v = vector();
        let body = v["response_body"].as_str().unwrap().as_bytes();
        let statement = Statement::parse(body).unwrap();
        let domain = domain(statement.chain_id, statement.registry_address);
        let message = statement.message();
        assert_eq!(message.eip712_type_hash(), hex32(&v["type_hash"]));
        assert_eq!(domain.separator(), hex32(&v["domain_separator"]));
        assert_eq!(message.eip712_hash_struct(), hex32(&v["struct_hash"]));
        assert_eq!(statement.signing_digest(), hex32(&v["digest"]));
        // bytes32[] is encoded as keccak256 of the concatenated elements.
        let concatenated: Vec<u8> = statement
            .tls_spki_sha256
            .iter()
            .flat_map(|pin| pin.0)
            .collect();
        assert_eq!(
            alloy::primitives::keccak256(concatenated),
            hex32(&v["tls_spki_sha256_array_hash"])
        );
        let mut preimage = vec![0x19, 0x01];
        preimage.extend_from_slice(domain.separator().as_slice());
        preimage.extend_from_slice(message.eip712_hash_struct().as_slice());
        assert_eq!(
            alloy::primitives::keccak256(preimage),
            statement.signing_digest()
        );
        assert_eq!(
            format!("0x{}", hex::encode(statement.signature)),
            v["signature"].as_str().unwrap()
        );
        let signer: Address = v["recovered_address"].as_str().unwrap().parse().unwrap();
        assert_eq!(statement.recover_signer().unwrap(), signer);
        assert_eq!(provider_key().address(), signer);
        // Within its lease the vector passes every relay-side rule.
        statement
            .verify(
                signer,
                statement.chain_id,
                statement.registry_address,
                statement.issued_at,
            )
            .unwrap();
        // The test signer reproduces the provider's exact wire bytes.
        assert_eq!(
            signed_attestor_tls(
                &provider_key(),
                statement.chain_id,
                statement.registry_address,
                &statement.tls_spki_sha256,
                statement.issued_at,
                statement.expires_at
            ),
            body
        );
    }

    #[test]
    fn acceptance_rules_cover_scope_signer_and_lease() {
        let v = vector();
        let statement = Statement::parse(v["response_body"].as_str().unwrap().as_bytes()).unwrap();
        let signer = statement.recover_signer().unwrap();
        let (chain, registry, issued, expires) = (
            statement.chain_id,
            statement.registry_address,
            statement.issued_at,
            statement.expires_at,
        );
        assert!(statement
            .verify(signer, chain + 1, registry, issued)
            .is_err());
        assert!(statement
            .verify(signer, chain, Address::repeat_byte(1), issued)
            .is_err());
        assert!(statement
            .verify(Address::repeat_byte(2), chain, registry, issued)
            .is_err());
        assert!(statement
            .verify(signer, chain, registry, issued - 31)
            .is_err());
        assert!(statement
            .verify(signer, chain, registry, issued - 30)
            .is_ok());
        assert!(statement
            .verify(signer, chain, registry, expires - 6)
            .is_ok());
        assert!(statement
            .verify(signer, chain, registry, expires - 5)
            .is_err());
        let mut zero_parity = statement.clone();
        zero_parity.signature[64] -= 27;
        assert_eq!(zero_parity.recover_signer().unwrap(), signer);
    }

    #[test]
    fn formats_and_invariants_are_strict() {
        let key = provider_key();
        let registry = Address::repeat_byte(9);
        let pin = |b: u8| B256::repeat_byte(b);
        let body = |registry: Address, pins: &[B256], issued: u64, expires: u64| {
            signed_attestor_tls(&key, 1, registry, pins, issued, expires)
        };
        let ok = body(registry, &[pin(1), pin(2)], 100, 400);
        assert!(Statement::parse(&ok).is_ok());
        let edit = |from: &str, to: &str| {
            String::from_utf8(ok.clone())
                .unwrap()
                .replace(from, to)
                .into_bytes()
        };
        let bad = [
            body(registry, &[], 100, 400),
            body(registry, &[pin(2), pin(1)], 100, 400),
            body(registry, &[pin(1), pin(1)], 100, 400),
            body(registry, &(1..=17).map(pin).collect::<Vec<_>>(), 100, 400),
            body(registry, &[pin(1)], 100, 401),
            body(registry, &[pin(1)], 100, 100),
            body(Address::ZERO, &[pin(1)], 100, 400),
            edit("\"version\":3", "\"version\":2"),
            edit("\"tls_spki_sha256\":[\"", "\"tls_spki_sha256\":[\"0x"),
            edit("}", ",\"app_id\":\"x\"}"),
            edit("0101", "0A01"),
        ];
        for (i, body) in bad.iter().enumerate() {
            assert!(Statement::parse(body).is_err(), "case {i}");
        }
        let mut huge = ok.clone();
        huge.resize(MAX_BODY_BYTES + 1, b' ');
        assert!(Statement::parse(&huge).is_err());
    }

    fn make_relay(body: Vec<u8>) -> (Arc<StaticStatementSource>, AttestorTlsRelay) {
        let source = Arc::new(StaticStatementSource::new(
            provider_key().address(),
            body,
            B256::repeat_byte(1),
        ));
        let relay = AttestorTlsRelay::new(source.clone(), 16602, Address::repeat_byte(9));
        (source, relay)
    }

    fn live(pins: &[B256], issued: u64, expires: u64) -> Vec<u8> {
        signed_attestor_tls(
            &provider_key(),
            16602,
            Address::repeat_byte(9),
            pins,
            issued,
            expires,
        )
    }

    #[tokio::test]
    async fn relays_the_verified_body_byte_identically_and_caches_it() {
        let now = unix_now();
        let body = live(
            &[B256::repeat_byte(1), B256::repeat_byte(2)],
            now,
            now + 288,
        );
        let (source, relay) = make_relay(body.clone());
        let provider = provider_key().address();
        assert_eq!(relay.statement(provider).await.unwrap().as_ref(), &body[..]);
        assert_eq!(relay.statement(provider).await.unwrap().as_ref(), &body[..]);
        assert_eq!(source.fetches.load(Ordering::SeqCst), 1);
        assert_eq!(
            relay.statement(Address::repeat_byte(7)).await,
            Err(RelayError::UnknownProvider)
        );
    }

    #[tokio::test]
    async fn refreshes_ahead_of_expiry_and_keeps_serving_on_failure() {
        let now = unix_now();
        let provider = provider_key().address();
        let first = live(&[B256::repeat_byte(1)], now, now + 50);
        let (source, relay) = make_relay(first.clone());
        assert_eq!(
            relay.statement(provider).await.unwrap().as_ref(),
            &first[..]
        );
        // Inside the refresh-ahead window a call refreshes.
        let second = live(&[B256::repeat_byte(1)], now + 1, now + 289);
        source.set_body(Ok(second.clone()));
        assert_eq!(
            relay.statement(provider).await.unwrap().as_ref(),
            &second[..]
        );
        assert_eq!(source.fetches.load(Ordering::SeqCst), 2);

        // A failed refresh keeps the still-acceptable statement and backs off.
        let (source, relay) = make_relay(first.clone());
        relay.statement(provider).await.unwrap();
        source.set_body(Err("provider 503".into()));
        assert_eq!(
            relay.statement(provider).await.unwrap().as_ref(),
            &first[..]
        );
        assert_eq!(
            relay.statement(provider).await.unwrap().as_ref(),
            &first[..]
        );
        assert_eq!(source.fetches.load(Ordering::SeqCst), 2, "backed off");
    }

    #[tokio::test]
    async fn rejects_statements_sealed_could_not_use() {
        let now = unix_now();
        let provider = provider_key().address();
        let other = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x77)).unwrap();
        let pinned = [B256::repeat_byte(1)];
        for body in [
            // Another signer.
            signed_attestor_tls(
                &other,
                16602,
                Address::repeat_byte(9),
                &pinned,
                now,
                now + 200,
            ),
            // This attestor's own key is not pinned.
            live(&[B256::repeat_byte(2)], now, now + 200),
            // About to expire.
            live(&pinned, now - 290, now + 5),
            // Another chain.
            signed_attestor_tls(
                &provider_key(),
                1,
                Address::repeat_byte(9),
                &pinned,
                now,
                now + 200,
            ),
            b"not json".to_vec(),
        ] {
            let (_, relay) = make_relay(body);
            assert_eq!(
                relay.statement(provider).await,
                Err(RelayError::Unavailable)
            );
        }
    }

    #[tokio::test]
    async fn an_unrefreshed_provider_is_not_asked_again_on_every_request() {
        let now = unix_now();
        let body = live(&[B256::repeat_byte(1)], now, now + 50);
        let (source, relay) = make_relay(body.clone());
        let provider = provider_key().address();
        for _ in 0..3 {
            assert_eq!(relay.statement(provider).await.unwrap().as_ref(), &body[..]);
        }
        // First load, one refresh that returned the same statement, then a
        // backoff.
        assert_eq!(source.fetches.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_cached_statement_is_served_without_consulting_discovery() {
        let now = unix_now();
        let provider = provider_key().address();
        let body = live(&[B256::repeat_byte(1)], now, now + 288);
        let (source, relay) = make_relay(body.clone());
        relay.statement(provider).await.unwrap();
        assert_eq!(source.provider_calls.load(Ordering::SeqCst), 1);

        // Discovery renewing or down: the cached statement is still served,
        // and discovery is not asked.
        source.provider_fails.store(true, Ordering::SeqCst);
        assert_eq!(relay.statement(provider).await.unwrap().as_ref(), &body[..]);
        assert_eq!(source.provider_calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_discovery_outage_during_refresh_keeps_serving_an_acceptable_statement() {
        let now = unix_now();
        let provider = provider_key().address();
        let body = live(&[B256::repeat_byte(1)], now, now + 50);
        let (source, relay) = make_relay(body.clone());
        relay.statement(provider).await.unwrap();

        // Inside the refresh-ahead window, discovery fails: serve the cached
        // statement, skip the fetch, and back off.
        source.provider_fails.store(true, Ordering::SeqCst);
        for _ in 0..2 {
            assert_eq!(relay.statement(provider).await.unwrap().as_ref(), &body[..]);
        }
        assert_eq!(source.provider_calls.load(Ordering::SeqCst), 2, "backed off");
        assert_eq!(source.fetches.load(Ordering::SeqCst), 1);

        // With nothing cached, an outage is a retryable 503.
        let (source, relay) = make_relay(body);
        source.provider_fails.store(true, Ordering::SeqCst);
        assert_eq!(
            relay.statement(provider).await,
            Err(RelayError::Unavailable)
        );
        assert_eq!(source.fetches.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_older_statement_never_replaces_the_cached_one() {
        let now = unix_now();
        let newer = live(&[B256::repeat_byte(1)], now, now + 50);
        let (source, relay) = make_relay(newer.clone());
        let provider = provider_key().address();
        relay.statement(provider).await.unwrap();
        source.set_body(Ok(live(&[B256::repeat_byte(1)], now - 10, now + 280)));
        assert_eq!(
            relay.statement(provider).await.unwrap().as_ref(),
            &newer[..]
        );
    }
}
