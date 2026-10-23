//! Production app identities: local tapp resolves through its live pinned Scan;
//! business authorization and URLs remain on their own contracts.
use crate::{tapp_grpc, Config};
use alloy::{
    primitives::{keccak256, Address, U256},
    sol,
};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::sync::Mutex;

pub const STARTUP_IDENTITY_TIMEOUT: Duration = Duration::from_secs(180);
const STARTUP_IDENTITY_RETRY: Duration = Duration::from_secs(2);
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(180);

type IdentityProvider =
    alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>;

fn identity_provider(
    url: reqwest::Url,
    request_timeout: Duration,
) -> anyhow::Result<IdentityProvider> {
    let transport = crate::chain::rpc_http_transport(url, request_timeout)?;
    let is_local = transport.guess_local();
    Ok(IdentityProvider::new(alloy::rpc::client::RpcClient::new(
        transport, is_local,
    )))
}

async fn snapshot_with_deadline<T>(
    budget: Duration,
    snapshot: impl Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    tokio::time::timeout(budget, snapshot)
        .await
        .map_err(|_| anyhow::anyhow!("identity snapshot refresh timed out"))?
}

/// Initialize key material once, then wait for observations and authorization.
/// The one deadline bounds initialization and every readiness attempt, including
/// an RPC that accepts a connection but never returns.
async fn initialize_then_wait<S, T, I, IFut, C, CFut>(
    timeout: Duration,
    retry_interval: Duration,
    initialize: I,
    mut check: C,
) -> anyhow::Result<(S, T)>
where
    S: Clone,
    I: FnOnce() -> IFut,
    IFut: Future<Output = anyhow::Result<S>>,
    C: FnMut(S) -> CFut,
    CFut: Future<Output = anyhow::Result<T>>,
{
    anyhow::ensure!(
        !timeout.is_zero() && !retry_interval.is_zero(),
        "invalid identity startup wait durations"
    );
    let deadline = tokio::time::Instant::now() + timeout;
    let state = tokio::time::timeout_at(deadline, initialize())
        .await
        .map_err(|_| anyhow::anyhow!("identity startup timed out during key initialization"))??;
    let mut attempt = 0u32;
    let mut last_error = "identity readiness was not observed".to_string();
    loop {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "identity startup timed out after {}s: {}",
                timeout.as_secs_f64(),
                last_error
            );
        }
        attempt += 1;
        match tokio::time::timeout_at(deadline, check(state.clone())).await {
            Ok(Ok(ready)) if tokio::time::Instant::now() < deadline => return Ok((state, ready)),
            Ok(Ok(_)) | Err(_) => {
                anyhow::bail!(
                    "identity startup timed out after {}s: {}",
                    timeout.as_secs_f64(),
                    last_error
                );
            }
            Ok(Err(error)) => {
                last_error = format!("{error:#}");
                tracing::warn!(attempt, error = %last_error, "application identities not ready; waiting before startup");
            }
        }
        let next = (tokio::time::Instant::now() + retry_interval).min(deadline);
        tokio::time::sleep_until(next).await;
    }
}

/// Start both lookups together and drain both before propagating either error,
/// so a fast failure cannot cancel the other app's accepted Scan lookup. Check
/// both leases against the same final time after both lookups succeed.
async fn ready_snapshots<A, S>(
    attestor: A,
    sandbox: S,
) -> anyhow::Result<(
    Option<AttestorTlsDescriptor>,
    Option<Arc<SandboxConnection>>,
)>
where
    A: Future<Output = anyhow::Result<Option<AttestorTlsDescriptor>>>,
    S: Future<Output = anyhow::Result<Option<Arc<SandboxConnection>>>>,
{
    let (attestor, sandbox) = tokio::join!(attestor, sandbox);
    let attestor = attestor?;
    let sandbox = sandbox?;
    let now = chrono::Utc::now().timestamp();
    anyhow::ensure!(
        attestor.as_ref().is_none_or(|a| a.expires_at > now + 5)
            && sandbox.as_ref().is_none_or(|s| s.expires_at > now + 5),
        "identity expired before startup readiness completed"
    );
    Ok((attestor, sandbox))
}

#[derive(Clone)]
pub struct StartupIdentities {
    pub app_private_key: [u8; 32],
    pub attestor: Option<Arc<AttestorDiscovery>>,
    pub sandbox: Option<Arc<SandboxDiscovery>>,
}

/// Both binaries share the same bootstrap order. No key fetch occurs inside the
/// readiness retry, and no mock/manual endpoint is used after a production error.
pub async fn initialize_for_startup(
    cfg: &mut Config,
    key_provider: &dyn crate::tee::TeeKeyProvider,
) -> anyhow::Result<StartupIdentities> {
    if !cfg.mock_tee {
        validate_attestor_config(cfg)?;
        if !cfg.mock_sandbox {
            // Validate static sandbox discovery settings before acquiring any key.
            SandboxDiscovery::new(cfg)?;
        }
    }
    let (identities, connection) = initialize_then_wait(
        STARTUP_IDENTITY_TIMEOUT,
        STARTUP_IDENTITY_RETRY,
        || async {
            let app_private_key = key_provider.app_private_key().await?;
            let signer = crate::sandbox::AdminSigner::from_priv(app_private_key)?.address();
            Ok(StartupIdentities {
                app_private_key,
                attestor: if cfg.mock_tee {
                    None
                } else {
                    Some(AttestorDiscovery::new(cfg, signer)?)
                },
                sandbox: if cfg.mock_tee || cfg.mock_sandbox {
                    None
                } else {
                    Some(SandboxDiscovery::new(cfg)?)
                },
            })
        },
        |identities: StartupIdentities| async move {
            let (_, sandbox) = ready_snapshots(
                async {
                    match &identities.attestor {
                        Some(identity) => Ok(Some(identity.snapshot().await?)),
                        None => Ok(None),
                    }
                },
                async {
                    match &identities.sandbox {
                        Some(identity) => Ok(Some(identity.snapshot().await?)),
                        None => Ok(None),
                    }
                },
            )
            .await?;
            Ok(sandbox)
        },
    )
    .await?;
    if let Some(snapshot) = connection {
        cfg.sandbox_provider_addr = Some(snapshot.provider);
        cfg.sandbox_endpoint = snapshot.base_url.clone();
    }
    Ok(identities)
}

fn validate_attestor_config(cfg: &Config) -> anyhow::Result<()> {
    anyhow::ensure!(
        cfg.tapp_socket
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty()),
        "production identity resolution requires ATTESTOR_TAPP_SOCKET"
    );
    anyhow::ensure!(
        cfg.app_id.as_deref().is_some_and(|s| !s.trim().is_empty()),
        "ATTESTOR_APP_ID is required"
    );
    anyhow::ensure!(
        cfg.chain_id != 0
            && cfg.tapp_registry_addr != Address::ZERO
            && cfg.agentic_id_addr != Address::ZERO,
        "chain scope, TappRegistry and AgenticID are required"
    );
    let rpc = reqwest::Url::parse(&cfg.chain_rpc)?;
    anyhow::ensure!(
        matches!(rpc.scheme(), "http" | "https") && rpc.host_str().is_some(),
        "ATTESTOR_CHAIN_RPC must be an HTTP(S) RPC URL"
    );
    validate_https_locator(&cfg.attestor_public_url)
}

sol! {
    #[sol(rpc)]
    interface IdentityRegistry {
        struct AppInfo { bytes composeHash; bytes volumesHash; bytes[] imageHashes; address owner; uint256 registeredAt; }
        function getAppInfo(string appId) external view returns (AppInfo info);
    }
    #[sol(rpc)]
    interface ServingIdentity {
        function services(address provider) external view returns (string url, string appId, uint256 pricePerCPUPerMin, uint256 pricePerMemGBPerMin, uint256 createFee);
        function serviceExists(address provider) external view returns (bool);
        function isActiveProvider(address provider) external view returns (bool);
        function kmsBindings(address provider) external view returns (uint256 epoch, bytes32 appIdHash);
        function tappRegistry() external view returns (address);
    }
    #[sol(rpc)]
    interface AttestorAuthorization {
        function instanceBoundAttestorsRequired() external view returns (bool);
        function isTrustedAttestor(address attestor) external view returns (bool);
        function trustedAttestorAppBinding(address attestor) external view returns (address registry, string appId, uint256 registeredAt, address appOwner);
    }
}

#[derive(Clone)]
pub struct SandboxConnection {
    pub provider: Address,
    pub base_url: String,
    pub registered_at: u64,
    pub expires_at: i64,
    pub http: reqwest::Client,
}

pub struct SandboxDiscovery {
    cfg: Config,
    // One refresh across callers; a failed refresh never serves an expired snapshot.
    cached: Mutex<Option<Arc<SandboxConnection>>>,
}

/// Public bootstrap data, delivered only through an authenticated sandbox create.
/// Runtimes independently refresh through the supplied pinned Scan trust anchor.
#[derive(Clone, Debug, serde::Serialize)]
pub struct AttestorTlsDescriptor {
    pub version: u8,
    pub chain_id: u64,
    pub registry_address: String,
    pub app_id: String,
    pub registered_at: u64,
    pub app_signer: String,
    pub url: String,
    pub scan_url: String,
    pub scan_public_key: String,
    pub tls_spki_sha256: Vec<String>,
    pub checked_at: i64,
    pub expires_at: i64,
}

pub struct AttestorDiscovery {
    cfg: Config,
    signer: Address,
    cached: Mutex<Option<AttestorTlsDescriptor>>,
}

impl AttestorDiscovery {
    pub fn new(cfg: &Config, signer: Address) -> anyhow::Result<Arc<Self>> {
        validate_attestor_config(cfg)?;
        anyhow::ensure!(
            signer != Address::ZERO,
            "attestor app signer must not be zero"
        );
        Ok(Arc::new(Self {
            cfg: cfg.clone(),
            signer,
            cached: Mutex::new(None),
        }))
    }

    pub async fn snapshot(&self) -> anyhow::Result<AttestorTlsDescriptor> {
        snapshot_with_deadline(SNAPSHOT_TIMEOUT, self.snapshot_inner()).await
    }

    async fn snapshot_inner(&self) -> anyhow::Result<AttestorTlsDescriptor> {
        let mut cached = self.cached.lock().await;
        if let Some(descriptor) = &*cached {
            if descriptor.expires_at > chrono::Utc::now().timestamp() + 30 {
                return Ok(descriptor.clone());
            }
        }
        let descriptor = attestor_descriptor(&self.cfg, self.signer).await?;
        if let Some(previous) = &*cached {
            anyhow::ensure!(
                descriptor.registered_at == previous.registered_at,
                "attestor registration changed; restart and recreate runtimes"
            );
        }
        *cached = Some(descriptor.clone());
        Ok(descriptor)
    }
}

impl SandboxDiscovery {
    pub async fn invalidate(&self) {
        *self.cached.lock().await = None;
    }
    pub fn new(cfg: &Config) -> anyhow::Result<Arc<Self>> {
        anyhow::ensure!(
            cfg.tapp_socket.is_some(),
            "production identity resolution requires ATTESTOR_TAPP_SOCKET"
        );
        anyhow::ensure!(
            cfg.sandbox_app_id
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty()),
            "ATTESTOR_SANDBOX_APP_ID is required"
        );
        anyhow::ensure!(
            cfg.sandbox_serving_addr.is_some_and(|a| a != Address::ZERO)
                && cfg.tapp_registry_addr != Address::ZERO,
            "SandboxServing and TappRegistry are required"
        );
        Ok(Arc::new(Self {
            cfg: cfg.clone(),
            cached: Mutex::new(None),
        }))
    }

    pub async fn snapshot(&self) -> anyhow::Result<Arc<SandboxConnection>> {
        snapshot_with_deadline(SNAPSHOT_TIMEOUT, self.snapshot_inner()).await
    }

    async fn snapshot_inner(&self) -> anyhow::Result<Arc<SandboxConnection>> {
        let mut cache = self.cached.lock().await;
        let now = chrono::Utc::now().timestamp();
        if let Some(snapshot) = &*cache {
            if snapshot.expires_at > now + 5 {
                return Ok(snapshot.clone());
            }
        }
        let app_id = self.cfg.sandbox_app_id.as_deref().unwrap();
        let resolved = resolve(&self.cfg, app_id).await?;
        let (signer, pins, expires_at) = validate_resolved(
            self.cfg.chain_id,
            self.cfg.tapp_registry_addr,
            app_id,
            &resolved,
            chrono::Utc::now().timestamp(),
        )?;
        let provider = identity_provider(
            self.cfg.chain_rpc.parse()?,
            crate::nonce_submit::RPC_TIMEOUT,
        )?;
        let registry = IdentityRegistry::new(self.cfg.tapp_registry_addr, &provider);
        let app = registry.getAppInfo(app_id.to_string()).call().await?.info;
        anyhow::ensure!(
            app.registeredAt == U256::from(resolved.registered_at) && app.owner != Address::ZERO,
            "sandbox registration changed during discovery"
        );
        let serving = ServingIdentity::new(self.cfg.sandbox_serving_addr.unwrap(), &provider);
        anyhow::ensure!(
            serving.tappRegistry().call().await?._0 == self.cfg.tapp_registry_addr,
            "SandboxServing registry mismatch"
        );
        let service = serving.services(signer).call().await?;
        let binding = serving.kmsBindings(signer).call().await?;
        anyhow::ensure!(
            service.appId == app_id && !service.url.is_empty(),
            "sandbox provider service appId/URL mismatch"
        );
        anyhow::ensure!(
            serving.serviceExists(signer).call().await?._0
                && serving.isActiveProvider(signer).call().await?._0,
            "sandbox provider is inactive"
        );
        anyhow::ensure!(
            binding.epoch != U256::ZERO
                && binding.epoch == app.registeredAt
                && binding.appIdHash == keccak256(app_id.as_bytes()),
            "sandbox KMS provider instance mismatch"
        );
        validate_https_locator(&service.url)?;
        let http = pinned_client(pins)?;
        // Authenticate the business endpoint too; management tee_url is not its URL.
        let response = http
            .get(format!("{}/api/info", service.url.trim_end_matches('/')))
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "sandbox endpoint info request failed: {}",
            response.status()
        );
        let info: serde_json::Value = response.json().await?;
        anyhow::ensure!(
            info["provider_address"]
                .as_str()
                .and_then(|s| s.parse::<Address>().ok())
                == Some(signer),
            "sandbox endpoint reports another provider"
        );
        anyhow::ensure!(
            info["app_id"].as_str() == Some(app_id),
            "sandbox endpoint reports another app"
        );
        // The remote lookup and TLS handshake can outlive the identity TTL.
        // Recheck both instance and freshness before publishing one snapshot.
        let current = registry.getAppInfo(app_id.to_string()).call().await?.info;
        anyhow::ensure!(
            current.registeredAt == app.registeredAt && current.owner == app.owner,
            "sandbox registration changed during discovery"
        );
        anyhow::ensure!(
            expires_at > chrono::Utc::now().timestamp() + 5,
            "sandbox identity expired during discovery"
        );
        let snapshot = Arc::new(SandboxConnection {
            provider: signer,
            base_url: service.url,
            registered_at: resolved.registered_at,
            expires_at,
            http,
        });
        *cache = Some(snapshot.clone());
        Ok(snapshot)
    }
}

pub async fn resolve(
    cfg: &Config,
    app_id: &str,
) -> anyhow::Result<tapp_grpc::proto::ResolveAppIdentityResponse> {
    use tapp_grpc::proto::{tapp_service_client::TappServiceClient, ResolveAppIdentityRequest};
    let mut client = TappServiceClient::new(tapp_grpc::connect(cfg).await?);
    let response = client
        .resolve_app_identity(ResolveAppIdentityRequest {
            chain_id: cfg.chain_id,
            registry_address: format!("{:#x}", cfg.tapp_registry_addr),
            app_id: app_id.to_string(),
        })
        .await?
        .into_inner();
    anyhow::ensure!(
        response.success,
        "tapp app identity resolution failed: {}",
        response.message
    );
    Ok(response)
}

fn validate_resolved(
    chain_id: u64,
    registry: Address,
    app_id: &str,
    response: &tapp_grpc::proto::ResolveAppIdentityResponse,
    now: i64,
) -> anyhow::Result<(Address, Vec<String>, i64)> {
    anyhow::ensure!(
        response.success
            && response.chain_id == chain_id
            && response.registry_address.parse::<Address>()? == registry
            && response.app_id == app_id
            && response.registered_at != 0,
        "resolved identity scope/instance mismatch"
    );
    anyhow::ensure!(!response.nodes.is_empty(), "app has no verified nodes");
    let mut signer = None;
    let mut pins = Vec::new();
    let mut expires = i64::MAX;
    for node in &response.nodes {
        anyhow::ensure!(
            node.expires_at > now + 5
                && node.checked_at <= now + 30
                && node.checked_at >= now - 300
                && node.expires_at <= node.checked_at + 300,
            "resolved app identity is stale"
        );
        anyhow::ensure!(
            node.image_env == "prod",
            "production identity requires a production TEE image"
        );
        let pin = node
            .tls_spki_sha256
            .strip_prefix("0x")
            .unwrap_or(&node.tls_spki_sha256);
        anyhow::ensure!(
            pin.len() == 64 && hex::decode(pin).is_ok(),
            "app has no valid TLS SPKI pin"
        );
        // A current standby can have acquired TLS before its stable signer.
        // Validate its observation, but do not route service traffic to it.
        if node.app_signer.is_empty() {
            continue;
        }
        let current: Address = node
            .app_signer
            .parse()
            .map_err(|_| anyhow::anyhow!("app has no valid stable app_signer"))?;
        anyhow::ensure!(
            current != Address::ZERO && signer.is_none_or(|s| s == current),
            "nodes disagree on app_signer"
        );
        signer = Some(current);
        pins.push(pin.to_ascii_lowercase());
        expires = expires.min(node.expires_at);
    }
    pins.sort();
    pins.dedup();
    let signer = signer.ok_or_else(|| anyhow::anyhow!("app has no ready stable app_signer"))?;
    Ok((signer, pins, expires))
}

pub fn validate_https_locator(locator: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(locator)?;
    anyhow::ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "business locator must be HTTPS without credentials/query/fragment"
    );
    Ok(())
}

pub fn pinned_client(pins: Vec<String>) -> anyhow::Result<reqwest::Client> {
    anyhow::ensure!(!pins.is_empty(), "no attested TLS pins");
    Ok(reqwest::Client::builder()
        .use_preconfigured_tls(crate::pinned_tls::client_config(pins))
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(std::time::Duration::from_secs(30))
        .build()?)
}

/// Production must migrate the business contract before using the stable key.
async fn attestor_descriptor(
    cfg: &Config,
    signer: Address,
) -> anyhow::Result<AttestorTlsDescriptor> {
    let app_id = tapp_grpc::require_app_id(cfg)?;
    let identity = resolve(cfg, &app_id).await?;
    let (resolved_signer, pins, expires_at) = validate_resolved(
        cfg.chain_id,
        cfg.tapp_registry_addr,
        &app_id,
        &identity,
        chrono::Utc::now().timestamp(),
    )?;
    anyhow::ensure!(
        signer == resolved_signer,
        "attestor signer differs from its attested app_signer"
    );
    validate_https_locator(&cfg.attestor_public_url)?;
    validate_https_locator(&identity.scan_url)?;
    let scan_pin = identity
        .scan_public_key
        .strip_prefix("0x")
        .unwrap_or(&identity.scan_public_key);
    anyhow::ensure!(
        scan_pin.len() == 64 && hex::decode(scan_pin).is_ok(),
        "attestor identity has no pinned Scan trust anchor"
    );
    let provider = identity_provider(cfg.chain_rpc.parse()?, crate::nonce_submit::RPC_TIMEOUT)?;
    let auth = AttestorAuthorization::new(cfg.agentic_id_addr, &provider);
    anyhow::ensure!(
        auth.instanceBoundAttestorsRequired().call().await?._0,
        "AgenticID requires the instance-bound attestor migration"
    );
    let binding = auth.trustedAttestorAppBinding(signer).call().await?;
    anyhow::ensure!(
        binding.registry == cfg.tapp_registry_addr
            && binding.appId == app_id
            && binding.registeredAt == U256::from(identity.registered_at),
        "attestor business authorization is bound to another app instance"
    );
    anyhow::ensure!(
        auth.isTrustedAttestor(signer).call().await?._0,
        "attestor app instance is no longer authorized"
    );
    anyhow::ensure!(
        expires_at > chrono::Utc::now().timestamp() + 5,
        "attestor identity expired during authorization lookup"
    );
    Ok(AttestorTlsDescriptor {
        version: 1,
        chain_id: cfg.chain_id,
        registry_address: format!("{:#x}", cfg.tapp_registry_addr),
        app_id,
        registered_at: identity.registered_at,
        app_signer: format!("{:#x}", signer),
        url: cfg.attestor_public_url.trim_end_matches('/').to_string(),
        scan_url: identity.scan_url,
        scan_public_key: scan_pin.to_ascii_lowercase(),
        tls_spki_sha256: pins,
        checked_at: identity
            .nodes
            .iter()
            .filter(|node| !node.app_signer.is_empty())
            .map(|node| node.checked_at)
            .min()
            .unwrap(),
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::TeeKeyProvider;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tapp_grpc::proto::{ResolveAppIdentityResponse, ResolvedAppNodeIdentity};

    #[tokio::test]
    async fn identity_rpc_deadline_bounds_a_real_silent_http_peer() {
        use alloy::providers::Provider;
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let (sent, received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4096];
            assert!(socket.read(&mut bytes).await.unwrap() > 0);
            sent.send(()).unwrap();
            std::future::pending::<()>().await;
            drop(socket);
        });
        // Both production discovery paths use this exact provider factory.
        let provider = identity_provider(url, Duration::from_millis(50)).unwrap();
        let request = tokio::spawn(async move { provider.get_block_number().await });
        tokio::time::timeout(Duration::from_secs(2), received)
            .await
            .unwrap()
            .unwrap();
        let result = tokio::time::timeout(Duration::from_millis(300), request).await;
        server.abort();
        assert!(result
            .expect("identity RPC ignored the HTTP request deadline")
            .unwrap()
            .is_err());
    }

    #[tokio::test]
    async fn snapshot_timeout_cancels_refresh_and_releases_its_cache_lock() {
        let cached_lease = chrono::Utc::now().timestamp() + 10;
        let cache = Mutex::new(Some(cached_lease));
        let started = std::sync::atomic::AtomicBool::new(false);
        let result = snapshot_with_deadline(Duration::from_millis(20), async {
            let mut cached = cache.lock().await;
            started.store(true, Ordering::SeqCst);
            // A local tapp request or authorization RPC never responds.
            // Publishing a replacement must happen only after it succeeds.
            std::future::pending::<()>().await;
            *cached = Some(cached_lease + 300);
            Ok(())
        })
        .await;
        assert!(result.unwrap_err().to_string().contains("timed out"));
        assert!(started.load(Ordering::SeqCst));
        let cached = cache
            .try_lock()
            .expect("cancelled refresh retained its lock");
        assert_eq!(*cached, Some(cached_lease), "timeout extended the lease");
    }

    #[tokio::test]
    async fn snapshot_timeout_also_bounds_waiting_for_another_refresh() {
        let cache = Mutex::new(None::<()>);
        let held = cache.lock().await;
        let started = std::sync::atomic::AtomicBool::new(false);
        let result = snapshot_with_deadline(Duration::from_millis(20), async {
            let _cached = cache.lock().await;
            started.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await;
        assert!(result.unwrap_err().to_string().contains("timed out"));
        assert!(!started.load(Ordering::SeqCst));
        drop(held);
        assert!(cache.try_lock().is_ok());
    }

    struct LookupCompletion {
        finished: Arc<std::sync::atomic::AtomicBool>,
        cancelled: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for LookupCompletion {
        fn drop(&mut self) {
            if !self.finished.load(Ordering::SeqCst) {
                self.cancelled.store(true, Ordering::SeqCst);
            }
        }
    }

    async fn slow_lookup<T>(
        gate: Arc<tokio::sync::Barrier>,
        completion: LookupCompletion,
    ) -> anyhow::Result<Option<T>> {
        let _completion = completion;
        gate.wait().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        _completion.finished.store(true, Ordering::SeqCst);
        Ok(None)
    }

    async fn failed_lookup<T>(gate: Arc<tokio::sync::Barrier>) -> anyhow::Result<Option<T>> {
        gate.wait().await;
        anyhow::bail!("fixture Scan returned 429")
    }

    async fn check_lookup_error_drains_other_side(attestor_fails: bool) {
        let gate = Arc::new(tokio::sync::Barrier::new(2));
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let completion = LookupCompletion {
            finished: finished.clone(),
            cancelled: cancelled.clone(),
        };
        let result = if attestor_fails {
            ready_snapshots(failed_lookup(gate.clone()), slow_lookup(gate, completion)).await
        } else {
            ready_snapshots(slow_lookup(gate.clone(), completion), failed_lookup(gate)).await
        };
        assert!(
            result.is_err(),
            "a failed identity lookup must still fail startup"
        );
        assert_eq!(
            result.err().unwrap().to_string(),
            "fixture Scan returned 429"
        );
        assert!(
            finished.load(Ordering::SeqCst),
            "the sibling lookup was cancelled before it could publish its observation"
        );
        assert!(
            !cancelled.load(Ordering::SeqCst),
            "a fast error dropped the accepted sibling lookup"
        );
    }

    #[tokio::test]
    async fn startup_lookup_error_drains_sandbox_before_returning_attestor_error() {
        check_lookup_error_drains_other_side(true).await;
    }

    #[tokio::test]
    async fn startup_lookup_error_drains_attestor_before_returning_sandbox_error() {
        check_lookup_error_drains_other_side(false).await;
    }

    #[tokio::test]
    async fn startup_snapshot_lookups_both_start_before_either_is_released() {
        let gate = Arc::new(tokio::sync::Barrier::new(3));
        let first = gate.clone();
        let second = gate.clone();
        let (ready, _) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(
                ready_snapshots(
                    async move {
                        first.wait().await;
                        Ok(None)
                    },
                    async move {
                        second.wait().await;
                        Ok(None)
                    },
                ),
                gate.wait(),
            )
        })
        .await
        .expect("both lookups must start concurrently before the barrier opens");
        assert!(ready.is_ok());
    }

    #[tokio::test]
    async fn startup_snapshots_require_both_final_leases_to_exceed_the_margin() {
        let expires_at = chrono::Utc::now().timestamp() + 5;
        let attestor = AttestorTlsDescriptor {
            version: 1,
            chain_id: 1,
            registry_address: String::new(),
            app_id: "app".into(),
            registered_at: 1,
            app_signer: String::new(),
            url: String::new(),
            scan_url: String::new(),
            scan_public_key: String::new(),
            tls_spki_sha256: vec![],
            checked_at: expires_at - 60,
            expires_at,
        };
        let sandbox = Arc::new(SandboxConnection {
            provider: Address::ZERO,
            base_url: String::new(),
            registered_at: 1,
            expires_at,
            http: reqwest::Client::new(),
        });
        for (attestor, sandbox) in [(Some(attestor), None), (None, Some(sandbox))] {
            let result = ready_snapshots(async { Ok(attestor) }, async { Ok(sandbox) }).await;
            match result {
                Err(error) => assert!(error
                    .to_string()
                    .contains("identity expired before startup")),
                Ok(_) => {
                    panic!("neither side may return a lease at or below the five-second margin")
                }
            }
        }
    }

    #[tokio::test]
    async fn startup_wait_retries_until_observation_is_ready() {
        let mut attempts = 0;
        let (state, ready) = initialize_then_wait(
            Duration::from_secs(2),
            Duration::from_millis(1),
            || async { Ok(7u8) },
            |state| {
                attempts += 1;
                let attempt = attempts;
                async move {
                    if attempt < 3 {
                        anyhow::bail!("Scan cache has not observed TLS yet");
                    }
                    Ok(state + 1)
                }
            },
        )
        .await
        .unwrap();
        assert_eq!((state, ready, attempts), (7, 8, 3));
    }

    #[tokio::test]
    async fn startup_wait_bounds_an_unresponsive_readiness_rpc() {
        let error = initialize_then_wait(
            Duration::from_millis(20),
            Duration::from_millis(1),
            || async { Ok(()) },
            |()| std::future::pending::<anyhow::Result<()>>(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("identity startup timed out"));
    }

    struct CountingKeyProvider(AtomicUsize);
    #[async_trait::async_trait]
    impl TeeKeyProvider for CountingKeyProvider {
        async fn app_private_key(&self) -> anyhow::Result<[u8; 32]> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok([1; 32])
        }
    }

    #[tokio::test]
    async fn startup_wait_initializes_key_provider_only_once() {
        let provider = CountingKeyProvider(AtomicUsize::new(0));
        let mut attempts = 0;
        let (key, ()) = initialize_then_wait(
            Duration::from_secs(2),
            Duration::from_millis(1),
            || provider.app_private_key(),
            |key| {
                attempts += 1;
                let attempt = attempts;
                async move {
                    assert_eq!(key, [1; 32]);
                    if attempt < 3 {
                        anyhow::bail!("business authorization is not ready");
                    }
                    Ok(())
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(key, [1; 32]);
        assert_eq!(attempts, 3);
        assert_eq!(provider.0.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn startup_wait_also_bounds_unresponsive_key_initialization() {
        let error = initialize_then_wait(
            Duration::from_millis(20),
            Duration::from_millis(1),
            || std::future::pending::<anyhow::Result<()>>(),
            |()| async { Ok(()) },
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("timed out during key initialization"));
    }
    fn response() -> ResolveAppIdentityResponse {
        ResolveAppIdentityResponse {
            success: true,
            chain_id: 16602,
            registry_address: format!("{:#x}", Address::repeat_byte(1)),
            app_id: "sandbox".into(),
            registered_at: 100,
            nodes: vec![ResolvedAppNodeIdentity {
                node_signer: format!("{:#x}", Address::repeat_byte(2)),
                app_signer: format!("{:#x}", Address::repeat_byte(3)),
                tls_spki_sha256: "ab".repeat(32),
                checked_at: 1_000,
                expires_at: 1_300,
                image_env: "prod".into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }
    fn check(r: &ResolveAppIdentityResponse) -> anyhow::Result<(Address, Vec<String>, i64)> {
        validate_resolved(16602, Address::repeat_byte(1), "sandbox", r, 1_010)
    }
    #[test]
    fn accepts_one_stable_signer_with_per_node_tls_keys() {
        let mut r = response();
        let mut second = r.nodes[0].clone();
        second.node_signer = format!("{:#x}", Address::repeat_byte(4));
        second.tls_spki_sha256 = "cd".repeat(32);
        second.expires_at = 1_200;
        r.nodes.push(second);
        let (signer, pins, expiry) = check(&r).unwrap();
        assert_eq!(signer, Address::repeat_byte(3));
        assert_eq!(pins.len(), 2);
        assert_eq!(expiry, 1_200);
    }
    #[test]
    fn tls_only_standby_does_not_contribute_service_pins_or_expiry() {
        let mut r = response();
        let mut standby = r.nodes[0].clone();
        standby.node_signer = format!("{:#x}", Address::repeat_byte(4));
        standby.app_signer.clear();
        standby.tls_spki_sha256 = "cd".repeat(32);
        standby.checked_at = 800;
        standby.expires_at = 1_050;
        r.nodes.insert(0, standby.clone());
        let (signer, pins, expiry) = check(&r).unwrap();
        assert_eq!(signer, Address::repeat_byte(3));
        assert_eq!(pins, vec!["ab".repeat(32)]);
        assert_eq!(expiry, 1_300);

        r.nodes = vec![standby];
        assert!(
            check(&r).is_err(),
            "TLS alone cannot authenticate a service signer"
        );
    }
    #[test]
    fn tls_only_standby_does_not_hide_invalid_or_conflicting_nodes() {
        let mutations: [fn(&mut ResolvedAppNodeIdentity); 5] = [
            |n| n.app_signer = "invalid".into(),
            |n| n.app_signer = format!("{:#x}", Address::repeat_byte(9)),
            |n| n.expires_at = 1_000,
            |n| n.image_env = "dev".into(),
            |n| n.tls_spki_sha256 = "bad".into(),
        ];
        for mutate in mutations {
            let mut r = response();
            let mut standby = r.nodes[0].clone();
            standby.app_signer.clear();
            mutate(&mut standby);
            r.nodes.push(standby);
            assert!(check(&r).is_err());
        }
    }
    #[test]
    fn rejects_missing_conflicting_stale_or_wrong_scope_identities() {
        let mutations: [fn(&mut ResolveAppIdentityResponse); 8] = [
            |r| r.chain_id = 1,
            |r| r.app_id = "other".into(),
            |r| r.registered_at = 0,
            |r| r.nodes[0].app_signer.clear(),
            |r| r.nodes[0].expires_at = 1_000,
            |r| r.nodes[0].image_env = "dev".into(),
            |r| r.nodes[0].tls_spki_sha256.clear(),
            |r| {
                let mut n = r.nodes[0].clone();
                n.app_signer = format!("{:#x}", Address::repeat_byte(9));
                r.nodes.push(n);
            },
        ];
        for mutate in mutations {
            let mut r = response();
            mutate(&mut r);
            assert!(check(&r).is_err());
        }
    }
    #[test]
    fn refuses_plaintext_and_ambiguous_locators() {
        for url in [
            "http://service",
            "https://user:pass@service",
            "https://service?q=1",
            "https://service/#x",
        ] {
            assert!(validate_https_locator(url).is_err());
        }
        assert!(validate_https_locator("https://service.example/api").is_ok());
        assert!(pinned_client(Vec::new()).is_err());
    }
}
