//! Production app identities: local tapp resolves through its live pinned Scan;
//! business authorization and URLs remain on their own contracts.
use crate::{tapp_grpc, Config};
use alloy::{
    primitives::{keccak256, Address, U256},
    providers::ProviderBuilder,
    sol,
};
use std::sync::Arc;
use tokio::sync::Mutex;

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
    pub fn new(cfg: &Config, signer: Address) -> Arc<Self> {
        Arc::new(Self {
            cfg: cfg.clone(),
            signer,
            cached: Mutex::new(None),
        })
    }

    pub async fn snapshot(&self) -> anyhow::Result<AttestorTlsDescriptor> {
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
            cfg.sandbox_app_id.as_deref().is_some_and(|s| !s.is_empty()),
            "ATTESTOR_SANDBOX_APP_ID is required"
        );
        anyhow::ensure!(
            cfg.sandbox_serving_addr.is_some() && cfg.tapp_registry_addr != Address::ZERO,
            "SandboxServing and TappRegistry are required"
        );
        Ok(Arc::new(Self {
            cfg: cfg.clone(),
            cached: Mutex::new(None),
        }))
    }

    pub async fn snapshot(&self) -> anyhow::Result<Arc<SandboxConnection>> {
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
        let provider = ProviderBuilder::new().on_http(self.cfg.chain_rpc.parse()?);
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
        let current: Address = node
            .app_signer
            .parse()
            .map_err(|_| anyhow::anyhow!("app has no stable app_signer"))?;
        anyhow::ensure!(
            current != Address::ZERO && signer.is_none_or(|s| s == current),
            "nodes disagree on app_signer"
        );
        signer = Some(current);
        let pin = node
            .tls_spki_sha256
            .strip_prefix("0x")
            .unwrap_or(&node.tls_spki_sha256);
        anyhow::ensure!(
            pin.len() == 64 && hex::decode(pin).is_ok(),
            "app has no valid TLS SPKI pin"
        );
        pins.push(pin.to_ascii_lowercase());
        expires = expires.min(node.expires_at);
    }
    pins.sort();
    pins.dedup();
    Ok((signer.unwrap(), pins, expires))
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
    let provider = ProviderBuilder::new().on_http(cfg.chain_rpc.parse()?);
    let auth = AttestorAuthorization::new(cfg.agentic_id_addr, &provider);
    anyhow::ensure!(
        auth.instanceBoundAttestorsRequired().call().await?._0,
        "AgenticID requires the 1.2 instance-bound attestor migration"
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
            .map(|node| node.checked_at)
            .min()
            .unwrap(),
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tapp_grpc::proto::{ResolveAppIdentityResponse, ResolvedAppNodeIdentity};
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
