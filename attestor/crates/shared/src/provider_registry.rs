//! Global inference configuration authorized by the live attestor Tapp owner.
//! Accepted revisions keep their exact signed bytes, publisher and immutable
//! history; compare-and-swap prevents replay and concurrent overwrites.
use alloy::primitives::Address;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::{
    collections::{BTreeMap, HashSet},
    sync::{Arc, Mutex},
};

pub const DOMAIN: &str = "AgentDNA.ProviderRegistry.v1";
pub const MAX_DOCUMENT_BYTES: usize = 256 * 1024;
pub const BUILTIN: &str = include_str!("../../../../sealed/internal/inference/providers.json");

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub native: bool,
    pub formats: Vec<String>,
    #[serde(
        rename = "defaultFormat",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub default_format: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub endpoints: BTreeMap<String, String>,
    #[serde(
        rename = "modelCatalog",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub model_catalog: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub compatibility: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub schema: u8,
    pub chain_id: u64,
    pub agentic_id_addr: Address,
    pub tapp_registry_addr: Address,
    pub attestor_app_id: String,
    pub base_version: i64,
    pub expires_at: i64,
    pub providers: Vec<Provider>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedUpdate {
    /// Exact UTF-8 JSON bytes covered by the signature. Never re-serialize.
    pub document: String,
    pub signature: String,
}

#[derive(Clone, Debug)]
pub struct StoredRegistry {
    pub version: i64,
    pub update: SignedUpdate,
    pub publisher: Address,
}

pub fn signing_message(document: &str) -> String {
    format!(
        "{DOMAIN}:{}",
        hex::encode(Sha256::digest(document.as_bytes()))
    )
}

/// Public fingerprint of the exact accepted envelope, consumed with the
/// trusted /config version. Independent of later owner/wallet-policy changes.
pub fn accepted_digest(update: &SignedUpdate) -> String {
    let bytes = format!(
        "AgentDNA.ProviderRegistryAccepted.v1:{}:{}",
        hex::encode(Sha256::digest(update.document.as_bytes())),
        update.signature
    );
    format!("0x{}", hex::encode(Sha256::digest(bytes.as_bytes())))
}

pub fn valid_provider_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

fn https_url(raw: &str) -> bool {
    if raw.bytes().any(|c| c.is_ascii_control()) {
        return false;
    }
    reqwest::Url::parse(raw).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

pub fn validate_providers(providers: &[Provider]) -> anyhow::Result<()> {
    anyhow::ensure!(
        !providers.is_empty() && providers.len() <= 128,
        "registry requires 1..128 providers"
    );
    let mut ids = HashSet::new();
    for provider in providers {
        anyhow::ensure!(
            valid_provider_id(&provider.id) && !provider.name.trim().is_empty(),
            "invalid provider id/name"
        );
        anyhow::ensure!(ids.insert(&provider.id), "duplicate provider id");
        anyhow::ensure!(
            !provider.formats.is_empty() && provider.formats.len() <= 2,
            "invalid provider formats"
        );
        let formats: HashSet<_> = provider.formats.iter().collect();
        anyhow::ensure!(
            formats.len() == provider.formats.len()
                && provider
                    .formats
                    .iter()
                    .all(|f| matches!(f.as_str(), "openai" | "anthropic")),
            "unsupported/duplicate protocol"
        );
        if provider.native {
            anyhow::ensure!(
                matches!(provider.id.as_str(), "openai" | "anthropic")
                    && provider.formats == vec![provider.id.clone()]
                    && provider.endpoints.is_empty()
                    && provider.model_catalog.is_none()
                    && provider.default_format.is_none(),
                "native provider must use known framework wiring"
            );
        } else {
            anyhow::ensure!(
                provider
                    .default_format
                    .as_ref()
                    .is_some_and(|f| formats.contains(f)),
                "missing defaultFormat"
            );
            anyhow::ensure!(
                provider.endpoints.len() == formats.len()
                    && provider
                        .formats
                        .iter()
                        .all(|f| provider.endpoints.get(f).is_some_and(|u| https_url(u))),
                "managed provider requires fixed HTTPS endpoints"
            );
        }
        anyhow::ensure!(
            provider.model_catalog.as_ref().is_none_or(|u| https_url(u)),
            "modelCatalog must be a public HTTPS URL"
        );
        for model in &provider.models {
            anyhow::ensure!(
                model.is_object()
                    && model
                        .get("id")
                        .and_then(Value::as_str)
                        .is_some_and(|id| !id.is_empty()),
                "model requires id"
            );
            for key in ["supported_parameters", "supported_formats"] {
                anyhow::ensure!(
                    model.get(key).is_none_or(|v| v
                        .as_array()
                        .is_some_and(|items| items.iter().all(Value::is_string))),
                    "invalid model capabilities"
                );
            }
            for key in ["context_length", "max_completion_tokens"] {
                anyhow::ensure!(
                    model
                        .get(key)
                        .is_none_or(|v| v.as_u64().is_some_and(|n| n <= i32::MAX as u64)),
                    "invalid model limits"
                );
            }
        }
        anyhow::ensure!(
            provider
                .compatibility
                .values()
                .all(|v| v.is_boolean() || v.is_string()),
            "compatibility values must be booleans/strings"
        );
    }
    // Preserve the long-standing compute route for old clients and migration.
    anyhow::ensure!(
        ids.contains(&"0g-compute".to_string()),
        "registry must retain 0g-compute"
    );
    Ok(())
}

pub fn parse_document(raw: &str) -> anyhow::Result<Document> {
    anyhow::ensure!(
        raw.len() <= MAX_DOCUMENT_BYTES,
        "provider document too large"
    );
    let doc: Document = serde_json::from_str(raw)?;
    anyhow::ensure!(
        doc.schema == 1 && doc.base_version >= 0 && doc.base_version < i64::MAX,
        "invalid registry schema/version"
    );
    validate_providers(&doc.providers)?;
    Ok(doc)
}

#[async_trait]
pub trait ProviderRegistryRepo: Send + Sync {
    async fn latest(&self) -> anyhow::Result<Option<StoredRegistry>>;
    async fn get(&self, version: i64) -> anyhow::Result<Option<StoredRegistry>>;
    async fn replace(
        &self,
        base: i64,
        update: SignedUpdate,
        publisher: Address,
    ) -> anyhow::Result<Option<i64>>;
}

pub struct PostgresProviderRegistry {
    pool: PgPool,
    chain_id: i64,
    contract: Address,
}
impl PostgresProviderRegistry {
    pub fn new(pool: PgPool, chain_id: u64, contract: Address) -> Arc<Self> {
        Arc::new(Self {
            pool,
            chain_id: chain_id as i64,
            contract,
        })
    }
}
#[async_trait]
impl ProviderRegistryRepo for PostgresProviderRegistry {
    async fn latest(&self) -> anyhow::Result<Option<StoredRegistry>> {
        let row = sqlx::query("SELECT version, document, signature, publisher FROM inference_provider_registry WHERE chain_id=$1 AND contract=$2 ORDER BY version DESC LIMIT 1")
            .bind(self.chain_id).bind(self.contract.as_slice()).fetch_optional(&self.pool).await?;
        row.map(|row| {
            let publisher: Vec<u8> = row.try_get("publisher")?;
            anyhow::ensure!(publisher.len() == 20, "invalid stored registry publisher");
            Ok(StoredRegistry {
                version: row.try_get("version")?,
                publisher: Address::from_slice(&publisher),
                update: SignedUpdate {
                    document: row.try_get("document")?,
                    signature: row.try_get("signature")?,
                },
            })
        })
        .transpose()
    }
    async fn get(&self, version: i64) -> anyhow::Result<Option<StoredRegistry>> {
        let row = sqlx::query("SELECT version, document, signature, publisher FROM inference_provider_registry WHERE chain_id=$1 AND contract=$2 AND version=$3")
            .bind(self.chain_id).bind(self.contract.as_slice()).bind(version).fetch_optional(&self.pool).await?;
        row.map(|row| {
            let publisher: Vec<u8> = row.try_get("publisher")?;
            anyhow::ensure!(publisher.len() == 20, "invalid stored registry publisher");
            Ok(StoredRegistry {
                version: row.try_get("version")?,
                publisher: Address::from_slice(&publisher),
                update: SignedUpdate {
                    document: row.try_get("document")?,
                    signature: row.try_get("signature")?,
                },
            })
        })
        .transpose()
    }
    async fn replace(
        &self,
        base: i64,
        update: SignedUpdate,
        publisher: Address,
    ) -> anyhow::Result<Option<i64>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(4703801312244819058)")
            .execute(&mut *tx)
            .await?;
        let version: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(version),0) FROM inference_provider_registry WHERE chain_id=$1 AND contract=$2")
            .bind(self.chain_id).bind(self.contract.as_slice()).fetch_one(&mut *tx).await?;
        if version != base {
            return Ok(None);
        }
        let next = base
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("registry version exhausted"))?;
        sqlx::query("INSERT INTO inference_provider_registry(chain_id,contract,version,document,signature,publisher) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(self.chain_id).bind(self.contract.as_slice()).bind(next).bind(update.document).bind(update.signature).bind(publisher.as_slice()).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(Some(next))
    }
}

#[derive(Default)]
pub struct MemoryProviderRegistry(Mutex<Vec<StoredRegistry>>);
#[async_trait]
impl ProviderRegistryRepo for MemoryProviderRegistry {
    async fn latest(&self) -> anyhow::Result<Option<StoredRegistry>> {
        Ok(self.0.lock().unwrap().last().cloned())
    }
    async fn get(&self, version: i64) -> anyhow::Result<Option<StoredRegistry>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.version == version)
            .cloned())
    }
    async fn replace(
        &self,
        base: i64,
        update: SignedUpdate,
        publisher: Address,
    ) -> anyhow::Result<Option<i64>> {
        let mut history = self.0.lock().unwrap();
        if history.last().map_or(0, |r| r.version) != base {
            return Ok(None);
        }
        let version = base
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("registry version exhausted"))?;
        history.push(StoredRegistry {
            version,
            update,
            publisher,
        });
        Ok(Some(version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires an isolated AGENTDNA_TEST_DATABASE_URL"]
    async fn postgres_registry_survives_reconnect_and_serializes_publishers() {
        let url = std::env::var("AGENTDNA_TEST_DATABASE_URL").expect("isolated test DB URL");
        let mut connection = None;
        for _ in 0..25 {
            match crate::repo::connect(&url).await {
                Ok(pool) => {
                    connection = Some(pool);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(200)).await,
            }
        }
        let pool = connection.expect("test Postgres ready");
        let contract = Address::from_slice(&rand::random::<[u8; 20]>());
        let first = PostgresProviderRegistry::new(pool.clone(), 16602, contract);
        assert!(first.latest().await.unwrap().is_none());
        let update = |value: &str| SignedUpdate {
            document: value.into(),
            signature: "operator-signature".into(),
        };
        assert_eq!(
            first
                .replace(0, update("first accepted bytes"), Address::ZERO)
                .await
                .unwrap(),
            Some(1)
        );
        // Another pool/API process sees exactly the same accepted bytes.
        let other_pool = crate::repo::connect(&url).await.unwrap();
        let second = PostgresProviderRegistry::new(other_pool, 16602, contract);
        let loaded = second.latest().await.unwrap().unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.update.document, "first accepted bytes");
        let (a, b) = tokio::join!(
            first.replace(1, update("publisher A"), Address::ZERO),
            second.replace(1, update("publisher B"), Address::ZERO)
        );
        assert_eq!(
            usize::from(a.unwrap().is_some()) + usize::from(b.unwrap().is_some()),
            1
        );
        assert_eq!(first.latest().await.unwrap().unwrap().version, 2);
        assert_eq!(
            second.get(1).await.unwrap().unwrap().update.document,
            "first accepted bytes"
        );
        assert!(second.get(99).await.unwrap().is_none());
        assert!(first
            .replace(0, update("replay"), Address::ZERO)
            .await
            .unwrap()
            .is_none());
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM inference_provider_registry WHERE chain_id=$1 AND contract=$2",
        )
        .bind(16602_i64)
        .bind(contract.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 2, "immutable publication history is retained");
    }
}
