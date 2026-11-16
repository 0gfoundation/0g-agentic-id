//! Owner-signed, agent-scoped runtime delegation. The operator controls and
//! funds its own sandbox; NFT ownership and container key proofs are unchanged.

use super::{verify_eip191_envelope, Canonical};
use crate::{
    sandbox::verify_envelope, ChainClient, CryptoModule, Deployment, DeploymentRepo,
    SandboxEnvelope, SealId,
};
use alloy::primitives::{Address, Bytes};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorDirective {
    pub domain: String,
    pub chain_id: u64,
    pub contract: Address,
    pub seal_id: SealId,
    pub owner: Address,
    pub base_version: i64,
    pub operator: Option<Address>,
    pub allow_recreate: bool,
    pub expires_at: i64,
    pub issued_at: i64,
}

impl Canonical for OperatorDirective {
    const DOMAIN: &'static str = "AgenticID.Operator.v1";
    fn domain(&self) -> &str {
        &self.domain
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorGrant {
    pub version: i64,
    pub owner: Address,
    pub signed_message_b64: String,
    pub signature: Bytes,
}

#[derive(Clone, Debug)]
pub struct OperatorUpdate {
    pub version: i64,
    pub retired_sandbox_id: Option<String>,
}

/// Included at the top level of an operator-signed sandbox envelope. The
/// provider authenticates the original bytes and ignores this extra field.
/// Binding the revision here also protects queued work against revoke/regrant.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBinding {
    pub chain_id: u64,
    pub contract: Address,
    pub seal_id: SealId,
    pub operator_version: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecyclePermission {
    Resume,
    Stop,
    Provision,
    Recreate,
}

/// Compute delegation does not confer image, process or owner-configuration
/// control. The attestor injects all runtime wiring after validating this
/// small request surface; SDK inference credentials are the only allowed env.
pub fn validate_operator_payload(payload: &serde_json::Value) -> anyhow::Result<()> {
    let object = payload
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("operator create payload must be an object"))?;
    anyhow::ensure!(
        object
            .keys()
            .all(|key| matches!(key.as_str(), "snapshot" | "sealed" | "env")),
        "operator create only accepts snapshot, sealed and inference credentials"
    );
    anyhow::ensure!(
        object.get("sealed").and_then(|v| v.as_bool()) == Some(true),
        "operator provisioning requires a sealed sandbox"
    );
    if let Some(env) = object.get("env") {
        let env = env
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("operator env must be an object"))?;
        anyhow::ensure!(
            env.iter().all(
                |(key, value)| matches!(key.as_str(), "API_KEY" | "SEAL_SECRET_ENV")
                    && value.is_string()
            ),
            "operator env only accepts inference credentials"
        );
        anyhow::ensure!(
            !(env.contains_key("API_KEY") && env.contains_key("SEAL_SECRET_ENV")),
            "pass one inference credential format"
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct RuntimePrincipal {
    pub owner: Address,
    pub actor: Address,
    pub operator_version: Option<i64>,
}

pub fn verify_operator_directive(
    signed_b64: &str,
    signature: &[u8],
    owner: Address,
    chain_id: u64,
    contract: Address,
    seal_id: SealId,
    crypto: &dyn CryptoModule,
) -> anyhow::Result<OperatorDirective> {
    let d: OperatorDirective = verify_eip191_envelope(signed_b64, signature, owner, crypto)?;
    anyhow::ensure!(d.owner == owner, "operator directive owner mismatch");
    anyhow::ensure!(
        d.chain_id == chain_id && d.contract == contract && d.seal_id == seal_id,
        "operator directive belongs to a different chain, contract or agent"
    );
    anyhow::ensure!(
        d.base_version >= 0 && d.base_version < i64::MAX,
        "invalid operator base version"
    );
    anyhow::ensure!(
        d.expires_at >= 0 && d.issued_at > 0,
        "invalid operator timestamps"
    );
    anyhow::ensure!(
        d.operator != Some(Address::ZERO),
        "operator cannot be the zero address"
    );
    if d.operator.is_none() {
        anyhow::ensure!(
            !d.allow_recreate && d.expires_at == 0,
            "revocation cannot carry operator permissions"
        );
    }
    Ok(d)
}

pub async fn live_owner(chain: &dyn ChainClient, d: &Deployment) -> anyhow::Result<Address> {
    match d.agent_id {
        Some(agent) => chain.owner_of(agent).await,
        None => Ok(d.owner),
    }
}

/// Re-verify the owner's original signature rather than trusting editable DB
/// columns. A transfer/revocation version bump invalidates the stored proof.
pub fn verify_operator_grant(
    grant: &OperatorGrant,
    owner: Address,
    chain_id: u64,
    contract: Address,
    seal_id: SealId,
    crypto: &dyn CryptoModule,
) -> anyhow::Result<OperatorDirective> {
    anyhow::ensure!(
        grant.owner == owner,
        "operator grant belongs to a previous owner"
    );
    let d = verify_operator_directive(
        &grant.signed_message_b64,
        grant.signature.as_ref(),
        owner,
        chain_id,
        contract,
        seal_id,
        crypto,
    )?;
    anyhow::ensure!(
        grant.version == d.base_version + 1,
        "operator grant version no longer valid"
    );
    anyhow::ensure!(d.operator.is_some(), "operator authorization was revoked");
    anyhow::ensure!(
        d.expires_at == 0 || d.expires_at > chrono::Utc::now().timestamp(),
        "operator authorization expired"
    );
    Ok(d)
}

pub async fn authorize_runtime(
    chain: &dyn ChainClient,
    crypto: &dyn CryptoModule,
    repo: &dyn DeploymentRepo,
    chain_id: u64,
    contract: Address,
    d: &Deployment,
    envelope: &SandboxEnvelope,
    permission: LifecyclePermission,
) -> anyhow::Result<RuntimePrincipal> {
    let message = verify_envelope(envelope, crypto)?;
    let owner = live_owner(chain, d).await?;
    let actor = envelope.wallet_address;
    let expected_action = match permission {
        LifecyclePermission::Resume => "start",
        LifecyclePermission::Stop => "stop",
        LifecyclePermission::Provision | LifecyclePermission::Recreate => "create",
    };
    anyhow::ensure!(
        message.action == expected_action,
        "runtime envelope action mismatch"
    );
    let mut principal = RuntimePrincipal {
        owner,
        actor,
        operator_version: None,
    };

    if actor != owner {
        anyhow::ensure!(
            d.agent_id.is_some(),
            "operator cannot authorize an unminted agent"
        );
        let grant = repo.operator_grant(d.seal_id).await?.ok_or_else(|| {
            anyhow::anyhow!("signer is neither current owner nor an authorized operator")
        })?;
        let directive =
            verify_operator_grant(&grant, owner, chain_id, contract, d.seal_id, crypto)?;
        anyhow::ensure!(
            directive.operator == Some(actor),
            "signer is not the authorized operator"
        );
        if permission == LifecyclePermission::Recreate {
            anyhow::ensure!(
                directive.allow_recreate,
                "operator is not authorized to recreate the sandbox"
            );
        }
        if permission == LifecyclePermission::Provision {
            anyhow::ensure!(
                d.sandbox_id.as_deref().unwrap_or("").is_empty(),
                "existing sandbox requires recreate permission"
            );
        }
        let binding = message.agentic_id.as_ref().ok_or_else(|| {
            anyhow::anyhow!("operator envelope must bind the agent and grant version")
        })?;
        anyhow::ensure!(
            binding.chain_id == chain_id
                && binding.contract == contract
                && binding.seal_id == d.seal_id
                && binding.operator_version == grant.version,
            "operator envelope agent or authorization version mismatch"
        );
        let now = chrono::Utc::now().timestamp();
        anyhow::ensure!(
            message.expires_at > now && message.expires_at <= now + 300,
            "operator envelope expired or validity exceeds five minutes"
        );
        let provider = message.provider.as_deref().unwrap_or("");
        anyhow::ensure!(
            provider
                .parse::<Address>()
                .is_ok_and(|a| a != Address::ZERO),
            "operator envelope must bind a provider"
        );
        anyhow::ensure!(
            !message.nonce.is_empty(),
            "operator envelope nonce is required"
        );
        principal.operator_version = Some(grant.version);
    }

    match permission {
        LifecyclePermission::Resume | LifecyclePermission::Stop => {
            // Existing owner envelopes with an empty resource remain compatible
            // at the API edge; the provider remains the authoritative verifier.
            if actor != owner || !message.resource_id.is_empty() {
                anyhow::ensure!(
                    d.sandbox_id.as_deref() == Some(message.resource_id.as_str())
                        && !message.resource_id.is_empty(),
                    "runtime envelope addresses a different sandbox"
                );
            }
            if let Some(boot) = repo.boot_authorization(d.seal_id).await? {
                anyhow::ensure!(
                    boot.owner == Some(owner),
                    "sandbox belongs to a previous agent owner"
                );
                anyhow::ensure!(boot.operator.unwrap_or(owner) == actor,
                    "sandbox is controlled and funded by another wallet; recreate with the intended operator");
            } else if actor != owner {
                anyhow::bail!("legacy sandbox must be recreated by its operator before delegated lifecycle calls");
            }
        }
        LifecyclePermission::Provision | LifecyclePermission::Recreate => {
            anyhow::ensure!(
                message.resource_id.is_empty(),
                "create envelope resource_id must be empty"
            );
            if actor != owner {
                validate_operator_payload(&message.payload)?;
            }
        }
    }
    Ok(principal)
}

/// Every key-delivery and authenticated status path checks the operator
/// revision as well as NFT ownership. Old containers cannot renew a receipt
/// after their delegation expires or is revoked.
pub async fn validate_boot_operator(
    chain: &dyn ChainClient,
    crypto: &dyn CryptoModule,
    repo: &dyn DeploymentRepo,
    chain_id: u64,
    contract: Address,
    d: &Deployment,
    boot: &super::status::BootAuthorization,
) -> anyhow::Result<()> {
    let owner = live_owner(chain, d).await?;
    anyhow::ensure!(
        boot.enabled && boot.owner == Some(owner),
        "boot belongs to a previous owner or was revoked"
    );
    if let Some(actor) = boot.operator {
        let grant = repo
            .operator_grant(d.seal_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("boot operator authorization is missing"))?;
        let directive =
            verify_operator_grant(&grant, owner, chain_id, contract, d.seal_id, crypto)?;
        anyhow::ensure!(
            directive.operator == Some(actor) && boot.operator_version == Some(grant.version),
            "boot operator authorization changed"
        );
    } else {
        anyhow::ensure!(
            boot.operator_version.is_none(),
            "inconsistent boot operator binding"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn operator_payload_cannot_override_runtime_or_owner_configuration() {
        let valid = json!({"snapshot":"sealed", "sealed":true,
            "env":{"SEAL_SECRET_ENV":"encrypted-inference-credential"}});
        validate_operator_payload(&valid).unwrap();
        for (field, value) in [
            ("entrypoint", json!("/bin/sh")),
            ("publicPorts", json!([8080, 3000])),
            ("volumes", json!([])),
            ("image", json!("another-image")),
            ("user", json!("root")),
        ] {
            let mut request = valid.clone();
            request[field] = value;
            assert!(
                validate_operator_payload(&request).is_err(),
                "accepted {field}"
            );
        }
        for name in [
            "NODE_OPTIONS",
            "LD_PRELOAD",
            "SEAL_OWNER_THINKING",
            "ATTESTOR_URL",
            "SEAL_BOOT_TICKET",
        ] {
            let mut request = valid.clone();
            request["env"][name] = json!("override");
            assert!(
                validate_operator_payload(&request).is_err(),
                "accepted {name}"
            );
        }
    }
}
