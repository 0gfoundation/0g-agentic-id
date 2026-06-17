//! AgentCard JSON assembly — the off-chain document that `tokenURI`
//! ultimately points at.
//!
//! Conforms simultaneously to ERC-721 Metadata JSON Schema (for NFT
//! marketplaces) and ERC-8004 / Google A2A AgentCard shape (for agent
//! discovery). No public `skills` field — skills live in the encrypted
//! iData. No framework.version at the card level either — version refers
//! to the *AgentCard schema* version, not the runtime framework.

use crate::agent_profile::AgentProfile;
use crate::avatar;
use crate::types::AgentId;
use alloy::primitives::Address;
use serde_json::{json, Value};

pub const AGENT_CARD_SCHEMA_VERSION: &str = "1.0.0";

/// All inputs `build_agent_card` needs. Grouped in a struct so callers
/// (worker post-mint, potentially api dry-run) don't drift on argument
/// order as the field set grows.
pub struct AgentCardInputs<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub image: Option<&'a str>,
    pub profile: &'a dyn AgentProfile,

    // Chain identity
    pub agent_id: AgentId,
    pub agent_seal_addr: Address,
    pub chain_id: u64,
    /// Seeds the deterministic pixel-art avatar when `image` is None.
    pub seal_id: &'a [u8; 32],

    // Sandbox endpoint — feeds AgentCard.url
    pub sandbox_id: &'a str,
    /// "host:port" SocketAddr-shaped string — split at `:` to fill nip.io
    /// subdomain + URL port independently.
    pub sandbox_proxy_addr: &'a str,
    /// Public service entry the agent exposes — what gets published on
    /// chain via `tokenURI`.
    pub agent_serve_port: u16,
    pub agent_serve_path: &'a str,
}

pub fn build_agent_card(i: AgentCardInputs<'_>) -> Value {
    let image = i
        .image
        .map(str::to_string)
        .unwrap_or_else(|| avatar::seed_to_data_url(i.seal_id));

    // ── attributes: universal species tag + profile-specific additions ──
    let mut attributes: Vec<Value> = vec![json!({
        "trait_type": "species",
        "value":      "agent",
    })];
    attributes.extend(i.profile.extra_attributes());

    // ── url: http://{cp}-{sid}.{host}.nip.io:{port}{path} ───────────────
    let url = build_agent_url(
        i.sandbox_proxy_addr,
        i.sandbox_id,
        i.agent_serve_port,
        i.agent_serve_path,
    );

    // ── registrations: [{ agentId, chainId, agentAddress }] ─────────────
    // alloy `Address` Display renders the EIP-55 checksummed "0x..." form.
    let registrations = json!([{
        "agentId":      i.agent_id.to_string(),
        "chainId":      i.chain_id,
        "agentAddress": i.agent_seal_addr.to_string(),
    }]);

    json!({
        // ── ERC-721 Metadata JSON Schema ──
        "name":        i.name,
        "description": i.description,
        "image":       image,
        "attributes":  attributes,

        // ── ERC-8004 / A2A AgentCard ──
        "url":           url,
        "version":       AGENT_CARD_SCHEMA_VERSION,
        "capabilities":  i.profile.default_capabilities(),
        "registrations": registrations,
        "trustModels":   json!(["tee-attestation"]),
    })
}

/// Construct the subdomain-routed proxy URL: `{port}-{sandbox_id}` is
/// prepended as a subdomain to whatever host the proxy is advertised under.
/// We do NOT hard-code a wildcard-DNS suffix — the caller supplies the full
/// base host via `sandbox_proxy_addr`. The scheme is inferred from whether a
/// port is present:
///   - `host:port` → `http://{port}-{sid}.{host}:{port}{path}`
///     (dev / IP behind a plain-HTTP proxy, e.g. `47.236.111.154.nip.io:4000`)
///   - bare `host` → `https://{port}-{sid}.{host}{path}`
///     (a real domain fronted by TLS on 443, e.g. `art.0g.ai`)
///
/// The bare-host → https rule keeps the on-chain AgentCard.url canonical:
/// without it a TLS domain would be written as `http://…:80` and only "work"
/// via an HTTP→HTTPS redirect, leaving the wrong scheme on chain.
pub fn build_agent_url(
    sandbox_proxy_addr: &str,
    sandbox_id: &str,
    container_port: u16,
    path: &str,
) -> String {
    match sandbox_proxy_addr.rsplit_once(':') {
        Some((host, port)) => {
            format!("http://{container_port}-{sandbox_id}.{host}:{port}{path}")
        }
        None => format!("https://{container_port}-{sandbox_id}.{sandbox_proxy_addr}{path}"),
    }
}

/// The sealed proxy's `/healthz` URL for a sandbox — same subdomain routing
/// as the agent's serve URL. Used by the worker's reconcile sweep to confirm
/// a stale-heartbeat agent is genuinely down before reaping its sandbox.
pub fn build_healthz_url(
    sandbox_proxy_addr: &str,
    sandbox_id: &str,
    agent_serve_port: u16,
) -> String {
    build_agent_url(sandbox_proxy_addr, sandbox_id, agent_serve_port, "/healthz")
}

/// GET `healthz_url` with a short timeout. Returns true ONLY on a 2xx
/// response; any failure (connection refused, timeout, non-2xx) → false.
/// Callers pair this with a stale heartbeat: only when BOTH the agent has
/// gone silent past the sweep window AND `/healthz` is unreachable is it
/// treated as dead — two independent signals guard against false positives
/// (e.g. a healthy agent whose outbound heartbeat path is briefly broken).
pub async fn agent_is_healthy(healthz_url: &str) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    matches!(client.get(healthz_url).send().await, Ok(r) if r.status().is_success())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_profile::OpenClawProfile;
    use alloy::primitives::U256;

    #[test]
    fn url_template_substitutes_all_parts() {
        // Caller supplies the full base host (including wildcard-DNS
        // suffix if any). Here: nip.io form of an IP + port 4000.
        let url = build_agent_url(
            "47.236.111.154.nip.io:4000",
            "8aba43ad-d34f-4a5f-8937-316c2a2bdc23",
            8080,
            "/hello",
        );
        assert_eq!(
            url,
            "http://8080-8aba43ad-d34f-4a5f-8937-316c2a2bdc23.47.236.111.154.nip.io:4000/hello"
        );
    }

    #[test]
    fn url_template_accepts_real_domain() {
        let url = build_agent_url("proxy.example.com:4000", "sb-1", 8080, "/result");
        assert_eq!(url, "http://8080-sb-1.proxy.example.com:4000/result");
    }

    #[test]
    fn url_template_bare_host_is_https() {
        // A bare host (no port) is a real domain fronted by TLS → https on
        // 443, no explicit port. Keeps the on-chain URL canonical instead of
        // an http://…:80 that only works via a redirect.
        let url = build_agent_url("art.0g.ai", "sb", 8080, "/hello");
        assert_eq!(url, "https://8080-sb.art.0g.ai/hello");
    }

    #[test]
    fn agent_card_carries_both_erc721_and_8004_fields() {
        let profile = OpenClawProfile;
        let seal_addr = Address::from_slice(&[0x42u8; 20]);
        let seed = [7u8; 32];
        let inputs = AgentCardInputs {
            name: "Sage",
            description: "DeFi helper",
            image: None,
            profile: &profile,
            agent_id: U256::from(7u64),
            agent_seal_addr: seal_addr,
            chain_id: 16602,
            seal_id: &seed,
            sandbox_id: "sb-123",
            sandbox_proxy_addr: "47.236.111.154.nip.io:4000",
            agent_serve_port: 8080,
            agent_serve_path: "/hello",
        };
        let card = build_agent_card(inputs);

        // ERC-721 fields
        assert_eq!(card["name"], "Sage");
        assert_eq!(card["description"], "DeFi helper");
        let img = card["image"].as_str().unwrap();
        assert!(
            img.starts_with("data:image/svg+xml;base64,"),
            "image falls back to deterministic avatar: {img}"
        );
        assert_eq!(card["attributes"][0]["trait_type"], "species");
        assert_eq!(card["attributes"][0]["value"], "agent");

        // ERC-8004 fields
        assert_eq!(
            card["url"],
            "http://8080-sb-123.47.236.111.154.nip.io:4000/hello"
        );
        assert_eq!(card["version"], AGENT_CARD_SCHEMA_VERSION);
        assert_eq!(card["capabilities"]["streaming"], true);
        assert_eq!(card["registrations"][0]["agentId"], "7");
        assert_eq!(card["registrations"][0]["chainId"], 16602);
        assert!(card["registrations"][0]["agentAddress"]
            .as_str()
            .unwrap()
            .starts_with("0x"));
        assert_eq!(card["trustModels"][0], "tee-attestation");

        // No public skills
        assert!(card.get("skills").is_none());
    }

    #[test]
    fn user_image_overrides_profile_default() {
        let profile = OpenClawProfile;
        let seed = [0u8; 32];
        let inputs = AgentCardInputs {
            name: "A",
            description: "B",
            image: Some("https://my.custom.logo/png"),
            profile: &profile,
            agent_id: U256::from(1u64),
            agent_seal_addr: Address::ZERO,
            chain_id: 1,
            seal_id: &seed,
            sandbox_id: "x",
            sandbox_proxy_addr: "h:1",
            agent_serve_port: 1,
            agent_serve_path: "/",
        };
        let card = build_agent_card(inputs);
        assert_eq!(card["image"], "https://my.custom.logo/png");
    }
}
