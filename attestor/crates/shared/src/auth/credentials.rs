//! Owner credential sets for sealed's credential proxy.
//!
//! The owner signs one EIP-712 `CredentialSet` per agent: the agent's seal,
//! the ownership epoch (block of the agent's last transfer, 0 if never
//! transferred), a version, and each entry's name with the keccak of its
//! definition bytes. Each definition names the keccak of its value's
//! ciphertext, sealed to the agent's agentSeal key (attestor cannot open it).
//! One signature therefore covers every entry and value.
//!
//! attestor keeps the document and hands it to the container at boot; it
//! checks what it can without the plaintext: the signer is the live owner,
//! the set is for this seal and this ownership, the version advances by one,
//! and every definition and value matches the hash the owner signed. The
//! container checks all of it again (sealed/internal/credentials).
//!
//! sealed writes back values it obtained itself (a rotated refresh token, a
//! login), signed by agentSeal over
//! `"CredentialWriteback.v1:<seal>:<name>:<set version>:<boot id>:<keccak(ct)>"`
//! with raw keccak256 and no EIP-191 prefix, like `/status`.
//!
//! The request formats mirror the settings channel (`auth::settings`): the
//! owner signs `"<tag>:0x<sealId>:<unix seconds>:<base version>[:<sha256 hex>]"`
//! with EIP-191, under the tags below.

use crate::crypto::recover_prehash_signer;
use crate::types::SealId;
use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::sol_types::{Eip712Domain, SolStruct};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::str::FromStr;

/// Tag of the owner's credential set reads and writes.
pub const CREDENTIALS_DOMAIN: &str = "AgenticID.Credentials.v1";
/// Tag of the owner's cross-agent pending count read.
pub const PENDING_DOMAIN: &str = "AgenticID.CredentialsPending.v1";
/// EIP-712 domain name and version.
pub const DOMAIN_NAME: &str = "AgentDNA Credentials";
pub const DOMAIN_VERSION: &str = "1";
/// Bound on a stored document: definitions plus sealed values.
pub const MAX_DOCUMENT_BYTES: usize = 256 * 1024;

alloy::sol! {
    struct Entry {
        string name;
        bytes32 defHash;
    }
    struct CredentialSet {
        bytes32 sealId;
        uint64 ownerEpoch;
        uint64 version;
        Entry[] entries;
    }
}

pub fn domain(chain_id: u64, contract: Address) -> Eip712Domain {
    Eip712Domain::new(
        Some(Cow::Borrowed(DOMAIN_NAME)),
        Some(Cow::Borrowed(DOMAIN_VERSION)),
        Some(U256::from(chain_id)),
        Some(contract),
        None,
    )
}

/// One line of the signed set, as JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SetEntry {
    pub name: String,
    pub def_hash: String,
}

/// The signed set, as JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SetWire {
    pub seal_id: String,
    pub owner_epoch: u64,
    pub version: u64,
    pub entries: Vec<SetEntry>,
}

/// A value sealed obtained and wrote back.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Writeback {
    pub ciphertext: String,
    pub set_version: u64,
    pub boot_id: String,
    pub signature: String,
}

/// The document an owner posts and the container receives.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub set: SetWire,
    pub signature: String,
    pub defs: BTreeMap<String, String>,
    pub values: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub writebacks: BTreeMap<String, Writeback>,
}

/// The fields of a definition attestor reads; the rest is the container's.
#[derive(Debug, Clone, Deserialize)]
pub struct DefinitionView {
    pub v: u32,
    pub name: String,
    #[serde(default)]
    pub value_hash: String,
    #[serde(default)]
    pub writeback: bool,
    #[serde(default)]
    pub mcp: Option<serde_json::Value>,
}

fn hash32(s: &str) -> anyhow::Result<B256> {
    let b = B256::from_str(s).map_err(|e| anyhow::anyhow!("want 32 bytes of hex: {e}"))?;
    Ok(b)
}

fn b64(s: &str) -> anyhow::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| anyhow::anyhow!("base64: {e}"))
}

fn signature_bytes(sig: &str) -> anyhow::Result<Vec<u8>> {
    let raw = hex::decode(sig.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("signature hex: {e}"))?;
    anyhow::ensure!(raw.len() == 65, "signature must be 65 bytes");
    Ok(raw)
}

impl SetWire {
    pub fn signing_hash(&self, chain_id: u64, contract: Address) -> anyhow::Result<B256> {
        let entries = self
            .entries
            .iter()
            .map(|e| {
                Ok(Entry {
                    name: e.name.clone(),
                    defHash: hash32(&e.def_hash)?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let set = CredentialSet {
            sealId: hash32(&self.seal_id)?,
            ownerEpoch: self.owner_epoch,
            version: self.version,
            entries,
        };
        Ok(set.eip712_signing_hash(&domain(chain_id, contract)))
    }
}

/// What a write must satisfy besides the owner's request signature.
pub struct Expect {
    pub seal_id: SealId,
    pub chain_id: u64,
    pub contract: Address,
    pub owner: Address,
    pub owner_epoch: u64,
    pub base_version: u64,
}

/// Check a document the owner posts. Returns the parsed definitions by name.
pub fn validate_document(
    doc: &Document,
    e: &Expect,
) -> anyhow::Result<BTreeMap<String, DefinitionView>> {
    anyhow::ensure!(
        hash32(&doc.set.seal_id)? == e.seal_id,
        "the credential set is for another agent"
    );
    anyhow::ensure!(
        doc.set.owner_epoch == e.owner_epoch,
        "the credential set was signed for ownership epoch {}, the agent is at {}",
        doc.set.owner_epoch,
        e.owner_epoch
    );
    anyhow::ensure!(
        doc.set.version == e.base_version + 1,
        "the credential set version must be {}",
        e.base_version + 1
    );
    let digest = doc.set.signing_hash(e.chain_id, e.contract)?;
    let signer = recover_prehash_signer(&digest.0, &signature_bytes(&doc.signature)?)?;
    anyhow::ensure!(
        signer == e.owner,
        "the credential set is not signed by the agent's owner"
    );
    anyhow::ensure!(
        doc.writebacks.is_empty(),
        "writebacks come from the container, not the owner"
    );

    let mut defs = BTreeMap::new();
    for entry in &doc.set.entries {
        anyhow::ensure!(
            !defs.contains_key(&entry.name),
            "credential {:?} listed twice",
            entry.name
        );
        let raw = b64(doc
            .defs
            .get(&entry.name)
            .ok_or_else(|| anyhow::anyhow!("definition of {:?} missing", entry.name))?)?;
        anyhow::ensure!(
            keccak256(&raw) == hash32(&entry.def_hash)?,
            "definition of {:?} does not match the signed hash",
            entry.name
        );
        let def: DefinitionView = serde_json::from_slice(&raw)
            .map_err(|e| anyhow::anyhow!("definition of {:?}: {e}", entry.name))?;
        anyhow::ensure!(
            def.v == 1 && def.name == entry.name,
            "definition of {:?} is not valid",
            entry.name
        );
        if def.value_hash.is_empty() {
            anyhow::ensure!(
                def.mcp.is_some(),
                "definition of {:?} has no value hash",
                entry.name
            );
        } else {
            let ct = b64(doc
                .values
                .get(&entry.name)
                .ok_or_else(|| anyhow::anyhow!("value of {:?} missing", entry.name))?)?;
            anyhow::ensure!(
                keccak256(&ct) == hash32(&def.value_hash)?,
                "value of {:?} does not match the signed hash",
                entry.name
            );
        }
        defs.insert(entry.name.clone(), def);
    }
    for name in doc.defs.keys().chain(doc.values.keys()) {
        anyhow::ensure!(defs.contains_key(name), "{name:?} is not in the signed set");
    }
    Ok(defs)
}

/// The exact message agentSeal signs for a writeback.
pub fn writeback_message(
    seal_id: SealId,
    name: &str,
    set_version: u64,
    boot_id: &str,
    ciphertext: &[u8],
) -> String {
    format!(
        "CredentialWriteback.v1:0x{}:{name}:{set_version}:{boot_id}:{}",
        hex::encode(seal_id.as_slice()),
        keccak256(ciphertext)
    )
}

/// Verify a writeback was signed by `agent_seal` for this seal, entry and boot.
pub fn verify_writeback(
    seal_id: SealId,
    name: &str,
    w: &Writeback,
    agent_seal: Address,
) -> anyhow::Result<()> {
    let ct = b64(&w.ciphertext)?;
    let msg = writeback_message(seal_id, name, w.set_version, &w.boot_id, &ct);
    let signer = recover_prehash_signer(
        &keccak256(msg.as_bytes()).0,
        &signature_bytes(&w.signature)?,
    )?;
    anyhow::ensure!(
        signer == agent_seal,
        "the writeback is not signed by the agent's seal"
    );
    Ok(())
}

/// The owner's request messages, settings grammar under `tag`.
pub fn owner_message(
    tag: &str,
    seal_id: SealId,
    timestamp: i64,
    base_version: i64,
    digest_hex: Option<&str>,
) -> String {
    let mut m = format!(
        "{tag}:0x{}:{timestamp}:{base_version}",
        hex::encode(seal_id.as_slice())
    );
    if let Some(d) = digest_hex {
        m.push(':');
        m.push_str(d);
    }
    m
}

/// A parsed owner request message.
pub struct OwnerMessage {
    pub seal_id: SealId,
    pub timestamp: i64,
    pub base_version: i64,
    pub digest_hex: Option<String>,
}

pub fn parse_owner_message(tag: &str, msg: &str) -> anyhow::Result<OwnerMessage> {
    let parts: Vec<&str> = msg.split(':').collect();
    anyhow::ensure!(
        matches!(parts.len(), 4 | 5) && parts[0] == tag,
        "X-Auth-Message must be \"{tag}:0x<sealId>:<unix seconds>:<base version>[:<sha256 hex>]\""
    );
    let seal_id = B256::from_str(parts[1]).map_err(|e| anyhow::anyhow!("bad sealId: {e}"))?;
    let timestamp: i64 = parts[2]
        .parse()
        .map_err(|e| anyhow::anyhow!("bad timestamp: {e}"))?;
    let base_version: i64 = parts[3]
        .parse()
        .map_err(|e| anyhow::anyhow!("bad base version: {e}"))?;
    anyhow::ensure!(base_version >= 0, "bad base version: must not be negative");
    let digest_hex = match parts.get(4) {
        Some(d) => {
            let d = d.to_ascii_lowercase();
            anyhow::ensure!(
                d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit()),
                "bad digest: expected 64 hex chars"
            );
            Some(d)
        }
        None => None,
    };
    Ok(OwnerMessage {
        seal_id,
        timestamp,
        base_version,
        digest_hex,
    })
}

/// `"<PENDING_DOMAIN>:<owner>:<unix seconds>"`, signed by the owner to read
/// the pending counts of every agent it owns.
pub fn pending_message(owner: Address, timestamp: i64) -> String {
    format!("{PENDING_DOMAIN}:{owner:#x}:{timestamp}")
}

pub fn parse_pending_message(msg: &str) -> anyhow::Result<(Address, i64)> {
    let parts: Vec<&str> = msg.split(':').collect();
    anyhow::ensure!(
        parts.len() == 3 && parts[0] == PENDING_DOMAIN,
        "X-Auth-Message must be \"{PENDING_DOMAIN}:<owner>:<unix seconds>\""
    );
    let owner = Address::from_str(parts[1]).map_err(|e| anyhow::anyhow!("bad owner: {e}"))?;
    let ts: i64 = parts[2]
        .parse()
        .map_err(|e| anyhow::anyhow!("bad timestamp: {e}"))?;
    Ok((owner, ts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;

    const SEAL: &str = "0x0fb3604de692a0a2ceae1d9e655d0dc28a8a81340534df4ba5c9a66a375f7c8f";

    fn contract() -> Address {
        Address::from_str("0x5BB5000000000000000000000000000000000001").unwrap()
    }

    /// Same vector as sealed's TestDigestVectors and the SDK; viem's
    /// hashTypedData agrees.
    #[test]
    fn digest_matches_the_cross_implementation_vector() {
        let set = SetWire {
            seal_id: SEAL.into(),
            owner_epoch: 7,
            version: 3,
            entries: vec![
                SetEntry {
                    name: "github".into(),
                    def_hash: format!("{}", keccak256(b"def-github")),
                },
                SetEntry {
                    name: "gcp".into(),
                    def_hash: format!("{}", keccak256(b"def-gcp")),
                },
            ],
        };
        assert_eq!(
            format!("{}", set.signing_hash(16602, contract()).unwrap()),
            "0xb176433ffedb59fd89cececf370cb5d8ba9ce6d526d51b4734fd4e278e6d1c76"
        );
    }

    fn b64e(b: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    fn signed_doc(owner: &PrivateKeySigner, version: u64, epoch: u64) -> Document {
        let ct = b"sealed-value-bytes".to_vec();
        let def = serde_json::json!({"v":1,"name":"github","hosts":["api.github.com"],"value_hash": format!("{}", keccak256(&ct))});
        let raw = serde_json::to_vec(&def).unwrap();
        let set = SetWire {
            seal_id: SEAL.into(),
            owner_epoch: epoch,
            version,
            entries: vec![SetEntry {
                name: "github".into(),
                def_hash: format!("{}", keccak256(&raw)),
            }],
        };
        let digest = set.signing_hash(16602, contract()).unwrap();
        let sig = owner.sign_hash_sync(&digest).unwrap();
        Document {
            set,
            signature: format!("0x{}", hex::encode(sig.as_bytes())),
            defs: [("github".to_string(), b64e(&raw))].into(),
            values: [("github".to_string(), b64e(&ct))].into(),
            writebacks: BTreeMap::new(),
        }
    }

    fn expect(owner: Address, base: u64, epoch: u64) -> Expect {
        Expect {
            seal_id: B256::from_str(SEAL).unwrap(),
            chain_id: 16602,
            contract: contract(),
            owner,
            owner_epoch: epoch,
            base_version: base,
        }
    }

    #[test]
    fn a_valid_document_passes() {
        let owner = PrivateKeySigner::random();
        let defs =
            validate_document(&signed_doc(&owner, 1, 0), &expect(owner.address(), 0, 0)).unwrap();
        assert!(defs.contains_key("github"));
    }

    #[test]
    fn refusals() {
        let owner = PrivateKeySigner::random();
        let doc = signed_doc(&owner, 1, 0);
        let other = PrivateKeySigner::random();
        assert!(
            validate_document(&doc, &expect(other.address(), 0, 0)).is_err(),
            "wrong owner"
        );
        assert!(
            validate_document(&doc, &expect(owner.address(), 1, 0)).is_err(),
            "version must advance by one"
        );
        assert!(
            validate_document(&doc, &expect(owner.address(), 0, 9)).is_err(),
            "epoch"
        );
        let mut tampered = doc.clone();
        tampered
            .values
            .insert("github".into(), b64e(b"another value"));
        assert!(
            validate_document(&tampered, &expect(owner.address(), 0, 0)).is_err(),
            "swapped value"
        );
        let mut extra = doc.clone();
        extra.values.insert("unsigned".into(), b64e(b"x"));
        assert!(
            validate_document(&extra, &expect(owner.address(), 0, 0)).is_err(),
            "unsigned extra value"
        );
    }

    #[test]
    fn writeback_needs_the_agent_seal() {
        let seal_key = PrivateKeySigner::random();
        let seal_id = B256::from_str(SEAL).unwrap();
        let ct = b"rotated".to_vec();
        let msg = writeback_message(seal_id, "gcp", 3, "0xboot", &ct);
        let sig = seal_key.sign_hash_sync(&keccak256(msg.as_bytes())).unwrap();
        let w = Writeback {
            ciphertext: b64e(&ct),
            set_version: 3,
            boot_id: "0xboot".into(),
            signature: format!("0x{}", hex::encode(sig.as_bytes())),
        };
        verify_writeback(seal_id, "gcp", &w, seal_key.address()).unwrap();
        assert!(
            verify_writeback(seal_id, "gcp", &w, PrivateKeySigner::random().address()).is_err()
        );
        assert!(verify_writeback(seal_id, "other", &w, seal_key.address()).is_err());
    }

    #[test]
    fn owner_messages_round_trip() {
        let seal_id = B256::from_str(SEAL).unwrap();
        let m = owner_message(
            CREDENTIALS_DOMAIN,
            seal_id,
            1_700_000_000,
            2,
            Some(&"ab".repeat(32)),
        );
        let p = parse_owner_message(CREDENTIALS_DOMAIN, &m).unwrap();
        assert_eq!(
            (p.seal_id, p.timestamp, p.base_version),
            (seal_id, 1_700_000_000, 2)
        );
        assert!(parse_owner_message("AgenticID.Settings.v1", &m).is_err());
        let owner = PrivateKeySigner::random().address();
        assert_eq!(
            parse_pending_message(&pending_message(owner, 5)).unwrap(),
            (owner, 5)
        );
    }
}
