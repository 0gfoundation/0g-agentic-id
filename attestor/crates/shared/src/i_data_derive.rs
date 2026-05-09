//! Post-intake normalization of user-supplied `i_data` entries.
//!
//! v0 attestor always synthesizes the registry-fallback profile's
//! defaults — user-supplied `i_data` entries are dropped (with a warn).
//! Pluggable per-deployment profiles + per-dim user merging is a future
//! concern: when it comes, the merge logic lives here.

use crate::agent_profile::ProfileRegistry;
use crate::types::IDataInput;

/// Normalize the user's raw i_data into a worker-safe form.
///
/// v0: ignore user input (warn if non-empty), return the fallback
/// profile's `default_i_data`. Pure function — no I/O, trivially testable.
pub fn normalize_i_data(
    raw: Vec<IDataInput>,
    name: &str,
    description: &str,
    registry: &ProfileRegistry,
) -> Vec<IDataInput> {
    if !raw.is_empty() {
        tracing::warn!(
            received = raw.len(),
            "v0 ignores user-supplied i_data; using profile defaults"
        );
    }
    registry.fallback().default_i_data(name, description)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_profile::OpenClawProfile;
    use std::sync::Arc;

    fn registry() -> ProfileRegistry {
        ProfileRegistry::new(Arc::new(OpenClawProfile))
    }

    #[test]
    fn empty_raw_produces_profile_defaults() {
        let out = normalize_i_data(Vec::new(), "Sage", "helper", &registry());
        let roles: Vec<&str> = out.iter().map(|e| e.role.as_str()).collect();
        assert_eq!(roles, vec!["framework", "persona"]);
    }

    #[test]
    fn non_empty_raw_is_ignored_and_defaults_returned() {
        // v0 spec: any user-supplied i_data is dropped (with a warn).
        // Output must STILL be the canonical default layout — not
        // defaults+raw.len(), not raw.len() — so downstream stages
        // don't have to defend against partial payloads.
        let raw = vec![
            IDataInput {
                role: "memory".into(),
                plaintext: serde_json::json!({"notes": "hi"}),
                extra: Default::default(),
            },
            IDataInput {
                role: "persona".into(),
                plaintext: serde_json::json!("user-supplied"),
                extra: Default::default(),
            },
        ];
        let out = normalize_i_data(raw, "Sage", "helper", &registry());
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].role, "framework");
        assert_eq!(out[1].role, "persona");
        // user's "user-supplied" persona must NOT have leaked through.
        assert!(out[1].plaintext.is_object());
        assert!(out[1].plaintext.get("system_prompt").is_some());
    }
}
