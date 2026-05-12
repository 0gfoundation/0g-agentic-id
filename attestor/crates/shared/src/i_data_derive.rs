//! Post-intake normalization of user-supplied `i_data` entries.
//!
//! Per-role merge: user entries override the registry-fallback
//! profile's defaults by `role`. Default roles the user didn't supply
//! are preserved; user roles unknown to the profile are appended at
//! the end. Empty user input → defaults verbatim. Sub-field merging
//! inside a single dim's plaintext is deliberately NOT done — if a
//! user wants to override `persona`, they send the FULL persona JSON;
//! the profile's `default_i_data` is only consulted role-by-role.
//! Keeps normalize purely structural; per-profile plaintext shape
//! stays the profile's concern.

use crate::agent_profile::ProfileRegistry;
use crate::types::IDataInput;
use std::collections::HashMap;

/// Normalize the user's raw i_data into a worker-safe form.
///
/// Pure function — no I/O, trivially testable.
pub fn normalize_i_data(
    raw: Vec<IDataInput>,
    name: &str,
    description: &str,
    registry: &ProfileRegistry,
) -> Vec<IDataInput> {
    let defaults = registry.fallback().default_i_data(name, description);
    if raw.is_empty() {
        return defaults;
    }
    let mut user_by_role: HashMap<String, IDataInput> = raw
        .into_iter()
        .map(|e| (e.role.clone(), e))
        .collect();
    let mut out: Vec<IDataInput> = Vec::with_capacity(defaults.len());
    for d in defaults {
        out.push(user_by_role.remove(&d.role).unwrap_or(d));
    }
    // Any user-supplied roles not in the default set get appended.
    // Stable iteration order would be nicer than HashMap's, but tests
    // assert on role membership not position, and downstream just
    // round-trips the array.
    out.extend(user_by_role.into_values());
    out
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
    fn user_persona_overrides_default_persona_keeping_framework() {
        // The 1-dim-customize path: user wants to swap inference provider,
        // sends just their persona; default framework stays untouched.
        let user_persona = serde_json::json!({
            "system_prompt": "You are Sage. helper\n",
            "inference": { "provider": "openai", "model": "gpt-4o" },
        });
        let raw = vec![IDataInput {
            role: "persona".into(),
            plaintext: user_persona.clone(),
            extra: Default::default(),
        }];
        let out = normalize_i_data(raw, "Sage", "helper", &registry());
        assert_eq!(out.len(), 2, "framework + persona");
        // Default framework preserved (didn't accidentally drop it)
        let framework = out.iter().find(|e| e.role == "framework").expect("framework dim");
        assert_eq!(framework.plaintext["name"], "openclaw");
        // User's persona won outright — including their inference choice
        let persona = out.iter().find(|e| e.role == "persona").expect("persona dim");
        assert_eq!(persona.plaintext, user_persona);
        assert_eq!(persona.plaintext["inference"]["provider"], "openai");
    }

    #[test]
    fn user_unknown_role_is_appended() {
        // Forward-compat: future profiles or power users may add roles
        // outside the default set (e.g. role="memory"). They land at the
        // tail, defaults stay intact.
        let raw = vec![IDataInput {
            role: "memory".into(),
            plaintext: serde_json::json!({"notes": "hi"}),
            extra: Default::default(),
        }];
        let out = normalize_i_data(raw, "Sage", "helper", &registry());
        assert_eq!(out.len(), 3, "framework + persona + memory");
        let roles: Vec<&str> = out.iter().map(|e| e.role.as_str()).collect();
        assert!(roles.contains(&"framework"));
        assert!(roles.contains(&"persona"));
        assert!(roles.contains(&"memory"));
        // memory's plaintext rides through verbatim
        let memory = out.iter().find(|e| e.role == "memory").expect("memory dim");
        assert_eq!(memory.plaintext["notes"], "hi");
    }

    #[test]
    fn full_override_replaces_all_defaults() {
        // Edge case: user supplies BOTH default roles → defaults fully
        // replaced. Useful to confirm no default leakage when caller
        // wants total control.
        let raw = vec![
            IDataInput {
                role: "framework".into(),
                plaintext: serde_json::json!({"name": "custom-fw"}),
                extra: Default::default(),
            },
            IDataInput {
                role: "persona".into(),
                plaintext: serde_json::json!({"system_prompt": "x"}),
                extra: Default::default(),
            },
        ];
        let out = normalize_i_data(raw, "Sage", "helper", &registry());
        assert_eq!(out.len(), 2);
        assert_eq!(
            out.iter().find(|e| e.role == "framework").unwrap().plaintext["name"],
            "custom-fw"
        );
        assert_eq!(
            out.iter().find(|e| e.role == "persona").unwrap().plaintext["system_prompt"],
            "x"
        );
    }
}
