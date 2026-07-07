//! Post-intake normalization of user-supplied `i_data` entries — the
//! framework-agnostic replacement for the old per-framework
//! `AgentProfile` system.
//!
//! attestor synthesizes exactly two neutral defaults when the user omits
//! a role, and understands neither beyond their protocol shape:
//!
//!   `role="framework"` — a VERSION-LESS binding `{name, schema_version}`.
//!     `name` is the opaque framework string the deploy request selected
//!     (validated against `supported_frameworks` at the API edge). The
//!     sealed adapter resolves the missing version to its own validated
//!     whitelistMax — version knowledge lives with the code that
//!     validates versions, not here.
//!
//!   `role="persona"` — the protocol seed `{system_prompt, inference}`.
//!     Every sealed adapter is contractually required to translate it
//!     into its own config artifacts (FRAMEWORK_ADAPTER.md §5.4), which
//!     is what lets this synthesis stay framework-neutral.
//!
//! Per-role merge: user entries override the defaults by `role`; roles
//! the user didn't supply are preserved; user roles outside the default
//! set are appended. Sub-field merging inside a single dim's plaintext is
//! deliberately NOT done — a user overriding `persona` sends the FULL
//! persona JSON.

use crate::types::IDataInput;
use std::collections::HashMap;

/// Protocol schema version stamped into the framework binding. Bumped
/// only when the binding shape itself changes.
pub const BINDING_SCHEMA_VERSION: u32 = 1;

/// Product-level inference defaults for the persona seed. These are
/// deploy defaults, not framework knowledge — adapters that can't honour
/// them (e.g. a non-anthropic-capable framework) log and keep their own
/// default per the seed-ingestion contract.
pub const DEFAULT_INFERENCE_PROVIDER: &str = "anthropic";
pub const DEFAULT_INFERENCE_MODEL: &str = "claude-opus-4-6";

/// The neutral default iData set: version-less framework binding +
/// persona seed. `framework` is treated as an opaque name.
pub fn default_i_data(framework: &str, name: &str, description: &str) -> Vec<IDataInput> {
    let binding = serde_json::json!({
        "name":           framework,
        "schema_version": BINDING_SCHEMA_VERSION,
    });
    let persona = serde_json::json!({
        "system_prompt": format!("You are {name}. {description}\n"),
        "inference": {
            "provider": DEFAULT_INFERENCE_PROVIDER,
            "model":    DEFAULT_INFERENCE_MODEL,
        },
    });
    vec![
        IDataInput {
            role: "framework".into(),
            plaintext: binding,
            extra: Default::default(),
        },
        IDataInput {
            role: "persona".into(),
            plaintext: persona,
            extra: Default::default(),
        },
    ]
}

/// Normalize the user's raw i_data into a worker-safe form.
///
/// Pure function — no I/O, trivially testable.
pub fn normalize_i_data(
    raw: Vec<IDataInput>,
    framework: &str,
    name: &str,
    description: &str,
) -> Vec<IDataInput> {
    let defaults = default_i_data(framework, name, description);
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

    #[test]
    fn empty_raw_produces_neutral_defaults() {
        let out = normalize_i_data(Vec::new(), "claude-code", "Sage", "helper");
        let roles: Vec<&str> = out.iter().map(|e| e.role.as_str()).collect();
        assert_eq!(roles, vec!["framework", "persona"]);
    }

    #[test]
    fn binding_is_version_less_and_carries_opaque_name() {
        // attestor must not speak any framework's release scheme: the
        // binding names the framework and nothing else; the sealed
        // adapter fills whitelistMax for the missing version.
        let out = default_i_data("claude-code", "Sage", "helper");
        let fw = &out.iter().find(|e| e.role == "framework").unwrap().plaintext;
        assert_eq!(fw["name"], "claude-code");
        assert_eq!(fw["schema_version"], 1);
        assert!(
            fw.get("package_version").is_none(),
            "binding must be version-less; got {fw}"
        );
    }

    #[test]
    fn persona_embeds_name_description_and_inference() {
        let out = default_i_data("openclaw", "Sage", "DeFi helper");
        let p = &out.iter().find(|e| e.role == "persona").unwrap().plaintext;
        let prompt = p["system_prompt"].as_str().expect("system_prompt is a string");
        assert!(prompt.contains("Sage"));
        assert!(prompt.contains("DeFi helper"));
        assert_eq!(p["inference"]["provider"], DEFAULT_INFERENCE_PROVIDER);
        assert_eq!(p["inference"]["model"], DEFAULT_INFERENCE_MODEL);
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
        let out = normalize_i_data(raw, "openclaw", "Sage", "helper");
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
        // Forward-compat: power users may add roles outside the default
        // set (e.g. role="memory"). They land at the tail, defaults stay
        // intact.
        let raw = vec![IDataInput {
            role: "memory".into(),
            plaintext: serde_json::json!({"notes": "hi"}),
            extra: Default::default(),
        }];
        let out = normalize_i_data(raw, "openclaw", "Sage", "helper");
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
        let out = normalize_i_data(raw, "openclaw", "Sage", "helper");
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
