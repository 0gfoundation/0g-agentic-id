//! Post-intake normalization of user-supplied `i_data` entries.
//!
//! The attestor must guarantee that, after processing, there exists at
//! least one `role="config"` entry whose plaintext is a valid-shape
//! `ConfigInput` object — otherwise the container can't boot. At the
//! same time we want to preserve everything the user sent verbatim (no
//! silent data loss). `normalize_i_data` reconciles these two goals:
//!
//! | Input                          | Output                                            |
//! |--------------------------------|---------------------------------------------------|
//! | empty Vec                      | \[default config\]                                |
//! | only role=config (valid object)| merge user fields into profile default, rewrite   |
//! | only role=config (not object) | keep original + append default config             |
//! | only role=memory (no config)  | keep memory + append default config               |
//! | config + others                | merge config, keep others                         |
//! | multiple configs               | first merged; later configs kept as-is            |
//!
//! The profile to use for defaults/merge base is selected from the
//! `ProfileRegistry` by reading the user's `framework.name` (from the
//! first parseable config); unknown / missing name → registry fallback.

use crate::agent_profile::{AgentProfile, ProfileRegistry};
use crate::types::{ConfigInput, IDataInput};

pub const ROLE_CONFIG: &str = "config";

/// Normalize user's raw i_data into a form that's safe for the worker:
/// always ≥1 valid-object `role=config` entry, user-supplied entries
/// preserved. Pure function — no I/O, trivially testable.
pub fn normalize_i_data(
    raw: Vec<IDataInput>,
    name: &str,
    description: &str,
    registry: &ProfileRegistry,
) -> Vec<IDataInput> {
    let mut out: Vec<IDataInput> = Vec::with_capacity(raw.len() + 1);
    let mut first_config_merged = false;
    let mut need_append_default = true;

    for input in raw.into_iter() {
        if input.role != ROLE_CONFIG || first_config_merged {
            // Not a config entry, or a secondary config — pass through.
            out.push(input);
            continue;
        }

        // First config entry: try to interpret its plaintext as a
        // ConfigInput object and merge with the registry-picked profile's
        // default.
        match serde_json::from_value::<ConfigInput>(input.plaintext.clone()) {
            Ok(user_cfg) => {
                let profile_name = user_cfg
                    .framework
                    .as_ref()
                    .and_then(|f| f.name.as_deref());
                let profile = registry.select(profile_name);
                let merged = merge_config_input(user_cfg, profile, name, description);
                let plaintext = serde_json::to_value(&merged).unwrap_or(serde_json::Value::Null);
                out.push(IDataInput {
                    role: input.role,
                    plaintext,
                    extra: input.extra,
                });
                first_config_merged = true;
                need_append_default = false;
            }
            Err(e) => {
                // Preserve the original (user's choice) and mark that we
                // still owe a synthesized default later.
                tracing::warn!(
                    error = %e,
                    "role=config plaintext is not a valid ConfigInput object; keeping original and appending default"
                );
                out.push(input);
                first_config_merged = true;
                // need_append_default stays true
            }
        }
    }

    if need_append_default {
        let profile = registry.fallback();
        let default_cfg = profile.default_config(name, description);
        out.push(IDataInput {
            role: ROLE_CONFIG.to_string(),
            plaintext: serde_json::to_value(&default_cfg)
                .unwrap_or(serde_json::Value::Null),
            extra: Default::default(),
        });
    }

    out
}

/// Field-level merge: `user`'s `Some` fields win, `None` fields inherit
/// from `profile.default_config(name, description)`. Sub-struct merge
/// recurses one level (framework.name + framework.version merge
/// independently). Extra maps: user's keys win over default's (default is
/// typically empty anyway).
pub fn merge_config_input(
    user: ConfigInput,
    profile: &dyn AgentProfile,
    name: &str,
    description: &str,
) -> ConfigInput {
    let mut base = profile.default_config(name, description);

    // framework
    if let Some(u_fw) = user.framework {
        let mut b_fw = base.framework.unwrap_or_default();
        if u_fw.name.is_some() {
            b_fw.name = u_fw.name;
        }
        if u_fw.package_version.is_some() {
            b_fw.package_version = u_fw.package_version;
        }
        extend_map(&mut b_fw.extra, u_fw.extra);
        base.framework = Some(b_fw);
    }

    // inference
    if let Some(u_inf) = user.inference {
        let mut b_inf = base.inference.unwrap_or_default();
        if u_inf.provider.is_some() {
            b_inf.provider = u_inf.provider;
        }
        if u_inf.model.is_some() {
            b_inf.model = u_inf.model;
        }
        // fallbacks: user's vec wins wholesale when non-empty (same rule
        // as `skills` at the top level). Empty user vec → inherit profile.
        if !u_inf.fallbacks.is_empty() {
            b_inf.fallbacks = u_inf.fallbacks;
        }
        extend_map(&mut b_inf.extra, u_inf.extra);
        base.inference = Some(b_inf);
    }

    // persona
    if let Some(u_p) = user.persona {
        let mut b_p = base.persona.unwrap_or_default();
        if u_p.system_prompt.is_some() {
            b_p.system_prompt = u_p.system_prompt;
        }
        extend_map(&mut b_p.extra, u_p.extra);
        base.persona = Some(b_p);
    }

    // skills — user's Vec wins wholesale. Default is empty.
    if !user.skills.is_empty() {
        base.skills = user.skills;
    }

    // top-level extra: user keys win
    extend_map(&mut base.extra, user.extra);

    base
}

fn extend_map(
    base: &mut serde_json::Map<String, serde_json::Value>,
    additions: serde_json::Map<String, serde_json::Value>,
) {
    for (k, v) in additions {
        base.insert(k, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_profile::OpenClawProfile;
    use std::sync::Arc;

    fn registry() -> ProfileRegistry {
        ProfileRegistry::new(Arc::new(OpenClawProfile))
    }

    fn config_plaintext(entry: &IDataInput) -> ConfigInput {
        serde_json::from_value(entry.plaintext.clone()).expect("parse merged config")
    }

    #[test]
    fn empty_raw_produces_single_default_config() {
        let out = normalize_i_data(Vec::new(), "Sage", "helper", &registry());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].role, ROLE_CONFIG);
        let cfg = config_plaintext(&out[0]);
        assert_eq!(cfg.framework.unwrap().name.as_deref(), Some("openclaw"));
    }

    #[test]
    fn partial_user_config_merges_with_default() {
        let raw = vec![IDataInput {
            role: ROLE_CONFIG.to_string(),
            plaintext: serde_json::json!({
                "framework": {"name": "openclaw", "package_version": "9.9.9"},
                "inference": {"model": "custom-llm"}
                // persona missing → default injected
            }),
            extra: Default::default(),
        }];
        let out = normalize_i_data(raw, "Sage", "helper", &registry());
        assert_eq!(out.len(), 1);
        let cfg = config_plaintext(&out[0]);
        let fw = cfg.framework.unwrap();
        assert_eq!(fw.name.as_deref(), Some("openclaw"));
        assert_eq!(fw.package_version.as_deref(), Some("9.9.9"), "user package_version wins");
        let inf = cfg.inference.unwrap();
        assert_eq!(inf.model.as_deref(), Some("custom-llm"), "user model wins");
        assert_eq!(
            inf.provider.as_deref(),
            Some("anthropic"),
            "default provider inherited"
        );
        assert!(cfg.persona.unwrap().system_prompt.is_some());
    }

    #[test]
    fn non_object_config_preserved_with_appended_default() {
        let raw = vec![IDataInput {
            role: ROLE_CONFIG.to_string(),
            plaintext: serde_json::json!("oops-a-string"),
            extra: Default::default(),
        }];
        let out = normalize_i_data(raw, "Sage", "helper", &registry());
        assert_eq!(out.len(), 2, "original kept + default appended");
        assert_eq!(out[0].plaintext, serde_json::json!("oops-a-string"));
        let cfg = config_plaintext(&out[1]);
        assert_eq!(cfg.framework.unwrap().name.as_deref(), Some("openclaw"));
    }

    #[test]
    fn only_non_config_roles_get_default_config_appended() {
        let raw = vec![IDataInput {
            role: "memory".to_string(),
            plaintext: serde_json::json!({"notes": "hi"}),
            extra: Default::default(),
        }];
        let out = normalize_i_data(raw, "Sage", "helper", &registry());
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].role, "memory");
        assert_eq!(out[1].role, ROLE_CONFIG);
    }

    #[test]
    fn multiple_configs_only_first_is_merged() {
        let raw = vec![
            IDataInput {
                role: ROLE_CONFIG.to_string(),
                plaintext: serde_json::json!({"inference": {"model": "custom"}}),
                extra: Default::default(),
            },
            IDataInput {
                role: ROLE_CONFIG.to_string(),
                plaintext: serde_json::json!({"raw_second_config": true}),
                extra: Default::default(),
            },
        ];
        let out = normalize_i_data(raw, "Sage", "helper", &registry());
        assert_eq!(out.len(), 2);
        // first: merged
        let first = config_plaintext(&out[0]);
        assert_eq!(first.inference.unwrap().model.as_deref(), Some("custom"));
        assert_eq!(
            first.framework.unwrap().name.as_deref(),
            Some("openclaw"),
            "default injected"
        );
        // second: untouched
        assert_eq!(
            out[1].plaintext,
            serde_json::json!({"raw_second_config": true})
        );
    }

    #[test]
    fn unknown_framework_name_falls_back_to_registry_default() {
        let raw = vec![IDataInput {
            role: ROLE_CONFIG.to_string(),
            plaintext: serde_json::json!({
                "framework": {"name": "langchain", "package_version": "1.2.3"}
            }),
            extra: Default::default(),
        }];
        let out = normalize_i_data(raw, "Sage", "helper", &registry());
        // user's framework name kept; but defaults (inference/persona) come
        // from OpenClaw since langchain isn't registered → fallback.
        let cfg = config_plaintext(&out[0]);
        assert_eq!(cfg.framework.unwrap().name.as_deref(), Some("langchain"));
        assert_eq!(
            cfg.inference.unwrap().provider.as_deref(),
            Some("anthropic"),
            "fallback OpenClaw default used"
        );
    }
}
