//! The OpenClaw framework profile — the v0 default.
//!
//! Synthesizes 2 default iData entries when the user omits `i_data`:
//!   `role="framework"` — `{name, package_version, schema_version}`
//!   `role="persona"`   — `{system_prompt, inference:{provider, model}}`
//!
//! Both plaintexts are JSON `Value`s; the attestor encrypts them
//! verbatim and uploads each ciphertext to 0G storage. Container reads
//! `framework` first to decide which npm package to install, then reads
//! `persona` for prompt + model pin.

use super::AgentProfile;
use crate::types::IDataInput;

pub struct OpenClawProfile;

impl OpenClawProfile {
    pub const FRAMEWORK_NAME: &'static str = "openclaw";
    /// npm-installable version openclaw is pinned to. Container
    /// bootstrap does `npm install openclaw@<this>`; without it
    /// bootstrap defaults to `latest`, which silently drifts when
    /// upstream cuts a new release. Bump deliberately.
    pub const PACKAGE_VERSION: &'static str = "2026.5.6";
    /// Bumped when any default-iData plaintext shape changes — the
    /// container reads this from the framework dim to decide whether it
    /// understands the rest.
    pub const SCHEMA_VERSION: u32 = 1;
    pub const DEFAULT_INFERENCE_PROVIDER: &'static str = "anthropic";
    pub const DEFAULT_INFERENCE_MODEL: &'static str = "claude-opus-4-6";
}

impl AgentProfile for OpenClawProfile {
    fn framework_name(&self) -> &str {
        Self::FRAMEWORK_NAME
    }

    fn default_i_data(&self, name: &str, description: &str) -> Vec<IDataInput> {
        let framework = serde_json::json!({
            "name":            Self::FRAMEWORK_NAME,
            "package_version": Self::PACKAGE_VERSION,
            "schema_version":  Self::SCHEMA_VERSION,
        });
        let persona = serde_json::json!({
            "system_prompt": format!("You are {name}. {description}\n"),
            "inference": {
                "provider": Self::DEFAULT_INFERENCE_PROVIDER,
                "model":    Self::DEFAULT_INFERENCE_MODEL,
            },
        });
        vec![
            IDataInput {
                role: "framework".into(),
                plaintext: framework,
                extra: Default::default(),
            },
            IDataInput {
                role: "persona".into(),
                plaintext: persona,
                extra: Default::default(),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_i_data_emits_framework_then_persona() {
        let entries = OpenClawProfile.default_i_data("Sage", "DeFi helper");
        let roles: Vec<&str> = entries.iter().map(|e| e.role.as_str()).collect();
        assert_eq!(roles, vec!["framework", "persona"]);
    }

    #[test]
    fn framework_plaintext_carries_name_package_version_schema() {
        let entries = OpenClawProfile.default_i_data("Sage", "x");
        let fw = &entries
            .iter()
            .find(|e| e.role == "framework")
            .expect("framework dim")
            .plaintext;
        assert_eq!(fw["name"], "openclaw");
        assert_eq!(fw["package_version"], "2026.5.6");
        assert_eq!(fw["schema_version"], 1);
    }

    #[test]
    fn persona_plaintext_embeds_name_description_and_inference() {
        let entries = OpenClawProfile.default_i_data("Sage", "DeFi helper");
        let p = &entries
            .iter()
            .find(|e| e.role == "persona")
            .expect("persona dim")
            .plaintext;
        let prompt = p["system_prompt"].as_str().expect("system_prompt is a string");
        assert!(prompt.contains("Sage"));
        assert!(prompt.contains("DeFi helper"));
        assert_eq!(p["inference"]["provider"], "anthropic");
        assert_eq!(p["inference"]["model"], "claude-opus-4-6");
    }
}
