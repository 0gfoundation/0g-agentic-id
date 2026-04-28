//! The OpenClaw framework profile — the v0 default.

use super::AgentProfile;
use crate::types::{ConfigInput, FrameworkSpec, InferenceSpec, PersonaSpec};

/// OpenClaw default profile. All framework-specific strings (version,
/// inference provider/model) live in this file only — the rest of the
/// crate never spells "openclaw" except as a value flowing through
/// `framework_name()`.
pub struct OpenClawProfile;

impl OpenClawProfile {
    const FRAMEWORK_NAME: &'static str = "openclaw";
    const FRAMEWORK_VERSION: &'static str = "0.1.0";
    const INFERENCE_PROVIDER: &'static str = "anthropic";
    const INFERENCE_MODEL: &'static str = "claude-opus-4-7";
    const INFERENCE_FALLBACKS: &'static [&'static str] = &["claude-opus-4-6"];
}

impl AgentProfile for OpenClawProfile {
    fn framework_name(&self) -> &str {
        Self::FRAMEWORK_NAME
    }

    fn default_config(&self, name: &str, description: &str) -> ConfigInput {
        ConfigInput {
            framework: Some(FrameworkSpec {
                name: Some(Self::FRAMEWORK_NAME.to_string()),
                version: Some(Self::FRAMEWORK_VERSION.to_string()),
                extra: Default::default(),
            }),
            inference: Some(InferenceSpec {
                provider: Some(Self::INFERENCE_PROVIDER.to_string()),
                model: Some(Self::INFERENCE_MODEL.to_string()),
                fallbacks: Self::INFERENCE_FALLBACKS.iter().map(|s| s.to_string()).collect(),
                extra: Default::default(),
            }),
            persona: Some(PersonaSpec {
                system_prompt: Some(format!("You are {name}. {description}")),
                extra: Default::default(),
            }),
            skills: Vec::new(),
            extra: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_populates_all_required_slots() {
        let c = OpenClawProfile.default_config("Sage", "DeFi helper");
        let fw = c.framework.expect("framework");
        assert_eq!(fw.name.as_deref(), Some("openclaw"));
        assert_eq!(fw.version.as_deref(), Some("0.1.0"));
        let inf = c.inference.expect("inference");
        assert_eq!(inf.provider.as_deref(), Some("anthropic"));
        assert_eq!(inf.model.as_deref(), Some("claude-opus-4-7"));
        assert_eq!(inf.fallbacks, vec!["claude-opus-4-6".to_string()]);
        let p = c.persona.expect("persona");
        assert_eq!(
            p.system_prompt.as_deref(),
            Some("You are Sage. DeFi helper")
        );
    }
}
