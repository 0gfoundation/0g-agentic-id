//! Agent-framework profiles — pluggable defaults for config + AgentCard.
//!
//! An `AgentProfile` encapsulates everything framework-specific the
//! attestor needs: the shape of a minimal valid `ConfigInput`, the logo
//! to use when the user doesn't provide an image, the capabilities flags
//! advertised in the public AgentCard, and any extra OpenSea traits.
//!
//! The attestor stays framework-agnostic: `normalize_i_data` and
//! `build_agent_card` never name a framework — they take a `&dyn
//! AgentProfile` picked from the `ProfileRegistry` by the user's
//! `ConfigInput.framework.name`. Adding a new framework (LangChain,
//! LlamaIndex, custom) is a single file implementing the trait plus one
//! `.register()` call at startup.

use crate::types::ConfigInput;
use std::collections::HashMap;
use std::sync::Arc;

pub mod openclaw;

pub use openclaw::OpenClawProfile;

pub trait AgentProfile: Send + Sync {
    /// Stable lookup key. Matches `ConfigInput.framework.name` so a user
    /// who sets `{"framework":{"name":"X"}}` routes to profile X.
    fn framework_name(&self) -> &str;

    /// Fully-populated ConfigInput used when the user's is absent or
    /// unparseable, and as the merge base when the user's is partial.
    /// Receives the agent's display `name`/`description` so the default
    /// `persona.system_prompt` can reference them.
    fn default_config(&self, name: &str, description: &str) -> ConfigInput;

    /// Logo URL used for `AgentCard.image` when the user didn't provide
    /// one. `None` → leave the field absent.
    fn default_image_url(&self) -> Option<&str> {
        None
    }

    /// `AgentCard.capabilities` map. The A2A protocol defines three
    /// canonical booleans (`streaming`, `pushNotifications`,
    /// `stateTransitionHistory`); profiles may add more.
    fn default_capabilities(&self) -> serde_json::Value {
        serde_json::json!({
            "streaming": true,
            "pushNotifications": false,
            "stateTransitionHistory": false,
        })
    }

    /// Additional OpenSea-style traits for `AgentCard.attributes` beyond
    /// the universal `{"trait_type":"species","value":"agent"}`. Default
    /// is empty; framework profiles may add framework-specific facets.
    fn extra_attributes(&self) -> Vec<serde_json::Value> {
        Vec::new()
    }
}

/// Registry of framework profiles. `new(default)` auto-registers the
/// profile by its `framework_name()` and also keeps it as the fallback
/// for unknown framework names. Further profiles can be added via
/// `register()` without affecting the fallback.
pub struct ProfileRegistry {
    by_name: HashMap<String, Arc<dyn AgentProfile>>,
    fallback: Arc<dyn AgentProfile>,
}

impl ProfileRegistry {
    pub fn new(fallback: Arc<dyn AgentProfile>) -> Self {
        let mut by_name = HashMap::new();
        by_name.insert(fallback.framework_name().to_string(), fallback.clone());
        Self { by_name, fallback }
    }

    /// Register another profile. If a profile with the same name already
    /// exists it is replaced. The fallback is left untouched.
    pub fn register(&mut self, profile: Arc<dyn AgentProfile>) {
        self.by_name
            .insert(profile.framework_name().to_string(), profile);
    }

    /// Look up by framework name; unknown / `None` returns the fallback.
    pub fn select(&self, framework_name: Option<&str>) -> &dyn AgentProfile {
        framework_name
            .and_then(|n| self.by_name.get(n))
            .map(|a| a.as_ref())
            .unwrap_or_else(|| self.fallback.as_ref())
    }

    pub fn fallback(&self) -> &dyn AgentProfile {
        self.fallback.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyProfile {
        name: &'static str,
    }
    impl AgentProfile for DummyProfile {
        fn framework_name(&self) -> &str {
            self.name
        }
        fn default_config(&self, _: &str, _: &str) -> ConfigInput {
            ConfigInput::default()
        }
    }

    #[test]
    fn select_known_framework_returns_registered_profile() {
        let registry =
            ProfileRegistry::new(Arc::new(DummyProfile { name: "openclaw" }));
        assert_eq!(registry.select(Some("openclaw")).framework_name(), "openclaw");
    }

    #[test]
    fn select_unknown_framework_returns_fallback() {
        let registry = ProfileRegistry::new(Arc::new(DummyProfile { name: "openclaw" }));
        // User claimed "langchain" but we didn't register it — fallback.
        assert_eq!(
            registry.select(Some("langchain")).framework_name(),
            "openclaw"
        );
        assert_eq!(registry.select(None).framework_name(), "openclaw");
    }

    #[test]
    fn register_adds_new_profile_without_replacing_fallback() {
        let mut registry =
            ProfileRegistry::new(Arc::new(DummyProfile { name: "openclaw" }));
        registry.register(Arc::new(DummyProfile { name: "langchain" }));
        assert_eq!(
            registry.select(Some("langchain")).framework_name(),
            "langchain"
        );
        assert_eq!(registry.fallback().framework_name(), "openclaw");
    }
}
