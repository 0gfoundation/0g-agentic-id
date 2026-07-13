//! Deploy-edge validation of the owner-supplied `i_data` — the WYSIWYS
//! successor to the old synthesis module (`i_data_derive`).
//!
//! The attestor no longer synthesizes ANY iData: what the owner signs is
//! exactly what gets encrypted and minted, so the exact on-chain
//! plaintexts are signature-covered (previously the owner signed the
//! *inputs* to a server-side template, and the template was silently part
//! of the trust surface). Default-content ergonomics moved to the clients
//! (SDK `defaultIData()`, the console's deploy form).
//!
//! What remains here is the one check the attestor must own: the
//! framework binding. The attestor needs exactly one unambiguous,
//! supported framework name per deploy — it is what `GET /config`
//! advertises and what the operator's sealed image actually bundles — so
//! a missing, duplicated, or unsupported name is rejected up front.
//! Whether the iData *content* lets the container boot is sealed's
//! contract, not the attestor's (sealed is an updatable consumer of the
//! minted bytes; what is valid to it can change across releases).
//! Everything else in i_data is opaque owner content — the attestor
//! neither parses nor judges it.

use crate::types::IDataInput;

/// Validate the framework binding inside a deploy's `i_data`. Returns the
/// (supported) framework name for logging, or a human-readable rejection.
///
/// Pure function — no I/O, trivially testable.
pub fn validate_framework_binding(
    i_data: &[IDataInput],
    supported: &[String],
) -> Result<String, String> {
    let mut bindings = i_data.iter().filter(|e| e.role == "framework");
    let entry = match bindings.next() {
        Some(e) => e,
        None => {
            return Err(format!(
                "i_data must contain a role=\"framework\" binding entry \
                 ({{\"name\", \"schema_version\"}}); the SDK's defaultIData() builds it. \
                 supported frameworks: {}",
                supported.join(", ")
            ))
        }
    };
    if bindings.next().is_some() {
        return Err("i_data contains more than one role=\"framework\" entry".to_string());
    }
    let name = match entry.plaintext.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.trim().is_empty() => n.trim(),
        _ => return Err("framework binding must carry a non-empty string `name`".to_string()),
    };
    if !supported.iter().any(|f| f == name) {
        return Err(format!(
            "unsupported framework {name:?}; supported: {}",
            supported.join(", ")
        ));
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn supported() -> Vec<String> {
        vec!["openclaw".into()]
    }

    fn binding(name: &str) -> IDataInput {
        IDataInput {
            role: "framework".into(),
            plaintext: serde_json::json!({"name": name, "schema_version": 1}),
            extra: Default::default(),
        }
    }

    fn persona() -> IDataInput {
        IDataInput {
            role: "persona".into(),
            plaintext: serde_json::json!({"system_prompt": "x"}),
            extra: Default::default(),
        }
    }

    #[test]
    fn valid_binding_passes_and_returns_name() {
        let name = validate_framework_binding(&[binding("openclaw"), persona()], &supported())
            .expect("valid");
        assert_eq!(name, "openclaw");
    }

    #[test]
    fn missing_binding_rejected() {
        // Without a binding the attestor has no framework name to serve
        // the deploy with.
        let err = validate_framework_binding(&[persona()], &supported()).unwrap_err();
        assert!(err.contains("must contain"), "got: {err}");
        assert!(err.contains("openclaw"), "lists supported: {err}");
    }

    #[test]
    fn empty_i_data_rejected() {
        assert!(validate_framework_binding(&[], &supported()).is_err());
    }

    #[test]
    fn unsupported_name_rejected() {
        let err = validate_framework_binding(&[binding("eliza")], &supported()).unwrap_err();
        assert!(err.contains("unsupported framework \"eliza\""), "got: {err}");
    }

    #[test]
    fn missing_or_empty_name_rejected() {
        let no_name = IDataInput {
            role: "framework".into(),
            plaintext: serde_json::json!({"schema_version": 1}),
            extra: Default::default(),
        };
        assert!(validate_framework_binding(&[no_name], &supported())
            .unwrap_err()
            .contains("non-empty string `name`"));
    }

    #[test]
    fn duplicate_binding_rejected() {
        // Two bindings would leave the adapter choice ambiguous.
        let err =
            validate_framework_binding(&[binding("openclaw"), binding("openclaw")], &supported())
                .unwrap_err();
        assert!(err.contains("more than one"), "got: {err}");
    }

    #[test]
    fn version_less_binding_is_fine() {
        // attestor stays out of version knowledge: {"name","schema_version"}
        // is the canonical client-built binding; adapters resolve the
        // missing version to their whitelistMax.
        assert!(validate_framework_binding(&[binding("openclaw")], &supported()).is_ok());
    }
}
