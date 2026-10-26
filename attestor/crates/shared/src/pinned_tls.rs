//! TLS that trusts an attested public key instead of a certificate authority.
//!
//! The peers here — KMS nodes, the verifier — are TEEs serving self-signed certificates.
//! No CA vouches for them and none should: what a caller checks is that the certificate's
//! public key is the one the peer's attestation committed to, which is a stronger statement
//! than any issuer can make. So this **replaces** certificate-authority validation rather
//! than adding to it.
//!
//! The distinction matters because the obvious alternatives are both wrong. Leaving the
//! default verifier in place fails outright, since nothing will ever chain a self-signed
//! certificate to a root. Reaching for `danger_accept_invalid_certs` makes it connect and
//! checks nothing, which is the hole this exists to close.
//!
//! What is deliberately *not* checked: the certificate's name, dates and chain. A name means
//! whatever its issuer decided it means, and there is no issuer. The identity being
//! established is the key, and the key is checked exactly.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Accepts a peer only when its certificate carries one of the expected public keys.
#[derive(Debug)]
pub struct PinnedKeys {
    /// sha256 of each acceptable SubjectPublicKeyInfo, lowercase hex without `0x`.
    ///
    /// A set rather than one value, because an app's nodes legitimately hold different
    /// keys: a `local` key is derived from each node's own signer, so a cluster has one
    /// per node. Any of them answering is equally correct, and the caller has no reason
    /// to care which did.
    expected: Vec<String>,
    /// Rustls still has to verify the handshake signature — that the peer holds the
    /// private key for the certificate it presented. Delegated to the stock
    /// implementation, since only the trust decision is ours to change.
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedKeys {
    /// `expected` are sha256 hashes of SubjectPublicKeyInfo, with or without `0x`.
    pub fn new(expected: impl IntoIterator<Item = String>) -> Self {
        Self {
            expected: expected
                .into_iter()
                .map(|k| k.trim_start_matches("0x").to_lowercase())
                .collect(),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.expected.is_empty()
    }
}

/// sha256 of a certificate's SubjectPublicKeyInfo, lowercase hex.
///
/// The SPKI is the DER structure that carries the algorithm and the key together, which is
/// what `openssl x509 -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256`
/// hashes and what `curl --pinnedpubkey` compares — so a value produced here can be checked
/// by hand with tools nobody has to trust us about.
pub fn spki_sha256(cert: &CertificateDer<'_>) -> Result<String, TlsError> {
    use x509_parser::prelude::*;
    let (_, parsed) = X509Certificate::from_der(cert.as_ref())
        .map_err(|e| TlsError::General(format!("cannot parse peer certificate: {e}")))?;
    let spki = parsed.tbs_certificate.subject_pki.raw;
    Ok(hex::encode(Sha256::digest(spki)))
}

impl ServerCertVerifier for PinnedKeys {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // An empty pin set would accept everything, which is worse than not connecting:
        // the caller would believe a check happened. Refuse instead.
        if self.expected.is_empty() {
            return Err(TlsError::General(
                "no attested key to pin against — refusing rather than accepting any peer".into(),
            ));
        }
        let got = spki_sha256(end_entity)?;
        if self.expected.iter().any(|e| *e == got) {
            Ok(ServerCertVerified::assertion())
        } else {
            // Name the key that was offered. Diagnosing a pin failure means comparing it
            // against what the verifier published, and a message that omits it forces the
            // reader to reproduce the handshake by hand to learn the first half.
            Err(TlsError::General(format!(
                "peer's TLS key 0x{got} is not among the {} attested for this app — \
                 refusing: something is answering that this app's attestation does not vouch for",
                self.expected.len()
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A rustls config that accepts only peers holding one of `expected`.
///
/// Shared by the HTTP client below and by gRPC, so both hops decide trust the same way
/// and cannot drift into two conventions.
pub fn client_config(expected: impl IntoIterator<Item = String>) -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring supports the TLS protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedKeys::new(expected)))
        .with_no_client_auth()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_normalised_so_a_0x_prefix_or_capitals_do_not_miss() {
        let p = PinnedKeys::new(vec!["0xAABB".to_string(), "ccdd".to_string()]);
        assert_eq!(p.expected, vec!["aabb", "ccdd"]);
    }

    #[test]
    fn an_empty_pin_set_is_recognisable_rather_than_silently_permissive() {
        assert!(PinnedKeys::new(Vec::new()).is_empty());
    }
}
