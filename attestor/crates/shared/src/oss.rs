//! Minimal Ali OSS client for public off-chain storage of AgentCard JSON
//! and images.
//!
//! Uses OSS v1 signature (HMAC-SHA1). Objects are uploaded with
//! `x-oss-object-acl: public-read` so the resulting URL can be referenced
//! unauthenticated from the on-chain `tokenURI`. This is deliberately a
//! tiny bespoke client rather than pulling `aws-sdk-s3` — we only need
//! PUT with a canonical URL and this keeps the dep footprint minimal.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::sync::Arc;

type HmacSha1 = Hmac<Sha1>;

/// Ali OSS client. Construct via `from_env()`; when required env vars are
/// missing the constructor returns `None` and callers should fail the
/// deploy path (or skip, depending on context — mirrors the JS
/// `ali-oss` graceful-warn pattern but Rust has no global `let oss`).
pub struct OssClient {
    access_key_id: String,
    access_key_secret: String,
    bucket: String,
    endpoint_host: String,
    public_url_base: String,
    http: reqwest::Client,
    /// Test-only short-circuit. When `Some`, every `put`/`put_json`
    /// call returns this synthetic URL without performing any HTTP
    /// request — lets unit tests exercise code paths that traverse
    /// OSS without needing real credentials or network. None in prod.
    test_stub_url: Option<String>,
}

impl OssClient {
    /// Returns `None` when any of the three credential env vars are
    /// missing. Logs a warning — same behaviour as the JS reference.
    /// Optional vars have defaults (`oss-cn-beijing`).
    pub fn from_env() -> Option<Arc<Self>> {
        let access_key_id = std::env::var("OSS_ACCESS_KEY_ID").ok();
        let access_key_secret = std::env::var("OSS_ACCESS_KEY_SECRET").ok();
        let bucket = std::env::var("OSS_BUCKET").ok();

        let (access_key_id, access_key_secret, bucket) =
            match (access_key_id, access_key_secret, bucket) {
                (Some(a), Some(b), Some(c)) if !a.is_empty() && !b.is_empty() && !c.is_empty() => {
                    (a, b, c)
                }
                _ => {
                    tracing::warn!(
                        "OSS_ACCESS_KEY_ID, OSS_ACCESS_KEY_SECRET, OSS_BUCKET not set — OSS disabled"
                    );
                    return None;
                }
            };

        let region = std::env::var("OSS_REGION").unwrap_or_else(|_| "oss-cn-beijing".to_string());
        let endpoint_host = std::env::var("OSS_ENDPOINT_HOST")
            .unwrap_or_else(|_| format!("{region}.aliyuncs.com"));
        let public_url_base = std::env::var("OSS_PUBLIC_URL_BASE")
            .unwrap_or_else(|_| format!("https://{bucket}.{endpoint_host}"));

        Some(Arc::new(Self {
            access_key_id,
            access_key_secret,
            bucket,
            endpoint_host,
            public_url_base,
            http: reqwest::Client::new(),
            test_stub_url: None,
        }))
    }

    /// Test-only constructor: every `put`/`put_json` call returns
    /// `https://oss.test/<key>` without issuing any HTTP. Lets unit
    /// tests for code that crosses OSS run hermetically.
    pub fn for_test() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            access_key_id: "test-key".into(),
            access_key_secret: "test-secret".into(),
            bucket: "test-bucket".into(),
            endpoint_host: "oss.test".into(),
            public_url_base: "https://oss.test".into(),
            http: reqwest::Client::new(),
            test_stub_url: Some("https://oss.test".into()),
        })
    }

    /// PUT a JSON object. Returns the public URL on success.
    pub async fn put_json(&self, key: &str, body: Vec<u8>) -> anyhow::Result<String> {
        self.put(key, "application/json", body).await
    }

    /// PUT arbitrary bytes under a caller-specified content-type.
    pub async fn put_bytes(
        &self,
        key: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> anyhow::Result<String> {
        self.put(key, content_type, body).await
    }

    async fn put(&self, key: &str, content_type: &str, body: Vec<u8>) -> anyhow::Result<String> {
        if let Some(base) = &self.test_stub_url {
            tracing::debug!(%key, bytes = body.len(), %content_type, "oss test stub: skipping HTTP");
            return Ok(format!("{}/{}", base.trim_end_matches('/'), key));
        }
        let url = format!("https://{}.{}/{}", self.bucket, self.endpoint_host, key);
        // RFC 1123 date is what OSS expects.
        let date = chrono::Utc::now()
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        let oss_acl = "public-read";

        let authorization = sign_put(
            &self.access_key_id,
            &self.access_key_secret,
            &self.bucket,
            key,
            content_type,
            &date,
            oss_acl,
        )?;

        let resp = self
            .http
            .put(&url)
            .header("Date", &date)
            .header("Content-Type", content_type)
            .header("x-oss-object-acl", oss_acl)
            .header("Authorization", authorization)
            .body(body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("OSS PUT {key} failed ({status}): {text}");
        }

        Ok(format!(
            "{}/{}",
            self.public_url_base.trim_end_matches('/'),
            key
        ))
    }

    /// Public URL that a GET on the stored object would use. Useful for
    /// callers that compute the URL before uploading (e.g. writing it into
    /// the AgentCard body itself).
    pub fn public_url(&self, key: &str) -> String {
        format!(
            "{}/{}",
            self.public_url_base.trim_end_matches('/'),
            key
        )
    }
}

/// OSS v1 Authorization header for a PUT request, extracted as a pure
/// function so it can be unit tested without a live network.
///
/// StringToSign layout:
/// ```text
///   PUT\n
///   \n                              (empty Content-MD5)
///   {content_type}\n
///   {date}\n
///   x-oss-object-acl:{acl}\n        (only canonicalized OSS header)
///   /{bucket}/{key}                 (no trailing newline)
/// ```
fn sign_put(
    access_key_id: &str,
    access_key_secret: &str,
    bucket: &str,
    key: &str,
    content_type: &str,
    date: &str,
    acl: &str,
) -> anyhow::Result<String> {
    let string_to_sign = format!(
        "PUT\n\n{content_type}\n{date}\nx-oss-object-acl:{acl}\n/{bucket}/{key}"
    );
    let mut mac = HmacSha1::new_from_slice(access_key_secret.as_bytes())
        .map_err(|e| anyhow::anyhow!("hmac key: {e}"))?;
    mac.update(string_to_sign.as_bytes());
    let signature = B64.encode(mac.finalize().into_bytes());
    Ok(format!("OSS {access_key_id}:{signature}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden-value test. If this breaks someone changed the StringToSign
    /// layout — regenerate by running this test and pasting the new value,
    /// but only after confirming the new value is what the OSS server
    /// actually accepts (i.e. run an integration upload first).
    #[test]
    fn sign_put_produces_stable_output() {
        let auth = sign_put(
            "TESTKEYID",
            "TESTSECRET",
            "my-bucket",
            "agent/0xabcd/card.json",
            "application/json",
            "Mon, 01 Jan 2024 00:00:00 GMT",
            "public-read",
        )
        .unwrap();
        assert_eq!(auth, "OSS TESTKEYID:bVx0cDqkNCYePRjHvyZXpcMRlOw=");
    }

    /// Live round-trip against a real OSS bucket. Requires the three
    /// OSS_* env vars; ignored by default so `cargo test` doesn't try to
    /// hit the network. Run with:
    ///   cargo test -p attestor-shared oss::tests::live_roundtrip -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn live_roundtrip() {
        let _ = dotenvy::from_filename("../../.env");
        let oss = OssClient::from_env().expect("OSS env not set");

        let key = format!(
            "ci-smoke/{}.json",
            uuid::Uuid::new_v4().simple()
        );
        let body = br#"{"hello":"oss","from":"attestor-shared test"}"#.to_vec();

        let url = oss.put_json(&key, body.clone()).await.expect("PUT");
        println!("uploaded: {url}");

        let resp = reqwest::get(&url).await.expect("GET");
        assert!(resp.status().is_success(), "GET status: {}", resp.status());
        let got = resp.bytes().await.expect("body").to_vec();
        assert_eq!(got, body, "round-trip body mismatch");
    }
}
