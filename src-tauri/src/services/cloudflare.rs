//! Cloudflare R2 (SigV4 presigned URLs) + delivery Worker registration.

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::Utc;
use hmac::{Hmac, Mac};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::errors::AppError;
use crate::services::with_retry;

type HmacSha256 = Hmac<Sha256>;

const REGION: &str = "auto";
const SERVICE: &str = "s3";

const SIGV4_ESCAPE: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');
const SIGV4_ESCAPE_PATH: &AsciiSet =
    &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~').remove(b'/');

#[derive(Clone)]
pub struct R2Client {
    http: reqwest::Client,
    account_id: String,
    bucket: String,
    access_key_id: String,
    secret_access_key: String,
}

impl R2Client {
    pub fn new(
        account_id: String,
        bucket: String,
        access_key_id: String,
        secret_access_key: String,
    ) -> Result<Self, AppError> {
        for (name, value) in [
            ("R2_ACCOUNT_ID", &account_id),
            ("R2_BUCKET", &bucket),
            ("R2_ACCESS_KEY_ID", &access_key_id),
            ("R2_SECRET_ACCESS_KEY", &secret_access_key),
        ] {
            if value.trim().is_empty() {
                return Err(AppError::Config(format!("{name} is required for R2 storage")));
            }
        }
        let http = reqwest::Client::builder()
            .https_only(true)
            .use_rustls_tls()
            .timeout(Duration::from_secs(120))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| AppError::Config(format!("http client init failed: {e}")))?;
        Ok(Self { http, account_id, bucket, access_key_id, secret_access_key })
    }

    fn host(&self) -> String {
        format!("{}.r2.cloudflarestorage.com", self.account_id)
    }

    pub fn presigned_put_url(&self, key: &str, expires_secs: u64) -> Result<String, AppError> {
        self.presign("PUT", key, expires_secs)
    }

    pub fn presigned_get_url(&self, key: &str, expires_secs: u64) -> Result<String, AppError> {
        self.presign("GET", key, expires_secs)
    }

    pub async fn put_object(&self, key: &str, data: &[u8]) -> Result<(), AppError> {
        let url = self.presigned_put_url(key, 900)?;
        let client = self.http.clone();
        let data = data.to_vec();

        with_retry("r2-put", 3, || {
            let url = url.clone();
            let client = client.clone();
            let body = data.clone();
            async move {
                let response = client
                    .put(url)
                    .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                    .body(body)
                    .send()
                    .await?;
                let status = response.status();
                if status.is_success() {
                    Ok(())
                } else {
                    let text = response.text().await.unwrap_or_default();
                    tracing::error!(http_status = %status, body = %truncate(&text, 512), "R2 upload failed");
                    Err(AppError::Storage(format!("R2 upload failed with status {status}")))
                }
            }
        })
        .await?;

        tracing::info!(key, "uploaded encrypted blob to R2");
        Ok(())
    }

    fn presign(&self, method: &str, key: &str, expires_secs: u64) -> Result<String, AppError> {
        validate_key(key)?;
        let expires_secs = expires_secs.clamp(60, 7 * 24 * 3600);

        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let scope = format!("{date_stamp}/{REGION}/{SERVICE}/aws4_request");
        let host = self.host();
        let canonical_uri = format!("/{}{}", self.bucket, uri_encode_keep_slash(&format!("/{key}")));

        let mut params: BTreeMap<&str, String> = BTreeMap::new();
        params.insert("X-Amz-Algorithm", "AWS4-HMAC-SHA256".into());
        params.insert("X-Amz-Credential", format!("{}/{}", self.access_key_id, scope));
        params.insert("X-Amz-Date", amz_date.clone());
        params.insert("X-Amz-Expires", expires_secs.to_string());
        params.insert("X-Amz-SignedHeaders", "host".into());

        let canonical_query = params
            .iter()
            .map(|(k, v)| format!("{}={}", uri_encode(k), uri_encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let canonical_request =
            format!("{method}\n{canonical_uri}\n{canonical_query}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD");

        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );

        let k_date = hmac_sha256(format!("AWS4{}", self.secret_access_key).as_bytes(), date_stamp.as_bytes())?;
        let k_region = hmac_sha256(&k_date, REGION.as_bytes())?;
        let k_service = hmac_sha256(&k_region, SERVICE.as_bytes())?;
        let k_signing = hmac_sha256(&k_service, b"aws4_request")?;
        let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes())?);

        Ok(format!(
            "https://{host}{canonical_uri}?{canonical_query}&X-Amz-Signature={signature}"
        ))
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, AppError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| AppError::Crypto("invalid HMAC key".into()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn uri_encode(value: &str) -> String {
    utf8_percent_encode(value, SIGV4_ESCAPE).to_string()
}

fn uri_encode_keep_slash(value: &str) -> String {
    utf8_percent_encode(value, SIGV4_ESCAPE_PATH).to_string()
}

fn validate_key(key: &str) -> Result<(), AppError> {
    if key.is_empty() || key.len() > 300 || key.starts_with('/') || key.contains("..") {
        return Err(AppError::Storage("invalid object key".into()));
    }
    if !key.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.')) {
        return Err(AppError::Storage("object key contains invalid characters".into()));
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Payload for the dispatch Worker.
#[derive(Debug, Serialize, Deserialize)] // <-- ADDED Deserialize
pub struct WorkerRegistration {
    pub delivery_id: String,
    pub delivery_token: String,
    pub recipient_name: String,
    pub recipient_email: String,
    pub scheduled_for: String,
    pub message_text: Option<String>,
    pub file_key: Option<String>,
    pub file_name: Option<String>,
    pub file_type: Option<String>,
    pub worker_dek: Option<String>,
    pub link_expires_at: Option<String>,
    pub link_max_views: Option<i64>,
    // Phase 2: Password-protected files
    pub claim_password_hash: Option<String>,
    pub claim_password_salt: Option<String>,
    pub claim_pw_wrapped_dek: Option<String>,
}

pub async fn register_delivery_with_worker(
    worker_url: &str,
    worker_secret: Option<&str>,
    registration: &WorkerRegistration,
) -> Result<(), AppError> {
    if !worker_url.starts_with("https://") {
        return Err(AppError::Config("DELIVERY_WORKER_URL must use HTTPS".into()));
    }
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| AppError::Config(format!("http client init failed: {e}")))?;

    let url = worker_url.trim_end_matches('/').to_string();
    let secret = worker_secret.map(|s| s.to_string());
    let payload =
        serde_json::to_vec(registration).map_err(|e| AppError::Internal(format!("serialize failed: {e}")))?;

    with_retry("worker-register", 3, || {
        let client = client.clone();
        let url = url.clone();
        let payload = payload.clone();
        let secret = secret.clone();
        async move {
            let mut req = client
                .post(&url)
                .header(reqwest::header::CONTENT_TYPE, "application/json");
            if let Some(s) = &secret {
                req = req.header("X-Worker-Secret", s);
            }
            let response = req.body(payload.clone()).send().await?;
            if response.status().is_success() {
                Ok(())
            } else {
                Err(AppError::Network(format!(
                    "delivery worker returned {}",
                    response.status()
                )))
            }
        }
    })
    .await
}