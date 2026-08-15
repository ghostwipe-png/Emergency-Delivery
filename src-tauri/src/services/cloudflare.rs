//! Cloudflare R2 (SigV4 presigned URLs) + Delivery Worker Registration.
//!
//! PRODUCTION-GRADE FEATURES:
//! - Zero-copy uploads using `bytes::Bytes` (prevents 50MB memory explosions on retries)
//! - Shared static HTTP client for Worker registration (connection pooling + TLS reuse)
//! - Smart retry logic (fails fast on 4xx, retries only on 5xx/network errors)
//! - Memory-safe secrets using `Zeroizing<String>`
//! - Strict SigV4 canonicalization (100% AWS S3 / R2 compliant)
//! - TCP keepalive and connection pool tuning
//!
//! @version 2.0.0
//! @status PRODUCTION

use std::collections::BTreeMap;
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::errors::AppError;

type HmacSha256 = Hmac<Sha256>;

const REGION: &str = "auto";
const SERVICE: &str = "s3";
const USER_AGENT: &str = "EmergencyDelivery/2.0 (Rust-Tauri)";

// SigV4 encoding sets (AWS strict requirements)
const SIGV4_ESCAPE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');
const SIGV4_ESCAPE_PATH: &AsciiSet = &SIGV4_ESCAPE.remove(b'/');

// =============================================================================
// SHARED HTTP CLIENT (Connection Pooling + TLS Reuse)
// =============================================================================

/// Global shared HTTP client for Worker registration.
/// Creating a new client per request destroys connection pooling and TLS session resumption.
/// This static client maintains a pool of idle connections for maximum performance.
static WORKER_HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .https_only(true)
        .use_rustls_tls()
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(5))
        .tcp_keepalive(Duration::from_secs(60))
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(90))
        .user_agent(USER_AGENT)
        .build()
        .expect("Failed to build shared worker HTTP client")
});

// =============================================================================
// R2 CLIENT (SigV4 Presigned URLs)
// =============================================================================

#[derive(Clone)]
pub struct R2Client {
    http: reqwest::Client,
    account_id: String,
    bucket: String,
    access_key_id: String,
    // SECURITY: Wrap secret in Zeroizing to prevent memory leaks
    secret_access_key: Zeroizing<String>,
}

impl R2Client {
    pub fn new(
        account_id: String,
        bucket: String,
        access_key_id: String,
        secret_access_key: String,
    ) -> Result<Self, AppError> {
        // Strict validation
        for (name, value) in [
            ("R2_ACCOUNT_ID", &account_id),
            ("R2_BUCKET", &bucket),
            ("R2_ACCESS_KEY_ID", &access_key_id),
            ("R2_SECRET_ACCESS_KEY", &secret_access_key),
        ] {
            if value.trim().is_empty() {
                return Err(AppError::Config(format!(
                    "{} is required for R2 storage",
                    name
                )));
            }
        }

        let http = reqwest::Client::builder()
            .https_only(true)
            .use_rustls_tls()
            .timeout(Duration::from_secs(120)) // 2 min for large file uploads
            .connect_timeout(Duration::from_secs(10))
            .tcp_keepalive(Duration::from_secs(60))
            .pool_max_idle_per_host(5)
            .user_agent(USER_AGENT)
            .build()
            .map_err(|e| AppError::Config(format!("R2 http client init failed: {e}")))?;

        Ok(Self {
            http,
            account_id,
            bucket,
            access_key_id,
            secret_access_key: Zeroizing::new(secret_access_key),
        })
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

    /// Uploads an encrypted blob to R2.
    ///
    /// # Performance
    /// Uses `bytes::Bytes` for zero-copy cloning. If a retry occurs, the 50MB buffer
    /// is NOT reallocated — only an Arc reference count is incremented.
    pub async fn put_object(&self, key: &str, data: &[u8]) -> Result<(), AppError> {
        let url = self.presigned_put_url(key, 900)?;
        
        // Zero-copy buffer: cloning this is O(1) and does not allocate memory
        let body = Bytes::copy_from_slice(data);

        let mut attempts = 0;
        let max_attempts = 3;
        let mut delay_ms = 500;

        loop {
            attempts += 1;
            let client = self.http.clone();
            let url_clone = url.clone();
            let body_clone = body.clone(); // O(1) clone

            let result = async move {
                // Handle network errors explicitly (no ? operator)
                let response = match client
                    .put(url_clone)
                    .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                    .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
                    .body(body_clone)
                    .send()
                    .await
                {
                    Ok(resp) => resp,
                    Err(e) => {
                        // Network error - treat as server error to trigger retry
                        return Err((
                            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Network error: {}", e)
                        ));
                    }
                };

                let status = response.status();
                if status.is_success() {
                    Ok(())
                } else {
                    let text = response.text().await.unwrap_or_default();
                    Err((status, text))
                }
            }
            .await;

            match result {
                Ok(()) => {
                    tracing::info!(key, "uploaded encrypted blob to R2");
                    return Ok(());
                }
                Err((status, text)) => {
                    // Smart retry: only retry on 5xx or network errors
                    if status.is_server_error() && attempts < max_attempts {
                        tracing::warn!(
                            attempt = attempts,
                            max_attempts,
                            http_status = %status,
                            "R2 upload failed (server error), retrying in {}ms",
                            delay_ms
                        );
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        delay_ms *= 2; // Exponential backoff
                        continue;
                    }

                    // Fail fast on 4xx (client error) or max attempts reached
                    tracing::error!(
                        http_status = %status,
                        body = %truncate(&text, 512),
                        "R2 upload failed permanently"
                    );
                    return Err(AppError::Storage(format!(
                        "R2 upload failed with status {}",
                        status
                    )));
                }
            }
        }
    }

    /// Generates a SigV4 presigned URL for R2 (S3-compatible).
    /// Strictly follows AWS Signature Version 4 specification.
    fn presign(&self, method: &str, key: &str, expires_secs: u64) -> Result<String, AppError> {
        validate_key(key)?;
        let expires_secs = expires_secs.clamp(60, 7 * 24 * 3600); // 1 min to 7 days

        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let scope = format!("{}/{}/{}/aws4_request", date_stamp, REGION, SERVICE);
        let host = self.host();
        
        // Canonical URI: /<bucket>/<key> (path-style for R2)
        let canonical_uri = format!(
            "/{}{}",
            self.bucket,
            uri_encode_keep_slash(&format!("/{}", key))
        );

        // Canonical Query String (must be sorted alphabetically)
        let mut params: BTreeMap<&str, String> = BTreeMap::new();
        params.insert("X-Amz-Algorithm", "AWS4-HMAC-SHA256".into());
        params.insert(
            "X-Amz-Credential",
            format!("{}/{}", self.access_key_id, scope),
        );
        params.insert("X-Amz-Date", amz_date.clone());
        params.insert("X-Amz-Expires", expires_secs.to_string());
        params.insert("X-Amz-SignedHeaders", "host".into());

        let canonical_query = params
            .iter()
            .map(|(k, v)| format!("{}={}", uri_encode(k), uri_encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        // Canonical Request
        let canonical_request = format!(
            "{}\n{}\n{}\nhost:{}\n\nhost\nUNSIGNED-PAYLOAD",
            method, canonical_uri, canonical_query, host
        );

        // String to Sign
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date,
            scope,
            sha256_hex(canonical_request.as_bytes())
        );

        // Signing Key Derivation
        let k_date = hmac_sha256(
            format!("AWS4{}", self.secret_access_key.as_str()).as_bytes(),
            date_stamp.as_bytes(),
        )?;
        let k_region = hmac_sha256(&k_date, REGION.as_bytes())?;
        let k_service = hmac_sha256(&k_region, SERVICE.as_bytes())?;
        let k_signing = hmac_sha256(&k_service, b"aws4_request")?;
        let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes())?);

        Ok(format!(
            "https://{}{}?{}&X-Amz-Signature={}",
            host, canonical_uri, canonical_query, signature
        ))
    }
}

// =============================================================================
// WORKER REGISTRATION
// =============================================================================

/// Payload for the dispatch Worker.
/// Must exactly match the TypeScript `Delivery` interface in the worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Registers a delivery with the Cloudflare Worker.
///
/// # Performance
/// Uses a shared static HTTP client (`WORKER_HTTP_CLIENT`) to leverage connection
/// pooling and TLS session resumption across multiple registrations.
///
/// # Smart Retry
/// - Retries on 5xx (server errors) and network timeouts
/// - Fails fast on 4xx (client errors like invalid JSON or auth failure)
pub async fn register_delivery_with_worker(
    worker_url: &str,
    worker_secret: Option<&str>,
    registration: &WorkerRegistration,
) -> Result<(), AppError> {
    // Strict URL validation
    if !worker_url.starts_with("https://") {
        return Err(AppError::Config(
            "DELIVERY_WORKER_URL must use HTTPS".into(),
        ));
    }

    let url = worker_url.trim_end_matches('/').to_string();
    let payload = serde_json::to_vec(registration)
        .map_err(|e| AppError::Internal(format!("serialize failed: {e}")))?;

    let mut attempts = 0;
    let max_attempts = 3;
    let mut delay_ms = 500;

    loop {
        attempts += 1;

        let mut req = WORKER_HTTP_CLIENT
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(payload.clone());

        if let Some(secret) = worker_secret {
            req = req.header("X-Worker-Secret", secret);
        }

        match req.send().await {
            Ok(response) => {
                let status = response.status();
                
                if status.is_success() {
                    return Ok(());
                }

                // Fail fast on 4xx (client error)
                if status.is_client_error() {
                    let text = response.text().await.unwrap_or_default();
                    tracing::error!(
                        http_status = %status,
                        body = %truncate(&text, 256),
                        "Worker registration failed (client error)"
                    );
                    return Err(AppError::Network(format!(
                        "delivery worker returned {} (client error)",
                        status
                    )));
                }

                // Retry on 5xx (server error)
                if attempts < max_attempts {
                    tracing::warn!(
                        attempt = attempts,
                        http_status = %status,
                        "Worker registration failed (server error), retrying in {}ms",
                        delay_ms
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms *= 2;
                    continue;
                }

                return Err(AppError::Network(format!(
                    "delivery worker returned {} after {} attempts",
                    status, attempts
                )));
            }
            Err(e) => {
                // Network error (timeout, DNS, connection refused)
                if attempts < max_attempts {
                    tracing::warn!(
                        attempt = attempts,
                        error = %e,
                        "Worker registration network error, retrying in {}ms",
                        delay_ms
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms *= 2;
                    continue;
                }

                return Err(AppError::Network(format!(
                    "worker network error after {} attempts: {}",
                    attempts, e
                )));
            }
        }
    }
}

// =============================================================================
// CRYPTOGRAPHIC & ENCODING HELPERS
// =============================================================================

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, AppError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| AppError::Crypto("invalid HMAC key".into()))?;
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
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
    {
        return Err(AppError::Storage(
            "object key contains invalid characters".into(),
        ));
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}