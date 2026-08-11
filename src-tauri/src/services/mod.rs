//! Service infrastructure: circuit breaker, retry/backoff, storage abstraction.

pub mod cloudflare;
pub mod mobitech;
pub mod paystack;
pub mod chat;
pub mod social;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::errors::AppError;

pub struct CircuitBreaker {
    failures: AtomicU32,
    last_failure_ms: AtomicU64,
    threshold: u32,
    reset_timeout_ms: u64,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, reset_timeout: Duration) -> Self {
        Self {
            failures: AtomicU32::new(0),
            last_failure_ms: AtomicU64::new(0),
            threshold,
            reset_timeout_ms: reset_timeout.as_millis() as u64,
        }
    }

    pub fn allow_request(&self) -> bool {
        let failures = self.failures.load(Ordering::Acquire);
        if failures < self.threshold {
            return true;
        }
        let last = self.last_failure_ms.load(Ordering::Acquire);
        now_ms().saturating_sub(last) >= self.reset_timeout_ms
    }

    pub fn record_success(&self) {
        self.failures.store(0, Ordering::Release);
    }

    pub fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::AcqRel);
        self.last_failure_ms.store(now_ms(), Ordering::Release);
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub async fn with_retry<T, F, Fut>(operation: &str, attempts: u32, mut f: F) -> Result<T, AppError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, AppError>>,
{
    let mut delay = Duration::from_millis(400);
    let max = attempts.max(1);
    for attempt in 1..=max {
        match f().await {
            Ok(value) => return Ok(value),
            Err(err) if err.is_retryable() && attempt < max => {
                tracing::warn!(operation, attempt, error = %err, "retrying after transient failure");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(8));
            }
            Err(err) => return Err(err),
        }
    }
    Err(AppError::Internal("retry budget exhausted".into()))
}

#[derive(Clone)]
pub enum StorageBackend {
    Local { dir: PathBuf },
    R2(cloudflare::R2Client),
}

impl StorageBackend {
    pub fn name(&self) -> &'static str {
        match self {
            StorageBackend::Local { .. } => "local-vault",
            StorageBackend::R2(_) => "cloudflare-r2",
        }
    }

    pub async fn put(&self, key: &str, data: Vec<u8>) -> Result<(), AppError> {
        match self {
            StorageBackend::Local { dir } => {
                let dir = dir.clone();
                let key = key.to_string();
                tokio::task::spawn_blocking(move || write_local(&dir, &key, data))
                    .await
                    .map_err(|_| AppError::Internal("storage task join failed".into()))?
            }
            StorageBackend::R2(client) => client.put_object(key, &data).await,
        }
    }

    pub fn presigned_put_url(&self, key: &str, expires_secs: u64) -> Result<String, AppError> {
        match self {
            StorageBackend::Local { .. } => {
                Err(AppError::Storage("presigned uploads require Cloudflare R2 configuration".into()))
            }
            StorageBackend::R2(client) => client.presigned_put_url(key, expires_secs),
        }
    }

    pub fn presigned_get_url(&self, key: &str, expires_secs: u64) -> Result<String, AppError> {
        match self {
            StorageBackend::Local { .. } => {
                Err(AppError::Storage("presigned downloads require Cloudflare R2 configuration".into()))
            }
            StorageBackend::R2(client) => client.presigned_get_url(key, expires_secs),
        }
    }

    /// Downloads the encrypted blob from Storage (Local vault or Cloudflare R2).
    pub async fn get(&self, key: &str) -> Result<Vec<u8>, AppError> {
        match self {
            StorageBackend::Local { dir } => {
                let dir = dir.clone();
                let key = key.to_string();
                tokio::task::spawn_blocking(move || {
                    let path = safe_path(&dir, &key)?;
                    if !path.exists() {
                        return Err(AppError::Storage("file not found in local vault".into()));
                    }
                    std::fs::read(&path).map_err(|e| AppError::Storage(format!("cannot read local file: {e}")))
                })
                .await
                .map_err(|_| AppError::Internal("storage task join failed".into()))?
            }
            StorageBackend::R2(client) => {
                let url = client.presigned_get_url(key, 60)?;
                let resp = reqwest::get(&url)
                    .await
                    .map_err(|e| AppError::Network(format!("R2 fetch failed: {e}")))?;
                if !resp.status().is_success() {
                    return Err(AppError::Storage(format!("R2 download failed with status {}", resp.status())));
                }
                resp.bytes()
                    .await
                    .map(|b| b.to_vec())
                    .map_err(|e| AppError::Network(format!("R2 read failed: {e}")))
            }
        }
    }

    pub async fn delete(&self, key: &str) -> Result<(), AppError> {
        match self {
            StorageBackend::Local { dir } => {
                let dir = dir.clone();
                let key = key.to_string();
                tokio::task::spawn_blocking(move || {
                    let path = safe_path(&dir, &key)?;
                    if path.exists() {
                        std::fs::remove_file(&path).map_err(|e| {
                            AppError::Storage(format!("cannot delete local file: {e}"))
                        })?;
                        tracing::info!(key = %key, "deleted encrypted blob from local vault");
                    }
                    Ok(())
                })
                .await
                .map_err(|_| AppError::Internal("storage task join failed".into()))?
            }
            StorageBackend::R2(_client) => {
                // TODO: Implement aws_sdk_s3 delete_object for R2 in Phase 7.
                // For now, we rely on crypto-shredding (KEK destruction) for GDPR compliance.
                tracing::warn!(key = %key, "R2 physical deletion pending implementation; relying on crypto-shredding");
                Ok(())
            }
        }
    }
}

fn write_local(dir: &Path, key: &str, data: Vec<u8>) -> Result<(), AppError> {
    let path = safe_path(dir, key)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| AppError::Storage(format!("cannot create storage dir: {e}")))?;
    }
    std::fs::write(&path, data).map_err(|e| AppError::Storage(format!("cannot write file: {e}")))?;
    tracing::info!(key, "stored encrypted blob in local vault");
    Ok(())
}

fn safe_path(base: &Path, key: &str) -> Result<PathBuf, AppError> {
    if key.is_empty() || key.len() > 300 || key.starts_with('/') || key.contains("..") || key.contains('\\') {
        return Err(AppError::Storage("invalid storage key".into()));
    }
    if !key.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.')) {
        return Err(AppError::Storage("invalid storage key".into()));
    }
    Ok(base.join(key))
}