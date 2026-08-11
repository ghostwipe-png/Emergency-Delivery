//! Centralized error handling. Full details are logged server-side; messages
//! returned to the UI are deliberately sanitized (no stack traces, no SQL,
//! no credential material).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Authentication error: {0}")]
    Auth(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Database error: {0}")]
    Database(String),
    #[error("Encryption error: {0}")]
    Crypto(String),
    #[error("Payment error: {0}")]
    Payment(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

impl AppError {
    /// Transient errors that are safe to retry with exponential backoff.
    pub fn is_retryable(&self) -> bool {
        matches!(self, AppError::Network(_) | AppError::Storage(_))
    }
}

impl From<AppError> for tauri::ipc::InvokeError {
    fn from(err: AppError) -> Self {
        tauri::ipc::InvokeError::from(err.to_string())
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        match &err {
            sqlx::Error::RowNotFound => AppError::NotFound("record not found".into()),
            sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => {
                AppError::Database("database is busy, please retry".into())
            }
            other => {
                // Log the full detail server-side only.
                tracing::error!(error = %other, "database error");
                AppError::Database("database operation failed".into())
            }
        }
    }
}

impl From<reqwest::Error> for AppError {
    fn from(err: reqwest::Error) -> Self {
        tracing::warn!(error = %err, "http request failed");
        if err.is_timeout() {
            AppError::Network("request timed out".into())
        } else if err.is_connect() {
            AppError::Network("unable to reach remote service".into())
        } else {
            AppError::Network("network request failed".into())
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::Storage(format!("i/o error: {err}"))
    }
}

impl From<base64::DecodeError> for AppError {
    fn from(_: base64::DecodeError) -> Self {
        AppError::Crypto("invalid base64 data".into())
    }
}

impl From<hex::FromHexError> for AppError {
    fn from(_: hex::FromHexError) -> Self {
        AppError::Crypto("invalid hex data".into())
    }
}