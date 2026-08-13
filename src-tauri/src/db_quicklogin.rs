//! Standalone Database Layer for Trusted Device Quick Login
//!
//! # ARCHITECTURE
//! This module provides database operations for the Quick Login feature, which
//! allows users to unlock the app with a favorite word instead of their password
//! on trusted devices.
//!
//! # SECURITY MODEL
//! - `device_id`: SHA-256 hash of the device secret (one-way, safe to store)
//! - `quick_salt`: Per-record random salt for PBKDF2 key derivation
//! - `encrypted_kek`: User's KEK wrapped with AES-256-GCM (key derived from word + device_secret + salt)
//! - `failed_attempts`: Rate limiting counter to prevent brute-force attacks
//! - `locked_until`: Timestamp when lock expires (NULL if not locked)
//!
//! # ISOLATION
//! This module is completely isolated from `db/mod.rs` to avoid touching the
//! core authentication schema. It operates on its own `trusted_devices` table.
//!
//! @version 1.1.4

use chrono::{DateTime, Utc};
use tracing::{debug, error, info, warn, instrument};

use crate::db::DbPool;
use crate::errors::AppError;

// =============================================================================
// CONSTANTS
// =============================================================================

/// Maximum allowed length for device_id (SHA-256 hex = 64 chars).
const MAX_DEVICE_ID_LENGTH: usize = 64;

/// Maximum allowed length for user_id (UUID format).
const MAX_USER_ID_LENGTH: usize = 64;

/// Maximum allowed length for quick_salt (hex-encoded, typically 32 chars).
const MAX_QUICK_SALT_LENGTH: usize = 128;

/// Maximum allowed length for encrypted_kek (AES-GCM encrypted hex string).
const MAX_ENCRYPTED_KEK_LENGTH: usize = 512;

// =============================================================================
// DATA MODELS
// =============================================================================

/// Database row representing a trusted device for quick login.
#[derive(sqlx::FromRow, serde::Serialize, Clone, Debug)]
pub struct TrustedDeviceRow {
    /// SHA-256 hash of the device secret (one-way identifier).
    pub device_id: String,
    /// User ID (foreign key to users table).
    pub user_id: String,
    /// Hex-encoded random salt for PBKDF2 key derivation.
    pub quick_salt: String,
    /// AES-256-GCM encrypted KEK (wrapped with key derived from word + device_secret + salt).
    pub encrypted_kek: String,
    /// ISO 8601 timestamp when this device was first registered.
    pub created_at: String,
    /// ISO 8601 timestamp of last successful quick login (NULL if never used).
    pub last_used_at: Option<String>,
    /// Number of consecutive failed quick login attempts (resets on success or lock expiry).
    pub failed_attempts: i64,
    /// ISO 8601 timestamp when lock expires (NULL if not locked).
    pub locked_until: Option<String>,
}

// =============================================================================
// INPUT VALIDATION HELPERS
// =============================================================================

/// Validates device_id format and length.
fn validate_device_id(device_id: &str) -> Result<(), AppError> {
    if device_id.is_empty() {
        return Err(AppError::Validation("device_id cannot be empty".into()));
    }
    
    if device_id.len() > MAX_DEVICE_ID_LENGTH {
        return Err(AppError::Validation(
            format!("device_id exceeds maximum length of {} characters", MAX_DEVICE_ID_LENGTH).into()
        ));
    }
    
    // SHA-256 hex format validation
    if !device_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::Validation("device_id must be hexadecimal".into()));
    }
    
    Ok(())
}

/// Validates user_id format and length.
fn validate_user_id(user_id: &str) -> Result<(), AppError> {
    if user_id.is_empty() {
        return Err(AppError::Validation("user_id cannot be empty".into()));
    }
    
    if user_id.len() > MAX_USER_ID_LENGTH {
        return Err(AppError::Validation(
            format!("user_id exceeds maximum length of {} characters", MAX_USER_ID_LENGTH).into()
        ));
    }
    
    // UUID format validation (basic check)
    if !user_id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return Err(AppError::Validation("user_id contains invalid characters".into()));
    }
    
    Ok(())
}

/// Validates quick_salt format and length.
fn validate_quick_salt(quick_salt: &str) -> Result<(), AppError> {
    if quick_salt.is_empty() {
        return Err(AppError::Validation("quick_salt cannot be empty".into()));
    }
    
    if quick_salt.len() > MAX_QUICK_SALT_LENGTH {
        return Err(AppError::Validation(
            format!("quick_salt exceeds maximum length of {} characters", MAX_QUICK_SALT_LENGTH).into()
        ));
    }
    
    // Hex format validation
    if !quick_salt.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::Validation("quick_salt must be hexadecimal".into()));
    }
    
    Ok(())
}

/// Validates encrypted_kek format and length.
fn validate_encrypted_kek(encrypted_kek: &str) -> Result<(), AppError> {
    if encrypted_kek.is_empty() {
        return Err(AppError::Validation("encrypted_kek cannot be empty".into()));
    }
    
    if encrypted_kek.len() > MAX_ENCRYPTED_KEK_LENGTH {
        return Err(AppError::Validation(
            format!("encrypted_kek exceeds maximum length of {} characters", MAX_ENCRYPTED_KEK_LENGTH).into()
        ));
    }
    
    // Format: v1:base64_nonce:base64_ciphertext
    let parts: Vec<&str> = encrypted_kek.split(':').collect();
    if parts.len() != 3 || parts[0] != "v1" {
        return Err(AppError::Validation("encrypted_kek has invalid format (expected v1:nonce:ciphertext)".into()));
    }
    
    Ok(())
}

// =============================================================================
// MIGRATIONS
// =============================================================================

/// Runs database migrations to create the `trusted_devices` table.
/// 
/// This function is idempotent and safe to run on every application startup.
/// It uses transactions to ensure atomicity.
/// 
/// # Security
/// - Foreign key constraint ensures trusted devices are deleted when user is deleted
/// - Composite primary key (device_id, user_id) prevents duplicates
/// - Index on user_id for efficient queries
#[instrument(skip(pool), fields(operation = "run_quicklogin_migrations"))]
pub async fn run_quicklogin_migrations(pool: &DbPool) -> Result<(), AppError> {
    info!("Running quick login migrations");
    
    let statements: &[&str] = &[
        "CREATE TABLE IF NOT EXISTS trusted_devices (
            device_id TEXT NOT NULL,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            quick_salt TEXT NOT NULL,
            encrypted_kek TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            PRIMARY KEY (device_id, user_id)
        )",
        "CREATE INDEX IF NOT EXISTS idx_trusted_devices_user ON trusted_devices(user_id)",
    ];
    
    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, "Failed to begin transaction for migrations");
        AppError::Internal(format!("Failed to begin migration transaction: {}", e).into())
    })?;
    
    for (idx, stmt) in statements.iter().enumerate() {
        sqlx::query(stmt).execute(&mut *tx).await.map_err(|e| {
            error!(error = %e, statement_index = idx, "Failed to execute migration statement");
            AppError::Internal(format!("Migration statement {} failed: {}", idx, e).into())
        })?;
        debug!(statement_index = idx, "Executed migration statement");
    }
    
    tx.commit().await.map_err(|e| {
        error!(error = %e, "Failed to commit migration transaction");
        AppError::Internal(format!("Failed to commit migrations: {}", e).into())
    })?;
    
    info!("Quick login migrations completed successfully");
    Ok(())
}

// =============================================================================
// CRUD OPERATIONS
// =============================================================================

/// Creates or updates a trusted device record.
/// 
/// Resets failed_attempts to 0 and locked_until to NULL on (re)setup.
/// This is called when a user enables or reconfigures quick login.
/// 
/// # Security
/// - Validates all inputs before database operation
/// - Uses UPSERT to prevent race conditions
/// - Automatically clears lock and failed attempts on setup
#[instrument(skip(pool, quick_salt, encrypted_kek), fields(operation = "upsert_trusted_device", device_id = %device_id, user_id = %user_id))]
pub async fn upsert_trusted_device(
    pool: &DbPool,
    device_id: &str,
    user_id: &str,
    quick_salt: &str,
    encrypted_kek: &str,
) -> Result<(), AppError> {
    debug!("Upserting trusted device");
    
    // Validate inputs
    validate_device_id(device_id)?;
    validate_user_id(user_id)?;
    validate_quick_salt(quick_salt)?;
    validate_encrypted_kek(encrypted_kek)?;
    
    let now = Utc::now();
    
    sqlx::query(
        "INSERT INTO trusted_devices (device_id, user_id, quick_salt, encrypted_kek, created_at, failed_attempts, locked_until)
         VALUES (?, ?, ?, ?, ?, 0, NULL)
         ON CONFLICT(device_id, user_id) DO UPDATE SET
            quick_salt = excluded.quick_salt,
            encrypted_kek = excluded.encrypted_kek,
            failed_attempts = 0,
            locked_until = NULL"
    )
    .bind(device_id)
    .bind(user_id)
    .bind(quick_salt)
    .bind(encrypted_kek)
    .bind(now)
    .execute(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to upsert trusted device");
        AppError::Internal(format!("Failed to upsert trusted device: {}", e).into())
    })?;
    
    info!("Trusted device upserted successfully");
    Ok(())
}

/// Retrieves a trusted device record by device_id and user_id.
/// 
/// Returns None if no record exists for this device/user combination.
/// 
/// # Security
/// - Validates device_id and user_id format before query
/// - Returns None (not error) if record doesn't exist (prevents enumeration)
#[instrument(skip(pool), fields(operation = "get_trusted_device", device_id = %device_id, user_id = %user_id))]
pub async fn get_trusted_device(
    pool: &DbPool,
    device_id: &str,
    user_id: &str,
) -> Result<Option<TrustedDeviceRow>, AppError> {
    debug!("Retrieving trusted device");
    
    // Validate inputs
    validate_device_id(device_id)?;
    validate_user_id(user_id)?;
    
    let row = sqlx::query_as::<_, TrustedDeviceRow>(
        "SELECT device_id, user_id, quick_salt, encrypted_kek, created_at, last_used_at, failed_attempts, locked_until
         FROM trusted_devices 
         WHERE device_id = ? AND user_id = ?"
    )
    .bind(device_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to query trusted device");
        AppError::Internal(format!("Failed to query trusted device: {}", e).into())
    })?;
    
    if row.is_some() {
        debug!("Trusted device found");
    } else {
        debug!("Trusted device not found");
    }
    
    Ok(row)
}

/// Increments the failed_attempts counter for a trusted device.
/// 
/// Returns the new failed_attempts count after incrementing.
/// Used to track brute-force attempts and trigger lockout.
/// 
/// # Security
/// - Validates device_id and user_id format before update
/// - Returns 0 if record doesn't exist (prevents enumeration)
/// - Atomic increment to prevent race conditions
#[instrument(skip(pool), fields(operation = "record_failed_attempt", device_id = %device_id, user_id = %user_id))]
pub async fn record_failed_attempt(
    pool: &DbPool,
    device_id: &str,
    user_id: &str,
) -> Result<i64, AppError> {
    debug!("Recording failed quick login attempt");
    
    // Validate inputs
    validate_device_id(device_id)?;
    validate_user_id(user_id)?;
    
    // Increment failed_attempts
    sqlx::query("UPDATE trusted_devices SET failed_attempts = failed_attempts + 1 WHERE device_id = ? AND user_id = ?")
        .bind(device_id)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to increment failed_attempts");
            AppError::Internal(format!("Failed to record failed attempt: {}", e).into())
        })?;
    
    // Fetch new count
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT failed_attempts FROM trusted_devices WHERE device_id = ? AND user_id = ?"
    )
    .bind(device_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch failed_attempts count");
        AppError::Internal(format!("Failed to fetch failed attempts: {}", e).into())
    })?;
    
    let attempts = row.map(|(n,)| n).unwrap_or(0);
    warn!(attempts, "Failed quick login attempt recorded");
    
    Ok(attempts)
}

/// Locks a device until a specified timestamp (rate limiting).
/// 
/// Sets the `locked_until` field to prevent further quick login attempts
/// until the lock expires.
/// 
/// # Security
/// - Validates device_id and user_id format before update
/// - Timestamp is stored in ISO 8601 format for consistency
#[instrument(skip(pool), fields(operation = "lock_device", device_id = %device_id, user_id = %user_id, until = %until))]
pub async fn lock_device(
    pool: &DbPool,
    device_id: &str,
    user_id: &str,
    until: DateTime<Utc>,
) -> Result<(), AppError> {
    warn!(lock_until = %until, "Locking device due to too many failed attempts");
    
    // Validate inputs
    validate_device_id(device_id)?;
    validate_user_id(user_id)?;
    
    sqlx::query("UPDATE trusted_devices SET locked_until = ? WHERE device_id = ? AND user_id = ?")
        .bind(until)
        .bind(device_id)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to lock device");
            AppError::Internal(format!("Failed to lock device: {}", e).into())
        })?;
    
    info!("Device locked successfully");
    Ok(())
}

/// Clears failed attempts and lock, and updates last_used_at timestamp.
/// 
/// Called after a successful quick login to reset the device's security state.
/// 
/// # Security
/// - Validates device_id and user_id format before update
/// - Sets failed_attempts to 0
/// - Sets locked_until to NULL (unlocks device)
/// - Updates last_used_at to current timestamp
#[instrument(skip(pool), fields(operation = "clear_failed_attempts", device_id = %device_id, user_id = %user_id))]
pub async fn clear_failed_attempts(
    pool: &DbPool,
    device_id: &str,
    user_id: &str,
) -> Result<(), AppError> {
    debug!("Clearing failed attempts and updating last_used_at");
    
    // Validate inputs
    validate_device_id(device_id)?;
    validate_user_id(user_id)?;
    
    let now = Utc::now();
    
    sqlx::query("UPDATE trusted_devices SET failed_attempts = 0, locked_until = NULL, last_used_at = ? WHERE device_id = ? AND user_id = ?")
        .bind(now)
        .bind(device_id)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to clear failed attempts");
            AppError::Internal(format!("Failed to clear failed attempts: {}", e).into())
        })?;
    
    info!("Failed attempts cleared successfully");
    Ok(())
}

/// Resets failed attempts and lock without updating last_used_at.
/// 
/// Called when a lock expires to give the device a fresh set of attempts
/// without marking it as "used" (since no successful login occurred).
/// 
/// # Security
/// - Validates device_id and user_id format before update
/// - Sets failed_attempts to 0
/// - Sets locked_until to NULL (unlocks device)
/// - Does NOT update last_used_at (preserves last successful login time)
#[instrument(skip(pool), fields(operation = "reset_failed_attempts", device_id = %device_id, user_id = %user_id))]
pub async fn reset_failed_attempts(
    pool: &DbPool,
    device_id: &str,
    user_id: &str,
) -> Result<(), AppError> {
    debug!("Resetting failed attempts after lock expiry");
    
    // Validate inputs
    validate_device_id(device_id)?;
    validate_user_id(user_id)?;
    
    sqlx::query("UPDATE trusted_devices SET failed_attempts = 0, locked_until = NULL WHERE device_id = ? AND user_id = ?")
        .bind(device_id)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to reset failed attempts");
            AppError::Internal(format!("Failed to reset failed attempts: {}", e).into())
        })?;
    
    info!("Failed attempts reset successfully");
    Ok(())
}

/// Removes a trusted device record (user opts out of quick login).
/// 
/// Returns true if a record was deleted, false if no record existed.
/// 
/// # Security
/// - Validates device_id and user_id format before delete
/// - Returns boolean instead of error if record doesn't exist (prevents enumeration)
#[instrument(skip(pool), fields(operation = "delete_trusted_device", device_id = %device_id, user_id = %user_id))]
pub async fn delete_trusted_device(
    pool: &DbPool,
    device_id: &str,
    user_id: &str,
) -> Result<bool, AppError> {
    info!("Deleting trusted device");
    
    // Validate inputs
    validate_device_id(device_id)?;
    validate_user_id(user_id)?;
    
    let result = sqlx::query("DELETE FROM trusted_devices WHERE device_id = ? AND user_id = ?")
        .bind(device_id)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to delete trusted device");
            AppError::Internal(format!("Failed to delete trusted device: {}", e).into())
        })?;
    
    let deleted = result.rows_affected() == 1;
    
    if deleted {
        info!("Trusted device deleted successfully");
    } else {
        debug!("No trusted device found to delete");
    }
    
    Ok(deleted)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().unwrap()
    }

    async fn test_pool() -> DbPool {
        // trusted_devices references users(id), so we create a minimal users table too.
        let options = SqliteConnectOptions::from_str("sqlite::memory:").unwrap();
        let pool = SqlitePoolOptions::new().connect_with(options).await.unwrap();
        sqlx::query("CREATE TABLE users (id TEXT PRIMARY KEY)").execute(&pool).await.unwrap();
        pool
    }

    #[test]
    fn quicklogin_lifecycle() {
        runtime().block_on(async {
            let pool = test_pool().await;
            run_quicklogin_migrations(&pool).await.unwrap();

            sqlx::query("INSERT INTO users (id) VALUES ('u1')").execute(&pool).await.unwrap();

            // Test upsert
            upsert_trusted_device(&pool, "a".repeat(64).as_str(), "u1", "b".repeat(32).as_str(), "v1:abc:def").await.unwrap();
            let dev = get_trusted_device(&pool, "a".repeat(64).as_str(), "u1").await.unwrap().unwrap();
            assert_eq!(dev.quick_salt, "b".repeat(32));
            assert_eq!(dev.failed_attempts, 0);
            assert!(dev.locked_until.is_none());

            // Test failed attempts increment
            let n = record_failed_attempt(&pool, "a".repeat(64).as_str(), "u1").await.unwrap();
            assert_eq!(n, 1);

            // Test lock
            let lock_time = Utc::now() + chrono::Duration::minutes(15);
            lock_device(&pool, "a".repeat(64).as_str(), "u1", lock_time).await.unwrap();
            let dev = get_trusted_device(&pool, "a".repeat(64).as_str(), "u1").await.unwrap().unwrap();
            assert!(dev.locked_until.is_some());

            // Test clear
            clear_failed_attempts(&pool, "a".repeat(64).as_str(), "u1").await.unwrap();
            let dev = get_trusted_device(&pool, "a".repeat(64).as_str(), "u1").await.unwrap().unwrap();
            assert_eq!(dev.failed_attempts, 0);
            assert!(dev.locked_until.is_none());
            assert!(dev.last_used_at.is_some());

            // Test reset
            record_failed_attempt(&pool, "a".repeat(64).as_str(), "u1").await.unwrap();
            reset_failed_attempts(&pool, "a".repeat(64).as_str(), "u1").await.unwrap();
            let dev = get_trusted_device(&pool, "a".repeat(64).as_str(), "u1").await.unwrap().unwrap();
            assert_eq!(dev.failed_attempts, 0);

            // Test delete
            assert!(delete_trusted_device(&pool, "a".repeat(64).as_str(), "u1").await.unwrap());
            assert!(get_trusted_device(&pool, "a".repeat(64).as_str(), "u1").await.unwrap().is_none());
        });
    }

    #[test]
    fn input_validation() {
        runtime().block_on(async {
            let pool = test_pool().await;
            run_quicklogin_migrations(&pool).await.unwrap();

            // Test empty device_id
            let result = get_trusted_device(&pool, "", "u1").await;
            assert!(result.is_err());

            // Test invalid device_id format
            let result = get_trusted_device(&pool, "not-hex", "u1").await;
            assert!(result.is_err());

            // Test empty user_id
            let result = get_trusted_device(&pool, "a".repeat(64).as_str(), "").await;
            assert!(result.is_err());

            // Test invalid quick_salt
            let result = upsert_trusted_device(&pool, "a".repeat(64).as_str(), "u1", "not-hex", "v1:abc:def").await;
            assert!(result.is_err());

            // Test invalid encrypted_kek format
            let result = upsert_trusted_device(&pool, "a".repeat(64).as_str(), "u1", "b".repeat(32).as_str(), "invalid").await;
            assert!(result.is_err());
        });
    }
}