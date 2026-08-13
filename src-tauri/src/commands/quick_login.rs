//! Quick Login Commands — Production-Grade Device-Bound Authentication
//!
//! # SECURITY POSTURE
//! - Device-bound KEK wrapping prevents credential theft
//! - Rate limiting prevents brute-force attacks
//! - Comprehensive audit logging for security events
//! - Memory-safe handling of cryptographic material
//! - Input validation prevents injection attacks
//!
//! # RESILIENCE FEATURES
//! - Structured error handling with detailed context
//! - Audit trail for all authentication events
//! - Graceful degradation on database failures
//! - Memory-safe cryptographic operations
//! - File-based fallback for device secret persistence
//!
//! @version 1.1.4

use chrono::{DateTime, Duration, Utc};
use tauri::State;
use tracing::{debug, error, info, warn, instrument};

use crate::commands::require_session;
use crate::crypto;
use crate::db;
use crate::db_quicklogin;
use crate::errors::AppError;
use crate::quick_login;
use crate::AppState;

// =============================================================================
// CONSTANTS
// =============================================================================

/// Session lifetime granted by a successful quick login (30 days).
const QUICK_SESSION_DAYS: i64 = 30;

/// Maximum allowed length for user_id to prevent DoS via long strings.
const MAX_USER_ID_LENGTH: usize = 64;

/// Maximum allowed length for favorite_word (enforced by core module, but double-check here).
const MAX_FAVORITE_WORD_LENGTH: usize = 15;

// =============================================================================
// RESPONSE TYPES
// =============================================================================

/// Account information for quick login status display.
#[derive(serde::Serialize, Debug)]
pub struct QuickLoginAccount {
    pub user_id: String,
    pub email: String,
    pub name: Option<String>,
    pub locked: bool,
    pub locked_until: Option<String>,
}

/// Successful quick login response containing session token and user info.
#[derive(serde::Serialize, Debug)]
pub struct QuickLoginResponse {
    pub token: String,
    pub user_id: String,
    pub email: String,
    pub name: Option<String>,
}

// =============================================================================
// INPUT VALIDATION HELPERS
// =============================================================================

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

/// Validates favorite_word length (core module does detailed validation).
fn validate_favorite_word_length(word: &str) -> Result<(), AppError> {
    if word.len() > MAX_FAVORITE_WORD_LENGTH {
        return Err(AppError::Validation(
            format!("favorite word exceeds maximum length of {} characters", MAX_FAVORITE_WORD_LENGTH).into()
        ));
    }
    Ok(())
}

// =============================================================================
// COMMANDS
// =============================================================================

/// Retrieves quick login status for the current device.
/// 
/// Called on the login screen (no session yet). Lists accounts with quick login
/// enabled on THIS device, so the UI can show "Welcome back, ...".
/// 
/// # Security
/// - Device secret is loaded from OS keychain (with file fallback)
/// - Only returns accounts for THIS device (device_id match)
/// - Locked accounts are flagged but still returned (UI handles lockout display)
#[tauri::command]
#[instrument(skip(state), fields(operation = "get_quick_login_status"))]
pub async fn get_quick_login_status(
    state: State<'_, AppState>,
) -> Result<Vec<QuickLoginAccount>, AppError> {
    info!("Retrieving quick login status");
    
    // Load device secret from OS keychain (with file fallback)
    let device_secret = match quick_login::get_or_create_device_secret(&state.data_dir) {
        Ok(secret) => secret,
        Err(e) => {
            error!(error = %e, "Failed to load device secret");
            return Err(e);
        }
    };
    
    let device_id = quick_login::device_id_from_secret(&device_secret);
    debug!(device_id = %device_id, "Loaded device identifier");

    // Query trusted devices for this device
    let rows: Vec<(String, String, Option<String>, i64, Option<String>)> = sqlx::query_as(
        "SELECT td.user_id, u.email, u.name, td.failed_attempts, td.locked_until
         FROM trusted_devices td 
         JOIN users u ON u.id = td.user_id
         WHERE td.device_id = ?"
    )
    .bind(&device_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        error!(error = %e, "Database query failed while fetching trusted devices");
        AppError::Internal(format!("Failed to query trusted devices: {}", e).into())
    })?;

    let now = Utc::now();
    let accounts: Vec<QuickLoginAccount> = rows
        .into_iter()
        .map(|(user_id, email, name, _attempts, locked_until)| {
            let locked = locked_until
                .as_deref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|until| now < until.with_timezone(&Utc))
                .unwrap_or(false);
            
            QuickLoginAccount {
                user_id,
                email,
                name,
                locked,
                locked_until,
            }
        })
        .collect();

    info!(count = accounts.len(), "Retrieved quick login accounts");
    Ok(accounts)
}

/// Sets up quick login for the current user on this device.
/// 
/// Called after a normal login. Sets the favorite word and stores the wrapped KEK.
/// 
/// # Security
/// - Validates favorite word against strict rules
/// - Derives encryption key from (word + device_secret + salt)
/// - Wraps KEK with AES-256-GCM (authenticated encryption)
/// - Stores wrapped KEK in database (cannot be unwrapped without word + device)
#[tauri::command]
#[instrument(skip(state, session_token, favorite_word), fields(operation = "setup_quick_login"))]
pub async fn setup_quick_login(
    state: State<'_, AppState>,
    session_token: String,
    favorite_word: String,
) -> Result<(), AppError> {
    info!("Setting up quick login");
    
    // Validate session
    let user = require_session(&state, &session_token).await?;
    
    // Get current KEK (must be logged in)
    let kek = state.current_kek()?;

    // Validate favorite word
    let word = favorite_word.trim().to_string();
    validate_favorite_word_length(&word)?;
    quick_login::validate_favorite_word(&word)?;
    
    debug!(user_id = %user.id, "Validated favorite word");

    // Load device secret from OS keychain (with file fallback)
    let device_secret = quick_login::get_or_create_device_secret(&state.data_dir)?;
    let device_id = quick_login::device_id_from_secret(&device_secret);
    debug!(device_id = %device_id, "Loaded device identifier");
    
    // Generate per-record salt
    let quick_salt = crypto::random_salt();
    debug!("Generated random salt for KEK wrapping");

    // Derive quick-unlock key from (word + device_secret + salt)
    let key = quick_login::derive_quick_key(&word, &quick_salt, &device_secret)
        .map_err(|e| {
            error!(error = %e, "Failed to derive quick-unlock key");
            e
        })?;
    
    // Wrap KEK with quick-unlock key
    let encrypted_kek = quick_login::wrap_kek(&*key, &*kek)
        .map_err(|e| {
            error!(error = %e, "Failed to wrap KEK");
            e
        })?;
    
    debug!("Successfully wrapped KEK");

    // Store in database
    db_quicklogin::upsert_trusted_device(
        &state.db,
        &device_id,
        &user.id,
        &hex::encode(quick_salt),
        &encrypted_kek,
    )
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %user.id, "Failed to store trusted device in database");
        AppError::Internal(format!("Failed to store quick login setup: {}", e).into())
    })?;

    info!(user_id = %user.id, "Quick login setup complete");
    Ok(())
}

/// Performs quick login using favorite word (no email/password needed).
/// 
/// # Security
/// - Validates user_id format
/// - Enforces rate limiting (locks device after N failed attempts)
/// - Derives key and unwraps KEK (AES-GCM auth tag verifies correctness)
/// - Clears failed attempts on success
/// - Logs all authentication events for audit trail
#[tauri::command]
#[instrument(skip(state, favorite_word), fields(operation = "quick_login", user_id = %user_id))]
pub async fn quick_login(
    state: State<'_, AppState>,
    user_id: String,
    favorite_word: String,
) -> Result<QuickLoginResponse, AppError> {
    info!(user_id = %user_id, "Attempting quick login");
    
    // Validate user_id
    validate_user_id(&user_id)?;
    
    // Load device secret from OS keychain (with file fallback)
    let device_secret = quick_login::get_or_create_device_secret(&state.data_dir)?;
    let device_id = quick_login::device_id_from_secret(&device_secret);
    debug!(device_id = %device_id, "Loaded device identifier");

    // Fetch trusted device record
    let device = db_quicklogin::get_trusted_device(&state.db, &device_id, &user_id)
        .await
        .map_err(|e| {
            error!(error = %e, user_id = %user_id, "Database query failed");
            AppError::Internal(format!("Failed to query trusted device: {}", e).into())
        })?
        .ok_or_else(|| {
            warn!(user_id = %user_id, "Quick login not set up for this user on this device");
            AppError::Auth("Quick login is not set up on this device".into())
        })?;

    // Enforce rate-limit lock
    if let Some(ref locked_str) = device.locked_until {
        if let Ok(until_fixed) = DateTime::parse_from_rfc3339(locked_str) {
            let until_utc = until_fixed.with_timezone(&Utc);
            if Utc::now() < until_utc {
                let remaining = until_utc - Utc::now();
                warn!(
                    user_id = %user_id,
                    remaining_minutes = remaining.num_minutes(),
                    "Quick login attempt blocked due to rate limit"
                );
                return Err(AppError::Auth(
                    format!(
                        "Too many failed attempts. Try again in {} minutes.",
                        remaining.num_minutes() + 1
                    )
                    .into(),
                ));
            }
            
            // Lock expired: reset failed attempts
            db_quicklogin::reset_failed_attempts(&state.db, &device_id, &user_id)
                .await
                .map_err(|e| {
                    error!(error = %e, "Failed to reset failed attempts after lock expiry");
                    AppError::Internal(format!("Failed to reset lock: {}", e).into())
                })?;
            
            info!(user_id = %user_id, "Lock expired, resetting failed attempts");
        }
    }

    // Decode salt
    let quick_salt = hex::decode(&device.quick_salt)
        .map_err(|_| {
            error!(user_id = %user_id, "Invalid hex encoding in quick_salt");
            AppError::Crypto("Invalid quick salt encoding".into())
        })?;
    
    let word = favorite_word.trim().to_string();

    // Derive quick-unlock key
    let key = quick_login::derive_quick_key(&word, &quick_salt, &device_secret)
        .map_err(|e| {
            error!(error = %e, user_id = %user_id, "Failed to derive quick-unlock key");
            e
        })?;
    
    // Attempt to unwrap KEK (AES-GCM auth tag verifies correctness)
    let kek = match quick_login::unwrap_kek(&*key, &device.encrypted_kek) {
        Ok(k) => {
            info!(user_id = %user_id, "KEK unwrapped successfully");
            k
        }
        Err(e) => {
            // Record failed attempt
            let attempts = db_quicklogin::record_failed_attempt(&state.db, &device_id, &user_id)
                .await
                .unwrap_or(0);
            
            warn!(
                user_id = %user_id,
                attempts,
                error = %e,
                "Quick login failed: incorrect favorite word"
            );
            
            // Check if we should lock the device
            if attempts >= quick_login::MAX_FAILED_ATTEMPTS {
                let until = Utc::now() + Duration::minutes(quick_login::LOCK_MINUTES);
                db_quicklogin::lock_device(&state.db, &device_id, &user_id, until)
                    .await
                    .map_err(|e| {
                        error!(error = %e, "Failed to lock device after max failed attempts");
                        AppError::Internal(format!("Failed to lock device: {}", e).into())
                    })?;
                
                warn!(
                    user_id = %user_id,
                    lock_minutes = quick_login::LOCK_MINUTES,
                    "Device locked due to too many failed attempts"
                );
                
                return Err(AppError::Auth(
                    format!(
                        "Too many failed attempts. Device locked for {} minutes.",
                        quick_login::LOCK_MINUTES
                    )
                    .into(),
                ));
            }
            
            let remaining = quick_login::MAX_FAILED_ATTEMPTS - attempts;
            return Err(AppError::Auth(
                format!(
                    "Incorrect favorite word. {} attempts remaining.",
                    remaining
                )
                .into(),
            ));
        }
    };

    // Success: clear failed attempts
    db_quicklogin::clear_failed_attempts(&state.db, &device_id, &user_id)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to clear failed attempts after successful login");
            AppError::Internal(format!("Failed to clear attempts: {}", e).into())
        })?;
    
    // Store KEK in AppState
    state.set_kek(Some(kek));
    debug!(user_id = %user_id, "KEK stored in application state");

    // Fetch user details
    let user = db::get_user_by_id(&state.db, &user_id)
        .await
        .map_err(|e| {
            error!(error = %e, user_id = %user_id, "Database query failed while fetching user");
            AppError::Internal(format!("Failed to fetch user: {}", e).into())
        })?
        .ok_or_else(|| {
            error!(user_id = %user_id, "User not found in database (data inconsistency)");
            AppError::Auth("User not found".into())
        })?;

    // Create session
    let token = crypto::secure_token();
    let expires = Utc::now() + Duration::days(QUICK_SESSION_DAYS);
    db::create_session(&state.db, &token, &user.id, expires)
        .await
        .map_err(|e| {
            error!(error = %e, user_id = %user.id, "Failed to create session");
            AppError::Internal(format!("Failed to create session: {}", e).into())
        })?;

    info!(
        user_id = %user.id,
        email = %user.email,
        session_expires = %expires,
        "Quick login successful"
    );

    Ok(QuickLoginResponse {
        token,
        user_id: user.id,
        email: user.email,
        name: user.name,
    })
}

/// Disables quick login for the current user on this device.
/// 
/// User opts out of quick login on this device.
#[tauri::command]
#[instrument(skip(state, session_token), fields(operation = "disable_quick_login"))]
pub async fn disable_quick_login(
    state: State<'_, AppState>,
    session_token: String,
) -> Result<(), AppError> {
    info!("Disabling quick login");
    
    // Validate session
    let user = require_session(&state, &session_token).await?;
    
    // Load device secret from OS keychain (with file fallback)
    let device_secret = quick_login::get_or_create_device_secret(&state.data_dir)?;
    let device_id = quick_login::device_id_from_secret(&device_secret);
    debug!(device_id = %device_id, "Loaded device identifier");
    
    // Delete from database
    db_quicklogin::delete_trusted_device(&state.db, &device_id, &user.id)
        .await
        .map_err(|e| {
            error!(error = %e, user_id = %user.id, "Failed to delete trusted device");
            AppError::Internal(format!("Failed to disable quick login: {}", e).into())
        })?;

    info!(user_id = %user.id, "Quick login disabled successfully");
    Ok(())
}