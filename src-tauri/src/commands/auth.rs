//! Local-first authentication + TOTP two-factor authentication.

use chrono::{Duration, Utc};
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::commands::require_session;
use crate::crypto;
use crate::db;
use crate::errors::AppError;
use crate::models::{AuthResponse, TwoFactorSetup, UserRecord};
use crate::utils;
use crate::AppState;

const SESSION_HOURS: i64 = 24;
const PENDING_2FA_MINUTES: i64 = 5;

/// In-memory pre-auth state while the user enters their TOTP code.
pub struct PendingTwoFactor {
    pub user_id: String,
    pub kek: Zeroizing<[u8; crypto::KEY_LEN]>,
    pub expires_at: i64,
}

fn build_totp(secret_raw: &[u8], email: &str) -> Result<totp_rs::TOTP, AppError> {
    totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret_raw.to_vec(),
        Some("Emergency Delivery".into()),
        email.to_string(),
    )
    .map_err(|e| AppError::Internal(format!("totp init failed: {e}")))
}

fn totp_check(secret_raw: &[u8], email: &str, code: &str) -> Result<bool, AppError> {
    let totp = build_totp(secret_raw, email)?;
    Ok(totp.check_current(code).unwrap_or(false))
}

async fn open_session(
    state: &AppState,
    user: UserRecord,
    kek: Zeroizing<[u8; crypto::KEY_LEN]>,
) -> Result<AuthResponse, AppError> {
    let token = crypto::secure_token();
    let expires_at = Utc::now() + Duration::hours(SESSION_HOURS);
    db::create_session(&state.db, &token, &user.id, expires_at).await?;
    state.set_kek(Some(kek));
    tracing::info!(user_id = %user.id, "session opened");
    
    let tos_update_required = user.tos_version < db::CURRENT_TOS_VERSION;
    
    Ok(AuthResponse {
        token,
        user: user.to_public(),
        expires_at,
        two_factor_required: false,
        tos_update_required,
    })
}

#[tauri::command]
pub async fn register_user(
    state: State<'_, AppState>,
    name: String,
    email: String,
    password: String,
) -> Result<AuthResponse, AppError> {
    let name = utils::validate_display_name(&name, "name")?;
    let email = utils::validate_email(&email)?;
    utils::validate_password(&password)?;

    if db::get_user_by_email(&state.db, &email).await?.is_some() {
        return Err(AppError::Auth("an account with this email already exists".into()));
    }

    let salt = crypto::random_salt();
    let kek = crypto::derive_key(&password, &salt, crypto::PBKDF2_ITERATIONS)?;
    let user_id = Uuid::new_v4().to_string();

    db::create_user(
        &state.db,
        &user_id,
        &email,
        Some(&name),
        &hex::encode(&*kek),
        &hex::encode(salt),
    )
    .await?;

    let _ = db::append_audit_log(&state.db, &user_id, "account_created", Some(&email)).await;

    let user = db::get_user_by_email(&state.db, &email)
        .await?
        .ok_or_else(|| AppError::Internal("user disappeared during registration".into()))?;

    open_session(&state, user, kek).await
}

#[tauri::command]
pub async fn login_user(
    state: State<'_, AppState>,
    email: String,
    password: String,
) -> Result<AuthResponse, AppError> {
    let email = utils::validate_email(&email)?;
    if password.is_empty() {
        return Err(AppError::Auth("password is required".into()));
    }

    let Some(user) = db::get_user_by_email(&state.db, &email).await? else {
        let dummy_salt = [0u8; crypto::SALT_LEN];
        let _ = crypto::derive_key(&password, &dummy_salt, crypto::PBKDF2_ITERATIONS);
        let _ = db::append_audit_log(&state.db, "unknown", "login_failed", Some(&email)).await;
        return Err(AppError::Auth("invalid email or password".into()));
    };

    let salt_bytes = hex::decode(&user.password_salt)
        .map_err(|_| AppError::Internal("corrupt credential record".into()))?;
    let kek = crypto::derive_key(&password, &salt_bytes, crypto::PBKDF2_ITERATIONS)?;

    let candidate = hex::encode(&*kek);
    if !crypto::ct_eq(candidate.as_bytes(), user.password_hash.as_bytes()) {
        tracing::warn!("failed login attempt");
        let _ = db::append_audit_log(&state.db, &user.id, "login_failed", None).await;
        return Err(AppError::Auth("invalid email or password".into()));
    }

    if user.totp_enabled {
        let pre_token = crypto::secure_token();
        let entry = PendingTwoFactor {
            user_id: user.id.clone(),
            kek,
            expires_at: (Utc::now() + Duration::minutes(PENDING_2FA_MINUTES)).timestamp(),
        };
        if let Ok(mut map) = state.pending_2fa.lock() {
            map.insert(pre_token.clone(), entry);
        }
        tracing::info!(user_id = %user.id, "2FA challenge issued");
        let _ = db::append_audit_log(&state.db, &user.id, "2fa_challenge_issued", None).await;
        
        let tos_update_required = user.tos_version < db::CURRENT_TOS_VERSION;
        
        return Ok(AuthResponse {
            token: pre_token,
            user: user.to_public(),
            expires_at: Utc::now() + Duration::minutes(PENDING_2FA_MINUTES),
            two_factor_required: true,
            tos_update_required,
        });
    }

    let _ = db::append_audit_log(&state.db, &user.id, "login_success", None).await;
    open_session(&state, user, kek).await
}

#[tauri::command]
pub async fn verify_two_factor(
    state: State<'_, AppState>,
    pre_token: String,
    code: String,
) -> Result<AuthResponse, AppError> {
    let code = code.trim().to_string();
    let entry = {
        let mut map = state
            .pending_2fa
            .lock()
            .map_err(|_| AppError::Internal("2FA store unavailable".into()))?;
        map.remove(pre_token.trim())
    };
    let Some(entry) = entry else {
        return Err(AppError::Auth("2FA session expired — sign in again".into()));
    };
    if entry.expires_at < Utc::now().timestamp() {
        return Err(AppError::Auth("2FA session expired — sign in again".into()));
    }

    let user = db::get_user_by_id(&state.db, &entry.user_id)
        .await?
        .ok_or_else(|| AppError::Auth("account not found".into()))?;
    let secret_enc = user
        .totp_secret
        .as_deref()
        .ok_or_else(|| AppError::Internal("2FA not configured".into()))?;
    let secret_raw = hex::decode(crypto::decrypt_field(&entry.kek, secret_enc)?)
        .map_err(|_| AppError::Internal("corrupt 2FA secret".into()))?;

    if !totp_check(&secret_raw, &user.email, &code)? {
        if let Ok(mut map) = state.pending_2fa.lock() {
            map.insert(pre_token.trim().to_string(), entry);
        }
        let _ = db::append_audit_log(&state.db, &user.id, "2fa_failed", None).await;
        return Err(AppError::Auth("invalid verification code".into()));
    }

    let _ = db::append_audit_log(&state.db, &user.id, "2fa_verified", None).await;
    open_session(&state, user, entry.kek).await
}

#[tauri::command]
pub async fn logout_user(state: State<'_, AppState>, session_token: String) -> Result<(), AppError> {
    let token = session_token.trim();
    if !token.is_empty() {
        if let Ok(Some(user)) = db::validate_session(&state.db, token).await {
            let _ = db::append_audit_log(&state.db, &user.id, "logout", None).await;
        }
        db::delete_session(&state.db, token).await?;
    }
    state.set_kek(None);
    tracing::info!("session closed");
    Ok(())
}

#[tauri::command]
pub async fn get_current_user(
    state: State<'_, AppState>,
    session_token: String,
) -> Result<crate::models::User, AppError> {
    let user = require_session(&state, &session_token).await?;
    Ok(user.to_public())
}

// ------------------------------------------------------------- 2FA setup

#[tauri::command]
pub async fn two_factor_setup(
    state: State<'_, AppState>,
    session_token: String,
) -> Result<TwoFactorSetup, AppError> {
    let user = require_session(&state, &session_token).await?;
    if user.totp_enabled {
        return Err(AppError::Validation("2FA is already enabled".into()));
    }

    let raw = totp_rs::Secret::generate_secret();
    let raw_bytes = raw
        .to_bytes()
        .map_err(|_| AppError::Internal("secret generation failed".into()))?;
    
    let secret_base32 = match totp_rs::Secret::Raw(raw_bytes.clone()).to_encoded() {
        totp_rs::Secret::Encoded(s) => s,
        _ => return Err(AppError::Internal("secret encoding failed".into())),
    };
    
    let otpauth_url = build_totp(&raw_bytes, &user.email)?.get_url();
    Ok(TwoFactorSetup {
        secret_base32,
        otpauth_url,
    })
}

#[tauri::command]
pub async fn two_factor_confirm(
    state: State<'_, AppState>,
    session_token: String,
    secret_base32: String,
    code: String,
) -> Result<(), AppError> {
    let user = require_session(&state, &session_token).await?;
    let kek = state.current_kek()?;

    let raw_bytes = totp_rs::Secret::Encoded(secret_base32.trim().to_string())
        .to_bytes()
        .map_err(|_| AppError::Validation("invalid secret format".into()))?;

    if !totp_check(&raw_bytes, &user.email, code.trim())? {
        return Err(AppError::Validation(
            "invalid verification code — scan again and retry".into(),
        ));
    }

    let secret_enc = crypto::encrypt_to_field(&kek, &hex::encode(&raw_bytes))?;
    db::set_user_totp(&state.db, &user.id, Some(&secret_enc), true).await?;
    let _ = db::append_audit_log(&state.db, &user.id, "2fa_enabled", None).await;
    tracing::info!(user_id = %user.id, "2FA enabled");
    Ok(())
}

#[tauri::command]
pub async fn two_factor_disable(
    state: State<'_, AppState>,
    session_token: String,
    code: String,
) -> Result<(), AppError> {
    let user = require_session(&state, &session_token).await?;
    let kek = state.current_kek()?;
    if !user.totp_enabled {
        return Err(AppError::Validation("2FA is not enabled".into()));
    }
    let secret_enc = user
        .totp_secret
        .as_deref()
        .ok_or_else(|| AppError::Internal("2FA not configured".into()))?;
    let secret_raw = hex::decode(crypto::decrypt_field(&kek, secret_enc)?)
        .map_err(|_| AppError::Internal("corrupt 2FA secret".into()))?;

    if !totp_check(&secret_raw, &user.email, code.trim())? {
        return Err(AppError::Validation("invalid verification code".into()));
    }

    db::set_user_totp(&state.db, &user.id, None, false).await?;
    let _ = db::append_audit_log(&state.db, &user.id, "2fa_disabled", None).await;
    tracing::info!(user_id = %user.id, "2FA disabled");
    Ok(())
}

// ------------------------------------------------------------- ToS Acceptance

#[tauri::command]
pub async fn accept_tos(
    state: State<'_, AppState>,
    session_token: String,
) -> Result<(), AppError> {
    let user = require_session(&state, &session_token).await?;
    db::accept_tos(&state.db, &user.id, db::CURRENT_TOS_VERSION).await?;
    let _ = db::append_audit_log(&state.db, &user.id, "tos_accepted", Some(&format!("v{}", db::CURRENT_TOS_VERSION))).await;
    tracing::info!(user_id = %user.id, version = db::CURRENT_TOS_VERSION, "ToS accepted");
    Ok(())
}

// ------------------------------------------------------------- GDPR & Audit Logs

#[tauri::command]
pub async fn delete_account(
    state: State<'_, AppState>,
    session_token: String,
    confirmation: String,
) -> Result<(), AppError> {
    if confirmation.trim() != "DELETE" {
        return Err(AppError::Validation("confirmation must be exactly 'DELETE'".into()));
    }
    
    let user = require_session(&state, &session_token).await?;
    let user_id = user.id.clone();
    let email = user.email.clone();

    // 1. Fetch all file keys to delete from storage (R2/Local)
    let file_keys = db::get_user_file_keys(&state.db, &user_id).await?;

    // 2. Wipe database completely (Cascading deletes + explicit wipes)
    db::delete_user_completely(&state.db, &user_id).await?;

    // 3. Crypto-shredding: Delete physical files from storage
    for key in file_keys {
        if let Err(e) = state.storage.delete(&key).await {
            tracing::warn!(file_key = %key, error = %e, "failed to delete physical file (crypto-shredded anyway)");
        }
    }

    // 4. Clear local state (Destroy the KEK)
    state.set_kek(None);
    
    // Note: We intentionally DO NOT write an audit log here because the user 
    // and the audit_logs table for this user were just deleted!
    
    tracing::info!(user_id = %user_id, email = %email, "account completely deleted (GDPR)");
    Ok(())
}

#[tauri::command]
pub async fn get_audit_logs(
    state: State<'_, AppState>,
    session_token: String,
) -> Result<Vec<db::AuditLogRow>, AppError> {
    let user = require_session(&state, &session_token).await?;
    db::get_audit_logs(&state.db, &user.id).await
}

// ------------------------------------------------------------- Phase 4: Dead Man's Switch

#[tauri::command]
pub async fn update_heartbeat(
    state: State<'_, AppState>,
    session_token: String,
    interval_days: i32,
) -> Result<(), AppError> {
    let user = require_session(&state, &session_token).await?;
    if interval_days < 0 || interval_days > 365 {
        return Err(AppError::Validation("interval must be between 0 and 365 days".into()));
    }
    db::update_heartbeat(&state.db, &user.id, interval_days).await?;
    let _ = db::append_audit_log(&state.db, &user.id, "heartbeat_configured", Some(&format!("{} days", interval_days))).await;
    tracing::info!(user_id = %user.id, interval_days, "heartbeat configured");
    Ok(())
}

#[tauri::command]
pub async fn manual_heartbeat(
    state: State<'_, AppState>,
    session_token: String,
) -> Result<(), AppError> {
    let user = require_session(&state, &session_token).await?;
    let current_interval = user.heartbeat_interval_days;
    if current_interval <= 0 {
        return Err(AppError::Validation("heartbeat is not enabled".into()));
    }
    db::update_heartbeat(&state.db, &user.id, current_interval).await?;
    tracing::info!(user_id = %user.id, "manual heartbeat recorded");
    Ok(())
}


// ------------------------------------------------------------- Phase 7: Biometric / OS Keychain

#[tauri::command]
pub async fn enable_biometric_unlock(
    state: tauri::State<'_, AppState>,
    user_id: String,
) -> Result<(), AppError> {
    let kek = state.current_kek()?;
    let kek_hex = hex::encode(&*kek);
    
    tokio::task::spawn_blocking(move || {
        let entry = keyring::Entry::new("EmergencyDelivery", &user_id)
            .map_err(|e| AppError::Internal(format!("keyring init failed: {}", e)))?;
        entry.set_password(&kek_hex)
            .map_err(|e| AppError::Internal(format!("keyring save failed: {}", e)))
    })
    .await
    .map_err(|_| AppError::Internal("task join failed".into()))?
}

#[tauri::command]
pub async fn login_with_biometrics(
    state: tauri::State<'_, AppState>,
    email: String,
) -> Result<crate::models::AuthResponse, AppError> {
    use crate::db;
    use crate::models::AuthResponse;
    use chrono::{Duration, Utc};

    let user = db::get_user_by_email(&state.db, &email)
        .await?
        .ok_or_else(|| AppError::Auth("account not found".into()))?;

    // Triggers native OS prompt (Touch ID / Windows Hello)
    let kek_hex = tokio::task::spawn_blocking({
        let user_id = user.id.clone();
        move || {
            let entry = keyring::Entry::new("EmergencyDelivery", &user_id).ok()?;
            entry.get_password().ok()
        }
    })
    .await
    .map_err(|_| AppError::Internal("task join failed".into()))?
    .ok_or_else(|| AppError::Auth("Biometric unlock not available or cancelled".into()))?;

    let kek_bytes = hex::decode(&kek_hex)
        .map_err(|_| AppError::Crypto("invalid KEK in keychain".into()))?;
    let kek_arr: [u8; crypto::KEY_LEN] = kek_bytes.try_into()
        .map_err(|_| AppError::Crypto("invalid KEK length in keychain".into()))?;
        
    let kek = zeroize::Zeroizing::new(kek_arr);

    // CRITICAL FIX: If 2FA is enabled, we must issue a pre-token and wait for the code
    if user.totp_enabled {
        let pre_token = crypto::secure_token();
        let entry = PendingTwoFactor {
            user_id: user.id.clone(),
            kek, // kek is moved into the pending state
            expires_at: (Utc::now() + Duration::minutes(PENDING_2FA_MINUTES)).timestamp(),
        };
        if let Ok(mut map) = state.pending_2fa.lock() {
            map.insert(pre_token.clone(), entry);
        }
        tracing::info!(user_id = %user.id, "biometric login: 2FA challenge issued");
        let _ = db::append_audit_log(&state.db, &user.id, "2fa_challenge_issued", None).await;
        
        return Ok(AuthResponse {
            token: pre_token,
            user: user.to_public(),
            expires_at: Utc::now() + Duration::minutes(PENDING_2FA_MINUTES),
            two_factor_required: true,
            tos_update_required: user.tos_version < crate::db::CURRENT_TOS_VERSION,
        });
    }

    // No 2FA: open full session immediately
    state.set_kek(Some(kek));

    let token = crypto::secure_token();
    let expires_at = Utc::now() + Duration::hours(SESSION_HOURS);
    db::create_session(&state.db, &token, &user.id, expires_at).await?;

    let _ = db::append_audit_log(&state.db, &user.id, "login_biometric", None).await;

    Ok(AuthResponse {
        token,
        user: user.to_public(),
        expires_at,
        two_factor_required: false,
        tos_update_required: user.tos_version < crate::db::CURRENT_TOS_VERSION,
    })
}
// ------------------------------------------------------------- Phase 7: Vault Backup & Restore

#[derive(serde::Serialize, serde::Deserialize)]
struct BackupEntry {
    name: String,
    data: String, // base64 encoded bytes
}

#[tauri::command]
pub async fn export_vault(
    state: tauri::State<'_, AppState>,
    password: String,
) -> Result<(), AppError> {
    if password.len() < 4 {
        return Err(AppError::Validation("Export password must be at least 4 characters".into()));
    }

    let file = tokio::task::spawn_blocking(|| {
        rfd::FileDialog::new()
            .set_file_name("emergency-delivery-backup.edbak")
            .add_filter("Backup", &["edbak"])
            .save_file()
    })
    .await
    .map_err(|_| AppError::Internal("dialog task failed".into()))?;

    let Some(path) = file else { return Ok(()) }; // User cancelled

    let data_dir = state.data_dir.clone();
    let db_path = data_dir.join("secure").join("deliveries.db");
    let vault_path = data_dir.join("vault");

    let mut entries: Vec<BackupEntry> = Vec::new();

    // 1. Read Database
    if db_path.exists() {
        let db_bytes = tokio::fs::read(&db_path).await
            .map_err(|e| AppError::Storage(format!("failed to read db: {e}")))?;
        entries.push(BackupEntry {
            name: "deliveries.db".into(),
            data: crypto::b64_encode(&db_bytes),
        });
    }

    // 2. Read Vault Files
    if vault_path.exists() {
        let mut dir = tokio::fs::read_dir(&vault_path).await
            .map_err(|e| AppError::Storage(format!("failed to read vault: {e}")))?;
        while let Some(entry) = dir.next_entry().await.map_err(|e| AppError::Storage(e.to_string()))? {
            if entry.file_type().await.map_err(|e| AppError::Storage(e.to_string()))?.is_file() {
                let name = entry.file_name().to_string_lossy().to_string();
                let bytes = tokio::fs::read(entry.path()).await
                    .map_err(|e| AppError::Storage(format!("failed to read vault file: {e}")))?;
                entries.push(BackupEntry {
                    name: format!("vault/{name}"),
                    data: crypto::b64_encode(&bytes),
                });
            }
        }
    }

    let json_payload = serde_json::to_vec(&entries)
        .map_err(|e| AppError::Internal(format!("json serialize failed: {e}")))?;

    let salt = crypto::random_salt();
    let kek = crypto::derive_key(&password, &salt, crypto::PBKDF2_ITERATIONS)?;
    let (ciphertext, nonce) = crypto::encrypt(&kek, &json_payload)?;

    // Format: [16-byte salt][12-byte nonce][ciphertext]
    let mut final_bytes = Vec::with_capacity(16 + 12 + ciphertext.len());
    final_bytes.extend_from_slice(&salt);
    final_bytes.extend_from_slice(&nonce);
    final_bytes.extend_from_slice(&ciphertext);

    tokio::fs::write(&path, &final_bytes).await
        .map_err(|e| AppError::Storage(format!("failed to write backup file: {e}")))?;

    let _ = db::append_audit_log(&state.db, "system", "vault_exported", None).await;
    tracing::info!("Vault exported successfully to {:?}", path);
    Ok(())
}

#[tauri::command]
pub async fn import_vault(
    state: tauri::State<'_, AppState>,
    password: String,
) -> Result<(), AppError> {
    let file = tokio::task::spawn_blocking(|| {
        rfd::FileDialog::new()
            .add_filter("Backup", &["edbak"])
            .pick_file()
    })
    .await
    .map_err(|_| AppError::Internal("dialog task failed".into()))?;

    let Some(path) = file else { return Ok(()) }; // User cancelled

    let raw_bytes = tokio::fs::read(&path).await
        .map_err(|e| AppError::Storage(format!("failed to read backup file: {e}")))?;

    if raw_bytes.len() < 28 {
        return Err(AppError::Validation("Invalid backup file (too small)".into()));
    }

    let salt: [u8; 16] = raw_bytes[0..16].try_into().unwrap();
    let nonce: [u8; 12] = raw_bytes[16..28].try_into().unwrap();
    let ciphertext = &raw_bytes[28..];

    let kek = crypto::derive_key(&password, &salt, crypto::PBKDF2_ITERATIONS)?;

    let json_payload = crypto::decrypt(&kek, ciphertext, &nonce)
        .map_err(|_| AppError::Auth("Invalid password or corrupted backup file".into()))?;

    let entries: Vec<BackupEntry> = serde_json::from_slice(&json_payload)
        .map_err(|e| AppError::Internal(format!("invalid backup format: {e}")))?;

    let data_dir = state.data_dir.clone();
    let db_path = data_dir.join("secure").join("deliveries.db");
    let vault_path = data_dir.join("vault");

    tokio::fs::create_dir_all(&vault_path).await.ok();

    for entry in entries {
        let bytes = crypto::b64_decode(&entry.data)?;

        if entry.name == "deliveries.db" {
            // Backup current DB just in case
            if db_path.exists() {
                let bak_path = data_dir.join("secure").join("deliveries.db.pre-import-bak");
                let _ = tokio::fs::copy(&db_path, &bak_path).await;
            }
            if let Err(e) = tokio::fs::write(&db_path, &bytes).await {
                return Err(AppError::Storage(format!("Failed to overwrite DB (it may be locked by the app). Please close the app, replace the DB manually, and restart. Error: {e}")));
            }
        } else if entry.name.starts_with("vault/") {
            let file_name = entry.name.trim_start_matches("vault/");
            let file_path = vault_path.join(file_name);
            tokio::fs::write(&file_path, &bytes).await
                .map_err(|e| AppError::Storage(format!("failed to write vault file: {e}")))?;
        }
    }

    tracing::info!("Vault imported successfully from {:?}", path);
    Ok(())
}