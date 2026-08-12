//! Digital Inheritance Vault — command layer (M-of-N Shamir + 8-digit codes).

use chrono::{DateTime, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tauri::State;

use crate::commands::require_session;
use crate::crypto;
use crate::db;
use crate::db_vault;
use crate::errors::AppError;
use crate::AppState;

pub const MAX_N: usize = 7;

// -----------------------------------------------------------------------------
// Request / response types
// -----------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct BeneficiaryInput {
    pub name: String,
    pub contact: String,
}

#[derive(serde::Deserialize)]
pub struct CreateVaultRequest {
    pub name: String,
    pub secret_type: String,
    pub secret: Option<String>,
    pub file_key: Option<String>,
    pub m: i64,
    pub n: i64,
    pub trigger_type: String,
    pub trigger_time: Option<DateTime<Utc>>,
    pub beneficiaries: Vec<BeneficiaryInput>,
}

#[derive(serde::Serialize)]
pub struct CreatedShardInfo {
    pub beneficiary_name: String,
    pub beneficiary_contact: String,
    pub access_code: String,
}

#[derive(serde::Serialize)]
pub struct CreateVaultResponse {
    pub vault_id: String,
    pub shards: Vec<CreatedShardInfo>,
}

#[derive(serde::Serialize)]
pub struct VaultWithShards {
    pub vault: db_vault::VaultRow,
    pub shards: Vec<db_vault::VaultShardRow>,
}

#[derive(serde::Deserialize)]
pub struct CreateLetterRequest {
    pub beneficiary_name: String,
    pub beneficiary_contact: String,
    pub channel: String,
    pub content_type: String,
    pub message_text: Option<String>,
    pub file_key: Option<String>,
    pub open_at: DateTime<Utc>,
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Uniform system-generated 8-digit code (00000000..99999999).
fn generate_8_digit_code() -> String {
    let mut buf = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let v = u32::from_le_bytes(buf) % 100_000_000;
    format!("{:08}", v)
}

// -----------------------------------------------------------------------------
// Commands
// -----------------------------------------------------------------------------

#[tauri::command]
pub async fn create_inheritance_vault(
    state: State<'_, AppState>,
    session_token: String,
    request: CreateVaultRequest,
) -> Result<CreateVaultResponse, AppError> {
    let user = require_session(&state, &session_token).await?;
    let kek = state.current_kek()?;

    let n = request.n as usize;
    let m = request.m as usize;
    if n > MAX_N || m < 2 || m > n {
        return Err(AppError::Validation(format!("invalid threshold: require 2 <= M <= N <= {MAX_N}").into()));
    }
    if request.beneficiaries.len() != n {
        return Err(AppError::Validation("beneficiary count must equal N".into()));
    }

    // Validate: must have either a secret OR a file
    let secret_to_split = if let Some(s) = &request.secret {
        if s.trim().is_empty() {
            return Err(AppError::Validation("secret must not be empty".into()));
        }
        s.clone()
    } else if let Some(fk) = &request.file_key {
        fk.clone()
    } else {
        return Err(AppError::Validation("must provide either a secret or a file".into()));
    };

    let trigger_type = match request.trigger_type.as_str() {
        "date" | "heartbeat" | "manual" => request.trigger_type.clone(),
        _ => return Err(AppError::Validation("invalid trigger type".into())),
    };
    if trigger_type == "date" && request.trigger_time.is_none() {
        return Err(AppError::Validation("date trigger requires a time".into()));
    }

    // Split the secret into N Shamir shards (threshold M).
    let shards = crate::shamir::split(secret_to_split.as_bytes(), n, m)
        .map_err(|e| AppError::Crypto(format!("shamir split failed: {e}")))?;

    let vault_id = uuid::Uuid::new_v4().to_string();

    // Owner master backup: full secret encrypted to the owner's KEK.
    let owner_backup_enc = crypto::encrypt_to_field(&kek, &secret_to_split)?;

    // IMPORTANT: Insert the vault FIRST (shards reference it via foreign key).
    db_vault::insert_vault(
        &state.db, &vault_id, &user.id, &request.name, &request.secret_type,
        m as i64, n as i64, &trigger_type, request.trigger_time, &owner_backup_enc,
    ).await?;

    // Now insert each shard with its 8-digit access code
    let mut created: Vec<CreatedShardInfo> = Vec::new();
    for (i, ben) in request.beneficiaries.iter().enumerate() {
        let code = generate_8_digit_code();
        let salt = crypto::random_salt();

        // Hash for verification (never store plaintext code).
        let mut h = Sha256::new();
        h.update(code.as_bytes());
        h.update(&salt);
        let code_hash = hex::encode(h.finalize());

        // Derive the shard key from the code; encrypt this shard with it.
        let shard_key = crypto::derive_key(&code, &salt, crypto::PBKDF2_ITERATIONS)?;
        let shard_hex = hex::encode(&shards[i]);
        let shard_enc = crypto::encrypt_to_field(&*shard_key, &shard_hex)?;

        let shard_id = uuid::Uuid::new_v4().to_string();
        db_vault::insert_vault_shard(
            &state.db, &shard_id, &vault_id, (i + 1) as i64,
            &ben.name, &ben.contact, &code_hash, &hex::encode(salt), &shard_enc,
        ).await?;

        created.push(CreatedShardInfo {
            beneficiary_name: ben.name.clone(),
            beneficiary_contact: ben.contact.clone(),
            access_code: code,
        });
    }

    let _ = db::append_audit_log(&state.db, &user.id, "vault_created", Some(&vault_id)).await;

    Ok(CreateVaultResponse { vault_id, shards: created })
}

#[tauri::command]
pub async fn list_inheritance_vaults(
    state: State<'_, AppState>,
    session_token: String,
) -> Result<Vec<VaultWithShards>, AppError> {
    let user = require_session(&state, &session_token).await?;
    let vaults = db_vault::list_vaults(&state.db, &user.id).await?;
    let mut out = Vec::new();
    for v in vaults {
        let shards = db_vault::list_vault_shards(&state.db, &v.id).await?;
        out.push(VaultWithShards { vault: v, shards });
    }
    Ok(out)
}

/// Owner-only recovery: decrypt the master backup with the owner's KEK.
#[tauri::command]
pub async fn recover_vault_secret(
    state: State<'_, AppState>,
    session_token: String,
    vault_id: String,
) -> Result<String, AppError> {
    let user = require_session(&state, &session_token).await?;
    let kek = state.current_kek()?;
    let backup = db_vault::get_vault_backup(&state.db, &vault_id, &user.id)
        .await?
        .ok_or_else(|| AppError::NotFound("vault backup not found".into()))?;
    let secret = crypto::decrypt_field(&kek, &backup)?;
    Ok(secret)
}

/// Cancel only while locked; once open, the vault is immutable.
#[tauri::command]
pub async fn cancel_inheritance_vault(
    state: State<'_, AppState>,
    session_token: String,
    vault_id: String,
) -> Result<(), AppError> {
    let user = require_session(&state, &session_token).await?;
    let ok = db_vault::cancel_vault(&state.db, &vault_id, &user.id).await?;
    if !ok {
        return Err(AppError::Validation("vault is already open or cancelled and cannot be cancelled".into()));
    }
    let _ = db::append_audit_log(&state.db, &user.id, "vault_cancelled", Some(&vault_id)).await;
    Ok(())
}

/// Future-dated letter (stored encrypted; dispatch is wired in a later phase).
#[tauri::command]
pub async fn create_vault_letter(
    state: State<'_, AppState>,
    session_token: String,
    request: CreateLetterRequest,
) -> Result<String, AppError> {
    let user = require_session(&state, &session_token).await?;
    let kek = state.current_kek()?;

    let channel = match request.channel.as_str() {
        "email" | "sms" => request.channel.clone(),
        _ => return Err(AppError::Validation("invalid channel".into())),
    };
    let content_type = match request.content_type.as_str() {
        "text" | "file" => request.content_type.clone(),
        _ => return Err(AppError::Validation("invalid content type".into())),
    };

    let payload = serde_json::json!({
        "content_type": content_type,
        "message_text": request.message_text,
        "file_key": request.file_key,
    });
    let payload_enc = crypto::encrypt_to_field(&kek, &payload.to_string())?;

    let letter_id = uuid::Uuid::new_v4().to_string();
    db_vault::insert_vault_letter(
        &state.db, &letter_id, &user.id, None,
        &request.beneficiary_name, &request.beneficiary_contact,
        &channel, &content_type, &payload_enc, request.open_at,
    ).await?;

    Ok(letter_id)
}

/// Manually trigger a vault (owner-only, while locked)
#[tauri::command]
pub async fn trigger_inheritance_vault(
    state: State<'_, AppState>,
    session_token: String,
    vault_id: String,
    worker_url: String,
    worker_secret: String,
) -> Result<(), AppError> {
    let user = require_session(&state, &session_token).await?;
    
    // Verify the vault exists and is locked
    let vault = db_vault::get_vault(&state.db, &vault_id, &user.id)
        .await?
        .ok_or_else(|| AppError::NotFound("vault not found".into()))?;
    
    if vault.status != "locked" {
        return Err(AppError::Validation("vault is already open or cancelled".into()));
    }

    // Mark as open in local DB
    db_vault::set_vault_status(&state.db, &vault_id, &user.id, "open").await?;

    // Fetch all shards
    let shards = db_vault::list_vault_shards(&state.db, &vault_id).await?;

    // Send notification email to each beneficiary with their claim link
    let client = reqwest::Client::new();
    for shard in shards {
        let claim_url = format!("{}/vault/shard/{}", worker_url.trim_end_matches('/'), shard.id);
        let email_body = serde_json::json!({
            "from": "Emergency Delivery <notifications@opinionplus.online>",
            "to": [shard.beneficiary_contact],
            "subject": format!("🧬 Your Inheritance Shard from {}", vault.name),
            "html": format!(
                r#"<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;">
                    <h1 style="color:#00a884;">🧬 Inheritance Vault Unlocked</h1>
                    <p>Hello <strong>{}</strong>,</p>
                    <p>A vault named "<strong>{}</strong>" has been opened.</p>
                    <p>You hold one of the shards needed to reconstruct the secret. Click the link below to retrieve your shard:</p>
                    <div style="text-align:center;margin:28px 0;">
                        <a href="{}" style="background:#00a884;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:700;">Retrieve My Shard</a>
                    </div>
                    <p style="color:#6b7280;font-size:13px;">Keep this link secure. You will need your 8-digit access code to unlock it.</p>
                </div>"#,
                shard.beneficiary_name, vault.name, claim_url
            )
        });

        let _ = client.post(format!("{}/send-email", worker_url.trim_end_matches('/')))
            .header("X-Worker-Secret", &worker_secret)
            .json(&email_body)
            .send()
            .await;
    }

    // Register the vault as open in the cloud
    let _ = client.post(format!("{}/vault/open", worker_url.trim_end_matches('/')))
        .header("X-Worker-Secret", &worker_secret)
        .json(&serde_json::json!({ "vault_id": vault_id }))
        .send()
        .await;

    let _ = db::append_audit_log(&state.db, &user.id, "vault_triggered", Some(&vault_id)).await;
    Ok(())
}