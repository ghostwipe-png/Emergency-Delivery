use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use tauri::State;
use uuid::Uuid;

use crate::commands::require_session;
use crate::crypto;
use crate::db;
use crate::errors::AppError;
use crate::utils;
use crate::AppState;

pub const COOLING_OFF_HOURS: i64 = 24;

#[derive(serde::Deserialize)]
pub struct GuardianLockRequest {
    pub content_type: String,
    pub file_key: Option<String>,
    pub message_text: Option<String>,
    pub recipient_name: String,
    pub recipient_email: Option<String>,
    pub recipient_phone: Option<String>,
    pub scheduled_for: chrono::DateTime<Utc>,
    pub seal_code: String,
}

#[tauri::command]
pub async fn lock_guardian_delivery(
    state: State<'_, AppState>,
    session_token: String,
    request: GuardianLockRequest,
) -> Result<serde_json::Value, AppError> {
    let user = require_session(&state, &session_token).await?;
    let kek = state.current_kek()?;

    let seal = request.seal_code.trim();
    if seal.len() != 6 || !seal.chars().all(|c| c.is_ascii_digit()) {
        return Err(AppError::Validation("seal code must be exactly 6 digits".into()));
    }
    
    let scheduled_for = utils::validate_schedule_time(request.scheduled_for)?;
    let channel = if request.content_type == "sms" { "sms" } else { "email" };

    // Deduct credit (email=1 email credit, sms=1 sms credit)
    if channel == "sms" { 
        db::deduct_credit(&state.db, &user.id, 0, 1, "guardian_lock").await?; 
    } else { 
        db::deduct_credit(&state.db, &user.id, 1, 0, "guardian_lock").await?; 
    }

    // Generate seal hash (never store the plaintext code)
    let salt = crypto::random_salt();
    let mut h = Sha256::new(); 
    h.update(seal.as_bytes()); 
    h.update(&salt);
    let seal_hash = hex::encode(h.finalize());

    // Encrypt the whole send-payload with the user's KEK
    let payload = serde_json::json!({
        "content_type": request.content_type,
        "file_key": request.file_key,
        "message_text": request.message_text,
        "recipient_name": request.recipient_name,
        "recipient_email": request.recipient_email,
        "recipient_phone": request.recipient_phone,
    });
    let payload_enc = crypto::encrypt_to_field(&kek, &payload.to_string())?;

    let id = Uuid::new_v4().to_string();
    let cooling_off_until = Utc::now() + Duration::hours(COOLING_OFF_HOURS);

        // Register with the cloud so it fires even if this device is destroyed.
    let mut cloud_registered: i64 = 0;
    if let (Some(worker_url), Some(wfk)) = (&state.worker_url, &state.worker_file_key) {
        let cloud_enc = crypto::encrypt_to_field(wfk, &payload.to_string())?;
        let body = serde_json::json!({
            "id": id, "channel": channel,
            "scheduled_for": scheduled_for.to_rfc3339(),
            "cooling_off_until": cooling_off_until.to_rfc3339(),
            "seal_hash": seal_hash, "payload_enc": cloud_enc,
        });
        let client = reqwest::Client::builder().https_only(true)
            .timeout(std::time::Duration::from_secs(10)).build()
            .map_err(|e| AppError::Config(format!("http client: {e}")))?;
        let mut req = client.post(format!("{}/guardian/lock", worker_url.trim_end_matches('/'))).json(&body);
        if let Some(secret) = &state.worker_secret { req = req.header("X-Worker-Secret", secret); }
        if let Ok(resp) = req.send().await { if resp.status().is_success() { cloud_registered = 1; } }
    }

        db::insert_guardian_lock(
        &state.db, 
        &id, 
        &user.id, 
        channel, 
        scheduled_for, 
        cooling_off_until, 
        &seal_hash, 
        &hex::encode(salt), 
        &payload_enc,
        cloud_registered
    ).await?;

    // Log the action to the immutable audit trail
    let _ = db::append_audit_log(&state.db, &user.id, "guardian_sealed", Some(&format!("lock_id: {}", id))).await;

    Ok(serde_json::json!({ 
        "id": id, 
        "cooling_off_until": cooling_off_until.to_rfc3339() 
    }))
}

#[tauri::command]
pub async fn cancel_guardian_delivery(
    state: State<'_, AppState>,
    session_token: String,
    lock_id: String,
) -> Result<(), AppError> {
    let user = require_session(&state, &session_token).await?;
    
    // Only allowed within the 24h cooling-off window. After that: irreversible.
    let ok = db::cancel_guardian_lock(&state.db, &lock_id, &user.id, Utc::now()).await?;
    if !ok {
        return Err(AppError::Validation("This Guardian delivery is sealed and irreversible. It cannot be cancelled.".into()));
    }
    
    let _ = db::append_audit_log(&state.db, &user.id, "guardian_cancelled", Some(&lock_id)).await;
    Ok(())
}
/// Background dispatcher: fires due Guardian locks. Called by the scheduler each tick.
/// Handles SMS (via Mobitech) and typed-email (via Worker). File-email arrives with the cloud phase.
pub async fn dispatch_due_guardian_locks(state: &AppState) {
    let now = Utc::now();
    let due = match db::due_guardian_locks(&state.db, now).await { Ok(d) => d, Err(_) => return };
    if due.is_empty() { return; }
    let kek = match state.current_kek() { Ok(k) => k, Err(_) => return };

    for (id, channel, payload_enc) in due {
        let payload_json = match crypto::decrypt_field(&kek, &payload_enc) { Ok(p) => p, Err(_) => continue };
        let v: serde_json::Value = match serde_json::from_str(&payload_json) { Ok(v) => v, Err(_) => continue };

        let msg = v["message_text"].as_str().unwrap_or("").to_string();
        let phone = v["recipient_phone"].as_str().map(|s| s.to_string());
        let email = v["recipient_email"].as_str().map(|s| s.to_string());
        let name = v["recipient_name"].as_str().unwrap_or("Recipient").to_string();

        if channel == "sms" {
            if let (Some(mobitech), Some(ph)) = (&state.mobitech, phone) {
                let text = if msg.is_empty() { "You have a secure Guardian message.".into() } else { msg };
                if mobitech.send_sms(&ph, &text).await.is_ok() {
                    let _ = db::mark_guardian_delivered(&state.db, &id).await;
                }
            }
        } else if let (Some(worker_url), Some(em)) = (&state.worker_url, email) {
            let reg = crate::services::cloudflare::WorkerRegistration {
                delivery_id: id.clone(),
                delivery_token: crypto::secure_token(),
                recipient_name: name,
                recipient_email: em,
                scheduled_for: now.to_rfc3339(),
                message_text: if msg.is_empty() { None } else { Some(msg) },
                file_key: None, file_name: None, file_type: None, worker_dek: None,
                link_expires_at: None, link_max_views: None,
                claim_password_hash: None, claim_password_salt: None, claim_pw_wrapped_dek: None,
            };
            if crate::services::cloudflare::register_delivery_with_worker(&worker_url, state.worker_secret.as_deref(), &reg).await.is_ok() {
                let _ = db::mark_guardian_delivered(&state.db, &id).await;
            }
        }
    }
}

#[tauri::command]
pub async fn list_guardian_locks(
    state: State<'_, AppState>,
    session_token: String,
) -> Result<Vec<serde_json::Value>, AppError> {
    let user = require_session(&state, &session_token).await?;
    let rows = db::list_guardian_locks(&state.db, &user.id).await?;
    Ok(rows.into_iter().map(|(id, channel, sched, cooling, status, created)| serde_json::json!({
        "id": id, "channel": channel, "scheduled_for": sched,
        "cooling_off_until": cooling, "status": status, "created_at": created
    })).collect())
}