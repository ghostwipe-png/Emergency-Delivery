//! Guardian View — Advanced Irrevocable Delivery System
//!
//! FEATURES:
//! - Instant delivery option
//! - Smart presets (2h, 6h, 12h, 2d, 1w, 1m, 2m)
//! - Dynamic cancellation windows (1h for <24h, 24h for ≥2d)
//! - Real-time credit monitoring
//! - Maximum 2-month scheduling horizon
//!
//! @version 3.0.0
//! @status PRODUCTION

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

// Maximum scheduling horizon: 2 months (60 days)
pub const MAX_SCHEDULE_DAYS: i64 = 60;

// Cancellation windows
pub const INSTANT_COOLDOWN_HOURS: i64 = 0;
pub const SHORT_COOLDOWN_HOURS: i64 = 1;  // For deliveries < 24h
pub const LONG_COOLDOWN_HOURS: i64 = 24;  // For deliveries >= 2d

// Credit warning threshold
pub const CREDIT_WARNING_THRESHOLD: i64 = 10;

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
    pub cancellation_hours: Option<i64>,
}

#[derive(serde::Serialize)]
pub struct ResourceUsage {
    pub email_credits_remaining: i64,
    pub sms_credits_remaining: i64,
    pub storage_used_mb: i64,
    pub storage_limit_mb: i64,
}

/// Calculate the cancellation window based on scheduled time
fn calculate_cancellation_window(scheduled_for: &chrono::DateTime<Utc>) -> i64 {
    let now = Utc::now();
    let hours_until_delivery = (*scheduled_for - now).num_hours();

    if hours_until_delivery <= 0 {
        INSTANT_COOLDOWN_HOURS
    } else if hours_until_delivery < 24 {
        SHORT_COOLDOWN_HOURS
    } else {
        LONG_COOLDOWN_HOURS
    }
}

/// Validate that the requested cancellation hours match the rules
fn validate_cancellation_hours(
    scheduled_for: &chrono::DateTime<Utc>,
    requested_hours: i64,
) -> Result<(), AppError> {
    let expected_hours = calculate_cancellation_window(scheduled_for);
    
    if requested_hours != expected_hours {
        return Err(AppError::Validation(format!(
            "Invalid cancellation window. Expected {} hours for this schedule.",
            expected_hours
        )));
    }
    
    Ok(())
}

#[tauri::command]
pub async fn lock_guardian_delivery(
    state: State<'_, AppState>,
    session_token: String,
    request: GuardianLockRequest,
) -> Result<serde_json::Value, AppError> {
    let user = require_session(&state, &session_token).await?;
    let kek = state.current_kek()?;

    // Validate seal code
    let seal = request.seal_code.trim();
    if seal.len() != 6 || !seal.chars().all(|c| c.is_ascii_digit()) {
        return Err(AppError::Validation("seal code must be exactly 6 digits".into()));
    }
    
    let scheduled_for = utils::validate_schedule_time(request.scheduled_for)?;
    
    // Validate schedule is within 2 months
    let max_future = Utc::now() + Duration::days(MAX_SCHEDULE_DAYS);
    if scheduled_for > max_future {
        return Err(AppError::Validation(format!(
            "Cannot schedule more than {} days in advance",
            MAX_SCHEDULE_DAYS
        )));
    }
    
    let channel = if request.content_type == "sms" { "sms" } else { "email" };
    
    // Check credits before proceeding
    if channel == "sms" {
        let balance = db::get_sms_balance(&state.db, &user.id).await?;
        let free_remaining = (db::FREE_SMS_LIMIT - balance.free_sms_used).max(0);
        let total_credits = free_remaining + user.sms_balance;
        if total_credits <= 0 {
            return Err(AppError::Payment("Insufficient SMS credits".into()));
        }
    } else {
        if user.delivery_credits <= 0 {
            return Err(AppError::Payment("Insufficient email credits".into()));
        }
    }

    // Calculate or validate cancellation window
    let cancellation_hours = request.cancellation_hours.unwrap_or_else(|| {
        calculate_cancellation_window(&scheduled_for)
    });
    
    validate_cancellation_hours(&scheduled_for, cancellation_hours)?;
    
    // Check if this is an instant delivery
    let is_instant = cancellation_hours == INSTANT_COOLDOWN_HOURS;
    
    // Calculate cooling_off_until (when cancellation window expires)
    let cooling_off_until = if is_instant {
        Utc::now()
    } else {
        Utc::now() + Duration::hours(cancellation_hours)
    };

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

    // Register with the cloud so it fires even if this device is destroyed
    let mut cloud_registered: i64 = 0;
    if let (Some(worker_url), Some(wfk)) = (&state.worker_url, &state.worker_file_key) {
        let cloud_enc = crypto::encrypt_to_field(wfk, &payload.to_string())?;
        let body = serde_json::json!({
            "id": id, 
            "channel": channel,
            "scheduled_for": scheduled_for.to_rfc3339(),
            "cooling_off_until": cooling_off_until.to_rfc3339(),
            "seal_hash": seal_hash, 
            "payload_enc": cloud_enc,
            "is_instant": is_instant,
        });
        let client = reqwest::Client::builder()
            .https_only(true)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| AppError::Config(format!("http client: {e}")))?;
        
        let mut req = client
            .post(format!("{}/guardian/lock", worker_url.trim_end_matches('/')))
            .json(&body);
        
        if let Some(secret) = &state.worker_secret { 
            req = req.header("X-Worker-Secret", secret); 
        }
        
        if let Ok(resp) = req.send().await { 
            if resp.status().is_success() { 
                cloud_registered = 1; 
            } 
        }
    }

    // Insert into database (with cancellation_hours)
    db::insert_guardian_lock(
        &state.db, 
        &id, 
        &user.id, 
        channel, 
        scheduled_for, 
        cooling_off_until,
        cancellation_hours,
        &seal_hash, 
        &hex::encode(salt), 
        &payload_enc,
        cloud_registered
    ).await?;

    // Log the action to the immutable audit trail
    let _ = db::append_audit_log(
        &state.db, 
        &user.id, 
        "guardian_sealed", 
        Some(&format!(
            "lock_id: {}, instant: {}, cancellation_hours: {}",
            id, is_instant, cancellation_hours
        ))
    ).await;

    // For instant deliveries, trigger immediate dispatch
    if is_instant {
        let state_clone = state.inner().clone();
        let id_clone = id.clone();
        let user_id_clone = user.id.clone();
        tokio::spawn(async move {
            dispatch_instant_guardian(&state_clone, &id_clone, &user_id_clone).await;
        });
    }

    Ok(serde_json::json!({ 
        "id": id, 
        "cooling_off_until": cooling_off_until.to_rfc3339(),
        "cancellation_hours": cancellation_hours,
        "is_instant": is_instant,
    }))
}

/// Dispatch an instant Guardian delivery immediately
async fn dispatch_instant_guardian(state: &AppState, lock_id: &str, user_id: &str) {
    let kek = match state.current_kek() { 
        Ok(k) => k, 
        Err(_) => return 
    };

    // Get the lock details
    let lock = match db::get_guardian_lock(&state.db, lock_id, user_id).await {
        Ok(Some(lock)) => lock,
        _ => return,
    };

    let (channel, payload_enc) = (lock.1, lock.6);
    
    let payload_json = match crypto::decrypt_field(&kek, &payload_enc) { 
        Ok(p) => p, 
        Err(_) => return 
    };
    
    let v: serde_json::Value = match serde_json::from_str(&payload_json) { 
        Ok(v) => v, 
        Err(_) => return 
    };

    let msg = v["message_text"].as_str().unwrap_or("").to_string();
    let phone = v["recipient_phone"].as_str().map(|s| s.to_string());
    let email = v["recipient_email"].as_str().map(|s| s.to_string());
    let name = v["recipient_name"].as_str().unwrap_or("Recipient").to_string();

    if channel == "sms" {
        if let (Some(mobitech), Some(ph)) = (&state.mobitech, phone) {
            let text = if msg.is_empty() { 
                "You have a secure Guardian message.".into() 
            } else { 
                msg 
            };
            if mobitech.send_sms(&ph, &text).await.is_ok() {
                let _ = db::mark_guardian_delivered(&state.db, lock_id).await;
            }
        }
    } else if let (Some(worker_url), Some(em)) = (&state.worker_url, email) {
        let reg = crate::services::cloudflare::WorkerRegistration {
            delivery_id: lock_id.to_string(),
            delivery_token: crypto::secure_token(),
            recipient_name: name,
            recipient_email: em,
            scheduled_for: Utc::now().to_rfc3339(),
            message_text: if msg.is_empty() { None } else { Some(msg) },
            file_key: None, 
            file_name: None, 
            file_type: None, 
            worker_dek: None,
            link_expires_at: None, 
            link_max_views: None,
            claim_password_hash: None, 
            claim_password_salt: None, 
            claim_pw_wrapped_dek: None,
        };
        if crate::services::cloudflare::register_delivery_with_worker(
            &worker_url, 
            state.worker_secret.as_deref(), 
            &reg
        ).await.is_ok() {
            let _ = db::mark_guardian_delivered(&state.db, lock_id).await;
        }
    }
}

#[tauri::command]
pub async fn cancel_guardian_delivery(
    state: State<'_, AppState>,
    session_token: String,
    lock_id: String,
) -> Result<(), AppError> {
    let user = require_session(&state, &session_token).await?;
    
    // Only allowed within the cooling-off window. After that: irreversible.
    let ok = db::cancel_guardian_lock(&state.db, &lock_id, &user.id, Utc::now()).await?;
    if !ok {
        return Err(AppError::Validation(
            "This Guardian delivery is sealed and irreversible. It cannot be cancelled.".into()
        ));
    }
    
    let _ = db::append_audit_log(
        &state.db, 
        &user.id, 
        "guardian_cancelled", 
        Some(&lock_id)
    ).await;
    
    Ok(())
}

/// Background dispatcher: fires due Guardian locks. Called by the scheduler each tick.
pub async fn dispatch_due_guardian_locks(state: &AppState) {
    let now = Utc::now();
    let due = match db::due_guardian_locks(&state.db, now).await { 
        Ok(d) => d, 
        Err(_) => return 
    };
    
    if due.is_empty() { 
        return; 
    }
    
    let kek = match state.current_kek() { 
        Ok(k) => k, 
        Err(_) => return 
    };

    for (id, channel, payload_enc) in due {
        let payload_json = match crypto::decrypt_field(&kek, &payload_enc) { 
            Ok(p) => p, 
            Err(_) => continue 
        };
        
        let v: serde_json::Value = match serde_json::from_str(&payload_json) { 
            Ok(v) => v, 
            Err(_) => continue 
        };

        let msg = v["message_text"].as_str().unwrap_or("").to_string();
        let phone = v["recipient_phone"].as_str().map(|s| s.to_string());
        let email = v["recipient_email"].as_str().map(|s| s.to_string());
        let name = v["recipient_name"].as_str().unwrap_or("Recipient").to_string();

        if channel == "sms" {
            if let (Some(mobitech), Some(ph)) = (&state.mobitech, phone) {
                let text = if msg.is_empty() { 
                    "You have a secure Guardian message.".into() 
                } else { 
                    msg 
                };
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
                file_key: None, 
                file_name: None, 
                file_type: None, 
                worker_dek: None,
                link_expires_at: None, 
                link_max_views: None,
                claim_password_hash: None, 
                claim_password_salt: None, 
                claim_pw_wrapped_dek: None,
            };
            if crate::services::cloudflare::register_delivery_with_worker(
                &worker_url, 
                state.worker_secret.as_deref(), 
                &reg
            ).await.is_ok() {
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
    
    Ok(rows.into_iter().map(|(id, channel, sched, cooling, status, created, cancellation_hours)| {
        serde_json::json!({
            "id": id, 
            "channel": channel, 
            "scheduled_for": sched,
            "cooling_off_until": cooling, 
            "status": status, 
            "created_at": created,
            "cancellation_hours": cancellation_hours
        })
    }).collect())
}

/// Get real-time resource usage for credit monitoring
#[tauri::command]
pub async fn get_resource_usage(
    state: State<'_, AppState>,
    session_token: String,
) -> Result<ResourceUsage, AppError> {
    let user = require_session(&state, &session_token).await?;
    
    // Get SMS balance
    let sms_balance = db::get_sms_balance(&state.db, &user.id).await?;
    let free_remaining = (db::FREE_SMS_LIMIT - sms_balance.free_sms_used).max(0);
    let sms_credits_remaining = free_remaining + user.sms_balance;
    
    // Get storage usage (query uploads table)
    let storage_used_bytes = db::get_user_storage_usage(&state.db, &user.id).await?;
    let storage_used_mb = storage_used_bytes / (1024 * 1024);
    
    // Storage limit: 1 GB per user
    let storage_limit_mb = 1024;
    
    Ok(ResourceUsage {
        email_credits_remaining: user.delivery_credits,
        sms_credits_remaining,
        storage_used_mb,
        storage_limit_mb,
    })
}