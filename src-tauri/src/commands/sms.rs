//! SMS commands (Kenya only, Mobitech, sender ID FULL_CIRCLE).

use chrono::Utc;
use tauri::State;
use uuid::Uuid;

use crate::commands::require_session;
use crate::crypto;
use crate::db;
use crate::errors::AppError;
use crate::models::{DeliveryRecord, DeliveryStatus, SmsResult, SmsStatus};
use crate::utils;
use crate::AppState;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SendSmsRequest {
    pub phone: String,
    pub message: String,
    #[serde(default)]
    pub recipient_name: Option<String>,
}

#[tauri::command]
pub async fn get_sms_status(
    state: State<'_, AppState>,
    session_token: String,
) -> Result<SmsStatus, AppError> {
    let user = require_session(&state, &session_token).await?;
    let balance = db::get_sms_balance(&state.db, &user.id).await?;
    Ok(SmsStatus {
        free_remaining: (db::FREE_SMS_LIMIT - balance.free_sms_used).max(0),
        credits: user.delivery_credits,
        sms_configured: state.mobitech.is_some(),
    })
}

#[tauri::command]
pub async fn send_sms(
    state: State<'_, AppState>,
    session_token: String,
    request: SendSmsRequest,
) -> Result<SmsResult, AppError> {
    let user = require_session(&state, &session_token).await?;
    let kek = state.current_kek()?;

    let mobitech = state
        .mobitech
        .as_ref()
        .ok_or_else(|| AppError::Config("SMS is not configured (set MOBITECH_API_KEY)".into()))?;

    let phone = utils::validate_kenyan_phone(&request.phone)?;
    let message = utils::validate_message(&request.message, utils::MAX_SMS_LEN, "SMS message")?;
    let recipient_name = match &request.recipient_name {
        Some(n) if !n.trim().is_empty() => utils::validate_display_name(n, "recipient name")?,
        _ => "Recipient".to_string(),
    };

    let balance = db::get_sms_balance(&state.db, &user.id).await?;
    let use_free = balance.free_sms_used < db::FREE_SMS_LIMIT;
    if !use_free && !db::decrement_credits(&state.db, &user.id).await? {
        return Err(AppError::Payment(
            "insufficient credits for SMS — purchase a plan to continue".into(),
        ));
    }

    // Use `match` so `err` is moved (owned), not borrowed — avoids Clone.
    let message_id = match mobitech.send_sms(&phone, &message).await {
        Ok(id) => id,
        Err(err) => {
            // Compensate the debited credit on failure.
            if !use_free {
                let _ = db::increment_credits(&state.db, &user.id, 1).await;
            }
            return Err(err);
        }
    };

    if use_free {
        db::increment_free_sms_used(&state.db, &user.id).await?;
    }

    let now = Utc::now();
    let record = DeliveryRecord {
        id: Uuid::new_v4().to_string(),
        user_id: user.id.clone(),
        content_type: "text".into(),
        channel: "sms".into(),
        file_name: None,
        file_size: message.len() as i64,
        file_type: Some("text/sms".into()),
        file_key: None,
        wrapped_dek: None,
        dek_nonce: None,
        message_text: Some(crypto::encrypt_to_field(&kek, &message)?),
        recipient_name: recipient_name.clone(),
        recipient_email: None,
        recipient_phone: Some(crypto::encrypt_to_field(&kek, &phone)?),
        sender_mode: "identified".into(),
        sender_name: None,
        sender_email: None,
        scheduled_for: now,
        status: DeliveryStatus::Delivered.as_str().into(),
        delivery_token: crypto::secure_token(),
        created_at: now,
        delivered_at: Some(now),
        link_expires_at: None,
        link_max_views: None,
        // Phase 2: Password protection fields (not applicable to SMS)
        claim_password_hash: None,
        claim_password_salt: None,
        claim_pw_wrapped_dek: None,
        recurrence: None,
        worker_registered: 1, // SMS is sent instantly, no worker queue needed
        worker_payload_enc: None,
        is_emergency: 0,
    };
    db::create_delivery(&state.db, &record).await?;

    let new_balance = db::get_sms_balance(&state.db, &user.id).await?;
    tracing::info!(user_id = %user.id, free = use_free, "SMS sent via Mobitech");

    Ok(SmsResult {
        success: true,
        message_id,
        used_free_sms: use_free,
        free_remaining: (db::FREE_SMS_LIMIT - new_balance.free_sms_used).max(0),
    })
}