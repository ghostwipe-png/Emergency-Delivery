//! Delivery scheduling: single or bulk recipients, typed messages, claim-link
//! expiry/view limits, Worker hand-off, receipts, cancel & clear-all.

use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use tauri::State;
use uuid::Uuid;

use crate::commands::require_session;
use crate::crypto;
use crate::db;
use crate::errors::AppError;
use crate::models::{
    Delivery, DeliveryChannel, DeliveryRecord, DeliveryStatus, NewDelivery, ReceiptEvent, SenderMode,
};
use crate::services::cloudflare::{register_delivery_with_worker, WorkerRegistration};
use crate::utils;
use crate::AppState;

#[tauri::command]
pub async fn schedule_delivery(
    state: State<'_, AppState>,
    session_token: String,
    data: NewDelivery,
) -> Result<Vec<Delivery>, AppError> {
    let user = require_session(&state, &session_token).await?;
    let kek = state.current_kek()?;

    if data.channel != DeliveryChannel::Email {
        return Err(AppError::Validation(
            "SMS is sent instantly from the SMS screen — scheduling applies to email".into(),
        ));
    }

    let has_file = data.file_key.as_ref().map(|k| !k.trim().is_empty()).unwrap_or(false);
    let has_text = data.message_text.as_ref().map(|m| !m.trim().is_empty()).unwrap_or(false);
    if has_file == has_text {
        return Err(AppError::Validation(
            "provide either a file or a typed message (exactly one)".into(),
        ));
    }

    // ---- Recipients (single or bulk) ----
    let mut emails: Vec<String> = Vec::new();
    if let Some(list) = &data.recipient_emails {
        let filtered: Vec<&String> = list.iter().filter(|e| !e.trim().is_empty()).collect();
        if filtered.is_empty() {
            return Err(AppError::Validation("no recipients provided".into()));
        }
        if filtered.len() > db::MAX_BULK_RECIPIENTS {
            return Err(AppError::Validation(format!(
                "bulk sending is limited to {} recipients",
                db::MAX_BULK_RECIPIENTS
            )));
        }
        for e in filtered {
            emails.push(utils::validate_email(e)?);
        }
    } else {
        match &data.recipient_email {
            Some(e) if !e.trim().is_empty() => emails.push(utils::validate_email(e)?),
            _ => {
                return Err(AppError::Validation("recipient email is required for email deliveries".into()))
            }
        }
    }
    emails.dedup();
    let n = emails.len() as i64;

    let recipient_name = utils::validate_display_name(&data.recipient_name, "recipient name")?;
    let recipient_phone = match data.recipient_phone.as_deref() {
        Some(p) if !p.trim().is_empty() => Some(utils::validate_phone(p)?),
        _ => None,
    };
    let scheduled_for = utils::validate_schedule_time(data.scheduled_for)?;

    let (sender_name, sender_email) = match data.sender_mode {
        SenderMode::Anonymous => (None, None),
        SenderMode::Identified => (
            Some(utils::validate_display_name(
                data.sender_name.as_deref().unwrap_or_default(),
                "sender name",
            )?),
            Some(utils::validate_email(data.sender_email.as_deref().unwrap_or_default())?),
        ),
    };

    // ---- Link controls ----
    let link_expires_at = match data.link_expires_hours {
        Some(h) if h > 0 => Some(scheduled_for + Duration::hours(h.min(24 * 365))),
        _ => None,
    };
    let link_max_views = match data.link_max_views {
        Some(v) if v > 0 => Some(v.min(1000)),
        _ => None,
    };

    // ---- Content resolution ----
    let mut file_name: Option<String> = None;
    let mut file_size: i64 = 0;
    let mut file_type: Option<String> = None;
    let mut file_key: Option<String> = None;
    let mut wrapped_dek: Option<String> = None;
    let mut dek_nonce: Option<String> = None;
    let mut message_enc: Option<String> = None;
    let mut message_plain: Option<String> = None;

    if has_file {
        let key = utils::validate_file_key(data.file_key.as_deref().unwrap_or_default())?;
        let upload = db::get_upload(&state.db, &key, &user.id)
            .await?
            .ok_or_else(|| AppError::NotFound("uploaded file not found".into()))?;
        if upload.used {
            return Err(AppError::Validation("this file has already been scheduled".into()));
        }
        wrapped_dek = Some(
            upload
                .wrapped_dek
                .clone()
                .ok_or_else(|| AppError::Storage("file lacks encryption metadata — re-upload securely".into()))?,
        );
        dek_nonce = Some(
            upload
                .dek_nonce
                .clone()
                .ok_or_else(|| AppError::Storage("file lacks encryption metadata — re-upload securely".into()))?,
        );
        file_name = Some(upload.file_name.clone());
        file_size = upload.file_size;
        file_type = Some(upload.file_type.clone());
        file_key = Some(key);
    } else {
        let msg = utils::validate_message(
            data.message_text.as_deref().unwrap_or_default(),
            utils::MAX_MESSAGE_LEN,
            "message",
        )?;
        message_enc = Some(crypto::encrypt_to_field(&kek, &msg)?);
        message_plain = Some(msg);
    }

    // ---- Re-wrap DEK for the Worker (claim-time decryption) ----
    let mut raw_dek: Option<Vec<u8>> = None;

    let worker_dek = match state.worker_file_key.as_ref() {
        Some(wfk) if file_key.is_some() => {
            let wrapped_ct = crypto::b64_decode(
                wrapped_dek
                    .as_deref()
                    .ok_or_else(|| AppError::Internal("missing wrapped DEK".into()))?,
            )?;
            let wrap_nonce_vec = crypto::b64_decode(
                dek_nonce
                    .as_deref()
                    .ok_or_else(|| AppError::Internal("missing DEK nonce".into()))?,
            )?;
            let wrap_nonce: [u8; crypto::NONCE_LEN] = wrap_nonce_vec
                .as_slice()
                .try_into()
                .map_err(|_| AppError::Crypto("invalid wrap nonce".into()))?;
            let dek = crypto::decrypt(&kek, &wrapped_ct, &wrap_nonce)?;
            raw_dek = Some(dek.clone());
            Some(crypto::encrypt_to_field(wfk, &hex::encode(&dek))?)
        }
        _ => None,
    };

    // ---- Phase 2: Password-Protected Files ----
    let mut claim_password_hash: Option<String> = None;
    let mut claim_password_salt: Option<String> = None;
    let mut claim_pw_wrapped_dek: Option<String> = None;

    if let Some(pw) = data.claim_password.as_deref() {
        if !pw.trim().is_empty() {
            if !has_file {
                return Err(AppError::Validation(
                    "password protection is only supported for file deliveries".into(),
                ));
            }
            if raw_dek.is_none() {
                return Err(AppError::Internal(
                    "cannot password-protect: missing file DEK (worker key not configured)".into(),
                ));
            }

            let pw_salt = crypto::random_salt();
            
            let mut hasher = Sha256::new();
            hasher.update(pw.as_bytes());
            hasher.update(&pw_salt);
            let pw_hash_bytes = hasher.finalize();
            claim_password_hash = Some(hex::encode(pw_hash_bytes));
            claim_password_salt = Some(hex::encode(pw_salt));

            let pw_kek = crypto::derive_key(pw, &pw_salt, crypto::PBKDF2_ITERATIONS)?;
            let dek_hex = hex::encode(raw_dek.as_ref().unwrap());
            claim_pw_wrapped_dek = Some(crypto::encrypt_to_field(&pw_kek, &dek_hex)?);
        }
    }

    // ---- Atomic credit debit for N recipients ----
    if !db::decrement_credits_by(&state.db, &user.id, n).await? {
        return Err(AppError::Payment(format!(
            "insufficient credits — this delivery costs {n} credit(s)"
        )));
    }

    // ---- Phase 3: Recurrence Validation ----
    let recurrence = match data.recurrence.as_deref() {
        Some(r) if !r.trim().is_empty() => {
            let r_lower = r.trim().to_lowercase();
            if ["daily", "weekly", "monthly", "none"].contains(&r_lower.as_str()) {
                if r_lower == "none" { None } else { Some(r_lower) }
            } else {
                return Err(AppError::Validation("invalid recurrence pattern (use daily, weekly, monthly, or none)".into()));
            }
        }
        _ => None,
    };

    // ---- Build one record per recipient ----
    let enc_sender_name = match &sender_name {
        Some(v) => Some(crypto::encrypt_to_field(&kek, v)?),
        None => None,
    };
    let enc_sender_email = match &sender_email {
        Some(v) => Some(crypto::encrypt_to_field(&kek, v)?),
        None => None,
    };
    let enc_phone = match &recipient_phone {
        Some(p) => Some(crypto::encrypt_to_field(&kek, p)?),
        None => None,
    };

    // Phase 3: Pre-build Worker Registrations and encrypt payloads for offline queue
    let has_worker_url = state.worker_url.is_some();
    let mut registrations: Vec<Option<WorkerRegistration>> = Vec::with_capacity(emails.len());
    let mut encrypted_payloads: Vec<Option<String>> = Vec::with_capacity(emails.len());
    
    for _email in &emails {
        if has_worker_url {
            // Use temporary ID/Token; we will overwrite them after DB insert generates the real UUIDs
            let reg = WorkerRegistration {
                delivery_id: "temp".into(),
                delivery_token: "temp".into(),
                recipient_name: recipient_name.clone(),
                recipient_email: "temp".into(),
                scheduled_for: scheduled_for.to_rfc3339(),
                message_text: message_plain.clone(),
                file_key: file_key.clone(),
                file_name: file_name.clone(),
                file_type: file_type.clone(),
                worker_dek: worker_dek.clone(),
                link_expires_at: link_expires_at.map(|t| t.to_rfc3339()),
                link_max_views,
                claim_password_hash: claim_password_hash.clone(),
                claim_password_salt: claim_password_salt.clone(),
                claim_pw_wrapped_dek: claim_pw_wrapped_dek.clone(),
            };
            
            let payload_json = serde_json::to_string(&reg).unwrap_or_default();
            let payload_enc = crypto::encrypt_to_field(&kek, &payload_json)?;
            
            registrations.push(Some(reg));
            encrypted_payloads.push(Some(payload_enc));
        } else {
            registrations.push(None);
            encrypted_payloads.push(None);
        }
    }

    let mut records: Vec<DeliveryRecord> = Vec::with_capacity(emails.len());
    for (idx, email) in emails.iter().enumerate() {
        records.push(DeliveryRecord {
            id: Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            content_type: if has_file { "file".into() } else { "text".into() },
            channel: DeliveryChannel::Email.as_str().into(),
            file_name: file_name.clone(),
            file_size,
            file_type: file_type.clone(),
            file_key: file_key.clone(),
            wrapped_dek: wrapped_dek.clone(),
            dek_nonce: dek_nonce.clone(),
            message_text: message_enc.clone(),
            recipient_name: recipient_name.clone(),
            recipient_email: Some(crypto::encrypt_to_field(&kek, email)?),
            recipient_phone: enc_phone.clone(),
            sender_mode: data.sender_mode.as_str().to_string(),
            sender_name: enc_sender_name.clone(),
            sender_email: enc_sender_email.clone(),
            scheduled_for,
            status: DeliveryStatus::Pending.as_str().to_string(),
            delivery_token: crypto::secure_token(),
            created_at: Utc::now(),
            delivered_at: None,
            link_expires_at,
            link_max_views,
            claim_password_hash: claim_password_hash.clone(),
            claim_password_salt: claim_password_salt.clone(),
            claim_pw_wrapped_dek: claim_pw_wrapped_dek.clone(),
            // Phase 3: Additive fields
            recurrence: recurrence.clone(),
            worker_registered: if has_worker_url { 0 } else { 1 },
            worker_payload_enc: encrypted_payloads[idx].clone(),
                        // Phase 4 Additive
            is_emergency: if data.is_emergency.unwrap_or(false) { 1 } else { 0 },
        });
    }
    
    // Update the temporary IDs/tokens in registrations to match the actual DB records
    for (idx, reg_opt) in registrations.iter_mut().enumerate() {
        if let Some(reg) = reg_opt {
            reg.delivery_id = records[idx].id.clone();
            reg.delivery_token = records[idx].delivery_token.clone();
            reg.recipient_email = emails[idx].clone();
        }
    }

    if let Err(err) = db::create_deliveries(&state.db, &records).await {
        let _ = db::increment_credits(&state.db, &user.id, n).await;
        return Err(err);
    }

    // ---- Worker hand-off (best effort, per recipient) ----
    if let Some(worker_url) = state.worker_url.clone() {
        for (idx, rec) in records.iter().enumerate() {
            if let Some(registration) = &registrations[idx] {
                match register_delivery_with_worker(&worker_url, state.worker_secret.as_deref(), registration).await
                {
                    Ok(()) => {
                        tracing::info!(delivery_id = %rec.id, "registered with delivery worker");
                        let _ = db::mark_worker_registered(&state.db, &rec.id).await;
                    },
                    Err(err) => {
                        tracing::warn!(delivery_id = %rec.id, error = %err, "worker registration failed; queued for offline retry");
                    }
                }
            }
        }
    }

    tracing::info!(count = records.len(), scheduled_for = %scheduled_for, "deliveries scheduled");
    records.iter().map(|r| Delivery::from_record(r, &kek)).collect()
}

#[tauri::command]
pub async fn get_deliveries(state: State<'_, AppState>, session_token: String) -> Result<Vec<Delivery>, AppError> {
    let user = require_session(&state, &session_token).await?;
    let kek = state.current_kek()?;
    let records = db::list_deliveries(&state.db, &user.id).await?;
    records.iter().map(|r| Delivery::from_record(r, &kek)).collect()
}

#[tauri::command]
pub async fn cancel_delivery(
    state: State<'_, AppState>,
    session_token: String,
    delivery_id: String,
) -> Result<Delivery, AppError> {
    let user = require_session(&state, &session_token).await?;
    let kek = state.current_kek()?;

    let delivery_id = delivery_id.trim();
    if delivery_id.is_empty() {
        return Err(AppError::Validation("delivery id is required".into()));
    }

    let cancelled = db::cancel_pending_delivery(&state.db, delivery_id, &user.id).await?;
    if !cancelled {
        return Err(AppError::Validation(
            "delivery cannot be cancelled (not found or already dispatched)".into(),
        ));
    }

    db::increment_credits(&state.db, &user.id, 1).await?;

    let record = db::get_delivery(&state.db, delivery_id, &user.id)
        .await?
        .ok_or_else(|| AppError::Internal("delivery disappeared after cancellation".into()))?;

    tracing::info!(delivery_id = %delivery_id, "delivery cancelled and credit refunded");
    Delivery::from_record(&record, &kek)
}

#[tauri::command]
pub async fn clear_all_deliveries(
    state: State<'_, AppState>,
    session_token: String,
) -> Result<u64, AppError> {
    let user = require_session(&state, &session_token).await?;
    let count = db::delete_all_deliveries(&state.db, &user.id).await?;
    tracing::info!(user_id = %user.id, count, "all deliveries cleared");
    Ok(count)
}

/// Fetches receipt events (email opened / file opened) from the Worker.
#[tauri::command]
pub async fn get_delivery_receipts(
    state: State<'_, AppState>,
    session_token: String,
    delivery_id: String,
) -> Result<Vec<ReceiptEvent>, AppError> {
    let user = require_session(&state, &session_token).await?;
    let record = db::get_delivery(&state.db, delivery_id.trim(), &user.id)
        .await?
        .ok_or_else(|| AppError::NotFound("delivery not found".into()))?;

    let worker_url = state
        .worker_url
        .as_ref()
        .ok_or_else(|| AppError::Config("delivery worker not configured".into()))?;

    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| AppError::Config(format!("http client init failed: {e}")))?;

    let url = format!(
        "{}/receipts/{}",
        worker_url.trim_end_matches('/'),
        record.id
    );
    let mut req = client.get(&url);
    if let Some(secret) = &state.worker_secret {
        req = req.header("X-Worker-Secret", secret);
    }

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            let events: Vec<ReceiptEvent> = resp.json().await.unwrap_or_default();
            Ok(events)
        }
        Ok(resp) => {
            tracing::warn!(status = %resp.status(), "receipts fetch failed");
            Ok(Vec::new())
        }
        Err(err) => {
            tracing::warn!(error = %err, "receipts fetch failed");
            Ok(Vec::new())
        }
    }
}

// ------------------------------------------------------------- Phase 5: Real-Time Notifications

#[derive(Debug, Clone, serde::Serialize)]
pub struct RecentReceipt {
    pub delivery_id: String,
    pub recipient_name: String,
    pub event_type: String,
    pub at: String,
}

#[tauri::command]
pub async fn get_recent_receipts(
    state: State<'_, AppState>,
    session_token: String,
) -> Result<Vec<RecentReceipt>, AppError> {
    let user = require_session(&state, &session_token).await?;
    let worker_url = match state.worker_url.as_ref() {
        Some(url) => url.clone(),
        None => return Ok(vec![]), // No worker configured, no receipts to fetch
    };

    // Get the 10 most recent deliveries to check for activity
    let records = db::list_deliveries(&state.db, &user.id).await?;
    let recent: Vec<_> = records.into_iter().take(10).collect();

    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| AppError::Config(format!("http client init failed: {e}")))?;

    let mut all_receipts = Vec::new();

    for rec in recent {
        let url = format!("{}/receipts/{}", worker_url.trim_end_matches('/'), rec.id);
        let mut req = client.get(&url);
        if let Some(secret) = &state.worker_secret {
            req = req.header("X-Worker-Secret", secret);
        }

        if let Ok(resp) = req.send().await {
            if resp.status().is_success() {
                let events: Vec<serde_json::Value> = resp.json().await.unwrap_or_default();
                for e in events {
                    let kind = e.get("type").or_else(|| e.get("kind")).and_then(|v| v.as_str()).unwrap_or("opened").to_string();
                    let at = e.get("at").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    all_receipts.push(RecentReceipt {
                        delivery_id: rec.id.clone(),
                        recipient_name: rec.recipient_name.clone(),
                        event_type: kind,
                        at,
                    });
                }
            }
        }
    }
    Ok(all_receipts)
}

// ------------------------------------------------------------- Phase 7: Global Search (Command Palette)

#[tauri::command]
pub async fn global_search(
    state: State<'_, AppState>,
    session_token: String,
    query: String,
) -> Result<Vec<Delivery>, AppError> {
    let user = require_session(&state, &session_token).await?;
    let kek = state.current_kek()?;

    let query_lower = query.trim().to_lowercase();
    if query_lower.is_empty() {
        return Ok(vec![]);
    }

    // Fetch the most recent deliveries (list_deliveries is capped at 500 in db/mod.rs)
    let records = db::list_deliveries(&state.db, &user.id).await?;
    let mut results = Vec::new();

    // Helper to safely check if a decrypted Option<String> contains the query
    let matches = |val: &Option<String>| -> bool {
        val.as_ref().map_or(false, |v| v.to_lowercase().contains(&query_lower))
    };

    for rec in records {
        // Decrypt the record into the public API struct
        let delivery = Delivery::from_record(&rec, &kek)?;

        let mut is_match = false;

        // Check unencrypted fields
        if delivery.recipient_name.to_lowercase().contains(&query_lower) {
            is_match = true;
        }
        
        // Check encrypted fields (now decrypted in memory)
        if matches(&delivery.recipient_email) { is_match = true; }
        if matches(&delivery.sender_name) { is_match = true; }
        if matches(&delivery.message_text) { is_match = true; }
        if matches(&delivery.file_name) { is_match = true; }

        if is_match {
            results.push(delivery);
        }
    }

    // Cap results to top 50 to prevent UI lag
    if results.len() > 50 {
        results.truncate(50);
    }

    Ok(results)
}