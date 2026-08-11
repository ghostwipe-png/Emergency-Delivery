// src-tauri/src/commands/social.rs
use tauri::State;
use crate::AppState;
use crate::services::social;
use crate::errors::AppError;
use sha2::{Digest, Sha256};

#[tauri::command]
pub async fn social_init(state: State<'_, AppState>) -> Result<(), AppError> {
    social::init_social_tables(&state.db).await
}

#[tauri::command]
pub async fn social_save_profile(
    state: State<'_, AppState>,
    session_token: String,
    display_name: String,
    status_text: String,
    phone_number: String,
    status_media_key: Option<String>,
    status_caption: Option<String>,
) -> Result<(), AppError> {
    let user = crate::commands::require_session(&state, &session_token).await?;
    
    let phone_hash = if phone_number.trim().is_empty() {
        None
    } else {
        let mut hasher = Sha256::new();
        hasher.update(phone_number.trim().as_bytes());
        Some(hex::encode(hasher.finalize()))
    };

    // Calculate 24hr expiry if media is present
    let status_expires_at = if status_media_key.is_some() {
        Some((chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339())
    } else {
        None
    };

    let profile = social::SocialProfile {
        user_id: user.id.clone(),
        display_name,
        phone_hash: phone_hash.clone(),
        avatar_key: None,
        status_text: Some(status_text),
        status_media_key,
        status_caption,
        status_expires_at,
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    social::upsert_profile(&state.db, &profile).await?;

    if let Some(worker_url) = &state.worker_url {
        let client = reqwest::Client::new();
        let url = format!("{}/social/register", worker_url);
        let _ = client.post(&url)
            .header("X-Worker-Secret", state.worker_secret.as_deref().unwrap_or(""))
            .json(&serde_json::json!({
                "user_id": user.id,
                "display_name": profile.display_name,
                "phone_hash": phone_hash,
                "status_text": profile.status_text,
                "status_media_key": profile.status_media_key,
                "status_caption": profile.status_caption,
                "status_expires_at": profile.status_expires_at
            }))
            .send()
            .await;
    }

    Ok(())
}

#[tauri::command]
pub async fn social_search_user(
    state: State<'_, AppState>,
    session_token: String,
    phone_number: String,
) -> Result<Option<serde_json::Value>, AppError> {
    let _user = crate::commands::require_session(&state, &session_token).await?;
    
    let mut hasher = Sha256::new();
    hasher.update(phone_number.trim().as_bytes());
    let hash = hex::encode(hasher.finalize());

    if let Some(worker_url) = &state.worker_url {
        let client = reqwest::Client::new();
        let url = format!("{}/social/search?hash={}", worker_url, hash);
        let res = client.get(&url)
            .header("X-Worker-Secret", state.worker_secret.as_deref().unwrap_or(""))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Search failed: {}", e)))?;
        
        if res.status().is_success() {
            return Ok(Some(res.json().await?));
        }
    }
    Ok(None)
}

#[tauri::command]
pub async fn social_add_contact(
    state: State<'_, AppState>,
    session_token: String,
    contact_user_id: String,
) -> Result<(), AppError> {
    let user = crate::commands::require_session(&state, &session_token).await?;
    social::add_contact(&state.db, &user.id, &contact_user_id).await
}

#[tauri::command]
pub async fn social_list_contacts(
    state: State<'_, AppState>,
    session_token: String,
) -> Result<Vec<social::SocialContact>, AppError> {
    let user = crate::commands::require_session(&state, &session_token).await?;
    social::list_contacts(&state.db, &user.id).await
}