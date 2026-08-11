// src-tauri/src/commands/chat.rs
use tauri::State;
use uuid::Uuid;
use crate::AppState;
use crate::services::chat;
use crate::{db, crypto, errors::AppError};

#[tauri::command]
pub async fn join_chat_channel(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    channel_id: String,
) -> Result<(), String> {
    let worker_url = state.worker_url.clone().ok_or("Worker URL not configured")?;
    chat::join_channel(app, worker_url, channel_id).await
}

#[tauri::command]
pub async fn send_chat_message(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    session_token: String,
    channel_id: String,
    ciphertext: String, 
) -> Result<(), String> {
    let user = crate::commands::require_session(&state, &session_token).await.map_err(|e| e.to_string())?;
    
    let payload: serde_json::Value = serde_json::from_str(&ciphertext).unwrap_or_default();
    let action = payload.get("action").and_then(|a| a.as_str()).unwrap_or("send");
    let msg_id = payload.get("id").and_then(|i| i.as_str()).unwrap_or(&uuid::Uuid::new_v4().to_string()).to_string();

    if action == "delete" {
        let target_id = payload.get("target_id").and_then(|i| i.as_str()).unwrap_or(&msg_id);
        db::delete_chat_message(&state.db, target_id).await.map_err(|e| e.to_string())?;
    } else if action == "edit" {
        let target_id = payload.get("target_id").and_then(|i| i.as_str()).unwrap_or(&msg_id);
        db::update_chat_message(&state.db, target_id, &ciphertext).await.map_err(|e| e.to_string())?;
    } else if action == "signal" {
        // Phase 11: Do NOT save call signals to DB, just broadcast them
    } else {
        db::save_chat_message(&state.db, &msg_id, &channel_id, &user.id, &ciphertext).await.map_err(|e| e.to_string())?;
    }

    chat::send_chat_message(app, channel_id, ciphertext).await
}

#[tauri::command]
pub async fn create_chat_channel(
    state: State<'_, AppState>,
    session_token: String,
    name: String,
    channel_dek_hex: String, // Frontend generates this and passes it in
) -> Result<String, AppError> {
    let _user = crate::commands::require_session(&state, &session_token).await?;
    let kek = state.current_kek()?;
    
    let id = Uuid::new_v4().to_string();
    // Wrap the channel DEK with the user's master KEK for secure local storage
    let dek_enc = crypto::encrypt_to_field(&kek, &channel_dek_hex)?;
    
    db::create_chat_channel(&state.db, &id, &name, &dek_enc).await?;
    Ok(id)
}

#[tauri::command]
pub async fn get_chat_channels(
    state: State<'_, AppState>,
    session_token: String,
) -> Result<Vec<serde_json::Value>, AppError> {
    let _user = crate::commands::require_session(&state, &session_token).await?;
    let kek = state.current_kek()?;
    let rows = db::get_chat_channels(&state.db).await?;
    
    let mut channels = Vec::new();
    for (id, name, dek_enc, created_at) in rows {
        let dek_hex = crypto::decrypt_field(&kek, &dek_enc)?;
        channels.push(serde_json::json!({
            "id": id,
            "name": name,
            "channel_dek": dek_hex,
            "created_at": created_at.to_rfc3339()
        }));
    }
    Ok(channels)
}

#[tauri::command]
pub async fn get_chat_messages(
    state: State<'_, AppState>,
    channel_id: String,
) -> Result<Vec<serde_json::Value>, AppError> {
    let rows = db::get_chat_messages(&state.db, &channel_id).await?;
    let mut messages = Vec::new();
    for (id, sender_id, ciphertext, created_at) in rows {
        messages.push(serde_json::json!({
            "id": id,
            "sender_id": sender_id,
            "ciphertext": ciphertext,
            "created_at": created_at.to_rfc3339()
        }));
    }
    Ok(messages)
}

// ------------------------------------------------------------- Phase 8: Robust Chat File Sharing

#[tauri::command]
#[allow(unused_variables)]
pub async fn upload_chat_blob(
    state: State<'_, AppState>,
    session_token: String,
    file_name: String,
    file_type: String,
    file_data_b64: String, // Changed from Vec<u8> to String to prevent IPC crashes
) -> Result<String, AppError> {
    let _user = crate::commands::require_session(&state, &session_token).await?;
    let file_key = uuid::Uuid::new_v4().to_string();
    
    // Decode base64 to bytes safely using your existing crypto module
    let file_data = crate::crypto::b64_decode(&file_data_b64)
        .map_err(|e| AppError::Storage(format!("Invalid file data: {}", e)))?;
        
    state.storage.put(&file_key, file_data.into()).await?;
    
    tracing::info!(file_key = %file_key, name = %file_name, "Chat file uploaded");
    Ok(file_key)
}

#[tauri::command]
pub async fn download_chat_blob(
    state: State<'_, AppState>,
    session_token: String,
    file_key: String,
) -> Result<String, AppError> { // Changed to return String (Base64)
    let _user = crate::commands::require_session(&state, &session_token).await?;
    let bytes = state.storage.get(&file_key).await?;
    Ok(crate::crypto::b64_encode(&bytes))
}