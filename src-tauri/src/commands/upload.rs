//! Secure upload pipeline: sanitize → magic-byte validation → envelope
//! encryption (random DEK per file, wrapped by session KEK) → storage.

use chrono::Utc;
use tauri::State;
use uuid::Uuid;

use crate::commands::require_session;
use crate::crypto;
use crate::db;
use crate::errors::AppError;
use crate::models::{PresignedUrl, UploadRecord, UploadResult, UserRecord};
use crate::utils;
use crate::AppState;

#[tauri::command]
pub async fn upload_file(
    state: State<'_, AppState>,
    session_token: String,
    file_name: String,
    file_bytes: Vec<u8>,
) -> Result<UploadResult, AppError> {
    let user = require_session(&state, &session_token).await?;
    process_upload(&state, &user, file_name, file_bytes).await
}

async fn process_upload(
    state: &AppState,
    user: &UserRecord,
    file_name: String,
    file_bytes: Vec<u8>,
) -> Result<UploadResult, AppError> {
    let clean_name = utils::sanitize_file_name(&file_name)?;
    let file_type = utils::validate_file_contents(&clean_name, &file_bytes)?;
    let kek = state.current_kek()?;

    // Envelope encryption: a random DEK encrypts the file; the KEK wraps it.
    let dek = zeroize::Zeroizing::new(crypto::random_bytes::<32>());
    let (ciphertext, nonce) = crypto::encrypt(&dek, &file_bytes)?;
    
    // FIX: Dereference `dek` explicitly with `&*dek` for the wrapper encryption
    let (wrapped_dek, wrap_nonce) = crypto::encrypt(&kek, &*dek)?;

    // FIX: Prepend nonce to ciphertext so we can recover both during decryption
    // Format stored: [12-byte nonce][ciphertext with GCM auth tag]
    let mut blob_with_nonce = nonce.to_vec();
    blob_with_nonce.extend_from_slice(&ciphertext);

    let file_key = format!("uploads/{}/{}", user.id, Uuid::new_v4().as_simple());
    state.storage.put(&file_key, blob_with_nonce).await?;

    let size = file_bytes.len() as i64;
    db::insert_upload(
        &state.db,
        &UploadRecord {
            file_key: file_key.clone(),
            user_id: user.id.clone(),
            file_name: clean_name.clone(),
            file_size: size,
            file_type: file_type.to_string(),
            wrapped_dek: Some(crypto::b64_encode(&wrapped_dek)),
            dek_nonce: Some(crypto::b64_encode(&wrap_nonce)),
            used: false,
            created_at: Utc::now(),
        },
    )
    .await?;

    // Explicit drop: the Zeroizing DEK is wiped from memory here.
    drop(dek);

    tracing::info!(file_key = %file_key, size, storage = state.storage.name(), "file encrypted and stored");
    Ok(UploadResult {
        file_key,
        file_name: clean_name,
        file_size: size,
        file_type: file_type.to_string(),
        storage: state.storage.name().to_string(),
    })
}

/// Native file dialog (rfd). The file never crosses the IPC boundary —
/// the efficient path for large (up to 100 MB) documents.
#[tauri::command]
pub async fn pick_and_upload_file(
    state: State<'_, AppState>,
    session_token: String,
) -> Result<Option<UploadResult>, AppError> {
    let user = require_session(&state, &session_token).await?;

    let picked = tokio::task::spawn_blocking(|| {
        rfd::FileDialog::new()
            .set_title("Choose a document to deliver")
            .add_filter("Supported documents", &["pdf", "docx", "jpg", "jpeg", "png", "mp4"])
            .pick_file()
    })
    .await
    .map_err(|_| AppError::Internal("file dialog task failed".into()))?;

    let Some(path) = picked else {
        return Ok(None); // user cancelled
    };

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .ok_or_else(|| AppError::Validation("selected file has an invalid name".into()))?;

    let bytes = tokio::task::spawn_blocking(move || std::fs::read(path))
        .await
        .map_err(|_| AppError::Internal("file read task failed".into()))?
        .map_err(|e| AppError::Storage(format!("cannot read file: {e}")))?;

    process_upload(&state, &user, file_name, bytes).await.map(Some)
}

/// Advanced flow: presigned PUT URL for programmatic uploads. Callers MUST
/// upload AES-256-GCM ciphertext; the standard `upload_file` command is the
/// recommended path because it encrypts automatically.
#[tauri::command]
pub async fn get_upload_url(
    state: State<'_, AppState>,
    session_token: String,
    file_name: String,
) -> Result<PresignedUrl, AppError> {
    let user = require_session(&state, &session_token).await?;
    let clean_name = utils::sanitize_file_name(&file_name)?;

    let file_key = format!("uploads/{}/{}", user.id, Uuid::new_v4().as_simple());
    let expires_in_secs: u64 = 900;
    let url = state.storage.presigned_put_url(&file_key, expires_in_secs)?;

    db::insert_upload(
        &state.db,
        &UploadRecord {
            file_key: file_key.clone(),
            user_id: user.id.clone(),
            file_name: clean_name,
            file_size: 0,
            file_type: "application/octet-stream".into(),
            wrapped_dek: None,
            dek_nonce: None,
            used: false,
            created_at: Utc::now(),
        },
    )
    .await?;

    Ok(PresignedUrl {
        url,
        file_key,
        expires_in_secs,
        note: "Advanced flow: PUT AES-256-GCM ciphertext only. Prefer the secure upload API, which encrypts automatically.".into(),
    })
}

// ------------------------------------------------------------- Phase 2: Secure Preview

/// Downloads the encrypted file from storage, unwraps the DEK using the 
/// user's master KEK, decrypts the file locally, and returns the plaintext bytes.
#[tauri::command]
pub async fn preview_file(
    state: State<'_, AppState>,
    session_token: String,
    file_key: String,
) -> Result<Vec<u8>, AppError> {
    let user = require_session(&state, &session_token).await?;
    let kek = state.current_kek()?;

    let key = utils::validate_file_key(&file_key)?;
    let upload = db::get_upload(&state.db, &key, &user.id)
        .await?
        .ok_or_else(|| AppError::NotFound("file not found".into()))?;

    let wrapped_dek_b64 = upload.wrapped_dek.ok_or_else(|| AppError::Storage("missing wrapped DEK".into()))?;
    let dek_nonce_b64 = upload.dek_nonce.ok_or_else(|| AppError::Storage("missing DEK nonce".into()))?;

    // 1. Unwrap the DEK using the user's master KEK
    let wrapped_ct = crypto::b64_decode(&wrapped_dek_b64)?;
    let wrap_nonce_vec = crypto::b64_decode(&dek_nonce_b64)?;
    let wrap_nonce: [u8; crypto::NONCE_LEN] = wrap_nonce_vec
        .as_slice()
        .try_into()
        .map_err(|_| AppError::Crypto("invalid wrap nonce".into()))?;

    let dek = crypto::decrypt(&kek, &wrapped_ct, &wrap_nonce)?;

    // 2. Fetch the encrypted blob from Storage (R2 or Local vault)
    let blob = state.storage.get(&key).await?;
    if blob.len() < crypto::NONCE_LEN {
        return Err(AppError::Crypto("blob too short".into()));
    }

    // 3. Decrypt the blob using the unwrapped DEK
    // The blob format is [12-byte nonce][ciphertext with GCM auth tag]
    let (nonce_bytes, ciphertext) = blob.split_at(crypto::NONCE_LEN);
    let nonce: [u8; crypto::NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| AppError::Crypto("invalid blob nonce".into()))?;

    let dek_arr: [u8; crypto::KEY_LEN] = dek.as_slice()
        .try_into()
        .map_err(|_| AppError::Crypto("invalid DEK length".into()))?;

    crypto::decrypt(&dek_arr, ciphertext, &nonce)
}