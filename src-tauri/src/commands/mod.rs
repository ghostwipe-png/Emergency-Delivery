//! Tauri command surface.

pub mod auth;
pub mod delivery;
pub mod payment;
pub mod sms;
pub mod system;
pub mod upload;
pub mod chat;
pub mod social;
pub mod guardian;

use crate::db;
use crate::errors::AppError;
use crate::models::UserRecord;
use crate::AppState;

pub async fn require_session(state: &AppState, session_token: &str) -> Result<UserRecord, AppError> {
    let token = session_token.trim();
    if token.is_empty() {
        return Err(AppError::Auth("session token is required".into()));
    }
    db::validate_session(&state.db, token)
        .await?
        .ok_or_else(|| AppError::Auth("session expired or invalid — please sign in again".into()))
}