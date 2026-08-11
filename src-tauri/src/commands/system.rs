//! Health check, diagnostics and usage analytics.

use chrono::Utc;
use tauri::State;

use crate::commands::require_session;
use crate::db;
use crate::errors::AppError;
use crate::models::{Analytics, SystemInfo};
use crate::AppState;

#[tauri::command]
pub async fn ping() -> Result<String, AppError> {
    Ok("pong".to_string())
}

#[tauri::command]
pub async fn get_system_info(state: State<'_, AppState>) -> Result<SystemInfo, AppError> {
    let (pending, delivered) = db::delivery_counts(&state.db).await?;
    Ok(SystemInfo {
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        local_time: Utc::now().to_rfc3339(),
        storage_backend: state.storage.name().to_string(),
        paystack_configured: state.paystack.is_some(),
        worker_configured: state.worker_url.is_some(),
        mobitech_configured: state.mobitech.is_some(),
        pending_deliveries: pending,
        delivered_deliveries: delivered,
    })
}

#[tauri::command]
pub async fn get_analytics(state: State<'_, AppState>, session_token: String) -> Result<Analytics, AppError> {
    let user = require_session(&state, &session_token).await?;
    let summary = db::analytics_summary(&state.db, &user.id).await?;
    let daily = db::analytics_daily(&state.db, &user.id).await?;
    Ok(Analytics { summary, daily })
}