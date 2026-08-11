//! Emergency Delivery — secure, scheduled document & message delivery.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use tauri::{Emitter, Manager};
use tracing_subscriber::filter::LevelFilter;
use zeroize::Zeroizing;

pub mod commands;
pub mod crypto;
pub mod db;
pub mod errors;
pub mod models;
pub mod services;
pub mod tray;
pub mod utils;

use commands::auth::PendingTwoFactor;
use errors::AppError;
use services::paystack::PaystackClient;
use services::{CircuitBreaker, StorageBackend};
use services::cloudflare::{register_delivery_with_worker, WorkerRegistration};

pub struct AppState {
    pub db: db::DbPool,
    pub storage: StorageBackend,
    pub data_dir: std::path::PathBuf,
    pub chat_manager: services::chat::ChatManager, 
    pub paystack: Option<PaystackClient>,
    pub mobitech: Option<services::mobitech::MobitechClient>,
    pub worker_url: Option<String>,
    pub worker_secret: Option<String>,
    pub worker_file_key: Option<[u8; crypto::KEY_LEN]>,
    /// Pre-auth state while a user completes their TOTP challenge.
    pub pending_2fa: Mutex<HashMap<String, PendingTwoFactor>>,
    kek: Mutex<Option<Zeroizing<[u8; crypto::KEY_LEN]>>>,
    pub circuit: CircuitBreaker,
    pub force_quit: AtomicBool,
    pub shutdown: Arc<AtomicBool>,
}

impl AppState {
    pub fn current_kek(&self) -> Result<Zeroizing<[u8; crypto::KEY_LEN]>, AppError> {
        let guard = self
            .kek
            .lock()
            .map_err(|_| AppError::Internal("key store unavailable".into()))?;
        guard
            .clone()
            .ok_or_else(|| AppError::Auth("encryption key not in session — sign in again".into()))
    }

    pub fn set_kek(&self, key: Option<Zeroizing<[u8; crypto::KEY_LEN]>>) {
        if let Ok(mut guard) = self.kek.lock() {
            *guard = key;
        }
    }
}

struct EnvConfig {
    paystack_secret_key: Option<String>,
    paystack_base_url: String,
    r2_account_id: Option<String>,
    r2_bucket: Option<String>,
    r2_access_key_id: Option<String>,
    r2_secret_access_key: Option<String>,
    worker_url: Option<String>,
    worker_secret: Option<String>,
    worker_file_key: Option<[u8; crypto::KEY_LEN]>,
    mobitech_api_key: Option<String>,
    mobitech_api_url: Option<String>,
}

fn load_env_config() -> EnvConfig {
    // option_env! reads the variables AT COMPILE TIME and bakes them into the binary.
    // Your users will never need a .env file!
    EnvConfig {
        paystack_secret_key: option_env!("PAYSTACK_SECRET_KEY").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        paystack_base_url: option_env!("PAYSTACK_BASE_URL").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "https://api.paystack.co".into()),
        r2_account_id: option_env!("R2_ACCOUNT_ID").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        r2_bucket: option_env!("R2_BUCKET").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        r2_access_key_id: option_env!("R2_ACCESS_KEY_ID").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        r2_secret_access_key: option_env!("R2_SECRET_ACCESS_KEY").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        worker_url: option_env!("DELIVERY_WORKER_URL").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        worker_secret: option_env!("DELIVERY_WORKER_SECRET").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        worker_file_key: option_env!("WORKER_FILE_KEY").map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
            .and_then(|v| hex::decode(v).ok().and_then(|b| b.try_into().ok())),
        mobitech_api_key: option_env!("MOBITECH_API_KEY").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        mobitech_api_url: option_env!("MOBITECH_API_URL").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
    }
}

fn init_logging(data_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let log_dir = data_dir.join("logs");
    std::fs::create_dir_all(&log_dir)?;
    let file = std::fs::File::options()
        .create(true)
        .append(true)
        .open(log_dir.join("app.log"))?;
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::fmt()
        .with_writer(file)
        .with_ansi(false)
        .with_target(false)
        .with_env_filter(filter)
        .init();
    Ok(())
}

fn build_storage(config: &EnvConfig, data_dir: &Path) -> StorageBackend {
    let r2 = match (
        &config.r2_account_id,
        &config.r2_bucket,
        &config.r2_access_key_id,
        &config.r2_secret_access_key,
    ) {
        (Some(account), Some(bucket), Some(key), Some(secret)) => {
            match services::cloudflare::R2Client::new(
                account.clone(),
                bucket.clone(),
                key.clone(),
                secret.clone(),
            ) {
                Ok(client) => Some(client),
                Err(err) => {
                    tracing::warn!(error = %err, "R2 misconfigured; falling back to local vault");
                    None
                }
            }
        }
        _ => None,
    };

    match r2 {
        Some(client) => {
            tracing::info!("storage backend: Cloudflare R2 (zero egress fees)");
            StorageBackend::R2(client)
        }
        None => {
            let vault = data_dir.join("vault");
            let _ = std::fs::create_dir_all(&vault);
            tracing::info!("storage backend: local encrypted vault");
            StorageBackend::Local { dir: vault }
        }
    }
}

async fn initialize(app: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = app.path().app_data_dir()?;
    std::fs::create_dir_all(&data_dir)?;
    init_logging(&data_dir)?;

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "Emergency Delivery starting");

    let config = load_env_config();
    if config.paystack_secret_key.is_none() {
        tracing::warn!("PAYSTACK_SECRET_KEY not set — payments disabled");
    }
    if config.worker_url.is_none() {
        tracing::warn!("DELIVERY_WORKER_URL not set — dispatch handled by local scheduler only");
    }
    if config.worker_url.is_some() && config.worker_file_key.is_none() {
        tracing::warn!("WORKER_FILE_KEY not set — recipients cannot decrypt files via claim links");
    }
    if config.mobitech_api_key.is_none() {
        tracing::warn!("MOBITECH_API_KEY not set — SMS disabled");
    }

    let db_path = data_dir.join("secure").join("deliveries.db");
    let pool = db::init_pool(&db_path).await?;
    
    // Phase 9: Social Tables
    let _ = crate::services::social::init_social_tables(&pool).await;
    tracing::info!("database ready");

    let storage = build_storage(&config, &data_dir);

    let paystack = match config.paystack_secret_key {
        Some(key) => match PaystackClient::new(key, &config.paystack_base_url) {
            Ok(client) => Some(client),
            Err(err) => {
                tracing::warn!(error = %err, "Paystack unavailable");
                None
            }
        },
        None => None,
    };

    let mobitech = match config.mobitech_api_key {
        Some(key) => match services::mobitech::MobitechClient::new(key, config.mobitech_api_url.clone()) {
            Ok(client) => Some(client),
            Err(err) => {
                tracing::warn!(error = %err, "Mobitech unavailable");
                None
            }
        },
        None => None,
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let state = AppState {
        db: pool.clone(),
        storage,
        data_dir: data_dir.clone(),
        chat_manager: services::chat::ChatManager::new(),
        paystack,
        mobitech,
        worker_url: config.worker_url.clone(),
        worker_secret: config.worker_secret.clone(),
        worker_file_key: config.worker_file_key,
        pending_2fa: Mutex::new(HashMap::new()),
        kek: Mutex::new(None),
        circuit: CircuitBreaker::new(5, Duration::from_secs(60)),
        force_quit: AtomicBool::new(false),
        shutdown: Arc::clone(&shutdown),
    };
    app.manage(state);

    tray::create_tray(app)?;

    spawn_scheduler(app, pool.clone(), Arc::clone(&shutdown));
    spawn_session_cleanup(pool, Arc::clone(&shutdown));

    tracing::info!("initialization complete");
    Ok(())
}

fn spawn_scheduler(app: &tauri::AppHandle, pool: db::DbPool, shutdown: Arc<AtomicBool>) {
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut first_tick = true;
        loop {
            let delay = if first_tick {
                Duration::from_secs(5)
            } else {
                Duration::from_secs(30)
            };
            first_tick = false;
            tokio::time::sleep(delay).await;
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            
            // 1. EXISTING: Mark due deliveries as delivered (local scheduler)
            match db::due_deliveries(&pool, Utc::now()).await {
                Ok(records) => {
                    for record in records {
                        match db::mark_delivered(&pool, &record.id).await {
                            Ok(true) => {
                                tracing::info!(delivery_id = %record.id, "delivery dispatched");
                                let _ = handle.emit("delivery-updated", record.id.clone());
                            }
                            Ok(false) => {}
                            Err(err) => {
                                tracing::warn!(delivery_id = %record.id, error = %err, "dispatch update failed")
                            }
                        }
                    }
                }
                Err(err) => tracing::warn!(error = %err, "scheduler tick failed"),
            }

            // ---- Phase 3: Offline Queue Retry (Strictly Additive) ----
            if let Some(state) = handle.try_state::<AppState>() {
                if let Some(worker_url) = state.worker_url.clone() {
                    if let Ok(kek) = state.current_kek() {
                        if let Ok(pending) = db::list_unregistered_pending(&pool, 10).await {
                            for rec in pending {
                                if let Some(payload_enc) = rec.worker_payload_enc {
                                    if let Ok(payload_json) = crate::crypto::decrypt_field(&*kek, &payload_enc) {
                                        if let Ok(registration) = serde_json::from_str::<WorkerRegistration>(&payload_json) {
                                            let secret = state.worker_secret.clone();
                                            match register_delivery_with_worker(
                                                &worker_url,
                                                secret.as_deref(),
                                                &registration,
                                            ).await {
                                                Ok(()) => {
                                                    tracing::info!(delivery_id = %rec.id, "offline queue: retry successful");
                                                    let _ = db::mark_worker_registered(&pool, &rec.id).await;
                                                }
                                                Err(err) => {
                                                    tracing::warn!(delivery_id = %rec.id, error = %err, "offline queue: retry failed, will try again later");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ---- Phase 4: Dead Man's Switch Evaluation (Strictly Additive) ----
            match db::check_expired_heartbeats(&pool).await {
                Ok(expired_users) => {
                    for user_id in expired_users {
                        match db::trigger_emergency_deliveries(&pool, &user_id).await {
                            Ok(count) if count > 0 => {
                                tracing::warn!(user_id = %user_id, count, "DEAD MAN'S SWITCH TRIGGERED: Emergency deliveries dispatched");
                                let _ = db::update_heartbeat(&pool, &user_id, 0).await;
                                let _ = db::append_audit_log(&pool, &user_id, "dead_mans_switch_triggered", Some(&format!("{} deliveries", count))).await;
                                let _ = handle.emit("dead-mans-switch-triggered", user_id);
                            }
                            _ => {}
                        }
                    }
                }
                Err(err) => tracing::warn!(error = %err, "heartbeat check failed"),
            }
        }
        tracing::info!("scheduler stopped");
    });
}

fn spawn_session_cleanup(pool: db::DbPool, shutdown: Arc<AtomicBool>) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            match db::delete_expired_sessions(&pool).await {
                Ok(n) if n > 0 => tracing::info!(expired = n, "cleaned expired sessions"),
                Ok(_) => {}
                Err(err) => tracing::warn!(error = %err, "session cleanup failed"),
            }
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _ = dotenv::dotenv();
    let ctx = tauri::generate_context!();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let handle = app.handle().clone();
            tauri::async_runtime::block_on(async move { initialize(&handle).await })?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::system::ping,
            commands::system::get_system_info,
            commands::system::get_analytics,
            commands::auth::register_user,
            commands::auth::login_user,
            commands::auth::logout_user,
            commands::auth::get_current_user,
            commands::auth::verify_two_factor,
            commands::auth::two_factor_setup,
            commands::auth::two_factor_confirm,
            commands::auth::two_factor_disable,
            commands::auth::accept_tos,
            commands::auth::delete_account,
            commands::auth::get_audit_logs,
            commands::payment::get_payment_plans,
            commands::payment::initialize_payment,
            commands::payment::verify_payment,
            commands::payment::get_credit_ledger, // <-- ADDED FOR PHASE 15 AUDIT TRAIL
            commands::delivery::schedule_delivery,
            commands::delivery::get_deliveries,
            commands::delivery::cancel_delivery,
            commands::delivery::clear_all_deliveries,
            commands::delivery::get_delivery_receipts,
            commands::delivery::get_recent_receipts,
            commands::delivery::global_search,
            commands::upload::upload_file,
            commands::upload::pick_and_upload_file,
            commands::upload::get_upload_url,
            commands::upload::preview_file, 
            commands::sms::send_sms,
            commands::sms::get_sms_status,
            commands::auth::update_heartbeat,
            commands::auth::manual_heartbeat,
            commands::auth::enable_biometric_unlock,
            commands::auth::login_with_biometrics,
            commands::auth::export_vault, 
            commands::auth::import_vault, 
            commands::chat::join_chat_channel,   
            commands::chat::send_chat_message,   
            commands::chat::create_chat_channel,
            commands::chat::get_chat_channels,
            commands::chat::get_chat_messages,
            commands::chat::upload_chat_blob,
            commands::chat::download_chat_blob,
            commands::social::social_init,
            commands::social::social_save_profile,
            commands::social::social_search_user,
            commands::social::social_add_contact,
            commands::social::social_list_contacts,
        ])
        .on_window_event(|window, event| match event {
            tauri::WindowEvent::CloseRequested { api, .. } => {
                if let Some(state) = window.try_state::<AppState>() {
                    if !state.force_quit.load(Ordering::Relaxed) {
                        api.prevent_close();
                        let _ = window.hide();
                        tracing::debug!("window hidden to tray");
                    }
                }
            }
            _ => {}
        })
        .build(ctx)
        .expect("failed to build Emergency Delivery")
        .run(move |app_handle, event| {
            if let tauri::RunEvent::ExitRequested { api, .. } = event {
                if let Some(state) = app_handle.try_state::<AppState>() {
                    state.shutdown.store(true, Ordering::Relaxed);
                    if !state.force_quit.load(Ordering::Relaxed) {
                        api.prevent_exit();
                    }
                }
            }
        });
}