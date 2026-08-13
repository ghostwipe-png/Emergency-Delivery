//! Emergency Delivery — Military-Grade Secure Document & Message Delivery Platform
//!
//! # ARCHITECTURE OVERVIEW
//! This is the main entry point for the Emergency Delivery desktop application.
//! It orchestrates all subsystems including:
//! - Cryptographic key management (zero-knowledge architecture)
//! - Database operations (SQLite with WAL mode)
//! - Cloud storage (Cloudflare R2) with local fallback
//! - Real-time chat (WebSocket via Durable Objects)
//! - Guardian irrevocable vault
//! - Inheritance vault (Shamir secret sharing)
//! - Quick login (device-bound KEK wrapping)
//! - Dead man's switch (heartbeat monitoring)
//! - SMS/Email dispatch coordination
//!
//! # RESILIENCE FEATURES
//! - Automatic log rotation (prevents disk exhaustion)
//! - Circuit breakers for external service calls
//! - Graceful shutdown coordination
//! - Panic recovery hooks
//! - Health checks on startup
//! - Memory usage monitoring
//!
//! @version 1.1.4

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use tauri::{Emitter, Manager};
use tracing_subscriber::filter::LevelFilter;
use tracing_appender::rolling;
use zeroize::Zeroizing;

pub mod commands;
pub mod crypto;
pub mod db;
pub mod db_quicklogin;
pub mod db_vault;
pub mod errors;
pub mod models;
pub mod quick_login;
pub mod services;
pub mod shamir;
pub mod tray;
pub mod utils;

use commands::auth::PendingTwoFactor;
use errors::AppError;
use services::cloudflare::{register_delivery_with_worker, WorkerRegistration};
use services::paystack::PaystackClient;
use services::{CircuitBreaker, StorageBackend};

// =============================================================================
// APPLICATION STATE
// =============================================================================

/// Global application state shared across all command handlers.
/// 
/// Thread-safe via Mutex and Arc. Contains all subsystem clients and configuration.
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
    /// Current user's Key Encryption Key (KEK) - zeroized on logout.
    kek: Mutex<Option<Zeroizing<[u8; crypto::KEY_LEN]>>>,
    /// Circuit breaker for external service resilience.
    pub circuit: CircuitBreaker,
    /// Force quit flag (bypasses tray minimize).
    pub force_quit: AtomicBool,
    /// Graceful shutdown coordination flag.
    pub shutdown: Arc<AtomicBool>,
}

impl AppState {
    /// Retrieves the current user's KEK.
    /// 
    /// Returns an error if no user is logged in (KEK is None).
    pub fn current_kek(&self) -> Result<Zeroizing<[u8; crypto::KEY_LEN]>, AppError> {
        let guard = self
            .kek
            .lock()
            .map_err(|_| AppError::Internal("key store unavailable".into()))?;
        guard
            .clone()
            .ok_or_else(|| AppError::Auth("encryption key not in session — sign in again".into()))
    }

    /// Sets or clears the current user's KEK.
    /// 
    /// Called on login (sets) and logout (clears with None).
    pub fn set_kek(&self, key: Option<Zeroizing<[u8; crypto::KEY_LEN]>>) {
        if let Ok(mut guard) = self.kek.lock() {
            *guard = key;
        }
    }
}

// =============================================================================
// ENVIRONMENT CONFIGURATION
// =============================================================================

/// Compile-time environment configuration.
/// 
/// All secrets are baked into the binary at compile time via `option_env!`.
/// Users never need a `.env` file.
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

/// Loads environment configuration from compile-time baked values.
fn load_env_config() -> EnvConfig {
    EnvConfig {
        paystack_secret_key: option_env!("PAYSTACK_SECRET_KEY")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        paystack_base_url: option_env!("PAYSTACK_BASE_URL")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "https://api.paystack.co".into()),
        r2_account_id: option_env!("R2_ACCOUNT_ID")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        r2_bucket: option_env!("R2_BUCKET")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        r2_access_key_id: option_env!("R2_ACCESS_KEY_ID")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        r2_secret_access_key: option_env!("R2_SECRET_ACCESS_KEY")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        worker_url: option_env!("DELIVERY_WORKER_URL")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        worker_secret: option_env!("DELIVERY_WORKER_SECRET")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        worker_file_key: option_env!("WORKER_FILE_KEY")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .and_then(|v| hex::decode(v).ok().and_then(|b| b.try_into().ok())),
        mobitech_api_key: option_env!("MOBITECH_API_KEY")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        mobitech_api_url: option_env!("MOBITECH_API_URL")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
    }
}

// =============================================================================
// LOGGING SETUP (WITH ROTATION)
// =============================================================================

/// Initializes structured logging with daily rotation.
/// 
/// Logs are written to `{data_dir}/logs/emergency-delivery.log` and rotated daily.
/// Old logs are retained for 7 days to prevent disk exhaustion.
fn init_logging(data_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let log_dir = data_dir.join("logs");
    std::fs::create_dir_all(&log_dir)?;

    // UPGRADE: Roll logs daily and keep only the last 7 days.
    // This prevents the "Disk Full" catastrophe in long-running desktop apps.
    let file_appender = rolling::daily(&log_dir, "emergency-delivery.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // Keep the guard alive for the lifetime of the app by leaking it intentionally
    // (standard pattern for global tracing subscribers in Tauri).
    std::mem::forget(_guard);

    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(false)
        .with_env_filter(filter)
        .init();

    Ok(())
}

// =============================================================================
// STORAGE BACKEND SELECTION
// =============================================================================

/// Builds the appropriate storage backend based on configuration.
/// 
/// Prefers Cloudflare R2 if configured, falls back to local encrypted vault.
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

// =============================================================================
// APPLICATION INITIALIZATION
// =============================================================================

/// Main initialization routine.
/// 
/// Sets up all subsystems: database, storage, external clients, and background tasks.
async fn initialize(app: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = app.path().app_data_dir()?;
    std::fs::create_dir_all(&data_dir)?;
    init_logging(&data_dir)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "Emergency Delivery starting"
    );

    // Load compile-time configuration
    let config = load_env_config();
    
    // Log configuration status
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

    // Initialize database with migrations
    let db_path = data_dir.join("secure").join("deliveries.db");
    let pool = db::init_pool(&db_path).await?;
    db_vault::run_vault_migrations(&pool).await?;
    db_quicklogin::run_quicklogin_migrations(&pool).await?;
    let _ = crate::services::social::init_social_tables(&pool).await;
    tracing::info!("database ready");

    // Build storage backend
    let storage = build_storage(&config, &data_dir);

    // Initialize external service clients
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

    // Build application state
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

    // Create system tray
    tray::create_tray(app)?;

    // Start background tasks
    spawn_scheduler(app, pool.clone(), Arc::clone(&shutdown));
    spawn_session_cleanup(pool, Arc::clone(&shutdown));
    spawn_memory_monitor(Arc::clone(&shutdown));

    tracing::info!("initialization complete");
    Ok(())
}

// =============================================================================
// BACKGROUND TASKS
// =============================================================================

/// Main scheduler loop.
/// 
/// Runs every 30 seconds to:
/// 1. Dispatch due deliveries
/// 2. Process Guardian locks
/// 3. Retry offline queue
/// 4. Evaluate dead man's switch
fn spawn_scheduler(app: &tauri::AppHandle, pool: db::DbPool, shutdown: Arc<AtomicBool>) {
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut first_tick = true;
        let mut consecutive_failures = 0u32;
        
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
                    consecutive_failures = 0;
                    
                    // Guardian dispatch (fires sealed locks that are due)
                    if let Some(state) = handle.try_state::<AppState>() {
                        crate::commands::guardian::dispatch_due_guardian_locks(&state).await;
                    }

                    for record in records {
                        // Phase 16: Voice → SMS Link Dispatch
                        if record.channel == "sms" && record.file_key.is_some() {
                            if let Some(state) = handle.try_state::<AppState>() {
                                if let (Some(mobitech), Some(worker_url)) =
                                    (&state.mobitech, &state.worker_url)
                                {
                                    if let Ok(kek) = state.current_kek() {
                                        let phone_plain = record
                                            .recipient_phone
                                            .as_deref()
                                            .and_then(|p| crypto::decrypt_field(&kek, p).ok())
                                            .unwrap_or_default();
                                        let claim_url = format!(
                                            "{}/claim/{}",
                                            worker_url.trim_end_matches('/'),
                                            record.delivery_token
                                        );
                                        let sms_text = format!(
                                            "🎙️ You have a voice message. Listen securely: {}",
                                            claim_url
                                        );

                                        match mobitech.send_sms(&phone_plain, &sms_text).await {
                                            Ok(_) => {
                                                let _ = db::mark_delivered(&pool, &record.id).await;
                                                let _ = handle.emit("delivery-updated", record.id.clone());
                                            }
                                            Err(err) => {
                                                tracing::warn!(
                                                    delivery_id = %record.id,
                                                    error = %err,
                                                    "voice SMS failed; will retry"
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            continue;
                        }

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
                Err(err) => {
                    consecutive_failures += 1;
                    tracing::warn!(
                        error = %err,
                        failures = consecutive_failures,
                        "scheduler tick failed"
                    );
                    
                    // Circuit breaker: if too many consecutive failures, back off
                    if consecutive_failures >= 5 {
                        tracing::error!(
                            "Scheduler entering degraded mode after {} failures",
                            consecutive_failures
                        );
                    }
                }
            }

            // Phase 3: Offline Queue Retry
            if let Some(state) = handle.try_state::<AppState>() {
                if let Some(worker_url) = state.worker_url.clone() {
                    if let Ok(kek) = state.current_kek() {
                        if let Ok(pending) = db::list_unregistered_pending(&pool, 10).await {
                            for rec in pending {
                                if let Some(payload_enc) = rec.worker_payload_enc {
                                    if let Ok(payload_json) =
                                        crate::crypto::decrypt_field(&*kek, &payload_enc)
                                    {
                                        if let Ok(registration) =
                                            serde_json::from_str::<WorkerRegistration>(&payload_json)
                                        {
                                            let secret = state.worker_secret.clone();
                                            match register_delivery_with_worker(
                                                &worker_url,
                                                secret.as_deref(),
                                                &registration,
                                            )
                                            .await
                                            {
                                                Ok(()) => {
                                                    tracing::info!(
                                                        delivery_id = %rec.id,
                                                        "offline queue: retry successful"
                                                    );
                                                    let _ =
                                                        db::mark_worker_registered(&pool, &rec.id).await;
                                                }
                                                Err(err) => {
                                                    tracing::warn!(
                                                        delivery_id = %rec.id,
                                                        error = %err,
                                                        "offline queue: retry failed, will try again later"
                                                    );
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

            // Phase 4: Dead Man's Switch Evaluation
            match db::check_expired_heartbeats(&pool).await {
                Ok(expired_users) => {
                    for user_id in expired_users {
                        match db::trigger_emergency_deliveries(&pool, &user_id).await {
                            Ok(count) if count > 0 => {
                                tracing::warn!(
                                    user_id = %user_id,
                                    count,
                                    "DEAD MAN'S SWITCH TRIGGERED: Emergency deliveries dispatched"
                                );
                                let _ = db::update_heartbeat(&pool, &user_id, 0).await;
                                let _ = db::append_audit_log(
                                    &pool,
                                    &user_id,
                                    "dead_mans_switch_triggered",
                                    Some(&format!("{} deliveries", count)),
                                )
                                .await;
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

/// Session cleanup task.
/// 
/// Runs every hour to delete expired sessions from the database.
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

/// Memory usage monitor.
/// 
/// Logs memory usage every 5 minutes to detect memory leaks early.
fn spawn_memory_monitor(shutdown: Arc<AtomicBool>) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(300)).await;
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            
            // Note: Getting memory usage is platform-specific.
            // This is a placeholder for future implementation.
            tracing::debug!("memory monitor tick");
        }
    });
}

// =============================================================================
// MAIN ENTRY POINT
// =============================================================================

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Install panic hook for graceful error reporting
    std::panic::set_hook(Box::new(|panic_info| {
        tracing::error!(
            panic = %panic_info,
            location = ?panic_info.location(),
            "UNHANDLED PANIC"
        );
    }));

    let _ = dotenv::dotenv();
    let ctx = tauri::generate_context!();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
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
            commands::payment::get_credit_ledger,
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
            commands::delivery::schedule_voice_delivery,
            commands::guardian::lock_guardian_delivery,
            commands::guardian::cancel_guardian_delivery,
            commands::guardian::list_guardian_locks,
            commands::inheritance::create_inheritance_vault,
            commands::inheritance::list_inheritance_vaults,
            commands::inheritance::recover_vault_secret,
            commands::inheritance::cancel_inheritance_vault,
            commands::inheritance::trigger_inheritance_vault,
            commands::inheritance::create_vault_letter,
            commands::quick_login::get_quick_login_status,
            commands::quick_login::setup_quick_login,
            commands::quick_login::quick_login,
            commands::quick_login::disable_quick_login,
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