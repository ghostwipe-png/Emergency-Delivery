//! Emergency Delivery — Production-Grade Entry Point
//!
//! ARCHITECTURE:
//! - This file handles: platform setup, single-instance guard, signal handlers,
//!   and startup validation BEFORE delegating to lib.rs for app initialization.
//! - lib.rs handles: logging setup, panic hooks, and Tauri app initialization.
//! - This separation prevents duplicate initialization and ensures clean startup.
//!
//! FEATURES:
//! - Single instance guard (prevents database corruption from double-launch)
//! - Graceful shutdown handling (Ctrl+C, SIGTERM)
//! - Platform-specific optimizations (Windows ANSI, macOS Dock, Linux prctl)
//! - Startup validation (data directory writable check)
//! - Exit codes for different failure modes (diagnostics)
//!
//! @version 2.0.1
//! @status PRODUCTION

// Prevents an extra console window on Windows in release builds
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// Global flag for graceful shutdown (shared with lib.rs signal handling)
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

fn main() -> ExitCode {
    // STEP 1: Load environment variables from .env (if present)
    // This must happen BEFORE any logging so RUST_LOG env var is available
    let _ = dotenv::dotenv();

    // STEP 2: Platform-specific setup (ANSI colors, process name)
    platform_setup();

    // STEP 3: Single instance guard (prevents database corruption)
    #[cfg(feature = "single-instance")]
    {
        if !acquire_single_instance_lock() {
            eprintln!("═══════════════════════════════════════════════════════════════");
            eprintln!("ANOTHER INSTANCE IS ALREADY RUNNING");
            eprintln!("═══════════════════════════════════════════════════════════════");
            eprintln!("");
            eprintln!("Emergency Delivery is already running. Please close the other");
            eprintln!("instance before starting a new one.");
            eprintln!("");
            eprintln!("If you believe this is an error, delete the lock file at:");
            eprintln!("  {}", get_lock_path().display());
            eprintln!("═══════════════════════════════════════════════════════════════");

            // On Windows, show a message box in release mode
            #[cfg(all(windows, not(debug_assertions)))]
            show_windows_error_dialog(
                "Another instance is already running",
                "Emergency Delivery is already running. Please close the other instance before starting a new one.",
            );

            return ExitCode::from(2);
        }
    }

    // STEP 4: Install signal handlers for graceful shutdown
    install_signal_handlers();

    // STEP 5: Validate critical resources (data directory writable)
    if let Err(e) = validate_startup_resources() {
        eprintln!("CRITICAL: Startup validation failed: {}", e);
        return ExitCode::from(3);
    }

    // STEP 6: Run the application
    // NOTE: lib.rs handles logging initialization, panic hooks, and Tauri setup.
    // We do NOT wrap this in catch_unwind because lib.rs already has its own
    // panic hook that shows Windows message boxes and logs structured errors.
    // The run() function returns () — it blocks until the app exits.
    emergency_delivery_lib::run();

    // If we reach here, the app exited normally
    ExitCode::SUCCESS
}

// =============================================================================
// PLATFORM-SPECIFIC SETUP
// =============================================================================

fn platform_setup() {
    // Windows: Enable ANSI color support in console (for colored log output)
    #[cfg(windows)]
    {
        // Try to enable ANSI support. If it fails (old Windows), colors just won't work.
        let _ = ansi_term::enable_ansi_support();
    }

    // macOS: Tauri handles activation policy automatically via tauri.conf.json
    // No custom setup needed here.

    // Linux: Set process name for better process management (top, htop, ps)
    #[cfg(target_os = "linux")]
    {
        if let Err(e) = set_process_name("emergency-dlvry") {
            eprintln!("Warning: Could not set process name: {}", e);
        }
    }
}

/// Sets the process name on Linux using prctl(PR_SET_NAME).
/// This makes the process show as "emergency-dlvry" in `top`, `htop`, `ps`.
#[cfg(target_os = "linux")]
fn set_process_name(name: &str) -> Result<(), std::io::Error> {
    use std::ffi::CString;

    let name_cstr = CString::new(name).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
    })?;

    unsafe {
        extern "C" {
            fn prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i32;
        }

        const PR_SET_NAME: i32 = 15;
        let result = prctl(
            PR_SET_NAME,
            name_cstr.as_ptr() as u64,
            0,
            0,
            0,
        );

        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

// =============================================================================
// SINGLE INSTANCE GUARD
// =============================================================================

/// Gets the path to the lock file.
fn get_lock_path() -> std::path::PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("emergency-delivery")
        .join(".lock")
}

/// Attempts to acquire an exclusive file lock to prevent multiple instances.
///
/// # Why This Matters
/// SQLite WAL mode allows concurrent readers but only ONE writer. If two instances
/// try to write simultaneously, one will get SQLITE_BUSY errors. Worse, if both
/// instances hold open transactions, they can corrupt the database.
///
/// # Returns
/// - `true` if lock acquired successfully (this instance owns the lock)
/// - `false` if another instance already holds the lock
#[cfg(feature = "single-instance")]
fn acquire_single_instance_lock() -> bool {
    use fs2::FileExt;

    let lock_path = get_lock_path();

    // Create parent directory if it doesn't exist
    if let Some(parent) = lock_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Try to create and lock the file
    match std::fs::File::create(&lock_path) {
        Ok(file) => {
            match file.try_lock_exclusive() {
                Ok(()) => {
                    // Lock acquired! Keep the file handle alive for the lifetime of the program.
                    // We intentionally leak it with mem::forget so the lock is held until exit.
                    std::mem::forget(file);
                    true
                }
                Err(_) => {
                    // Another instance holds the lock
                    false
                }
            }
        }
        Err(_) => {
            // Could not create lock file (permissions issue?)
            // Fail open: allow the app to start rather than block the user
            eprintln!("Warning: Could not create lock file at {}", lock_path.display());
            true
        }
    }
}

// =============================================================================
// SIGNAL HANDLERS
// =============================================================================

/// Installs signal handlers for graceful shutdown.
///
/// Handles:
/// - Ctrl+C (SIGINT) on all platforms
/// - SIGTERM on Unix (Linux, macOS)
///
/// The SHUTDOWN_REQUESTED flag is checked by lib.rs background tasks to exit cleanly.
fn install_signal_handlers() {
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let flag_clone = shutdown_flag.clone();

    // Handle Ctrl+C (SIGINT) — works on Windows, macOS, Linux
    if let Err(e) = ctrlc::set_handler(move || {
        flag_clone.store(true, Ordering::SeqCst);
        SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
    }) {
        eprintln!("Warning: Could not install Ctrl+C handler: {}", e);
    }

    // Handle SIGTERM (Unix only) — sent by systemd, Docker, kill command
    #[cfg(unix)]
    {
        use signal_hook::consts::SIGTERM;
        use signal_hook::iterator::Signals;

        match Signals::new(&[SIGTERM]) {
            Ok(mut signals) => {
                std::thread::spawn(move || {
                    for sig in signals.forever() {
                        if sig == SIGTERM {
                            SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("Warning: Could not install SIGTERM handler: {}", e);
            }
        }
    }
}

// =============================================================================
// STARTUP VALIDATION
// =============================================================================

/// Validates that critical resources are available before starting the app.
///
/// Checks:
/// - Data directory exists and is writable
/// - Basic filesystem operations work
///
/// # Returns
/// - `Ok(())` if all checks pass
/// - `Err(...)` with descriptive error message
fn validate_startup_resources() -> Result<(), Box<dyn std::error::Error>> {
    // Get the data directory (platform-specific)
    let data_dir = dirs::data_local_dir()
        .ok_or("Could not determine data directory. Is %LOCALAPPDATA% set?")?
        .join("emergency-delivery");

    // Create the directory if it doesn't exist
    std::fs::create_dir_all(&data_dir)?;

    // Test write access by creating and deleting a temporary file
    let test_file = data_dir.join(".write_test");
    std::fs::write(&test_file, "test")?;
    std::fs::remove_file(&test_file)?;

    // Create the secure subdirectory (used for SQLite database)
    let secure_dir = data_dir.join("secure");
    std::fs::create_dir_all(&secure_dir)?;

    // Create the logs directory
    let logs_dir = data_dir.join("logs");
    std::fs::create_dir_all(&logs_dir)?;

    // Create the vault directory (for local storage fallback)
    let vault_dir = data_dir.join("vault");
    std::fs::create_dir_all(&vault_dir)?;

    Ok(())
}

// =============================================================================
// WINDOWS ERROR DIALOG
// =============================================================================

/// Shows a Windows error dialog box (release mode only).
///
/// This is used when the app cannot start (e.g., another instance running)
/// and there is no console window visible to show the error message.
#[cfg(all(windows, not(debug_assertions)))]
fn show_windows_error_dialog(title: &str, message: &str) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    let message_wide: Vec<u16> = OsStr::new(message)
        .encode_wide()
        .chain(Some(0))
        .collect();

    let title_wide: Vec<u16> = OsStr::new(title)
        .encode_wide()
        .chain(Some(0))
        .collect();

    unsafe {
        extern "system" {
            fn MessageBoxW(
                hwnd: *mut std::ffi::c_void,
                lp_text: *const u16,
                lp_caption: *const u16,
                u_type: u32,
            ) -> i32;
        }
        MessageBoxW(
            null_mut(),
            message_wide.as_ptr(),
            title_wide.as_ptr(),
            0x10, // MB_ICONERROR
        );
    }
}