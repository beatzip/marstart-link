#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

// ============================================================================
// MODULES
// ============================================================================
mod profiles;
mod utils;
mod wireguard;
mod wireguard_config;
mod wireguard_parser;
mod wireguard_serializer;

use std::sync::Arc;

use tauri::Manager;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::utils::resolve_dll_path;
use crate::wireguard::{TunnelState, WireGuardDll};

// ============================================================================
// ENTRY
// ============================================================================
fn main() {
    // CRIT-1 FIX: WorkerGuard must be held until end of main().
    // Previous code used `_guard` which drops immediately, losing all file logs.
    let _log_guard: WorkerGuard = setup_logging();

    if let Err(e) = run_app() {
        show_error_dialog(&format!("Failed to start Game Accelerator:\n\n{}", e));
        std::process::exit(1);
    }
    // _log_guard drops here → background thread flushes remaining log entries
}

// ============================================================================
// LOGGING  (CRIT-1 fix + log rotation)
// ============================================================================
fn setup_logging() -> WorkerGuard {
    let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
    let log_dir = format!("{}\\GameAccelerator\\logs", app_data);
    let _ = std::fs::create_dir_all(&log_dir);

    // Rotate: keep last 7 daily log files, delete older ones at startup
    cleanup_old_logs(&log_dir, 7);

    let file_appender = rolling::daily(&log_dir, "app.log");

    // CRIT-1: non_blocking returns (Writer, WorkerGuard). Guard MUST be kept alive.
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_writer(non_blocking))
        .with(fmt::layer().with_writer(std::io::stdout))
        .init();

    tracing::info!("========================================");
    tracing::info!("Game Accelerator starting...");
    tracing::info!("Log directory: {}", log_dir);
    tracing::info!("========================================");

    guard // <── held by caller until process exit
}

/// Delete log files older than `keep_days` days. Called once at startup.
fn cleanup_old_logs(log_dir: &str, keep_days: u64) {
    use std::time::{Duration, SystemTime};
    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(keep_days * 86_400))
        .unwrap_or(SystemTime::UNIX_EPOCH);

    if let Ok(entries) = std::fs::read_dir(log_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let is_log = path.extension().map(|e| e == "log").unwrap_or(false);
            if !is_log {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                if let Ok(modified) = meta.modified() {
                    if modified < cutoff && std::fs::remove_file(&path).is_ok() {
                        // Can't use tracing here — subscriber not yet set up at first call.
                        // Subsequent calls (after reinit) could use tracing.
                    }
                }
            }
        }
    }
}

// ============================================================================
// TAURI APP
// ============================================================================
fn run_app() -> Result<(), Box<dyn std::error::Error>> {
    tauri::Builder::default()
        .setup(|app| {
            tracing::info!("Initializing WireGuard subsystem...");

            let handle = app.handle();

            // ── Resolve + load DLL ──────────────────────────────────────────
            let dll_path = resolve_dll_path(handle, "wireguard.dll")
                .map_err(|e| format!("wireguard.dll not found: {}", e))?;
            tracing::info!("WireGuard DLL path: {:?}", dll_path);

            let dll_path_str = dll_path.to_str().ok_or("Invalid DLL path encoding")?;
            let dll = Arc::new(
                WireGuardDll::load(dll_path_str)
                    .map_err(|e| format!("Failed to load WireGuard DLL: {}", e))?,
            );
            tracing::info!("WireGuard DLL loaded successfully");

            // ── Tunnel state ────────────────────────────────────────────────
            let tunnel_state = TunnelState::new(dll.clone());

            // ── Panic hook with full runtime cleanup (Task-4 fix) ───────────
            let (dll_ph, adapter_ph, runtime_ph) = tunnel_state.clone_for_panic_hook();
            wireguard::setup_panic_hook(dll_ph, adapter_ph, runtime_ph);

            // ── Background monitors ─────────────────────────────────────────
            // M-1: Sleep/resume monitor → sets reconnect_on_resume flag
            wireguard::spawn_power_monitor(tunnel_state.reconnect_on_resume.clone());

            // M-6: Route change monitor → refreshes bypass route on gateway change
            wireguard::spawn_route_monitor(tunnel_state.runtime.clone(), tunnel_state.dll.clone());
            wireguard::spawn_dns_refresher(tunnel_state.runtime.clone());

            // ── Register managed state ──────────────────────────────────────
            app.manage(tunnel_state);
            tracing::info!("Tunnel state registered");
            Ok(())
        })
        // ====================================================================
        // IPC COMMANDS
        // ====================================================================
        .invoke_handler(tauri::generate_handler![
            wireguard::tunnel_apply_config,
            wireguard::tunnel_disconnect,
            wireguard::tunnel_get_status,
            wireguard::tunnel_get_stats,
            wireguard::tunnel_get_diagnostics,
            wireguard::tunnel_clear_reconnect_flag,
            profiles::keyring_set,
            profiles::keyring_get,
            profiles::keyring_delete,
        ])
        // ====================================================================
        // RUN
        // ====================================================================
        .run(tauri::generate_context!())
        .map_err(|e| format!("Tauri runtime error: {}", e))?;

    Ok(())
}

// ============================================================================
// ERROR DIALOG
// ============================================================================
fn show_error_dialog(message: &str) {
    #[cfg(target_os = "windows")]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

        let msg_wide: Vec<u16> = OsStr::new(message).encode_wide().chain(Some(0)).collect();
        let title_wide: Vec<u16> = OsStr::new("Game Accelerator Error")
            .encode_wide()
            .chain(Some(0))
            .collect();
        unsafe {
            MessageBoxW(
                None,
                PCWSTR(msg_wide.as_ptr()),
                PCWSTR(title_wide.as_ptr()),
                MB_ICONERROR | MB_OK,
            );
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        eprintln!("ERROR: {}", message);
    }
}
