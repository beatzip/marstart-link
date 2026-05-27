#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

// ============================================================================
// MODULES
// ============================================================================
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
    // ✅ FIX: _guard must live for the ENTIRE program lifetime.
    // Previously it was dropped immediately after setup_logging() returned,
    // silently stopping all file logging from the first line of run_app().
    let _log_guard = setup_logging();

    if let Err(e) = run_app() {
        show_error_dialog(&format!("Failed to start Game Accelerator:\n\n{}", e));
        std::process::exit(1);
    }
}

// ============================================================================
// LOGGING
// ============================================================================
fn setup_logging() -> WorkerGuard {
    let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
    let log_dir = format!("{}\\GameAccelerator\\logs", app_data);
    let _ = std::fs::create_dir_all(&log_dir);

    let file_appender = rolling::daily(&log_dir, "app.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_writer(non_blocking))
        .with(fmt::layer().with_writer(std::io::stdout))
        .init();

    tracing::info!("========================================");
    tracing::info!("Game Accelerator starting...");
    tracing::info!("========================================");

    guard // returned so main() keeps it alive for the entire process lifetime
}

// ============================================================================
// TAURI APP
// ============================================================================
fn run_app() -> Result<(), Box<dyn std::error::Error>> {
    tauri::Builder::default()
        .setup(|app| {
            tracing::info!("Initializing WireGuard subsystem...");

            let handle = app.handle();

            let dll_path = resolve_dll_path(&handle, "wireguard.dll")
                .map_err(|e| format!("wireguard.dll not found: {}", e))?;

            tracing::info!("WireGuard DLL path: {:?}", dll_path);

            let dll_path_str = dll_path.to_str().ok_or("Invalid DLL path encoding")?;

            let dll = Arc::new(
                WireGuardDll::load(dll_path_str)
                    .map_err(|e| format!("Failed to load WireGuard DLL: {}", e))?,
            );

            tracing::info!("WireGuard DLL loaded successfully");

            let tunnel_state = TunnelState::new(dll.clone());

            let (dll_for_hook, adapter_for_hook) = tunnel_state.clone_for_panic_hook();
            wireguard::setup_panic_hook(dll_for_hook, adapter_for_hook);

            app.manage(tunnel_state);
            tracing::info!("Tunnel state registered");

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            wireguard::tunnel_apply_config,
            wireguard::tunnel_disconnect,
            wireguard::tunnel_get_status,
            wireguard::tunnel_get_stats,
            wireguard::tunnel_get_diagnostics,
        ])
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
