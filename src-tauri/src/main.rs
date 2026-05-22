#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod wireguard;
mod utils;
pub mod multipath;

use std::sync::Arc;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use tracing_appender::rolling;
use tauri::Manager;
use wireguard::{WireGuardDll, TunnelState};
use crate::utils::resolve_dll_path;

fn setup_logging() -> tracing_appender::non_blocking::WorkerGuard {
    let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
    let log_dir = format!("{}\\GameAccelerator\\logs", app_data);
    let file_appender = rolling::daily(log_dir, "app.log");

    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_writer(non_blocking))
        .with(fmt::layer().with_writer(std::io::stdout))
        .init();

    guard
}

fn setup_panic_hook(
    dll: Arc<WireGuardDll>,
    adapter_state: Arc<std::sync::Mutex<Option<wireguard::WireGuardAdapterHandle>>>,
) {
    let default_hook = std::panic::take_hook();

    std::panic::set_hook(Box::new(move |info| {
        tracing::error!("💥 CRITICAL PANIC: {:?}", info);
        tracing::info!("Executing emergency network cleanup...");

        if let Ok(mut guard) = adapter_state.try_lock() {
            if let Some(handle) = guard.take() {
                let _ = dll.set_state(handle, wireguard::WireGuardAdapterState::Down);
                dll.close_adapter(handle);
            }
        }

        default_hook(info);
        std::process::exit(1);
    }));
}

fn main() -> anyhow::Result<()> {
    let _log_guard = setup_logging();

    tauri::Builder::default()
        .setup(|app| {
            // Загружаем DLL при старте
            let dll_path = resolve_dll_path(&app.handle(), "wireguard.dll")?;
            let dll_path_str = dll_path.to_str().ok_or("Invalid DLL path")?;
            let dll = Arc::new(WireGuardDll::load(dll_path_str)?);

            let tunnel_state = TunnelState::new(dll.clone());
            let (dll_for_hook, adapter_for_hook) = tunnel_state.clone_for_panic_hook();

            app.manage(tunnel_state);
            setup_panic_hook(dll_for_hook, adapter_for_hook);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            wireguard::tunnel_apply_config,
            wireguard::tunnel_disconnect,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");

    Ok(())
}