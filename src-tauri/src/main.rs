#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod wireguard;
mod utils;

use std::sync::Arc;
use tauri::Manager;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use tracing_appender::rolling;

use crate::utils::resolve_dll_path;
use crate::wireguard::{WireGuardDll, TunnelState};

fn main() {
    let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
    let log_dir = format!("{}\\GameAccelerator\\logs", app_data);
    let file_appender = rolling::daily(log_dir, "app.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_writer(non_blocking))
        .with(fmt::layer().with_writer(std::io::stdout))
        .init();

    tauri::Builder::default()
        .setup(|app| {
            let handle = app.handle();
           
            let dll_path = resolve_dll_path(&handle, "wireguard.dll")
                .expect("Failed to resolve wireguard.dll");
            let dll_path_str = dll_path.to_str().expect("Invalid DLL path");
            
            let dll = Arc::new(WireGuardDll::load(dll_path_str)
                .expect("Failed to load WireGuard DLL"));
            
            let tunnel_state = TunnelState::new(dll.clone());
            let (dll_for_hook, adapter_for_hook) = tunnel_state.clone_for_panic_hook();
            
            app.manage(tunnel_state);
            wireguard::setup_panic_hook(dll_for_hook, adapter_for_hook);
           
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            wireguard::tunnel_apply_config,
            wireguard::tunnel_disconnect,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}