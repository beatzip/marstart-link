#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod wireguard;
mod utils;
pub mod multipath;

use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use tracing_appender::rolling;
use wireguard_nt::Adapter;
use std::sync::{Arc, Mutex};

fn setup_logging() -> tracing_appender::non_blocking::WorkerGuard {
    let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
    let log_dir = format!("{}\\GameAccelerator\\logs", app_data);
    let file_appender = rolling::daily(log_dir, "app.log");

    // ✅ non_blocking для избежания IO-блокировок на Windows
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_writer(non_blocking))
        .with(fmt::layer().with_writer(std::io::stdout))
        .init();

    guard // Возвращаем guard, чтобы он жил в main
}

fn setup_panic_hook(adapter_state: Arc<Mutex<Option<Adapter>>>) {
    let default_hook = std::panic::take_hook();

    std::panic::set_hook(Box::new(move |info| {
        tracing::error!("💥 CRITICAL PANIC: {:?}", info);
        tracing::info!("Executing emergency network cleanup...");

        if let Ok(mut guard) = adapter_state.try_lock() {
            if let Some(adapter) = guard.take() {
                drop(adapter);
            }
        }

        default_hook(info);
        std::process::exit(1);
    }));
}

fn main() -> anyhow::Result<()> {
    // ✅ Guard должен жить до конца main, иначе file writer сбросится
    let _log_guard = setup_logging();

    tauri::Builder::default()
        .manage(wireguard::TunnelState::new()) // ✅ Без Arc снаружи
        .setup(|app| {
            let state = app.state::<wireguard::TunnelState>();
            setup_panic_hook(state.inner().clone_for_panic_hook());
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