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

fn setup_logging() {
    let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
    let log_dir = format!("{}\\GameAccelerator\\logs", app_data);
    let file_appender = rolling::daily(log_dir, "app.log");

    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env().add_directive("info".into()))
        .with(fmt::layer().with_writer(file_appender))
        .with(fmt::layer().with_writer(std::io::stdout))
        .init();
}

fn setup_panic_hook(
    tunnel_state: Arc<wireguard::TunnelState>,
) {
    let default_hook = std::panic::take_hook();

    std::panic::set_hook(Box::new(move |info| {
        tracing::error!("💥 CRITICAL PANIC: {:?}", info);
        tracing::info!("Executing emergency network cleanup...");

        if let Ok(mut guard) = tunnel_state.adapter.try_lock() {
            if let Some(adapter) = guard.take() {
                let _ = adapter.set_state(wireguard_nt::AdapterState::Down);
                drop(adapter);
            }
        }

        default_hook(info);
        std::process::exit(1);
    }));
}

fn main() -> anyhow::Result<()> {
    setup_logging();
    let tunnel_state = Arc::new(wireguard::TunnelState::new());
    setup_panic_hook(tunnel_state.clone());

    tauri::Builder::default()
        .manage(tunnel_state)
        .run(tauri::generate_context()?)?;

    Ok(())
}