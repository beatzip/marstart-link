#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod autopilot;
mod events;
mod game_detection;
mod loadbalance;
mod metrics;
mod monitor;
mod net_probe;
mod profiles;
mod ringbuf;
mod routes;
mod snapshot;
mod utils;
mod wireguard;
mod wireguard_config;
mod wireguard_parser;
mod wireguard_serializer;

use std::sync::{Arc, Mutex};
use tauri::State;

#[derive(Clone)]
struct AppState {
    tunnel: Arc<Mutex<Option<wireguard::WireGuardTunnel>>>,
}

#[tauri::command]
async fn connect(profile_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.tunnel.lock().map_err(|e| e.to_string())?;
    if guard.is_some() {
        return Err("Туннель уже активен".into());
    }
    let profile = profiles::load_profile(&profile_id)?;
    // Verify config file exists
    if let Some(ref config_path) = profile.wg_config_path {
        if !std::path::Path::new(config_path).exists() {
            return Err(format!("WireGuard config not found: {}", config_path));
        }
    }

    // Create tunnel in blocking context
    let tunnel = tokio::task::spawn_blocking(move || wireguard::WireGuardTunnel::new(&profile))
        .await
        .map_err(|e| e.to_string())??;

    // Connect in blocking context, returning tunnel regardless of result
    let (tunnel, connect_result) = tokio::task::spawn_blocking(move || {
        let mut tunnel = tunnel;
        let result = tunnel.connect();
        (tunnel, result)
    })
    .await
    .map_err(|e| e.to_string())?;

    if let Err(e) = connect_result {
        // Cleanup on connect failure - ensure adapter is removed from system
        let _ = tokio::task::spawn_blocking(move || tunnel.teardown()).await;
        return Err(e);
    }
    *guard = Some(tunnel);
    Ok(())
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.tunnel.lock().map_err(|e| e.to_string())?;
    if let Some(tunnel) = guard.take() {
        // Teardown in blocking context, errors are tolerant
        let _ = tokio::task::spawn_blocking(move || tunnel.teardown())
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string());
        // Teardown errors are logged but don't fail the disconnect operation
    }
    Ok(())
}

#[tauri::command]
async fn get_status(state: State<'_, AppState>) -> Result<wireguard::TunnelStatus, String> {
    let guard = state.tunnel.lock().map_err(|e| e.to_string())?;
    Ok(if let Some(t) = &*guard {
        t.status()
    } else {
        wireguard::TunnelStatus::Disconnected
    })
}

fn main() {
    let state = AppState {
        tunnel: Arc::new(Mutex::new(None)),
    };

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![connect, disconnect, get_status])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
