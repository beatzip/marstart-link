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

use base64::Engine;
use std::sync::{Arc, Mutex};
use tauri::State;

#[derive(Clone)]
struct AppState {
    tunnel: Arc<Mutex<Option<wireguard::WireGuardTunnel>>>,
}

#[tauri::command]
async fn connect(profile: Profile, state: State<'_, AppState>) -> Result<(), String> {
    let tunnel = tokio::task::spawn_blocking(move || wireguard::WireGuardTunnel::new(&profile))
        .await
        .map_err(|e| e.to_string())??;

    let (tunnel, connect_result) = tokio::task::spawn_blocking(move || {
        let mut tunnel = tunnel;
        let result = tunnel.connect();
        (tunnel, result)
    })
    .await
    .map_err(|e| e.to_string())?;

    if let Err(e) = connect_result {
        let _ = tokio::task::spawn_blocking(move || tunnel.teardown()).await;
        return Err(e);
    }

    let mut guard = state.tunnel.lock().map_err(|e| e.to_string())?;
    *guard = Some(tunnel);

    Ok(())
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    let tunnel = {
        let mut guard = state.tunnel.lock().map_err(|e| e.to_string())?;
        guard.take()
    };

    if let Some(tunnel) = tunnel {
        let _ = tokio::task::spawn_blocking(move || tunnel.teardown())
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string());
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
