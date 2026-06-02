#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod profiles;
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
    let tunnel = wireguard::WireGuardTunnel::new(&profile)?;
    *guard = Some(tunnel);
    Ok(())
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.tunnel.lock().map_err(|e| e.to_string())?;
    if let Some(tunnel) = guard.take() {
        tunnel.teardown()?;
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
