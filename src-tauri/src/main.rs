#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

// ✅ 1. 必须在根目录声明所有模块，包括 wireguard_serializer
mod wireguard;
mod wireguard_config;
mod wireguard_parser;
mod wireguard_serializer; // ✅ 必须加上，因为 wireguard.rs 依赖它
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
    let _ = std::fs::create_dir_all(&log_dir);
    let file_appender = rolling::daily(&log_dir, "app.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_writer(non_blocking))
        .with(fmt::layer().with_writer(std::io::stdout))
        .init();

    if let Err(e) = run_app() {
        show_error_dialog(&format!("Failed to start Game Accelerator:\n\n{}", e));
        std::process::exit(1);
    }
}

fn run_app() -> Result<(), Box<dyn std::error::Error>> {
    tauri::Builder::default()
        .setup(|app| {
            let handle = app.handle();
            let dll_path = resolve_dll_path(&handle, "wireguard.dll")
                .map_err(|e| format!("DLL not found: {}", e))?;
            let dll_path_str = dll_path.to_str()
                .ok_or("Invalid DLL path encoding")?;

            let dll = Arc::new(
                WireGuardDll::load(dll_path_str)
                    .map_err(|e| format!("Failed to load DLL: {}", e))?
            );

            let tunnel_state = TunnelState::new(dll.clone());
            let (dll_for_hook, adapter_for_hook) = tunnel_state.clone_for_panic_hook();

            app.manage(tunnel_state);
            wireguard::setup_panic_hook(dll_for_hook, adapter_for_hook);
           
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            wireguard::tunnel_apply_config,
            wireguard::tunnel_disconnect,
            wireguard::tunnel_get_stats, // ✅ 2. 必须注册你新加的统计命令
        ])
        // ✅ 修复：generate_context!() 返回 Context 而不是 Result，不能加 ?
        .run(tauri::generate_context!())
        .map_err(|e| format!("Tauri runtime error: {}", e))?;

    Ok(())
}

fn show_error_dialog(message: &str) {
    #[cfg(target_os = "windows")]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
        use windows::core::PCWSTR;

        let msg_wide: Vec<u16> = OsStr::new(message).encode_wide().chain(Some(0)).collect();
        let title_wide: Vec<u16> = OsStr::new("Game Accelerator Error")
            .encode_wide().chain(Some(0)).collect();

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
    eprintln!("ERROR: {}", message);
}