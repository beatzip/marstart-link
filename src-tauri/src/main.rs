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

use std::sync::{Arc, Mutex}; // CHANGED: добавлен Mutex

use serde::{Deserialize, Serialize}; // NEW
use tauri::Manager;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::utils::resolve_dll_path;
use crate::wireguard::{TunnelState, WireGuardDll};

// ============================================================================
// NEW: Общий путь к директории логов
//
// Выделен в функцию, чтобы одно место использовалось и в setup_logging(),
// и в Tauri-команде get_log_path() — без дублирования строки.
// ============================================================================
fn log_dir() -> String {
    let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
    format!("{}\\GameAccelerator\\logs", app_data)
}

// ============================================================================
// NEW: Версия ОС для заголовка лога
//
// Читаем из реестра (winreg уже в зависимостях).
// На не-Windows возвращает имя платформы из std.
// ============================================================================
fn os_version_string() -> String {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion") {
            let product: String = key.get_value("ProductName").unwrap_or_default();
            let build: String = key.get_value("CurrentBuildNumber").unwrap_or_default();
            let ubr: u32 = key.get_value("UBR").unwrap_or(0u32);
            return format!("{product} (Build {build}.{ubr})");
        }
    }
    std::env::consts::OS.to_string()
}

// ============================================================================
// NEW: Структура результатов диагностики запуска
//
// Создаётся в .setup(), заполняется пошагово, управляется как Tauri state.
// Фронтенд запрашивает её через get_startup_diagnostics() при старте.
// ============================================================================
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StartupDiagnostic {
    /// wireguard.dll найден в resources/
    pub wireguard_dll_found: bool,
    /// Полный путь к wireguard.dll (если найден)
    pub wireguard_dll_path: Option<String>,
    /// wintun.dll найден в resources/
    pub wintun_dll_found: bool,
    /// Полный путь к wintun.dll (если найден)
    pub wintun_dll_path: Option<String>,
    /// WireGuardDll::load() прошёл успешно
    pub wireguard_dll_loaded: bool,
    /// Ошибка загрузки DLL (None если успех)
    pub load_error: Option<String>,
    /// Путь к директории лог-файлов
    pub log_dir: String,
    /// Версия Windows из реестра
    pub os_info: String,
}

// ============================================================================
// NEW: Tauri-команды диагностики и журнала
//
// Три команды:
//  - get_log_path()              → путь к папке логов (для кнопки "Открыть журнал")
//  - get_startup_diagnostics()   → результаты проверок при старте
//  - open_log_dir()              → открыть папку в Проводнике (Windows)
//
// НЕ ЗАБЫТЬ: все три должны быть добавлены в permissions/allow-app-commands.toml
// ============================================================================

/// Возвращает путь к директории лог-файлов.
/// UI использует это чтобы показать пользователю "где смотреть при ошибке".
#[tauri::command]
fn get_log_path() -> String {
    log_dir()
}

/// Возвращает снимок StartupDiagnostic, собранного при запуске.
/// UI использует это для экрана первичной диагностики / отладки.
#[tauri::command]
fn get_startup_diagnostics(state: tauri::State<'_, Mutex<StartupDiagnostic>>) -> StartupDiagnostic {
    state.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

/// Открывает папку с логами в Проводнике.
/// Вызывается из UI при нажатии "Открыть журнал".
#[tauri::command]
fn open_log_dir() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let dir = log_dir();
        // Создать директорию если ещё нет (например при первом запуске)
        let _ = std::fs::create_dir_all(&dir);
        std::process::Command::new("explorer.exe")
            .arg(&dir)
            .spawn()
            .map_err(|e| format!("Не удалось открыть папку логов: {e}"))?;
    }
    Ok(())
}

// ============================================================================
// ENTRY
// ============================================================================
fn main() {
    // WorkerGuard должен жить до конца main(), иначе буфер не сбросится.
    let _log_guard: WorkerGuard = setup_logging();

    if let Err(e) = run_app() {
        show_error_dialog(&format!("Failed to start Game Accelerator:\n\n{}", e));
        std::process::exit(1);
    }
    // _log_guard дропается здесь → фоновый поток сбрасывает оставшиеся записи
}

// ============================================================================
// LOGGING  (CHANGED: используем log_dir(), добавлен заголовок с OS/version)
// ============================================================================
fn setup_logging() -> WorkerGuard {
    // CHANGED: вместо inline-строки — общая функция log_dir()
    let dir = log_dir();
    let _ = std::fs::create_dir_all(&dir);

    cleanup_old_logs(&dir, 7);

    let file_appender = rolling::daily(&dir, "app.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_writer(non_blocking))
        .with(fmt::layer().with_writer(std::io::stdout))
        .init();

    // CHANGED: добавлена версия приложения и версия ОС
    tracing::info!("===========================================");
    tracing::info!("Game Accelerator v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Log dir: {}", dir);
    tracing::info!("OS: {}", os_version_string());
    tracing::info!("===========================================");

    guard
}

/// Удаляет лог-файлы старше `keep_days` дней. Вызывается один раз при старте.
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
                    if modified < cutoff {
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
        }
    }
}

// ============================================================================
// TAURI APP  (CHANGED: .setup() переработан — пошаговая диагностика DLL)
// ============================================================================
fn run_app() -> Result<(), Box<dyn std::error::Error>> {
    tauri::Builder::default()
        .setup(|app| {
            let handle = app.handle();

            tracing::info!("=== STARTUP DIAGNOSTICS ===");

            // ── Инициализируем диагностику ─────────────────────────────────
            // Заполняем её пошагово ниже; manage() вызываем ДО первого ?
            // чтобы фронтенд мог запросить её даже при фатальной ошибке.
            let mut diag = StartupDiagnostic {
                log_dir: log_dir(),
                os_info: os_version_string(),
                ..Default::default()
            };

            // ── [1/4] Check wireguard.dll ──────────────────────────────────
            let wireguard_path_opt = match resolve_dll_path(handle, "wireguard.dll") {
                Ok(path) => {
                    tracing::info!("[DIAG] [1/4] wireguard.dll FOUND: {:?}", path);
                    diag.wireguard_dll_found = true;
                    diag.wireguard_dll_path = Some(path.to_string_lossy().into_owned());
                    Some(path)
                }
                Err(e) => {
                    tracing::error!("[DIAG] [1/4] wireguard.dll NOT FOUND: {e}");
                    None
                }
            };

            // ── [2/4] Check wintun.dll ─────────────────────────────────────
            // wintun.dll загружается неявно через wireguard.dll из той же директории.
            // Проверяем его наличие отдельно для ранней диагностики:
            // если wintun.dll отсутствует, wireguard.dll упадёт с невнятной ошибкой.
            match resolve_dll_path(handle, "wintun.dll") {
                Ok(path) => {
                    tracing::info!("[DIAG] [2/4] wintun.dll FOUND: {:?}", path);
                    diag.wintun_dll_found = true;
                    diag.wintun_dll_path = Some(path.to_string_lossy().into_owned());
                }
                Err(e) => {
                    tracing::warn!(
                        "[DIAG] [2/4] wintun.dll NOT FOUND (wireguard.dll load may fail): {e}"
                    );
                }
            }

            // ── [3/4] Load wireguard.dll ───────────────────────────────────
            let dll_result: Result<Arc<WireGuardDll>, String> = match wireguard_path_opt {
                Some(path) => match path.to_str() {
                    Some(path_str) => match WireGuardDll::load(path_str) {
                        Ok(dll) => {
                            tracing::info!("[DIAG] [3/4] wireguard.dll LOADED OK");
                            diag.wireguard_dll_loaded = true;
                            Ok(Arc::new(dll))
                        }
                        Err(e) => {
                            let msg = format!(
                                "Не удалось загрузить wireguard.dll: {e}\n\
                                 Убедитесь, что wintun.dll также находится рядом с wireguard.dll."
                            );
                            tracing::error!("[DIAG] [3/4] DLL load FAILED: {e}");
                            diag.load_error = Some(msg.clone());
                            Err(msg)
                        }
                    },
                    None => {
                        let msg = "Некорректный путь к wireguard.dll (non-UTF8 path)".to_string();
                        diag.load_error = Some(msg.clone());
                        Err(msg)
                    }
                },
                None => {
                    let msg = "wireguard.dll не найден в resources/. \
                               Убедитесь, что DLL скопирована в ресурсы приложения."
                        .to_string();
                    diag.load_error = Some(msg.clone());
                    Err(msg)
                }
            };

            // ── Регистрируем StartupDiagnostic ДО любого ? ─────────────────
            // Это гарантирует, что get_startup_diagnostics() работает даже при
            // фатальном сбое загрузки DLL.
            app.manage(Mutex::new(diag));

            // Теперь можно использовать ? — ошибка покажет диалог,
            // а фронтенд (если успеет инициализироваться) увидит load_error.
            let dll = dll_result?;

            // ── [4/4] Tunnel subsystem ─────────────────────────────────────
            tracing::info!("[DIAG] [4/4] Initializing tunnel subsystem...");

            let tunnel_state = TunnelState::new(dll.clone());

            // Panic hook: чистим адаптер и роуты при панике
            let (dll_ph, adapter_ph, runtime_ph) = tunnel_state.clone_for_panic_hook();
            wireguard::setup_panic_hook(dll_ph, adapter_ph, runtime_ph);

            // Фоновые мониторы (sleep/resume, route change, DNS refresh)
            wireguard::spawn_power_monitor(tunnel_state.reconnect_on_resume.clone());
            wireguard::spawn_route_monitor(tunnel_state.runtime.clone(), tunnel_state.dll.clone());
            wireguard::spawn_dns_refresher(tunnel_state.runtime.clone());

            app.manage(tunnel_state);

            tracing::info!("[DIAG] [4/4] Tunnel subsystem OK");
            tracing::info!("=== STARTUP COMPLETE ===");

            Ok(())
        })
        // ====================================================================
        // IPC COMMANDS  (CHANGED: добавлены 3 новых команды диагностики)
        // ====================================================================
        .invoke_handler(tauri::generate_handler![
            // Tunnel control
            wireguard::tunnel_apply_config,
            wireguard::tunnel_disconnect,
            wireguard::tunnel_get_status,
            wireguard::tunnel_get_stats,
            wireguard::tunnel_get_diagnostics,
            wireguard::tunnel_clear_reconnect_flag,
            // Secure key storage
            profiles::keyring_set,
            profiles::keyring_get,
            profiles::keyring_delete,
            // NEW: Diagnostics & log access
            get_log_path,
            get_startup_diagnostics,
            open_log_dir,
        ])
        .run(tauri::generate_context!())
        .map_err(|e| format!("Tauri runtime error: {}", e))?;

    Ok(())
}

// ============================================================================
// ERROR DIALOG  (без изменений)
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