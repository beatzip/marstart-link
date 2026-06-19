use crate::profiles::Profile;
use crate::wireguard_config::ParsedConfig;
use crate::wireguard_parser::{parse_wireguard_config, validate_config};
#[cfg(target_os = "windows")]
use crate::wireguard_serializer::{read_peer_stats, serialize_config};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use windows::core::{s, PCWSTR};
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{FreeLibrary, BOOL, HANDLE, HMODULE};
#[cfg(target_os = "windows")]
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

#[cfg(target_os = "windows")]
// ИСПРАВЛЕНО: Правильная сигнатура WireGuardCreateAdapter
type WireGuardCreateAdapterFunc =
    unsafe extern "system" fn(adapter_name: PCWSTR, tunnel_name: PCWSTR, reserved: *const std::ffi::c_void) -> HANDLE;

#[cfg(target_os = "windows")]
type WireGuardSetConfigurationFunc = unsafe extern "system" fn(
    adapter: HANDLE,
    config_bytes: *const std::ffi::c_void,
    config_size: u32,
) -> BOOL;

#[cfg(target_os = "windows")]
type WireGuardGetConfigurationFunc = unsafe extern "system" fn(
    adapter: HANDLE,
    config_bytes: *mut std::ffi::c_void,
    config_size: *mut u32,
) -> BOOL;

#[cfg(target_os = "windows")]
// ИСПРАВЛЕНО: Правильная сигнатура WireGuardDeleteAdapter (только HANDLE)
type WireGuardDeleteAdapterFunc = unsafe extern "system" fn(adapter: HANDLE);

fn get_dll_path(dll_name: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    exe.parent()
        .map(|p| p.join(dll_name))
        .unwrap_or_else(|| PathBuf::from(dll_name))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", content = "message")]
pub enum TunnelStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

#[derive(Debug, Default)]
pub struct TunnelCounters {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub last_handshake_unix: AtomicU64,
}

impl TunnelCounters {
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.tx_bytes.load(Ordering::Relaxed),
            self.rx_bytes.load(Ordering::Relaxed),
            self.last_handshake_unix.load(Ordering::Relaxed),
        )
    }

    pub fn clear(&self) {
        self.tx_bytes.store(0, Ordering::Relaxed);
        self.rx_bytes.store(0, Ordering::Relaxed);
        self.last_handshake_unix.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub handshake_timestamp_unix: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub endpoint: Option<String>,
}

pub struct WireGuardTunnel {
    adapter_name: String,
    config: ParsedConfig,
    status: Mutex<TunnelStatus>,
    counters: Arc<TunnelCounters>,
    connect_time: Mutex<Option<Instant>>,
    #[cfg(target_os = "windows")]
    adapter_handle: Mutex<Option<HANDLE>>,
    #[cfg(target_os = "windows")]
    wg_lib: HMODULE,
    #[cfg(target_os = "windows")]
    fn_create: WireGuardCreateAdapterFunc,
    #[cfg(target_os = "windows")]
    fn_delete: WireGuardDeleteAdapterFunc,
    #[cfg(target_os = "windows")]
    fn_set_cfg: WireGuardSetConfigurationFunc,
    #[cfg(target_os = "windows")]
    fn_get_cfg: WireGuardGetConfigurationFunc,
}

impl WireGuardTunnel {
    pub fn new(profile: &Profile) -> Result<Self, String> {
        let config_path = profile
            .wg_config_path
            .as_deref()
            .ok_or_else(|| format!("profile '{}' has no WireGuard config path", profile.id))?;
        let config_text = std::fs::read_to_string(config_path)
            .map_err(|e| format!("failed to read WireGuard config '{}': {e}", config_path))?;
        let config = parse_wireguard_config(&config_text)?;
        validate_config(&config)?;

        #[cfg(target_os = "windows")]
        let (wg_lib, fn_create, fn_delete, fn_set_cfg, fn_get_cfg) = {
            let dll_path = get_dll_path("wireguard.dll");
            let dll_path_wide = wide_path(&dll_path);
            let lib = unsafe { LoadLibraryW(PCWSTR(dll_path_wide.as_ptr())) }
                .map_err(|e| format!("failed to load wireguard.dll: {e}"))?;
            let create_proc = unsafe {
                GetProcAddress(lib, s!("WireGuardCreateAdapter"))
                    .ok_or_else(|| "WireGuardCreateAdapter not found".to_string())?
            };
            let delete_proc = unsafe {
                GetProcAddress(lib, s!("WireGuardDeleteAdapter"))
                    .ok_or_else(|| "WireGuardDeleteAdapter not found".to_string())?
            };
            let set_cfg_proc = unsafe {
                GetProcAddress(lib, s!("WireGuardSetConfiguration"))
                    .ok_or_else(|| "WireGuardSetConfiguration not found".to_string())?
            };
            let get_cfg_proc = unsafe {
                GetProcAddress(lib, s!("WireGuardGetConfiguration"))
                    .ok_or_else(|| "WireGuardGetConfiguration not found".to_string())?
            };
            (
                lib,
                unsafe {
                    std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        WireGuardCreateAdapterFunc,
                    >(create_proc)
                },
                unsafe {
                    std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        WireGuardDeleteAdapterFunc,
                    >(delete_proc)
                },
                unsafe {
                    std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        unsafe extern "system" fn(HANDLE, *const std::ffi::c_void, u32) -> BOOL,
                    >(set_cfg_proc)
                },
                unsafe {
                    std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        unsafe extern "system" fn(HANDLE, *mut std::ffi::c_void, *mut u32) -> BOOL,
                    >(get_cfg_proc)
                },
            )
        };

        Ok(Self {
            adapter_name: format!("MARSTART-{}", profile.id),
            config,
            status: Mutex::new(TunnelStatus::Disconnected),
            counters: Arc::new(TunnelCounters::default()),
            connect_time: Mutex::new(None),
            #[cfg(target_os = "windows")]
            adapter_handle: Mutex::new(None),
            #[cfg(target_os = "windows")]
            wg_lib,
            #[cfg(target_os = "windows")]
            fn_create,
            #[cfg(target_os = "windows")]
            fn_delete,
            #[cfg(target_os = "windows")]
            fn_set_cfg,
            #[cfg(target_os = "windows")]
            fn_get_cfg,
        })
    }

    pub fn connect(&mut self) -> Result<(), String> {
        {
            let mut status = self.status.lock().map_err(|e| e.to_string())?;
            match &*status {
                TunnelStatus::Connected | TunnelStatus::Connecting => {
                    return Err("tunnel is already active".to_string());
                }
                TunnelStatus::Disconnected | TunnelStatus::Error(_) => {
                    *status = TunnelStatus::Connecting;
                }
            }
        }

        let result = self.connect_impl();
        match result {
            Ok(()) => {
                *self.status.lock().map_err(|e| e.to_string())? = TunnelStatus::Connected;
                *self.connect_time.lock().map_err(|e| e.to_string())? = Some(Instant::now());
                Ok(())
            }
            Err(e) => {
                *self.status.lock().map_err(|lock| lock.to_string())? =
                    TunnelStatus::Error(e.clone());
                let _ = self.teardown();
                Err(e)
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn connect_impl(&mut self) -> Result<(), String> {
        let tunnel_wide = wide_str(&self.adapter_name);
        let tunnel_name = PCWSTR(tunnel_wide.as_ptr());
        
        // ИСПРАВЛЕНО: Передаем имя адаптера, имя туннеля и null для reserved
        let handle = unsafe { (self.fn_create)(tunnel_name, tunnel_name, std::ptr::null()) };

        if handle.0 == 0 {
            return Err("failed to create WireGuard adapter".to_string());
        }

        *self.adapter_handle.lock().map_err(|e| e.to_string())? = Some(handle);

        let config_blob = serialize_config(&self.config)
            .map_err(|e| format!("failed to serialize config: {e}"))?;
        
        let ok = unsafe {
            (self.fn_set_cfg)(
                handle,
                config_blob.as_ptr() as *const std::ffi::c_void,
                config_blob.len() as u32,
            )
        };
        if !ok.as_bool() {
            let os_err = std::io::Error::last_os_error();
            let _ = self.delete_adapter_handle();
            return Err(format!("WireGuardSetConfiguration failed: {os_err}"));
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn connect_impl(&mut self) -> Result<(), String> {
        Err("WireGuard control is only supported on Windows".to_string())
    }

    pub fn teardown(&self) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        self.delete_adapter_handle()?;

        self.counters.clear();
        *self.connect_time.lock().map_err(|e| e.to_string())? = None;
        *self.status.lock().map_err(|e| e.to_string())? = TunnelStatus::Disconnected;
        Ok(())
    }

    pub fn status(&self) -> TunnelStatus {
        self.status
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_else(|_| TunnelStatus::Error("tunnel status lock poisoned".to_string()))
    }

    pub fn stats(&self) -> Result<(u64, u64, u64), String> {
        #[cfg(target_os = "windows")]
        {
            let handle = *self.adapter_handle.lock().map_err(|e| e.to_string())?;
            if let Some(handle) = handle {
                let stats = self.read_peer_stats(handle)?;
                self.counters.tx_bytes.store(stats.0, Ordering::Relaxed);
                self.counters.rx_bytes.store(stats.1, Ordering::Relaxed);
                self.counters
                    .last_handshake_unix
                    .store(stats.2, Ordering::Relaxed);
                return Ok(stats);
            }
        }

        Ok(self.counters.snapshot())
    }

    pub fn connection_info(&self) -> Result<ConnectionInfo, String> {
        let (tx, rx, handshake) = self.stats()?;
        Ok(ConnectionInfo {
            handshake_timestamp_unix: handshake,
            tx_bytes: tx,
            rx_bytes: rx,
            endpoint: self
                .config
                .peers
                .first()
                .and_then(|peer| peer.endpoint)
                .map(|endpoint| endpoint.to_string()),
        })
    }

    pub fn elapsed(&self) -> Option<Duration> {
        self.connect_time.lock().ok().and_then(|guard| {
            let started = *guard;
            started.map(|instant| instant.elapsed())
        })
    }

    #[cfg(target_os = "windows")]
    fn delete_adapter_handle(&self) -> Result<(), String> {
        let handle = self
            .adapter_handle
            .lock()
            .map_err(|e| e.to_string())?
            .take();
        let Some(handle) = handle else {
            return Ok(());
        };

        // ИСПРАВЛЕНО: Передаем только handle
        unsafe {
            (self.fn_delete)(handle);
            let _ = windows::Win32::Foundation::CloseHandle(handle);
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn read_peer_stats(&self, handle: HANDLE) -> Result<(u64, u64, u64), String> {
        let mut buf_size: u32 = 0;
        unsafe {
            (self.fn_get_cfg)(handle, std::ptr::null_mut(), &mut buf_size);
        }
        if buf_size == 0 {
            return Ok((0, 0, 0));
        }

        let mut buffer = vec![0u8; buf_size as usize];
        let ok = unsafe { (self.fn_get_cfg)(handle, buffer.as_mut_ptr() as *mut _, &mut buf_size) };
        if !ok.as_bool() {
            return Ok((0, 0, 0));
        }

        Ok(read_peer_stats(&buffer)
            .into_iter()
            .next()
            .unwrap_or((0, 0, 0)))
    }
}

#[cfg(target_os = "windows")]
fn wide_str(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(target_os = "windows")]
fn wide_path(value: &std::path::Path) -> Vec<u16> {
    value
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(target_os = "windows")]
impl Drop for WireGuardTunnel {
    fn drop(&mut self) {
        // ИСПРАВЛЕНО: Гарантированно удаляем адаптер перед уничтожением объекта
        let _ = self.delete_adapter_handle();
        
        // Free the DLL when tunnel is dropped
        unsafe {
            let _ = FreeLibrary(self.wg_lib);
        }
    }
}
