// ✅ ИСПРАВЛЕНО: pub mod перенесены в main.rs, здесь только use crate::
use crate::wireguard_config;
use crate::wireguard_parser;

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ✅ ИСПРАВЛЕНО: убран неиспользуемый Symbol (был warning → в CI станет error)
use libloading::Library;
use serde::{Deserialize, Serialize};
use tauri::State;
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToIndex, GetIfEntry2, GetIpForwardEntry2, GetIpInterfaceEntry,
    InitializeIpInterfaceEntry, SetIpForwardEntry2, SetIpInterfaceEntry, MIB_IF_ROW2,
    MIB_IPINTERFACE_ROW,
};
use windows::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows::Win32::Networking::WinSock::AF_INET;

use crate::utils::{create_forward_row, parse_cidr};

// ============================================================================
// Newtype для Send + Sync (сырой указатель на handle адаптера)
// ============================================================================
#[derive(Clone, Copy)]
pub struct WireGuardAdapterHandle(*mut c_void);

unsafe impl Send for WireGuardAdapterHandle {}
unsafe impl Sync for WireGuardAdapterHandle {}

// ============================================================================
// WireGuard Adapter State (из wireguard.h)
// ============================================================================
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireGuardAdapterState {
    Down = 0,
    Up = 1,
}

// ============================================================================
// FFI Type Aliases (точные сигнатуры из wireguard.h)
// ============================================================================
type WireGuardCreateAdapterFn = unsafe extern "system" fn(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: *const c_void,
) -> *mut c_void;

type WireGuardCloseAdapterFn = unsafe extern "system" fn(adapter: *mut c_void);

type WireGuardSetStateFn = unsafe extern "system" fn(
    adapter: *mut c_void,
    state: WireGuardAdapterState,
) -> i32;

type WireGuardGetAdapterLuidFn = unsafe extern "system" fn(
    adapter: *mut c_void,
    luid: *mut NET_LUID_LH,
);

type WireGuardSetConfigurationFn = unsafe extern "system" fn(
    adapter: *mut c_void,
    bytes: *const u8,
    size: u32,
) -> i32;

type WireGuardGetConfigurationFn = unsafe extern "system" fn(
    adapter: *mut c_void,
    bytes: *mut u8,
    size: *mut u32,
) -> i32;

// ============================================================================
// WireGuard DLL Wrapper
// ============================================================================
pub struct WireGuardDll {
    _lib: Library,
    create_adapter_fn: WireGuardCreateAdapterFn,
    close_adapter_fn: WireGuardCloseAdapterFn,
    set_state_fn: WireGuardSetStateFn,
    get_adapter_luid_fn: WireGuardGetAdapterLuidFn,
    set_configuration_fn: WireGuardSetConfigurationFn,
    get_configuration_fn: WireGuardGetConfigurationFn,
}

impl WireGuardDll {
    pub fn load(path: &str) -> Result<Self, String> {
        unsafe {
            let lib = Library::new(path).map_err(|e| format!("Failed to load DLL: {e}"))?;

            let create_adapter_fn = *lib.get(b"WireGuardCreateAdapter").map_err(|e| format!("Symbol not found: {e}"))?;
            let close_adapter_fn = *lib.get(b"WireGuardCloseAdapter").map_err(|e| format!("Symbol not found: {e}"))?;
            let set_state_fn = *lib.get(b"WireGuardSetState").map_err(|e| format!("Symbol not found: {e}"))?;
            let get_adapter_luid_fn = *lib.get(b"WireGuardGetAdapterLUID").map_err(|e| format!("Symbol not found: {e}"))?;
            let set_configuration_fn = *lib.get(b"WireGuardSetConfiguration").map_err(|e| format!("Symbol not found: {e}"))?;
            let get_configuration_fn = *lib.get(b"WireGuardGetConfiguration").map_err(|e| format!("Symbol not found: {e}"))?;

            Ok(Self {
                _lib: lib,
                create_adapter_fn,
                close_adapter_fn,
                set_state_fn,
                get_adapter_luid_fn,
                set_configuration_fn,
                get_configuration_fn,
            })
        }
    }

    pub fn create_adapter(&self, name: &str, tunnel_type: &str) -> Result<WireGuardAdapterHandle, String> {
        let name_wide: Vec<u16> = OsStr::new(name).encode_wide().chain(Some(0)).collect();
        let tunnel_type_wide: Vec<u16> = OsStr::new(tunnel_type).encode_wide().chain(Some(0)).collect();

        unsafe {
            let handle = (self.create_adapter_fn)(
                name_wide.as_ptr(),
                tunnel_type_wide.as_ptr(),
                std::ptr::null(),
            );
            if handle.is_null() {
                Err("WireGuardCreateAdapter returned NULL".into())
            } else {
                Ok(WireGuardAdapterHandle(handle))
            }
        }
    }

    pub fn close_adapter(&self, handle: WireGuardAdapterHandle) {
        unsafe { (self.close_adapter_fn)(handle.0) };
    }

    pub fn set_state(&self, handle: WireGuardAdapterHandle, state: WireGuardAdapterState) -> Result<(), String> {
        unsafe {
            let result = (self.set_state_fn)(handle.0, state);
            if result == 0 {
                Err("WireGuardSetState failed".into())
            } else {
                Ok(())
            }
        }
    }

    pub fn get_adapter_luid(&self, handle: WireGuardAdapterHandle) -> NET_LUID_LH {
        unsafe {
            let mut luid: NET_LUID_LH = std::mem::zeroed();
            (self.get_adapter_luid_fn)(handle.0, &mut luid);
            luid
        }
    }

    pub fn set_configuration(&self, handle: WireGuardAdapterHandle, bytes: &[u8]) -> Result<(), String> {
        unsafe {
            let result = (self.set_configuration_fn)(
                handle.0,
                bytes.as_ptr(),
                bytes.len() as u32,
            );
            if result == 0 {
                Err("WireGuardSetConfiguration failed (check flags, layout, key lengths)".into())
            } else {
                Ok(())
            }
        }
    }

    #[allow(dead_code)]
    pub fn get_configuration(&self, handle: WireGuardAdapterHandle) -> Result<Vec<u8>, String> {
        unsafe {
            let mut size: u32 = 0;
            let _ = (self.get_configuration_fn)(handle.0, std::ptr::null_mut(), &mut size);
            
            if size == 0 {
                return Err("WireGuardGetConfiguration: failed to get required size".into());
            }

            let mut buffer = vec![0u8; size as usize];
            let result = (self.get_configuration_fn)(
                handle.0,
                buffer.as_mut_ptr(),
                &mut size,
            );
            
            if result == 0 {
                Err("WireGuardGetConfiguration: failed to read config".into())
            } else {
                buffer.truncate(size as usize);
                Ok(buffer)
            }
        }
    }
}

// ============================================================================
// Tunnel State
// ============================================================================
pub struct TunnelState {
    pub dll: Arc<WireGuardDll>,
    pub adapter: Arc<Mutex<Option<WireGuardAdapterHandle>>>,
}

impl TunnelState {
    pub fn new(dll: Arc<WireGuardDll>) -> Self {
        Self {
            dll,
            adapter: Arc::new(Mutex::new(None)),
        }
    }

    pub fn clone_for_panic_hook(&self) -> (Arc<WireGuardDll>, Arc<Mutex<Option<WireGuardAdapterHandle>>>) {
        (self.dll.clone(), self.adapter.clone())
    }
}

// ============================================================================
// Tauri IPC Types
// ============================================================================
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TunnelStatus {
    pub is_active: bool,
    pub adapter_name: Option<String>,
    pub interface_index: Option<u32>,
    pub mtu: Option<u32>,
}

// ============================================================================
// Tauri Commands
// ============================================================================
#[tauri::command]
pub async fn tunnel_apply_config(
    state: State<'_, TunnelState>,
    config_content: String,
    adapter_name: String,
    expected_routes: Vec<String>,
) -> Result<TunnelStatus, String> {
    // ✅ ШАГ 1: Парсим и валидируем конфиг (Base64, DNS, CIDR)
    // ⚠️ DNS-резолвинг в parse_endpoint блокирует tokio-поток
    //    TODO: обернуть в tokio::task::spawn_blocking
    let parsed_config = wireguard_parser::parse_wireguard_config(&config_content)?;
    tracing::info!("✅ Config parsed successfully: {} peers, endpoint: {:?}", 
        parsed_config.peers.len(), 
        parsed_config.peers.first().and_then(|p| p.endpoint));

    // ⚠️ ВРЕМЕННО: binary blob serializer ещё не написан
    // let blob = wireguard_serializer::serialize_config(&parsed_config)?;
    // state.dll.set_configuration(handle, &blob)?;
    tracing::warn!("⚠️ Config parsed but NOT applied to driver yet (TODO: Serializer)");

    let interface_index = {
        // ✅ ИСПРАВЛЕНО: unwrap_or_else защищает от Mutex Poisoning
        let mut adapter_lock = state.adapter.lock()
            .unwrap_or_else(|p| p.into_inner());

        if let Some(old_handle) = adapter_lock.take() {
            let _ = state.dll.set_state(old_handle, WireGuardAdapterState::Down);
            state.dll.close_adapter(old_handle);
        }

        let handle = state.dll.create_adapter(&adapter_name, "GameAccelerator")?;
        
        // ✅ ИСПРАВЛЕНО: cleanup при ошибке set_state
        if let Err(e) = state.dll.set_state(handle, WireGuardAdapterState::Up) {
            state.dll.close_adapter(handle);
            return Err(e);
        }

        let luid = state.dll.get_adapter_luid(handle);
        let if_idx = match luid_to_index(luid) {
            Ok(idx) => idx,
            Err(e) => {
                // ✅ Cleanup при ошибке конвертации
                let _ = state.dll.set_state(handle, WireGuardAdapterState::Down);
                state.dll.close_adapter(handle);
                return Err(e);
            }
        };

        *adapter_lock = Some(handle);
        if_idx
    };

    // ✅ ИСПРАВЛЕНО: cleanup зомби-адаптера при таймауте
    if let Err(e) = wait_for_interface_up(interface_index, Duration::from_secs(15)).await {
        let mut adapter_lock = state.adapter.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(handle) = adapter_lock.take() {
            let _ = state.dll.set_state(handle, WireGuardAdapterState::Down);
            state.dll.close_adapter(handle);
        }
        return Err(e);
    }

    set_interface_mtu(interface_index, 1280)?;
    force_route_metrics(interface_index, &expected_routes)?;

    Ok(TunnelStatus {
        is_active: true,
        adapter_name: Some(adapter_name),
        interface_index: Some(interface_index),
        mtu: Some(1280),
    })
}

#[tauri::command]
pub async fn tunnel_disconnect(state: State<'_, TunnelState>) -> Result<(), String> {
    // ✅ ИСПРАВЛЕНО: unwrap_or_else защищает от Mutex Poisoning
    let mut adapter_lock = state.adapter.lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(handle) = adapter_lock.take() {
        let _ = state.dll.set_state(handle, WireGuardAdapterState::Down);
        state.dll.close_adapter(handle);
    }
    Ok(())
}

// ============================================================================
// Panic Hook
// ============================================================================
pub fn setup_panic_hook(
    dll: Arc<WireGuardDll>,
    adapter_state: Arc<Mutex<Option<WireGuardAdapterHandle>>>,
) {
    let default_hook = std::panic::take_hook();

    std::panic::set_hook(Box::new(move |info| {
        tracing::error!("💥 CRITICAL PANIC: {:?}", info);
        tracing::info!("Executing emergency network cleanup...");

        if let Ok(mut guard) = adapter_state.try_lock() {
            if let Some(handle) = guard.take() {
                let _ = dll.set_state(handle, WireGuardAdapterState::Down);
                dll.close_adapter(handle);
            }
        }

        default_hook(info);
        std::process::exit(1);
    }));
}

// ============================================================================
// Helper Functions
// ============================================================================
fn luid_to_index(luid: NET_LUID_LH) -> Result<u32, String> {
    unsafe {
        let mut index = 0u32;
        ConvertInterfaceLuidToIndex(&luid, &mut index)
            .map_err(|e| format!("Failed to convert LUID to InterfaceIndex: {e}"))?;
        Ok(index)
    }
}

async fn wait_for_interface_up(interface_index: u32, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    let mut delay_ms = 100u64; // ✅ Начинаем с 100мс, растём до 500мс
    while start.elapsed() < timeout {
        unsafe {
            let mut row: MIB_IF_ROW2 = std::mem::zeroed();
            row.InterfaceIndex = interface_index;
            if GetIfEntry2(&mut row).is_ok() && row.OperStatus == IfOperStatusUp {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        delay_ms = (delay_ms * 2).min(500); // exponential backoff, cap at 500ms
    }
    Err("Timeout waiting for interface to become UP".into())
}

fn set_interface_mtu(interface_index: u32, mtu: u32) -> Result<(), String> {
    unsafe {
        let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
        InitializeIpInterfaceEntry(&mut row);
        row.InterfaceIndex = interface_index;
        row.Family = AF_INET;
        if GetIpInterfaceEntry(&mut row).is_err() {
            return Err("GetIpInterfaceEntry failed".into());
        }
        row.NlMtu = mtu;
        if SetIpInterfaceEntry(&mut row).is_err() {
            return Err("SetIpInterfaceEntry (MTU) failed".into());
        }
    }
    Ok(())
}

fn force_route_metrics(interface_index: u32, expected_cidrs: &[String]) -> Result<(), String> {
    // ✅ Лимит на количество маршрутов (защита от resource exhaustion)
    if expected_cidrs.len() > 50 {
        return Err("Too many routes (max 50)".into());
    }
    for cidr in expected_cidrs {
        let (ip, prefix_len) = parse_cidr(cidr)?;
        if let std::net::IpAddr::V4(ipv4) = ip {
            let mut row = unsafe { create_forward_row(ipv4, prefix_len, interface_index) };
            unsafe {
                if GetIpForwardEntry2(&mut row).is_err() {
                    tracing::warn!("Route not found for {cidr}, skipping metric force");
                    continue;
                }
                row.Metric = 8;
                if SetIpForwardEntry2(&mut row).is_err() {
                    tracing::warn!("Failed to set metric for {cidr}");
                }
            }
        }
    }
    Ok(())
}
