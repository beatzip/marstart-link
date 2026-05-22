use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use libloading::{Library, Symbol};
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

// === Newtype для Send + Sync ===
#[derive(Clone, Copy)]
pub struct WireGuardAdapterHandle(*mut c_void);

unsafe impl Send for WireGuardAdapterHandle {}
unsafe impl Sync for WireGuardAdapterHandle {}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireGuardAdapterState {
    Down = 0,
    Up = 1,
}

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

pub struct WireGuardDll {
    _lib: Library,
    create_adapter_fn: WireGuardCreateAdapterFn,
    close_adapter_fn: WireGuardCloseAdapterFn,
    set_state_fn: WireGuardSetStateFn,
    get_adapter_luid_fn: WireGuardGetAdapterLuidFn,
}

impl WireGuardDll {
    pub fn load(path: &str) -> Result<Self, String> {
        unsafe {
            let lib = Library::new(path).map_err(|e| format!("Failed to load DLL: {e}"))?;

            let create_adapter_fn = {
                let sym: Symbol<WireGuardCreateAdapterFn> = lib
                    .get(b"WireGuardCreateAdapter")
                    .map_err(|e| format!("Symbol not found: {e}"))?;
                *sym.into_raw()
            };
            let close_adapter_fn = {
                let sym: Symbol<WireGuardCloseAdapterFn> = lib
                    .get(b"WireGuardCloseAdapter")
                    .map_err(|e| format!("Symbol not found: {e}"))?;
                *sym.into_raw()
            };
            let set_state_fn = {
                let sym: Symbol<WireGuardSetStateFn> = lib
                    .get(b"WireGuardSetState")
                    .map_err(|e| format!("Symbol not found: {e}"))?;
                *sym.into_raw()
            };
            let get_adapter_luid_fn = {
                let sym: Symbol<WireGuardGetAdapterLuidFn> = lib
                    .get(b"WireGuardGetAdapterLUID")
                    .map_err(|e| format!("Symbol not found: {e}"))?;
                *sym.into_raw()
            };

            Ok(Self {
                _lib: lib,
                create_adapter_fn,
                close_adapter_fn,
                set_state_fn,
                get_adapter_luid_fn,
            })
        }
    }

    pub fn create_adapter(&self, name: &str, tunnel_type: &str) -> Result<WireGuardAdapterHandle, String> {
        let name_wide: Vec<u16> = OsStr::new(name).encode_wide().chain(Some(0)).collect();
        let tunnel_type_wide: Vec<u16> = OsStr::new(tunnel_type).encode_wide().chain(Some(0)).collect();

        unsafe {
            let handle = (self.create_adapter_fn)(name_wide.as_ptr(), tunnel_type_wide.as_ptr(), std::ptr::null());
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
}

// === Tunnel State ===
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TunnelStatus {
    pub is_active: bool,
    pub adapter_name: Option<String>,
    pub interface_index: Option<u32>,
    pub mtu: Option<u32>,
}

#[tauri::command]
pub async fn tunnel_apply_config(
    state: State<'_, TunnelState>,
    config_content: String,
    adapter_name: String,
    expected_routes: Vec<String>,
) -> Result<TunnelStatus, String> {
    // TODO: здесь будет WireGuardSetConfiguration через FFI
    let config_path = std::env::temp_dir().join("game_accelerator_wg.conf");
    std::fs::write(&config_path, &config_content).map_err(|e| format!("Failed to write config: {e}"))?;
    tracing::info!("Config written to {:?}", config_path);

    let interface_index = {
        let mut adapter_lock = state.adapter.lock().map_err(|e| e.to_string())?;

        if let Some(old_handle) = adapter_lock.take() {
            let _ = state.dll.set_state(old_handle, WireGuardAdapterState::Down);
            state.dll.close_adapter(old_handle);
        }

        let handle = state.dll.create_adapter(&adapter_name, "GameAccelerator")?;
        state.dll.set_state(handle, WireGuardAdapterState::Up)?;

        let luid = state.dll.get_adapter_luid(handle);
        let if_idx = luid_to_index(luid)?;

        *adapter_lock = Some(handle);
        if_idx
    };

    wait_for_interface_up(interface_index, Duration::from_secs(15)).await?;
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
    let mut adapter_lock = state.adapter.lock().map_err(|e| e.to_string())?;
    if let Some(handle) = adapter_lock.take() {
        let _ = state.dll.set_state(handle, WireGuardAdapterState::Down);
        state.dll.close_adapter(handle);
    }
    Ok(())
}

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

    while start.elapsed() < timeout {
        unsafe {
            let mut row: MIB_IF_ROW2 = std::mem::zeroed();
            row.InterfaceIndex = interface_index;

            if GetIfEntry2(&mut row).is_ok() && row.OperStatus == IfOperStatusUp {
                return Ok(());
            }
        }

        tokio::time::sleep(Duration::from_millis(200)).await;
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