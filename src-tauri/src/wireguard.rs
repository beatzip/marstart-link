use crate::utils::{create_forward_row, parse_cidr};
use crate::wireguard_config::{
    socket_addr_to_sockaddr_inet, WireguardAllowedIp, WireguardInterface, WireguardPeer,
};
use crate::wireguard_parser;
use crate::wireguard_serializer::{hexdump, read_peer_stats, serialize_config};

use std::ffi::c_void;
use std::net::{IpAddr, SocketAddr};
use std::os::windows::ffi::OsStrExt;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use libloading::os::windows::{Library, LOAD_WITH_ALTERED_SEARCH_PATH};
use serde::{Deserialize, Serialize};
use tauri::State;
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToIndex, CreateIpForwardEntry2, CreateUnicastIpAddressEntry,
    DeleteIpForwardEntry2, DeleteUnicastIpAddressEntry, GetIfEntry2, GetIpForwardEntry2,
    GetIpInterfaceEntry, GetUnicastIpAddressEntry, InitializeIpInterfaceEntry,
    InitializeUnicastIpAddressEntry, MIB_IF_ROW2, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW, SetIpForwardEntry2, SetIpInterfaceEntry,
    SetUnicastIpAddressEntry,
};
use windows::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows::Win32::Networking::WinSock::AF_INET;

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
// Runtime cleanup state
// ============================================================================
#[derive(Debug, Clone)]
struct AssignedAddress {
    ip: IpAddr,
    prefix: u8,
}

struct TunnelRuntime {
    interface_index: u32,
    assigned_address: Option<AssignedAddress>,
    dns_servers: Vec<String>,
    created_routes: Vec<windows::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2>,
}

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
            let lib = Library::load_with_flags(path, LOAD_WITH_ALTERED_SEARCH_PATH)
                .map_err(|e| format!("Failed to load DLL: {e}"))?;

            let create_adapter_fn = *lib
                .get(b"WireGuardCreateAdapter")
                .map_err(|e| format!("Symbol not found: {e}"))?;
            let close_adapter_fn = *lib
                .get(b"WireGuardCloseAdapter")
                .map_err(|e| format!("Symbol not found: {e}"))?;
            let set_state_fn = *lib
                .get(b"WireGuardSetAdapterState")
                .map_err(|e| format!("Symbol not found: {e}"))?;
            let get_adapter_luid_fn = *lib
                .get(b"WireGuardGetAdapterLUID")
                .map_err(|e| format!("Symbol not found: {e}"))?;
            let set_configuration_fn = *lib
                .get(b"WireGuardSetConfiguration")
                .map_err(|e| format!("Symbol not found: {e}"))?;
            let get_configuration_fn = *lib
                .get(b"WireGuardGetConfiguration")
                .map_err(|e| format!("Symbol not found: {e}"))?;

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

    pub fn create_adapter(
        &self,
        name: &str,
        tunnel_type: &str,
    ) -> Result<WireGuardAdapterHandle, String> {
        let name_wide: Vec<u16> = std::ffi::OsStr::new(name)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let tunnel_type_wide: Vec<u16> = std::ffi::OsStr::new(tunnel_type)
            .encode_wide()
            .chain(Some(0))
            .collect();

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

    pub fn set_state(
        &self,
        handle: WireGuardAdapterHandle,
        state: WireGuardAdapterState,
    ) -> Result<(), String> {
        unsafe {
            let result = (self.set_state_fn)(handle.0, state);
            if result == 0 {
                Err("WireGuardSetAdapterState failed".into())
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

    pub fn set_configuration(
        &self,
        handle: WireGuardAdapterHandle,
        bytes: &[u8],
    ) -> Result<(), String> {
        unsafe {
            let result = (self.set_configuration_fn)(handle.0, bytes.as_ptr(), bytes.len() as u32);
            if result == 0 {
                Err("WireGuardSetConfiguration failed".into())
            } else {
                Ok(())
            }
        }
    }

    pub fn get_configuration(&self, handle: WireGuardAdapterHandle) -> Result<Vec<u8>, String> {
        unsafe {
            let mut size: u32 = 0;
            let _ = (self.get_configuration_fn)(handle.0, std::ptr::null_mut(), &mut size);

            if size == 0 {
                return Err("WireGuardGetConfiguration: failed to get required size".into());
            }

            let mut buffer = vec![0u8; size as usize];
            let result = (self.get_configuration_fn)(handle.0, buffer.as_mut_ptr(), &mut size);

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
    runtime: Arc<Mutex<Option<TunnelRuntime>>>,
    pub status: Arc<Mutex<TunnelStatus>>,
}

impl TunnelState {
    pub fn new(dll: Arc<WireGuardDll>) -> Self {
        Self {
            dll,
            adapter: Arc::new(Mutex::new(None)),
            runtime: Arc::new(Mutex::new(None)),
            status: Arc::new(Mutex::new(TunnelStatus {
                is_active: false,
                adapter_name: None,
                interface_index: None,
                mtu: None,
                assigned_address: None,
                dns_servers: vec![],
            })),
        }
    }

    pub fn clone_for_panic_hook(
        &self,
    ) -> (
        Arc<WireGuardDll>,
        Arc<Mutex<Option<WireGuardAdapterHandle>>>,
    ) {
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
    pub assigned_address: Option<String>,
    pub dns_servers: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TunnelStats {
    pub is_active: bool,
    pub total_tx: u64,
    pub total_rx: u64,
}

#[tauri::command]
pub async fn tunnel_get_status(state: State<'_, TunnelState>) -> Result<TunnelStatus, String> {
    let status = state.status.lock().unwrap_or_else(|p| p.into_inner()).clone();
    Ok(status)
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
    let parsed_config = tokio::task::spawn_blocking({
        let content = config_content.clone();
        move || wireguard_parser::parse_wireguard_config(&content)
    })
    .await
    .map_err(|e| format!("Config parse task failed: {e}"))??;

    tracing::info!("Config parsed successfully: {} peers", parsed_config.peers.len());

    let mut runtime = TunnelRuntime {
        interface_index: 0,
        assigned_address: None,
        dns_servers: vec![],
        created_routes: vec![],
    };

    let interface_index = {
        let mut adapter_lock = state.adapter.lock().unwrap_or_else(|p| p.into_inner());

        if let Some(old_handle) = adapter_lock.take() {
            let _ = state.dll.set_state(old_handle, WireGuardAdapterState::Down);
            state.dll.close_adapter(old_handle);
        }

        let handle = state.dll.create_adapter(&adapter_name, "GameAccelerator")?;

        let blob = serialize_config(&parsed_config)?;
        tracing::info!("WG blob size = {} bytes", blob.len());
        tracing::debug!("WG blob hexdump:\n{}", hexdump(&blob, 128));

        if let Err(e) = state.dll.set_configuration(handle, &blob) {
            let _ = state.dll.set_state(handle, WireGuardAdapterState::Down);
            state.dll.close_adapter(handle);
            return Err(format!("WireGuardSetConfiguration failed: {}", e));
        }

        let luid = state.dll.get_adapter_luid(handle);
        let if_idx = match luid_to_index(luid) {
            Ok(idx) => idx,
            Err(e) => {
                let _ = state.dll.set_state(handle, WireGuardAdapterState::Down);
                state.dll.close_adapter(handle);
                return Err(e);
            }
        };

        if let Err(e) = state.dll.set_state(handle, WireGuardAdapterState::Up) {
            let _ = state.dll.set_state(handle, WireGuardAdapterState::Down);
            state.dll.close_adapter(handle);
            return Err(e);
        }

        if let Err(e) = wait_for_handshake(&state.dll, handle) {
            let _ = state.dll.set_state(handle, WireGuardAdapterState::Down);
            state.dll.close_adapter(handle);
            return Err(format!("Handshake failed: {}", e));
        }

        *adapter_lock = Some(handle);
        if_idx
    };

    runtime.interface_index = interface_index;

    if let Err(e) = wait_for_interface_up(interface_index, Duration::from_secs(15)).await {
        cleanup_runtime(&state.dll, &mut runtime);
        let mut adapter_lock = state.adapter.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(handle) = adapter_lock.take() {
            let _ = state.dll.set_state(handle, WireGuardAdapterState::Down);
            state.dll.close_adapter(handle);
        }
        return Err(e);
    }

    if let (Some(ip), Some(prefix)) = (parsed_config.interface_address, parsed_config.interface_prefix) {
        assign_interface_address(interface_index, ip, prefix)?;
        runtime.assigned_address = Some(AssignedAddress { ip, prefix });
    }

    if !parsed_config.dns_servers.is_empty() {
        apply_dns_servers(interface_index, &parsed_config.dns_servers)?;
        runtime.dns_servers = parsed_config.dns_servers.clone();
    }

    set_interface_mtu(interface_index, 1280)?;
    force_route_metrics(interface_index, &expected_routes, &mut runtime.created_routes)?;

    *state.runtime.lock().unwrap_or_else(|p| p.into_inner()) = Some(runtime);

    let status = TunnelStatus {
        is_active: true,
        adapter_name: Some(adapter_name),
        interface_index: Some(interface_index),
        mtu: Some(1280),
        assigned_address: parsed_config
            .interface_address
            .map(|ip| format!("{}/{}", ip, parsed_config.interface_prefix.unwrap_or(0))),
        dns_servers: parsed_config.dns_servers.clone(),
    };

    *state.status.lock().unwrap_or_else(|p| p.into_inner()) = status.clone();
    Ok(status)
}

#[tauri::command]
pub async fn tunnel_disconnect(state: State<'_, TunnelState>) -> Result<(), String> {
    cleanup_all_network_state(&state);

    let mut adapter_lock = state.adapter.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(handle) = adapter_lock.take() {
        let _ = state.dll.set_state(handle, WireGuardAdapterState::Down);
        state.dll.close_adapter(handle);
    }

    *state.status.lock().unwrap_or_else(|p| p.into_inner()) = TunnelStatus {
        is_active: false,
        adapter_name: None,
        interface_index: None,
        mtu: None,
        assigned_address: None,
        dns_servers: vec![],
    };

    Ok(())
}

#[tauri::command]
pub async fn tunnel_get_stats(state: State<'_, TunnelState>) -> Result<TunnelStats, String> {
    let adapter_lock = state.adapter.lock().unwrap_or_else(|p| p.into_inner());

    let handle = match *adapter_lock {
        Some(h) => h,
        None => {
            return Ok(TunnelStats {
                is_active: false,
                total_tx: 0,
                total_rx: 0,
            })
        }
    };

    let buffer = state.dll.get_configuration(handle)?;

    if buffer.len() < std::mem::size_of::<WireguardInterface>() {
        return Err("Invalid configuration buffer size".into());
    }

    let iface = unsafe { &*(buffer.as_ptr() as *const WireguardInterface) };
    let mut total_tx = 0u64;
    let mut total_rx = 0u64;

    let mut offset = std::mem::size_of::<WireguardInterface>();

    for _ in 0..iface.peers_count {
        if offset + std::mem::size_of::<WireguardPeer>() > buffer.len() {
            break;
        }

        let peer = unsafe { &*(buffer.as_ptr().add(offset) as *const WireguardPeer) };
        total_tx += peer.tx_bytes;
        total_rx += peer.rx_bytes;

        offset += std::mem::size_of::<WireguardPeer>();
        offset += (peer.allowed_ips_count as usize) * std::mem::size_of::<WireguardAllowedIp>();
    }

    Ok(TunnelStats {
        is_active: true,
        total_tx,
        total_rx,
    })
}

// ============================================================================
// Panic Hook & Helpers
// ============================================================================
pub fn setup_panic_hook(
    dll: Arc<WireGuardDll>,
    adapter_state: Arc<Mutex<Option<WireGuardAdapterHandle>>>,
) {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!("CRITICAL PANIC: {:?}", info);
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
    let mut delay_ms = 100u64;

    while start.elapsed() < timeout {
        unsafe {
            let mut row: MIB_IF_ROW2 = std::mem::zeroed();
            row.InterfaceIndex = interface_index;
            if GetIfEntry2(&mut row).is_ok() && row.OperStatus == IfOperStatusUp {
                return Ok(());
            }
        }

        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        delay_ms = (delay_ms * 2).min(500);
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

fn wait_for_handshake(
    dll: &WireGuardDll,
    handle: WireGuardAdapterHandle,
) -> anyhow::Result<()> {
    for _ in 0..20 {
        let blob = dll.get_configuration(handle).map_err(anyhow::Error::msg)?;
        let peers = read_peer_stats(&blob);

        for (_, _, handshake) in peers {
            if handshake > 0 {
                tracing::info!("WireGuard handshake established");
                return Ok(());
            }
        }

        thread::sleep(Duration::from_millis(500));
    }

    anyhow::bail!("No WireGuard handshake received")
}

fn assign_interface_address(
    interface_index: u32,
    ip: IpAddr,
    prefix: u8,
) -> Result<(), String> {
    let sockaddr = socket_addr_to_sockaddr_inet(&SocketAddr::new(ip, 0));

    unsafe {
        let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        InitializeUnicastIpAddressEntry(&mut row);
        row.InterfaceIndex = interface_index;
        row.Address = sockaddr;
        row.OnLinkPrefixLength = prefix;
        row.SkipAsSource = false.into();

        match CreateUnicastIpAddressEntry(&row) {
            Ok(_) => {
                tracing::info!("Assigned interface address {}/{}", ip, prefix);
                Ok(())
            }
            Err(create_err) => {
                // Если адрес уже существует, пробуем обновить его.
                let mut existing: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
                InitializeUnicastIpAddressEntry(&mut existing);
                existing.InterfaceIndex = interface_index;
                existing.Address = sockaddr;

                if GetUnicastIpAddressEntry(&mut existing).is_ok() {
                    existing.OnLinkPrefixLength = prefix;
                    existing.SkipAsSource = false.into();
                    SetUnicastIpAddressEntry(&existing)
                        .map_err(|e| format!("Failed to update interface address: {e}"))?;
                    tracing::info!("Updated existing interface address {}/{}", ip, prefix);
                    Ok(())
                } else {
                    Err(format!("CreateUnicastIpAddressEntry failed: {create_err}"))
                }
            }
        }
    }
}

fn remove_interface_address(interface_index: u32, ip: IpAddr, prefix: u8) {
    let sockaddr = socket_addr_to_sockaddr_inet(&SocketAddr::new(ip, 0));

    unsafe {
        let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        InitializeUnicastIpAddressEntry(&mut row);
        row.InterfaceIndex = interface_index;
        row.Address = sockaddr;
        row.OnLinkPrefixLength = prefix;
        let _ = DeleteUnicastIpAddressEntry(&row);
    }
}

fn run_powershell(script: &str) -> Result<(), String> {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"])
        .arg(script)
        .output()
        .map_err(|e| format!("Failed to launch PowerShell: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Err(format!(
            "PowerShell command failed (code {:?}): {} {}",
            output.status.code(),
            stderr,
            stdout
        ))
    }
}

fn apply_dns_servers(interface_index: u32, dns_servers: &[String]) -> Result<(), String> {
    if dns_servers.is_empty() {
        return Ok(());
    }

    let quoted = dns_servers
        .iter()
        .map(|s| format!("'{}'", s.replace('"', "''")))
        .collect::<Vec<_>>()
        .join(",");

    let script = format!(
        "Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses @({})",
        interface_index, quoted
    );

    run_powershell(&script)
}

fn reset_dns_servers(interface_index: u32) -> Result<(), String> {
    let script = format!(
        "Set-DnsClientServerAddress -InterfaceIndex {} -ResetServerAddresses",
        interface_index
    );

    run_powershell(&script)
}

fn force_route_metrics(
    interface_index: u32,
    expected_cidrs: &[String],
    created_routes: &mut Vec<windows::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2>,
) -> Result<(), String> {
    if expected_cidrs.len() > 50 {
        return Err("Too many routes (max 50)".into());
    }

    for cidr in expected_cidrs {
        let (ip, prefix_len) = parse_cidr(cidr)?;
        if let IpAddr::V4(ipv4) = ip {
            let mut row = unsafe { create_forward_row(ipv4, prefix_len, interface_index) };
            unsafe {
                if GetIpForwardEntry2(&mut row).is_err() {
                    tracing::info!("Route not found for {cidr}, creating it");
                    if CreateIpForwardEntry2(&row).is_err() {
                        tracing::warn!("Failed to create route for {cidr}");
                    } else {
                        created_routes.push(row);
                        tracing::info!("Created missing route for {cidr}");
                    }
                } else {
                    row.Metric = 8;
                    if SetIpForwardEntry2(&mut row).is_err() {
                        tracing::warn!("Failed to set metric for {cidr}");
                    }
                }
            }
        }
    }

    Ok(())
}

fn delete_created_routes(created_routes: &[windows::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2]) {
    for route in created_routes {
        unsafe {
            let _ = DeleteIpForwardEntry2(route);
        }
    }
}

fn cleanup_runtime(dll: &WireGuardDll, runtime: &mut TunnelRuntime) {
    if let Some(addr) = runtime.assigned_address.take() {
        remove_interface_address(runtime.interface_index, addr.ip, addr.prefix);
    }

    if !runtime.dns_servers.is_empty() {
        let _ = reset_dns_servers(runtime.interface_index);
        runtime.dns_servers.clear();
    }

    if !runtime.created_routes.is_empty() {
        delete_created_routes(&runtime.created_routes);
        runtime.created_routes.clear();
    }

    let _ = dll; // keep signature future-proof; dll is used indirectly in higher-level cleanup paths.
}

fn cleanup_all_network_state(state: &State<'_, TunnelState>) {
    if let Some(mut runtime) = state
        .runtime
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take()
    {
        cleanup_runtime(&state.dll, &mut runtime);
    }
}
