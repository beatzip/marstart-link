use crate::utils::{create_forward_row, parse_cidr};
use crate::wireguard_config::socket_addr_to_sockaddr_inet;
use crate::wireguard_serializer::read_peer_stats;

use std::ffi::c_void;
use std::net::{IpAddr, SocketAddr};
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use libloading::os::windows::{Library, LOAD_WITH_ALTERED_SEARCH_PATH};
use serde::{Deserialize, Serialize};
use tauri::State;
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
    DeleteUnicastIpAddressEntry, GetIfEntry2, GetIpForwardEntry2, GetUnicastIpAddressEntry,
    InitializeIpForwardEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
    SetIpForwardEntry2, SetUnicastIpAddressEntry, MIB_IF_ROW2, MIB_IPFORWARD_ROW2,
    MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
};
use windows::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_INET};
use windows::Win32::UI::WindowsAndMessaging::DefWindowProcW;

const WG_INTERFACE_MTU: u32 = 1420;
const ROUTE_MONITOR_INTERVAL_SECS: u64 = 15;
const DNS_REFRESH_INTERVAL_SECS: u64 = 300;
const MAX_ADAPTER_NAME_LEN: usize = 64;
const MAX_DNS_ENTRY_LEN: usize = 64;
const MAX_DNS_ENTRIES: usize = 8;

fn validate_adapter_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Adapter name must not be empty".into());
    }
    if name.len() > MAX_ADAPTER_NAME_LEN {
        return Err(format!(
            "Adapter name too long: {} > {MAX_ADAPTER_NAME_LEN}",
            name.len()
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ')
    {
        return Err(format!(
            "Adapter name contains invalid characters: {:?}",
            name
        ));
    }
    Ok(())
}

fn validate_dns_servers(servers: &[String]) -> Result<(), String> {
    if servers.len() > MAX_DNS_ENTRIES {
        return Err(format!(
            "Too many DNS entries: {} > {MAX_DNS_ENTRIES}",
            servers.len()
        ));
    }
    for s in servers {
        if s.len() > MAX_DNS_ENTRY_LEN {
            return Err(format!("DNS entry too long: {:?}", s));
        }
        if s.parse::<IpAddr>().is_err() {
            return Err(format!("DNS entry is not a valid IP address: {:?}", s));
        }
    }
    Ok(())
}

fn extract_hostname_from_config(config: &str) -> Option<String> {
    for line in config.lines() {
        let line = line.trim();
        if line.starts_with("Endpoint =") || line.starts_with("Endpoint=") {
            let after_eq = line.split('=').nth(1)?.trim();
            // IPv6: [::1]:51820
            if after_eq.starts_with('[') {
                if let Some(end) = after_eq.find(']') {
                    let host = &after_eq[1..end];
                    if host.parse::<std::net::IpAddr>().is_err() {
                        return Some(host.to_string());
                    }
                    return None;
                }
            }
            // IPv4 / hostname: host:port  — порт после ПОСЛЕДНЕГО ':'
            let host_part = if let Some(idx) = after_eq.rfind(':') {
                &after_eq[..idx]
            } else {
                after_eq
            };
            let host_part = host_part.trim();
            if host_part.parse::<std::net::IpAddr>().is_err() {
                return Some(host_part.to_string());
            }
        }
    }
    None
}

fn sockaddr_inet_from_ipv6(addr: &std::net::Ipv6Addr) -> SOCKADDR_INET {
    let mut sa = unsafe { std::mem::zeroed::<SOCKADDR_INET>() };
    sa.si_family = AF_INET6;
    sa.Ipv6.sin6_family = AF_INET6;
    sa.Ipv6.sin6_addr = IN6_ADDR {
        u: IN6_ADDR_0 {
            Byte: addr.octets(),
        },
    };
    sa.Ipv6.sin6_port = 0;
    sa.Ipv6.sin6_flowinfo = 0;
    sa
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TunnelPhase {
    #[default]
    Idle,
    ApplyingConfig,
    WaitingHandshake,
    Connected,
    Disconnecting,
    Failed,
}

impl TunnelPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            TunnelPhase::Idle => "idle",
            TunnelPhase::ApplyingConfig => "connecting",
            TunnelPhase::WaitingHandshake => "connected",
            TunnelPhase::Connected => "connected",
            TunnelPhase::Disconnecting => "disconnecting",
            TunnelPhase::Failed => "idle",
        }
    }
}

impl Serialize for TunnelPhase {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TunnelPhase {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "idle" => TunnelPhase::Idle,
            "connecting" => TunnelPhase::ApplyingConfig,
            "connected" => TunnelPhase::Connected,
            "disconnecting" => TunnelPhase::Disconnecting,
            _ => TunnelPhase::Idle,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TunnelHealth {
    pub adapter_ok: bool,
    pub interface_ok: bool,
    pub routes_ok: bool,
    pub dns_ok: bool,
    pub handshake_ok: bool,
    pub game_path_verified: bool,
    pub leak_detected: bool,
    pub packet_loss_percent: f32,
    pub avg_rtt_ms: u32,
    pub jitter_ms: u32,
}

type WireGuardCreateAdapterFn = unsafe extern "system" fn(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: *const c_void,
) -> *mut c_void;
type WireGuardCloseAdapterFn = unsafe extern "system" fn(adapter: *mut c_void);
type WireGuardSetStateFn =
    unsafe extern "system" fn(adapter: *mut c_void, state: WireGuardAdapterState) -> i32;
type WireGuardGetAdapterLuidFn =
    unsafe extern "system" fn(adapter: *mut c_void, luid: *mut NET_LUID_LH);
type WireGuardSetConfigurationFn =
    unsafe extern "system" fn(adapter: *mut c_void, bytes: *const u8, size: u32) -> i32;
type WireGuardGetConfigurationFn =
    unsafe extern "system" fn(adapter: *mut c_void, bytes: *mut u8, size: *mut u32) -> i32;

#[derive(Debug, Clone)]
pub struct AssignedAddress {
    ip: IpAddr,
    prefix: u8,
}

pub struct TunnelRuntime {
    pub interface_index: u32,
    pub interface_luid: NET_LUID_LH,
    pub assigned_address: Option<AssignedAddress>,
    pub dns_servers: Vec<String>,
    pub primary_endpoint: Option<SocketAddr>,
    pub created_routes: Vec<MIB_IPFORWARD_ROW2>,
    pub endpoint_hostname: Option<String>,
    pub current_bypass_row: Option<MIB_IPFORWARD_ROW2>,
}

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
            let lib =
                Library::load_with_flags(path, LOAD_WITH_ALTERED_SEARCH_PATH).map_err(|e| {
                    let os = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                    format!("LoadLibraryExW failed for \"{path}\": {e} (OS error {os})")
                })?;

            macro_rules! sym {
                ($name:expr) => {
                    *lib.get($name)
                        .map_err(|e| format!("Symbol {:?} not found: {e}", $name))?
                };
            }

            Ok(Self {
                create_adapter_fn: sym!(b"WireGuardCreateAdapter"),
                close_adapter_fn: sym!(b"WireGuardCloseAdapter"),
                set_state_fn: sym!(b"WireGuardSetAdapterState"),
                get_adapter_luid_fn: sym!(b"WireGuardGetAdapterLUID"),
                set_configuration_fn: sym!(b"WireGuardSetConfiguration"),
                get_configuration_fn: sym!(b"WireGuardGetConfiguration"),
                _lib: lib,
            })
        }
    }

    pub fn create_adapter(
        &self,
        name: &str,
        tunnel_type: &str,
    ) -> Result<WireGuardAdapterHandle, String> {
        let name_w: Vec<u16> = std::ffi::OsStr::new(name)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let type_w: Vec<u16> = std::ffi::OsStr::new(tunnel_type)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let handle =
            unsafe { (self.create_adapter_fn)(name_w.as_ptr(), type_w.as_ptr(), std::ptr::null()) };
        if handle.is_null() {
            Err(format!(
                "WireGuardCreateAdapter returned NULL for \"{name}\""
            ))
        } else {
            Ok(WireGuardAdapterHandle(handle))
        }
    }

    pub fn close_adapter(&self, h: WireGuardAdapterHandle) {
        unsafe { (self.close_adapter_fn)(h.0) }
    }

    pub fn set_state(
        &self,
        h: WireGuardAdapterHandle,
        s: WireGuardAdapterState,
    ) -> Result<(), String> {
        let ok = unsafe { (self.set_state_fn)(h.0, s) };
        if ok == 0 {
            Err(format!("WireGuardSetAdapterState({s:?}) failed"))
        } else {
            Ok(())
        }
    }

    pub fn get_adapter_luid(&self, h: WireGuardAdapterHandle) -> NET_LUID_LH {
        let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
        unsafe { (self.get_adapter_luid_fn)(h.0, &mut luid) }
        luid
    }

    pub fn set_configuration(&self, h: WireGuardAdapterHandle, bytes: &[u8]) -> Result<(), String> {
        let ok = unsafe { (self.set_configuration_fn)(h.0, bytes.as_ptr(), bytes.len() as u32) };
        if ok == 0 {
            Err("WireGuardSetConfiguration failed".into())
        } else {
            Ok(())
        }
    }

    pub fn get_configuration(&self, h: WireGuardAdapterHandle) -> Result<Vec<u8>, String> {
        unsafe {
            let mut size: u32 = 0;
            (self.get_configuration_fn)(h.0, std::ptr::null_mut(), &mut size);
            if size == 0 {
                return Err("GetConfiguration: size query returned 0".into());
            }
            const MAX_CONFIG_SIZE: u32 = 1024 * 1024;
            if size > MAX_CONFIG_SIZE {
                return Err(format!(
                    "GetConfiguration: reported size {size} exceeds max {MAX_CONFIG_SIZE}"
                ));
            }
            let mut buf = vec![0u8; size as usize];
            let ok = (self.get_configuration_fn)(h.0, buf.as_mut_ptr(), &mut size);
            if ok == 0 {
                return Err("GetConfiguration: read failed".into());
            }
            buf.truncate(size as usize);
            Ok(buf)
        }
    }
}

pub struct TunnelState {
    pub dll: Arc<WireGuardDll>,
    pub adapter: Arc<Mutex<Option<WireGuardAdapterHandle>>>,
    pub runtime: Arc<Mutex<Option<TunnelRuntime>>>,
    pub status: Arc<Mutex<TunnelStatus>>,
    pub session_id: Arc<AtomicU64>,
    pub reconnect_on_resume: Arc<AtomicBool>,
    /// Глобальный замок операций жизненного цикла туннеля.
    /// Гарантирует, что apply_config и disconnect не пересекаются.
    pub op_lock: Arc<tokio::sync::Mutex<()>>,
}

impl TunnelState {
    pub fn new(dll: Arc<WireGuardDll>) -> Self {
        Self {
            dll,
            adapter: Arc::new(Mutex::new(None)),
            runtime: Arc::new(Mutex::new(None)),
            status: Arc::new(Mutex::new(TunnelStatus::default())),
            session_id: Arc::new(AtomicU64::new(0)),
            reconnect_on_resume: Arc::new(AtomicBool::new(false)),
            op_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn clone_for_panic_hook(
        &self,
    ) -> (
        Arc<WireGuardDll>,
        Arc<Mutex<Option<WireGuardAdapterHandle>>>,
        Arc<Mutex<Option<TunnelRuntime>>>,
    ) {
        (self.dll.clone(), self.adapter.clone(), self.runtime.clone())
    }

    /// Инвалидирует все ранее запущенные фоновые задачи (handshake-wait и т.п.)
    /// и возвращает НОВЫЙ session_id.
    pub fn invalidate_and_begin_session(&self) -> u64 {
        self.session_id
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1)
    }

    pub fn current_session(&self) -> u64 {
        self.session_id.load(Ordering::SeqCst)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TunnelStatus {
    pub is_active: bool,
    pub adapter_name: Option<String>,
    pub interface_index: Option<u32>,
    pub mtu: Option<u32>,
    pub assigned_address: Option<String>,
    pub dns_servers: Vec<String>,
    pub phase: TunnelPhase,
    pub session_id: u64,
    pub health: TunnelHealth,
    pub needs_reconnect: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TunnelStats {
    pub is_active: bool,
    pub total_tx: u64,
    pub total_rx: u64,
    pub last_handshake_unix: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TunnelDiagnostics {
    pub session_id: u64,
    pub phase: TunnelPhase,
    pub is_active: bool,
    pub handshake_ok: bool,
    pub handshake_age_secs: Option<u64>,
    pub route_health_ok: bool,
    pub dns_health_ok: bool,
    pub game_path_verified: bool,
    pub leak_detected: bool,
    pub best_route_interface_index: Option<u32>,
    pub expected_interface_index: Option<u32>,
    pub packet_loss_percent: f32,
    pub avg_rtt_ms: u32,
    pub jitter_ms: u32,
}

#[tauri::command]
pub async fn tunnel_get_status(state: State<'_, TunnelState>) -> Result<TunnelStatus, String> {
    let mut status = state
        .status
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    status.needs_reconnect = state.reconnect_on_resume.load(Ordering::SeqCst);
    Ok(status)
}

#[tauri::command]
pub async fn tunnel_clear_reconnect_flag(state: State<'_, TunnelState>) -> Result<(), String> {
    state.reconnect_on_resume.store(false, Ordering::SeqCst);
    tracing::info!("reconnect_on_resume flag cleared by frontend");
    Ok(())
}

#[tauri::command]
pub async fn tunnel_get_stats(state: State<'_, TunnelState>) -> Result<TunnelStats, String> {
    let handle = {
        let guard = state.adapter.lock().unwrap_or_else(|p| p.into_inner());
        match *guard {
            Some(h) => h,
            None => return Ok(TunnelStats::default()),
        }
    };

    let buf = match state.dll.get_configuration(handle) {
        Ok(b) => b,
        Err(_) => return Ok(TunnelStats::default()),
    };
    let peers = read_peer_stats(&buf);

    let total_tx = peers.iter().map(|(tx, _, _)| tx).sum();
    let total_rx = peers.iter().map(|(_, rx, _)| rx).sum();
    let last_handshake = peers.iter().map(|(_, _, hs)| *hs).max().unwrap_or(0);

    if last_handshake > 0 {
        let mut status = state.status.lock().unwrap_or_else(|p| p.into_inner());
        status.health.handshake_ok = true;
        if matches!(status.phase, TunnelPhase::WaitingHandshake) {
            status.phase = TunnelPhase::Connected;
        }
    }

    let is_active = state
        .status
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_active;

    Ok(TunnelStats {
        is_active,
        total_tx,
        total_rx,
        last_handshake_unix: last_handshake,
    })
}

#[tauri::command]
pub async fn tunnel_get_diagnostics(
    state: State<'_, TunnelState>,
) -> Result<TunnelDiagnostics, String> {
    let status = state
        .status
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();

    let (runtime_endpoint, runtime_interface_index) = {
        let guard = state.runtime.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(rt) = guard.as_ref() {
            (rt.primary_endpoint, Some(rt.interface_index))
        } else {
            (None, None)
        }
    };

    let mut diag = TunnelDiagnostics {
        session_id: status.session_id,
        phase: status.phase,
        is_active: status.is_active,
        handshake_ok: status.health.handshake_ok,
        handshake_age_secs: None,
        route_health_ok: status.health.routes_ok,
        dns_health_ok: status.health.dns_ok,
        game_path_verified: status.health.game_path_verified,
        leak_detected: status.health.leak_detected,
        best_route_interface_index: None,
        expected_interface_index: runtime_interface_index,
        packet_loss_percent: status.health.packet_loss_percent,
        avg_rtt_ms: status.health.avg_rtt_ms,
        jitter_ms: status.health.jitter_ms,
    };

    if let Some(handle) = *state.adapter.lock().unwrap_or_else(|p| p.into_inner()) {
        if let Ok(buf) = state.dll.get_configuration(handle) {
            let peers = read_peer_stats(&buf);
            let latest_handshake = peers.iter().map(|(_, _, hs)| *hs).max().unwrap_or(0);
            if latest_handshake > 0 {
                diag.handshake_ok = true;
                diag.handshake_age_secs =
                    Some(current_unix_secs().saturating_sub(latest_handshake));
            }
        }
    }

    if let (Some(endpoint), Some(if_idx)) = (runtime_endpoint, runtime_interface_index) {
        match best_route_interface_for(endpoint) {
            Ok(best_if) => {
                diag.best_route_interface_index = Some(best_if);
                // Endpoint должен идти НЕ через тоннель.
                let route_ok = best_if != if_idx;
                diag.route_health_ok = route_ok;
                diag.leak_detected = !route_ok;
                diag.game_path_verified = route_ok && diag.handshake_ok;

                let mut sg = state.status.lock().unwrap_or_else(|p| p.into_inner());
                sg.health.game_path_verified = diag.game_path_verified;
                sg.health.leak_detected = !route_ok;
                sg.health.routes_ok = route_ok;
            }
            Err(e) => tracing::debug!("best_route_interface_for failed: {e}"),
        }
    }

    Ok(diag)
}

/// Полностью разрушает текущую сессию туннеля. Идемпотентна.
/// Не трогает session_id (это делает caller).
fn teardown_current_session(
    dll: &WireGuardDll,
    adapter: &Arc<Mutex<Option<WireGuardAdapterHandle>>>,
    runtime: &Arc<Mutex<Option<TunnelRuntime>>>,
    status: &Arc<Mutex<TunnelStatus>>,
) {
    if let Some(mut rt) = runtime.lock().unwrap_or_else(|p| p.into_inner()).take() {
        cleanup_runtime(dll, &mut rt);
    }
    let h_opt = adapter.lock().unwrap_or_else(|p| p.into_inner()).take();
    if let Some(h) = h_opt {
        let _ = dll.set_state(h, WireGuardAdapterState::Down);
        dll.close_adapter(h);
    }
    let mut s = status.lock().unwrap_or_else(|p| p.into_inner());
    *s = TunnelStatus {
        phase: TunnelPhase::Idle,
        ..Default::default()
    };
}

#[tauri::command]
pub async fn tunnel_apply_config(
    state: State<'_, TunnelState>,
    config_content: String,
    adapter_name: String,
    expected_routes: Vec<String>,
) -> Result<TunnelStatus, String> {
    use crate::wireguard_parser;
    use crate::wireguard_serializer::serialize_config;

    let _op = state.op_lock.clone().lock_owned().await;

    validate_adapter_name(&adapter_name)?;

    const MAX_CONFIG_LEN: usize = 65_536;
    if config_content.len() > MAX_CONFIG_LEN {
        return Err(format!(
            "Config too large: {} bytes (max {MAX_CONFIG_LEN})",
            config_content.len()
        ));
    }

    // Инвалидируем ВСЕ предыдущие фоновые задачи и забираем новый session_id.
    let session_id = state.invalidate_and_begin_session();

    // Полная очистка прошлой сессии ДО создания нового адаптера.
    teardown_current_session(&state.dll, &state.adapter, &state.runtime, &state.status);

    let parsed = tokio::task::spawn_blocking({
        let content = config_content.clone();
        move || wireguard_parser::parse_wireguard_config(&content)
    })
    .await
    .map_err(|e| format!("Parse task panic: {e}"))??;

    tracing::info!(session_id, "Config parsed: {} peer(s)", parsed.peers.len());

    validate_dns_servers(&parsed.dns_servers).map_err(|e| format!("Invalid DNS config: {e}"))?;

    let total_allowed_ips: usize = parsed.peers.iter().map(|p| p.allowed_ips.len()).sum();
    if total_allowed_ips > 50 {
        return Err(format!(
            "Config contains {} AllowedIPs across all peers (max 50)",
            total_allowed_ips
        ));
    }

    let blob = serialize_config(&parsed)?;
    tracing::info!(session_id, "WG blob {} bytes", blob.len());

    {
        let mut status = state.status.lock().unwrap_or_else(|p| p.into_inner());
        status.phase = TunnelPhase::ApplyingConfig;
        status.session_id = session_id;
        status.health = TunnelHealth::default();
        status.adapter_name = Some(adapter_name.clone());
    }

    let (handle, if_idx, luid) = {
        let handle = state.dll.create_adapter(&adapter_name, "GameAccelerator")?;
        tracing::info!(session_id, "Adapter created: {adapter_name}");

        if let Err(e) = state.dll.set_configuration(handle, &blob) {
            state.dll.close_adapter(handle);
            return Err(format!("SetConfiguration: {e}"));
        }
        tracing::info!(session_id, "WireGuard configuration applied");

        let luid = state.dll.get_adapter_luid(handle);
        let if_idx = match luid_to_index(luid) {
            Ok(i) => i,
            Err(e) => {
                state.dll.close_adapter(handle);
                return Err(e);
            }
        };

        if let Err(e) = state.dll.set_state(handle, WireGuardAdapterState::Up) {
            state.dll.close_adapter(handle);
            return Err(format!("SetState(Up): {e}"));
        }
        tracing::info!(session_id, "Adapter UP, InterfaceIndex={if_idx}");

        *state.adapter.lock().unwrap_or_else(|p| p.into_inner()) = Some(handle);
        (handle, if_idx, luid)
    };

    let do_emergency_teardown = |msg: String| -> String {
        teardown_current_session(&state.dll, &state.adapter, &state.runtime, &state.status);
        let mut s = state.status.lock().unwrap_or_else(|p| p.into_inner());
        s.phase = TunnelPhase::Failed;
        s.health.leak_detected = true;
        msg
    };

    if let Err(e) = wait_for_interface_up(if_idx, Duration::from_secs(20)).await {
        return Err(do_emergency_teardown(e));
    }
    tracing::info!(session_id, "Interface IfOperStatusUp confirmed");
    state
        .status
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .health
        .interface_ok = true;

    let mut runtime = TunnelRuntime {
        interface_index: if_idx,
        interface_luid: luid,
        assigned_address: None,
        dns_servers: vec![],
        primary_endpoint: parsed.peers.first().and_then(|peer| peer.endpoint),
        created_routes: vec![],
        endpoint_hostname: extract_hostname_from_config(&config_content),
        current_bypass_row: None,
    };

    let has_half1 = expected_routes.iter().any(|r| r == "0.0.0.0/1");
    let has_half2 = expected_routes.iter().any(|r| r == "128.0.0.0/1");
    let is_full_tunnel = expected_routes.iter().any(|r| r == "0.0.0.0/0" || r == "::/0")
        || (has_half1 && has_half2);

    if is_full_tunnel {
        if let Some(peer) = parsed.peers.first() {
            if let Some(endpoint) = peer.endpoint {
                match add_full_tunnel_bypass_route(endpoint) {
                    Ok(Some(row)) => {
                        tracing::info!(
                            session_id,
                            "Full-tunnel bypass route added for {}",
                            endpoint.ip()
                        );
                        runtime.current_bypass_row = Some(row);
                    }
                    Ok(None) => tracing::info!(session_id, "Endpoint on-link — no bypass needed"),
                    Err(e) => tracing::warn!(session_id, "Bypass route failed (non-fatal): {e}"),
                }
            }
        }
    }

    if let (Some(ip), Some(prefix)) = (parsed.interface_address, parsed.interface_prefix) {
        match assign_interface_address(if_idx, ip, prefix) {
            Ok(_) => {
                tracing::info!(session_id, "Assigned IP {ip}/{prefix} to interface");
                runtime.assigned_address = Some(AssignedAddress { ip, prefix });
                state
                    .status
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .health
                    .adapter_ok = true;
            }
            Err(e) => {
                // Перед глобальным teardown — приклеиваем runtime, чтобы cleanup его подобрал.
                *state.runtime.lock().unwrap_or_else(|p| p.into_inner()) = Some(runtime);
                return Err(do_emergency_teardown(format!("IP assignment failed: {e}")));
            }
        }
    } else {
        tracing::warn!(
            session_id,
            "No Address field in config — interface has no IP"
        );
    }

    if let Err(e) = set_interface_mtu(if_idx, WG_INTERFACE_MTU) {
        tracing::warn!(session_id, "MTU set failed (non-fatal): {e}");
    } else {
        tracing::info!(session_id, "MTU set to {WG_INTERFACE_MTU}");
    }

    if let Err(e) = inject_routes(if_idx, &expected_routes, &mut runtime.created_routes) {
        tracing::warn!(
            session_id,
            "Route injection partial failure (non-fatal): {e}"
        );
        state
            .status
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .health
            .routes_ok = false;
    } else {
        state
            .status
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .health
            .routes_ok = true;
    }

    if !parsed.dns_servers.is_empty() {
        match apply_dns_servers(luid, if_idx, &parsed.dns_servers) {
            Ok(_) => {
                tracing::info!(session_id, "DNS set: {:?}", parsed.dns_servers);
                runtime.dns_servers = parsed.dns_servers.clone();
                state
                    .status
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .health
                    .dns_ok = true;
            }
            Err(e) => {
                tracing::warn!(session_id, "DNS set failed (non-fatal): {e}");
                state
                    .status
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .health
                    .dns_ok = false;
            }
        }
    }

    *state.runtime.lock().unwrap_or_else(|p| p.into_inner()) = Some(runtime);

    let health = state
        .status
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .health
        .clone();
    let status = TunnelStatus {
        is_active: true,
        adapter_name: Some(adapter_name.clone()),
        interface_index: Some(if_idx),
        mtu: Some(WG_INTERFACE_MTU),
        assigned_address: parsed
            .interface_address
            .zip(parsed.interface_prefix)
            .map(|(ip, p)| format!("{ip}/{p}")),
        dns_servers: parsed.dns_servers.clone(),
        phase: TunnelPhase::WaitingHandshake,
        session_id,
        health,
        needs_reconnect: false,
    };
    *state.status.lock().unwrap_or_else(|p| p.into_inner()) = status.clone();

    let dll = state.dll.clone();
    let adapter = state.adapter.clone();
    let status_arc = state.status.clone();
    let session_guard = state.session_id.clone();
    let sg_check = session_guard.clone();
    tokio::spawn(async move {
        match wait_for_handshake(
            dll,
            adapter,
            session_guard,
            session_id,
            handle,
            Duration::from_secs(30),
        )
        .await
        {
            Ok(ts) => {
                if sg_check.load(Ordering::SeqCst) == session_id {
                    tracing::info!(session_id, "WireGuard handshake at unix={ts}");
                    let mut s = status_arc.lock().unwrap_or_else(|p| p.into_inner());
                    s.phase = TunnelPhase::Connected;
                    s.health.handshake_ok = true;
                }
            }
            Err(e) => {
                if sg_check.load(Ordering::SeqCst) == session_id {
                    tracing::warn!(session_id, "Handshake timeout/error: {e}");
                }
            }
        }
    });

    tracing::info!(
        session_id,
        "tunnel_apply_config complete: adapter={adapter_name} if_idx={if_idx}"
    );
    Ok(status)
}

#[tauri::command]
pub async fn tunnel_disconnect(state: State<'_, TunnelState>) -> Result<(), String> {
    let _op = state.op_lock.clone().lock_owned().await;

    // Инвалидируем все фоновые задачи.
    state.invalidate_and_begin_session();
    state.reconnect_on_resume.store(false, Ordering::SeqCst);

    {
        let mut s = state.status.lock().unwrap_or_else(|p| p.into_inner());
        s.phase = TunnelPhase::Disconnecting;
    }

    teardown_current_session(&state.dll, &state.adapter, &state.runtime, &state.status);

    state.session_id.store(0, Ordering::SeqCst);
    tracing::info!("Tunnel disconnected");
    Ok(())
}

pub fn setup_panic_hook(
    dll: Arc<WireGuardDll>,
    adapter: Arc<Mutex<Option<WireGuardAdapterHandle>>>,
    runtime: Arc<Mutex<Option<TunnelRuntime>>>,
) {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!("PANIC: {info:?}");

        if let Ok(mut rg) = runtime.try_lock() {
            if let Some(mut rt) = rg.take() {
                cleanup_runtime(&dll, &mut rt);
            }
        }

        if let Ok(mut g) = adapter.try_lock() {
            if let Some(h) = g.take() {
                let _ = dll.set_state(h, WireGuardAdapterState::Down);
                dll.close_adapter(h);
            }
        }

        default(info);
        std::process::exit(1);
    }));
}

pub fn spawn_power_monitor(reconnect_flag: Arc<AtomicBool>) {
    std::thread::Builder::new()
        .name("ga-power-monitor".into())
        .spawn(move || power_monitor_thread(reconnect_flag))
        .ok();
}

#[cfg(target_os = "windows")]
fn power_monitor_thread(reconnect_flag: Arc<AtomicBool>) {
    use windows::core::PCWSTR;
    use windows::Win32::System::Power::{
        RegisterPowerSettingNotification, DEVICE_NOTIFY_WINDOW_HANDLE,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DispatchMessageW, GetMessageW, RegisterClassExW, TranslateMessage,
        HWND_MESSAGE, MSG, WINDOW_EX_STYLE, WINDOW_STYLE, WNDCLASSEXW,
    };

    // Глобальный флаг для wnd_proc.
    use std::sync::OnceLock;
    static RECONNECT_FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    let _ = RECONNECT_FLAG.set(reconnect_flag);

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        const WM_POWERBROADCAST: u32 = 0x0218;
        const PBT_APMRESUMESUSPEND: usize = 7;
        const PBT_APMRESUMEAUTOMATIC: usize = 18;
        const PBT_APMSUSPEND: usize = 4;

        if msg == WM_POWERBROADCAST {
            let event = wparam.0 as usize;
            match event {
                PBT_APMRESUMESUSPEND | PBT_APMRESUMEAUTOMATIC => {
                    tracing::info!("System resume detected (event={event}), flagging reconnect");
                    if let Some(flag) = RECONNECT_FLAG.get() {
                        flag.store(true, Ordering::SeqCst);
                    }
                }
                PBT_APMSUSPEND => {
                    tracing::info!("System suspend detected");
                }
                _ => {}
            }
            return LRESULT(1);
        }
        DefWindowProcW(hwnd, msg, wparam, lparam)
    }

    let class_name: Vec<u16> = std::ffi::OsStr::new("GA_PowerMonitor_WndClass")
        .encode_wide()
        .chain(Some(0))
        .collect();

    unsafe {
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(wnd_proc),
            lpszClassName: PCWSTR(class_name.as_ptr()),
            ..Default::default()
        };
        RegisterClassExW(&wc);

        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            PCWSTR(class_name.as_ptr()),
            PCWSTR::null(),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            None,
            None,
            None,
        );
        if hwnd.0 == 0 {
            tracing::warn!("PowerMonitor: CreateWindowExW returned NULL");
            return;
        }

        // Регистрируем явные подписки на ключевые power-настройки,
        // чтобы гарантированно получать WM_POWERBROADCAST даже для service-like окон.
        let _ = RegisterPowerSettingNotification(
            windows::Win32::Foundation::HANDLE(hwnd.0),
            &windows::Win32::System::Power::GUID_CONSOLE_DISPLAY_STATE,
            DEVICE_NOTIFY_WINDOW_HANDLE,
        );
        let _ = RegisterPowerSettingNotification(
            windows::Win32::Foundation::HANDLE(hwnd.0),
            &windows::Win32::System::Power::GUID_SYSTEM_AWAYMODE,
            DEVICE_NOTIFY_WINDOW_HANDLE,
        );

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, hwnd, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn power_monitor_thread(_reconnect_flag: Arc<AtomicBool>) {}

pub fn spawn_route_monitor(runtime: Arc<Mutex<Option<TunnelRuntime>>>, _dll: Arc<WireGuardDll>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(ROUTE_MONITOR_INTERVAL_SECS)).await;

            let (endpoint, if_idx) = {
                let guard = runtime.lock().unwrap_or_else(|p| p.into_inner());
                match guard.as_ref() {
                    Some(rt) => (rt.primary_endpoint, rt.interface_index),
                    None => continue,
                }
            };

            let Some(ep) = endpoint else { continue };

            match best_route_interface_for(ep) {
                Ok(best_if) if best_if == if_idx => {
                    tracing::warn!(
                        "Route monitor: endpoint route uses tunnel if_idx={if_idx} — bypass broken; refreshing"
                    );
                    // Сначала удаляем старый bypass, потом создаём новый.
                    {
                        let mut guard = runtime.lock().unwrap_or_else(|p| p.into_inner());
                        if let Some(rt) = guard.as_mut() {
                            if let Some(old) = rt.current_bypass_row.take() {
                                unsafe {
                                    let _ = DeleteIpForwardEntry2(&old);
                                }
                            }
                        }
                    }
                    if let Ok(Some(new_row)) = add_full_tunnel_bypass_route(ep) {
                        let mut guard = runtime.lock().unwrap_or_else(|p| p.into_inner());
                        if let Some(rt) = guard.as_mut() {
                            rt.current_bypass_row = Some(new_row);
                        } else {
                            // Туннель уже закрыли — откатываем созданный bypass.
                            unsafe {
                                let _ = DeleteIpForwardEntry2(&new_row);
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => tracing::debug!("Route monitor: best_route_interface_for error: {e}"),
            }
        }
    });
}

pub fn spawn_dns_refresher(runtime: Arc<Mutex<Option<TunnelRuntime>>>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(DNS_REFRESH_INTERVAL_SECS));
        loop {
            interval.tick().await;
            let (hostname, old_endpoint) = {
                let guard = runtime.lock().unwrap_or_else(|p| p.into_inner());
                let rt = match guard.as_ref() {
                    Some(rt) => rt,
                    None => continue,
                };
                (rt.endpoint_hostname.clone(), rt.primary_endpoint)
            };
            let Some(hostname) = hostname else { continue };
            let new_ips = match tokio::net::lookup_host(format!("{}:0", hostname)).await {
                Ok(ips) => ips,
                Err(e) => {
                    tracing::warn!("DNS refresh lookup failed for {}: {}", hostname, e);
                    continue;
                }
            };
            let new_ip = new_ips.into_iter().next().map(|sa| sa.ip());
            let Some(new_ip) = new_ip else { continue };
            let port = old_endpoint.map_or(51820, |ep| ep.port());
            let new_endpoint = SocketAddr::new(new_ip, port);
            if Some(new_endpoint) == old_endpoint {
                continue;
            }
            tracing::info!("DNS refresh: {} resolved to new IP {}", hostname, new_ip);

            // Сначала удаляем старый bypass, потом создаём новый.
            {
                let mut guard = runtime.lock().unwrap_or_else(|p| p.into_inner());
                let rt = match guard.as_mut() {
                    Some(rt) => rt,
                    None => continue,
                };
                if let Some(old_row) = rt.current_bypass_row.take() {
                    unsafe {
                        let _ = DeleteIpForwardEntry2(&old_row);
                    }
                }
            }

            match add_full_tunnel_bypass_route(new_endpoint) {
                Ok(Some(new_row)) => {
                    let mut guard = runtime.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(rt) = guard.as_mut() {
                        rt.current_bypass_row = Some(new_row);
                        rt.primary_endpoint = Some(new_endpoint);
                        tracing::info!("DNS refresh: bypass route updated for new endpoint");
                    } else {
                        unsafe {
                            let _ = DeleteIpForwardEntry2(&new_row);
                        }
                    }
                }
                Ok(None) => {
                    let mut guard = runtime.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(rt) = guard.as_mut() {
                        rt.primary_endpoint = Some(new_endpoint);
                        tracing::info!("DNS refresh: endpoint now on-link, no bypass needed");
                    }
                }
                Err(e) => tracing::warn!("DNS refresh: bypass creation failed: {}", e),
            }
        }
    });
}

fn luid_to_index(luid: NET_LUID_LH) -> Result<u32, String> {
    use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToIndex;
    let mut idx = 0u32;
    unsafe { ConvertInterfaceLuidToIndex(&luid, &mut idx) }
        .map_err(|e| format!("LUID→Index: {e}"))?;
    Ok(idx)
}

async fn wait_for_interface_up(if_idx: u32, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    let mut wait = 100u64;
    while start.elapsed() < timeout {
        let up = unsafe {
            let mut row: MIB_IF_ROW2 = std::mem::zeroed();
            row.InterfaceIndex = if_idx;
            GetIfEntry2(&mut row).is_ok() && row.OperStatus == IfOperStatusUp
        };
        if up {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(wait)).await;
        wait = (wait * 2).min(500);
    }
    Err(format!(
        "Interface {if_idx} did not come up within {}s",
        timeout.as_secs()
    ))
}

async fn wait_for_handshake(
    dll: Arc<WireGuardDll>,
    adapter: Arc<Mutex<Option<WireGuardAdapterHandle>>>,
    session_guard: Arc<AtomicU64>,
    session_id: u64,
    handle: WireGuardAdapterHandle,
    timeout: Duration,
) -> Result<u64, String> {
    let start = Instant::now();
    let mut wait = 250u64;
    while start.elapsed() < timeout {
        if session_guard.load(Ordering::SeqCst) != session_id {
            return Err("Handshake task cancelled".into());
        }
        let handshake_ts = {
            let guard = adapter.lock().unwrap_or_else(|p| p.into_inner());
            let h = match *guard {
                Some(h) if h.0 == handle.0 => h,
                _ => return Err("Adapter changed during handshake wait".into()),
            };
            match dll.get_configuration(h) {
                Ok(buf) => {
                    let peers = read_peer_stats(&buf);
                    peers.iter().map(|(_, _, hs)| *hs).max().unwrap_or(0)
                }
                Err(_) => 0,
            }
        };
        if handshake_ts > 0 {
            return Ok(handshake_ts);
        }
        tokio::time::sleep(Duration::from_millis(wait)).await;
        wait = (wait * 2).min(2000);
    }
    Err("No handshake within timeout".into())
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn best_route_interface_for(endpoint: SocketAddr) -> Result<u32, String> {
    use windows::Win32::NetworkManagement::IpHelper::GetBestRoute2;

    let dst: SOCKADDR_INET = match endpoint.ip() {
        IpAddr::V4(v4) => {
            let mut sa = SOCKADDR_INET::default();
            sa.si_family = AF_INET;
            sa.Ipv4.sin_family = AF_INET;
            sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
            sa
        }
        IpAddr::V6(v6) => sockaddr_inet_from_ipv6(&v6),
    };

    unsafe {
        let mut best_route: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        let mut best_src: SOCKADDR_INET = std::mem::zeroed();
        GetBestRoute2(
            None,
            0,
            None,
            &dst as *const SOCKADDR_INET,
            0,
            &mut best_route,
            &mut best_src,
        )
        .map_err(|e| format!("GetBestRoute2: {e}"))?;
        Ok(best_route.InterfaceIndex)
    }
}

fn set_interface_mtu(if_idx: u32, mtu: u32) -> Result<(), String> {
    use windows::Win32::NetworkManagement::IpHelper::{GetIpInterfaceEntry, SetIpInterfaceEntry};
    unsafe {
        let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
        InitializeIpInterfaceEntry(&mut row);
        row.InterfaceIndex = if_idx;
        row.Family = AF_INET;
        GetIpInterfaceEntry(&mut row).map_err(|e| format!("GetIpInterfaceEntry: {e}"))?;
        row.NlMtu = mtu;
        SetIpInterfaceEntry(&mut row).map_err(|e| format!("SetIpInterfaceEntry(MTU): {e}"))?;
    }
    Ok(())
}

fn assign_interface_address(if_idx: u32, ip: IpAddr, prefix: u8) -> Result<(), String> {
    let sockaddr = socket_addr_to_sockaddr_inet(&SocketAddr::new(ip, 0));
    unsafe {
        let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        InitializeUnicastIpAddressEntry(&mut row);
        row.InterfaceIndex = if_idx;
        row.Address = sockaddr;
        row.OnLinkPrefixLength = prefix;
        row.SkipAsSource = false.into();

        match CreateUnicastIpAddressEntry(&row) {
            Ok(_) => Ok(()),
            Err(create_err) => {
                let mut existing: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
                InitializeUnicastIpAddressEntry(&mut existing);
                existing.InterfaceIndex = if_idx;
                existing.Address = sockaddr;
                if GetUnicastIpAddressEntry(&mut existing).is_ok() {
                    existing.OnLinkPrefixLength = prefix;
                    SetUnicastIpAddressEntry(&existing)
                        .map_err(|e| format!("SetUnicastIpAddressEntry: {e}"))
                } else {
                    Err(format!("CreateUnicastIpAddressEntry: {create_err}"))
                }
            }
        }
    }
}

fn remove_interface_address(if_idx: u32, ip: IpAddr, prefix: u8) {
    let sockaddr = socket_addr_to_sockaddr_inet(&SocketAddr::new(ip, 0));
    unsafe {
        let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        InitializeUnicastIpAddressEntry(&mut row);
        row.InterfaceIndex = if_idx;
        row.Address = sockaddr;
        row.OnLinkPrefixLength = prefix;
        let _ = DeleteUnicastIpAddressEntry(&row);
    }
}

fn add_full_tunnel_bypass_route(
    endpoint: SocketAddr,
) -> Result<Option<MIB_IPFORWARD_ROW2>, String> {
    use windows::Win32::NetworkManagement::IpHelper::GetBestRoute2;

    let (family, dst, ip_str) = match endpoint.ip() {
        IpAddr::V4(v4) => {
            let mut sa = SOCKADDR_INET::default();
            sa.si_family = AF_INET;
            sa.Ipv4.sin_family = AF_INET;
            sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
            (AF_INET, sa, format!("{}", v4))
        }
        IpAddr::V6(v6) => {
            let sa = sockaddr_inet_from_ipv6(&v6);
            (AF_INET6, sa, format!("{}", v6))
        }
    };

    unsafe {
        let mut best_route: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        let mut best_src: SOCKADDR_INET = std::mem::zeroed();

        GetBestRoute2(
            None,
            0,
            None,
            &dst as *const SOCKADDR_INET,
            0,
            &mut best_route,
            &mut best_src,
        )
        .map_err(|e| format!("GetBestRoute2 for endpoint {}: {e}", ip_str))?;

        let is_on_link = match family {
            AF_INET => best_route.NextHop.Ipv4.sin_addr.S_un.S_addr == 0,
            AF_INET6 => {
                let zero = IN6_ADDR::default();
                best_route.NextHop.Ipv6.sin6_addr.u.Byte == zero.u.Byte
            }
            _ => false,
        };

        if is_on_link {
            tracing::info!("Endpoint {} is on-link — no bypass needed", ip_str);
            return Ok(None);
        }

        let mut bypass: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        InitializeIpForwardEntry(&mut bypass);
        bypass.InterfaceIndex = best_route.InterfaceIndex;
        bypass.InterfaceLuid = best_route.InterfaceLuid;
        bypass.NextHop = best_route.NextHop;
        bypass.Metric = 1;

        if family == AF_INET {
            bypass.DestinationPrefix.PrefixLength = 32;
            bypass.DestinationPrefix.Prefix.Ipv4 = dst.Ipv4;
        } else {
            bypass.DestinationPrefix.PrefixLength = 128;
            bypass.DestinationPrefix.Prefix.Ipv6 = dst.Ipv6;
        }

        CreateIpForwardEntry2(&bypass)
            .map_err(|e| format!("CreateIpForwardEntry2 (bypass for {}): {e}", ip_str))?;

        tracing::info!(
            "Bypass host route added: {}/{} via gateway_if={}",
            ip_str,
            if family == AF_INET { 32 } else { 128 },
            bypass.InterfaceIndex
        );
        Ok(Some(bypass))
    }
}

fn inject_routes(
    if_idx: u32,
    cidrs: &[String],
    created_routes: &mut Vec<MIB_IPFORWARD_ROW2>,
) -> Result<(), String> {
    if cidrs.len() > 50 {
        return Err("Too many routes (max 50)".into());
    }

    for cidr in cidrs {
        let Ok((ip, prefix)) = parse_cidr(cidr) else {
            continue;
        };
        let IpAddr::V4(ipv4) = ip else { continue };

        let row = unsafe { create_forward_row(ipv4, prefix, if_idx) };
        unsafe {
            match CreateIpForwardEntry2(&row) {
                Ok(_) => {
                    tracing::info!("Route created: {cidr}");
                    created_routes.push(row);
                }
                Err(e) if e.code().0 as u32 == 0x8007_1392 => {
                    let mut existing = row;
                    if GetIpForwardEntry2(&mut existing).is_ok() {
                        existing.Metric = 8;
                        if SetIpForwardEntry2(&existing).is_err() {
                            tracing::warn!("Route metric update failed for {cidr}");
                        } else {
                            tracing::info!("Route metric updated: {cidr}");
                        }
                    }
                }
                Err(e) => tracing::warn!("Route create failed for {cidr}: {e}"),
            }
        }
    }
    Ok(())
}

fn delete_created_routes(routes: &[MIB_IPFORWARD_ROW2]) {
    for row in routes {
        unsafe {
            let _ = DeleteIpForwardEntry2(row);
        }
    }
}

fn apply_dns_via_registry(luid: NET_LUID_LH, servers: &[String]) -> Result<(), String> {
    use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToGuid;
    use winreg::{enums::*, RegKey};

    let mut guid: windows::core::GUID = unsafe { std::mem::zeroed() };
    unsafe { ConvertInterfaceLuidToGuid(&luid as *const NET_LUID_LH, &mut guid) }
        .map_err(|e| format!("ConvertInterfaceLuidToGuid: {e}"))?;

    let guid_str = format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7]
    );

    let reg_path = format!(
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{}",
        guid_str
    );

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm
        .create_subkey(&reg_path)
        .map_err(|e| format!("Registry create_subkey({reg_path}): {e}"))?;

    let dns_value = servers.join(",");
    key.set_value("NameServer", &dns_value)
        .map_err(|e| format!("Registry set NameServer: {e}"))?;

    tracing::debug!("DNS written to registry for GUID={guid_str}: {dns_value}");
    Ok(())
}

fn reset_dns_via_registry(luid: NET_LUID_LH) {
    if let Err(e) = apply_dns_via_registry(luid, &[]) {
        tracing::warn!("reset_dns_via_registry failed: {e}");
    }
}

fn apply_dns_servers(luid: NET_LUID_LH, if_idx: u32, servers: &[String]) -> Result<(), String> {
    if servers.is_empty() {
        return Ok(());
    }
    match apply_dns_via_registry(luid, servers) {
        Ok(()) => Ok(()),
        Err(e) => {
            tracing::warn!("Registry DNS failed ({e}), falling back to PowerShell");
            apply_dns_via_powershell(if_idx, servers)
        }
    }
}

fn reset_dns_servers(luid: NET_LUID_LH, if_idx: u32) {
    reset_dns_via_registry(luid);
    let _ = run_powershell(&format!(
        "Set-DnsClientServerAddress -InterfaceIndex {if_idx} -ResetServerAddresses"
    ));
}

fn apply_dns_via_powershell(if_idx: u32, servers: &[String]) -> Result<(), String> {
    let quoted = servers
        .iter()
        .map(|s| format!("'{}'", s.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");
    run_powershell(&format!(
        "Set-DnsClientServerAddress -InterfaceIndex {if_idx} -ServerAddresses @({quoted})"
    ))
}

fn run_powershell(script: &str) -> Result<(), String> {
    use std::process::Command;
    let out = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
        ])
        .arg(script)
        .output()
        .map_err(|e| format!("PowerShell launch failed: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(format!("PowerShell failed: {err}"))
    }
}

fn cleanup_runtime(_dll: &WireGuardDll, rt: &mut TunnelRuntime) {
    if !rt.created_routes.is_empty() {
        delete_created_routes(&rt.created_routes);
        tracing::info!("Deleted {} routes", rt.created_routes.len());
        rt.created_routes.clear();
    }
    if let Some(row) = rt.current_bypass_row.take() {
        unsafe {
            let _ = DeleteIpForwardEntry2(&row);
        }
        tracing::info!("Deleted bypass host route");
    }
    if !rt.dns_servers.is_empty() {
        reset_dns_servers(rt.interface_luid, rt.interface_index);
        rt.dns_servers.clear();
        tracing::info!("DNS reset");
    }
    if let Some(addr) = rt.assigned_address.take() {
        remove_interface_address(rt.interface_index, addr.ip, addr.prefix);
        tracing::info!("Removed IP {}/{}", addr.ip, addr.prefix);
    }
}
