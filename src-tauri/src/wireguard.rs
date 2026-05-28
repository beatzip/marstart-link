use crate::utils::{create_forward_row, parse_cidr};
use crate::wireguard_config::socket_addr_to_sockaddr_inet;
use crate::wireguard_serializer::read_peer_stats;

use std::ffi::c_void;
use std::net::{IpAddr, SocketAddr};
use std::os::windows::ffi::OsStrExt;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use libloading::os::windows::{Library, LOAD_WITH_ALTERED_SEARCH_PATH};
use serde::{Deserialize, Serialize};
use tauri::State;
use windows::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
    DeleteUnicastIpAddressEntry, GetIfEntry2, GetIpForwardEntry2, GetUnicastIpAddressEntry,
    InitializeIpForwardEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
    SetIpForwardEntry2, SetUnicastIpAddressEntry, MIB_IF_ROW2,
    MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
};
use windows::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET};

// ============================================================================
// MTU
// 1500 (Ethernet) − 20 (IPv4) − 8 (UDP) − 32 (WireGuard overhead) = 1440
// Запас на PPPoE (+8) и прочее → 1420 — стандарт WireGuard Windows клиента
// ============================================================================
const WG_INTERFACE_MTU: u32 = 1420;

// ============================================================================
// Newtype для Send + Sync (raw pointer на handle адаптера)
// ============================================================================
#[derive(Clone, Copy)]
pub struct WireGuardAdapterHandle(*mut c_void);
unsafe impl Send for WireGuardAdapterHandle {}
unsafe impl Sync for WireGuardAdapterHandle {}

// ============================================================================
// WireGuard Adapter State
// ============================================================================
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireGuardAdapterState {
    Down = 0,
    Up = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TunnelPhase {
    #[default]
    Idle,
    ApplyingConfig,
    WaitingHandshake,
    Connected,
    Disconnecting,
    Failed,
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

// ============================================================================
// FFI Type Aliases
// ============================================================================
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
    primary_endpoint: Option<SocketAddr>,
    /// Маршруты, созданные нами — удаляем при disconnect
    created_routes: Vec<MIB_IPFORWARD_ROW2>,
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
                "WireGuardCreateAdapter returned NULL for \"{}\"",
                name
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

// ============================================================================
// Tunnel State
// ============================================================================
pub struct TunnelState {
    pub dll: Arc<WireGuardDll>,
    pub adapter: Arc<Mutex<Option<WireGuardAdapterHandle>>>,
    runtime: Arc<Mutex<Option<TunnelRuntime>>>,
    pub status: Arc<Mutex<TunnelStatus>>,
    pub session_id: Arc<AtomicU64>,
}

impl TunnelState {
    pub fn new(dll: Arc<WireGuardDll>) -> Self {
        Self {
            dll,
            adapter: Arc::new(Mutex::new(None)),
            runtime: Arc::new(Mutex::new(None)),
            status: Arc::new(Mutex::new(TunnelStatus::default())),
            session_id: Arc::new(AtomicU64::new(0)),
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

    pub fn begin_session(&self) -> u64 {
        self.session_id
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1)
    }

    pub fn invalidate_session(&self) -> u64 {
        self.session_id
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1)
    }

    #[allow(dead_code)]
    pub fn current_session(&self) -> u64 {
        self.session_id.load(Ordering::SeqCst)
    }
}

// ============================================================================
// IPC Types
// ============================================================================
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
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TunnelStats {
    pub is_active: bool,
    pub total_tx: u64,
    pub total_rx: u64,
    pub last_handshake_unix: u64, // 0 = нет хэндшейка
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

// ============================================================================
// Tauri Commands
// ============================================================================
#[tauri::command]
pub async fn tunnel_get_status(state: State<'_, TunnelState>) -> Result<TunnelStatus, String> {
    Ok(state
        .status
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone())
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

    let buf = state.dll.get_configuration(handle)?;
    let peers = read_peer_stats(&buf);

    let total_tx = peers.iter().map(|(tx, _, _)| tx).sum();
    let total_rx = peers.iter().map(|(_, rx, _)| rx).sum();
    // Last handshake = max across all peers (most recent)
    let last_handshake = peers.iter().map(|(_, _, hs)| *hs).max().unwrap_or(0);

    if last_handshake > 0 {
        let mut status = state.status.lock().unwrap_or_else(|p| p.into_inner());
        status.health.handshake_ok = true;
        if matches!(status.phase, TunnelPhase::WaitingHandshake) {
            status.phase = TunnelPhase::Connected;
        }
    }

    let is_active = {
        let status = state.status.lock().unwrap_or_else(|p| p.into_inner());
        status.is_active
    };

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

    if let Some(handle) = {
        let guard = state.adapter.lock().unwrap_or_else(|p| p.into_inner());
        *guard
    } {
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
                let route_ok = best_if == if_idx;
                diag.route_health_ok = route_ok;
                diag.game_path_verified = route_ok && diag.handshake_ok && !diag.leak_detected;

                let mut status_guard = state.status.lock().unwrap_or_else(|p| p.into_inner());
                status_guard.health.game_path_verified = diag.game_path_verified;
                status_guard.health.leak_detected = !route_ok;
                status_guard.health.routes_ok = status_guard.health.routes_ok && route_ok;
            }
            Err(e) => tracing::debug!("best_route_interface_for failed: {e}"),
        }
    }

    Ok(diag)
}

#[tauri::command]
pub async fn tunnel_apply_config(
    state: State<'_, TunnelState>,
    config_content: String,
    adapter_name: String,
    expected_routes: Vec<String>,
) -> Result<TunnelStatus, String> {
    use crate::wireguard_parser;
    use crate::wireguard_serializer::{hexdump, serialize_config};

    state.invalidate_session();
    let session_id = state.begin_session();

    // ── 1. Parse (spawn_blocking: DNS resolution may block) ────────────────
    let parsed = tokio::task::spawn_blocking({
        let content = config_content.clone();
        move || wireguard_parser::parse_wireguard_config(&content)
    })
    .await
    .map_err(|e| format!("Parse task panic: {e}"))?;

    let parsed = parsed?;
    tracing::info!("Config parsed: {} peer(s)", parsed.peers.len());

    // ── 2. Serialize ───────────────────────────────────────────────────────
    let blob = serialize_config(&parsed)?;
    tracing::info!("WG blob {} bytes", blob.len());
    tracing::debug!("WG blob:\n{}", hexdump(&blob, 256));

    {
        let mut status = state.status.lock().unwrap_or_else(|p| p.into_inner());
        status.phase = TunnelPhase::ApplyingConfig;
        status.session_id = session_id;
        status.health = TunnelHealth::default();
        status.adapter_name = Some(adapter_name.clone());
    }

    // ── 3. Create adapter + configure + bring Up (fast, synchronous) ───────
    let (handle, if_idx) = {
        let mut lock = state.adapter.lock().unwrap_or_else(|p| p.into_inner());

        // Close previous adapter if any
        if let Some(old) = lock.take() {
            let _ = state.dll.set_state(old, WireGuardAdapterState::Down);
            state.dll.close_adapter(old);
        }

        let handle = state.dll.create_adapter(&adapter_name, "GameAccelerator")?;
        tracing::info!("Adapter created: {adapter_name}");

        if let Err(e) = state.dll.set_configuration(handle, &blob) {
            state.dll.close_adapter(handle);
            return Err(format!("SetConfiguration: {e}"));
        }
        tracing::info!("WireGuard configuration applied");

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
        tracing::info!("Adapter UP, InterfaceIndex={if_idx}");

        // ← Store handle early so get_stats can proceed
        *lock = Some(handle);
        (handle, if_idx)
    };

    // ── Helper: emergency teardown ──────────────────────────────────────────
    let do_emergency_teardown = |msg: String| -> String {
        if let Some(mut rt) = state
            .runtime
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            cleanup_runtime(&state.dll, &mut rt);
        }

        let mut lock = state.adapter.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(h) = lock.take() {
            let _ = state.dll.set_state(h, WireGuardAdapterState::Down);
            state.dll.close_adapter(h);
        }

        let mut status = state.status.lock().unwrap_or_else(|p| p.into_inner());
        status.is_active = false;
        status.phase = TunnelPhase::Failed;
        status.health.leak_detected = true;

        msg
    };

    // ── 4. Wait for interface to be operationally Up ────────────────────────
    if let Err(e) = wait_for_interface_up(if_idx, Duration::from_secs(20)).await {
        return Err(do_emergency_teardown(e));
    }
    tracing::info!("Interface IfOperStatusUp confirmed");
    {
        let mut status = state.status.lock().unwrap_or_else(|p| p.into_inner());
        status.health.interface_ok = true;
    }

    // ── 5. Full-tunnel bypass route (MUST come before injecting 0.0.0.0/0) ─
    let mut runtime = TunnelRuntime {
        interface_index: if_idx,
        assigned_address: None,
        dns_servers: vec![],
        primary_endpoint: parsed.peers.first().and_then(|peer| peer.endpoint),
        created_routes: vec![],
    };

    let has_half1 = expected_routes.iter().any(|r| r == "0.0.0.0/1");
    let has_half2 = expected_routes.iter().any(|r| r == "128.0.0.0/1");
    let is_full_tunnel =
        expected_routes.iter().any(|r| r == "0.0.0.0/0") || (has_half1 && has_half2);
    if is_full_tunnel {
        if let Some(peer) = parsed.peers.first() {
            if let Some(endpoint) = peer.endpoint {
                match add_full_tunnel_bypass_route(endpoint) {
                    Ok(row) => {
                        tracing::info!("Full-tunnel bypass route added for {}", endpoint.ip());
                        runtime.created_routes.push(row);
                    }
                    Err(e) => tracing::warn!("Bypass route failed (non-fatal): {e}"),
                }
            }
        }
    }

    // ── 6. Assign interface IP ────────────────────────────────────────────
    if let (Some(ip), Some(prefix)) = (parsed.interface_address, parsed.interface_prefix) {
        match assign_interface_address(if_idx, ip, prefix) {
            Ok(_) => {
                tracing::info!("Assigned IP {ip}/{prefix} to interface");
                runtime.assigned_address = Some(AssignedAddress { ip, prefix });
                state
                    .status
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .health
                    .adapter_ok = true;
            }
            Err(e) => {
                cleanup_runtime(&state.dll, &mut runtime);
                return Err(do_emergency_teardown(format!("IP assignment failed: {e}")));
            }
        }
    } else {
        tracing::warn!("No Address field in config — interface has no IP");
    }

    // ── 7. Set MTU (1420 = standard WireGuard optimal) ───────────────────
    if let Err(e) = set_interface_mtu(if_idx, WG_INTERFACE_MTU) {
        tracing::warn!("MTU set failed (non-fatal): {e}");
    } else {
        tracing::info!("MTU set to {WG_INTERFACE_MTU}");
    }

    // ── 8. Inject routes ─────────────────────────────────────────────────
    if let Err(e) = inject_routes(if_idx, &expected_routes, &mut runtime.created_routes) {
        tracing::warn!("Route injection partial failure (non-fatal): {e}");
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

    // ── 9. DNS ──────────────────────────────────────────────────────────
    if !parsed.dns_servers.is_empty() {
        match apply_dns_servers(if_idx, &parsed.dns_servers) {
            Ok(_) => {
                tracing::info!("DNS set: {:?}", parsed.dns_servers);
                runtime.dns_servers = parsed.dns_servers.clone();
                state
                    .status
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .health
                    .dns_ok = true;
            }
            Err(e) => {
                tracing::warn!("DNS set failed (non-fatal): {e}");
                state
                    .status
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .health
                    .dns_ok = false;
            }
        }
    }

    // ── 10. Store runtime ─────────────────────────────────────────────────
    *state.runtime.lock().unwrap_or_else(|p| p.into_inner()) = Some(runtime);

    // ── 11. Update status ─────────────────────────────────────────────────
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
    };
    *state.status.lock().unwrap_or_else(|p| p.into_inner()) = status.clone();

    // ── 12. Async handshake wait (non-fatal — tunnel is up regardless) ────
    let dll = state.dll.clone();
    let adapter = state.adapter.clone();
    let status_arc = state.status.clone();
    let session_guard = state.session_id.clone();
    let session_guard_check = session_guard.clone();
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
                tracing::info!("WireGuard handshake at unix={ts}");
                if session_guard_check.load(Ordering::SeqCst) == session_id {
                    let mut status = status_arc.lock().unwrap_or_else(|p| p.into_inner());
                    status.phase = TunnelPhase::Connected;
                    status.health.handshake_ok = true;
                }
            }
            Err(e) => tracing::warn!("Handshake timeout/error: {e}"),
        }
    });

    tracing::info!("tunnel_apply_config complete: adapter={adapter_name} if_idx={if_idx}");
    Ok(status)
}

#[tauri::command]
pub async fn tunnel_disconnect(state: State<'_, TunnelState>) -> Result<(), String> {
    state.invalidate_session();
    {
        let mut status = state.status.lock().unwrap_or_else(|p| p.into_inner());
        status.phase = TunnelPhase::Disconnecting;
    }

    // Cleanup routes, DNS, IP address
    if let Some(mut rt) = state
        .runtime
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take()
    {
        cleanup_runtime(&state.dll, &mut rt);
    }

    // Bring adapter down
    let mut lock = state.adapter.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(h) = lock.take() {
        let _ = state.dll.set_state(h, WireGuardAdapterState::Down);
        state.dll.close_adapter(h);
        tracing::info!("Adapter closed");
    }

    let mut status = state.status.lock().unwrap_or_else(|p| p.into_inner());
    *status = TunnelStatus::default();
    status.phase = TunnelPhase::Idle;
    status.health = TunnelHealth::default();
    state.session_id.store(0, Ordering::SeqCst);
    Ok(())
}

// ============================================================================
// Panic hook
// ============================================================================
pub fn setup_panic_hook(
    dll: Arc<WireGuardDll>,
    adapter: Arc<Mutex<Option<WireGuardAdapterHandle>>>,
) {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!("PANIC: {info:?}");
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

// ============================================================================
// Helper functions
// ============================================================================

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

/// ASYNC handshake wait — не блокирует Tokio runtime
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

        let current_handle = {
            let guard = adapter.lock().unwrap_or_else(|p| p.into_inner());
            match *guard {
                Some(h) if h.0 == handle.0 => h,
                _ => return Err("Adapter changed during handshake wait".into()),
            }
        };

        if let Ok(buf) = dll.get_configuration(current_handle) {
            let peers = read_peer_stats(&buf);
            if let Some((_, _, hs)) = peers.iter().max_by_key(|(_, _, hs)| *hs) {
                if *hs > 0 {
                    return Ok(*hs);
                }
            }
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
    let endpoint_ipv4 = match endpoint.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Err("route verification for IPv6 endpoint not implemented".into()),
    };

    unsafe {
        let mut dst: SOCKADDR_INET = std::mem::zeroed();
        dst.si_family = AF_INET;
        dst.Ipv4.sin_family = AF_INET;
        dst.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(endpoint_ipv4.octets());

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
        .map_err(|e| format!("GetBestRoute2(route verification): {e}"))?;

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
                // Address might already exist — try update
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

/// Добавляет host-маршрут /32 для VPN endpoint через текущий default gateway ISP.
/// Критически важно для full-tunnel (0.0.0.0/0): без него трафик к VPS endpoint
/// тоже пойдёт в туннель → routing loop → отключение.
fn add_full_tunnel_bypass_route(endpoint: SocketAddr) -> Result<MIB_IPFORWARD_ROW2, String> {
    use windows::Win32::NetworkManagement::IpHelper::GetBestRoute2;
    let endpoint_ipv4 = match endpoint.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Err("IPv6 endpoint bypass not implemented".into()),
    };

    unsafe {
        let mut dst: SOCKADDR_INET = std::mem::zeroed();
        dst.si_family = AF_INET;
        dst.Ipv4.sin_family = AF_INET;
        dst.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(endpoint_ipv4.octets());

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
        .map_err(|e| format!("GetBestRoute2 for endpoint {endpoint_ipv4}: {e}"))?;

        let mut bypass: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        InitializeIpForwardEntry(&mut bypass);
        bypass.InterfaceIndex = best_route.InterfaceIndex;
        bypass.InterfaceLuid = best_route.InterfaceLuid;
        bypass.DestinationPrefix.PrefixLength = 32;
        bypass.DestinationPrefix.Prefix.si_family = AF_INET;
        bypass.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr =
            u32::from_ne_bytes(endpoint_ipv4.octets());
        bypass.NextHop = best_route.NextHop;
        bypass.Metric = 1;

        let next_hop_v4 = best_route.NextHop.Ipv4.sin_addr.S_un.S_addr;
        if next_hop_v4 == 0 {
            tracing::info!("Endpoint {endpoint_ipv4} is on-link — no bypass needed");
            return Ok(std::mem::zeroed());
        }

        CreateIpForwardEntry2(&bypass)
            .map_err(|e| format!("CreateIpForwardEntry2 (bypass): {e}"))?;

        tracing::info!(
            "Bypass host route added: {}/32 via gateway_if={}",
            endpoint_ipv4,
            bypass.InterfaceIndex
        );

        Ok(bypass)
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
                    // ERROR_OBJECT_ALREADY_EXISTS — update metric
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

fn run_powershell(script: &str) -> Result<(), String> {
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

fn apply_dns_servers(if_idx: u32, servers: &[String]) -> Result<(), String> {
    if servers.is_empty() {
        return Ok(());
    }
    let quoted = servers
        .iter()
        .map(|s| format!("'{}'", s.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");
    run_powershell(&format!(
        "Set-DnsClientServerAddress -InterfaceIndex {if_idx} -ServerAddresses @({quoted})"
    ))
}

fn reset_dns_servers(if_idx: u32) {
    let _ = run_powershell(&format!(
        "Set-DnsClientServerAddress -InterfaceIndex {if_idx} -ResetServerAddresses"
    ));
}

fn cleanup_runtime(dll: &WireGuardDll, rt: &mut TunnelRuntime) {
    if let Some(addr) = rt.assigned_address.take() {
        remove_interface_address(rt.interface_index, addr.ip, addr.prefix);
        tracing::info!("Removed IP {}/{}", addr.ip, addr.prefix);
    }
    if !rt.dns_servers.is_empty() {
        reset_dns_servers(rt.interface_index);
        rt.dns_servers.clear();
        tracing::info!("DNS reset");
    }
    if !rt.created_routes.is_empty() {
        delete_created_routes(&rt.created_routes);
        tracing::info!("Deleted {} routes", rt.created_routes.len());
        rt.created_routes.clear();
    }
    let _ = dll; // future-proof
}
