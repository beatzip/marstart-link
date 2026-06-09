#[cfg(target_os = "windows")]
use crate::wireguard_config::{ParsedConfig, WIREGUARD_KEY_LENGTH};
use crate::wireguard_parser::{parse_wireguard_config, validate_config};
#[cfg(target_os = "windows")]
use crate::wireguard_serializer::{read_peer_stats, serialize_config};
#[cfg(target_os = "windows")]
use base64::Engine;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{FARPROC, HANDLE, NTSTATUS, WIN32_ERROR};
#[cfg(target_os = "windows")]
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};
#[cfg(target_os = "windows")]
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
#[cfg(target_os = "windows")]
use PCWSTR;

/// Returns path to DLL next to the executable
fn get_dll_path(dll_name: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    exe.parent()
        .map(|p| p.join(dll_name))
        .unwrap_or_else(|| PathBuf::from(dll_name))
}

#[derive(Clone, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub handshake_timestamp_unix: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub endpoint: Option<String>,
}

#[cfg(target_os = "windows")]
pub struct WireGuardTunnel {
    adapter_name: String,
    config: crate::wireguard_config::ParsedConfig,
    status: Mutex<TunnelStatus>,
    counters: Arc<TunnelCounters>,
    interface_index: Mutex<u32>,
    created_routes: Mutex<Vec<(std::net::IpAddr, u8)>>,
    connect_time: Option<std::time::Instant>,
    adapter_handle: Mutex<Option<HANDLE>>,
    original_dns: Mutex<Vec<String>>,
    /// Имя основного (non-tunnel) адаптера для восстановления DNS
    primary_adapter_name: Mutex<Option<String>>,
}

#[cfg(target_os = "windows")]
type WireGuardCreateAdapterFunc = unsafe extern "system" fn(
    flags: u32,
    adapter_name: windows::Win32::Foundation::PCWSTR,
    tunnel_name: windows::Win32::Foundation::PCWSTR,
) -> HANDLE;

#[cfg(target_os = "windows")]
type WireGuardDeleteAdapterFunc =
    unsafe extern "system" fn(adapter: HANDLE, adapter_name: windows::Win32::Foundation::PCWSTR);

#[cfg(target_os = "windows")]
type WireGuardSetConfigurationFunc = unsafe extern "system" fn(
    adapter: HANDLE,
    config_bytes: *const std::ffi::c_void,
    config_size: u32,
) -> NTSTATUS;

#[cfg(target_os = "windows")]
type WireGuardGetConfigurationFunc = unsafe extern "system" fn(
    adapter: HANDLE,
    config_bytes: *mut std::ffi::c_void,
    config_size: *mut u32,
) -> NTSTATUS;

#[cfg(not(target_os = "windows"))]
impl WireGuardTunnel {
    pub fn new(profile: &crate::profiles::Profile) -> Result<Self, String> {
        let private_key = keyring::Entry::new("GameAccelerator", &profile.id)
            .map_err(|e| e.to_string())?
            .get_password()
            .map_err(|e| e.to_string())?;

        let config = if let Some(ref config_path) = profile.wg_config_path {
            let config_text = std::fs::read_to_string(config_path)
                .map_err(|e| format!("Failed to read config {}: {}", config_path, e))?;
            let mut parsed = parse_wireguard_config(&config_text)?;
            let mut key_bytes = [0u8; WIREGUARD_KEY_LENGTH];
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&private_key)
                .map_err(|e| format!("Invalid base64 private key: {}", e))?;
            if decoded.len() != WIREGUARD_KEY_LENGTH {
                return Err(format!(
                    "Invalid private key length: expected {}, got {}",
                    WIREGUARD_KEY_LENGTH,
                    decoded.len()
                ));
            }
            key_bytes.copy_from_slice(&decoded);
            parsed.private_key = key_bytes;
            validate_config(&parsed)?;
            parsed
        } else {
            return Err("No WireGuard config path in profile".to_string());
        };

        Ok(Self {
            adapter_name: format!("WG-{}", &profile.id),
            config,
            status: Mutex::new(TunnelStatus::Disconnected),
            counters: Arc::new(TunnelCounters::default()),
            interface_index: Mutex::new(0),
            created_routes: Mutex::new(Vec::new()),
            connect_time: None,
            adapter_handle: Mutex::new(None),
            original_dns: Mutex::new(Vec::new()),
            primary_adapter_name: Mutex::new(None),
        })
    }

    pub fn connect(&mut self) -> Result<(), String> {
        *self.status.lock().map_err(|e| e.to_string())? = TunnelStatus::Connecting;

        #[cfg(target_os = "windows")]
        use std::os::windows::ffi::OsStrExt;
        {
            // Load WireGuard DLL from same directory as executable
            let dll_path = get_dll_path("wireguard.dll");
            let dll_path_wide: Vec<u16> = std::ffi::OsStr::new(&dll_path)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let wg_lib = unsafe { LoadLibraryW(PCWSTR(dll_path_wide.as_ptr())) }
                .map_err(|e| format!("Failed to load wireguard.dll from {:?}: {}", dll_path, e))?;

            let create_adapter: FARPROC = unsafe {
                GetProcAddress(wg_lib, s!("WireGuardCreateAdapter"))
                    .map_err(|e| format!("WireGuardCreateAdapter not found: {}", e))?
            };

            let tunnel_wide: Vec<u16> = std::ffi::OsStr::new(&self.adapter_name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let tunnel_name = windows::Win32::Foundation::PCWSTR(tunnel_wide.as_ptr());

            let handle: HANDLE = unsafe {
                let func: WireGuardCreateAdapterFunc = std::mem::transmute(create_adapter.0);
                func(0, tunnel_name, tunnel_name)
            };

            if handle.0 == ptr::null_mut() {
                *self.status.lock().map_err(|e| e.to_string())? =
                    TunnelStatus::Error("Failed to create adapter".to_string());
                return Err("Failed to create WireGuard adapter".to_string());
            }

            // Store handle immediately for cleanup on error
            *self.adapter_handle.lock().map_err(|e| e.to_string())? = Some(handle);

            // Get interface index with cleanup on error
            let if_index = match self.query_interface_index(handle) {
                Ok(idx) => idx,
                Err(e) => {
                    self.cleanup_adapter_handle()?;
                    return Err(e);
                }
            };
            *self.interface_index.lock().map_err(|e| e.to_string())? = if_index;

            // Clear previous DNS state for clean reconnect
            *self.original_dns.lock().map_err(|e| e.to_string())? =
                self.get_primary_adapter_dns()?;

            // Apply tunnel DNS if configured
            let dns_changed = !self.config.dns_servers.is_empty();
            if dns_changed {
                self.set_dns(&self.config.dns_servers)?;
            }

            // Apply configuration
            let config_blob = serialize_config(&self.config)
                .map_err(|e| format!("Failed to serialize config: {}", e))?;

            let set_config: FARPROC = unsafe {
                GetProcAddress(wg_lib, s!("WireGuardSetConfiguration"))
                    .map_err(|e| format!("WireGuardSetConfiguration not found: {}", e))?
            };

            let status: NTSTATUS = unsafe {
                let func: WireGuardSetConfigurationFunc = std::mem::transmute(set_config.0);
                func(
                    handle,
                    config_blob.as_ptr() as *const std::ffi::c_void,
                    config_blob.len() as u32,
                )
            };

            if status != NTSTATUS(0) {
                *self.status.lock().map_err(|e| e.to_string())? =
                    TunnelStatus::Error(format!("WireGuardSetConfiguration failed: {:?}", status));
                // Rollback DNS if it was changed
                if !self.config.dns_servers.is_empty() {
                    let _ = self.reset_adapter_dns();
                }
                self.cleanup_adapter_handle()?;
                return Err("Failed to set WireGuard configuration".to_string());
            }

            // Create routes with real interface index
            // Track added routes for rollback on error
            let mut added_routes: Vec<(std::net::IpAddr, u8)> = Vec::new();

            // First create route for interface address itself
            if let (Some(addr), Some(prefix)) =
                (self.config.interface_address, self.config.interface_prefix)
            {
                if let Err(e) = self.create_route(addr, prefix) {
                    // Rollback DNS if it was changed
                    if dns_changed {
                        let _ = self.reset_adapter_dns();
                    }
                    self.cleanup_adapter_handle()?;
                    return Err(e);
                }
                added_routes.push((addr, prefix));
            }

            if let Some(peer) = self.config.peers.first() {
                for aip in &peer.allowed_ips {
                    if let Err(e) = self.create_route(aip.address, aip.cidr) {
                        // Rollback routes in reverse order
                        for route in added_routes.iter().rev() {
                            let _ = self.delete_route(route.0, route.1);
                        }
                        // Rollback DNS if it was changed
                        if dns_changed {
                            let _ = self.reset_adapter_dns();
                        }
                        self.cleanup_adapter_handle()?;
                        return Err(e);
                    }
                    added_routes.push((aip.address, aip.cidr));
                }
            }
            // Store routes for later cleanup
            self.created_routes
                .lock()
                .map_err(|e| e.to_string())?
                .extend(added_routes.iter().cloned());
        }

        #[cfg(not(target_os = "windows"))]
        {
            return Err("WireGuard only supported on Windows".to_string());
        }

        *self.status.lock().map_err(|e| e.to_string())? = TunnelStatus::Connected;
        self.connect_time = Some(Instant::now());
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn delete_adapter(&self, handle: HANDLE) -> Result<(), String> {
        // Load WireGuard DLL from same directory as executable
        let dll_path = get_dll_path("wireguard.dll");
        let dll_path_wide: Vec<u16> = std::ffi::OsStr::new(&dll_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        if let Ok(lib) = unsafe { LoadLibraryW(PCWSTR(dll_path_wide.as_ptr())) } {
            if let Ok(proc) = unsafe { GetProcAddress(lib, s!("WireGuardDeleteAdapter")) } {
                let func: WireGuardDeleteAdapterFunc = unsafe { std::mem::transmute(proc.0) };
                let tunnel_wide: Vec<u16> = std::ffi::OsStr::new(&self.adapter_name)
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();
                let tunnel_name = windows::Win32::Foundation::PCWSTR(tunnel_wide.as_ptr());
                unsafe {
                    func(handle, tunnel_name);
                }
                return Ok(());
            }
        }
        Err("Failed to load WireGuardDeleteAdapter".to_string())
    }

    #[cfg(target_os = "windows")]
    fn cleanup_adapter_handle(&self) -> Result<(), String> {
        // Take the handle out without holding the lock - prevents deadlock
        let handle = self
            .adapter_handle
            .lock()
            .map_err(|e| e.to_string())?
            .take();
        if let Some(h) = handle {
            // Delete routes with rollback before adapter removal
            let routes = self
                .created_routes
                .lock()
                .map_err(|e| e.to_string())?
                .clone();
            for (dest, prefix_len) in &routes {
                let _ = self.delete_route(*dest, *prefix_len);
            }
            self.created_routes
                .lock()
                .map_err(|e| e.to_string())?
                .clear();

            // Delete adapter before closing handle
            let _ = self.delete_adapter(h);
            unsafe {
                windows::Win32::Foundation::CloseHandle(h);
            }
        }
        *self.interface_index.lock().map_err(|e| e.to_string())? = 0;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn query_interface_index(&self, _handle: HANDLE) -> Result<u32, String> {
        use windows::Win32::NetworkManagement::IpHelper::GetAdaptersAddresses;
        use windows::Win32::NetworkManagement::IpHelper::PIP_ADAPTER_ADDRESSES;

        // Retry up to 10 times with 100ms delay - adapter may not appear immediately
        for _attempt in 0..10 {
            let mut buf_size: u32 = 0;
            unsafe {
                GetAdaptersAddresses(
                    AF_INET, // Pass ADDRESS_FAMILY directly (u16), API handles conversion
                    0x10,    // GAA_FLAG_INCLUDE_PREFIX
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut buf_size,
                );
            }

            if buf_size == 0 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }

            let mut buffer = vec![0u8; buf_size as usize];
            let result = unsafe {
                GetAdaptersAddresses(
                    AF_INET, // Pass ADDRESS_FAMILY directly
                    0x10,    // GAA_FLAG_INCLUDE_PREFIX
                    std::ptr::null_mut(),
                    buffer.as_mut_ptr() as *mut _,
                    &mut buf_size,
                )
            };

            if result != 0 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }

            // Parse adapters to find our tunnel
            unsafe {
                let mut current = buffer.as_ptr() as PIP_ADAPTER_ADDRESSES;
                while !current.is_null() {
                    let friendly_name = (*current).FriendlyName;
                    if !friendly_name.is_null() {
                        let name_str = std::ffi::OsStr::from_wide(std::slice::from_raw_parts(
                            friendly_name.0,
                            (0..1024)
                                .take_while(|&i| *(*current).FriendlyName.0.add(i) != 0)
                                .count(),
                        ));
                        if let Ok(name) = name_str.and_then(|n| n.to_str()) {
                            if name.contains(&self.adapter_name) {
                                return Ok((*current).IfIndex);
                            }
                        }
                    }
                    current = (*current).Next;
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        Err("Adapter not found in system after retries".to_string())
    }

    #[cfg(not(target_os = "windows"))]
    fn query_interface_index(&self, _handle: HANDLE) -> Result<u32, String> {
        Ok(0)
    }

    #[cfg(target_os = "windows")]
    fn create_route(&self, dest: std::net::IpAddr, prefix_len: u8) -> Result<(), String> {
        use windows::Win32::Foundation::WIN32_ERROR;
        use windows::Win32::NetworkManagement::IpHelper::{
            CreateIpForwardEntry2, MIB_IPFORWARD_ROW2,
        };

        let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        unsafe {
            windows::Win32::NetworkManagement::IpHelper::InitializeIpForwardEntry(&mut row);
        }

        match dest {
            std::net::IpAddr::V4(v4) => {
                row.DestinationPrefix.Prefix.si_family = AF_INET;
                row.DestinationPrefix.Prefix.Ipv4.sin_addr =
                    windows::Win32::Networking::WinSock::IN_ADDR {
                        S_un: windows::Win32::Networking::WinSock::IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(v4.octets()),
                        },
                    };
                row.DestinationPrefix.PrefixLength = prefix_len;
                row.InterfaceIndex = *self.interface_index.lock().map_err(|e| e.to_string())?;
                row.Metric = 10;

                let status = unsafe { CreateIpForwardEntry2(&row) };
                if status != WIN32_ERROR(0) {
                    return Err(format!("CreateIpForwardEntry2 failed: {}", status.0));
                }
            }
            std::net::IpAddr::V6(_) => {
                tracing::warn!("IPv6 routes not implemented");
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn create_route(&self, _dest: std::net::IpAddr, _prefix_len: u8) -> Result<(), String> {
        Ok(())
    }

    pub fn teardown(&self) -> Result<(), String> {
        // Restore original primary adapter DNS if it was changed
        let original_dns: Vec<String> =
            self.original_dns.lock().map_err(|e| e.to_string())?.clone();
        let dns_changed = !original_dns.is_empty() || !self.config.dns_servers.is_empty();
        if dns_changed {
            let _ = self.restore_primary_dns();
        }

        // Reset tunnel adapter DNS to DHCP (tolerant - adapter may not exist)
        let _ = self.reset_adapter_dns();

        // Delete routes using stored routes - ignore errors, route may already be gone
        let routes = self
            .created_routes
            .lock()
            .map_err(|e| e.to_string())?
            .clone();
        for (dest, prefix_len) in &routes {
            let _ = self.delete_route(*dest, *prefix_len);
        }
        // Clear routes after deletion
        self.created_routes
            .lock()
            .map_err(|e| e.to_string())?
            .clear();

        #[cfg(target_os = "windows")]
        {
            // Take the handle to avoid double-locking
            let handle = self
                .adapter_handle
                .lock()
                .map_err(|e| e.to_string())?
                .take();
            if let Some(h) = handle {
                // Use the helper function to delete adapter
                let _ = self.delete_adapter(h);
                unsafe {
                    windows::Win32::Foundation::CloseHandle(h);
                }
            }
        }

        self.counters.tx_bytes.store(0, Ordering::Relaxed);
        self.counters.rx_bytes.store(0, Ordering::Relaxed);
        self.counters
            .last_handshake_unix
            .store(0, Ordering::Relaxed);

        // Clear interface index
        *self.interface_index.lock().map_err(|e| e.to_string())? = 0;

        *self.status.lock().map_err(|e| e.to_string())? = TunnelStatus::Disconnected;
        Ok(())
    }

    pub fn status(&self) -> TunnelStatus {
        self.status
            .lock()
            .map(|g| g.clone())
            .unwrap_or(TunnelStatus::Disconnected)
    }

    pub fn stats(&self) -> Result<(u64, u64, u64), String> {
        // Try to get real stats from WireGuard
        let handle_guard = self.adapter_handle.lock().map_err(|e| e.to_string())?;
        if let Some(handle) = handle_guard.as_ref() {
            let (tx, rx, handshake) = self.read_peer_stats(*handle)?;
            return Ok((tx, rx, handshake));
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
                .and_then(|p| p.endpoint)
                .map(|e| e.to_string()),
        })
    }

    #[cfg(target_os = "windows")]
    fn read_peer_stats(&self, handle: HANDLE) -> Result<(u64, u64, u64), String> {
        let dll_path = get_dll_path("wireguard.dll");
        let dll_path_wide: Vec<u16> = std::ffi::OsStr::new(&dll_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let lib = match unsafe { LoadLibraryW(PCWSTR(dll_path_wide.as_ptr())) } {
            Ok(l) => l,
            Err(_) => return Ok((0, 0, 0)),
        };

        let get_config_ptr = match unsafe { GetProcAddress(lib, s!("WireGuardGetConfiguration")) } {
            Ok(p) => p,
            Err(_) => return Ok((0, 0, 0)),
        };

        let get_config_fn: WireGuardGetConfigurationFunc =
            unsafe { std::mem::transmute(get_config_ptr.0) };

        // Get buffer size
        let mut buf_size: u32 = 0;
        unsafe {
            get_config_fn(handle, std::ptr::null_mut(), &mut buf_size);
        };

        if buf_size == 0 {
            return Ok((0, 0, 0));
        }

        let mut buffer = vec![0u8; buf_size as usize];
        let status = unsafe { get_config_fn(handle, buffer.as_mut_ptr() as *mut _, &mut buf_size) };

        if status != NTSTATUS(0) {
            return Ok((0, 0, 0));
        }

        // Use existing safe parser from wireguard_serializer
        let stats = read_peer_stats(&buffer);
        if let Some((tx, rx, handshake)) = stats.into_iter().next() {
            Ok((tx, rx, handshake))
        } else {
            Ok((0, 0, 0))
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn read_peer_stats(&self, _handle: HANDLE) -> Result<(u64, u64, u64), String> {
        Ok((0, 0, 0))
    }

    #[cfg(target_os = "windows")]
    fn delete_route(&self, dest: std::net::IpAddr, prefix_len: u8) -> Result<(), String> {
        use windows::Win32::Foundation::WIN32_ERROR;
        use windows::Win32::NetworkManagement::IpHelper::{
            DeleteIpForwardEntry2, MIB_IPFORWARD_ROW2,
        };

        let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        unsafe {
            windows::Win32::NetworkManagement::IpHelper::InitializeIpForwardEntry(&mut row);
        }
        row.DestinationPrefix.PrefixLength = prefix_len;
        row.InterfaceIndex = *self.interface_index.lock().map_err(|e| e.to_string())?;

        match dest {
            std::net::IpAddr::V4(v4) => {
                row.DestinationPrefix.Prefix.si_family = AF_INET;
                row.DestinationPrefix.Prefix.Ipv4.sin_addr =
                    windows::Win32::Networking::WinSock::IN_ADDR {
                        S_un: windows::Win32::Networking::WinSock::IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(v4.octets()),
                        },
                    };
            }
            std::net::IpAddr::V6(_) => return Err("IPv6 route cleanup not implemented".to_string()),
        }

        let status = unsafe { DeleteIpForwardEntry2(&row) };
        if status != WIN32_ERROR(0) {
            return Err(format!("DeleteIpForwardEntry2 failed: {}", status.0));
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn delete_route(&self, _dest: std::net::IpAddr, _prefix_len: u8) -> Result<(), String> {
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn get_primary_adapter_dns(&self) -> Result<Vec<String>, String> {
        use windows::Win32::NetworkManagement::IpHelper::{
            FreeMibTable, GetAdaptersAddresses, GetIpForwardTable2, MIB_IPFORWARD_ROW2,
            MIB_IPFORWARD_TABLE2, PIP_ADAPTER_ADDRESSES,
        };

        // Step 1: Get the primary route (0.0.0.0/0 with lowest metric)
        let mut table_ptr: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        let result = unsafe { GetIpForwardTable2(AF_INET, &mut table_ptr) };
        if result != 0 || table_ptr.is_null() {
            return Ok(Vec::new());
        }

        let (primary_if_index, primary_adapter_name) = unsafe {
            let table = &*table_ptr;
            let mut best_metric: u32 = u32::MAX;
            let mut best_index: u32 = 0;
            for i in 0..table.NumEntries {
                // Get pointer to MIB_IPFORWARD_ROW2
                let row_ptr = table.Table.add(i);
                // Read the row
                let row: MIB_IPFORWARD_ROW2 = std::ptr::read_unaligned(row_ptr);
                // Check for default route (0.0.0.0/0) - PrefixLength == 0 and IP is 0.0.0.0
                if row.DestinationPrefix.PrefixLength == 0 {
                    if row.Metric < best_metric {
                        best_metric = row.Metric;
                        best_index = row.InterfaceIndex;
                    }
                }
            }
            (best_index, String::new())
        };

        // Free the table using the correct API for MIB tables
        unsafe {
            windows::Win32::NetworkManagement::IpHelper::FreeMibTable(table_ptr);
        }

        if primary_if_index == 0 {
            return Ok(Vec::new());
        }

        // Step 2: Get DNS and adapter name from the primary adapter
        let mut buf_size: u32 = 0;
        unsafe {
            GetAdaptersAddresses(
                AF_INET,
                0x10,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut buf_size,
            );
        }

        if buf_size == 0 {
            return Ok(Vec::new());
        }

        let mut buffer = vec![0u8; buf_size as usize];
        let result = unsafe {
            GetAdaptersAddresses(
                AF_INET,
                0x10,
                std::ptr::null_mut(),
                buffer.as_mut_ptr() as *mut _,
                &mut buf_size,
            )
        };

        if result != 0 {
            return Ok(Vec::new());
        }

        let mut dns_servers = Vec::new();
        let mut primary_adapter_name_result = String::new();

        unsafe {
            let mut current = buffer.as_ptr() as PIP_ADAPTER_ADDRESSES;
            while !current.is_null() {
                let if_index = (*current).IfIndex;
                if if_index == primary_if_index {
                    // Get primary adapter name
                    if let Some(name_ptr) = (*current).FriendlyName.0.as_ref() {
                        let name_len = (0..1024)
                            .take_while(|&i| *(*current).FriendlyName.0.add(i) != 0)
                            .count();
                        let name_str = std::ffi::OsStr::from_wide(std::slice::from_raw_parts(
                            (*current).FriendlyName.0,
                            name_len,
                        ));
                        if let Ok(name) = name_str.and_then(|n| n.to_str()) {
                            primary_adapter_name_result = name.to_string();
                        }
                    }

                    // Get DNS servers
                    let mut dns_ptr = (*current).FirstDnsServerAddress;
                    while !dns_ptr.is_null() {
                        let sockaddr_ptr = (*dns_ptr).Sockaddr;
                        if !sockaddr_ptr.is_null() {
                            let family = unsafe { (*(sockaddr_ptr)).si_family };
                            if family == AF_INET.0 as u16 {
                                let addr_info = sockaddr_ptr as *const SOCKADDR_IN;
                                let addr = unsafe { (*addr_info).sin_addr.S_un.S_addr };
                                let octets = addr.to_ne_bytes();
                                dns_servers.push(format!(
                                    "{}.{}.{}.{}",
                                    octets[0], octets[1], octets[2], octets[3]
                                ));
                            }
                        }
                        dns_ptr = (**dns_ptr).Next;
                    }
                    break;
                }
                current = (*current).Next;
            }
        }

        // Store primary adapter name for later restoration
        if !primary_adapter_name_result.is_empty() {
            *self
                .primary_adapter_name
                .lock()
                .map_err(|e| e.to_string())? = Some(primary_adapter_name_result);
        }

        Ok(dns_servers)
    }

    #[cfg(target_os = "windows")]
    fn restore_primary_dns(&self) -> Result<(), String> {
        use std::process::Command;
        // Restore DNS on the primary (non-tunnel) adapter
        let primary_adapter_name = match self
            .primary_adapter_name
            .lock()
            .map_err(|e| e.to_string())?
            .as_ref()
        {
            Some(name) => name.clone(),
            None => return Ok(()), // No primary adapter saved, nothing to restore
        };

        let original_dns = self.original_dns.lock().map_err(|e| e.to_string())?.clone();

        if original_dns.is_empty() {
            // Reset to DHCP if no original DNS
            let output = Command::new("netsh")
                .args([
                    "interface",
                    "ip",
                    "set",
                    "dns",
                    &format!("name={}", primary_adapter_name),
                    "source=dhcp",
                ])
                .output()
                .map_err(|e| format!("Failed to execute netsh: {}", e))?;

            if !output.status.success() {
                tracing::warn!(
                    "netsh dns reset to DHCP failed for primary adapter: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        } else {
            // Restore original DNS servers
            let output = Command::new("netsh")
                .args([
                    "interface",
                    "ip",
                    "set",
                    "dns",
                    &format!("name={}", primary_adapter_name),
                    "source=static",
                    &format!("addr={}", original_dns[0]),
                ])
                .output()
                .map_err(|e| format!("Failed to execute netsh: {}", e))?;

            if !output.status.success() {
                tracing::warn!(
                    "netsh dns restore failed for primary adapter: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            for server in original_dns.iter().skip(1) {
                let output = Command::new("netsh")
                    .args([
                        "interface",
                        "ip",
                        "add",
                        "dns",
                        &format!("name={}", primary_adapter_name),
                        &format!("addr={}", server),
                        "register=primary",
                    ])
                    .output()
                    .map_err(|e| format!("Failed to execute netsh: {}", e))?;

                if !output.status.success() {
                    tracing::warn!(
                        "netsh dns add failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn get_current_dns(&self) -> Result<Vec<String>, String> {
        use windows::Win32::NetworkManagement::IpHelper::{
            GetAdaptersAddresses, PIP_ADAPTER_ADDRESSES,
        };

        let mut buf_size: u32 = 0;
        unsafe {
            GetAdaptersAddresses(
                AF_INET, // Pass ADDRESS_FAMILY directly
                0x10,    // GAA_FLAG_INCLUDE_PREFIX
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut buf_size,
            );
        }

        if buf_size == 0 {
            return Ok(Vec::new());
        }

        let mut buffer = vec![0u8; buf_size as usize];
        let result = unsafe {
            GetAdaptersAddresses(
                AF_INET, // Pass ADDRESS_FAMILY directly
                0x10,    // GAA_FLAG_INCLUDE_PREFIX
                std::ptr::null_mut(),
                buffer.as_mut_ptr() as *mut _,
                &mut buf_size,
            )
        };

        if result != 0 {
            return Ok(Vec::new());
        }

        let mut dns_servers = Vec::new();

        unsafe {
            let mut current = buffer.as_ptr() as PIP_ADAPTER_ADDRESSES;
            while !current.is_null() {
                let friendly_name = (*current).FriendlyName;
                if !friendly_name.is_null() {
                    let name_str = std::ffi::OsStr::from_wide(std::slice::from_raw_parts(
                        friendly_name.0,
                        (0..1024)
                            .take_while(|&i| *(*current).FriendlyName.0.add(i) != 0)
                            .count(),
                    ));

                    // Get DNS for the tunnel adapter
                    if let Ok(name) = name_str.and_then(|n| n.to_str()) {
                        if name.contains(&self.adapter_name) {
                            // Read DNS from adapter
                            let mut dns_ptr = (*current).FirstDnsServerAddress;
                            while !dns_ptr.is_null() {
                                // Get sockaddr - need to read through the pointer
                                let sockaddr_ptr = (*dns_ptr).Sockaddr;
                                if !sockaddr_ptr.is_null() {
                                    // Check family before casting - only IPv4 supported
                                    let family = unsafe { (*(sockaddr_ptr)).si_family };
                                    if family == AF_INET.0 as u16 {
                                        let addr_info = sockaddr_ptr as *const SOCKADDR_IN;
                                        let addr = unsafe { (*addr_info).sin_addr.S_un.S_addr };
                                        let octets = addr.to_ne_bytes();
                                        let ip_str = format!(
                                            "{}.{}.{}.{}",
                                            octets[0], octets[1], octets[2], octets[3]
                                        );
                                        dns_servers.push(ip_str);
                                    }
                                }
                                dns_ptr = (**dns_ptr).Next;
                            }
                        }
                    }
                }
                current = (*current).Next;
            }
        }

        Ok(dns_servers)
    }

    #[cfg(target_os = "windows")]
    fn set_dns(&self, servers: &[String]) -> Result<(), String> {
        use std::process::Command;
        // Use netsh to set DNS on the tunnel adapter
        let adapter_name = &self.adapter_name;

        if servers.is_empty() {
            return Ok(());
        }

        // First DNS server: set (replaces)
        let output = Command::new("netsh")
            .args([
                "interface",
                "ip",
                "set",
                "dns",
                "name=",
                adapter_name,
                "source=static",
                "addr=",
                &servers[0],
            ])
            .output()
            .map_err(|e| format!("Failed to execute netsh: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "netsh set dns failed for {}: {}",
                servers[0],
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Subsequent DNS servers: add (appends)
        for server in servers.iter().skip(1) {
            let output = Command::new("netsh")
                .args([
                    "interface",
                    "ip",
                    "add",
                    "dns",
                    "name=",
                    adapter_name,
                    "addr=",
                    server,
                    "register=primary",
                ])
                .output()
                .map_err(|e| format!("Failed to execute netsh add dns: {}", e))?;

            if !output.status.success() {
                return Err(format!(
                    "netsh add dns failed for {}: {}",
                    server,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn restore_dns(&self, servers: &[String]) -> Result<(), String> {
        use std::process::Command;
        // Restore original DNS or reset to DHCP
        let adapter_name = &self.adapter_name;
        if servers.is_empty() {
            // No original DNS - reset to DHCP
            let output = Command::new("netsh")
                .args([
                    "interface",
                    "ip",
                    "set",
                    "dns",
                    "name=",
                    adapter_name,
                    "source=dhcp",
                ])
                .output()
                .map_err(|e| format!("Failed to execute netsh: {}", e))?;

            if !output.status.success() {
                tracing::warn!(
                    "netsh dns reset to DHCP failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        } else {
            // Restore original DNS servers
            for server in servers {
                let output = Command::new("netsh")
                    .args([
                        "interface",
                        "ip",
                        "set",
                        "dnsservers",
                        "name=",
                        adapter_name,
                        "addr=",
                        server,
                        "register=primary",
                    ])
                    .output()
                    .map_err(|e| format!("Failed to execute netsh: {}", e))?;

                if !output.status.success() {
                    tracing::warn!(
                        "netsh dns restore failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn reset_adapter_dns(&self) -> Result<(), String> {
        use std::process::Command;
        // Reset tunnel adapter DNS to DHCP
        // This is tolerant - if adapter doesn't exist, just log and return Ok
        let adapter_name = &self.adapter_name;
        let output = Command::new("netsh")
            .args([
                "interface",
                "ip",
                "set",
                "dns",
                "name=",
                adapter_name,
                "source=dhcp",
            ])
            .output()
            .map_err(|e| format!("Failed to execute netsh: {}", e))?;

        if !output.status.success() {
            // Adapter may not exist yet or other error - just log
            tracing::warn!(
                "netsh dns reset to DHCP failed (tolerant): {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn reset_adapter_dns(&self) -> Result<(), String> {
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn get_current_dns(&self) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }

    #[cfg(not(target_os = "windows"))]
    fn set_dns(&self, _servers: &[String]) -> Result<(), String> {
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn restore_dns(&self, _servers: &[String]) -> Result<(), String> {
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn restore_primary_dns(&self) -> Result<(), String> {
        Ok(())
    }

    pub fn elapsed(&self) -> Option<Duration> {
        self.connect_time.map(|t| t.elapsed())
    }
}
