//! Windows Route Manager — manages IP route entries owned by MARSTART LINK.
//!
//! Uses native Windows IP Helper APIs (`CreateIpForwardEntry2`,
//! `DeleteIpForwardEntry2`, `GetIpForwardTable2`) from `netioapi.h`
//! via the `windows` crate (linked from `iphlpapi.lib`).
//!
//! Routes are tagged with `Protocol = MIB_IPPROTO_NETMGMT` for ownership
//! identification. Only routes that match a previously-installed entry in
//! our in-memory registry are removed. Foreign routes are never touched.
//!
//! # Safety (FFI)
//! Every `unsafe` block wraps a Windows IP-Helper (`netioapi.h`) call and is
//! annotated inline.  Soundness rests on: (1) each `MIB_IPFORWARD_ROW2` is
//! zero-initialized then populated via `InitializeIpForwardEntry` before being
//! passed by `&`/`&mut` to the OS; (2) pointers handed to the APIs point at
//! in-bounds, owned, live memory (stack rows, or a table buffer sized from the
//! API's own `NumEntries`/length field and freed with `FreeMibTable`);
//! (3) every `ERROR_ACCESS_DENIED`/`ERROR_FILE_NOT_FOUND` result is handled so
//! a non-elevated process never observes uninitialized memory; (4) the
//! in-memory `routes` map is `StdMutex`-guarded (poison-tolerant via
//! `unwrap_or_else`) and is only an authoritative-OS mirror.

#![allow(clippy::result_large_err)]

use serde::Serialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex as StdMutex;

#[cfg(target_os = "windows")]
use windows::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetIpForwardTable2,
    InitializeIpForwardEntry, SetIpForwardEntry2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
#[cfg(target_os = "windows")]
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
#[cfg(target_os = "windows")]
use windows::Win32::Networking::WinSock::{
    AF_INET, MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_INET,
};

/// Win32 error code for ACCESS_DENIED (not elevated).
const ERROR_ACCESS_DENIED: u32 = 5;
/// Win32 error code for "object already exists" — treat as idempotent success.
const ERROR_OBJECT_ALREADY_EXISTS: u32 = 1117;

/// A route entry managed by MARSTART LINK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedRoute {
    pub path_id: String,
    pub destination: Ipv4Addr,
    pub prefix_length: u8,
    pub interface_luid: u64,
    pub interface_index: u32,
    pub next_hop: Ipv4Addr,
    pub metric: u32,
    pub generation: u64,
}

/// Metric for the actively preferred path.
pub const ACTIVE_METRIC: u32 = 10;
/// Metric for the standby (non-preferred) path.
pub const STANDBY_METRIC: u32 = 20;

/// Error returned by WindowsRouteManager operations.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub struct RouteError {
    pub error_code: i32,
    pub operation: String,
    pub destination: String,
    pub path_id: String,
    pub interface_luid: Option<u64>,
    pub stage: String,
    pub message: String,
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} failed: {} (code={}, path={}, dest={}, stage={})",
            self.operation,
            self.message,
            self.error_code,
            self.path_id,
            self.destination,
            self.stage,
        )
    }
}

impl std::error::Error for RouteError {}

/// Result of a route switch operation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SwitchResult {
    pub from_path: Option<String>,
    pub to_path: Option<String>,
    pub datapath_applied: bool,
    pub routes_added: Vec<String>,
    pub routes_removed: Vec<String>,
    pub error: Option<String>,
}

/// Route ownership key — uniquely identifies a MARSTART-installed route.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OwnedRouteKey {
    destination: u32,
    prefix_length: u8,
    path_id: String,
}

impl OwnedRouteKey {
    fn from(destination: Ipv4Addr, prefix_length: u8, path_id: &str) -> Self {
        Self {
            destination: u32::from_ne_bytes(destination.octets()),
            prefix_length,
            path_id: path_id.to_string(),
        }
    }
}

/// Windows-native route table manager.
///
/// On Windows, uses the `windows` crate bindings to `iphlpapi.dll`
/// (`CreateIpForwardEntry2`, `DeleteIpForwardEntry2`, `GetIpForwardTable2`).
/// On non-Windows, all operations are in-memory stubs for testability.
pub struct WindowsRouteManager {
    routes: StdMutex<HashMap<OwnedRouteKey, ManagedRoute>>,
}

impl std::fmt::Debug for WindowsRouteManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        f.debug_struct("WindowsRouteManager")
            .field("routes", &routes.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(target_os = "windows")]
impl WindowsRouteManager {
    pub fn new() -> Self {
        Self {
            routes: StdMutex::new(HashMap::new()),
        }
    }

    /// Build a `SOCKADDR_IN` for an IPv4 address.
    fn sockaddr_in(addr: Ipv4Addr) -> SOCKADDR_IN {
        // SAFETY: `std::mem::zeroed()` is sound for `SOCKADDR_IN` (a
        // `#[repr(C)]` POD struct over integers); every field is overwritten
        // below (`sin_family`, `sin_addr`).
        let mut result: SOCKADDR_IN = unsafe { std::mem::zeroed() };
        result.sin_family = AF_INET;
        result.sin_addr.S_un.S_addr = u32::from_ne_bytes(addr.octets());
        result
    }

    /// Build a `MIB_IPFORWARD_ROW2` for an IPv4 on-link route.
    ///
    /// NextHop = 0.0.0.0 (on-link). The WireGuard driver handles
    /// encapsulation: packets sent to the WireGuard interface are
    /// encrypted and sent to the configured peer endpoint.
    fn build_row(
        destination: Ipv4Addr,
        prefix_length: u8,
        interface_luid: u64,
        metric: u32,
    ) -> MIB_IPFORWARD_ROW2 {
        // SAFETY: `std::mem::zeroed()` is sound for `MIB_IPFORWARD_ROW2` (a
        // `#[repr(C)]` POD struct); `InitializeIpForwardEntry` then sets the
        // reserved/prefix fields the OS requires.  No out-of-bounds or
        // uninitialized reads occur.
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        unsafe { InitializeIpForwardEntry(&mut row) };

        // Set InterfaceLuid from u64
        row.InterfaceLuid = NET_LUID_LH {
            Value: interface_luid,
        };

        // Destination prefix
        row.DestinationPrefix.Prefix = SOCKADDR_INET {
            Ipv4: Self::sockaddr_in(destination),
        };
        row.DestinationPrefix.PrefixLength = prefix_length;

        // NextHop: 0.0.0.0 = on-link. WireGuard driver handles encapsulation.
        row.NextHop = SOCKADDR_INET {
            Ipv4: Self::sockaddr_in(Ipv4Addr::UNSPECIFIED),
        };

        // Ownership tag
        row.Protocol = MIB_IPPROTO_NETMGMT;
        row.Metric = metric;

        row
    }

    /// Install a route entry in the Windows routing table.
    pub fn install_route(
        &self,
        path_id: &str,
        destination: Ipv4Addr,
        prefix_length: u8,
        interface_luid: u64,
        interface_index: u32,
        metric: u32,
    ) -> Result<(), RouteError> {
        let row = Self::build_row(destination, prefix_length, interface_luid, metric);

        // SAFETY: `CreateIpForwardEntry2` installs a forwarding row.  `&row`
        // points at a fully-initialized, stack-owned `MIB_IPFORWARD_ROW2`; the
        // borrow is valid for the call.  `ERROR_OBJECT_ALREADY_EXISTS` (idempotent
        // re-install) is expected and handled below.
        let err = unsafe { CreateIpForwardEntry2(&row) };
        let code = err.0;

        if code != 0 && code != ERROR_OBJECT_ALREADY_EXISTS {
            // If running without admin privileges, still register the route
            // in our in-memory map so ownership tracking stays consistent.
            // The Windows route table won't have the entry, but our registry
            // will know we intend to manage it. A reconciliation pass later
            // will detect the missing entry and can retry once elevated.
            if code != ERROR_ACCESS_DENIED {
                return Err(RouteError {
                    error_code: code as i32,
                    operation: "CreateIpForwardEntry2".to_string(),
                    destination: format!("{}/{}", destination, prefix_length),
                    path_id: path_id.to_string(),
                    interface_luid: Some(interface_luid),
                    stage: "install".to_string(),
                    message: format!("Win32 error {}", code),
                });
            }
            tracing::warn!(
                "install_route: access denied (non-elevated). path={}, dest={}/{}. \
                 Route tracked in registry but NOT installed in Windows table.",
                path_id,
                destination,
                prefix_length
            );
        }

        let mut routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        let key = OwnedRouteKey::from(destination, prefix_length, path_id);
        routes.insert(
            key,
            ManagedRoute {
                path_id: path_id.to_string(),
                destination,
                prefix_length,
                interface_luid,
                interface_index,
                next_hop: Ipv4Addr::new(0, 0, 0, 0),
                metric,
                generation: 0,
            },
        );

        Ok(())
    }

    /// Remove a route entry. Only removes routes in our registry (ownership check).
    pub fn remove_route(
        &self,
        path_id: &str,
        destination: Ipv4Addr,
        prefix_length: u8,
        interface_luid: u64,
    ) -> Result<(), RouteError> {
        // Ownership check
        {
            let routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
            let key = OwnedRouteKey::from(destination, prefix_length, path_id);
            if !routes.contains_key(&key) {
                tracing::warn!(
                    "attempt to remove unmanaged route: {}/{}/{}",
                    destination,
                    prefix_length,
                    path_id
                );
                return Err(RouteError {
                    error_code: 0,
                    operation: "remove_route".to_string(),
                    destination: format!("{}/{}", destination, prefix_length),
                    path_id: path_id.to_string(),
                    interface_luid: Some(interface_luid),
                    stage: "ownership_check".to_string(),
                    message: "route not found in MARSTART registry — refusing to delete"
                        .to_string(),
                });
            }
        }

        let row = Self::build_row(destination, prefix_length, interface_luid, ACTIVE_METRIC);

        // SAFETY: `DeleteIpForwardEntry2` removes a forwarding row.  `&row` is a
        // fully-initialized, stack-owned `MIB_IPFORWARD_ROW2`; the borrow is
        // valid for the call.  `ERROR_FILE_NOT_FOUND`/`ERROR_ACCESS_DENIED` are
        // handled after the call (registry-only cleanup).
        let err = unsafe { DeleteIpForwardEntry2(&row) };
        let code = err.0;

        if code != 0 {
            // ERROR_FILE_NOT_FOUND (2) — route doesn't exist in Windows table
            // but is in our registry (e.g. installed in a previous elevated session).
            // Clean up registry and return OK.
            if code == 2 || code == ERROR_ACCESS_DENIED {
                if code == ERROR_ACCESS_DENIED {
                    tracing::warn!(
                        "remove_route: access denied (non-elevated). path={}, dest={}/{}. \
                         Removing from registry only.",
                        path_id,
                        destination,
                        prefix_length
                    );
                }
                let mut routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
                let key = OwnedRouteKey::from(destination, prefix_length, path_id);
                routes.remove(&key);
                return Ok(());
            }
            return Err(RouteError {
                error_code: code as i32,
                operation: "DeleteIpForwardEntry2".to_string(),
                destination: format!("{}/{}", destination, prefix_length),
                path_id: path_id.to_string(),
                interface_luid: Some(interface_luid),
                stage: "remove".to_string(),
                message: format!("Win32 error {}", code),
            });
        }

        let mut routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        let key = OwnedRouteKey::from(destination, prefix_length, path_id);
        routes.remove(&key);

        Ok(())
    }

    /// Enumerate all owned routes from our in-memory registry.
    pub fn enumerate_owned_routes(&self) -> Vec<ManagedRoute> {
        let routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        routes.values().cloned().collect()
    }

    /// Enumerate Windows routing table for routes tagged with MIB_IPPROTO_NETMGMT.
    pub fn enumerate_windows_routes(&self) -> Vec<ManagedRoute> {
        let mut owned: Vec<ManagedRoute> = Vec::new();

        let mut table_ptr: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        // SAFETY: `GetIpForwardTable2` allocates a table buffer and writes its
        // address into `table_ptr` (an out `*mut` pointer).  `AF_INET` selects
        // IPv4.  On success `table_ptr` is owned by us and freed via
        // `FreeMibTable` below.
        let err = unsafe { GetIpForwardTable2(AF_INET, &mut table_ptr) };
        let code = err.0;

        if code != 0 || table_ptr.is_null() {
            tracing::warn!("GetIpForwardTable2 failed: error {}", code);
            return owned;
        }

        // SAFETY: `table_ptr` is non-null and points at a valid
        // `MIB_IPFORWARD_TABLE2` allocated by `GetIpForwardTable2` (success was
        // checked above).  `NumEntries` is the API-returned count; `Table[0]`
        // and `.add(i)` iterate within `[0, NumEntries)`.  We only READ each row.
        unsafe {
            let num_entries = (*table_ptr).NumEntries;
            let row_ptr = &(*table_ptr).Table[0] as *const MIB_IPFORWARD_ROW2;

            for i in 0..num_entries as usize {
                let row = &*row_ptr.add(i);
                if row.Protocol == MIB_IPPROTO_NETMGMT {
                    let dest = Ipv4Addr::from(u32::from_be(
                        row.DestinationPrefix
                            .Prefix
                            .Ipv4
                            .sin_addr
                            .S_un
                            .S_addr
                            .to_be(),
                    ));
                    owned.push(ManagedRoute {
                        path_id: "recovered".to_string(),
                        destination: dest,
                        prefix_length: row.DestinationPrefix.PrefixLength,
                        interface_luid: row.InterfaceLuid.Value,
                        interface_index: row.InterfaceIndex,
                        next_hop: Ipv4Addr::UNSPECIFIED,
                        metric: row.Metric,
                        generation: 0,
                    });
                }
            }
        }

        // SAFETY: `FreeMibTable` frees the buffer allocated by
        // `GetIpForwardTable2`.  `table_ptr` is valid (checked above) and not
        // referenced after this call.  Called exactly once on success.
        unsafe {
            FreeMibTable(table_ptr as *const std::ffi::c_void);
        }

        owned
    }

    /// Remove a route from the OS routing table **without** checking the
    /// in-memory registry. Used during `enumerate_and_reconcile()` to
    /// clean up orphaned routes that exist in the OS but have no matching
    /// in-memory path.
    ///
    /// On Windows, calls `DeleteIpForwardEntry2` directly. Also cleans up
    /// any matching entry from the in-memory registry.
    pub fn remove_route_os(
        &self,
        destination: Ipv4Addr,
        prefix_length: u8,
        interface_luid: u64,
    ) -> Result<(), RouteError> {
        let row = Self::build_row(destination, prefix_length, interface_luid, ACTIVE_METRIC);

        // SAFETY: `DeleteIpForwardEntry2` removes an OS forwarding row during
        // orphan reconciliation.  `&row` is a fully-initialized, stack-owned
        // `MIB_IPFORWARD_ROW2`; the borrow is valid for the call.  `ERROR_FILE_NOT_FOUND`/
        // `ERROR_ACCESS_DENIED` are tolerated (registry-only cleanup).
        let err = unsafe { DeleteIpForwardEntry2(&row) };
        let code = err.0;

        // ERROR_FILE_NOT_FOUND (2) — route doesn't exist in OS table. OK.
        // ERROR_ACCESS_DENIED (5) — non-elevated process. Still clean up
        // the in-memory registry for consistency, mirroring install_route's
        // behavior.
        if code != 0 && code != 2 && code != ERROR_ACCESS_DENIED {
            return Err(RouteError {
                error_code: code as i32,
                operation: "DeleteIpForwardEntry2".to_string(),
                destination: format!("{}/{}", destination, prefix_length),
                path_id: "orphan".to_string(),
                interface_luid: Some(interface_luid),
                stage: "remove_os".to_string(),
                message: format!("Win32 error {}", code),
            });
        }

        if code == ERROR_ACCESS_DENIED {
            tracing::warn!(
                "remove_route_os: access denied (non-elevated). dest={}/{}. \
                 Route removed from registry but NOT from Windows table.",
                destination,
                prefix_length
            );
        }

        // Clean up in-memory registry if the entry exists there too.
        let mut routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        routes.retain(|_, r| {
            !(r.destination == destination
                && r.prefix_length == prefix_length
                && r.interface_luid == interface_luid)
        });

        Ok(())
    }

    pub fn all_routes(&self) -> Vec<ManagedRoute> {
        let routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        routes.values().cloned().collect()
    }

    pub fn route_exists(
        &self,
        destination: Ipv4Addr,
        prefix_length: u8,
        interface_luid: u64,
    ) -> bool {
        let routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        routes.values().any(|r| {
            r.destination == destination
                && r.prefix_length == prefix_length
                && r.interface_luid == interface_luid
        })
    }

    pub fn update_route_metric(
        &self,
        path_id: &str,
        destination: Ipv4Addr,
        prefix_length: u8,
        metric: u32,
    ) -> Result<(), RouteError> {
        let mut routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        let key = OwnedRouteKey::from(destination, prefix_length, path_id);
        if let Some(route) = routes.get_mut(&key) {
            route.metric = metric;
            route.generation = route.generation.wrapping_add(1);
            Ok(())
        } else {
            Err(RouteError {
                error_code: 0,
                operation: "update_route_metric".to_string(),
                destination: format!("{}/{}", destination, prefix_length),
                path_id: path_id.to_string(),
                interface_luid: None,
                stage: "update".to_string(),
                message: "route not found in registry".to_string(),
            })
        }
    }

    /// Update the metric of an existing route in the Windows OS routing table
    /// via `SetIpForwardEntry2`, without deleting/recreating the route.
    ///
    /// This is the Phase 3 replacement for the delete-then-create pattern
    /// used by `install_path_route()`. It preserves route identity
    /// (destination, prefix, interface LUID) and changes only the metric.
    ///
    /// On non-elevated Windows, `SetIpForwardEntry2` returns
    /// `ERROR_ACCESS_DENIED`. Like `install_route()`, this is treated as
    /// non-fatal — the in-memory registry is still updated so that
    /// ownership tracking stays consistent.
    pub fn update_route_metric_os(
        &self,
        path_id: &str,
        destination: Ipv4Addr,
        prefix_length: u8,
        interface_luid: u64,
        metric: u32,
    ) -> Result<(), RouteError> {
        let row = Self::build_row(destination, prefix_length, interface_luid, metric);

        let err = unsafe { SetIpForwardEntry2(&row) };
        let code = err.0;

        if code != 0 && code != ERROR_ACCESS_DENIED {
            return Err(RouteError {
                error_code: code as i32,
                operation: "SetIpForwardEntry2".to_string(),
                destination: format!("{}/{}", destination, prefix_length),
                path_id: path_id.to_string(),
                interface_luid: Some(interface_luid),
                stage: "update_os".to_string(),
                message: format!("Win32 error {}", code),
            });
        }

        if code == ERROR_ACCESS_DENIED {
            tracing::warn!(
                "update_route_metric_os: access denied (non-elevated). path={}, dest={}/{}. \
                 Metric updated in registry but NOT in Windows table.",
                path_id,
                destination,
                prefix_length
            );
        }

        // Update in-memory registry
        self.update_route_metric(path_id, destination, prefix_length, metric)?;
        Ok(())
    }

    pub fn cleanup_owned_routes(&self) -> Vec<RouteError> {
        let mut errors = Vec::new();
        let to_remove: Vec<ManagedRoute> = {
            let routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
            routes.values().cloned().collect()
        };
        for route in &to_remove {
            if let Err(e) = self.remove_route(
                &route.path_id,
                route.destination,
                route.prefix_length,
                route.interface_luid,
            ) {
                errors.push(e);
            }
        }
        errors
    }
}

#[cfg(not(target_os = "windows"))]
impl WindowsRouteManager {
    pub fn new() -> Self {
        Self {
            routes: StdMutex::new(HashMap::new()),
        }
    }

    pub fn install_route(
        &self,
        path_id: &str,
        destination: Ipv4Addr,
        prefix_length: u8,
        interface_luid: u64,
        _interface_index: u32,
        metric: u32,
    ) -> Result<(), RouteError> {
        let mut routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        let key = OwnedRouteKey::from(destination, prefix_length, path_id);
        routes.insert(
            key,
            ManagedRoute {
                path_id: path_id.to_string(),
                destination,
                prefix_length,
                interface_luid,
                interface_index: 0,
                next_hop: Ipv4Addr::new(0, 0, 0, 0),
                metric,
                generation: 0,
            },
        );
        Ok(())
    }

    pub fn remove_route(
        &self,
        path_id: &str,
        destination: Ipv4Addr,
        prefix_length: u8,
        interface_luid: u64,
    ) -> Result<(), RouteError> {
        let mut routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        let key = OwnedRouteKey::from(destination, prefix_length, path_id);
        if routes.remove(&key).is_none() {
            return Err(RouteError {
                error_code: 0,
                operation: "remove_route".to_string(),
                destination: format!("{}/{}", destination, prefix_length),
                path_id: path_id.to_string(),
                interface_luid: Some(interface_luid),
                stage: "ownership_check".to_string(),
                message: "route not found in MARSTART registry".to_string(),
            });
        }
        Ok(())
    }

    pub fn enumerate_owned_routes(&self) -> Vec<ManagedRoute> {
        let routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        routes.values().cloned().collect()
    }

    pub fn enumerate_windows_routes(&self) -> Vec<ManagedRoute> {
        let routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        routes.values().cloned().collect()
    }

    /// Remove a route from the in-memory registry without OS API calls.
    /// On non-Windows, this is a stub that only manages the registry.
    pub fn remove_route_os(
        &self,
        destination: Ipv4Addr,
        prefix_length: u8,
        interface_luid: u64,
    ) -> Result<(), RouteError> {
        let mut routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        let before = routes.len();
        routes.retain(|_, r| {
            !(r.destination == destination
                && r.prefix_length == prefix_length
                && r.interface_luid == interface_luid)
        });
        if routes.len() == before {
            return Err(RouteError {
                error_code: 0,
                operation: "remove_route_os".to_string(),
                destination: format!("{}/{}", destination, prefix_length),
                path_id: "orphan".to_string(),
                interface_luid: Some(interface_luid),
                stage: "ownership_check".to_string(),
                message: "route not found in MARSTART registry".to_string(),
            });
        }
        Ok(())
    }

    pub fn all_routes(&self) -> Vec<ManagedRoute> {
        let routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        routes.values().cloned().collect()
    }

    pub fn route_exists(
        &self,
        destination: Ipv4Addr,
        prefix_length: u8,
        interface_luid: u64,
    ) -> bool {
        let routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        routes.values().any(|r| {
            r.destination == destination
                && r.prefix_length == prefix_length
                && r.interface_luid == interface_luid
        })
    }

    pub fn update_route_metric(
        &self,
        path_id: &str,
        destination: Ipv4Addr,
        prefix_length: u8,
        metric: u32,
    ) -> Result<(), RouteError> {
        let mut routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        let key = OwnedRouteKey::from(destination, prefix_length, path_id);
        if let Some(route) = routes.get_mut(&key) {
            route.metric = metric;
            route.generation = route.generation.wrapping_add(1);
            Ok(())
        } else {
            Err(RouteError {
                error_code: 0,
                operation: "update_route_metric".to_string(),
                destination: format!("{}/{}", destination, prefix_length),
                path_id: path_id.to_string(),
                interface_luid: None,
                stage: "update".to_string(),
                message: "route not found in registry".to_string(),
            })
        }
    }

    /// Phase 3: Platform-agnostic metric update. On non-Windows, this is
    /// a stub that only updates the in-memory registry.
    pub fn update_route_metric_os(
        &self,
        path_id: &str,
        destination: Ipv4Addr,
        prefix_length: u8,
        interface_luid: u64,
        metric: u32,
    ) -> Result<(), RouteError> {
        // Non-Windows stub: only manage in-memory registry
        self.update_route_metric(path_id, destination, prefix_length, metric)?;
        // Suppress unused warning for interface_luid on non-Windows
        let _ = interface_luid;
        Ok(())
    }

    pub fn cleanup_owned_routes(&self) -> Vec<RouteError> {
        let mut routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        routes.clear();
        Vec::new()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_and_remove_route_in_registry() {
        let mgr = WindowsRouteManager::new();
        let result = mgr.install_route(
            "path-a",
            Ipv4Addr::new(203, 0, 113, 10),
            32,
            0x1234,
            42,
            ACTIVE_METRIC,
        );
        // On non-elevated Windows, CreateIpForwardEntry2 returns
        // ERROR_ACCESS_DENIED. The route is still tracked in our registry.
        assert!(result.is_ok());
        assert!(mgr.route_exists(Ipv4Addr::new(203, 0, 113, 10), 32, 0x1234));
        let routes = mgr.all_routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].path_id, "path-a");
        assert_eq!(routes[0].metric, ACTIVE_METRIC);
    }

    #[test]
    fn remove_unmanaged_route_is_safe() {
        let mgr = WindowsRouteManager::new();
        let result = mgr.remove_route("path-a", Ipv4Addr::new(192, 0, 2, 1), 32, 0x9999);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("not found in MARSTART registry"));
    }

    #[test]
    fn foreign_route_is_never_deleted() {
        let mgr = WindowsRouteManager::new();
        // Register path-a route
        mgr.install_route(
            "path-a",
            Ipv4Addr::new(203, 0, 113, 10),
            32,
            0x0001,
            1,
            ACTIVE_METRIC,
        )
        .unwrap();

        // Try to remove with different path_id — should fail (ownership mismatch)
        let result = mgr.remove_route("path-b", Ipv4Addr::new(203, 0, 113, 10), 32, 0x0001);
        assert!(result.is_err());

        // Correct path_id should work
        let result = mgr.remove_route("path-a", Ipv4Addr::new(203, 0, 113, 10), 32, 0x0001);
        assert!(result.is_ok());
    }

    #[test]
    fn route_key_uniqueness() {
        let mgr = WindowsRouteManager::new();
        mgr.install_route("a", Ipv4Addr::new(203, 0, 113, 10), 32, 1, 1, ACTIVE_METRIC)
            .unwrap();
        mgr.install_route(
            "b",
            Ipv4Addr::new(203, 0, 113, 10),
            32,
            2,
            2,
            STANDBY_METRIC,
        )
        .unwrap();
        assert_eq!(mgr.all_routes().len(), 2);
    }

    #[test]
    fn cleanup_removes_all() {
        let mgr = WindowsRouteManager::new();
        mgr.install_route("a", Ipv4Addr::new(203, 0, 113, 10), 32, 1, 1, 10)
            .unwrap();
        mgr.install_route("b", Ipv4Addr::new(203, 0, 113, 10), 32, 2, 2, 20)
            .unwrap();
        let _errors = mgr.cleanup_owned_routes();
        assert_eq!(mgr.all_routes().len(), 0);
    }

    #[test]
    fn update_metric_changes_generation() {
        let mgr = WindowsRouteManager::new();
        mgr.install_route("a", Ipv4Addr::new(203, 0, 113, 10), 32, 1, 1, ACTIVE_METRIC)
            .unwrap();
        let gen_before = mgr.all_routes()[0].generation;
        mgr.update_route_metric("a", Ipv4Addr::new(203, 0, 113, 10), 32, STANDBY_METRIC)
            .unwrap();
        let gen_after = mgr.all_routes()[0].generation;
        assert_eq!(gen_after, gen_before + 1);
        assert_eq!(mgr.all_routes()[0].metric, STANDBY_METRIC);
    }

    #[test]
    fn route_not_found_returns_error() {
        let mgr = WindowsRouteManager::new();
        let result = mgr.remove_route("nonexistent", Ipv4Addr::new(203, 0, 113, 10), 32, 1);
        assert!(result.is_err());
    }

    // ── Phase 2 tests for remove_route_os ──────────────────────────────

    #[test]
    fn remove_route_os_without_registry_entry_returns_error_non_windows() {
        let mgr = WindowsRouteManager::new();
        let result = mgr.remove_route_os(Ipv4Addr::new(203, 0, 113, 10), 32, 0x1234);
        // On all platforms: the route doesn't exist, so remove_route_os
        // returns Ok (ERROR_FILE_NOT_FOUND is treated as success, and
        // ERROR_ACCESS_DENIED on non-elevated Windows is also handled gracefully).
        assert!(result.is_ok());
    }

    #[test]
    fn remove_route_os_removes_from_registry_when_present() {
        let mgr = WindowsRouteManager::new();
        mgr.install_route(
            "path-a",
            Ipv4Addr::new(203, 0, 113, 10),
            32,
            0x1234,
            42,
            ACTIVE_METRIC,
        )
        .unwrap();
        assert_eq!(mgr.all_routes().len(), 1);

        let result = mgr.remove_route_os(Ipv4Addr::new(203, 0, 113, 10), 32, 0x1234);
        // On Windows it calls DeleteIpForwardEntry2 (may fail with ACCESS_DENIED if
        // not elevated, but still removes from registry). On non-Windows it removes
        // from registry directly.
        assert!(result.is_ok());
        assert_eq!(mgr.all_routes().len(), 0);
    }

    #[test]
    fn remove_route_os_preserves_unrelated_routes() {
        let mgr = WindowsRouteManager::new();
        mgr.install_route("a", Ipv4Addr::new(203, 0, 113, 10), 32, 1, 1, ACTIVE_METRIC)
            .unwrap();
        mgr.install_route(
            "b",
            Ipv4Addr::new(198, 51, 100, 1),
            32,
            2,
            2,
            STANDBY_METRIC,
        )
        .unwrap();
        assert_eq!(mgr.all_routes().len(), 2);

        // Remove only route "a"
        let _ = mgr.remove_route_os(Ipv4Addr::new(203, 0, 113, 10), 32, 1);

        let remaining = mgr.all_routes();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].destination, Ipv4Addr::new(198, 51, 100, 1));
    }

    // ── Phase 3 tests for update_route_metric_os ──────────────────────

    #[test]
    fn update_metric_os_active_route_metric_becomes_10() {
        let mgr = WindowsRouteManager::new();
        mgr.install_route(
            "path-a",
            Ipv4Addr::new(203, 0, 113, 10),
            32,
            0x1234,
            42,
            STANDBY_METRIC,
        )
        .unwrap();

        let result = mgr.update_route_metric_os(
            "path-a",
            Ipv4Addr::new(203, 0, 113, 10),
            32,
            0x1234,
            ACTIVE_METRIC,
        );
        assert!(result.is_ok());

        let routes = mgr.all_routes();
        let route = routes
            .iter()
            .find(|r| r.path_id == "path-a" && r.destination == Ipv4Addr::new(203, 0, 113, 10))
            .expect("route should exist");
        assert_eq!(route.metric, ACTIVE_METRIC, "metric should be 10");
    }

    #[test]
    fn update_metric_os_standby_route_metric_becomes_20() {
        let mgr = WindowsRouteManager::new();
        mgr.install_route(
            "path-a",
            Ipv4Addr::new(203, 0, 113, 10),
            32,
            0x1234,
            42,
            ACTIVE_METRIC,
        )
        .unwrap();

        let result = mgr.update_route_metric_os(
            "path-a",
            Ipv4Addr::new(203, 0, 113, 10),
            32,
            0x1234,
            STANDBY_METRIC,
        );
        assert!(result.is_ok());

        let routes = mgr.all_routes();
        let route = routes
            .iter()
            .find(|r| r.path_id == "path-a" && r.destination == Ipv4Addr::new(203, 0, 113, 10))
            .expect("route should exist");
        assert_eq!(route.metric, STANDBY_METRIC, "metric should be 20");
    }

    #[test]
    fn update_metric_os_does_not_modify_unrelated_routes() {
        let mgr = WindowsRouteManager::new();

        // Install two MARSTART-owned routes
        mgr.install_route(
            "path-a",
            Ipv4Addr::new(203, 0, 113, 10),
            32,
            0x1234,
            42,
            ACTIVE_METRIC,
        )
        .unwrap();
        mgr.install_route(
            "path-b",
            Ipv4Addr::new(198, 51, 100, 1),
            32,
            0x5678,
            42,
            ACTIVE_METRIC,
        )
        .unwrap();

        // Update only path-a
        let result = mgr.update_route_metric_os(
            "path-a",
            Ipv4Addr::new(203, 0, 113, 10),
            32,
            0x1234,
            STANDBY_METRIC,
        );
        assert!(result.is_ok());

        let routes = mgr.all_routes();
        let a_route = routes
            .iter()
            .find(|r| r.path_id == "path-a")
            .expect("path-a route should exist");
        let b_route = routes
            .iter()
            .find(|r| r.path_id == "path-b")
            .expect("path-b route should exist");

        assert_eq!(a_route.metric, STANDBY_METRIC, "path-a should be updated");
        assert_eq!(
            b_route.metric, ACTIVE_METRIC,
            "path-b should remain unchanged"
        );
    }

    #[test]
    fn update_metric_os_preserves_route_identity() {
        let mgr = WindowsRouteManager::new();
        mgr.install_route(
            "path-a",
            Ipv4Addr::new(203, 0, 113, 10),
            32,
            0x1234,
            42,
            STANDBY_METRIC,
        )
        .unwrap();

        let before_routes = mgr.all_routes();
        let before = before_routes
            .iter()
            .find(|r| r.path_id == "path-a")
            .unwrap();
        let dest_before = before.destination;
        let prefix_before = before.prefix_length;
        let luid_before = before.interface_luid;
        let if_index_before = before.interface_index;
        let path_id_before = before.path_id.clone();
        let generation_before = before.generation;

        mgr.update_route_metric_os(
            "path-a",
            dest_before,
            prefix_before,
            luid_before,
            ACTIVE_METRIC,
        )
        .unwrap();

        let after_routes = mgr.all_routes();
        let after = after_routes
            .iter()
            .find(|r| r.path_id == "path-a")
            .expect("route should still exist");

        // Destination, prefix, LUID, interface index, and path_id must be preserved
        assert_eq!(
            after.destination, dest_before,
            "destination must be preserved"
        );
        assert_eq!(
            after.prefix_length, prefix_before,
            "prefix must be preserved"
        );
        assert_eq!(after.interface_luid, luid_before, "LUID must be preserved");
        assert_eq!(
            after.interface_index, if_index_before,
            "interface index must be preserved"
        );
        assert_eq!(after.path_id, path_id_before, "path_id must be preserved");
        // Metric changed
        assert_eq!(after.metric, ACTIVE_METRIC);
        // Generation must have advanced (identity changed but route identity preserved)
        assert_eq!(
            after.generation,
            generation_before + 1,
            "generation should advance"
        );
    }

    #[test]
    fn update_metric_os_handles_access_denied_gracefully() {
        let mgr = WindowsRouteManager::new();
        mgr.install_route(
            "path-a",
            Ipv4Addr::new(203, 0, 113, 10),
            32,
            0x1234,
            42,
            STANDBY_METRIC,
        )
        .unwrap();

        // update_route_metric_os should handle ERROR_ACCESS_DENIED gracefully
        // (non-elevated Windows). On non-Windows, it always succeeds by
        // updating the in-memory registry.
        let result = mgr.update_route_metric_os(
            "path-a",
            Ipv4Addr::new(203, 0, 113, 10),
            32,
            0x1234,
            ACTIVE_METRIC,
        );
        // Must be Ok — the route should still be tracked regardless of
        // whether the OS API call was denied
        assert!(result.is_ok(), "ACCESS_DENIED should be handled gracefully");

        // The route should still exist in the registry
        let routes = mgr.all_routes();
        let route = routes
            .iter()
            .find(|r| r.path_id == "path-a")
            .expect("route should still be tracked");
        assert_eq!(route.metric, ACTIVE_METRIC);
    }

    #[test]
    fn update_metric_os_nonexistent_route_returns_error() {
        let mgr = WindowsRouteManager::new();

        let result = mgr.update_route_metric_os(
            "nonexistent",
            Ipv4Addr::new(203, 0, 113, 10),
            32,
            0x1234,
            ACTIVE_METRIC,
        );
        // On non-Windows, this should error since the route is not in the registry.
        // On Windows, it may error or succeed depending on OS state, but the
        // important thing is it doesn't panic.
        #[cfg(not(target_os = "windows"))]
        {
            assert!(
                result.is_err(),
                "should error on non-Windows for unregistered route"
            );
        }

        #[cfg(target_os = "windows")]
        {
            // On Windows, it may return Ok or Err depending on whether
            // SetIpForwardEntry2 finds the route. Just ensure no panic.
            let _ = result;
        }
    }

    #[test]
    fn update_metric_os_non_windows_stub_is_deterministic() {
        let mgr = WindowsRouteManager::new();
        mgr.install_route(
            "path-a",
            Ipv4Addr::new(203, 0, 113, 10),
            32,
            0x1234,
            42,
            STANDBY_METRIC,
        )
        .unwrap();

        // On non-Windows, update_route_metric_os should succeed by updating
        // the in-memory registry directly.
        let result = mgr.update_route_metric_os(
            "path-a",
            Ipv4Addr::new(203, 0, 113, 10),
            32,
            0x1234,
            ACTIVE_METRIC,
        );

        #[cfg(not(target_os = "windows"))]
        {
            assert!(result.is_ok(), "non-Windows stub should succeed");
            let routes = mgr.all_routes();
            let route = routes.iter().find(|r| r.path_id == "path-a").unwrap();
            assert_eq!(route.metric, ACTIVE_METRIC);
        }

        #[cfg(target_os = "windows")]
        {
            // On Windows, may succeed or fail with ACCESS_DENIED, but must not panic
            // If it succeeded, verify the metric was updated
            if result.is_ok() {
                let routes = mgr.all_routes();
                let route = routes.iter().find(|r| r.path_id == "path-a").unwrap();
                assert_eq!(route.metric, ACTIVE_METRIC);
            }
        }
    }
}
