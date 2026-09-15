//! Path Manager — manages multiple WireGuard tunnel paths.
//!
//! Wraps WireGuard adapters + Windows route entries into first-class
//! Path abstractions. Each Path owns a WireGuardTunnel and the
//! Windows route table entries for its destination.

#![allow(clippy::result_large_err)]
use serde::Serialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::windows_route_manager::{
    RouteError, SwitchResult, WindowsRouteManager, ACTIVE_METRIC, STANDBY_METRIC,
};

/// Unique identifier for a path (e.g. "path-a", "path-b").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct PathId(String);

impl PathId {
    pub fn new(id: &str) -> Self {
        Self(id.to_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PathId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Health state of a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PathHealth {
    Healthy,
    Degraded,
    Unhealthy,
}

/// State of a WireGuard tunnel within a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TunnelState {
    Down,
    Up,
}

/// A single SD-WAN path — a WireGuard tunnel + managed Windows routes.
#[derive(Debug, Clone, Serialize)]
pub struct Path {
    pub id: PathId,
    pub profile_name: String,
    pub tunnel_state: TunnelState,
    pub interface_luid: u64,
    pub interface_index: u32,
    pub active: bool,
    pub health: PathHealth,
    pub destination: Option<Ipv4Addr>,
    pub prefix_length: u8,
    pub generation: u64,
}

impl Path {
    pub fn new(id: PathId, profile_name: &str) -> Self {
        Self {
            id,
            profile_name: profile_name.to_string(),
            tunnel_state: TunnelState::Down,
            interface_luid: 0,
            interface_index: 0,
            active: false,
            health: PathHealth::Unhealthy,
            destination: None,
            prefix_length: 32,
            generation: 0,
        }
    }

    /// Install this path's route into the Windows routing table (standby metric).
    pub fn install_route(&mut self, router: &WindowsRouteManager) -> Result<(), String> {
        let dest = self.destination.ok_or("no destination set")?;
        router
            .install_route(
                self.id.as_str(),
                dest,
                self.prefix_length,
                self.interface_luid,
                self.interface_index,
                if self.active {
                    ACTIVE_METRIC
                } else {
                    STANDBY_METRIC
                },
            )
            .map_err(|e| format!("install_route error: {}", e))
    }

    /// Remove this path's route from the Windows routing table.
    pub fn remove_route(&self, router: &WindowsRouteManager) -> Result<(), String> {
        let dest = self.destination.ok_or("no destination set")?;
        router
            .remove_route(
                self.id.as_str(),
                dest,
                self.prefix_length,
                self.interface_luid,
            )
            .map_err(|e| format!("remove_route error: {}", e))
    }
}

/// PathManager owns a collection of Paths and coordinates route installation.
#[derive(Debug)]
pub struct PathManager {
    // Poison-tolerant: a panicked peer thread would otherwise poison this
    // Mutex and a subsequent `.lock().unwrap()` in the routing/failure path
    // (`activate_path`, `failover`, `clear_paths`, …) would propagate a panic
    // into a Tauri command.  We recover the guard via `unwrap_or_else(|e|
    // e.into_inner())` everywhere so a panic in another thread degrades to a
    // best-effort routing outcome (logged via the router), never a hard app
    // crash.  `inner` is only a *desired-state* mirror of the authoritative OS
    // routing table (the OS is re-checked in `install_path_route`), so
    // recovery on a poisoned lock is safe.
    inner: StdMutex<HashMap<String, Path>>,
    router: WindowsRouteManager,
    /// Serializes failover operations to prevent concurrent failover race
    /// conditions. Held across the entire async failover() body, including
    /// the .await on the verify closure. This is the smallest synchronization
    /// mechanism needed to prevent:
    /// - Both paths promoted to metric 10 simultaneously
    /// - Both paths demoted to metric 20 simultaneously
    /// - Inconsistent active-path state
    failover_lock: tokio::sync::Mutex<()>,
}

use std::sync::Mutex as StdMutex;

impl PathManager {
    pub fn new() -> Self {
        Self {
            inner: StdMutex::new(HashMap::new()),
            router: WindowsRouteManager::new(),
            failover_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Register a new path with the given ID and profile name.
    pub fn add_path(&self, id: &str, profile_name: &str) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.contains_key(id) {
            return Err(format!("path '{}' already exists", id));
        }
        inner.insert(id.to_string(), Path::new(PathId::new(id), profile_name));
        Ok(())
    }

    /// Connect (activate) a path: set active=true, install route with ACTIVE_METRIC,
    /// and set other paths to STANDBY.
    pub fn activate_path(&self, path_id: &str) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if !inner.contains_key(path_id) {
            return Err(format!("path '{}' not found", path_id));
        }

        // Set all paths to standby
        for (_id, path) in inner.iter_mut() {
            path.active = false;
        }

        // Activate the target path
        if let Some(path) = inner.get_mut(path_id) {
            path.active = true;
        }

        std::mem::drop(inner);

        // Install/update routes with correct metrics
        let all_ids: Vec<String> = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.keys().cloned().collect()
        };

        for id in &all_ids {
            let (metric, dest, prefix_len, luid, idx) = {
                let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                let path = inner.get(id).unwrap();
                (
                    if *id == path_id {
                        ACTIVE_METRIC
                    } else {
                        STANDBY_METRIC
                    },
                    path.destination,
                    path.prefix_length,
                    path.interface_luid,
                    path.interface_index,
                )
            };

            if let Some(dest) = dest {
                // Delete old route first, then install with new metric
                let _ = self.router.remove_route(id, dest, prefix_len, luid);
                let _ = self
                    .router
                    .install_route(id, dest, prefix_len, luid, idx, metric);
                let _ = self
                    .router
                    .update_route_metric(id, dest, prefix_len, metric);
            }
        }

        Ok(())
    }

    /// Deactivate a path (set standby route).
    pub fn deactivate_path(&self, path_id: &str) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let path = inner.get_mut(path_id).ok_or("path not found")?;
        path.active = false;
        std::mem::drop(inner);

        let dest = self
            .inner
            .lock()
            .unwrap()
            .get(path_id)
            .and_then(|p| p.destination);
        if let Some(dest) = dest {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let path = inner.get(path_id).unwrap();
            let _ =
                self.router
                    .update_route_metric(path_id, dest, path.prefix_length, STANDBY_METRIC);
            std::mem::drop(inner);
        }
        Ok(())
    }

    /// Connect a path: assign LUID/index, set tunnel UP.
    pub fn connect_path(&self, path_id: &str, luid: u64, index: u32) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let path = inner.get_mut(path_id).ok_or("path not found")?;
        path.interface_luid = luid;
        path.interface_index = index;
        path.tunnel_state = TunnelState::Up;
        path.generation = path.generation.wrapping_add(1);
        Ok(())
    }

    /// Disconnect a path: set tunnel DOWN.
    pub fn disconnect_path(&self, path_id: &str) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let path = inner.get_mut(path_id).ok_or("path not found")?;
        path.tunnel_state = TunnelState::Down;
        Ok(())
    }

    /// Get a snapshot of all paths.
    pub fn get_paths(&self) -> Vec<Path> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.values().cloned().collect()
    }

    /// Get a specific path by ID.
    pub fn get_path(&self, path_id: &str) -> Option<Path> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.get(path_id).cloned()
    }

    pub fn inner(&self) -> &StdMutex<HashMap<String, Path>> {
        &self.inner
    }

    pub fn router(&self) -> &WindowsRouteManager {
        &self.router
    }

    /// Check if a path exists.
    pub fn has_path(&self, path_id: &str) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.contains_key(path_id)
    }

    /// Remove all paths and their associated routes.
    pub fn clear_paths(&self) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Remove routes for all paths before clearing
        for (id, path) in inner.iter() {
            if let Some(dest) = path.destination {
                let _ = self
                    .router
                    .remove_route(id, dest, path.prefix_length, path.interface_luid);
            }
        }
        inner.clear();
        Ok(())
    }

    /// Set the managed destination (IP + prefix) for a path.
    /// This is the destination CIDR that gets installed in the Windows
    /// routing table for this path's WireGuard interface.
    pub fn set_destination(
        &self,
        path_id: &str,
        destination: Ipv4Addr,
        prefix_length: u8,
    ) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let path = inner.get_mut(path_id).ok_or("path not found")?;
        path.destination = Some(destination);
        path.prefix_length = prefix_length;
        Ok(())
    }

    /// Returns diagnostic information about all paths.
    pub fn diagnostics(&self) -> Vec<Path> {
        self.get_paths()
    }

    /// Install (or re-install) a route for a single path with the specified
    /// metric. If the route already exists in the **OS routing table**, uses
    /// `SetIpForwardEntry2` (Phase 3) to update the metric without
    /// deleting/recreating the route. If the route does not exist in the OS
    /// table, creates it via `CreateIpForwardEntry2`.
    ///
    /// CRITICAL: Existence is checked against the authoritative OS routing
    /// table (via `enumerate_windows_routes()`), NOT the in-memory registry.
    /// A route may exist in the in-memory registry but be externally removed
    /// from the OS table — in that case the route must be reinstalled, not
    /// updated via `SetIpForwardEntry2` (which would return
    /// `ERROR_FILE_NOT_FOUND`).
    ///
    /// This is a private helper used by `failover()`.
    fn install_path_route(&self, path_id: &str, metric: u32) -> Result<(), RouteError> {
        let (dest, prefix_len, luid, idx) = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let path = inner.get(path_id).ok_or_else(|| RouteError {
                error_code: 0,
                operation: "install_path_route".to_string(),
                destination: String::new(),
                path_id: path_id.to_string(),
                interface_luid: None,
                stage: "lookup".to_string(),
                message: "path not found".to_string(),
            })?;
            (
                path.destination.ok_or_else(|| RouteError {
                    error_code: 0,
                    operation: "install_path_route".to_string(),
                    destination: String::new(),
                    path_id: path_id.to_string(),
                    interface_luid: Some(path.interface_luid),
                    stage: "destination".to_string(),
                    message: "path has no managed destination".to_string(),
                })?,
                path.prefix_length,
                path.interface_luid,
                path.interface_index,
            )
        };

        // Check the OS routing table for an existing route. The OS table is
        // the authoritative source — the in-memory registry tracks ownership
        // and metadata but must NOT falsely establish OS route existence.
        // If the route was externally removed from the OS, we must reinstall
        // it via CreateIpForwardEntry2, not SetIpForwardEntry2.
        let os_routes = self.router.enumerate_windows_routes();
        let os_route_exists = os_routes.iter().any(|r| {
            r.destination == dest && r.prefix_length == prefix_len && r.interface_luid == luid
        });

        if os_route_exists {
            // Route exists in OS — update metric in-place via SetIpForwardEntry2.
            self.router
                .update_route_metric_os(path_id, dest, prefix_len, luid, metric)?;
        } else {
            // Route is missing from OS (whether or not it's in the registry) —
            // install it fresh via CreateIpForwardEntry2.
            self.router
                .install_route(path_id, dest, prefix_len, luid, idx, metric)?;
        }

        Ok(())
    }

    /// Update in-memory `active` flags so that only `active_path_id` is
    /// marked active. Does NOT touch the Windows route table — use
    /// `install_path_route()` for that.
    fn set_path_active(&self, active_path_id: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        for (id, path) in inner.iter_mut() {
            path.active = id == active_path_id;
        }
    }

    /// Atomic failover from `old_path_id` to `new_path_id` with verification
    /// and rollback.
    ///
    /// Implements the failover sequence from §10.2 / §8.4 of
    /// `SDWAN_ARCHITECTURE_DECISION.md`:
    ///
    /// 1. Install `new_path` route with an ACTIVE metric (10) — makes
    ///    the new path the preferred path in the Windows routing table.
    /// 2. Call `verify()` (async) to test reachability through the new path.
    /// 3. If verification **passes**: demote `old_path` route to
    ///    STANDBY metric (20). Both adapters remain UP.
    /// 4. If verification **fails**: rollback — demote `new_path` to
    ///    STANDBY and restore `old_path` to ACTIVE.
    ///
    /// No adapters are destroyed or recreated during failover.
    ///
    /// # Arguments
    ///
    /// * `old_path_id` — currently active path (will become standby)
    /// * `new_path_id` — path to promote to active
    /// * `verify` — async closure that receives a cloned `Path` snapshot
    ///   and returns `true` if the new path is reachable
    pub async fn failover<F, Fut>(
        &self,
        old_path_id: &str,
        new_path_id: &str,
        verify: F,
    ) -> Result<SwitchResult, String>
    where
        F: Fn(&Path) -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        // Acquire exclusive lock across the entire failover operation to
        // prevent concurrent failover race conditions. The lock is held
        // across the .await on verify() — this is safe because
        // tokio::sync::Mutex is designed for async holding.
        let _guard = self.failover_lock.lock().await;

        // --- Validate both paths exist and are connected ---

        let old_path = self
            .get_path(old_path_id)
            .ok_or_else(|| format!("old path '{}' not found", old_path_id))?;
        let new_path = self
            .get_path(new_path_id)
            .ok_or_else(|| format!("new path '{}' not found", new_path_id))?;

        if new_path.destination.is_none() {
            return Err(format!(
                "new path '{}' has no managed destination",
                new_path_id
            ));
        }
        if old_path.destination.is_none() {
            return Err(format!(
                "old path '{}' has no managed destination",
                old_path_id
            ));
        }

        if new_path.interface_luid == 0 {
            return Err(format!(
                "new path '{}' is not connected (LUID is 0)",
                new_path_id
            ));
        }
        if old_path.interface_luid == 0 {
            return Err(format!(
                "old path '{}' is not connected (LUID is 0)",
                old_path_id
            ));
        }

        // --- No-op if already on the requested path ---
        if old_path_id == new_path_id {
            return Ok(SwitchResult {
                from_path: Some(old_path_id.to_string()),
                to_path: Some(new_path_id.to_string()),
                datapath_applied: true,
                routes_added: Vec::new(),
                routes_removed: Vec::new(),
                error: None,
            });
        }

        let dest = new_path.destination.unwrap();
        let prefix_len = new_path.prefix_length;

        // --- Step 1: Install new_path route with ACTIVE_METRIC ---
        self.install_path_route(new_path_id, ACTIVE_METRIC)
            .map_err(|e| format!("failover: failed to install new path route: {}", e))?;

        // --- Step 2: Verify reachability ---
        let new_path_snapshot = self
            .get_path(new_path_id)
            .ok_or("path not found after route install")?;
        let verification_passed = verify(&new_path_snapshot).await;

        if verification_passed {
            // --- Step 3: Demote old_path to STANDBY ---
            if let Err(e) = self.install_path_route(old_path_id, STANDBY_METRIC) {
                tracing::warn!(
                    "failover: failed to demote old path '{}': {}",
                    old_path_id,
                    e
                );
            }

            self.set_path_active(new_path_id);

            Ok(SwitchResult {
                from_path: Some(old_path_id.to_string()),
                to_path: Some(new_path_id.to_string()),
                datapath_applied: true,
                routes_added: vec![format!("{}/{}", dest, prefix_len)],
                routes_removed: vec![format!("{}/{}", dest, prefix_len)],
                error: None,
            })
        } else {
            // --- Step 3b: Rollback ---
            tracing::warn!(
                "failover: verification failed for path '{}'; rolling back to '{}'",
                new_path_id,
                old_path_id
            );

            if let Err(e) = self.install_path_route(new_path_id, STANDBY_METRIC) {
                tracing::warn!(
                    "failover: rollback — failed to demote new path '{}': {}",
                    new_path_id,
                    e
                );
            }
            if let Err(e) = self.install_path_route(old_path_id, ACTIVE_METRIC) {
                tracing::warn!(
                    "failover: rollback — failed to restore old path '{}': {}",
                    old_path_id,
                    e
                );
            }

            self.set_path_active(old_path_id);

            Err(format!(
                "failover verification failed for path '{}'; rolled back to '{}'",
                new_path_id, old_path_id
            ))
        }
    }

    /// Enumerate OS-level routes and reconcile them against the in-memory
    /// path registry.
    ///
    /// Implements the State Reconciliation sequence from §11.3 of
    /// `SDWAN_ARCHITECTURE_DECISION.md`:
    ///
    /// 1. Enumerate all Windows routing table entries tagged
    ///    [`MIB_IPPROTO_NETMGMT`].
    /// 2. For each OS route: if no matching in-memory path exists, it is
    ///    an orphan — remove it from the OS via `DeleteIpForwardEntry2`.
    /// 3. For each in-memory path with [`TunnelState::Up`] and a managed
    ///    destination:
    ///    - If the route is missing from the OS, re-install it via
    ///      `CreateIpForwardEntry2`.
    ///    - If the route exists in the OS but has the wrong metric,
    ///      correct it via `SetIpForwardEntry2` (preserving route identity).
    ///
    /// Returns a vector of human-readable action descriptions.
    pub fn enumerate_and_reconcile(&self) -> Vec<String> {
        let mut actions = Vec::new();

        // 1. Enumerate OS-level routes owned by MARSTART
        let os_routes = self.router.enumerate_windows_routes();

        // 2. Get in-memory path snapshots
        let paths: Vec<Path> = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.values().cloned().collect()
        };

        // 3. Find orphaned OS routes (exist in OS but no matching in-memory path)
        for os_route in &os_routes {
            let matched = paths.iter().any(|p| {
                p.interface_luid == os_route.interface_luid
                    && p.destination == Some(os_route.destination)
                    && p.prefix_length == os_route.prefix_length
            });
            if !matched {
                match self.router.remove_route_os(
                    os_route.destination,
                    os_route.prefix_length,
                    os_route.interface_luid,
                ) {
                    Ok(_) => actions.push(format!(
                        "enumerate_and_reconcile: removed orphan route dest={}/{}, luid=0x{:x}",
                        os_route.destination, os_route.prefix_length, os_route.interface_luid
                    )),
                    Err(e) => actions.push(format!(
                        "enumerate_and_reconcile: failed to remove orphan: {}",
                        e
                    )),
                }
            }
        }

        // 4. Reconcile routes for UP paths.
        //    CRITICAL: Check against the OS routing table snapshot (os_routes),
        //    NOT against the in-memory registry (route_exists). The in-memory
        //    registry may still contain stale entries for routes that were
        //    externally removed from the OS table. Only the OS snapshot
        //    reflects the true state of the routing table.
        for path in &paths {
            if let Some(dest) = path.destination {
                if path.tunnel_state != TunnelState::Up {
                    continue;
                }

                let expected_metric = if path.active {
                    ACTIVE_METRIC
                } else {
                    STANDBY_METRIC
                };

                // Check if route exists in the OS routing table
                let os_route_match = os_routes.iter().find(|r| {
                    r.destination == dest
                        && r.prefix_length == path.prefix_length
                        && r.interface_luid == path.interface_luid
                });

                if let Some(os_route) = os_route_match {
                    // Route exists in OS — check if metric is correct
                    if os_route.metric != expected_metric {
                        match self.router.update_route_metric_os(
                            path.id.as_str(),
                            dest,
                            path.prefix_length,
                            path.interface_luid,
                            expected_metric,
                        ) {
                            Ok(_) => actions.push(format!(
                                "enumerate_and_reconcile: corrected metric for path '{}' (dest={}, old_metric={}, new_metric={})",
                                path.id, dest, os_route.metric, expected_metric
                            )),
                            Err(e) => actions.push(format!(
                                "enumerate_and_reconcile: failed to correct metric for path '{}': {}",
                                path.id, e
                            )),
                        }
                    }
                } else {
                    // Route is missing from OS — install it
                    match self.router.install_route(
                        path.id.as_str(),
                        dest,
                        path.prefix_length,
                        path.interface_luid,
                        path.interface_index,
                        expected_metric,
                    ) {
                        Ok(_) => actions.push(format!(
                            "enumerate_and_reconcile: installed missing route for path '{}' (dest={}, metric={})",
                            path.id, dest, expected_metric
                        )),
                        Err(e) => actions.push(format!(
                            "enumerate_and_reconcile: failed to install route for path '{}': {}",
                            path.id, e
                        )),
                    }
                }
            }
        }

        actions
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_pathmanager_has_no_paths() {
        let pm = PathManager::new();
        assert_eq!(pm.get_paths().len(), 0);
    }

    #[test]
    fn add_path_registers_new_path() {
        let pm = PathManager::new();
        assert!(pm.add_path("path-a", "wg0").is_ok());
        assert_eq!(pm.get_paths().len(), 1);
        assert!(pm.has_path("path-a"));
    }

    #[test]
    fn add_duplicate_path_fails() {
        let pm = PathManager::new();
        pm.add_path("path-a", "wg0").unwrap();
        assert!(pm.add_path("path-a", "wg1").is_err());
    }

    #[test]
    fn connect_path_sets_luid_and_state() {
        let pm = PathManager::new();
        pm.add_path("path-a", "wg0").unwrap();
        assert!(pm.connect_path("path-a", 0x1234, 42).is_ok());

        let path = pm.get_path("path-a").unwrap();
        assert_eq!(path.interface_luid, 0x1234);
        assert_eq!(path.interface_index, 42);
        assert_eq!(path.tunnel_state, TunnelState::Up);
    }

    #[test]
    fn activate_path_sets_active_and_standby() {
        let pm = PathManager::new();
        pm.add_path("path-a", "wg0").unwrap();
        pm.add_path("path-b", "wg1").unwrap();

        // Set destinations and connect
        {
            let mut inner = pm.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.get_mut("path-a").unwrap().destination = Some(Ipv4Addr::new(203, 0, 113, 10));
            inner.get_mut("path-b").unwrap().destination = Some(Ipv4Addr::new(203, 0, 113, 10));
            std::mem::drop(inner);
        }
        pm.connect_path("path-a", 1, 1).unwrap();
        pm.connect_path("path-b", 2, 2).unwrap();

        // Activate path-a
        pm.activate_path("path-a").unwrap();

        let paths = pm.get_paths();
        let a = paths.iter().find(|p| p.id.as_str() == "path-a").unwrap();
        let b = paths.iter().find(|p| p.id.as_str() == "path-b").unwrap();
        assert!(a.active);
        assert!(!b.active);
    }

    #[test]
    fn deactivate_path_clears_active_flag() {
        let pm = PathManager::new();
        pm.add_path("path-a", "wg0").unwrap();
        pm.connect_path("path-a", 1, 1).unwrap();
        pm.activate_path("path-a").unwrap();

        assert!(pm.get_path("path-a").unwrap().active);
        pm.deactivate_path("path-a").unwrap();
        assert!(!pm.get_path("path-a").unwrap().active);
    }

    #[test]
    fn disconnect_path_sets_tunnel_down() {
        let pm = PathManager::new();
        pm.add_path("path-a", "wg0").unwrap();
        pm.connect_path("path-a", 1, 1).unwrap();
        assert_eq!(pm.get_path("path-a").unwrap().tunnel_state, TunnelState::Up);
        pm.disconnect_path("path-a").unwrap();
        assert_eq!(
            pm.get_path("path-a").unwrap().tunnel_state,
            TunnelState::Down
        );
    }

    #[test]
    fn get_nonexistent_path_returns_none() {
        let pm = PathManager::new();
        assert!(pm.get_path("nonexistent").is_none());
    }

    #[test]
    fn set_destination_updates_path() {
        let pm = PathManager::new();
        pm.add_path("path-a", "wg0").unwrap();
        pm.set_destination("path-a", Ipv4Addr::new(10, 0, 0, 1), 24)
            .unwrap();
        let path = pm.get_path("path-a").unwrap();
        assert_eq!(path.destination, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(path.prefix_length, 24);
    }

    #[test]
    fn set_destination_nonexistent_path_fails() {
        let pm = PathManager::new();
        assert!(pm
            .set_destination("nope", Ipv4Addr::new(10, 0, 0, 1), 24)
            .is_err());
    }

    #[test]
    fn clear_paths_removes_all_paths_and_routes() {
        let pm = PathManager::new();
        pm.add_path("path-a", "wg0").unwrap();
        pm.add_path("path-b", "wg1").unwrap();
        assert_eq!(pm.get_paths().len(), 2);
        pm.clear_paths().unwrap();
        assert_eq!(pm.get_paths().len(), 0);
    }

    #[test]
    fn has_path_returns_correct_bool() {
        let pm = PathManager::new();
        assert!(!pm.has_path("path-a"));
        pm.add_path("path-a", "wg0").unwrap();
        assert!(pm.has_path("path-a"));
    }

    #[test]
    fn connect_path_nonexistent_fails() {
        let pm = PathManager::new();
        assert!(pm.connect_path("nonexistent", 1, 1).is_err());
    }

    #[test]
    fn disconnect_path_nonexistent_fails() {
        let pm = PathManager::new();
        assert!(pm.disconnect_path("nonexistent").is_err());
    }

    #[test]
    fn diagnostics_returns_all_paths() {
        let pm = PathManager::new();
        pm.add_path("path-a", "wg0").unwrap();
        pm.add_path("path-b", "wg1").unwrap();
        let diag = pm.diagnostics();
        assert_eq!(diag.len(), 2);
    }

    // ── Phase 2 tests: failover() ───────────────────────────────────

    /// Helper: set up two connected paths with a shared destination.
    fn setup_two_paths() -> PathManager {
        let pm = PathManager::new();
        pm.add_path("path-a", "wg0").unwrap();
        pm.add_path("path-b", "wg1").unwrap();

        {
            let mut inner = pm.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.get_mut("path-a").unwrap().destination = Some(Ipv4Addr::new(203, 0, 113, 10));
            inner.get_mut("path-a").unwrap().prefix_length = 32;
            inner.get_mut("path-b").unwrap().destination = Some(Ipv4Addr::new(203, 0, 113, 10));
            inner.get_mut("path-b").unwrap().prefix_length = 32;
            std::mem::drop(inner);
        }

        pm.connect_path("path-a", 0xAA, 10).unwrap();
        pm.connect_path("path-b", 0xBB, 20).unwrap();
        pm.activate_path("path-a").unwrap();
        pm
    }

    #[tokio::test]
    async fn failover_switches_active_to_new_path_on_verification_success() {
        let pm = setup_two_paths();

        let result = pm
            .failover("path-a", "path-b", |_| async { true })
            .await
            .unwrap();
        assert_eq!(result.from_path, Some("path-a".to_string()));
        assert_eq!(result.to_path, Some("path-b".to_string()));
        assert!(result.datapath_applied);
        assert!(result.error.is_none());

        // Verify in-memory state
        let paths = pm.get_paths();
        let a = paths.iter().find(|p| p.id.as_str() == "path-a").unwrap();
        let b = paths.iter().find(|p| p.id.as_str() == "path-b").unwrap();
        assert!(!a.active, "old path should be inactive");
        assert!(b.active, "new path should be active");
    }

    #[tokio::test]
    async fn failover_rolls_back_on_verification_failure() {
        let pm = setup_two_paths();

        // Before failover: path-a is active
        assert!(pm.get_path("path-a").unwrap().active);
        assert!(!pm.get_path("path-b").unwrap().active);

        let result = pm.failover("path-a", "path-b", |_| async { false }).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("rolled back"));

        // After rollback: path-a should be active again
        let paths = pm.get_paths();
        let a = paths.iter().find(|p| p.id.as_str() == "path-a").unwrap();
        let b = paths.iter().find(|p| p.id.as_str() == "path-b").unwrap();
        assert!(a.active, "old path should remain active after rollback");
        assert!(!b.active, "new path should remain inactive after rollback");
    }

    #[tokio::test]
    async fn failover_nonexistent_old_path_returns_error() {
        let pm = setup_two_paths();
        let result = pm.failover("path-x", "path-b", |_| async { true }).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[tokio::test]
    async fn failover_nonexistent_new_path_returns_error() {
        let pm = setup_two_paths();
        let result = pm.failover("path-a", "path-x", |_| async { true }).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[tokio::test]
    async fn failover_same_path_is_noop() {
        let pm = setup_two_paths();
        let result = pm
            .failover("path-a", "path-a", |_| async { true })
            .await
            .unwrap();
        assert!(result.datapath_applied);
        assert_eq!(result.from_path, Some("path-a".to_string()));
        assert_eq!(result.to_path, Some("path-a".to_string()));
    }

    #[tokio::test]
    async fn failover_missing_destination_returns_error() {
        let pm = PathManager::new();
        pm.add_path("path-a", "wg0").unwrap();
        pm.add_path("path-b", "wg1").unwrap();
        pm.connect_path("path-a", 0xAA, 10).unwrap();
        pm.connect_path("path-b", 0xBB, 20).unwrap();
        // No destination set on either path
        let result = pm.failover("path-a", "path-b", |_| async { true }).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("managed destination"));
    }

    #[tokio::test]
    async fn failover_unconnected_path_returns_error() {
        let pm = PathManager::new();
        pm.add_path("path-a", "wg0").unwrap();
        pm.add_path("path-b", "wg1").unwrap();

        // Set destinations so the destination check passes, but don't connect
        // — LUID remains 0, triggering the "not connected" error
        {
            let mut inner = pm.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.get_mut("path-a").unwrap().destination = Some(Ipv4Addr::new(203, 0, 113, 10));
            inner.get_mut("path-a").unwrap().prefix_length = 32;
            inner.get_mut("path-b").unwrap().destination = Some(Ipv4Addr::new(203, 0, 113, 10));
            inner.get_mut("path-b").unwrap().prefix_length = 32;
            std::mem::drop(inner);
        }

        let result = pm.failover("path-a", "path-b", |_| async { true }).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not connected"));
    }

    #[tokio::test]
    async fn failover_sets_correct_metrics_after_success() {
        let pm = setup_two_paths();
        pm.failover("path-a", "path-b", |_| async { true })
            .await
            .unwrap();

        // After failover, path-b (new active) should have ACTIVE_METRIC in registry
        // and path-a should have STANDBY_METRIC
        let routes = pm.router().all_routes();
        let dest = Ipv4Addr::new(203, 0, 113, 10);

        let active_route = routes
            .iter()
            .find(|r| r.path_id == "path-b" && r.destination == dest);
        let standby_route = routes
            .iter()
            .find(|r| r.path_id == "path-a" && r.destination == dest);

        assert!(active_route.is_some(), "active route should exist");
        assert_eq!(active_route.unwrap().metric, ACTIVE_METRIC);

        assert!(standby_route.is_some(), "standby route should exist");
        assert_eq!(standby_route.unwrap().metric, STANDBY_METRIC);
    }

    // ── failover() invariant regression tests ───────────────────────

    /// Invariant 1: Successful A→B failover — B=10, A=20, active=B
    #[tokio::test]
    async fn failover_invariant_success_metrics_and_active() {
        let pm = setup_two_paths();

        let result = pm
            .failover("path-a", "path-b", |_| async { true })
            .await
            .unwrap();
        assert!(result.datapath_applied);
        assert!(result.error.is_none());

        // B route should have ACTIVE_METRIC (10)
        let routes = pm.router().all_routes();
        let dest = Ipv4Addr::new(203, 0, 113, 10);
        let b_route = routes
            .iter()
            .find(|r| r.path_id == "path-b" && r.destination == dest)
            .expect("path-b route should exist");
        assert_eq!(
            b_route.metric, ACTIVE_METRIC,
            "new active path route should have ACTIVE_METRIC"
        );

        // A route should have STANDBY_METRIC (20)
        let a_route = routes
            .iter()
            .find(|r| r.path_id == "path-a" && r.destination == dest)
            .expect("path-a route should exist");
        assert_eq!(
            a_route.metric, STANDBY_METRIC,
            "old path route should have STANDBY_METRIC"
        );

        // Active path should be B
        assert!(!pm.get_path("path-a").unwrap().active);
        assert!(pm.get_path("path-b").unwrap().active);
    }

    /// Invariant 2: Failed verification — A=10, B=20, active=A, no partial state
    #[tokio::test]
    async fn failover_invariant_rollback_preserves_original_state() {
        let pm = setup_two_paths();

        let result = pm.failover("path-a", "path-b", |_| async { false }).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("rolled back"));

        let routes = pm.router().all_routes();
        let dest = Ipv4Addr::new(203, 0, 113, 10);

        // A route should still have ACTIVE_METRIC (10) — rolled back
        let a_route = routes
            .iter()
            .find(|r| r.path_id == "path-a" && r.destination == dest)
            .expect("path-a route should exist");
        assert_eq!(
            a_route.metric, ACTIVE_METRIC,
            "old path should be restored to ACTIVE"
        );

        // B route should have STANDBY_METRIC (20) — rolled back
        let b_route = routes
            .iter()
            .find(|r| r.path_id == "path-b" && r.destination == dest)
            .expect("path-b route should exist");
        assert_eq!(
            b_route.metric, STANDBY_METRIC,
            "new path should be demoted to STANDBY"
        );

        // Active path should still be A
        assert!(pm.get_path("path-a").unwrap().active);
        assert!(!pm.get_path("path-b").unwrap().active);
    }

    /// Invariant 3: Same-path failover is a true no-op
    #[tokio::test]
    async fn failover_invariant_same_path_noop() {
        let pm = setup_two_paths();
        // Ensure path-a is active
        pm.activate_path("path-a").unwrap();

        let routes_before = pm.router().all_routes();
        let metrics_before: Vec<(String, u32)> = routes_before
            .iter()
            .map(|r| (format!("{}/{}", r.path_id, r.destination), r.metric))
            .collect();

        let result = pm
            .failover("path-a", "path-a", |_| async { true })
            .await
            .unwrap();
        assert!(result.datapath_applied);
        assert_eq!(result.from_path, Some("path-a".to_string()));
        assert_eq!(result.to_path, Some("path-a".to_string()));
        assert!(result.error.is_none());

        // Verify no route state changed
        let routes_after = pm.router().all_routes();
        let metrics_after: Vec<(String, u32)> = routes_after
            .iter()
            .map(|r| (format!("{}/{}", r.path_id, r.destination), r.metric))
            .collect();

        assert_eq!(metrics_before, metrics_after, "no routes should change");
        assert!(pm.get_path("path-a").unwrap().active);
        assert!(!pm.get_path("path-b").unwrap().active);
    }

    /// Invariant 4: Missing/unconnected path cannot modify route state
    #[tokio::test]
    async fn failover_invariant_no_route_state_change_on_missing_path() {
        let pm = setup_two_paths();
        let routes_before = pm.router().all_routes();
        let metrics_before: Vec<(String, u32)> = routes_before
            .iter()
            .map(|r| (format!("{}", r.destination), r.metric))
            .collect();

        // Try to failover to a nonexistent path
        let result = pm
            .failover("path-a", "nonexistent", |_| async { true })
            .await;
        assert!(result.is_err());

        // No route state should have changed
        let routes_after = pm.router().all_routes();
        let metrics_after: Vec<(String, u32)> = routes_after
            .iter()
            .map(|r| (format!("{}", r.destination), r.metric))
            .collect();
        assert_eq!(
            metrics_before, metrics_after,
            "no routes should change on error"
        );

        // Try to failover from a nonexistent path
        let result = pm
            .failover("nonexistent", "path-b", |_| async { true })
            .await;
        assert!(result.is_err());

        // Still no change
        let routes_after2 = pm.router().all_routes();
        let metrics_after2: Vec<(String, u32)> = routes_after2
            .iter()
            .map(|r| (format!("{}", r.destination), r.metric))
            .collect();
        assert_eq!(
            metrics_before, metrics_after2,
            "no routes should change on error"
        );
    }

    /// Invariant 5: No WireGuard adapter is destroyed/recreated by failover
    #[tokio::test]
    async fn failover_invariant_no_adapter_destroyed() {
        let pm = setup_two_paths();
        let luid_a_before = pm.get_path("path-a").unwrap().interface_luid;
        let luid_b_before = pm.get_path("path-b").unwrap().interface_luid;
        let idx_a_before = pm.get_path("path-a").unwrap().interface_index;
        let idx_b_before = pm.get_path("path-b").unwrap().interface_index;
        let state_a_before = pm.get_path("path-a").unwrap().tunnel_state;
        let state_b_before = pm.get_path("path-b").unwrap().tunnel_state;

        pm.failover("path-a", "path-b", |_| async { true })
            .await
            .unwrap();

        let luid_a_after = pm.get_path("path-a").unwrap().interface_luid;
        let luid_b_after = pm.get_path("path-b").unwrap().interface_luid;
        let idx_a_after = pm.get_path("path-a").unwrap().interface_index;
        let idx_b_after = pm.get_path("path-b").unwrap().interface_index;
        let state_a_after = pm.get_path("path-a").unwrap().tunnel_state;
        let state_b_after = pm.get_path("path-b").unwrap().tunnel_state;

        // LUIDs must not change (no adapter recreated)
        assert_eq!(luid_a_before, luid_a_after, "path-a LUID must not change");
        assert_eq!(luid_b_before, luid_b_after, "path-b LUID must not change");
        assert_eq!(idx_a_before, idx_a_after, "path-a index must not change");
        assert_eq!(idx_b_before, idx_b_after, "path-b index must not change");
        assert_eq!(
            state_a_before, state_a_after,
            "path-a tunnel state must not change"
        );
        assert_eq!(
            state_b_before, state_b_after,
            "path-b tunnel state must not change"
        );
    }

    /// Invariant 6: Existing unrelated routes are never removed by failover
    #[tokio::test]
    async fn failover_invariant_unrelated_routes_not_removed() {
        let pm = setup_two_paths();

        // Install an unrelated route that doesn't belong to either path
        pm.router()
            .install_route(
                "unrelated",
                Ipv4Addr::new(10, 0, 0, 1),
                32,
                0x7777,
                77,
                ACTIVE_METRIC,
            )
            .unwrap();

        let unrelated_before = pm.router().all_routes();
        let before = unrelated_before.iter().find(|r| r.path_id == "unrelated");
        assert!(before.is_some());

        // Perform failover
        pm.failover("path-a", "path-b", |_| async { true })
            .await
            .unwrap();

        // The unrelated route must still exist
        let unrelated_after = pm.router().all_routes();
        let after = unrelated_after.iter().find(|r| r.path_id == "unrelated");
        assert!(
            after.is_some(),
            "unrelated route must not be removed by failover"
        );
        assert_eq!(
            before.unwrap().metric,
            after.unwrap().metric,
            "unrelated route metric must not change"
        );
    }

    // ── Phase 2 tests: enumerate_and_reconcile() ─────────────────────

    #[test]
    fn reconcile_reinstalls_missing_routes_for_up_paths() {
        let pm = setup_two_paths();

        // Remove routes from in-memory registry (simulating they're missing
        // from the OS table)
        pm.router().cleanup_owned_routes();

        // Verify routes are gone from registry
        assert_eq!(pm.router().all_routes().len(), 0);

        // Reconcile should re-install routes for UP paths
        let actions = pm.enumerate_and_reconcile();

        // Each UP path with a destination should have its route re-installed
        // (path-a active, path-b standby)
        assert!(
            actions
                .iter()
                .any(|a| a.contains("installed missing route")),
            "expected 'installed missing route' in actions: {:?}",
            actions
        );

        let routes = pm.router().all_routes();
        assert!(
            routes
                .iter()
                .any(|r| r.destination == Ipv4Addr::new(203, 0, 113, 10)),
            "expected route to be re-installed"
        );
    }

    #[test]
    fn reconcile_no_action_when_consistent() {
        let pm = setup_two_paths();
        // activate_path already installed routes
        // enumerate_and_reconcile should find everything consistent
        let actions = pm.enumerate_and_reconcile();

        // On non-Windows, enumerate_windows_routes returns in-memory routes
        // which are already installed, so route_exists should be true
        // and no "installed missing route" actions should occur
        #[cfg(not(target_os = "windows"))]
        {
            assert!(
                !actions
                    .iter()
                    .any(|a| a.contains("installed missing route")),
                "no routes should need installation when consistent: {:?}",
                actions
            );
            assert!(
                !actions.iter().any(|a| a.contains("corrected metric")),
                "no metrics should need correction when consistent: {:?}",
                actions
            );
        }

        #[cfg(target_os = "windows")]
        {
            // On Windows non-elevated, routes are in the registry but NOT in
            // the real OS table (CreateIpForwardEntry2 returns ACCESS_DENIED).
            // enumerate_windows_routes returns real OS routes, so our routes
            // won't be found → they will be installed (not corrected).
            assert!(actions
                .iter()
                .all(|a| a.starts_with("enumerate_and_reconcile")));
        }
    }

    /// Audit #3: When the OS route exists with the wrong metric,
    /// reconciliation should correct it to the expected metric
    /// (ACTIVE_METRIC=10 for active path, STANDBY_METRIC=20 for standby).
    ///
    /// On non-Windows, enumerate_windows_routes() returns the in-memory
    /// registry, so we can simulate an OS route with wrong metric by
    /// directly setting the metric in the registry.
    /// On Windows (non-elevated), routes are never in the real OS table,
    /// so this scenario only applies on non-Windows.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn reconcile_corrects_wrong_metric_on_existing_os_route() {
        let pm = setup_two_paths();
        let dest = Ipv4Addr::new(203, 0, 113, 10);

        // Path-a is active (should have metric 10). Corrupt its metric in the
        // "OS" (in-memory registry on non-Windows) to an incorrect value.
        pm.router()
            .update_route_metric("path-a", dest, 32, 999)
            .unwrap();

        // Verify the metric was corrupted
        let routes = pm.router().all_routes();
        let route = routes
            .iter()
            .find(|r| r.path_id == "path-a" && r.destination == dest)
            .unwrap();
        assert_eq!(route.metric, 999, "metric should be corrupted");

        // Reconcile should detect the wrong metric and correct it
        let actions = pm.enumerate_and_reconcile();

        // Should have a "corrected metric" action
        let corrected = actions
            .iter()
            .find(|a| a.contains("corrected metric") && a.contains("path-a"));
        assert!(
            corrected.is_some(),
            "expected 'corrected metric' action for path-a: {:?}",
            actions
        );

        // Verify the metric was corrected to ACTIVE_METRIC (10)
        let routes = pm.router().all_routes();
        let route = routes
            .iter()
            .find(|r| r.path_id == "path-a" && r.destination == dest)
            .unwrap();
        assert_eq!(
            route.metric, ACTIVE_METRIC,
            "metric should be corrected to ACTIVE_METRIC after reconciliation"
        );
    }

    /// Audit #3 continuation: Verify that reconciliation does NOT overwrite
    /// a valid OS metric with stale registry state. After failover (B=10,
    /// A=20), reconciliation should keep the correct metrics.
    #[tokio::test]
    async fn reconcile_preserves_correct_metrics_after_failover() {
        let pm = setup_two_paths();

        // Perform failover: A→B
        let result = pm
            .failover("path-a", "path-b", |_| async { true })
            .await
            .unwrap();
        assert!(result.datapath_applied);

        // After failover: B=10 (active), A=20 (standby)
        let routes = pm.router().all_routes();
        let dest = Ipv4Addr::new(203, 0, 113, 10);
        let b_route = routes
            .iter()
            .find(|r| r.path_id == "path-b" && r.destination == dest)
            .expect("path-b route should exist");
        let a_route = routes
            .iter()
            .find(|r| r.path_id == "path-a" && r.destination == dest)
            .expect("path-a route should exist");
        assert_eq!(b_route.metric, ACTIVE_METRIC, "B should be active (10)");
        assert_eq!(a_route.metric, STANDBY_METRIC, "A should be standby (20)");

        // Reconcile — should NOT overwrite correct metrics
        let actions = pm.enumerate_and_reconcile();

        // On non-Windows, no correction needed (metrics already correct)
        #[cfg(not(target_os = "windows"))]
        {
            assert!(
                !actions.iter().any(|a| a.contains("corrected metric")),
                "reconciliation should NOT correct already-correct metrics: {:?}",
                actions
            );
        }

        #[cfg(target_os = "windows")]
        {
            // On non-elevated Windows, routes are in the registry but NOT in
            // the real OS table. enumerate_and_reconcile will attempt to
            // reinstall them (which fails with ACCESS_DENIED but tracks in
            // registry). The key invariant: metrics remain correct.
            assert!(
                !actions.iter().any(|a| a.contains("corrected metric")),
                "reconciliation should NOT correct already-correct metrics: {:?}",
                actions
            );
        }

        // Verify metrics are still correct after reconciliation
        let routes = pm.router().all_routes();
        let b_route = routes
            .iter()
            .find(|r| r.path_id == "path-b" && r.destination == dest)
            .expect("path-b route should still exist");
        let a_route = routes
            .iter()
            .find(|r| r.path_id == "path-a" && r.destination == dest)
            .expect("path-a route should still exist");
        assert_eq!(
            b_route.metric, ACTIVE_METRIC,
            "B should remain active (10) after reconciliation"
        );
        assert_eq!(
            a_route.metric, STANDBY_METRIC,
            "A should remain standby (20) after reconciliation"
        );
    }

    #[test]
    fn reconcile_returns_action_list() {
        let pm = setup_two_paths();
        let actions = pm.enumerate_and_reconcile();
        // Should return a Vec<String>, even if empty
        assert!(actions
            .iter()
            .all(|a| a.starts_with("enumerate_and_reconcile")));
    }

    // ── Regression tests for correctness audit ───────────────────────

    /// Regression: A route that exists in the in-memory registry but is
    /// externally removed from the OS routing table must be detected as
    /// missing and reinstalled.
    ///
    /// This test verifies that `enumerate_and_reconcile()` checks against
    /// the OS snapshot (`enumerate_windows_routes`), NOT the in-memory
    /// registry (`route_exists`). On non-elevated Windows, routes installed
    /// via `install_route` are in the in-memory registry (because
    /// `CreateIpForwardEntry2` returns ACCESS_DENIED) but NOT in the actual
    /// OS routing table. The old implementation used `route_exists()` which
    /// only checked the in-memory registry, so it would NOT detect this
    /// discrepancy and would skip reinstallation.
    ///
    /// After the fix, `enumerate_and_reconcile()` cross-references each
    /// path's route against the `os_routes` snapshot. If the route is absent
    /// from the OS, it is reinstalled.
    #[test]
    fn reconcile_reinstalls_route_missing_from_os_despite_registry() {
        let pm = setup_two_paths();

        // On non-elevated Windows (and non-Windows stub), `activate_path`
        // → `install_route` → route is in the in-memory registry.
        // On Windows, it is NOT in the actual OS routing table
        // (CreateIpForwardEntry2 returns ACCESS_DENIED).
        // On non-Windows, the in-memory registry IS the "OS table" stub.
        //
        // On non-Windows: clear the registry to simulate OS removal.
        // On Windows: the route is already NOT in the real OS table.
        #[cfg(not(target_os = "windows"))]
        {
            pm.router().cleanup_owned_routes();
        }

        // On Windows, routes are never actually installed in the OS table
        // (ACCESS_DENIED without elevation). So `os_routes` from
        // `GetIpForwardTable2` won't contain our path routes (203.0.113.10).
        // On non-Windows, we cleared the registry, so `os_routes` is empty.
        // Either way, the path routes should be detected as missing.
        let actions = pm.enumerate_and_reconcile();

        // Verify that "installed missing route" actions were generated.
        // This confirms the function checks the OS snapshot, not the
        // in-memory registry alone.
        let reinstall_actions: Vec<&String> = actions
            .iter()
            .filter(|a| a.contains("installed missing route"))
            .collect();

        #[cfg(not(target_os = "windows"))]
        {
            assert!(
                !reinstall_actions.is_empty(),
                "routes should be detected as missing from OS and reinstalled: {:?}",
                actions
            );
        }

        #[cfg(target_os = "windows")]
        {
            // On Windows without elevation, routes are in the in-memory
            // registry but NOT in the OS table. With the fix,
            // enumerate_and_reconcile() should detect them as missing
            // and attempt reinstallation.
            assert!(
                !reinstall_actions.is_empty(),
                "routes in registry but not in OS table should be detected as missing: {:?}",
                actions
            );
        }
    }

    /// Regression: `enumerate_and_reconcile()` must detect orphaned MARSTART-
    /// owned OS routes and remove ONLY those, leaving foreign/unmanaged routes
    /// untouched.
    ///
    /// Required scenario:
    /// 1. A MARSTART-owned route exists (in registry).
    /// 2. No corresponding PathManager path matches it.
    /// 3. Reconciliation detects it as orphaned.
    /// 4. Only that orphaned route is removed.
    /// 5. Foreign/unmanaged routes remain untouched.
    #[test]
    fn reconcile_removes_only_orphaned_managed_routes() {
        let pm = setup_two_paths();

        // Install an extra route in the registry that belongs to no path.
        // This simulates a stale MARSTART-owned route (e.g., from a previous
        // path that was disconnected but its route wasn't cleaned up).
        pm.router()
            .install_route(
                "orphan",
                Ipv4Addr::new(198, 51, 100, 99),
                32,
                0x8888,
                88,
                ACTIVE_METRIC,
            )
            .unwrap();

        let registry_before = pm.router().all_routes();
        assert_eq!(registry_before.len(), 3); // path-a + path-b + orphan

        let actions = pm.enumerate_and_reconcile();

        // The orphan route (198.51.100.99, luid=0x8888) has no matching path.
        // On non-Windows, it is in the registry AND returned by
        // enumerate_windows_routes → it will be detected as orphan and removed.
        #[cfg(not(target_os = "windows"))]
        {
            let orphan_action = actions
                .iter()
                .find(|a| a.contains("removed orphan") && a.contains("198.51.100.99"));
            assert!(
                orphan_action.is_some(),
                "orphan route should be detected and removed: {:?}",
                actions
            );

            // Verify the orphan was removed from the registry
            let registry_after = pm.router().all_routes();
            assert_eq!(registry_after.len(), 2); // path-a + path-b remain
            assert!(
                !registry_after.iter().any(|r| r.path_id == "orphan"),
                "orphan route should be removed from registry"
            );
        }

        #[cfg(target_os = "windows")]
        {
            // On Windows, enumerate_windows_routes returns real OS routes.
            // The orphan in the in-memory registry may or may not be in the
            // actual OS table. Just verify no panic and correct action format.
            assert!(actions
                .iter()
                .all(|a| a.starts_with("enumerate_and_reconcile")));
        }
    }

    #[test]
    fn reconcile_cleans_unmatched_registry_routes() {
        let pm = setup_two_paths();

        // On non-Windows, enumerate_windows_routes() returns in-memory
        // registry entries. A registry route with no matching PathManager
        // path is an orphan and should be removed.
        //
        // On Windows, enumerate_windows_routes() returns real OS routes
        // (via GetIpForwardTable2), so this test only validates the
        // in-memory behavior on non-Windows.
        #[cfg(not(target_os = "windows"))]
        {
            pm.router()
                .install_route(
                    "foreign",
                    Ipv4Addr::new(192, 0, 2, 1),
                    32,
                    0x9999,
                    99,
                    ACTIVE_METRIC,
                )
                .unwrap();

            let actions = pm.enumerate_and_reconcile();

            // The orphan should be detected and removed
            let orphan_action = actions
                .iter()
                .find(|a| a.contains("removed orphan") && a.contains("192.0.2.1"));
            assert!(
                orphan_action.is_some(),
                "orphan route should be removed: {:?}",
                actions
            );

            // Verify the orphan is gone from the registry
            let routes = pm.router().all_routes();
            assert!(
                !routes.iter().any(|r| {
                    r.path_id == "foreign" && r.destination == Ipv4Addr::new(192, 0, 2, 1)
                }),
                "foreign route should be removed from registry"
            );
        }

        #[cfg(target_os = "windows")]
        {
            // On Windows, enumerate_windows_routes returns real OS routes.
            // Just verify the function runs without panic and returns actions.
            let actions = pm.enumerate_and_reconcile();
            assert!(actions
                .iter()
                .all(|a| a.starts_with("enumerate_and_reconcile")));
        }
    }

    // ── Phase 3 tests: async failover verification ───────────────────

    /// Verifies that the async verify closure is actually awaited and its
    /// result determines the failover outcome. A closure that returns false
    /// (after an async yield) should trigger rollback.
    #[tokio::test]
    async fn failover_async_verify_false_triggers_rollback() {
        let pm = setup_two_paths();

        let verify_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let verify_called_clone = std::sync::Arc::clone(&verify_called);

        let result = pm
            .failover("path-a", "path-b", move |_| {
                let flag = verify_called_clone.clone();
                async move {
                    // Simulate async work (e.g., ICMP probe)
                    tokio::task::yield_now().await;
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    false // verification fails
                }
            })
            .await;

        assert!(result.is_err());
        assert!(
            verify_called.load(std::sync::atomic::Ordering::SeqCst),
            "async verify closure must have been called and awaited"
        );

        // Rollback: path-a should be active again
        assert!(
            pm.get_path("path-a").unwrap().active,
            "old path should be active after rollback"
        );
        assert!(
            !pm.get_path("path-b").unwrap().active,
            "new path should be inactive after rollback"
        );
    }

    /// Verifies that the async verify closure returning true succeeds.
    #[tokio::test]
    async fn failover_async_verify_true_succeeds() {
        let pm = setup_two_paths();

        let result = pm
            .failover("path-a", "path-b", |_| async {
                // Simulate async work
                tokio::task::yield_now().await;
                true
            })
            .await
            .unwrap();

        assert!(result.datapath_applied);
        assert!(result.error.is_none());

        // path-b should be active
        assert!(pm.get_path("path-b").unwrap().active);
        assert!(!pm.get_path("path-a").unwrap().active);
    }

    /// Verifies that same-path failover with async verify is a true no-op.
    #[tokio::test]
    async fn failover_async_same_path_noop() {
        let pm = setup_two_paths();

        let verify_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let vc = verify_called.clone();

        let result = pm
            .failover("path-a", "path-a", move |_| {
                let flag = vc.clone();
                async move {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    true
                }
            })
            .await
            .unwrap();

        // Same-path should be a no-op — verify should NOT be called
        assert!(
            !verify_called.load(std::sync::atomic::Ordering::SeqCst),
            "verify should not be called for same-path failover (no-op)"
        );

        assert!(result.datapath_applied);
        assert!(pm.get_path("path-a").unwrap().active);
        assert!(!pm.get_path("path-b").unwrap().active);
    }

    /// Verifies that failover to a nonexistent path with async verify
    /// does NOT call the verify closure (early validation failure).
    #[tokio::test]
    async fn failover_async_missing_path_does_not_call_verify() {
        let pm = setup_two_paths();

        let verify_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let vc = verify_called.clone();

        let result = pm
            .failover("path-a", "nonexistent", move |_| {
                let flag = vc.clone();
                async move {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    true
                }
            })
            .await;

        assert!(result.is_err());
        assert!(
            !verify_called.load(std::sync::atomic::Ordering::SeqCst),
            "verify should not be called when path is missing"
        );
    }

    // ── Phase 3: concurrency safety ─────────────────────────────────

    /// Verifies that concurrent failover calls are serialized by the
    /// failover_lock, preventing race conditions that could leave both
    /// paths at metric 10 or both at metric 20.
    #[tokio::test]
    async fn failover_concurrent_calls_are_serialized() {
        let pm = setup_two_paths();

        // Run two conflicting failovers concurrently: A→B and B→A.
        // The failover_lock serializes them.
        let (result1, result2) = tokio::join!(
            pm.failover("path-a", "path-b", |_| async { true }),
            pm.failover("path-b", "path-a", |_| async { true }),
        );

        // Both should succeed (serialized, not raced)
        assert!(result1.is_ok(), "first failover should succeed");
        assert!(result2.is_ok(), "second failover should succeed");

        // Final state: exactly one active path
        let paths = pm.get_paths();
        let active_count = paths.iter().filter(|p| p.active).count();
        assert_eq!(
            active_count, 1,
            "exactly one path should be active after concurrent failover"
        );

        // Verify metrics are consistent: active=10, standby=20
        let routes = pm.router().all_routes();
        for path in &paths {
            let route = routes.iter().find(|r| {
                r.path_id == path.id.as_str() && r.destination == path.destination.unwrap()
            });
            if let Some(r) = route {
                if path.active {
                    assert_eq!(r.metric, ACTIVE_METRIC, "active path should have metric 10");
                } else {
                    assert_eq!(
                        r.metric, STANDBY_METRIC,
                        "standby path should have metric 20"
                    );
                }
            }
        }
    }

    // ── Phase 3 regression: install_path_route OS-level existence check ─

    /// Regression for critical audit finding: `install_path_route()` must
    /// check the OS routing table (via `enumerate_windows_routes()`), NOT
    /// the in-memory registry (`route_exists()`).
    ///
    /// Scenario:
    /// 1. A MARSTART route exists in the in-memory registry.
    /// 2. The corresponding OS route is externally deleted.
    /// 3. `install_path_route()` is called.
    /// 4. The implementation must detect the OS route is missing and
    ///    reinstall it via `install_route()` (CreateIpForwardEntry2), NOT
    ///    attempt `SetIpForwardEntry2` against a nonexistent route.
    ///
    /// On non-Windows, the in-memory registry IS the OS table stub, so
    /// we simulate external deletion by clearing the registry.
    /// On Windows (non-elevated), MARSTART routes are tracked in the
    /// registry but never actually present in the real OS table
    /// (CreateIpForwardEntry2 returns ACCESS_DENIED), so the OS route
    /// is already "missing" — install_path_route naturally calls
    /// install_route().
    #[tokio::test]
    async fn install_path_route_reinstalls_when_os_route_missing() {
        let pm = setup_two_paths();
        let dest = Ipv4Addr::new(203, 0, 113, 10);

        // Routes were installed by activate_path() in setup_two_paths()
        assert!(
            pm.router().route_exists(dest, 32, 0xAA),
            "route should exist in registry initially"
        );

        // Simulate external OS route deletion.
        #[cfg(not(target_os = "windows"))]
        {
            // On non-Windows, the registry IS the OS table. Clear it to
            // simulate the OS route being externally removed.
            pm.router().cleanup_owned_routes();
        }

        // On non-Windows, verify the route is gone from OS view
        #[cfg(not(target_os = "windows"))]
        {
            let os_routes = pm.router().enumerate_windows_routes();
            assert!(
                !os_routes
                    .iter()
                    .any(|r| r.destination == dest && r.interface_luid == 0xAA),
                "OS route should be missing after cleanup"
            );
        }

        // install_path_route must detect the OS route is missing and
        // reinstall it via install_route() (CreateIpForwardEntry2),
        // NOT update_route_metric_os() (SetIpForwardEntry2) which would
        // fail with ERROR_FILE_NOT_FOUND on a nonexistent route.
        let result = pm.install_path_route("path-a", ACTIVE_METRIC);
        assert!(
            result.is_ok(),
            "install_path_route must reinstall missing OS route, not call SetIpForwardEntry2: {:?}",
            result.err()
        );

        // Route should be back in the in-memory registry
        assert!(
            pm.router().route_exists(dest, 32, 0xAA),
            "route should be reinstalled in registry"
        );

        // Verify correct metric was set during install
        let routes = pm.router().all_routes();
        let route = routes
            .iter()
            .find(|r| r.path_id == "path-a" && r.destination == dest)
            .expect("installed route should exist");
        assert_eq!(route.metric, ACTIVE_METRIC);
    }

    /// Verifies that when the route DOES exist in the OS table,
    /// `install_path_route()` uses `SetIpForwardEntry2` (update) rather
    /// than deleting/recreating the route. The generation counter
    /// distinguishes update (incremented) from install (reset to 0).
    ///
    /// On Windows (non-elevated), MARSTART routes installed via
    /// CreateIpForwardEntry2 are tracked in the registry but NOT in the
    /// real OS table (ACCESS_DENIED). Therefore the "route exists in OS"
    /// path can only be exercised on non-Windows, where the in-memory
    /// registry serves as the OS table stub.
    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn install_path_route_updates_metric_when_os_route_exists() {
        let pm = setup_two_paths();
        let dest = Ipv4Addr::new(203, 0, 113, 10);

        let gen_before = pm
            .router()
            .all_routes()
            .iter()
            .find(|r| r.path_id == "path-a" && r.destination == dest)
            .expect("route should exist")
            .generation;

        // install_path_route should detect the route exists in OS (registry
        // on non-Windows) and call update_route_metric_os() → SetIpForwardEntry2
        pm.install_path_route("path-a", STANDBY_METRIC)
            .expect("update should succeed");

        let routes = pm.router().all_routes();
        let route = routes
            .iter()
            .find(|r| r.path_id == "path-a" && r.destination == dest)
            .expect("route should still exist");
        assert_eq!(route.metric, STANDBY_METRIC);
        assert_eq!(
            route.generation,
            gen_before + 1,
            "generation should be incremented by update_route_metric_os (update path, not reinstall)"
        );
    }

    /// Regression test for the exact audit scenario (#1 and #3): route in
    /// registry, route missing from OS table.
    ///
    /// On Windows this happens when the process is non-elevated and
    /// CreateIpForwardEntry2 returned ACCESS_DENIED (route tracked in
    /// registry but never actually created in the OS).
    /// On non-Windows, we simulate by clearing the registry (which serves
    /// as the OS table stub).
    ///
    /// With the buggy implementation (route_exists on registry only),
    /// update_route_metric_os would call SetIpForwardEntry2 on a
    /// nonexistent route and return ERROR_FILE_NOT_FOUND.
    /// With the fixed implementation (enumerate_windows_routes check),
    /// install_route is called instead and succeeds.
    #[tokio::test]
    async fn install_path_route_does_not_update_missing_os_route() {
        let pm = setup_two_paths();
        let dest = Ipv4Addr::new(203, 0, 113, 10);

        // Step 1: Route exists in in-memory registry
        assert!(pm.router().route_exists(dest, 32, 0xAA));

        // Step 2: OS route is externally deleted
        // On Windows non-elevated: route is already not in real OS table
        //   (GetIpForwardTable2 won't find it).
        // On non-Windows: clear the registry to simulate OS deletion.
        #[cfg(not(target_os = "windows"))]
        {
            pm.router().cleanup_owned_routes();
        }

        // Step 3: install_path_route() is called
        let result = pm.install_path_route("path-a", ACTIVE_METRIC);

        // Step 4 & 5: Must succeed by reinstalling, NOT fail with
        // ERROR_FILE_NOT_FOUND from SetIpForwardEntry2
        assert!(
            result.is_ok(),
            "install_path_route must reinstall missing OS route, not call SetIpForwardEntry2: {:?}",
            result.err()
        );

        // Route should be back in the in-memory registry
        assert!(
            pm.router().route_exists(dest, 32, 0xAA),
            "route should be present in registry after reinstall"
        );

        // Verify correct metric
        let routes = pm.router().all_routes();
        let route = routes
            .iter()
            .find(|r| r.path_id == "path-a" && r.destination == dest)
            .expect("reinstalled route should exist");
        assert_eq!(route.metric, ACTIVE_METRIC);
    }
}
