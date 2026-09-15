#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]
#![allow(dead_code)]

mod autopilot;
mod events;
mod game_detection;
mod loadbalance;
mod metrics;
mod monitor;
mod net_probe;
mod path_manager;
mod profiles;
mod ringbuf;
mod route_registry;
mod routes;
mod snapshot;
mod utils;
mod windows_route_manager;
mod wireguard;
mod wireguard_config;
mod wireguard_parser;
mod wireguard_serializer;

use crate::autopilot::{Autopilot, AutopilotDecision, AutopilotIntent};
use crate::events::{EV_AUTOPILOT_ACTION, EV_AUTOPILOT_STATE};
use crate::game_detection::{GameDetector, GameProfile, GameSignal};
use crate::loadbalance::{FlowBinding, FlowKey, LbState, LbStrategy, LoadBalancer};
use crate::metrics::{AggregatedMetrics, MetricsStore};
use crate::monitor::{MonitorConfig, MonitorService, MonitorState, MonitorTarget};
use crate::path_manager::{Path, PathManager};
use crate::profiles::{load_profile, EndpointSpec, Profile};
use crate::route_registry::RouteRegistry;
use crate::routes::{RouteEvaluation, RouteManager, RouteState};
use crate::snapshot::{RouteSnapshotEngine, Snapshot};
use crate::windows_route_manager::SwitchResult;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::task::JoinHandle;

fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        let thread_name = thread.name().unwrap_or("<unnamed>");
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "Box<dyn Any>".to_string());
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown>".to_string());
        let backtrace = std::backtrace::Backtrace::force_capture();
        eprintln!(
            "[PANIC] thread={thread_name} payload={payload} location={location}\n{backtrace}"
        );
        default_hook(info);
    }));
}

#[derive(Clone)]
struct AppState {
    tunnel: Arc<Mutex<Option<wireguard::WireGuardTunnel>>>,
    tunnel_op: Arc<tokio::sync::Mutex<()>>,
    /// SD-WAN multi-adapter path manager (Phase 1 datapath).
    paths: Arc<PathManager>,
    /// Additional WireGuardTunnel instances (beyond the primary) kept alive.
    /// These are the standby paths that remain UP for failover.
    extra_tunnels: Arc<Mutex<Vec<wireguard::WireGuardTunnel>>>,
    metrics: MetricsStore,
    monitor: MonitorService,
    snapshot: Arc<RouteSnapshotEngine>,
    routes: Arc<RouteManager>,
    game: Arc<GameDetector>,
    lb: Arc<LoadBalancer>,
    autopilot: Arc<Autopilot>,
    autopilot_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    registry: Arc<RouteRegistry>,
}

#[derive(Debug, Clone, Serialize)]
struct PlaceholderState {
    enabled: bool,
    message: &'static str,
}

#[tauri::command]
async fn connect(
    profile_id: Option<String>,
    profile: Option<Profile>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let _op = state.tunnel_op.lock().await;

    if state
        .tunnel
        .lock()
        .map_err(|e| e.to_string())?
        .as_ref()
        .is_some_and(|t| {
            matches!(
                t.status(),
                wireguard::TunnelStatus::Connected | wireguard::TunnelStatus::Connecting
            )
        })
    {
        return Err("tunnel is already active".to_string());
    }

    let profile = match (profile, profile_id) {
        (Some(profile), _) => profile,
        (None, Some(profile_id)) => load_profile(&profile_id)?,
        (None, None) => load_profile("default")?,
    };

    // SD-WAN Phase 1: Create one WireGuardTunnel per config path.
    // Each tunnel becomes a Path in PathManager. Both tunnels are
    // kept UP; the Windows route table selects the active path.
    let config_paths = profile.get_config_paths();

    // Phase 1: support at least 2 paths (multi-adapter)
    let max_paths = 2;
    let n_paths = config_paths.len().min(max_paths);

    let path_ids: Vec<String> = (0..n_paths)
        .map(|i| {
            if i < 26 {
                format!("path-{}", (b'a' + i as u8) as char)
            } else {
                format!("path-{}", i)
            }
        })
        .collect();

    // Clear any existing paths from a previous session
    let _ = state.paths.clear_paths();

    let mut tunnels: Vec<wireguard::WireGuardTunnel> = Vec::new();
    let mut registered_path_ids: Vec<String> = Vec::new();

    for (i, cfg_path) in config_paths.into_iter().take(n_paths).enumerate() {
        // Create a single-config profile for this path
        let single_profile = Profile {
            id: profile.id.clone(),
            display_name: profile.display_name.clone(),
            endpoints: profile.endpoints.clone(),
            wg_config_path: Some(cfg_path.clone()),
            wg_config_paths: vec![cfg_path.clone()],
            managed_destination: profile.managed_destination.clone(),
        };

        let path_id = path_ids[i].clone();

        let tunnel =
            tokio::task::spawn_blocking(move || wireguard::WireGuardTunnel::new(&single_profile))
                .await
                .map_err(|e| e.to_string())??;

        tunnels.push(tunnel);

        // Register this path in PathManager (without LUID yet)
        if let Err(e) = state.paths.add_path(&path_id, &profile.id) {
            // Partial failure: clean up tunnels and paths already created
            // to avoid stale state.
            for t in tunnels {
                let _ = tokio::task::spawn_blocking(move || t.teardown())
                    .await
                    .map_err(|e| tracing::error!("teardown error during connect failure: {}", e));
            }
            let _ = state.paths.clear_paths();
            return Err(format!(
                "connect: failed to register path '{}': {}",
                path_id, e
            ));
        }
        registered_path_ids.push(path_id);
    }

    // Connect each tunnel and get its adapter LUID
    let mut connected: Vec<wireguard::WireGuardTunnel> = Vec::new();
    for (i, mut tunnel) in tunnels.into_iter().enumerate() {
        let path_id = path_ids[i].clone();

        let (tunnel, connect_result) = tokio::task::spawn_blocking(move || {
            let result = tunnel.connect();
            (tunnel, result)
        })
        .await
        .map_err(|e| e.to_string())?;

        if let Err(e) = connect_result {
            // Tear down all tunnels created so far
            for t in connected.into_iter() {
                let _ = tokio::task::spawn_blocking(move || t.teardown())
                    .await
                    .map_err(|e| tracing::error!("teardown error during connect failure: {}", e));
            }
            let _ = tokio::task::spawn_blocking(move || tunnel.teardown())
                .await
                .map_err(|e| tracing::error!("teardown error during connect failure: {}", e));
            // Clean up partially registered paths to prevent stale state
            let _ = state.paths.clear_paths();
            return Err(e);
        }

        // Get the adapter LUID via WireGuardGetAdapterLUID
        let luid = tunnel.get_adapter_luid().unwrap_or_else(|e| {
            tracing::warn!(
                "connect: failed to get adapter LUID for path '{}': {} — \
                 tunnel state may be unusable for routing",
                path_id,
                e
            );
            0
        });
        let index = 0u32; // LUID is sufficient; index resolved via GetAdaptersAddresses if needed

        if luid == 0 {
            tracing::warn!(
                "connect: path '{}' has LUID 0 — adapter may not be ready. \
                 Route installation will be skipped by failover validation.",
                path_id
            );
        }

        // Connect the path in PathManager
        if let Err(e) = state.paths.connect_path(&path_id, luid, index) {
            // Clean up tunnels already connected
            for t in connected.into_iter() {
                let _ = tokio::task::spawn_blocking(move || t.teardown())
                    .await
                    .map_err(|e| tracing::error!("teardown error during connect failure: {}", e));
            }
            let _ = tokio::task::spawn_blocking(move || tunnel.teardown())
                .await
                .map_err(|e| tracing::error!("teardown error during connect failure: {}", e));
            // Clean up partially registered paths
            let _ = state.paths.clear_paths();
            return Err(format!(
                "connect: failed to connect path '{}': {}",
                path_id, e
            ));
        }

        // Set the managed destination if available
        if let Some(dest_str) = &profile.managed_destination {
            if let Some((dest_ip, prefix_len)) = parse_destination(dest_str) {
                let _ = state.paths.set_destination(&path_id, dest_ip, prefix_len);
            }
        }

        connected.push(tunnel);
    }

    // Store the primary tunnel for backward compatibility
    let primary_tunnel = connected.remove(0);
    let mut guard = state.tunnel.lock().map_err(|e| e.to_string())?;
    *guard = Some(primary_tunnel);
    drop(guard);

    // Store remaining tunnels so they stay UP (not dropped)
    state
        .extra_tunnels
        .lock()
        .map_err(|e| e.to_string())?
        .extend(connected);

    // Activate the first path as active, others as standby
    if let Some(first) = path_ids.first() {
        let _ = state.paths.activate_path(first);
    }

    // Phase 3: Reconcile routes after path activation to ensure
    // OS routing table matches the intended active/standby state.
    let reconcile_actions = state.paths.enumerate_and_reconcile();
    for action in &reconcile_actions {
        tracing::info!("post-connect reconcile: {}", action);
    }

    Ok(())
}

/// Parses a destination CIDR string like "203.0.113.0/24" into (Ipv4Addr, u8).
fn parse_destination(s: &str) -> Option<(std::net::Ipv4Addr, u8)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let addr: std::net::Ipv4Addr = parts[0].parse().ok()?;
    let prefix: u8 = parts[1].parse().ok()?;
    Some((addr, prefix))
}

/// Test-only: Connects two WireGuard tunnels using configuration paths
/// supplied via environment variables.
///
/// Environment variables:
///   `MARSTART_PATH_A_CONFIG` — Path A WireGuard .conf path
///   `MARSTART_PATH_B_CONFIG` — Path B WireGuard .conf path
///   `MARSTART_MANAGED_DESTINATION` — destination CIDR (optional)
///
/// This command does NOT accept credentials via IPC. All secrets remain
/// inside the .conf files on the external filesystem.
#[cfg(any(test, target_os = "windows"))]
#[tauri::command]
async fn connect_test(state: State<'_, AppState>) -> Result<(), String> {
    let profile = Profile::from_test_env()?;
    connect(None, Some(profile), state).await
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    let _op = state.tunnel_op.lock().await;

    // Tear down the primary tunnel
    let tunnel = {
        let mut guard = state.tunnel.lock().map_err(|e| e.to_string())?;
        guard.take()
    };

    if let Some(tunnel) = tunnel {
        let _ = tokio::task::spawn_blocking(move || tunnel.teardown())
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string());
    }

    // Tear down extra tunnels (standby paths)
    let extra_tunnels: Vec<wireguard::WireGuardTunnel> = {
        let mut guard = state.extra_tunnels.lock().map_err(|e| e.to_string())?;
        guard.drain(..).collect()
    };
    for tunnel in extra_tunnels {
        let _ = tokio::task::spawn_blocking(move || tunnel.teardown())
            .await
            .map_err(|e| e.to_string())?;
    }

    // Clear all paths from PathManager (removes routes from in-memory
    // registry; on elevated Windows, DeleteIpForwardEntry2 removes from
    // OS table; on non-elevated, ACCESS_DENIED is treated as non-fatal)
    let _ = state.paths.clear_paths();

    // Reconcile to clean up any orphaned OS routes that could not be
    // removed by clear_paths() (e.g., on non-elevated Windows where
    // DeleteIpForwardEntry2 returns ACCESS_DENIED).
    // Since all paths are now cleared, any remaining MARSTART-owned
    // OS routes will be detected as orphans and removed.
    let reconcile_actions = state.paths.enumerate_and_reconcile();
    for action in &reconcile_actions {
        tracing::info!("post-disconnect reconcile: {}", action);
    }

    Ok(())
}

#[tauri::command]
fn get_status(state: State<'_, AppState>) -> Result<wireguard::TunnelStatus, String> {
    let guard = state.tunnel.lock().map_err(|e| e.to_string())?;
    Ok(if let Some(t) = &*guard {
        t.status()
    } else {
        wireguard::TunnelStatus::Disconnected
    })
}

#[tauri::command]
fn get_connection_info(
    state: State<'_, AppState>,
) -> Result<Option<wireguard::ConnectionInfo>, String> {
    let guard = state.tunnel.lock().map_err(|e| e.to_string())?;
    guard
        .as_ref()
        .map(|tunnel| tunnel.connection_info())
        .transpose()
}

/// Pre-flight driver status diagnostic command.
///
/// Checks whether `wireguard.dll` is present and loadable, whether the
/// WireGuard-NT kernel driver is loaded, and whether the process has
/// Administrator privileges.  Returns a structured [`wireguard::DriverStatus`].
///
/// This command does NOT create an adapter or install anything — it is a
/// pure read-only check suitable for display at application startup.
#[tauri::command]
fn wireguard_driver_status() -> wireguard::DriverStatus {
    wireguard::wireguard_driver_status()
}

/// Deletes the WireGuard-NT kernel driver if no adapters are in use.
/// Requires Administrator privileges.  Returns Ok(()) on success or an
/// error string on failure.  Intended for clean uninstall scenarios.
#[tauri::command]
fn wireguard_delete_driver() -> Result<(), String> {
    wireguard::wireguard_delete_driver()
}

/// Runtime smoke-test / diagnostic command.
///
/// Creates a short-lived WireGuardTunnel from the given profile (or "default"),
/// exercises the full FFI lifecycle, and returns a structured
/// [`wireguard::DiagnosticsReport`] with per-step pass/fail flags.
/// The tunnel is torn down before this function returns — no orphaned adapter
/// remains.  Safe to call while no other tunnel is connected.
#[tauri::command]
async fn tunnel_diagnostics(
    profile_id: Option<String>,
    profile: Option<Profile>,
    state: State<'_, AppState>,
) -> Result<wireguard::DiagnosticsReport, String> {
    let _op = state.tunnel_op.lock().await;

    let profile = match (profile, profile_id) {
        (Some(profile), _) => profile,
        (None, Some(profile_id)) => load_profile(&profile_id)?,
        (None, None) => load_profile("default")?,
    };

    wireguard::run_diagnostics(&profile)
}

#[tauri::command]
fn monitor_get_snapshot(state: State<'_, AppState>) -> Vec<AggregatedMetrics> {
    state.metrics.aggregated_all()
}

#[tauri::command]
fn monitor_get_state(state: State<'_, AppState>) -> MonitorState {
    state.monitor.snapshot_state()
}

#[tauri::command]
fn monitor_set_targets(
    targets: Vec<MonitorTarget>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // Convert MonitorTarget to EndpointSpec for registry
    let specs: Vec<EndpointSpec> = targets
        .iter()
        .map(|t| EndpointSpec {
            id: t.id.clone(),
            addr: std::net::SocketAddr::new(t.addr, t.fallback_port),
            label: String::new(),
            weight: 1.0,
        })
        .collect();
    state.registry.set_endpoints(specs)?;
    Ok(())
}

#[tauri::command]
fn monitor_start(
    config: Option<MonitorConfig>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<MonitorState, String> {
    if let Some(config) = config {
        state
            .monitor
            .set_interval(config.interval_ms, config.probe_timeout_ms);
        // Convert MonitorTarget to EndpointSpec and use registry
        let specs: Vec<EndpointSpec> = config
            .targets
            .into_iter()
            .map(|t| EndpointSpec {
                id: t.id,
                addr: std::net::SocketAddr::new(t.addr, t.fallback_port),
                label: String::new(),
                weight: 1.0,
            })
            .collect();
        state.registry.set_endpoints(specs)?;
    }
    state.monitor.start(app)?;
    Ok(state.monitor.snapshot_state())
}

#[tauri::command]
fn monitor_stop(app: AppHandle, state: State<'_, AppState>) -> MonitorState {
    state.monitor.stop(&app);
    state.monitor.snapshot_state()
}

#[tauri::command]
fn routes_set_candidates(
    candidates: Vec<EndpointSpec>,
    state: State<'_, AppState>,
) -> Result<RouteState, String> {
    // Use RouteRegistry for coordinated update
    state.registry.set_endpoints(candidates)?;
    Ok(state.registry.route_state())
}

#[tauri::command]
fn routes_list(state: State<'_, AppState>) -> RouteEvaluation {
    state.routes.evaluate()
}

#[tauri::command]
fn routes_get_state(state: State<'_, AppState>) -> RouteState {
    state.routes.state()
}

#[tauri::command]
fn routes_select_manual(
    id: Option<String>,
    state: State<'_, AppState>,
) -> Result<RouteState, String> {
    if let Some(id) = id {
        state.routes.select_manual(&id)?;
        state.routes.commit(Some(id));
    } else {
        state.routes.clear_manual();
    }
    Ok(state.routes.state())
}

#[tauri::command]
fn game_list_profiles(state: State<'_, AppState>) -> Vec<GameProfile> {
    state.game.list_profiles()
}

#[tauri::command]
fn game_add_profile(profile: GameProfile, state: State<'_, AppState>) -> Vec<GameProfile> {
    state.game.register_profile(profile);
    state.game.list_profiles()
}

#[tauri::command]
fn game_remove_profile(id: String, state: State<'_, AppState>) -> Vec<GameProfile> {
    state.game.unregister_profile(&id);
    state.game.list_profiles()
}

#[tauri::command]
fn game_get_state(state: State<'_, AppState>) -> GameSignal {
    state.game.current()
}

#[tauri::command]
fn game_force_active(game_id: Option<String>, state: State<'_, AppState>) -> GameSignal {
    if let Some(id) = game_id {
        let matches = state
            .game
            .list_profiles()
            .into_iter()
            .find(|profile| profile.id == id)
            .map(|profile| profile.process_names)
            .unwrap_or_default();
        state.game.set_cached_matches(matches);
    }
    state.game.compute_signal()
}

#[tauri::command]
fn lb_set_strategy(strategy: LbStrategy, state: State<'_, AppState>) -> LbState {
    state.lb.set_strategy(strategy);
    state.lb.state()
}

#[tauri::command]
fn lb_register_flow(flow: FlowKey, state: State<'_, AppState>) -> Option<FlowBinding> {
    state.lb.register_flow(flow)
}

#[tauri::command]
fn lb_unregister_flow(flow: FlowKey, state: State<'_, AppState>) -> bool {
    state.lb.unregister_flow(&flow)
}

#[tauri::command]
fn lb_list_flows(state: State<'_, AppState>) -> Vec<FlowBinding> {
    state.lb.list_flows()
}

#[tauri::command]
fn autopilot_get_state(state: State<'_, AppState>) -> Option<AutopilotDecision> {
    state.autopilot.last_decision()
}

#[tauri::command]
fn autopilot_enable(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<PlaceholderState, String> {
    let autopilot = Arc::clone(&state.autopilot);
    let autopilot_handle = Arc::clone(&state.autopilot_handle);
    let snapshot = Arc::clone(&state.snapshot);
    let game = Arc::clone(&state.game);
    let routes = Arc::clone(&state.routes);
    let lb = Arc::clone(&state.lb);
    let app_clone = app.clone();

    // Check if already running
    {
        let handle_guard = autopilot_handle.lock().map_err(|e| e.to_string())?;
        if handle_guard.is_some() {
            return Ok(PlaceholderState {
                enabled: true,
                message: "autopilot already running",
            });
        }
    }

    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_millis(500));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let snap = snapshot.current();
            let game_signal = game.compute_signal();
            // Rebind flows from bad routes before autopilot decision
            let rebind_result = lb.rebind_bad();
            if rebind_result.rebound > 0 || rebind_result.dropped > 0 {
                tracing::info!(
                    "lb rebind: rebound={} dropped={}",
                    rebind_result.rebound,
                    rebind_result.dropped
                );
            }
            let decision = autopilot.update(&snap, &game_signal);
            let _ = app_clone.emit(EV_AUTOPILOT_STATE, &decision);
            let _ = app_clone.emit(EV_AUTOPILOT_ACTION, &decision);
            if decision.intent == AutopilotIntent::Switch {
                if let Some(route_id) = decision.to_route.clone() {
                    routes.commit(Some(route_id));
                }
            }
        }
    });

    *state.autopilot_handle.lock().map_err(|e| e.to_string())? = Some(handle);
    Ok(PlaceholderState {
        enabled: true,
        message: "autopilot tick controller started",
    })
}

#[tauri::command]
fn autopilot_disable(state: State<'_, AppState>) -> Result<PlaceholderState, String> {
    let handle = state
        .autopilot_handle
        .lock()
        .map_err(|e| e.to_string())?
        .take();
    if let Some(h) = handle {
        h.abort();
    }
    Ok(PlaceholderState {
        enabled: false,
        message: "autopilot tick controller stopped",
    })
}

#[tauri::command]
fn autopilot_override(
    route_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<RouteState, String> {
    routes_select_manual(route_id, state)
}

#[tauri::command]
fn route_snapshot(state: State<'_, AppState>) -> Snapshot {
    (*state.snapshot.current()).clone()
}

#[tauri::command]
fn routes_set_policy(
    cooldown_ms: Option<u64>,
    switch_margin: Option<f32>,
    state: State<'_, AppState>,
) -> RouteState {
    if let Some(cooldown_ms) = cooldown_ms {
        state.routes.set_cooldown_ms(cooldown_ms);
    }
    if let Some(switch_margin) = switch_margin {
        state.routes.set_switch_margin(switch_margin);
    }
    state.routes.state()
}

#[tauri::command]
fn qos_list_rules() -> Vec<String> {
    Vec::new()
}

#[tauri::command]
fn qos_add_rule() -> Result<PlaceholderState, String> {
    Err("QoS rule backend is not implemented yet".to_string())
}

#[tauri::command]
fn qos_remove_rule() -> Result<PlaceholderState, String> {
    Err("QoS rule backend is not implemented yet".to_string())
}

#[tauri::command]
fn qos_set_profile() -> Result<PlaceholderState, String> {
    Err("QoS profile backend is not implemented yet".to_string())
}

#[tauri::command]
fn qos_get_state() -> PlaceholderState {
    PlaceholderState {
        enabled: false,
        message: "QoS backend is not implemented yet",
    }
}

#[tauri::command]
fn multihop_set_chain() -> Result<PlaceholderState, String> {
    Err("multipath chain backend is not implemented yet".to_string())
}

#[tauri::command]
fn multihop_start() -> Result<PlaceholderState, String> {
    Err("multipath transport backend is not implemented yet".to_string())
}

#[tauri::command]
fn multihop_stop() -> PlaceholderState {
    PlaceholderState {
        enabled: false,
        message: "multipath transport backend is not implemented yet",
    }
}

#[tauri::command]
fn multihop_get_state() -> PlaceholderState {
    PlaceholderState {
        enabled: false,
        message: "multipath transport backend is not implemented yet",
    }
}

/// Phase 3: Atomic failover from one path to another with asynchronous
/// reachability verification and rollback.
///
/// After installing the new path's route with an ACTIVE metric (10),
/// the command asynchronously tests reachability by probing the managed
/// destination (ICMP echo on Windows, TCP connect fallback). If the test
/// succeeds, the old path's route is demoted to STANDBY metric (20). If
/// the test fails, the switch is rolled back so traffic continues through
/// the original path.
///
/// Both WireGuard adapters remain UP throughout — no teardown.
#[tauri::command]
async fn routes_failover(
    old_path: String,
    new_path: String,
    state: State<'_, AppState>,
) -> Result<SwitchResult, String> {
    let new_path_obj = state
        .paths
        .get_path(&new_path)
        .ok_or_else(|| format!("new path '{}' not found", new_path))?;

    let dest = new_path_obj
        .destination
        .ok_or("new path has no managed destination")?;

    let dest_ip = dest;

    state
        .paths
        .failover(&old_path, &new_path, move |_: &Path| {
            let dest = dest_ip;
            async move {
                #[cfg(target_os = "windows")]
                {
                    crate::net_probe::ping(dest.into(), std::time::Duration::from_millis(500), 80)
                        .await
                        .is_ok()
                }

                #[cfg(not(target_os = "windows"))]
                {
                    let _ = dest;
                    // Non-Windows stub — always succeeds for testing
                    true
                }
            }
        })
        .await
}

/// Phase 2: Enumerate OS-level routes and reconcile against the in-memory
/// path registry.
///
/// Calls `PathManager::enumerate_and_reconcile()` which:
/// 1. Scans the Windows routing table for MARSTART-owned routes
/// 2. Removes orphaned routes (in OS but no matching in-memory path)
/// 3. Re-installs missing routes for paths that are UP
///
/// Returns a list of action descriptions.
#[tauri::command]
fn paths_reconcile(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    Ok(state.paths.enumerate_and_reconcile())
}

/// Phase 2: Returns all path descriptors from PathManager.
#[tauri::command]
fn paths_get(state: State<'_, AppState>) -> Vec<Path> {
    state.paths.get_paths()
}

/// Phase 2: Returns a SwitchResult describing the last failover operation.
/// Since failover is synchronous, this returns an empty (default) result
/// when no failover has occurred. The actual result is returned by
/// `routes_failover()`.
#[tauri::command]
fn routes_get_switch_result(state: State<'_, AppState>) -> SwitchResult {
    let _ = &state;
    SwitchResult::default()
}

fn main() {
    install_panic_hook();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .with_ansi(false)
        .init();

    tracing::info!("MARSTART LINK starting");

    let metrics = MetricsStore::new();
    let monitor = MonitorService::new(metrics.clone());
    let snapshot = RouteSnapshotEngine::new(metrics.clone());
    let routes = RouteManager::new(metrics.clone(), Arc::clone(&snapshot));
    let game = GameDetector::new();
    let lb = LoadBalancer::new(Arc::clone(&snapshot));
    let autopilot = Autopilot::new(metrics.clone());
    let paths = Arc::new(PathManager::new());
    routes.set_paths(Arc::clone(&paths));
    let registry = RouteRegistry::new(
        metrics.clone(),
        monitor.clone(),
        Arc::clone(&snapshot),
        Arc::clone(&routes),
        Arc::clone(&lb),
    );

    let state = AppState {
        tunnel: Arc::new(Mutex::new(None)),
        tunnel_op: Arc::new(tokio::sync::Mutex::new(())),
        paths,
        extra_tunnels: Arc::new(Mutex::new(Vec::new())),
        metrics,
        monitor,
        snapshot,
        routes,
        game,
        lb,
        autopilot,
        autopilot_handle: Arc::new(Mutex::new(None)),
        registry,
    };

    match tauri::Builder::default()
        .manage(state)
        .setup(|app| {
            tracing::info!("Tauri setup called");
            let snapshot = Arc::clone(&app.state::<AppState>().snapshot);
            snapshot.start(app.handle().clone());
            tracing::info!("Snapshot engine started");

            // Phase 3: Startup crash recovery — enumerate OS routes and
            // reconcile any leftover MARSTART-owned routes from a previous
            // session. Removes orphaned routes and reinstalls missing ones
            // for any previously-known paths. At fresh startup with no
            // paths registered, this safely removes orphaned MARSTART
            // routes left behind by a crashed process.
            let paths = Arc::clone(&app.state::<AppState>().paths);
            let actions = paths.enumerate_and_reconcile();
            for action in &actions {
                tracing::info!("startup reconcile: {}", action);
            }
            if !actions.is_empty() {
                tracing::info!(
                    "startup reconcile completed: {} actions taken",
                    actions.len()
                );
            } else {
                tracing::info!("startup reconcile: no actions needed (clean state)");
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            connect,
            connect_test,
            disconnect,
            get_status,
            get_connection_info,
            tunnel_diagnostics,
            wireguard_driver_status,
            wireguard_delete_driver,
            monitor_start,
            monitor_stop,
            monitor_get_snapshot,
            monitor_get_state,
            monitor_set_targets,
            routes_list,
            routes_set_candidates,
            routes_select_manual,
            routes_get_state,
            game_list_profiles,
            game_add_profile,
            game_remove_profile,
            game_get_state,
            game_force_active,
            lb_register_flow,
            lb_unregister_flow,
            lb_list_flows,
            lb_set_strategy,
            qos_list_rules,
            qos_add_rule,
            qos_remove_rule,
            qos_set_profile,
            qos_get_state,
            routes_set_policy,
            multihop_set_chain,
            multihop_start,
            multihop_stop,
            multihop_get_state,
            autopilot_enable,
            autopilot_disable,
            autopilot_override,
            autopilot_get_state,
            route_snapshot,
            routes_failover,
            paths_reconcile,
            paths_get,
            routes_get_switch_result
        ])
        .run(tauri::generate_context!())
    {
        Ok(_) => tracing::info!("MARSTART LINK exited normally"),
        Err(e) => {
            tracing::error!("Failed to start Tauri: {e}");
            eprintln!("Failed to start MARSTART LINK: {e}");
            std::process::exit(1);
        }
    }
}
