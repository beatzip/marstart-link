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
mod profiles;
mod ringbuf;
mod route_registry;
mod routes;
mod snapshot;
mod utils;
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
use crate::profiles::{load_profile, EndpointSpec, Profile};
use crate::route_registry::RouteRegistry;
use crate::routes::{RouteEvaluation, RouteManager, RouteState};
use crate::snapshot::{RouteSnapshotEngine, Snapshot};
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

    let tunnel = tokio::task::spawn_blocking(move || wireguard::WireGuardTunnel::new(&profile))
        .await
        .map_err(|e| e.to_string())??;

    let (tunnel, connect_result) = tokio::task::spawn_blocking(move || {
        let mut tunnel = tunnel;
        let result = tunnel.connect();
        (tunnel, result)
    })
    .await
    .map_err(|e| e.to_string())?;

    if let Err(e) = connect_result {
        let _ = tokio::task::spawn_blocking(move || tunnel.teardown()).await;
        return Err(e);
    }

    let mut guard = state.tunnel.lock().map_err(|e| e.to_string())?;
    *guard = Some(tunnel);

    Ok(())
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    let _op = state.tunnel_op.lock().await;
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
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            connect,
            disconnect,
            get_status,
            get_connection_info,
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
            route_snapshot
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
