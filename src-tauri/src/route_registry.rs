//! RouteRegistry — unified coordinator for route/endpoint management.
//!
//! Provides a single entry point for updating endpoints, synchronizing
//! MonitorService, RouteSnapshotEngine, RouteManager, and LoadBalancer.

use crate::loadbalance::LoadBalancer;
use crate::metrics::MetricsStore;
use crate::monitor::{MonitorService, MonitorTarget};
use crate::profiles::EndpointSpec;
use crate::routes::{RouteEvaluation, RouteManager, RouteState};
use crate::snapshot::RouteSnapshotEngine;
use serde::Serialize;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize)]
pub struct RegistryState {
    pub endpoint_count: usize,
    pub cooldown_ms: u64,
    pub switch_margin: f32,
}

pub struct RouteRegistry {
    monitor: MonitorService,
    snapshot: Arc<RouteSnapshotEngine>,
    routes: Arc<RouteManager>,
    lb: Arc<LoadBalancer>,
    initialized: AtomicBool,
}

impl RouteRegistry {
    pub fn new(
        _metrics: MetricsStore,
        monitor: MonitorService,
        snapshot: Arc<RouteSnapshotEngine>,
        routes: Arc<RouteManager>,
        lb: Arc<LoadBalancer>,
    ) -> Arc<Self> {
        Arc::new(Self {
            monitor,
            snapshot,
            routes,
            lb,
            initialized: AtomicBool::new(false),
        })
    }

    /// Set endpoints as the single source of truth. Updates all subsystems atomically.
    pub fn set_endpoints(&self, specs: Vec<EndpointSpec>) -> Result<(), String> {
        // Convert EndpointSpec to MonitorTarget
        let targets: Vec<MonitorTarget> = specs
            .iter()
            .map(|spec| MonitorTarget {
                id: spec.id.clone(),
                addr: spec.addr.ip(),
                fallback_port: spec.addr.port(),
            })
            .collect();

        // Update all subsystems
        self.routes.set_candidates(specs);
        self.snapshot
            .set_targets(targets.iter().map(|t| t.id.clone()).collect());
        self.monitor.set_targets(targets);

        self.initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    pub fn route_state(&self) -> RouteState {
        self.routes.state()
    }

    pub fn route_eval(&self) -> RouteEvaluation {
        self.routes.evaluate()
    }

    pub fn state(&self) -> RegistryState {
        RegistryState {
            endpoint_count: self.routes.state().candidates.len(),
            cooldown_ms: self.routes.state().cooldown_ms,
            switch_margin: self.routes.state().switch_margin,
        }
    }
}
