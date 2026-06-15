//! Sticky flow-based load balancing across routes.
//!
//! Snapshot-only: decisions consume `Snapshot::routes` for health and
//! score, never `RouteManager`. Owns `FlowKey -> route_id` bindings and
//! applies the active strategy when picking a route for a new flow.
//! Bad routes are evicted from bindings on `rebind_bad()` and flows
//! are re-picked via the strategy.

use crate::snapshot::{Health, RouteSnapshot, RouteSnapshotEngine, Snapshot};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum LbStrategy {
    RoundRobin,
    #[default]
    LeastLatency,
    WeightedHash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowBinding {
    pub flow: FlowKey,
    pub route_id: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LbState {
    pub strategy: LbStrategy,
    pub bindings_count: usize,
    pub rr_counter: usize,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct RebindResult {
    pub rebound: usize,
    pub dropped: usize,
}

struct LbInner {
    bindings: HashMap<FlowKey, FlowBinding>,
    strategy: LbStrategy,
}

pub struct LoadBalancer {
    snapshot: Arc<RouteSnapshotEngine>,
    inner: RwLock<LbInner>,
    weights: RwLock<HashMap<String, f32>>,
    rr_counter: AtomicUsize,
}

impl LoadBalancer {
    pub fn new(snapshot: Arc<RouteSnapshotEngine>) -> Arc<Self> {
        Arc::new(Self {
            snapshot,
            inner: RwLock::new(LbInner {
                bindings: HashMap::new(),
                strategy: LbStrategy::default(),
            }),
            weights: RwLock::new(HashMap::new()),
            rr_counter: AtomicUsize::new(0),
        })
    }

    pub fn set_strategy(&self, s: LbStrategy) {
        self.inner.write().strategy = s;
    }

    pub fn strategy(&self) -> LbStrategy {
        self.inner.read().strategy
    }

    pub fn set_route_weights(&self, w: HashMap<String, f32>) {
        *self.weights.write() = w;
    }

    pub fn register_flow(&self, flow: FlowKey) -> Option<FlowBinding> {
        if let Some(existing) = self.inner.read().bindings.get(&flow).cloned() {
            return Some(existing);
        }
        let snap = self.snapshot.current();
        let route_id = self.pick_route(&flow, &snap, false)?;
        let binding = FlowBinding {
            flow,
            route_id,
            created_at_ms: chrono::Utc::now().timestamp_millis(),
        };
        self.inner
            .write()
            .bindings
            .insert(binding.flow, binding.clone());
        Some(binding)
    }

    pub fn unregister_flow(&self, flow: &FlowKey) -> bool {
        self.inner.write().bindings.remove(flow).is_some()
    }

    pub fn list_flows(&self) -> Vec<FlowBinding> {
        self.inner.read().bindings.values().cloned().collect()
    }

    pub fn state(&self) -> LbState {
        let g = self.inner.read();
        LbState {
            strategy: g.strategy,
            bindings_count: g.bindings.len(),
            rr_counter: self.rr_counter.load(Ordering::Relaxed),
        }
    }

    pub fn rebind_bad(&self) -> RebindResult {
        let snap = self.snapshot.current();
        let bad: HashSet<String> = snap
            .routes
            .iter()
            .filter(|r| r.health == Health::Bad)
            .map(|r| r.route_id.clone())
            .collect();
        if bad.is_empty() {
            return RebindResult {
                rebound: 0,
                dropped: 0,
            };
        }
        let affected: Vec<FlowKey> = {
            let g = self.inner.read();
            g.bindings
                .iter()
                .filter(|(_, b)| bad.contains(&b.route_id))
                .map(|(k, _)| *k)
                .collect()
        };
        let mut updates: Vec<(FlowKey, Option<String>)> = Vec::with_capacity(affected.len());
        for flow in affected {
            let new_id = self.pick_route(&flow, &snap, true);
            updates.push((flow, new_id));
        }
        let mut rebound = 0usize;
        let mut dropped = 0usize;
        {
            let mut g = self.inner.write();
            for (flow, new_id) in updates {
                match new_id {
                    Some(id) => {
                        if let Some(b) = g.bindings.get_mut(&flow) {
                            b.route_id = id;
                            b.created_at_ms = chrono::Utc::now().timestamp_millis();
                            rebound += 1;
                        }
                    }
                    None => {
                        g.bindings.remove(&flow);
                        dropped += 1;
                    }
                }
            }
        }
        RebindResult { rebound, dropped }
    }

    fn pick_route(&self, flow: &FlowKey, snap: &Snapshot, strict: bool) -> Option<String> {
        let strategy = self.inner.read().strategy;
        if snap.routes.is_empty() {
            return None;
        }
        let healthy: Vec<&RouteSnapshot> = snap
            .routes
            .iter()
            .filter(|r| r.health != Health::Bad)
            .collect();
        let candidates: Vec<&RouteSnapshot> = if healthy.is_empty() {
            if strict {
                return None;
            }
            snap.routes.iter().collect()
        } else {
            healthy
        };
        match strategy {
            LbStrategy::RoundRobin => self.pick_round_robin(&candidates),
            LbStrategy::LeastLatency => self.pick_least_latency(&candidates),
            LbStrategy::WeightedHash => self.pick_weighted_hash(flow, &candidates),
        }
    }

    fn pick_round_robin(&self, candidates: &[&RouteSnapshot]) -> Option<String> {
        if candidates.is_empty() {
            return None;
        }
        let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
        Some(candidates[idx].route_id.clone())
    }

    fn pick_least_latency(&self, candidates: &[&RouteSnapshot]) -> Option<String> {
        candidates
            .iter()
            .min_by(|a, b| {
                a.score
                    .partial_cmp(&b.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|r| r.route_id.clone())
    }

    fn pick_weighted_hash(&self, flow: &FlowKey, candidates: &[&RouteSnapshot]) -> Option<String> {
        if candidates.is_empty() {
            return None;
        }
        let mut h = DefaultHasher::new();
        flow.hash(&mut h);
        let h_val = h.finish();
        let weights = self.weights.read();
        let mut total: u64 = 0;
        let mut scaled: Vec<u64> = Vec::with_capacity(candidates.len());
        for r in candidates {
            let w = (weights.get(&r.route_id).copied().unwrap_or(1.0) * 1000.0) as u64;
            total = total.saturating_add(w);
            scaled.push(w);
        }
        if total == 0 {
            return candidates.first().map(|r| r.route_id.clone());
        }
        let target = h_val % total;
        let mut acc: u64 = 0;
        for (r, w) in candidates.iter().zip(scaled.iter()) {
            acc = acc.saturating_add(*w);
            if target < acc {
                return Some(r.route_id.clone());
            }
        }
        candidates.last().map(|r| r.route_id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{MetricsStore, PingSample};
    use crate::snapshot::RouteSnapshotEngine;
    use chrono::Utc;
    use std::net::Ipv4Addr;

    fn push_ok(m: &MetricsStore, id: &str, rtt_ms: f32) {
        m.push(
            id,
            PingSample {
                rtt_ms: Some(rtt_ms),
                timestamp_ms: Utc::now().timestamp_millis(),
            },
        );
    }

    fn push_lost(m: &MetricsStore, id: &str) {
        m.push(
            id,
            PingSample {
                rtt_ms: None,
                timestamp_ms: Utc::now().timestamp_millis(),
            },
        );
    }

    fn seed_good(m: &MetricsStore, id: &str, rtt: f32) {
        for _ in 0..10 {
            push_ok(m, id, rtt);
        }
    }

    fn seed_bad(m: &MetricsStore, id: &str) {
        for _ in 0..3 {
            push_ok(m, id, 30.0);
        }
        for _ in 0..7 {
            push_lost(m, id);
        }
    }

    fn make_lb(route_ids: &[&str]) -> (Arc<LoadBalancer>, MetricsStore, Arc<RouteSnapshotEngine>) {
        let metrics = MetricsStore::new();
        let snap = RouteSnapshotEngine::new(metrics.clone());
        let lb = LoadBalancer::new(Arc::clone(&snap));
        snap.set_targets(route_ids.iter().map(|s| s.to_string()).collect());
        (lb, metrics, snap)
    }

    fn flow(seed: u8) -> FlowKey {
        FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, seed)),
            src_port: 1000 + seed as u16,
            dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            dst_port: 443,
            proto: 6,
        }
    }

    fn force_bad(metrics: &MetricsStore, snap: &RouteSnapshotEngine, id: &str) {
        for _ in 0..30 {
            push_lost(metrics, id);
        }
        for _ in 0..4 {
            let _ = snap.refresh_now();
        }
        assert_eq!(snap.current().health_of(id), Health::Bad);
    }

    #[test]
    fn sticky_reregister_returns_same_route() {
        let (lb, metrics, snap) = make_lb(&["a", "b", "c"]);
        seed_good(&metrics, "a", 20.0);
        seed_good(&metrics, "b", 30.0);
        seed_good(&metrics, "c", 40.0);
        let _ = snap.refresh_now();
        let f = flow(1);
        let b1 = lb.register_flow(f).expect("should bind");
        let b2 = lb.register_flow(f).expect("should be sticky");
        assert_eq!(b1.route_id, b2.route_id);
        assert_eq!(lb.state().bindings_count, 1);
    }

    #[test]
    fn rebind_bad_moves_flow_to_healthy_route() {
        let (lb, metrics, snap) = make_lb(&["a", "b"]);
        seed_good(&metrics, "a", 20.0);
        seed_good(&metrics, "b", 30.0);
        let _ = snap.refresh_now();
        let f = flow(1);
        let binding = lb.register_flow(f).unwrap();
        assert_eq!(binding.route_id, "a");
        force_bad(&metrics, &snap, "a");
        let r = lb.rebind_bad();
        assert_eq!(r.rebound, 1);
        assert_eq!(r.dropped, 0);
        let flows = lb.list_flows();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].route_id, "b");
    }

    #[test]
    fn rebind_bad_drops_when_no_alternative() {
        let (lb, metrics, snap) = make_lb(&["a"]);
        seed_good(&metrics, "a", 20.0);
        let _ = snap.refresh_now();
        lb.register_flow(flow(1)).unwrap();
        force_bad(&metrics, &snap, "a");
        let r = lb.rebind_bad();
        assert_eq!(r.rebound, 0);
        assert_eq!(r.dropped, 1);
        assert_eq!(lb.state().bindings_count, 0);
    }

    #[test]
    fn rebind_bad_noop_when_all_healthy() {
        let (lb, metrics, snap) = make_lb(&["a", "b"]);
        seed_good(&metrics, "a", 20.0);
        seed_good(&metrics, "b", 30.0);
        let _ = snap.refresh_now();
        lb.register_flow(flow(1)).unwrap();
        lb.register_flow(flow(2)).unwrap();
        let r = lb.rebind_bad();
        assert_eq!(r.rebound, 0);
        assert_eq!(r.dropped, 0);
        assert_eq!(lb.state().bindings_count, 2);
    }

    #[test]
    fn round_robin_cycles_through_routes() {
        let (lb, metrics, snap) = make_lb(&["a", "b", "c"]);
        seed_good(&metrics, "a", 20.0);
        seed_good(&metrics, "b", 30.0);
        seed_good(&metrics, "c", 40.0);
        let _ = snap.refresh_now();
        lb.set_strategy(LbStrategy::RoundRobin);
        let mut counts: HashMap<String, usize> = HashMap::new();
        for i in 0..6 {
            let f = flow(i + 1);
            if let Some(b) = lb.register_flow(f) {
                *counts.entry(b.route_id).or_insert(0) += 1;
            }
        }
        assert_eq!(counts.len(), 3, "RR should hit all 3 routes across 6 flows");
    }

    #[test]
    fn least_latency_picks_lowest_score() {
        let (lb, metrics, snap) = make_lb(&["a", "b", "c"]);
        seed_good(&metrics, "a", 50.0);
        seed_good(&metrics, "b", 20.0);
        seed_good(&metrics, "c", 100.0);
        let _ = snap.refresh_now();
        lb.set_strategy(LbStrategy::LeastLatency);
        for i in 0..5 {
            let f = flow(i + 1);
            let b = lb.register_flow(f).unwrap();
            assert_eq!(b.route_id, "b");
        }
    }

    #[test]
    fn weighted_hash_same_flow_same_route() {
        let (lb, metrics, snap) = make_lb(&["a", "b", "c"]);
        seed_good(&metrics, "a", 20.0);
        seed_good(&metrics, "b", 30.0);
        seed_good(&metrics, "c", 40.0);
        let _ = snap.refresh_now();
        lb.set_strategy(LbStrategy::WeightedHash);
        let f = flow(7);
        let b1 = lb.register_flow(f).unwrap();
        let b2 = lb.register_flow(f).unwrap();
        assert_eq!(b1.route_id, b2.route_id);
    }

    #[test]
    fn weighted_hash_weight_zero_excludes_route() {
        let (lb, metrics, snap) = make_lb(&["a", "b"]);
        seed_good(&metrics, "a", 20.0);
        seed_good(&metrics, "b", 30.0);
        let _ = snap.refresh_now();
        let mut weights = HashMap::new();
        weights.insert("a".to_string(), 0.0);
        weights.insert("b".to_string(), 1.0);
        lb.set_route_weights(weights);
        lb.set_strategy(LbStrategy::WeightedHash);
        for i in 0..10 {
            let f = flow(i + 1);
            let b = lb.register_flow(f).expect("bind exists");
            assert_eq!(b.route_id, "b", "flow {} landed on a (weight 0)", i);
        }
    }

    #[test]
    fn unregister_flow_removes_binding() {
        let (lb, metrics, snap) = make_lb(&["a"]);
        seed_good(&metrics, "a", 20.0);
        let _ = snap.refresh_now();
        let f = flow(1);
        lb.register_flow(f).unwrap();
        assert_eq!(lb.state().bindings_count, 1);
        assert!(lb.unregister_flow(&f));
        assert_eq!(lb.state().bindings_count, 0);
        assert!(!lb.unregister_flow(&f));
    }
}
