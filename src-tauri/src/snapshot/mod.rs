//! Immutable snapshot of route health for the rest of the system.
//!
//! `RouteSnapshotEngine` periodically samples `MetricsStore`, computes
//! a per-route score, derives a hysteresis-protected health bucket,
//! and publishes an immutable `Arc<Snapshot>`. Readers (routes, lb,
//! autopilot, tick) only ever see the latest immutable snapshot.

use crate::events::{EV_ROUTE_CHANGED, EV_ROUTE_STATE};
use crate::metrics::{AggregatedMetrics, MetricsStore};
use chrono::Utc;
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::task::JoinHandle;

const HEALTH_HYSTERESIS_STREAK: u32 = 3;
const LOSS_BAD: f32 = 0.10;
const LOSS_DEGRADED: f32 = 0.03;
const RTT_BAD_MS: f32 = 200.0;
const RTT_DEGRADED_MS: f32 = 120.0;
const JITTER_DEGRADED_MS: f32 = 30.0;
const MIN_INTERVAL_MS: u64 = 100;
const MAX_INTERVAL_MS: u64 = 250;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum Health {
    Unknown,
    Good,
    Degraded,
    Bad,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteSnapshot {
    pub route_id: String,
    pub score: f32,
    pub health: Health,
    pub latest_rtt_ms: Option<f32>,
    pub avg_rtt_ms: Option<f32>,
    pub jitter_ms: f32,
    pub loss_ratio: f32,
    pub stability: f32,
    pub samples: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub routes: Vec<RouteSnapshot>,
    pub selected: Option<String>,
    pub timestamp_ms: i64,
}

impl Snapshot {
    pub fn route(&self, id: &str) -> Option<&RouteSnapshot> {
        self.routes.iter().find(|r| r.route_id == id)
    }

    pub fn health_of(&self, id: &str) -> Health {
        self.route(id).map(|r| r.health).unwrap_or(Health::Unknown)
    }

    pub fn healthy(&self) -> Vec<(String, f32)> {
        self.routes
            .iter()
            .filter(|r| matches!(r.health, Health::Good | Health::Degraded))
            .map(|r| (r.route_id.clone(), r.score))
            .collect()
    }
}

pub fn compute_score(agg: &AggregatedMetrics) -> f32 {
    let rtt = agg.avg_rtt_ms.unwrap_or(f32::INFINITY);
    rtt + agg.jitter_ms * 2.0 + agg.loss_ratio * 1000.0
}

pub fn derive_health(agg: &AggregatedMetrics) -> Health {
    if agg.samples == 0 {
        return Health::Unknown;
    }
    let rtt_bad = agg.avg_rtt_ms.map(|r| r > RTT_BAD_MS).unwrap_or(true);
    if agg.loss_ratio > LOSS_BAD || rtt_bad {
        return Health::Bad;
    }
    let rtt_deg = agg.avg_rtt_ms.map(|r| r > RTT_DEGRADED_MS).unwrap_or(false);
    if agg.loss_ratio > LOSS_DEGRADED || rtt_deg || agg.jitter_ms > JITTER_DEGRADED_MS {
        return Health::Degraded;
    }
    Health::Good
}

struct TrackedTarget {
    health: Health,
    streak: u32,
}

struct EngineState {
    targets: HashMap<String, TrackedTarget>,
}

pub struct RouteSnapshotEngine {
    metrics: MetricsStore,
    state: Arc<RwLock<EngineState>>,
    selected: Arc<RwLock<Option<String>>>,
    last_emitted_selected: Arc<RwLock<Option<String>>>,
    current: Arc<RwLock<Arc<Snapshot>>>,
    interval_ms: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    app: Arc<Mutex<Option<AppHandle>>>,
}

impl RouteSnapshotEngine {
    pub fn new(metrics: MetricsStore) -> Arc<Self> {
        let empty = Arc::new(Snapshot {
            routes: Vec::new(),
            selected: None,
            timestamp_ms: Utc::now().timestamp_millis(),
        });
        Arc::new(Self {
            metrics,
            state: Arc::new(RwLock::new(EngineState {
                targets: HashMap::new(),
            })),
            selected: Arc::new(RwLock::new(None)),
            last_emitted_selected: Arc::new(RwLock::new(None)),
            current: Arc::new(RwLock::new(empty)),
            interval_ms: Arc::new(AtomicU64::new(150)),
            running: Arc::new(AtomicBool::new(false)),
            handle: Arc::new(Mutex::new(None)),
            app: Arc::new(Mutex::new(None)),
        })
    }

    pub fn set_interval_ms(&self, ms: u64) {
        self.interval_ms.store(
            ms.clamp(MIN_INTERVAL_MS, MAX_INTERVAL_MS),
            Ordering::Relaxed,
        );
    }

    pub fn interval_ms(&self) -> u64 {
        self.interval_ms.load(Ordering::Relaxed)
    }

    pub fn set_targets(&self, ids: Vec<String>) {
        let mut g = self.state.write();
        let keep: std::collections::HashSet<String> = ids.iter().cloned().collect();
        g.targets.retain(|id, _| keep.contains(id));
        for id in ids {
            g.targets.entry(id).or_insert(TrackedTarget {
                health: Health::Unknown,
                streak: 0,
            });
        }
    }

    pub fn set_selected(&self, id: Option<String>) {
        *self.selected.write() = id;
    }

    pub fn current(&self) -> Arc<Snapshot> {
        Arc::clone(&*self.current.read())
    }

    pub fn refresh_now(&self) -> Arc<Snapshot> {
        let snap = self.compute_snapshot();
        *self.current.write() = Arc::clone(&snap);
        self.maybe_emit(&snap);
        snap
    }

    fn compute_snapshot(&self) -> Arc<Snapshot> {
        // TOCTOU fix: hold write lock across entire compute to prevent race
        // with set_targets. First, capture data we need from other sources.
        let selected = self.selected.read().clone();
        
        let mut g = self.state.write();
        let ids: Vec<String> = g.targets.keys().cloned().collect();
        let mut routes: Vec<RouteSnapshot> = Vec::with_capacity(ids.len());
        
        for id in &ids {
            let agg = self.metrics.aggregated(id);
            let (score, health_now) = match &agg {
                Some(a) => (compute_score(a), derive_health(a)),
                None => (f32::INFINITY, Health::Unknown),
            };
            // Get prev health/streak while holding write lock (safe from race)
            let prev = g.targets.get(id).map(|t| (t.health, t.streak));
            // Hysteresis: require HEALTH_HYSTERESIS_STREAK consecutive readings before switching
            let (health, streak) = match prev {
                Some((h, _s)) if h == health_now => (h, 0),
                Some((h, s)) => {
                    let ns = s + 1;
                    if ns >= HEALTH_HYSTERESIS_STREAK {
                        (health_now, 0)
                    } else {
                        (h, ns)
                    }
                }
                None => (health_now, 0),
            };
            g.targets.insert(id.clone(), TrackedTarget { health, streak });
            
            let (latest, avg, jitter, loss, stab, samples) = match &agg {
                Some(a) => (
                    a.latest_rtt_ms,
                    a.avg_rtt_ms,
                    a.jitter_ms,
                    a.loss_ratio,
                    a.stability,
                    a.samples,
                ),
                None => (None, None, 0.0, 0.0, 0.0, 0usize),
            };
            routes.push(RouteSnapshot {
                route_id: id.clone(),
                score,
                health,
                latest_rtt_ms: latest,
                avg_rtt_ms: avg,
                jitter_ms: jitter,
                loss_ratio: loss,
                stability: stab,
                samples,
            });
        }
        routes.sort_by(|a, b| a.route_id.cmp(&b.route_id));
        Arc::new(Snapshot {
            routes,
            selected,
            timestamp_ms: Utc::now().timestamp_millis(),
        })
    }

    fn maybe_emit(&self, snap: &Snapshot) {
        let Some(app) = self.app.lock().clone() else {
            return;
        };
        // Always emit the full route state tick.
        let _ = app.emit(EV_ROUTE_STATE, snap);

        let cur = snap.selected.clone();
        // Atomic check-then-update under a single write lock.
        // Previously used read().clone() followed by a separate write(), leaving a window where two
        // concurrent callers could both observe a change and both emit EV_ROUTE_CHANGED.
        // Now: acquire write lock once, compare, update, release — then emit outside the lock to
        // avoid re-entrancy issues with Tauri's event bus.
        let changed = {
            let mut last = self.last_emitted_selected.write();
            if *last != cur {
                *last = cur.clone();
                true
            } else {
                false
            }
        };
        if changed {
            let _ = app.emit(EV_ROUTE_CHANGED, &cur);
        }
    }

    pub fn start(self: &Arc<Self>, app: AppHandle) {
        *self.app.lock() = Some(app.clone());
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        let me = Arc::clone(self);
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(
                me.interval_ms.load(Ordering::Relaxed),
            ));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                if !me.running.load(Ordering::Relaxed) {
                    break;
                }
                let snap = me.compute_snapshot();
                *me.current.write() = Arc::clone(&snap);
                me.maybe_emit(&snap);
            }
        });
        *self.handle.lock() = Some(handle);
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(h) = self.handle.lock().take() {
            h.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::PingSample;

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

    #[test]
    fn score_lower_for_better_rtt() {
        let m = MetricsStore::new();
        push_ok(&m, "good", 10.0);
        push_ok(&m, "bad", 100.0);
        let a = m.aggregated("good").unwrap();
        let b = m.aggregated("bad").unwrap();
        assert!(compute_score(&a) < compute_score(&b));
    }

    #[test]
    fn score_infinite_when_no_rtt() {
        let m = MetricsStore::new();
        push_lost(&m, "x");
        let agg = m.aggregated("x").unwrap();
        assert!(compute_score(&agg).is_infinite());
    }

    #[test]
    fn health_bad_under_high_loss() {
        let m = MetricsStore::new();
        for _ in 0..5 {
            push_ok(&m, "x", 30.0);
        }
        for _ in 0..5 {
            push_lost(&m, "x");
        }
        let agg = m.aggregated("x").unwrap();
        assert!(agg.loss_ratio > LOSS_BAD);
        assert_eq!(derive_health(&agg), Health::Bad);
    }

    #[test]
    fn health_degraded_under_moderate_loss() {
        let m = MetricsStore::new();
        for _ in 0..19 {
            push_ok(&m, "x", 30.0);
        }
        push_lost(&m, "x");
        let agg = m.aggregated("x").unwrap();
        assert!(agg.loss_ratio > LOSS_DEGRADED);
        assert!(agg.loss_ratio < LOSS_BAD);
        assert_eq!(derive_health(&agg), Health::Degraded);
    }

    #[test]
    fn health_hysteresis_resists_flicker() {
        let m = MetricsStore::new();
        let eng = RouteSnapshotEngine::new(m.clone());
        eng.set_targets(vec!["x".to_string()]);
        for _ in 0..100 {
            push_ok(&m, "x", 20.0);
        }
        let s1 = eng.refresh_now();
        assert_eq!(s1.health_of("x"), Health::Good);
        for _ in 0..5 {
            push_lost(&m, "x");
        }
        let s2 = eng.refresh_now();
        assert_eq!(s2.health_of("x"), Health::Good);
        let s3 = eng.refresh_now();
        assert_eq!(s3.health_of("x"), Health::Good);
        let s4 = eng.refresh_now();
        assert_eq!(s4.health_of("x"), Health::Degraded);
    }

    #[test]
    fn hysteresis_no_prev_means_no_hysteresis() {
        let m = MetricsStore::new();
        let eng = RouteSnapshotEngine::new(m.clone());
        eng.set_targets(vec!["x".to_string()]);
        for _ in 0..10 {
            push_lost(&m, "x");
        }
        let s = eng.refresh_now();
        assert_eq!(s.health_of("x"), Health::Bad);
    }

    #[test]
    fn set_selected_round_trips() {
        let m = MetricsStore::new();
        let eng = RouteSnapshotEngine::new(m.clone());
        eng.set_targets(vec!["a".to_string(), "b".to_string()]);
        eng.set_selected(Some("a".to_string()));
        let snap = eng.refresh_now();
        assert_eq!(snap.selected.as_deref(), Some("a"));
    }

    #[test]
    fn set_interval_clamps() {
        let m = MetricsStore::new();
        let eng = RouteSnapshotEngine::new(m.clone());
        eng.set_interval_ms(5);
        assert!(eng.interval_ms() >= MIN_INTERVAL_MS);
        eng.set_interval_ms(10_000);
        assert!(eng.interval_ms() <= MAX_INTERVAL_MS);
    }

    #[test]
    fn empty_targets_yields_empty_snapshot() {
        let m = MetricsStore::new();
        let eng = RouteSnapshotEngine::new(m.clone());
        let snap = eng.refresh_now();
        assert!(snap.routes.is_empty());
        assert!(snap.selected.is_none());
    }

    #[test]
    fn healthy_includes_good_and_degraded_only() {
        let m = MetricsStore::new();
        let eng = RouteSnapshotEngine::new(m.clone());
        eng.set_targets(vec!["g".into(), "d".into(), "b".into(), "u".into()]);
        for _ in 0..10 {
            push_ok(&m, "g", 20.0);
            push_ok(&m, "d", 130.0);
            push_ok(&m, "b", 20.0);
            push_lost(&m, "b");
        }
        let snap = eng.refresh_now();
        let mut ids: Vec<String> = snap.healthy().into_iter().map(|(id, _)| id).collect();
        ids.sort();
        assert_eq!(ids, vec!["d".to_string(), "g".to_string()]);
    }
}