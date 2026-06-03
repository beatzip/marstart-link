//! Route scoring, health, and selection.
//!
//! `RouteManager` is a thin control layer on top of `RouteSnapshotEngine`.
//! It owns the candidate set (from `EndpointSpec`), computes a weighted
//! score, applies cooldown + switch-margin to avoid flapping, and tracks
//! manual overrides. Health is read from the snapshot engine (single
//! source of truth); routes do not re-derive it.

use crate::metrics::MetricsStore;
use crate::profiles::EndpointSpec;
use crate::snapshot::{Health, RouteSnapshotEngine};
use parking_lot::RwLock;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub use crate::snapshot::Health as RouteHealth;

const DEFAULT_COOLDOWN_MS: u64 = 10_000;
const DEFAULT_SWITCH_MARGIN: f32 = 0.10;
const MIN_WEIGHT: f32 = 0.01;

#[derive(Debug, Clone, Serialize)]
pub struct RouteCandidate {
    pub id: String,
    pub addr: SocketAddr,
    pub label: String,
    pub weight: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteScoreView {
    pub id: String,
    pub score: f32,
    pub weighted_score: f32,
    pub health: Health,
    pub weight: f32,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum EvalReason {
    NoCandidates,
    NoChange,
    ManualOverride,
    EmergencyBypass,
    Improvement,
    CooldownBlocked,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteEvaluation {
    pub current: Option<String>,
    pub recommended: Option<String>,
    pub manual_override: Option<String>,
    pub scores: Vec<RouteScoreView>,
    pub reason: EvalReason,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteState {
    pub candidates: Vec<RouteCandidate>,
    pub current: Option<String>,
    pub manual_override: Option<String>,
    pub last_switch_ms: u64,
    pub cooldown_ms: u64,
    pub switch_margin: f32,
}

struct RouteInner {
    candidates: HashMap<String, RouteCandidate>,
    manual_override: Option<String>,
}

pub struct RouteManager {
    snapshot: Arc<RouteSnapshotEngine>,
    inner: RwLock<RouteInner>,
    last_switch_ms: AtomicU64,
    started: Instant,
    cooldown_ms: AtomicU64,
    switch_margin: AtomicU32,
}

impl RouteManager {
    pub fn new(_metrics: MetricsStore, snapshot: Arc<RouteSnapshotEngine>) -> Arc<Self> {
        Arc::new(Self {
            snapshot,
            inner: RwLock::new(RouteInner {
                candidates: HashMap::new(),
                manual_override: None,
            }),
            last_switch_ms: AtomicU64::new(0),
            started: Instant::now(),
            cooldown_ms: AtomicU64::new(DEFAULT_COOLDOWN_MS),
            switch_margin: AtomicU32::new(DEFAULT_SWITCH_MARGIN.to_bits()),
        })
    }

    pub fn set_candidates(&self, specs: Vec<EndpointSpec>) {
        let mut g = self.inner.write();
        let keep: HashSet<String> = specs.iter().map(|s| s.id.clone()).collect();
        g.candidates.retain(|id, _| keep.contains(id));
        for spec in specs {
            g.candidates.insert(
                spec.id.clone(),
                RouteCandidate {
                    id: spec.id,
                    addr: spec.addr,
                    label: spec.label,
                    weight: spec.weight.max(MIN_WEIGHT),
                },
            );
        }
        if let Some(m) = g.manual_override.clone() {
            if !g.candidates.contains_key(&m) {
                g.manual_override = None;
            }
        }
    }

    pub fn candidates(&self) -> Vec<RouteCandidate> {
        self.inner.read().candidates.values().cloned().collect()
    }

    pub fn select_manual(&self, id: &str) -> Result<(), String> {
        {
            let g = self.inner.read();
            if !g.candidates.contains_key(id) {
                return Err(format!("unknown route id: {id}"));
            }
        }
        self.inner.write().manual_override = Some(id.to_string());
        Ok(())
    }

    pub fn clear_manual(&self) {
        self.inner.write().manual_override = None;
    }

    pub fn current(&self) -> Option<String> {
        self.snapshot.current().selected.clone()
    }

    pub fn health_of(&self, id: &str) -> Health {
        self.snapshot.current().health_of(id)
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    pub fn can_switch(&self) -> bool {
        self.elapsed_ms()
            .saturating_sub(self.last_switch_ms.load(Ordering::Relaxed))
            >= self.cooldown_ms.load(Ordering::Relaxed)
    }

    pub fn set_cooldown_ms(&self, ms: u64) {
        self.cooldown_ms.store(ms, Ordering::Relaxed);
    }

    pub fn cooldown_ms(&self) -> u64 {
        self.cooldown_ms.load(Ordering::Relaxed)
    }

    pub fn set_switch_margin(&self, margin: f32) {
        self.switch_margin.store(margin.to_bits(), Ordering::Relaxed);
    }

    pub fn switch_margin(&self) -> f32 {
        f32::from_bits(self.switch_margin.load(Ordering::Relaxed))
    }

    pub fn evaluate(&self) -> RouteEvaluation {
        let (candidates, manual) = {
            let g = self.inner.read();
            (
                g.candidates.values().cloned().collect::<Vec<_>>(),
                g.manual_override.clone(),
            )
        };
        let current = self.current();

        if candidates.is_empty() {
            return RouteEvaluation {
                current,
                recommended: None,
                manual_override: manual,
                scores: Vec::new(),
                reason: EvalReason::NoCandidates,
            };
        }

        let snap = self.snapshot.current();
        let mut scores: Vec<RouteScoreView> = candidates
            .iter()
            .map(|c| {
                let health = snap.health_of(&c.id);
                let base = snap.route(&c.id).map(|r| r.score).unwrap_or(f32::INFINITY);
                let weighted = base / c.weight.max(MIN_WEIGHT);
                RouteScoreView {
                    id: c.id.clone(),
                    score: base,
                    weighted_score: weighted,
                    health,
                    weight: c.weight,
                }
            })
            .collect();

        let mut recommended: Option<String> = manual.clone();
        if recommended.is_none() {
            let healthy: Vec<&RouteScoreView> = scores
                .iter()
                .filter(|s| s.health != Health::Bad)
                .collect();
            if let Some(best) = healthy.iter().min_by(|a, b| {
                a.weighted_score
                    .partial_cmp(&b.weighted_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }) {
                recommended = Some(best.id.clone());
            } else if let Some(best) = scores.iter().min_by(|a, b| {
                a.weighted_score
                    .partial_cmp(&b.weighted_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }) {
                recommended = Some(best.id.clone());
            }
        }

        let reason = if manual.is_some() {
            EvalReason::ManualOverride
        } else if recommended == current {
            EvalReason::NoChange
        } else {
            let cur_health = current
                .as_ref()
                .map(|id| snap.health_of(id))
                .unwrap_or(Health::Unknown);
            if cur_health == Health::Bad {
                EvalReason::EmergencyBypass
            } else if !self.can_switch() {
                EvalReason::CooldownBlocked
            } else {
                let cur_score = current.as_ref().and_then(|id| {
                    scores.iter().find(|s| &s.id == id).map(|s| s.weighted_score)
                });
                let rec_score = recommended.as_ref().and_then(|id| {
                    scores.iter().find(|s| &s.id == id).map(|s| s.weighted_score)
                });
                match (cur_score, rec_score) {
                    (Some(cs), Some(rs)) if cs > 0.0 => {
                        if (cs - rs) / cs >= self.switch_margin() {
                            EvalReason::Improvement
                        } else {
                            EvalReason::NoChange
                        }
                    }
                    _ => EvalReason::Improvement,
                }
            }
        };

        scores.sort_by(|a, b| a.id.cmp(&b.id));

        RouteEvaluation {
            current,
            recommended,
            manual_override: manual,
            scores,
            reason,
        }
    }

    pub fn commit(&self, new_id: Option<String>) {
        let prev = self.current();
        if new_id == prev {
            return;
        }
        self.last_switch_ms.store(self.elapsed_ms(), Ordering::Relaxed);
        self.snapshot.set_selected(new_id);
    }

    pub fn state(&self) -> RouteState {
        let g = self.inner.read();
        RouteState {
            candidates: g.candidates.values().cloned().collect(),
            current: self.snapshot.current().selected.clone(),
            manual_override: g.manual_override.clone(),
            last_switch_ms: self.last_switch_ms.load(Ordering::Relaxed),
            cooldown_ms: self.cooldown_ms.load(Ordering::Relaxed),
            switch_margin: self.switch_margin(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::PingSample;
    use chrono::Utc;

    fn specs(items: &[(&str, f32)]) -> Vec<EndpointSpec> {
        items
            .iter()
            .map(|(id, w)| EndpointSpec {
                id: (*id).to_string(),
                addr: "127.0.0.1:0".parse().unwrap(),
                label: (*id).to_string(),
                weight: *w,
            })
            .collect()
    }

    fn make(items: &[(&str, f32)]) -> (Arc<RouteManager>, MetricsStore, Arc<RouteSnapshotEngine>) {
        let metrics = MetricsStore::new();
        let snap = RouteSnapshotEngine::new(metrics.clone());
        let mgr = RouteManager::new(metrics.clone(), Arc::clone(&snap));
        mgr.set_candidates(specs(items));
        (mgr, metrics, snap)
    }

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

    fn set_targets_and_pump(snap: &RouteSnapshotEngine, ids: &[&str]) {
        snap.set_targets(ids.iter().map(|s| s.to_string()).collect());
        let _ = snap.refresh_now();
    }

    #[test]
    fn set_candidates_populates_state() {
        let (mgr, _, _) = make(&[("a", 1.0), ("b", 2.0)]);
        let s = mgr.state();
        assert_eq!(s.candidates.len(), 2);
    }

    #[test]
    fn remove_candidate_clears_stale_manual() {
        let (mgr, _, _) = make(&[("a", 1.0), ("b", 1.0)]);
        mgr.select_manual("a").unwrap();
        assert!(mgr.state().manual_override.is_some());
        mgr.set_candidates(specs(&[("b", 1.0)]));
        assert!(mgr.state().manual_override.is_none());
    }

    #[test]
    fn select_manual_rejects_unknown_id() {
        let (mgr, _, _) = make(&[("a", 1.0)]);
        assert!(mgr.select_manual("z").is_err());
    }

    #[test]
    fn weighted_score_prefers_higher_weight() {
        let (mgr, metrics, snap) = make(&[("a", 1.0), ("b", 2.0)]);
        set_targets_and_pump(&snap, &["a", "b"]);
        seed_good(&metrics, "a", 50.0);
        seed_good(&metrics, "b", 50.0);
        let _ = snap.refresh_now();
        let ev = mgr.evaluate();
        let a = ev.scores.iter().find(|s| s.id == "a").unwrap();
        let b = ev.scores.iter().find(|s| s.id == "b").unwrap();
        assert!(b.weighted_score < a.weighted_score);
        assert_eq!(ev.recommended.as_deref(), Some("b"));
    }

    #[test]
    fn evaluate_picks_lowest_weighted_among_healthy() {
        let (mgr, metrics, snap) = make(&[("a", 1.0), ("b", 1.0)]);
        set_targets_and_pump(&snap, &["a", "b"]);
        seed_good(&metrics, "a", 30.0);
        seed_good(&metrics, "b", 80.0);
        let _ = snap.refresh_now();
        let ev = mgr.evaluate();
        assert_eq!(ev.recommended.as_deref(), Some("a"));
    }

    #[test]
    fn evaluate_skips_bad_routes() {
        let (mgr, metrics, snap) = make(&[("good", 1.0), ("bad", 1.0)]);
        set_targets_and_pump(&snap, &["good", "bad"]);
        seed_good(&metrics, "good", 30.0);
        seed_bad(&metrics, "bad");
        let _ = snap.refresh_now();
        let ev = mgr.evaluate();
        assert_eq!(ev.recommended.as_deref(), Some("good"));
    }

    #[test]
    fn evaluate_falls_back_when_all_bad() {
        let (mgr, metrics, snap) = make(&[("a", 1.0), ("b", 1.0)]);
        set_targets_and_pump(&snap, &["a", "b"]);
        seed_bad(&metrics, "a");
        seed_bad(&metrics, "b");
        let _ = snap.refresh_now();
        let ev = mgr.evaluate();
        assert!(ev.recommended.is_some());
    }

    #[test]
    fn manual_override_beats_auto() {
        let (mgr, metrics, snap) = make(&[("a", 1.0), ("b", 1.0)]);
        set_targets_and_pump(&snap, &["a", "b"]);
        seed_good(&metrics, "a", 30.0);
        seed_good(&metrics, "b", 80.0);
        let _ = snap.refresh_now();
        mgr.select_manual("b").unwrap();
        let ev = mgr.evaluate();
        assert_eq!(ev.recommended.as_deref(), Some("b"));
        assert_eq!(ev.reason, EvalReason::ManualOverride);
    }

    #[test]
    fn clear_manual_reverts_to_auto() {
        let (mgr, metrics, snap) = make(&[("a", 1.0), ("b", 1.0)]);
        set_targets_and_pump(&snap, &["a", "b"]);
        seed_good(&metrics, "a", 30.0);
        seed_good(&metrics, "b", 80.0);
        let _ = snap.refresh_now();
        mgr.select_manual("b").unwrap();
        let ev = mgr.evaluate();
        assert_eq!(ev.recommended.as_deref(), Some("b"));
        mgr.clear_manual();
        let ev = mgr.evaluate();
        assert_eq!(ev.recommended.as_deref(), Some("a"));
    }

    #[test]
    fn commit_updates_current_and_idempotent() {
        let (mgr, metrics, snap) = make(&[("a", 1.0)]);
        set_targets_and_pump(&snap, &["a"]);
        seed_good(&metrics, "a", 30.0);
        let _ = snap.refresh_now();
        assert!(mgr.current().is_none());
        mgr.commit(Some("a".into()));
        assert_eq!(mgr.current().as_deref(), Some("a"));
        let t1 = mgr.state().last_switch_ms;
        mgr.commit(Some("a".into()));
        let t2 = mgr.state().last_switch_ms;
        assert_eq!(t1, t2);
    }

    #[test]
    fn cooldown_blocks_recommended_switch() {
        let (mgr, metrics, snap) = make(&[("a", 1.0), ("b", 1.0)]);
        set_targets_and_pump(&snap, &["a", "b"]);
        seed_good(&metrics, "a", 30.0);
        seed_good(&metrics, "b", 80.0);
        let _ = snap.refresh_now();
        mgr.set_cooldown_ms(10_000);
        mgr.commit(Some("a".into()));
        seed_good(&metrics, "b", 10.0);
        let _ = snap.refresh_now();
        let ev = mgr.evaluate();
        assert_eq!(ev.recommended.as_deref(), Some("b"));
        assert_eq!(ev.reason, EvalReason::CooldownBlocked);
    }

    #[test]
    fn emergency_bypass_when_current_is_bad() {
        let (mgr, metrics, snap) = make(&[("a", 1.0), ("b", 1.0)]);
        set_targets_and_pump(&snap, &["a", "b"]);
        seed_good(&metrics, "a", 30.0);
        seed_good(&metrics, "b", 80.0);
        let _ = snap.refresh_now();
        mgr.set_cooldown_ms(10_000);
        mgr.commit(Some("a".into()));
        for _ in 0..30 {
            push_lost(&metrics, "a");
        }
        for _ in 0..4 {
            let _ = snap.refresh_now();
        }
        assert_eq!(mgr.health_of("a"), Health::Bad);
        let ev = mgr.evaluate();
        assert_eq!(ev.recommended.as_deref(), Some("b"));
        assert_eq!(ev.reason, EvalReason::EmergencyBypass);
    }

    #[test]
    fn health_of_delegates_to_snapshot() {
        let (mgr, metrics, snap) = make(&[("a", 1.0)]);
        set_targets_and_pump(&snap, &["a"]);
        seed_good(&metrics, "a", 30.0);
        let _ = snap.refresh_now();
        assert_eq!(mgr.health_of("a"), Health::Good);
        assert_eq!(mgr.health_of("missing"), Health::Unknown);
    }

    #[test]
    fn no_change_when_recommended_equals_current() {
        let (mgr, metrics, snap) = make(&[("a", 1.0)]);
        set_targets_and_pump(&snap, &["a"]);
        seed_good(&metrics, "a", 30.0);
        let _ = snap.refresh_now();
        mgr.commit(Some("a".into()));
        let ev = mgr.evaluate();
        assert_eq!(ev.reason, EvalReason::NoChange);
    }
}
