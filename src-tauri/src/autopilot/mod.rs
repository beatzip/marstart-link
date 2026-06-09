//! Snapshot-driven autopilot. Emits `AutopilotDecision` (intent + reason)
//! per tick. Does NOT mutate `RouteManager` or `LoadBalancer` — the
//! tick controller is responsible for acting on the emitted intent.

pub mod policy;
pub mod stability;

use crate::game_detection::GameSignal;
use crate::metrics::MetricsStore;
use crate::snapshot::{Health, Snapshot};
use parking_lot::RwLock;
use policy::{FsmState, PolicyContext, PolicyGate, PolicyVerdict, Verdict};
#[cfg(test)]
use policy::PolicyConfig;
use serde::Serialize;
use stability::{StabilityHistory, StabilitySample};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[allow(unused_imports)]
pub use policy::FsmState as AutopilotFsmState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AutopilotIntent {
    Hold,
    Switch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DecisionReason {
    NoCandidates,
    AlreadyOnBest,
    StableNoImprovement,
    CooldownActive,
    HysteresisPending,
    Improvement,
    GameModeSwitch,
    EmergencyBypass,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutopilotDecision {
    pub intent: AutopilotIntent,
    pub reason: DecisionReason,
    pub from_route: Option<String>,
    pub to_route: Option<String>,
    pub fsm_state: FsmState,
    pub stability: HashMap<String, f32>,
    pub verdict: Option<PolicyVerdict>,
    pub timestamp_ms: i64,
}

impl AutopilotDecision {
    pub fn recommended_id(&self) -> Option<String> {
        self.to_route.clone()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FsmStateView {
    pub state: FsmState,
    pub streak: u32,
    pub last_recommended: Option<String>,
    pub state_entered_ms: u64,
    pub elapsed_ms: u64,
}

struct AutopilotInner {
    fsm_state: FsmState,
    state_entered_ms: u64,
    last_recommended: Option<String>,
    streak: u32,
    last_recorded_ts: HashMap<String, i64>,
    last_decision: Option<AutopilotDecision>,
}

pub struct Autopilot {
    metrics: MetricsStore,
    stability: StabilityHistory,
    policy: PolicyGate,
    inner: RwLock<AutopilotInner>,
    last_switch_ms: AtomicU64,
    started: Instant,
}

impl Autopilot {
    pub fn new(metrics: MetricsStore) -> Arc<Self> {
        Arc::new(Self {
            metrics,
            stability: StabilityHistory::new(),
            policy: PolicyGate::new(),
            inner: RwLock::new(AutopilotInner {
                fsm_state: FsmState::Init,
                state_entered_ms: 0,
                last_recommended: None,
                streak: 0,
                last_recorded_ts: HashMap::new(),
                last_decision: None,
            }),
            last_switch_ms: AtomicU64::new(0),
            started: Instant::now(),
        })
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    pub fn stability_of(&self, route_id: &str) -> f32 {
        self.stability.stability_index(route_id)
    }

    pub fn state(&self) -> FsmStateView {
        let g = self.inner.read();
        FsmStateView {
            state: g.fsm_state,
            streak: g.streak,
            last_recommended: g.last_recommended.clone(),
            state_entered_ms: g.state_entered_ms,
            elapsed_ms: self.elapsed_ms(),
        }
    }

    pub fn last_decision(&self) -> Option<AutopilotDecision> {
        self.inner.read().last_decision.clone()
    }

    pub fn policy(&self) -> &PolicyGate {
        &self.policy
    }

    pub fn update(&self, snap: &Snapshot, game: &GameSignal) -> AutopilotDecision {
        let now_ms = self.elapsed_ms();
        let now_ms_i64 = chrono::Utc::now().timestamp_millis();
        let route_ids: Vec<String> = snap.routes.iter().map(|r| r.route_id.clone()).collect();
        self.feed_stability(&route_ids);

        let mut stability_map: HashMap<String, f32> = HashMap::new();
        for id in &route_ids {
            stability_map.insert(id.clone(), self.stability.stability_index(id));
        }

        let mut candidates: Vec<(String, f32, Health)> = snap
            .routes
            .iter()
            .filter(|r| r.health != Health::Bad)
            .map(|r| {
                let idx = stability_map.get(&r.route_id).copied().unwrap_or(0.5);
                let eff = r.score / idx.max(0.01);
                (r.route_id.clone(), eff, r.health)
            })
            .collect();
        candidates.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        let current = snap.selected.clone();
        let in_game = game.detected && game.confidence >= 0.5;

        let new_fsm = self.next_fsm(snap, &current, game, &candidates, now_ms);
        let recommended = candidates.first().map(|(id, _, _)| id.clone());

        let (new_streak, _new_last_recommended) = {
            let g = self.inner.read();
            let lr = g.last_recommended.clone();
            if lr == recommended {
                (g.streak + 1, lr)
            } else {
                (1u32, recommended.clone())
            }
        };

        let (fsm_state, state_entered_ms) = {
            let g = self.inner.read();
            if g.fsm_state != new_fsm {
                (new_fsm, now_ms)
            } else {
                (g.fsm_state, g.state_entered_ms)
            }
        };

        let decision = self.build_decision(
            snap,
            &candidates,
            current,
            recommended,
            new_streak,
            fsm_state,
            in_game,
            &stability_map,
            now_ms,
            now_ms_i64,
        );

        {
            let mut g = self.inner.write();
            g.fsm_state = fsm_state;
            g.state_entered_ms = state_entered_ms;
            g.last_recommended = decision.recommended_id();
            g.streak = new_streak;
            g.last_decision = Some(decision.clone());
            if matches!(decision.intent, AutopilotIntent::Switch) {
                self.last_switch_ms.store(now_ms, Ordering::Relaxed);
            }
        }

        decision
    }

    fn feed_stability(&self, route_ids: &[String]) {
        for id in route_ids {
            let samples = self.metrics.samples(id);
            if let Some(latest) = samples.last() {
                let last_ts = {
                    let g = self.inner.read();
                    g.last_recorded_ts.get(id).copied().unwrap_or(i64::MIN)
                };
                if latest.timestamp_ms >= last_ts {
                    self.stability
                        .record(id, StabilitySample::from_ping(latest));
                    self.inner
                        .write()
                        .last_recorded_ts
                        .insert(id.clone(), latest.timestamp_ms);
                }
            }
        }
    }

    fn next_fsm(
        &self,
        snap: &Snapshot,
        current: &Option<String>,
        game: &GameSignal,
        _candidates: &[(String, f32, Health)],
        now_ms: u64,
    ) -> FsmState {
        if snap.routes.is_empty() {
            return FsmState::Init;
        }
        let in_game = game.detected && game.confidence >= 0.5;
        let cur_health = current
            .as_ref()
            .and_then(|id| snap.route(id).map(|r| r.health))
            .unwrap_or(Health::Unknown);
        if in_game {
            return FsmState::GameMode;
        }
        let prev = self.inner.read().fsm_state;
        let recovery_elapsed = if matches!(prev, FsmState::Recovery) {
            let entered = self.inner.read().state_entered_ms;
            now_ms.saturating_sub(entered)
        } else {
            u64::MAX
        };
        match (prev, cur_health, recovery_elapsed) {
            (FsmState::GameMode, _, _) => FsmState::Recovery,
            (FsmState::Recovery, _, e) if e < 200 => FsmState::Recovery,
            (FsmState::Recovery, _, _) => FsmState::Stable,
            (_, Health::Degraded, _) => FsmState::Degraded,
            _ => FsmState::Stable,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_decision(
        &self,
        snap: &Snapshot,
        candidates: &[(String, f32, Health)],
        current: Option<String>,
        recommended: Option<String>,
        streak: u32,
        fsm_state: FsmState,
        in_game: bool,
        stability: &HashMap<String, f32>,
        now_ms: u64,
        now_ms_i64: i64,
    ) -> AutopilotDecision {
        if candidates.is_empty() {
            return AutopilotDecision {
                intent: AutopilotIntent::Hold,
                reason: DecisionReason::NoCandidates,
                from_route: current,
                to_route: None,
                fsm_state,
                stability: stability.clone(),
                verdict: None,
                timestamp_ms: now_ms_i64,
            };
        }
        let rec = recommended.as_ref().unwrap();

        if Some(rec) == current.as_ref() {
            return AutopilotDecision {
                intent: AutopilotIntent::Hold,
                reason: DecisionReason::AlreadyOnBest,
                from_route: current,
                to_route: Some(rec.clone()),
                fsm_state,
                stability: stability.clone(),
                verdict: None,
                timestamp_ms: now_ms_i64,
            };
        }

        let cur_health = current
            .as_ref()
            .and_then(|id| snap.route(id).map(|r| r.health))
            .unwrap_or(Health::Unknown);

        if cur_health == Health::Bad {
            return AutopilotDecision {
                intent: AutopilotIntent::Switch,
                reason: DecisionReason::EmergencyBypass,
                from_route: current,
                to_route: Some(rec.clone()),
                fsm_state,
                stability: stability.clone(),
                verdict: None,
                timestamp_ms: now_ms_i64,
            };
        }

        let cur_score = current.as_ref().and_then(|id| {
            candidates
                .iter()
                .find(|(id2, _, _)| id2 == id)
                .map(|(_, s, _)| *s)
        });
        let rec_score = candidates
            .iter()
            .find(|(id, _, _)| id == rec)
            .map(|(_, s, _)| *s);
        let improvement = match (cur_score, rec_score) {
            (Some(c), Some(r)) if c > 0.0 => (c - r) / c,
            _ => 1.0,
        };

        let elapsed = now_ms.saturating_sub(self.last_switch_ms.load(Ordering::Relaxed));
        let ctx = PolicyContext {
            in_game,
            current_health: cur_health,
            fsm_state,
            improvement,
            streak,
            elapsed_since_switch_ms: elapsed,
        };
        let verdict = self.policy.evaluate(&ctx);

        let (intent, reason) = match verdict.verdict {
            Verdict::Allow => {
                let reason = if in_game {
                    DecisionReason::GameModeSwitch
                } else {
                    DecisionReason::Improvement
                };
                (AutopilotIntent::Switch, reason)
            }
            Verdict::Block => {
                let reason = if verdict.streak < verdict.streak_needed {
                    DecisionReason::HysteresisPending
                } else if verdict.elapsed_since_switch_ms < verdict.cooldown_ms {
                    DecisionReason::CooldownActive
                } else {
                    DecisionReason::StableNoImprovement
                };
                (AutopilotIntent::Hold, reason)
            }
        };

        AutopilotDecision {
            intent,
            reason,
            from_route: current,
            to_route: Some(rec.clone()),
            fsm_state,
            stability: stability.clone(),
            verdict: Some(verdict),
            timestamp_ms: now_ms_i64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::PingSample;
    use crate::snapshot::RouteSnapshot;
    use chrono::Utc;

    #[cfg(test)]
    fn no_cooldown_cfg() -> PolicyConfig {
        PolicyConfig {
            game_mode_cooldown_ms: 0,
            recovery_cooldown_ms: 0,
            stable_cooldown_ms: 0,
            degraded_cooldown_ms: 0,
            game_mode_margin: 0.0,
            stable_margin: 0.0,
            other_margin: 0.0,
            degraded_margin: 0.0,
            hysteresis_streak: 1,
        }
    }

    fn route(id: &str, score: f32, health: Health) -> RouteSnapshot {
        RouteSnapshot {
            route_id: id.to_string(),
            score,
            health,
            latest_rtt_ms: None,
            avg_rtt_ms: None,
            jitter_ms: 0.0,
            loss_ratio: 0.0,
            stability: 0.0,
            samples: 0,
        }
    }

    fn snap(routes: Vec<RouteSnapshot>, selected: Option<&str>) -> Snapshot {
        Snapshot {
            routes,
            selected: selected.map(String::from),
            timestamp_ms: Utc::now().timestamp_millis(),
        }
    }

    fn idle_game() -> GameSignal {
        GameSignal {
            detected: false,
            game_id: None,
            game_name: None,
            confidence: 0.0,
            reason: crate::game_detection::DetectionReason::Idle,
            timestamp_ms: 0,
        }
    }

    fn active_game(confidence: f32) -> GameSignal {
        GameSignal {
            detected: true,
            game_id: Some("cs2".to_string()),
            game_name: Some("Counter-Strike 2".to_string()),
            confidence,
            reason: crate::game_detection::DetectionReason::Both,
            timestamp_ms: 0,
        }
    }

    fn push_ok(m: &MetricsStore, id: &str, rtt: f32) {
        m.push(
            id,
            PingSample {
                rtt_ms: Some(rtt),
                timestamp_ms: Utc::now().timestamp_millis(),
            },
        );
    }

    fn make_ap() -> (Arc<Autopilot>, MetricsStore) {
        let metrics = MetricsStore::new();
        let ap = Autopilot::new(metrics.clone());
        ap.policy().set_config(no_cooldown_cfg());
        (ap, metrics)
    }

    #[test]
    fn emits_hold_when_no_candidates() {
        let (ap, _) = make_ap();
        let d = ap.update(&snap(vec![], None), &idle_game());
        assert_eq!(d.intent, AutopilotIntent::Hold);
        assert_eq!(d.reason, DecisionReason::NoCandidates);
    }

    #[test]
    fn emits_hold_when_already_on_best() {
        let (ap, _) = make_ap();
        let routes = vec![
            route("a", 50.0, Health::Good),
            route("b", 100.0, Health::Good),
        ];
        let d = ap.update(&snap(routes, Some("a")), &idle_game());
        assert_eq!(d.intent, AutopilotIntent::Hold);
        assert_eq!(d.reason, DecisionReason::AlreadyOnBest);
    }

    #[test]
    fn emits_switch_with_improvement() {
        let (ap, _) = make_ap();
        let routes = vec![
            route("a", 200.0, Health::Good),
            route("b", 50.0, Health::Good),
        ];
        let d = ap.update(&snap(routes, Some("a")), &idle_game());
        assert_eq!(d.intent, AutopilotIntent::Switch);
        assert_eq!(d.to_route.as_deref(), Some("b"));
        assert_eq!(d.reason, DecisionReason::Improvement);
    }

    #[test]
    fn emergency_bypass_when_current_is_bad() {
        let (ap, _) = make_ap();
        let routes = vec![
            route("a", 200.0, Health::Bad),
            route("b", 50.0, Health::Good),
        ];
        let d = ap.update(&snap(routes, Some("a")), &idle_game());
        assert_eq!(d.intent, AutopilotIntent::Switch);
        assert_eq!(d.reason, DecisionReason::EmergencyBypass);
    }

    #[test]
    fn game_mode_emits_game_mode_switch() {
        let (ap, _) = make_ap();
        let routes = vec![
            route("a", 200.0, Health::Good),
            route("b", 50.0, Health::Good),
        ];
        let d = ap.update(&snap(routes, Some("a")), &active_game(0.8));
        assert_eq!(d.intent, AutopilotIntent::Switch);
        assert_eq!(d.reason, DecisionReason::GameModeSwitch);
        assert_eq!(d.fsm_state, FsmState::GameMode);
    }

    #[test]
    fn cooldown_blocks_when_policy_says_so() {
        let (ap, _) = make_ap();
        ap.policy().set_config(PolicyConfig::default());
        let routes = vec![
            route("a", 200.0, Health::Good),
            route("b", 50.0, Health::Good),
        ];
        let d = ap.update(&snap(routes, Some("a")), &idle_game());
        assert_eq!(d.intent, AutopilotIntent::Hold);
        assert!(matches!(
            d.reason,
            DecisionReason::CooldownActive | DecisionReason::HysteresisPending
        ));
    }

    #[test]
    fn stable_no_improvement_blocks() {
        let (ap, _) = make_ap();
        ap.policy().set_config(PolicyConfig {
            stable_margin: 0.5,
            ..no_cooldown_cfg()
        });
        let routes = vec![
            route("a", 100.0, Health::Good),
            route("b", 90.0, Health::Good),
        ];
        let d = ap.update(&snap(routes, Some("a")), &idle_game());
        assert_eq!(d.intent, AutopilotIntent::Hold);
        assert_eq!(d.reason, DecisionReason::StableNoImprovement);
        let verdict = d.verdict.as_ref().expect("verdict present on hold");
        assert!(
            verdict.improvement < verdict.margin,
            "improvement={} should be < margin={}",
            verdict.improvement,
            verdict.margin
        );
        assert!(verdict.streak >= verdict.streak_needed);
        assert!(verdict.elapsed_since_switch_ms >= verdict.cooldown_ms);
    }

    #[test]
    fn streak_resets_when_recommended_changes() {
        let (ap, _) = make_ap();
        let routes1 = vec![
            route("a", 50.0, Health::Good),
            route("b", 100.0, Health::Good),
        ];
        let _ = ap.update(&snap(routes1, None), &idle_game());
        let s1 = ap.state();
        let routes2 = vec![
            route("a", 200.0, Health::Good),
            route("b", 50.0, Health::Good),
        ];
        let _ = ap.update(&snap(routes2, Some("a")), &idle_game());
        let s2 = ap.state();
        assert!(s2.streak <= s1.streak + 1);
    }

    #[test]
    fn stability_recorded_from_metrics() {
        let (ap, metrics) = make_ap();
        for _ in 0..10 {
            push_ok(&metrics, "a", 20.0);
        }
        let routes = vec![route("a", 50.0, Health::Good)];
        let _ = ap.update(&snap(routes, None), &idle_game());
        assert!(ap.stability_of("a") > 0.5);
    }

    #[test]
    fn fsm_recovery_after_game_mode_ends() {
        let (ap, _) = make_ap();
        let routes = vec![route("a", 50.0, Health::Good)];
        let _ = ap.update(&snap(routes.clone(), None), &active_game(0.8));
        assert_eq!(ap.state().state, FsmState::GameMode);
        let d = ap.update(&snap(routes, None), &idle_game());
        assert_eq!(d.fsm_state, FsmState::Recovery);
    }

    #[test]
    fn degraded_current_uses_degraded_margin() {
        let (ap, _) = make_ap();
        ap.policy().set_config(PolicyConfig {
            stable_margin: 0.30,
            degraded_margin: 0.05,
            other_margin: 0.30,
            ..no_cooldown_cfg()
        });
        let routes_good = vec![
            route("a", 100.0, Health::Degraded),
            route("b", 90.0, Health::Good),
        ];
        let d = ap.update(&snap(routes_good, Some("a")), &idle_game());
        assert_eq!(d.intent, AutopilotIntent::Switch);
        let verdict = d.verdict.as_ref().unwrap();
        assert!(
            verdict.margin < 0.30,
            "degraded margin should be lower than stable"
        );
    }
}
