//! Policy gate: cooldown, improvement margin, hysteresis checks.
//! Pure function of (context, config) -> Verdict. No side effects,
//! no access to other modules. Used by the autopilot FSM to decide
//! whether a candidate switch is currently permitted.

use crate::snapshot::Health;
use parking_lot::RwLock;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FsmState {
    Init,
    Stable,
    GameMode,
    Degraded,
    Recovery,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyConfig {
    pub game_mode_cooldown_ms: u64,
    pub recovery_cooldown_ms: u64,
    pub stable_cooldown_ms: u64,
    pub degraded_cooldown_ms: u64,
    pub game_mode_margin: f32,
    pub stable_margin: f32,
    pub other_margin: f32,
    pub degraded_margin: f32,
    pub hysteresis_streak: u32,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            game_mode_cooldown_ms: 2500,
            recovery_cooldown_ms: 200,
            stable_cooldown_ms: 1500,
            degraded_cooldown_ms: 800,
            game_mode_margin: 0.15,
            stable_margin: 0.20,
            other_margin: 0.12,
            degraded_margin: 0.08,
            hysteresis_streak: 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CooldownClass {
    GameMode,
    Recovery,
    Stable,
    Degraded,
}

impl CooldownClass {
    pub fn duration_ms(&self, cfg: &PolicyConfig) -> u64 {
        match self {
            Self::GameMode => cfg.game_mode_cooldown_ms,
            Self::Recovery => cfg.recovery_cooldown_ms,
            Self::Stable => cfg.stable_cooldown_ms,
            Self::Degraded => cfg.degraded_cooldown_ms,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Verdict {
    Allow,
    Block,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyVerdict {
    pub verdict: Verdict,
    pub class: CooldownClass,
    pub improvement: f32,
    pub margin: f32,
    pub streak: u32,
    pub streak_needed: u32,
    pub elapsed_since_switch_ms: u64,
    pub cooldown_ms: u64,
}

#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub in_game: bool,
    pub current_health: Health,
    pub fsm_state: FsmState,
    pub improvement: f32,
    pub streak: u32,
    pub elapsed_since_switch_ms: u64,
}

pub struct PolicyGate {
    config: RwLock<PolicyConfig>,
}

impl PolicyGate {
    pub fn new() -> Self {
        Self {
            config: RwLock::new(PolicyConfig::default()),
        }
    }

    pub fn with_config(cfg: PolicyConfig) -> Self {
        Self {
            config: RwLock::new(cfg),
        }
    }

    pub fn config(&self) -> PolicyConfig {
        self.config.read().clone()
    }

    pub fn set_config(&self, cfg: PolicyConfig) {
        *self.config.write() = cfg;
    }

    pub fn cooldown_class(
        &self,
        in_game: bool,
        current_health: Health,
        fsm_state: FsmState,
    ) -> CooldownClass {
        if in_game {
            return CooldownClass::GameMode;
        }
        if matches!(fsm_state, FsmState::Recovery) {
            return CooldownClass::Recovery;
        }
        match current_health {
            Health::Degraded => CooldownClass::Degraded,
            _ => CooldownClass::Stable,
        }
    }

    pub fn margin(&self, in_game: bool, current_health: Health, cfg: &PolicyConfig) -> f32 {
        if in_game {
            return cfg.game_mode_margin;
        }
        match current_health {
            Health::Good => cfg.stable_margin,
            Health::Degraded => cfg.degraded_margin,
            _ => cfg.other_margin,
        }
    }

    pub fn evaluate(&self, ctx: &PolicyContext) -> PolicyVerdict {
        let cfg = self.config.read().clone();
        let class = self.cooldown_class(ctx.in_game, ctx.current_health, ctx.fsm_state);
        let cooldown = class.duration_ms(&cfg);
        let margin = self.margin(ctx.in_game, ctx.current_health, &cfg);
        let streak_ok = ctx.streak >= cfg.hysteresis_streak;
        let cooldown_ok = ctx.elapsed_since_switch_ms >= cooldown;
        let margin_ok = ctx.improvement >= margin;
        let allow = streak_ok && cooldown_ok && margin_ok;
        PolicyVerdict {
            verdict: if allow {
                Verdict::Allow
            } else {
                Verdict::Block
            },
            class,
            improvement: ctx.improvement,
            margin,
            streak: ctx.streak,
            streak_needed: cfg.hysteresis_streak,
            elapsed_since_switch_ms: ctx.elapsed_since_switch_ms,
            cooldown_ms: cooldown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(
        in_game: bool,
        health: Health,
        state: FsmState,
        improvement: f32,
        streak: u32,
        elapsed: u64,
    ) -> PolicyContext {
        PolicyContext {
            in_game,
            current_health: health,
            fsm_state: state,
            improvement,
            streak,
            elapsed_since_switch_ms: elapsed,
        }
    }

    #[test]
    fn default_config_matches_spec() {
        let g = PolicyGate::new();
        let cfg = g.config();
        assert_eq!(cfg.game_mode_cooldown_ms, 2500);
        assert_eq!(cfg.recovery_cooldown_ms, 200);
        assert_eq!(cfg.stable_cooldown_ms, 1500);
        assert_eq!(cfg.degraded_cooldown_ms, 800);
        assert!((cfg.game_mode_margin - 0.15).abs() < 1e-6);
        assert!((cfg.stable_margin - 0.20).abs() < 1e-6);
        assert!((cfg.other_margin - 0.12).abs() < 1e-6);
        assert!((cfg.degraded_margin - 0.08).abs() < 1e-6);
        assert_eq!(cfg.hysteresis_streak, 3);
    }

    #[test]
    fn cooldown_blocks_immediate_switch() {
        let g = PolicyGate::new();
        let v = g.evaluate(&ctx(false, Health::Good, FsmState::Stable, 0.5, 3, 100));
        assert_eq!(v.verdict, Verdict::Block);
        assert_eq!(v.class, CooldownClass::Stable);
        let v2 = g.evaluate(&ctx(false, Health::Good, FsmState::Stable, 0.5, 3, 2000));
        assert_eq!(v2.verdict, Verdict::Allow);
    }

    #[test]
    fn margin_blocks_small_improvement() {
        let g = PolicyGate::new();
        let v = g.evaluate(&ctx(false, Health::Good, FsmState::Stable, 0.05, 3, 9999));
        assert_eq!(v.verdict, Verdict::Block);
        let v2 = g.evaluate(&ctx(false, Health::Good, FsmState::Stable, 0.25, 3, 9999));
        assert_eq!(v2.verdict, Verdict::Allow);
    }

    #[test]
    fn hysteresis_blocks_early() {
        let g = PolicyGate::new();
        let v = g.evaluate(&ctx(false, Health::Good, FsmState::Stable, 0.5, 1, 9999));
        assert_eq!(v.verdict, Verdict::Block);
        let v2 = g.evaluate(&ctx(false, Health::Good, FsmState::Stable, 0.5, 3, 9999));
        assert_eq!(v2.verdict, Verdict::Allow);
    }

    #[test]
    fn game_mode_uses_lower_margin() {
        let g = PolicyGate::new();
        let v = g.evaluate(&ctx(true, Health::Good, FsmState::GameMode, 0.10, 3, 9999));
        assert_eq!(v.verdict, Verdict::Allow);
        assert_eq!(v.class, CooldownClass::GameMode);
    }

    #[test]
    fn recovery_uses_short_cooldown() {
        let g = PolicyGate::new();
        let v = g.evaluate(&ctx(false, Health::Good, FsmState::Recovery, 0.5, 3, 100));
        assert_eq!(v.verdict, Verdict::Allow);
        assert_eq!(v.class, CooldownClass::Recovery);
    }

    #[test]
    fn degraded_uses_separate_margin() {
        let g = PolicyGate::new();
        let v = g.evaluate(&ctx(
            false,
            Health::Degraded,
            FsmState::Degraded,
            0.10,
            3,
            9999,
        ));
        assert_eq!(v.verdict, Verdict::Allow);
        assert_eq!(v.class, CooldownClass::Degraded);
        let v2 = g.evaluate(&ctx(
            false,
            Health::Degraded,
            FsmState::Degraded,
            0.05,
            3,
            9999,
        ));
        assert_eq!(v2.verdict, Verdict::Block);
        let good = g.evaluate(&ctx(false, Health::Good, FsmState::Stable, 0.10, 3, 9999));
        assert_eq!(good.verdict, Verdict::Block);
        assert!(good.margin > v.margin);
    }

    #[test]
    fn set_config_overrides() {
        let g = PolicyGate::new();
        g.set_config(PolicyConfig {
            hysteresis_streak: 1,
            ..PolicyConfig::default()
        });
        let v = g.evaluate(&ctx(false, Health::Good, FsmState::Stable, 0.0, 1, 9999));
        assert_eq!(v.verdict, Verdict::Allow);
    }
}
