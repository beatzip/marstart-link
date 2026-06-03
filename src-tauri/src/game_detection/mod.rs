//! Game detection: process scan + UDP burst signals.
//!
//! `GameDetector` is a pure observer. External code feeds UDP packet
//! events via `observe_udp`. Process scanning is throttled to 1Hz and
//! exposed via `scan_processes`. `compute_signal` returns the current
//! `GameSignal` based on cached process matches and the sliding 1s
//! UDP burst window. Confidence in [0, 1].
//!
//! Built-in default profile: Counter-Strike 2 (`cs2.exe`, UDP
//! 27005-27050, threshold 40 pps, max packet 200 bytes). Custom
//! profiles can be added at runtime via `register_profile`.

use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use sysinfo::{ProcessesToUpdate, System};

const SCAN_THROTTLE_MS: i64 = 1000;
const BURST_WINDOW_MS: i64 = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameProfile {
    pub id: String,
    pub name: String,
    pub process_names: Vec<String>,
    pub udp_ports: Vec<u16>,
    pub burst_threshold_pps: f32,
    pub max_packet_size: usize,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum DetectionReason {
    Idle,
    Process,
    UdpBurst,
    Both,
}

#[derive(Debug, Clone, Serialize)]
pub struct GameSignal {
    pub detected: bool,
    pub game_id: Option<String>,
    pub game_name: Option<String>,
    pub confidence: f32,
    pub reason: DetectionReason,
    pub timestamp_ms: i64,
}

impl GameSignal {
    fn idle(now_ms: i64) -> Self {
        Self {
            detected: false,
            game_id: None,
            game_name: None,
            confidence: 0.0,
            reason: DetectionReason::Idle,
            timestamp_ms: now_ms,
        }
    }
}

struct DetectorState {
    profiles: Vec<GameProfile>,
    bursts: VecDeque<(u16, usize, i64)>,
    cached_matches: Vec<String>,
    last_signal: GameSignal,
}

pub struct GameDetector {
    state: RwLock<DetectorState>,
    last_scan_ms: AtomicI64,
    scan_count: AtomicU64,
}

impl GameDetector {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: RwLock::new(DetectorState {
                profiles: vec![Self::default_cs2_profile()],
                bursts: VecDeque::new(),
                cached_matches: Vec::new(),
                last_signal: GameSignal::idle(0),
            }),
            last_scan_ms: AtomicI64::new(0),
            scan_count: AtomicU64::new(0),
        })
    }

    fn default_cs2_profile() -> GameProfile {
        GameProfile {
            id: "cs2".to_string(),
            name: "Counter-Strike 2".to_string(),
            process_names: vec!["cs2.exe".to_string()],
            udp_ports: (27005..=27050).collect(),
            burst_threshold_pps: 40.0,
            max_packet_size: 200,
        }
    }

    pub fn register_profile(&self, profile: GameProfile) {
        let mut g = self.state.write();
        g.profiles.retain(|p| p.id != profile.id);
        g.profiles.push(profile);
    }

    pub fn unregister_profile(&self, id: &str) -> bool {
        let mut g = self.state.write();
        let before = g.profiles.len();
        g.profiles.retain(|p| p.id != id);
        before != g.profiles.len()
    }

    pub fn list_profiles(&self) -> Vec<GameProfile> {
        self.state.read().profiles.clone()
    }

    pub fn set_cached_matches(&self, names: Vec<String>) {
        self.state.write().cached_matches = names;
    }

    pub fn observe_udp(&self, port: u16, size: usize) {
        self.observe_udp_at(port, size, Utc::now().timestamp_millis());
    }

    pub fn observe_udp_at(&self, port: u16, size: usize, ts_ms: i64) {
        self.state.write().bursts.push_back((port, size, ts_ms));
    }

    pub fn scan_processes(&self) -> Vec<String> {
        let now = Utc::now().timestamp_millis();
        let last = self.last_scan_ms.load(Ordering::Relaxed);
        if last != 0 && now - last < SCAN_THROTTLE_MS {
            return self.state.read().cached_matches.clone();
        }
        self.last_scan_ms.store(now, Ordering::Relaxed);
        self.scan_count.fetch_add(1, Ordering::Relaxed);
        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::All);
        let names: Vec<String> = sys
            .processes()
            .values()
            .map(|p| p.name().to_string_lossy().to_lowercase())
            .collect();
        let matched = self.match_process_names(&names);
        self.state.write().cached_matches = matched.clone();
        matched
    }

    pub fn scan_count(&self) -> u64 {
        self.scan_count.load(Ordering::Relaxed)
    }

    fn match_process_names(&self, names: &[String]) -> Vec<String> {
        let profiles = self.state.read().profiles.clone();
        let name_set: HashSet<String> = names.iter().cloned().collect();
        let mut out = Vec::new();
        for p in &profiles {
            for pn in &p.process_names {
                if name_set.contains(&pn.to_lowercase()) {
                    out.push(pn.clone());
                }
            }
        }
        out
    }

    pub fn compute_signal(&self) -> GameSignal {
        let now = Utc::now().timestamp_millis();
        {
            let mut g = self.state.write();
            while let Some((_, _, ts)) = g.bursts.front() {
                if now - *ts > BURST_WINDOW_MS {
                    g.bursts.pop_front();
                } else {
                    break;
                }
            }
        }
        let (profiles, bursts, cached) = {
            let g = self.state.read();
            (
                g.profiles.clone(),
                g.bursts.clone(),
                g.cached_matches.clone(),
            )
        };
        let mut best: Option<GameSignal> = None;
        for p in &profiles {
            let proc_match = cached.iter().any(|m| {
                let ml = m.to_lowercase();
                p.process_names.iter().any(|pn| pn.to_lowercase() == ml)
            });
            let port_packets: usize = bursts
                .iter()
                .filter(|(port, size, _)| {
                    *size <= p.max_packet_size && p.udp_ports.contains(port)
                })
                .count();
            let udp_match = (port_packets as f32) >= p.burst_threshold_pps;
            let (confidence, reason) = match (proc_match, udp_match) {
                (true, true) => (0.95, DetectionReason::Both),
                (true, false) => (0.6, DetectionReason::Process),
                (false, true) => (0.5, DetectionReason::UdpBurst),
                (false, false) => (0.0, DetectionReason::Idle),
            };
            if confidence > 0.0 {
                let sig = GameSignal {
                    detected: true,
                    game_id: Some(p.id.clone()),
                    game_name: Some(p.name.clone()),
                    confidence,
                    reason,
                    timestamp_ms: now,
                };
                if best.as_ref().map_or(true, |b| confidence > b.confidence) {
                    best = Some(sig);
                }
            }
        }
        let sig = best.unwrap_or_else(|| GameSignal::idle(now));
        self.state.write().last_signal = sig.clone();
        sig
    }

    pub fn current(&self) -> GameSignal {
        self.state.read().last_signal.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_signal_when_no_activity() {
        let det = GameDetector::new();
        let sig = det.compute_signal();
        assert!(!sig.detected);
        assert_eq!(sig.confidence, 0.0);
        assert_eq!(sig.reason, DetectionReason::Idle);
    }

    #[test]
    fn process_match_triggers_signal() {
        let det = GameDetector::new();
        det.set_cached_matches(vec!["cs2.exe".to_string()]);
        let sig = det.compute_signal();
        assert!(sig.detected);
        assert_eq!(sig.game_id.as_deref(), Some("cs2"));
        assert_eq!(sig.game_name.as_deref(), Some("Counter-Strike 2"));
        assert!(sig.confidence >= 0.5);
        assert_eq!(sig.reason, DetectionReason::Process);
    }

    #[test]
    fn udp_burst_triggers_signal() {
        let det = GameDetector::new();
        let now = Utc::now().timestamp_millis();
        for i in 0..50i64 {
            det.observe_udp_at(27015, 100, now - i);
        }
        let sig = det.compute_signal();
        assert!(sig.detected);
        assert_eq!(sig.game_id.as_deref(), Some("cs2"));
        assert_eq!(sig.reason, DetectionReason::UdpBurst);
        assert!(sig.confidence >= 0.5);
    }

    #[test]
    fn both_signals_increase_confidence() {
        let det = GameDetector::new();
        det.set_cached_matches(vec!["cs2.exe".to_string()]);
        let now = Utc::now().timestamp_millis();
        for i in 0..50i64 {
            det.observe_udp_at(27015, 100, now - i);
        }
        let sig = det.compute_signal();
        assert!(sig.detected);
        assert!(sig.confidence >= 0.95);
        assert_eq!(sig.reason, DetectionReason::Both);
    }

    #[test]
    fn burst_window_prunes_old_packets() {
        let det = GameDetector::new();
        let now = Utc::now().timestamp_millis();
        for _ in 0..50 {
            det.observe_udp_at(27015, 100, now - 2000);
        }
        let sig = det.compute_signal();
        assert!(!sig.detected);
    }

    #[test]
    fn burst_outside_port_range_does_not_count() {
        let det = GameDetector::new();
        let now = Utc::now().timestamp_millis();
        for i in 0..50i64 {
            det.observe_udp_at(30000, 100, now - i);
        }
        let sig = det.compute_signal();
        assert!(!sig.detected);
    }

    #[test]
    fn burst_above_max_size_does_not_count() {
        let det = GameDetector::new();
        let now = Utc::now().timestamp_millis();
        for i in 0..50i64 {
            det.observe_udp_at(27015, 1000, now - i);
        }
        let sig = det.compute_signal();
        assert!(!sig.detected);
    }

    #[test]
    fn custom_profile_can_be_registered() {
        let det = GameDetector::new();
        let custom = GameProfile {
            id: "test_game".to_string(),
            name: "Test Game".to_string(),
            process_names: vec!["test.exe".to_string()],
            udp_ports: vec![12345],
            burst_threshold_pps: 5.0,
            max_packet_size: 500,
        };
        det.register_profile(custom);
        let now = Utc::now().timestamp_millis();
        for i in 0..10i64 {
            det.observe_udp_at(12345, 200, now - i);
        }
        let sig = det.compute_signal();
        assert_eq!(sig.game_id.as_deref(), Some("test_game"));
    }

    #[test]
    fn custom_profile_replaces_existing_with_same_id() {
        let det = GameDetector::new();
        let mut p = det.list_profiles().into_iter().find(|p| p.id == "cs2").unwrap();
        p.burst_threshold_pps = 999.0;
        det.register_profile(p);
        let profile = det.list_profiles().into_iter().find(|p| p.id == "cs2").unwrap();
        assert!((profile.burst_threshold_pps - 999.0).abs() < 0.01);
    }

    #[test]
    fn scan_throttles_within_one_second() {
        let det = GameDetector::new();
        assert_eq!(det.scan_count(), 0);
        det.scan_processes();
        assert_eq!(det.scan_count(), 1);
        det.scan_processes();
        assert_eq!(det.scan_count(), 1);
    }

    #[test]
    fn unregister_profile_removes_it() {
        let det = GameDetector::new();
        assert!(det.list_profiles().iter().any(|p| p.id == "cs2"));
        assert!(det.unregister_profile("cs2"));
        assert!(!det.list_profiles().iter().any(|p| p.id == "cs2"));
        assert!(!det.unregister_profile("cs2"));
    }

    #[test]
    fn current_returns_last_signal() {
        let det = GameDetector::new();
        assert!(!det.current().detected);
        det.set_cached_matches(vec!["cs2.exe".to_string()]);
        let _ = det.compute_signal();
        assert!(det.current().detected);
        assert_eq!(det.current().game_id.as_deref(), Some("cs2"));
    }
}
