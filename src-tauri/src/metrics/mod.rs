//! Sliding-window metrics: ping / jitter / loss.
//!
//! `MetricsStore` агрегирует выборки для каждого target'а (endpoint / hop).
//! Поток мониторинга пишет сюда `PingSample`, UI читает агрегаты через
//! Tauri commands и через events `monitor:tick`.
//!
//! Алгоритмы:
//! * jitter = mean(|rtt[i] - rtt[i-1]|) по succeeded RTT в окне (RFC 3550-style)
//! * loss   = lost / total в окне (в долях [0..1])
//! * stability score = низкий стандартный девиейшн RTT + низкий loss

use crate::ringbuf::RingBuffer;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_WINDOW: usize = 120; // ~2 минуты при tick=1s

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PingSample {
    /// RTT in milliseconds. `None` = packet lost.
    pub rtt_ms: Option<f32>,
    pub timestamp_ms: i64,
}

impl PingSample {
    pub fn ok(rtt: Duration, ts: DateTime<Utc>) -> Self {
        Self {
            rtt_ms: Some(rtt.as_secs_f32() * 1000.0),
            timestamp_ms: ts.timestamp_millis(),
        }
    }
    pub fn lost(ts: DateTime<Utc>) -> Self {
        Self {
            rtt_ms: None,
            timestamp_ms: ts.timestamp_millis(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AggregatedMetrics {
    pub target_id: String,
    /// Latest RTT in ms (None if last probe lost).
    pub latest_rtt_ms: Option<f32>,
    pub avg_rtt_ms: Option<f32>,
    pub min_rtt_ms: Option<f32>,
    pub max_rtt_ms: Option<f32>,
    pub jitter_ms: f32,
    /// Packet loss ratio in [0..1].
    pub loss_ratio: f32,
    /// Heuristic stability score in [0..1] (1 = perfect).
    pub stability: f32,
    pub samples: usize,
    pub window: usize,
}

/// Aggregation helpers — pure functions, easy to unit-test.
pub mod aggregate {
    use super::PingSample;

    pub fn loss_ratio(samples: &[PingSample]) -> f32 {
        if samples.is_empty() {
            return 0.0;
        }
        let lost = samples.iter().filter(|s| s.rtt_ms.is_none()).count() as f32;
        lost / samples.len() as f32
    }

    pub fn jitter_ms(samples: &[PingSample]) -> f32 {
        let rtts: Vec<f32> = samples.iter().filter_map(|s| s.rtt_ms).collect();
        if rtts.len() < 2 {
            return 0.0;
        }
        let mut acc = 0.0f32;
        for w in rtts.windows(2) {
            acc += (w[1] - w[0]).abs();
        }
        acc / (rtts.len() - 1) as f32
    }

    pub fn avg_min_max(samples: &[PingSample]) -> (Option<f32>, Option<f32>, Option<f32>) {
        let rtts: Vec<f32> = samples.iter().filter_map(|s| s.rtt_ms).collect();
        if rtts.is_empty() {
            return (None, None, None);
        }
        let mut min = f32::INFINITY;
        let mut max = f32::NEG_INFINITY;
        let mut sum = 0.0f32;
        for &v in &rtts {
            if v < min {
                min = v;
            }
            if v > max {
                max = v;
            }
            sum += v;
        }
        (Some(sum / rtts.len() as f32), Some(min), Some(max))
    }

    /// 0 = unstable, 1 = perfect. Combines normalized jitter & loss.
    pub fn stability(jitter_ms: f32, loss_ratio: f32) -> f32 {
        let j_norm = (jitter_ms / 50.0).clamp(0.0, 1.0); // 50 ms jitter ≈ "very bad"
        let l_norm = loss_ratio.clamp(0.0, 1.0);
        let bad = (j_norm * 0.5) + (l_norm * 0.5);
        (1.0 - bad).clamp(0.0, 1.0)
    }
}

#[derive(Debug, Clone)]
struct TargetSlot {
    buffer: RingBuffer<PingSample>,
}

#[derive(Debug, Clone)]
pub struct MetricsStore {
    inner: Arc<RwLock<MetricsInner>>,
}

#[derive(Debug)]
struct MetricsInner {
    targets: HashMap<String, TargetSlot>,
    window: usize,
}

impl MetricsStore {
    pub fn new() -> Self {
        Self::with_window(DEFAULT_WINDOW)
    }

    pub fn with_window(window: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(MetricsInner {
                targets: HashMap::new(),
                window,
            })),
        }
    }

    pub fn ensure_target(&self, target_id: &str) {
        let mut g = self.inner.write();
        if !g.targets.contains_key(target_id) {
            let buf = RingBuffer::new(g.window);
            g.targets
                .insert(target_id.to_string(), TargetSlot { buffer: buf });
        }
    }

    pub fn remove_target(&self, target_id: &str) {
        self.inner.write().targets.remove(target_id);
    }

    pub fn clear_target(&self, target_id: &str) {
        if let Some(slot) = self.inner.read().targets.get(target_id) {
            slot.buffer.clear();
        }
    }

    pub fn push(&self, target_id: &str, sample: PingSample) {
        self.ensure_target(target_id);
        if let Some(slot) = self.inner.read().targets.get(target_id) {
            slot.buffer.push(sample);
        }
    }

    pub fn list_targets(&self) -> Vec<String> {
        self.inner.read().targets.keys().cloned().collect()
    }

    pub fn samples(&self, target_id: &str) -> Vec<PingSample> {
        self.inner
            .read()
            .targets
            .get(target_id)
            .map(|s| s.buffer.snapshot())
            .unwrap_or_default()
    }

    pub fn aggregated(&self, target_id: &str) -> Option<AggregatedMetrics> {
        let (samples, window) = {
            let g = self.inner.read();
            let slot = g.targets.get(target_id)?;
            (slot.buffer.snapshot(), g.window)
        };
        let (avg, min, max) = aggregate::avg_min_max(&samples);
        let jitter = aggregate::jitter_ms(&samples);
        let loss = aggregate::loss_ratio(&samples);
        let stab = aggregate::stability(jitter, loss);
        let latest_rtt_ms = samples.last().and_then(|s| s.rtt_ms);
        Some(AggregatedMetrics {
            target_id: target_id.to_string(),
            latest_rtt_ms,
            avg_rtt_ms: avg,
            min_rtt_ms: min,
            max_rtt_ms: max,
            jitter_ms: jitter,
            loss_ratio: loss,
            stability: stab,
            samples: samples.len(),
            window,
        })
    }

    pub fn aggregated_all(&self) -> Vec<AggregatedMetrics> {
        let ids = self.list_targets();
        ids.into_iter()
            .filter_map(|id| self.aggregated(&id))
            .collect()
    }
}

impl Default for MetricsStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::time::Duration;

    fn s(rtt: Option<f32>) -> PingSample {
        PingSample {
            rtt_ms: rtt,
            timestamp_ms: Utc::now().timestamp_millis(),
        }
    }

    #[test]
    fn loss_ratio_computes() {
        let samples = vec![s(Some(10.0)), s(None), s(Some(20.0)), s(None)];
        assert!((aggregate::loss_ratio(&samples) - 0.5).abs() < 1e-6);
    }

    #[test]
    fn jitter_skips_lost() {
        let samples = vec![s(Some(10.0)), s(None), s(Some(20.0)), s(Some(15.0))];
        // rtts: [10,20,15] -> |10-20|+|20-15| = 15 / (3-1) = 7.5
        assert!((aggregate::jitter_ms(&samples) - 7.5).abs() < 1e-6);
    }

    #[test]
    fn stability_perfect_when_clean() {
        let stab = aggregate::stability(0.0, 0.0);
        assert!((stab - 1.0).abs() < 1e-6);
    }

    #[test]
    fn stability_drops_with_loss() {
        let a = aggregate::stability(0.0, 0.0);
        let b = aggregate::stability(0.0, 0.5);
        assert!(b < a);
    }

    #[test]
    fn store_aggregates_per_target() {
        let m = MetricsStore::with_window(8);
        let now = Utc::now();
        m.push("eu", PingSample::ok(Duration::from_millis(20), now));
        m.push("eu", PingSample::lost(now));
        m.push("eu", PingSample::ok(Duration::from_millis(40), now));
        m.push("us", PingSample::ok(Duration::from_millis(100), now));

        let eu = m.aggregated("eu").unwrap();
        assert_eq!(eu.samples, 3);
        assert!((eu.loss_ratio - (1.0 / 3.0)).abs() < 1e-3);
        let us = m.aggregated("us").unwrap();
        assert_eq!(us.samples, 1);
        assert_eq!(us.loss_ratio, 0.0);
    }

    #[test]
    fn store_remove_clears_target() {
        let m = MetricsStore::new();
        m.push("x", s(Some(5.0)));
        assert!(m.aggregated("x").is_some());
        m.remove_target("x");
        assert!(m.aggregated("x").is_none());
    }
}
