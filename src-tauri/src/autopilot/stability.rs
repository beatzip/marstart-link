//! Per-route stability index in [0, 1] (1 = perfectly stable).
//! Combines RTT coefficient-of-variation, loss frequency, and slope
//! of RTT over the recent window.

use crate::metrics::PingSample;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};

const DEFAULT_CAP: usize = 10;
const MIN_SAMPLES: usize = 3;

#[derive(Debug, Clone, Copy)]
pub struct StabilitySample {
    pub rtt_ms: f32,
    pub loss: bool,
    pub ts_ms: i64,
}

impl StabilitySample {
    pub fn from_ping(s: &PingSample) -> Self {
        Self {
            rtt_ms: s.rtt_ms.unwrap_or(0.0),
            loss: s.rtt_ms.is_none(),
            ts_ms: s.timestamp_ms,
        }
    }
}

struct StabilityInner {
    samples: HashMap<String, VecDeque<StabilitySample>>,
}

pub struct StabilityHistory {
    inner: RwLock<StabilityInner>,
    cap: usize,
}

impl StabilityHistory {
    pub fn new() -> Self {
        Self::with_cap(DEFAULT_CAP)
    }

    pub fn with_cap(cap: usize) -> Self {
        assert!(cap > 0, "StabilityHistory capacity must be > 0");
        Self {
            inner: RwLock::new(StabilityInner {
                samples: HashMap::new(),
            }),
            cap,
        }
    }

    pub fn record(&self, route_id: &str, sample: StabilitySample) {
        let mut g = self.inner.write();
        let buf = g
            .samples
            .entry(route_id.to_string())
            .or_insert_with(|| VecDeque::with_capacity(self.cap));
        if buf.len() == self.cap {
            buf.pop_front();
        }
        buf.push_back(sample);
    }

    pub fn stability_index(&self, route_id: &str) -> f32 {
        let g = self.inner.read();
        let Some(buf) = g.samples.get(route_id) else {
            return 0.5;
        };
        if buf.len() < MIN_SAMPLES {
            return 0.5;
        }
        let ok: Vec<(f32, i64)> = buf
            .iter()
            .filter(|s| !s.loss)
            .map(|s| (s.rtt_ms, s.ts_ms))
            .collect();
        if ok.is_empty() {
            return 0.0;
        }
        let mean = ok.iter().map(|(r, _)| r).sum::<f32>() / ok.len() as f32;
        let stddev = if ok.len() > 1 {
            let var = ok.iter().map(|(r, _)| (r - mean).powi(2)).sum::<f32>() / ok.len() as f32;
            var.sqrt()
        } else {
            0.0
        };
        let cv = if mean > 0.0 { stddev / mean } else { 0.0 };
        let loss_freq = buf.iter().filter(|s| s.loss).count() as f32 / buf.len() as f32;
        let slope_mag = if ok.len() >= 2 {
            let n = ok.len() as f32;
            let xs: Vec<f32> = (0..ok.len()).map(|i| i as f32).collect();
            let x_mean = xs.iter().sum::<f32>() / n;
            let num: f32 = xs
                .iter()
                .zip(ok.iter())
                .map(|(x, (y, _))| (x - x_mean) * (y - mean))
                .sum();
            let den: f32 = xs.iter().map(|x| (x - x_mean).powi(2)).sum();
            if den > 0.0 { (num / den).abs() } else { 0.0 }
        } else {
            0.0
        };
        let cv_penalty = (cv * 4.0).clamp(0.0, 1.0);
        let loss_penalty = loss_freq.clamp(0.0, 1.0);
        let slope_penalty = (slope_mag / 5.0).clamp(0.0, 1.0);
        let bad = cv_penalty * 0.6 + loss_penalty * 0.3 + slope_penalty * 0.1;
        (1.0 - bad).clamp(0.0, 1.0)
    }

    pub fn clear(&self, route_id: &str) {
        self.inner.write().samples.remove(route_id);
    }

    pub fn len(&self, route_id: &str) -> usize {
        self.inner
            .read()
            .samples
            .get(route_id)
            .map(|b| b.len())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample(rtt: Option<f32>, offset_ms: i64) -> StabilitySample {
        StabilitySample {
            rtt_ms: rtt.unwrap_or(0.0),
            loss: rtt.is_none(),
            ts_ms: Utc::now().timestamp_millis() - offset_ms,
        }
    }

    #[test]
    fn empty_returns_neutral() {
        let h = StabilityHistory::new();
        assert!((h.stability_index("x") - 0.5).abs() < 0.01);
    }

    #[test]
    fn few_samples_returns_neutral() {
        let h = StabilityHistory::new();
        h.record("x", sample(Some(20.0), 0));
        h.record("x", sample(Some(20.0), 100));
        assert!((h.stability_index("x") - 0.5).abs() < 0.01);
    }

    #[test]
    fn stable_rtts_yield_high_index() {
        let h = StabilityHistory::new();
        for i in 0..5 {
            h.record("x", sample(Some(20.0), i * 100));
        }
        let idx = h.stability_index("x");
        assert!(idx > 0.7, "expected high index, got {idx}");
    }

    #[test]
    fn high_loss_yields_low_index() {
        let h = StabilityHistory::new();
        h.record("x", sample(None, 0));
        h.record("x", sample(None, 100));
        h.record("x", sample(None, 200));
        h.record("x", sample(None, 300));
        h.record("x", sample(None, 400));
        let idx = h.stability_index("x");
        assert!(idx < 0.1, "expected very low index, got {idx}");
    }

    #[test]
    fn high_cv_yields_low_index() {
        let h = StabilityHistory::new();
        for (i, rtt) in [10.0, 100.0, 10.0, 100.0, 10.0].iter().enumerate() {
            h.record("x", sample(Some(*rtt), i as i64 * 100));
        }
        let idx = h.stability_index("x");
        assert!(idx < 0.5, "expected low index, got {idx}");
    }

    #[test]
    fn ring_buffer_caps_at_capacity() {
        let h = StabilityHistory::with_cap(3);
        for i in 0..10 {
            h.record("x", sample(Some(20.0), i * 100));
        }
        assert_eq!(h.len("x"), 3);
    }
}
