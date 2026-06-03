//! Realtime monitoring service (A + B).
//!
//! Запускает фоновый tokio-таск, который с заданным интервалом:
//!   1. пингует каждый target из `MonitorConfig::targets`
//!   2. пушит `PingSample` в общий `MetricsStore`
//!   3. эмитит `monitor:tick` с агрегированными метриками
//!
//! Старт/стоп — через `MonitorService::start` / `stop`. Гарантируется,
//! что одновременно работает не более одного worker'а.

use crate::events::{EV_MONITOR_STATE, EV_MONITOR_TICK};
use crate::metrics::{MetricsStore, PingSample};
use crate::net_probe;
use chrono::Utc;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorTarget {
    pub id: String,
    pub addr: IpAddr,
    /// Используется как порт для TCP fallback (например 443 / 53).
    #[serde(default = "default_fallback_port")]
    pub fallback_port: u16,
}

fn default_fallback_port() -> u16 {
    443
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub interval_ms: u64,
    pub probe_timeout_ms: u64,
    pub targets: Vec<MonitorTarget>,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            interval_ms: 1000,
            probe_timeout_ms: 800,
            targets: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MonitorState {
    pub running: bool,
    pub interval_ms: u64,
    pub targets: Vec<MonitorTarget>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MonitorTick {
    pub timestamp_ms: i64,
    pub samples: Vec<TargetSample>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetSample {
    pub target_id: String,
    pub sample: PingSample,
}

#[derive(Clone)]
pub struct MonitorService {
    metrics: MetricsStore,
    state: Arc<Mutex<MonitorConfig>>,
    running: Arc<AtomicBool>,
    handle: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl MonitorService {
    pub fn new(metrics: MetricsStore) -> Self {
        Self {
            metrics,
            state: Arc::new(Mutex::new(MonitorConfig::default())),
            running: Arc::new(AtomicBool::new(false)),
            handle: Arc::new(Mutex::new(None)),
        }
    }

    pub fn metrics(&self) -> &MetricsStore {
        &self.metrics
    }

    pub fn snapshot_state(&self) -> MonitorState {
        let cfg = self.state.lock().clone();
        MonitorState {
            running: self.running.load(Ordering::Relaxed),
            interval_ms: cfg.interval_ms,
            targets: cfg.targets,
        }
    }

    pub fn set_targets(&self, targets: Vec<MonitorTarget>) {
        let mut cfg = self.state.lock();
        // Drop metric history for removed targets to keep memory bounded.
        let new_ids: std::collections::HashSet<_> = targets.iter().map(|t| t.id.clone()).collect();
        for t in &cfg.targets {
            if !new_ids.contains(&t.id) {
                self.metrics.remove_target(&t.id);
            }
        }
        for t in &targets {
            self.metrics.ensure_target(&t.id);
        }
        cfg.targets = targets;
    }

    pub fn set_interval(&self, interval_ms: u64, probe_timeout_ms: u64) {
        let mut cfg = self.state.lock();
        cfg.interval_ms = interval_ms.max(50);
        cfg.probe_timeout_ms = probe_timeout_ms.max(50);
    }

    pub fn start(&self, app: AppHandle) -> Result<(), String> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(()); // уже работает — идемпотентно
        }
        let metrics = self.metrics.clone();
        let cfg_arc = Arc::clone(&self.state);
        let running = Arc::clone(&self.running);
        let app_for_task = app.clone();

        let handle = tokio::spawn(async move {
            tracing::info!("monitor: worker started");
            while running.load(Ordering::Relaxed) {
                let cfg = cfg_arc.lock().clone();
                let interval = Duration::from_millis(cfg.interval_ms);
                let timeout = Duration::from_millis(cfg.probe_timeout_ms);

                if cfg.targets.is_empty() {
                    tokio::time::sleep(interval).await;
                    continue;
                }

                let mut futs = Vec::with_capacity(cfg.targets.len());
                for t in &cfg.targets {
                    let id = t.id.clone();
                    let addr = t.addr;
                    let port = t.fallback_port;
                    futs.push(async move {
                        let r = net_probe::ping(addr, timeout, port).await;
                        (id, r)
                    });
                }
                let results = futures_join_all(futs).await;

                let now = Utc::now();
                let mut samples_for_event = Vec::with_capacity(results.len());
                for (id, r) in results {
                    let sample = match r.rtt {
                        Some(rtt) => PingSample::ok(rtt, now),
                        None => PingSample::lost(now),
                    };
                    metrics.push(&id, sample);
                    samples_for_event.push(TargetSample {
                        target_id: id,
                        sample,
                    });
                }

                let payload = MonitorTick {
                    timestamp_ms: now.timestamp_millis(),
                    samples: samples_for_event,
                };
                if let Err(e) = app_for_task.emit(EV_MONITOR_TICK, &payload) {
                    tracing::warn!("monitor: failed to emit tick: {e}");
                }

                tokio::time::sleep(interval).await;
            }
            tracing::info!("monitor: worker stopped");
        });

        *self.handle.lock() = Some(handle);
        let _ = app.emit(EV_MONITOR_STATE, self.snapshot_state());
        Ok(())
    }

    pub fn stop(&self, app: &AppHandle) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(h) = self.handle.lock().take() {
            h.abort();
        }
        let _ = app.emit(EV_MONITOR_STATE, self.snapshot_state());
    }
}

/// Tiny ad-hoc helper: equivalent of `futures::future::join_all` без зависимости от
/// crate `futures`. Все запросы стартуют сразу, поэтому общая длительность
/// определяется самым медленным таргетом, а не суммой.
async fn futures_join_all<F, T>(futs: Vec<F>) -> Vec<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let mut handles = Vec::with_capacity(futs.len());
    for f in futs {
        handles.push(tokio::spawn(f));
    }
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        match h.await {
            Ok(v) => out.push(v),
            Err(e) => tracing::warn!("monitor: task join error: {e}"),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_targets_creates_metric_slots() {
        let m = MetricsStore::new();
        let svc = MonitorService::new(m.clone());
        svc.set_targets(vec![MonitorTarget {
            id: "a".into(),
            addr: "1.1.1.1".parse().unwrap(),
            fallback_port: 443,
        }]);
        assert!(m.list_targets().contains(&"a".to_string()));
    }

    #[test]
    fn set_targets_removes_orphans() {
        let m = MetricsStore::new();
        let svc = MonitorService::new(m.clone());
        svc.set_targets(vec![MonitorTarget {
            id: "a".into(),
            addr: "1.1.1.1".parse().unwrap(),
            fallback_port: 443,
        }]);
        svc.set_targets(vec![MonitorTarget {
            id: "b".into(),
            addr: "8.8.8.8".parse().unwrap(),
            fallback_port: 443,
        }]);
        let ids = m.list_targets();
        assert!(!ids.contains(&"a".to_string()));
        assert!(ids.contains(&"b".to_string()));
    }

    #[test]
    fn interval_floor_enforced() {
        let svc = MonitorService::new(MetricsStore::new());
        svc.set_interval(10, 10);
        let s = svc.snapshot_state();
        assert!(s.interval_ms >= 50);
    }
}
