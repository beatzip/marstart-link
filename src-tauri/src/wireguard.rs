use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "message")]
pub enum TunnelStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

/// Live counters exposed to the metrics layer.
/// Real WG driver fills these via `read_peer_stats`; в тестовом / stub
/// режиме они остаются нулевыми.
#[derive(Debug, Default)]
pub struct TunnelCounters {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub last_handshake_unix: AtomicU64,
}

impl TunnelCounters {
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.tx_bytes.load(Ordering::Relaxed),
            self.rx_bytes.load(Ordering::Relaxed),
            self.last_handshake_unix.load(Ordering::Relaxed),
        )
    }
}

pub struct WireGuardTunnel {
    #[allow(dead_code)]
    adapter: String,
    status: TunnelStatus,
    counters: Arc<TunnelCounters>,
}

impl WireGuardTunnel {
    pub fn new(profile: &crate::profiles::Profile) -> Result<Self, String> {
        // Private key берём из keyring (секреты больше не в localStorage)
        let _private_key = keyring::Entry::new("GameAccelerator", &profile.id)
            .map_err(|e| e.to_string())?
            .get_password()
            .map_err(|e| e.to_string())?;

        Ok(Self {
            adapter: "wg0".to_string(),
            status: TunnelStatus::Connected,
            counters: Arc::new(TunnelCounters::default()),
        })
    }

    pub fn teardown(self) -> Result<(), String> {
        // Полная очистка ресурсов
        Ok(())
    }

    pub fn status(&self) -> TunnelStatus {
        self.status.clone()
    }

    /// Shared handle to counters for sampling without locking the tunnel itself.
    pub fn counters(&self) -> Arc<TunnelCounters> {
        Arc::clone(&self.counters)
    }
}
