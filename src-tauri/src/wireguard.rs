use keyring::Entry;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub enum TunnelStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

pub struct WireGuardTunnel {
    adapter: String,
    status: TunnelStatus,
}

impl WireGuardTunnel {
    pub fn new(profile: &profiles::Profile) -> Result<Self, String> {
        let private_key = Entry::new("GameAccelerator", &profile.id)
            .map_err(|e| e.to_string())?
            .get_password()
            .map_err(|e| e.to_string())?;

        // Здесь будет реальная инициализация WireGuard-NT + wintun
        Ok(Self {
            adapter: "wg0".to_string(),
            status: TunnelStatus::Connected,
        })
    }

    pub fn teardown(self) -> Result<(), String> {
        // Полная очистка адаптера, маршрутов, DNS
        Ok(())
    }

    pub fn status(&self) -> TunnelStatus {
        self.status.clone()
    }
}
