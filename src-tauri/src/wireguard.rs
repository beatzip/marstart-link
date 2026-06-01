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
        // Private key from keyring
        let _private_key = keyring::Entry::new("GameAccelerator", &profile.id)
            .map_err(|e| e.to_string())?
            .get_password()
            .map_err(|e| e.to_string())?;

        Ok(Self {
            adapter: "wg0".to_string(),
            status: TunnelStatus::Connected,
        })
    }

    pub fn teardown(self) -> Result<(), String> {
        Ok(())
    }

    pub fn status(&self) -> TunnelStatus {
        self.status.clone()
    }
}
