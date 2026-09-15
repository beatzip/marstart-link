//! Profile abstraction extended for SD-WAN multi-endpoint support.
//!
//! Старая сигнатура `load_profile(&str) -> Result<Profile>` сохранена.
//! Добавлены поля `endpoints` и `wg_config_path` для интеграции с
//! route manager / autopilot. Backwards-compatible: пустой `endpoints`
//! означает "профиль без SD-WAN".

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    #[serde(default)]
    pub display_name: String,
    /// Список candidate-endpoints для auto-route selection / load balancing.
    /// Если пуст — профиль ведёт себя как одиночный туннель.
    #[serde(default)]
    pub endpoints: Vec<EndpointSpec>,
    /// Optional path to a .conf file used for actual WG bring-up.
    #[serde(default)]
    pub wg_config_path: Option<String>,
    /// Multiple config paths for multi-adapter SD-WAN support.
    /// If empty, falls back to `wg_config_path` as a single-element list.
    #[serde(default)]
    pub wg_config_paths: Vec<String>,
    /// Managed destination for route installation (e.g. "203.0.113.0/24").
    /// If None, routes are installed per-endpoint address.
    #[serde(default)]
    pub managed_destination: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointSpec {
    pub id: String,
    pub addr: SocketAddr,
    /// Optional human-readable label (e.g. "EU-Frankfurt").
    #[serde(default)]
    pub label: String,
    /// Weight bias for the route scorer (1.0 = neutral).
    #[serde(default = "default_weight")]
    pub weight: f32,
}

fn default_weight() -> f32 {
    1.0
}

pub fn load_profile(id: &str) -> Result<Profile, String> {
    if id.is_empty() || id.contains('/') || id.contains('\\') || id.contains("..") {
        return Err("invalid profile id".to_string());
    }

    let exe_path =
        std::env::current_exe().map_err(|e| format!("failed to get executable path: {e}"))?;
    let exe_dir = exe_path
        .parent()
        .ok_or_else(|| "failed to get executable directory".to_string())?;
    let candidates = [
        exe_dir.join("profiles").join(format!("{id}.conf")),
        exe_dir
            .join("resources")
            .join("profiles")
            .join(format!("{id}.conf")),
    ];
    let config_path = candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            format!("WireGuard profile '{id}' not found; expected profiles/{id}.conf")
        })?;
    let wg_config_path = config_path
        .into_os_string()
        .into_string()
        .map_err(|_| "profile path contains non-UTF-8 characters".to_string())?;

    Ok(Profile {
        id: id.to_string(),
        display_name: id.to_string(),
        endpoints: Vec::new(),
        wg_config_path: Some(wg_config_path.clone()),
        wg_config_paths: vec![wg_config_path],
        managed_destination: None,
    })
}

impl Profile {
    /// Returns the list of WireGuard config paths to use for multi-adapter setup.
    /// Falls back to `wg_config_path` if `wg_config_paths` is empty.
    pub fn get_config_paths(&self) -> Vec<String> {
        if !self.wg_config_paths.is_empty() {
            self.wg_config_paths.clone()
        } else if let Some(path) = &self.wg_config_path {
            vec![path.clone()]
        } else {
            Vec::new()
        }
    }

    /// Returns the number of paths this profile supports.
    pub fn path_count(&self) -> usize {
        self.get_config_paths().len()
    }

    /// Test-only: Builds a two-path Profile from environment variables.
    ///
    /// Reads:
    ///   `MARSTART_PATH_A_CONFIG` — filesystem path to Path A WireGuard .conf
    ///   `MARSTART_PATH_B_CONFIG` — filesystem path to Path B WireGuard .conf
    ///   `MARSTART_MANAGED_DESTINATION` — destination CIDR (e.g. "203.0.113.10/32")
    ///
    /// No secrets are read from the environment — only file paths and a
    /// destination CIDR. The actual private keys remain inside the .conf
    /// files on the external filesystem.
    ///
    /// This function is only available when the `test` feature is enabled
    /// or on Windows targets. It does NOT affect production builds.
    #[cfg(any(test, target_os = "windows"))]
    pub fn from_test_env() -> Result<Self, String> {
        let path_a = std::env::var("MARSTART_PATH_A_CONFIG")
            .map_err(|_| "MARSTART_PATH_A_CONFIG env var not set")?;
        let path_b = std::env::var("MARSTART_PATH_B_CONFIG")
            .map_err(|_| "MARSTART_PATH_B_CONFIG env var not set")?;
        let managed_destination = std::env::var("MARSTART_MANAGED_DESTINATION").ok();

        // Verify config files exist
        if !std::path::Path::new(&path_a).is_file() {
            return Err(format!("MARSTART_PATH_A_CONFIG file not found: {}", path_a));
        }
        if !std::path::Path::new(&path_b).is_file() {
            return Err(format!("MARSTART_PATH_B_CONFIG file not found: {}", path_b));
        }

        Ok(Profile {
            id: "live-test".to_string(),
            display_name: "Live Test Profile".to_string(),
            endpoints: Vec::new(),
            wg_config_path: Some(path_a.clone()),
            wg_config_paths: vec![path_a, path_b],
            managed_destination,
        })
    }
}
