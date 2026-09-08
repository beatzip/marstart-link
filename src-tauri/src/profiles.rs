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
        wg_config_path: Some(wg_config_path),
    })
}
