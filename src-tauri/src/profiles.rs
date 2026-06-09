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
    // Реальная загрузка из файлового хранилища — отдельная задача (см. roadmap).
    // Build absolute config path relative to executable location
    let wg_config_path = (|| {
        let exe_path =
            std::env::current_exe().map_err(|e| format!("Failed to get exe path: {}", e))?;
        let exe_dir = exe_path
            .parent()
            .map(|p| p.to_path_buf())
            .ok_or_else(|| "Failed to get exe parent directory".to_string())?;
        Ok::<_, String>(
            exe_dir
                .join("profiles")
                .join(format!("{}.conf", id))
                .into_os_string()
                .into_string()
                .map_err(|_| "Config path contains non-UTF8 characters".to_string())?,
        )
    })()?;

    Ok(Profile {
        id: id.to_string(),
        display_name: id.to_string(),
        endpoints: Vec::new(),
        wg_config_path,
    })
}
