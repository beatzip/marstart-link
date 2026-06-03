//! Event names + payload types for Tauri -> UI broadcasts.
//!
//! Все события идут через `tauri::Emitter::emit` с этими константами.
//! Полезные нагрузки сериализуются в JSON через serde.

use serde::Serialize;

pub const EV_MONITOR_TICK: &str = "monitor:tick";
pub const EV_MONITOR_STATE: &str = "monitor:state";
pub const EV_ROUTE_CHANGED: &str = "routes:changed";
pub const EV_ROUTE_STATE: &str = "routes:state";
pub const EV_QOS_STATE: &str = "qos:state";
pub const EV_GAME_DETECTED: &str = "game:detected";
pub const EV_GAME_STATE: &str = "game:state";
pub const EV_LB_STATE: &str = "lb:state";
pub const EV_MULTIHOP_STATE: &str = "multihop:state";
pub const EV_AUTOPILOT_STATE: &str = "autopilot:state";
pub const EV_AUTOPILOT_ACTION: &str = "autopilot:action";

#[derive(Debug, Clone, Serialize)]
pub struct LogEvent<'a> {
    pub level: &'a str,
    pub source: &'a str,
    pub message: String,
}
