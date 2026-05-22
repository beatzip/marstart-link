use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::{AppHandle, State};
use wireguard_nt::{Adapter, AdapterState};
use windows::Win32::NetworkManagement::IpHelper::{
    GetIfEntry2, GetIpInterfaceEntry, GetIpForwardEntry2,
    InitializeIpInterfaceEntry, SetIpInterfaceEntry, SetIpForwardEntry2,
    MIB_IF_ROW2, MIB_IPINTERFACE_ROW,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::AF_INET;
use serde::{Serialize, Deserialize};

use crate::utils::{resolve_dll_path, parse_cidr, create_forward_row};

pub struct TunnelState {
    pub adapter: Mutex<Option<Adapter>>,
}

impl TunnelState {
    pub fn new() -> Self {
        Self { adapter: Mutex::new(None) }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TunnelStatus {
    pub is_active: bool,
    pub adapter_name: Option<String>,
    pub interface_index: Option<u32>,
    pub mtu: Option<u32>,
}

#[tauri::command]
pub async fn tunnel_apply_config(
    app: AppHandle,
    state: State<'_, TunnelState>,
    config_content: String,
    adapter_name: String,
    expected_routes: Vec<String>,
) -> Result<TunnelStatus, String> {
    let dll_path = resolve_dll_path(&app, "wireguard.dll")?;
    let dll_path_str = dll_path.to_str().ok_or("Invalid DLL path")?;

    // === ЭТАП 1: Синхронная работа под локом ===
    let (adapter, interface_index) = {
        let mut adapter_lock = state.adapter.lock().map_err(|e| e.to_string())?;

        if let Some(old) = adapter_lock.take() {
            let _ = old.set_state(AdapterState::Down);
            drop(old);
        }

        let adapter = Adapter::create(dll_path_str, &adapter_name, "GameAccelerator", None)
            .map_err(|e| format!("Failed to create adapter: {:?}", e))?;

        adapter.set_config(&config_content).map_err(|e| format!("SetConfig failed: {:?}", e))?;
        adapter.set_state(AdapterState::Up).map_err(|e| format!("SetState Up failed: {:?}", e))?;

        let if_idx = adapter.get_interface_index().map_err(|e| format!("Failed to get interface index: {:?}", e))?;
        (adapter, if_idx)
    }; // Lock отпущен

    // === ЭТАП 2: Асинхронное ожидание и настройка ===
    wait_for_interface_up(interface_index, Duration::from_secs(15)).await?;
    set_interface_mtu(interface_index, 1280)?;
    force_route_metrics(interface_index, &expected_routes)?;

    // === ЭТАП 3: Сохранение результата ===
    {
        let mut adapter_lock = state.adapter.lock().map_err(|e| e.to_string())?;
        *adapter_lock = Some(adapter);
    }

    Ok(TunnelStatus {
        is_active: true,
        adapter_name: Some(adapter_name),
        interface_index: Some(interface_index),
        mtu: Some(1280),
    })
}

async fn wait_for_interface_up(interface_index: u32, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        unsafe {
            let mut row: MIB_IF_ROW2 = std::mem::zeroed();
            row.InterfaceIndex = interface_index;
            if GetIfEntry2(&mut row).is_ok() && row.OperStatus == IfOperStatusUp {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err("Timeout waiting for interface to become UP".into())
}

fn set_interface_mtu(interface_index: u32, mtu: u32) -> Result<(), String> {
    unsafe {
        let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
        InitializeIpInterfaceEntry(&mut row);
        row.InterfaceIndex = interface_index;
        row.Family = AF_INET;

        if GetIpInterfaceEntry(&mut row).is_err() {
            return Err("GetIpInterfaceEntry failed".into());
        }
        row.NlMtu = mtu;
        if SetIpInterfaceEntry(&mut row).is_err() {
            return Err("SetIpInterfaceEntry (MTU) failed".into());
        }
    }
    Ok(())
}

fn force_route_metrics(interface_index: u32, expected_cidrs: &[String]) -> Result<(), String> {
    for cidr in expected_cidrs {
        let (ip, prefix_len) = parse_cidr(cidr)?;

        if let std::net::IpAddr::V4(ipv4) = ip {
            let mut row = unsafe { create_forward_row(ipv4, prefix_len, interface_index) };
            unsafe {
                if GetIpForwardEntry2(&mut row).is_err() {
                    tracing::warn!("Route not found for {}, skipping metric force", cidr);
                    continue;
                }
                row.Metric = 8;
                if SetIpForwardEntry2(&mut row).is_err() {
                    tracing::warn!("Failed to set metric for {}", cidr);
                }
            }
        }
    }
    Ok(())
}