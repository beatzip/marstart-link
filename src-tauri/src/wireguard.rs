use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use wireguard_nt::{Adapter, SetInterface};

use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToIndex, GetIfEntry2, GetIpForwardEntry2, GetIpInterfaceEntry,
    InitializeIpInterfaceEntry, SetIpInterfaceEntry, SetIpForwardEntry2, MIB_IF_ROW2,
    MIB_IPINTERFACE_ROW,
};
use windows::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows::Win32::Networking::WinSock::AF_INET;

use crate::utils::{create_forward_row, parse_cidr, resolve_dll_path};

pub struct TunnelState {
    pub adapter: Arc<Mutex<Option<Adapter>>>,
}

impl TunnelState {
    pub fn new() -> Self {
        Self {
            adapter: Arc::new(Mutex::new(None)),
        }
    }

    pub fn clone_for_panic_hook(&self) -> Arc<Mutex<Option<Adapter>>> {
        self.adapter.clone()
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
    let dll = load_wireguard_dll(&app)?;
    let config = parse_set_interface(&config_content)?;

    let (adapter, interface_index) = {
        let mut adapter_lock = state.adapter.lock().map_err(|e| e.to_string())?;

        if let Some(old) = adapter_lock.take() {
            drop(old);
        }

        let adapter = Adapter::create(dll, &adapter_name, "GameAccelerator", None)
            .map_err(|e| format!("Failed to create adapter: {e}"))?;

        adapter
            .set_config(&config)
            .map_err(|e| format!("SetConfig failed: {e}"))?;

        let luid = adapter.get_luid();
        let interface_index = luid_to_index(luid)?;

        (adapter, interface_index)
    }; // Lock отпущен

    wait_for_interface_up(interface_index, Duration::from_secs(15)).await?;
    set_interface_mtu(interface_index, 1280)?;
    force_route_metrics(interface_index, &expected_routes)?;

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

#[tauri::command]
pub async fn tunnel_disconnect(state: State<'_, TunnelState>) -> Result<(), String> {
    let mut adapter_lock = state.adapter.lock().map_err(|e| e.to_string())?;
    if let Some(adapter) = adapter_lock.take() {
        drop(adapter);
    }
    Ok(())
}

fn load_wireguard_dll(app: &AppHandle) -> Result<Arc<wireguard_nt::dll::dll>, String> {
    let dll_path = resolve_dll_path(app, "wireguard.dll")?;
    wireguard_nt::dll::load(&dll_path)
        .map_err(|e| format!("Failed to load wireguard.dll: {e}"))
}

fn parse_set_interface(config_content: &str) -> Result<SetInterface, String> {
    config_content
        .parse::<SetInterface>()
        .map_err(|e| format!("Failed to parse WireGuard config: {e}"))
}

fn luid_to_index(luid: NET_LUID_LH) -> Result<u32, String> {
    unsafe {
        let mut index = 0u32;
        ConvertInterfaceLuidToIndex(&luid, &mut index)
            .ok()
            .map_err(|e| format!("Failed to convert LUID to InterfaceIndex: {e}"))?;
        Ok(index)
    }
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

        if let IpAddr::V4(ipv4) = ip {
            let mut row = unsafe { create_forward_row(ipv4, prefix_len, interface_index) };

            unsafe {
                if GetIpForwardEntry2(&mut row).is_err() {
                    tracing::warn!("Route not found for {cidr}, skipping metric force");
                    continue;
                }

                row.Metric = 8;

                if SetIpForwardEntry2(&mut row).is_err() {
                    tracing::warn!("Failed to set metric for {cidr}");
                }
            }
        }
    }

    Ok(())
}