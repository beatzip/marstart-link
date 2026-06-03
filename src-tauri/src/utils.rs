#![allow(dead_code)]
use std::net::Ipv4Addr;
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

#[cfg(target_os = "windows")]
use windows::Win32::NetworkManagement::IpHelper::{InitializeIpForwardEntry, MIB_IPFORWARD_ROW2};
#[cfg(target_os = "windows")]
use windows::Win32::Networking::WinSock::AF_INET;

pub fn resolve_dll_path(handle: &AppHandle, dll_name: &str) -> Result<PathBuf, String> {
    // 1. Try the bundled resource path used by Tauri v2.
    if let Ok(resource_path) = handle.path().resolve(
        format!("resources/{dll_name}"),
        tauri::path::BaseDirectory::Resource,
    ) {
        if resource_path.exists() {
            return Ok(resource_path);
        }
    }

    // 2. Fallback: development relative path.
    let dev_path = PathBuf::from("resources").join(dll_name);
    if dev_path.exists() {
        return Ok(dev_path);
    }

    Err(format!(
        "DLL {} not found in resources or dev path",
        dll_name
    ))
}

pub fn parse_cidr(cidr: &str) -> Result<(std::net::IpAddr, u8), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid CIDR format: {}", cidr));
    }
    let ip = parts[0]
        .parse::<std::net::IpAddr>()
        .map_err(|e| format!("Invalid IP in CIDR: {}", e))?;
    let prefix = parts[1]
        .parse::<u8>()
        .map_err(|e| format!("Invalid prefix in CIDR: {}", e))?;
    Ok((ip, prefix))
}

#[cfg(target_os = "windows")]
pub unsafe fn create_forward_row(
    ip: Ipv4Addr,
    prefix_len: u8,
    interface_index: u32,
) -> MIB_IPFORWARD_ROW2 {
    let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
    InitializeIpForwardEntry(&mut row);

    row.InterfaceIndex = interface_index;
    row.DestinationPrefix.Prefix.si_family = AF_INET;
    row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
    row.DestinationPrefix.PrefixLength = prefix_len;
    row.Metric = 8;

    row
}
