#[cfg(target_os = "windows")]
use std::net::Ipv4Addr;
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

#[cfg(target_os = "windows")]
use windows::Win32::NetworkManagement::IpHelper::{InitializeIpForwardEntry, MIB_IPFORWARD_ROW2};
#[cfg(target_os = "windows")]
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
#[cfg(target_os = "windows")]
use windows::Win32::Networking::WinSock::{AF_INET, MIB_IPPROTO_NETMGMT};

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

/// Builds a `MIB_IPFORWARD_ROW2` entry for installing a route via
/// `CreateIpForwardEntry2`.  Uses LUID-based interface identification
/// (preferred over InterfaceIndex) and sets:
///   - Protocol = `MIB_IPPROTO_NETMGMT` (tag for ownership tracking)
///   - NextHop = 0.0.0.0 (on-link, WireGuard driver handles encapsulation)
///   - Metric = caller-specified (10 = active, 20 = standby)
#[cfg(target_os = "windows")]
pub unsafe fn create_forward_row(
    destination: Ipv4Addr,
    prefix_length: u8,
    interface_luid: u64,
    metric: u32,
) -> MIB_IPFORWARD_ROW2 {
    let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
    InitializeIpForwardEntry(&mut row);

    // Bind the route to the specific WireGuard adapter via LUID
    row.InterfaceLuid = NET_LUID_LH {
        Value: interface_luid,
    };

    // Destination prefix
    row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr =
        u32::from_ne_bytes(destination.octets());
    row.DestinationPrefix.PrefixLength = prefix_length;

    // NextHop: 0.0.0.0 = on-link
    row.NextHop.Ipv4.sin_family = AF_INET;
    row.NextHop.Ipv4.sin_addr.S_un.S_addr = 0;

    // Ownership tag + metric
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Metric = metric;

    row
}

#[cfg(not(target_os = "windows"))]
/// Builds a forward row — stub on non-Windows (returns zeroed memory).
pub unsafe fn create_forward_row(
    _destination: u32,
    _prefix_length: u8,
    _interface_luid: u64,
    _metric: u32,
) -> [u8; 0] {
    []
}
