use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use tauri::AppHandle;
use windows::Win32::NetworkManagement::IpHelper::{InitializeIpForwardEntry, MIB_IPFORWARD_ROW2};
use windows::Win32::Networking::WinSock::{AF_INET, IN_ADDR};

pub fn resolve_dll_path(app: &AppHandle, dll_name: &str) -> Result<PathBuf, String> {
    app.path_resolver()
        .resolve_resource(dll_name)
        .ok_or_else(|| format!("Critical: {} not found in bundled resources", dll_name))
}

pub fn cidr_to_subnet_mask(prefix_len: u8) -> Result<String, String> {
    if prefix_len > 32 {
        return Err(format!("Invalid prefix length: {}", prefix_len));
    }
    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len as u32)
    };
    let bytes = mask.to_be_bytes();
    Ok(format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]))
}

pub fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid CIDR format: {}", cidr));
    }
    
    // ✅ ИСПРАВЛЕНО: явная типизация для закрытия E0282
    let ip: IpAddr = parts[0].parse::<IpAddr>().map_err(|e| e.to_string())?;
    let prefix_len: u8 = parts[1].parse::<u8>().map_err(|e| e.to_string())?;
    
    if prefix_len > 32 {
        return Err(format!("Invalid prefix length: {}", prefix_len));
    }
    Ok((ip, prefix_len))
}

pub unsafe fn create_forward_row(ip: Ipv4Addr, prefix_len: u8, interface_index: u32) -> MIB_IPFORWARD_ROW2 {
    let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
    InitializeIpForwardEntry(&mut row);

    row.InterfaceIndex = interface_index;
    row.DestinationPrefix.PrefixLength = prefix_len;
    row.DestinationPrefix.Prefix.si_family = AF_INET;

    row.DestinationPrefix.Prefix.Ipv4.sin_addr = IN_ADDR {
        S_un: windows::Win32::Networking::WinSock::IN_ADDR_0 {
            S_addr: u32::from_be_bytes(ip.octets()),
        },
    };

    row.NextHop.si_family = AF_INET;
    row.Metric = 8;

    row
}