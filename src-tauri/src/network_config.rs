// src/network_config.rs
use std::net::IpAddr;
use windows::Win32::NetworkManagement::IpHelper::{
    CreateUnicastIpAddressEntry, InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
    CreateIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
    ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToGuid, IpDadStatePreferred,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use winreg::enums::*;
use winreg::RegKey;

/// Step 7: Assign an IP address to the virtual network adapter
pub fn assign_ip_address(interface_index: u32, ip: IpAddr, prefix_len: u8) -> Result<(), String> {
    unsafe {
        let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        InitializeUnicastIpAddressEntry(&mut row);
        row.InterfaceIndex = interface_index;
        row.OnLinkPrefixLength = prefix_len;
        // Skip the DAD (Duplicate Address Detection) delay and make the IP effective immediately.
        row.DadState = IpDadStatePreferred; 
        
        match ip {
            IpAddr::V4(ipv4) => {
                row.Address.si_family = AF_INET;
                row.Address.Ipv4.sin_family = AF_INET;
                row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_be_bytes(ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                row.Address.si_family = AF_INET6;
                row.Address.Ipv6.sin6_family = AF_INET6;
                row.Address.Ipv6.sin6_addr.u.Byte = ipv6.octets();
            }
        }

        let status = CreateUnicastIpAddressEntry(&row);
        // 5010 = ERROR_OBJECT_ALREADY_EXISTS (Ignore if called repeatedly)
        if status != 0 && status != 5010 { 
            return Err(format!("CreateUnicastIpAddressEntry failed: {}", status));
        }
    }
    Ok(())
}

/// Step 6: Inject routes (point AllowedIPs to the virtual network adapter)
pub fn add_route(interface_index: u32, destination: IpAddr, prefix_len: u8) -> Result<(), String> {
    unsafe {
        let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        InitializeIpForwardEntry(&mut row);
        row.InterfaceIndex = interface_index;
        row.Metric = 1; // Set high priority
        row.DestinationPrefix.PrefixLength = prefix_len;
        
        match destination {
            IpAddr::V4(ipv4) => {
                row.DestinationPrefix.Prefix.si_family = AF_INET;
                row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
                row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = u32::from_be_bytes(ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                row.DestinationPrefix.Prefix.si_family = AF_INET6;
                row.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
                row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte = ipv6.octets();
            }
        }

        let status = CreateIpForwardEntry2(&row);
        if status != 0 && status != 5010 {
            return Err(format!("CreateIpForwardEntry2 failed: {}", status));
        }
    }
    Ok(())
}

/// Step 8: Configure DNS (via registry, compatible with all Windows versions)
pub fn set_dns_servers(interface_index: u32, dns_servers: &[IpAddr]) -> Result<(), String> {
    if dns_servers.is_empty() {
        return Ok(());
    }

    unsafe {
        let mut luid = std::mem::zeroed();
        ConvertInterfaceIndexToLuid(interface_index, &mut luid)
            .map_err(|e| format!("ConvertInterfaceIndexToLuid failed: {}", e))?;
        
        let mut guid = std::mem::zeroed();
        ConvertInterfaceLuidToGuid(&luid, &mut guid)
            .map_err(|e| format!("ConvertInterfaceLuidToGuid failed: {}", e))?;

        // Format the GUID as a registry path. {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
        let guid_str = format!(
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            guid.data1, guid.data2, guid.data3,
            guid.data4[0], guid.data4[1], guid.data4[2], guid.data4[3],
            guid.data4[4], guid.data4[5], guid.data4[6], guid.data4[7]
        );

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let path = format!(r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{}", guid_str);
        let (key, _) = hklm.create_subkey(&path).map_err(|e| format!("Failed to open reg key: {}", e))?;
        
        let name_server: String = dns_servers.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(",");
        key.set_value("NameServer", &name_server).map_err(|e| format!("Failed to set DNS: {}", e))?;
    }
    Ok(())
}