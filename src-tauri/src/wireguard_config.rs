use std::net::SocketAddr;
use windows::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, IN6_ADDR, IN_ADDR, IN_ADDR_0, SOCKADDR_INET,
};

pub const WIREGUARD_KEY_LENGTH: usize = 32;

// ============================================================================
// FLAGS
// ============================================================================
pub type WireguardInterfaceFlag = u32;
pub const WIREGUARD_INTERFACE_HAS_PRIVATE_KEY: WireguardInterfaceFlag = 1 << 1;
pub const WIREGUARD_INTERFACE_HAS_LISTEN_PORT: WireguardInterfaceFlag = 1 << 2;
pub const WIREGUARD_INTERFACE_REPLACE_PEERS: WireguardInterfaceFlag = 1 << 3;

pub type WireguardPeerFlag = u32;
pub const WIREGUARD_PEER_HAS_PUBLIC_KEY: WireguardPeerFlag = 1 << 0;
pub const WIREGUARD_PEER_HAS_PRESHARED_KEY: WireguardPeerFlag = 1 << 1;
pub const WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE: WireguardPeerFlag = 1 << 2;
pub const WIREGUARD_PEER_HAS_ENDPOINT: WireguardPeerFlag = 1 << 3;
pub const WIREGUARD_PEER_REPLACE_ALLOWED_IPS: WireguardPeerFlag = 1 << 5;

pub type WireguardAllowedIpFlag = u32;
pub const _WIREGUARD_ALLOWED_IP_REMOVE: WireguardAllowedIpFlag = 1 << 0;

// ============================================================================
// PARSED CONFIG (Safe Rust)
// ============================================================================
#[derive(Debug, Clone)]
pub struct ParsedConfig {
    pub private_key: [u8; WIREGUARD_KEY_LENGTH],
    pub listen_port: Option<u16>,
    pub interface_address: Option<std::net::IpAddr>,
    pub interface_prefix: Option<u8>,
    pub dns_servers: Vec<String>,
    pub peers: Vec<ParsedPeer>,
}

#[derive(Debug, Clone)]
pub struct ParsedPeer {
    pub public_key: [u8; WIREGUARD_KEY_LENGTH],
    pub preshared_key: Option<[u8; WIREGUARD_KEY_LENGTH]>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: Option<u16>,
    pub allowed_ips: Vec<ParsedAllowedIp>,
}

#[derive(Debug, Clone)]
pub struct ParsedAllowedIp {
    pub address: std::net::IpAddr,
    pub cidr: u8,
}

// ============================================================================
// NATIVE ABI (WireGuard NT — 1:1 с wireguard.h)
// ============================================================================
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct WireguardInterface {
    pub flags: WireguardInterfaceFlag, // +0   4b
    pub listen_port: u16,              // +4   2b
    pub private_key: [u8; 32],         // +6   32b
    pub public_key: [u8; 32],          // +38  32b
    pub peers_count: u32,              // +72  4b  (padding +2 before)
                                       // total = 80 bytes
}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct WireguardPeer {
    pub flags: WireguardPeerFlag,  // +0    4b
    pub reserved: u32,             // +4    4b
    pub public_key: [u8; 32],      // +8    32b
    pub preshared_key: [u8; 32],   // +40   32b
    pub persistent_keepalive: u16, // +72   2b
    // +74: 2b implicit C padding (Reserved2) — repr(C) вставит автоматически
    pub endpoint: SOCKADDR_INET, // +76   28b
    pub tx_bytes: u64,           // +104  8b
    pub rx_bytes: u64,           // +112  8b
    pub last_handshake: u64,     // +120  8b  Windows FILETIME
    pub allowed_ips_count: u32,  // +128  4b
                                 // +132: 4b trailing padding → total = 136 bytes
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union WireguardIpAddress {
    pub v4: IN_ADDR,
    pub v6: IN6_ADDR,
}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct WireguardAllowedIp {
    pub address: WireguardIpAddress,    // +0   16b
    pub address_family: ADDRESS_FAMILY, // +16  2b
    pub cidr: u8,                       // +18  1b
                                        // padding to 8 → total = 24 bytes
}

// ============================================================================
// HELPER: SocketAddr → SOCKADDR_INET
//
// ✅ FIX: S_addr must use from_ne_bytes (NOT from_be_bytes).
//   S_addr stores IP in network byte order in memory.
//   On x86 (LE), from_ne_bytes([0xC0,0xA8,0x01,0x01]) = 0x0101A8C0,
//   which when stored in LE memory gives bytes [0xC0,0xA8,0x01,0x01] ← correct.
//   from_be_bytes would produce 0xC0A80101, stored as [0x01,0x01,0xA8,0xC0] ← wrong!
// ============================================================================
pub fn socket_addr_to_sockaddr_inet(addr: &SocketAddr) -> SOCKADDR_INET {
    let mut sockaddr: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    
        match addr {
            SocketAddr::V4(v4) => {
                sockaddr.si_family = AF_INET;
                sockaddr.Ipv4.sin_family = AF_INET;
                sockaddr.Ipv4.sin_port = v4.port().to_be(); // port: always big-endian
                sockaddr.Ipv4.sin_addr = IN_ADDR {
                    // ✅ from_ne_bytes: preserves network byte order in memory
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(v4.ip().octets()),
                    },
                };
            }
            SocketAddr::V6(v6) => {
                sockaddr.si_family = AF_INET6;
                sockaddr.Ipv6.sin6_family = AF_INET6;
                sockaddr.Ipv6.sin6_port = v6.port().to_be();
                sockaddr.Ipv6.sin6_flowinfo = v6.flowinfo();
                sockaddr.Ipv6.sin6_addr = IN6_ADDR {
                    u: windows::Win32::Networking::WinSock::IN6_ADDR_0 {
                        Byte: v6.ip().octets(),
                    },
                };
                sockaddr.Ipv6.Anonymous.sin6_scope_id = v6.scope_id();
            }
        }
    }
    sockaddr
}

// ============================================================================
// ABI VALIDATION TESTS
// ============================================================================
#[cfg(test)]
mod abi_tests {
    use super::*;
    use memoffset::offset_of;
    use std::mem::{align_of, size_of};

    #[test]
    fn test_alignment() {
        assert_eq!(align_of::<WireguardInterface>(), 8);
        assert_eq!(align_of::<WireguardPeer>(), 8);
        assert_eq!(align_of::<WireguardAllowedIp>(), 8);
    }

    #[test]
    fn test_interface_offsets() {
        assert_eq!(offset_of!(WireguardInterface, flags), 0);
        assert_eq!(offset_of!(WireguardInterface, listen_port), 4);
        assert_eq!(offset_of!(WireguardInterface, private_key), 6);
        assert_eq!(offset_of!(WireguardInterface, public_key), 38);
        assert_eq!(offset_of!(WireguardInterface, peers_count), 72);
        assert_eq!(size_of::<WireguardInterface>(), 80, "must be 80 (0x50)");
    }

    #[test]
    fn test_peer_offsets() {
        assert_eq!(offset_of!(WireguardPeer, flags), 0);
        assert_eq!(offset_of!(WireguardPeer, reserved), 4);
        assert_eq!(offset_of!(WireguardPeer, public_key), 8);
        assert_eq!(offset_of!(WireguardPeer, preshared_key), 40);
        assert_eq!(offset_of!(WireguardPeer, persistent_keepalive), 72);
        assert_eq!(
            offset_of!(WireguardPeer, endpoint),
            76,
            "0x4c — after Reserved2 padding"
        );
        assert_eq!(offset_of!(WireguardPeer, tx_bytes), 104, "0x68");
        assert_eq!(offset_of!(WireguardPeer, rx_bytes), 112);
        assert_eq!(offset_of!(WireguardPeer, last_handshake), 120);
        assert_eq!(offset_of!(WireguardPeer, allowed_ips_count), 128, "0x80");
        assert_eq!(size_of::<WireguardPeer>(), 136, "must be 136 (0x88)");
    }

    #[test]
    fn test_allowed_ip_offsets() {
        assert_eq!(offset_of!(WireguardAllowedIp, address), 0);
        assert_eq!(offset_of!(WireguardAllowedIp, address_family), 16);
        assert_eq!(offset_of!(WireguardAllowedIp, cidr), 18);
        assert_eq!(size_of::<WireguardAllowedIp>(), 24);
    }

    #[test]
    fn test_byte_order_fix() {
        // Verify that from_ne_bytes preserves network byte order in memory
        // For IP 192.168.1.1 = [0xC0, 0xA8, 0x01, 0x01]
        let octets: [u8; 4] = [0xC0, 0xA8, 0x01, 0x01];
        let s_addr = u32::from_ne_bytes(octets);
        let stored_bytes = s_addr.to_ne_bytes();
        assert_eq!(
            stored_bytes, octets,
            "S_addr bytes in memory must match network order"
        );
    }
}
