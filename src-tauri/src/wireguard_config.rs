use std::net::SocketAddr;
use windows::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, SOCKADDR_INET,
};

pub const WIREGUARD_KEY_LENGTH: usize = 32;

// ============================================================================
// FLAGS (точные значения из wireguard.h)
// ============================================================================
pub type WireguardInterfaceFlag = u32;
pub const WIREGUARD_INTERFACE_HAS_PUBLIC_KEY: WireguardInterfaceFlag = 1 << 0;
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
pub const WIREGUARD_ALLOWED_IP_REMOVE: WireguardAllowedIpFlag = 1 << 0;

// ============================================================================
// LAYER 1: PARSED CONFIG (Safe Rust)
// ============================================================================
#[derive(Debug, Clone)]
pub struct ParsedConfig {
    pub private_key: [u8; WIREGUARD_KEY_LENGTH],
    pub listen_port: Option<u16>,
    pub interface_address: Option<std::net::IpAddr>,
    pub interface_prefix: Option<u8>,
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
// LAYER 2: NATIVE MODEL (WireGuard NT ABI — mirror 1:1 из wireguard.h)
// ============================================================================
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct WireguardInterface {
    pub flags: WireguardInterfaceFlag,
    pub listen_port: u16,
    pub private_key: [u8; WIREGUARD_KEY_LENGTH],
    pub public_key: [u8; WIREGUARD_KEY_LENGTH],
    pub peers_count: u32,
}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct WireguardPeer {
    pub flags: WireguardPeerFlag,
    pub reserved: u32,
    pub public_key: [u8; WIREGUARD_KEY_LENGTH],
    pub preshared_key: [u8; WIREGUARD_KEY_LENGTH],
    pub persistent_keepalive: u16,
    pub endpoint: SOCKADDR_INET,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_handshake: u64,
    pub allowed_ips_count: u32,
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
    pub address: WireguardIpAddress,
    pub address_family: ADDRESS_FAMILY,
    pub cidr: u8,
}

// ============================================================================
// HELPER: SocketAddr → SOCKADDR_INET
// ============================================================================
pub fn socket_addr_to_sockaddr_inet(addr: &SocketAddr) -> SOCKADDR_INET {
    let mut sockaddr: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            sockaddr.si_family = AF_INET;
            sockaddr.Ipv4.sin_family = AF_INET;
            sockaddr.Ipv4.sin_port = v4.port().to_be();
            sockaddr.Ipv4.sin_addr = IN_ADDR {
                S_un: IN_ADDR_0 { S_addr: u32::from_be_bytes(v4.ip().octets()) },
            };
        },
        SocketAddr::V6(v6) => {
            sockaddr.si_family = AF_INET6;
            sockaddr.Ipv6.sin6_family = AF_INET6;
            sockaddr.Ipv6.sin6_port = v6.port().to_be();
            sockaddr.Ipv6.sin6_flowinfo = v6.flowinfo();
            sockaddr.Ipv6.sin6_addr = IN6_ADDR {
                u: windows::Win32::Networking::WinSock::IN6_ADDR_0 { Byte: v6.ip().octets() },
            };
            sockaddr.Ipv6.Anonymous.sin6_scope_id = v6.scope_id();
        },
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
    fn test_offsets() {
        assert_eq!(offset_of!(WireguardInterface, flags), 0);
        assert_eq!(offset_of!(WireguardInterface, listen_port), 4);
        assert_eq!(offset_of!(WireguardPeer, flags), 0);
        assert_eq!(offset_of!(WireguardPeer, reserved), 4);
        assert_eq!(offset_of!(WireguardAllowedIp, address), 0);
        assert_eq!(offset_of!(WireguardAllowedIp, address_family), 16);
        assert_eq!(offset_of!(WireguardAllowedIp, cidr), 18);
    }

    #[test]
    fn print_sizes() {
        println!("Interface size: {}", size_of::<WireguardInterface>());
        println!("Peer size: {}", size_of::<WireguardPeer>());
        println!("AllowedIp size: {}", size_of::<WireguardAllowedIp>());
    }

    #[test] 
    fn test_peer_critical_offsets() {
        assert_eq!(offset_of!(WireguardPeer, persistent_keepalive), 72, "keepalive offset wrong");
        assert_eq!(offset_of!(WireguardPeer, endpoint), 76, "endpoint must be at 0x4c");
        assert_eq!(offset_of!(WireguardPeer, tx_bytes), 104, "tx_bytes must be at 0x68");
        assert_eq!(offset_of!(WireguardPeer, allowed_ips_count), 128, "allowed_ips_count must be at 0x80");
        assert_eq!(size_of::<WireguardPeer>(), 136, "WireguardPeer must be 136 bytes");
    }

    #[test]
    fn test_interface_critical_offsets() {
        assert_eq!(offset_of!(WireguardInterface, private_key), 6);
        assert_eq!(offset_of!(WireguardInterface, public_key), 38);
        assert_eq!(size_of::<WireguardInterface>(), 80, "WireguardInterface must be 80 bytes");
    }
}