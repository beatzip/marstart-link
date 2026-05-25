// src/wireguard_serializer.rs
use crate::wireguard_parser::WireGuardConfig;
use std::net::{IpAddr, SocketAddr};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_INET};

// Флаги из wireguard.h
const WIREGUARD_INTERFACE_HAS_PRIVATE_KEY: u32 = 1 << 1;
const WIREGUARD_INTERFACE_HAS_LISTEN_PORT: u32 = 1 << 2;
const WIREGUARD_INTERFACE_REPLACE_PEERS: u32 = 1 << 3;

const WIREGUARD_PEER_HAS_PUBLIC_KEY: u32 = 1 << 0;
const WIREGUARD_PEER_HAS_PRESHARED_KEY: u32 = 1 << 1;
const WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE: u32 = 1 << 2;
const WIREGUARD_PEER_HAS_ENDPOINT: u32 = 1 << 3;
const WIREGUARD_PEER_REPLACE_ALLOWED_IPS: u32 = 1 << 5;

#[repr(C)]
#[derive(Clone, Copy)]
struct WireGuardAllowedIp {
    address: [u8; 16], // Union IN_ADDR/IN6_ADDR (max 16 bytes)
    address_family: u16,
    cidr: u8,
    flags: u32,
}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct WireGuardPeer {
    flags: u32,
    reserved: u32,
    public_key: [u8; 32],
    preshared_key: [u8; 32],
    persistent_keepalive: u16,
    endpoint: SOCKADDR_INET,
    tx_bytes: u64,
    rx_bytes: u64,
    last_handshake: u64,
    allowed_ips_count: u32,
}

#[repr(C, align(8))]
struct WireGuardInterface {
    flags: u32,
    listen_port: u16,
    private_key: [u8; 32],
    public_key: [u8; 32],
    peers_count: u32,
}

pub fn serialize_config(config: &WireGuardConfig) -> Result<Vec<u8>, String> {
    let mut flags = WIREGUARD_INTERFACE_REPLACE_PEERS | WIREGUARD_INTERFACE_HAS_PRIVATE_KEY;
    if config.interface.listen_port != 0 {
        flags |= WIREGUARD_INTERFACE_HAS_LISTEN_PORT;
    }

    let interface = WireGuardInterface {
        flags,
        listen_port: config.interface.listen_port,
        private_key: config.interface.private_key,
        public_key: [0; 32], // Не передаем публичный ключ при настройке
        peers_count: config.peers.len() as u32,
    };

    let mut buffer = Vec::new();
    buffer.extend_from_slice(unsafe { std::slice::from_raw_parts(
        &interface as *const _ as *const u8,
        std::mem::size_of::<WireGuardInterface>(),
    )});

    for peer in &config.peers {
        let mut peer_flags = WIREGUARD_PEER_REPLACE_ALLOWED_IPS | WIREGUARD_PEER_HAS_PUBLIC_KEY;
        if peer.preshared_key.is_some() { peer_flags |= WIREGUARD_PEER_HAS_PRESHARED_KEY; }
        if peer.keepalive != 0 { peer_flags |= WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE; }
        if peer.endpoint.is_some() { peer_flags |= WIREGUARD_PEER_HAS_ENDPOINT; }

        let mut endpoint: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        if let Some(sock_addr) = peer.endpoint {
            unsafe {
                match sock_addr.ip() {
                    IpAddr::V4(ipv4) => {
                        endpoint.Ipv4.sin_family = AF_INET;
                        endpoint.Ipv4.sin_port = sock_addr.port().to_be(); // Network byte order
                        endpoint.Ipv4.sin_addr.S_un.S_addr = u32::from_be_bytes(ipv4.octets());
                    }
                    IpAddr::V6(ipv6) => {
                        endpoint.Ipv6.sin6_family = AF_INET6;
                        endpoint.Ipv6.sin6_port = sock_addr.port().to_be();
                        endpoint.Ipv6.sin6_addr.u.Byte = ipv6.octets();
                    }
                }
            }
        }

        let wg_peer = WireGuardPeer {
            flags: peer_flags,
            reserved: 0,
            public_key: peer.public_key,
            preshared_key: peer.preshared_key.unwrap_or([0; 32]),
            persistent_keepalive: peer.keepalive,
            endpoint,
            tx_bytes: 0, rx_bytes: 0, last_handshake: 0,
            allowed_ips_count: peer.allowed_ips.len() as u32,
        };

        buffer.extend_from_slice(unsafe { std::slice::from_raw_parts(
            &wg_peer as *const _ as *const u8,
            std::mem::size_of::<WireGuardPeer>(),
        )});

        for allowed_ip in &peer.allowed_ips {
            let mut addr_bytes = [0u8; 16];
            let family = match allowed_ip.ip {
                IpAddr::V4(ipv4) => {
                    addr_bytes[..4].copy_from_slice(&ipv4.octets());
                    AF_INET
                },
                IpAddr::V6(ipv6) => {
                    addr_bytes.copy_from_slice(&ipv6.octets());
                    AF_INET6
                },
            };

            let ip_struct = WireGuardAllowedIp {
                address: addr_bytes,
                address_family: family,
                cidr: allowed_ip.prefix_len,
                flags: 0,
            };

            buffer.extend_from_slice(unsafe { std::slice::from_raw_parts(
                &ip_struct as *const _ as *const u8,
                std::mem::size_of::<WireGuardAllowedIp>(),
            )});
        }
    }

    Ok(buffer)
}