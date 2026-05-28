// src/wireguard_serializer.rs
use crate::wireguard_config::*;
use std::mem::size_of;
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

pub fn serialize_config(config: &ParsedConfig) -> Result<Vec<u8>, String> {
    // 1. Рассчитываем точный размер буфера
    let mut total_size = size_of::<WireguardInterface>();
    for peer in &config.peers {
        total_size += size_of::<WireguardPeer>();
        total_size += peer.allowed_ips.len() * size_of::<WireguardAllowedIp>();
    }

    let mut buffer: Vec<u8> = Vec::with_capacity(total_size);
    
    // 2. Формируем Interface
    let mut interface_flags = WIREGUARD_INTERFACE_HAS_PRIVATE_KEY | WIREGUARD_INTERFACE_REPLACE_PEERS;
    if config.listen_port.is_some() {
        interface_flags |= WIREGUARD_INTERFACE_HAS_LISTEN_PORT;
    }

    let interface = WireguardInterface {
        flags: interface_flags,
        listen_port: config.listen_port.unwrap_or(0),
        private_key: config.private_key,
        public_key: [0u8; 32], // Драйвер сам вычислит публичный ключ из приватного
        peers_count: config.peers.len() as u32,
    };
    append_struct(&mut buffer, &interface);

    // 3. Формируем Peers и их AllowedIPs
    for peer in &config.peers {
        let mut peer_flags = WIREGUARD_PEER_HAS_PUBLIC_KEY | WIREGUARD_PEER_REPLACE_ALLOWED_IPS;
        if peer.preshared_key.is_some() {
            peer_flags |= WIREGUARD_PEER_HAS_PRESHARED_KEY;
        }
        if peer.persistent_keepalive.is_some() {
            peer_flags |= WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE;
        }
        if peer.endpoint.is_some() {
            peer_flags |= WIREGUARD_PEER_HAS_ENDPOINT;
        }

        let endpoint = peer.endpoint
            .map(|e| socket_addr_to_sockaddr_inet(&e))
            .unwrap_or_else(|| unsafe { std::mem::zeroed() });

        let wg_peer = WireguardPeer {
            flags: peer_flags,
            reserved: 0,
            public_key: peer.public_key,
            preshared_key: peer.preshared_key.unwrap_or([0u8; 32]),
            persistent_keepalive: peer.persistent_keepalive.unwrap_or(0),
            endpoint,
            tx_bytes: 0,
            rx_bytes: 0,
            last_handshake: 0,
            allowed_ips_count: peer.allowed_ips.len() as u32,
        };
        append_struct(&mut buffer, &wg_peer);

        for allowed_ip in &peer.allowed_ips {
            let (address, family) = match allowed_ip.address {
                std::net::IpAddr::V4(ipv4) => {
                    let mut addr: WireguardIpAddress = unsafe { std::mem::zeroed() };
                    addr.v4.S_un.S_addr = u32::from_be_bytes(ipv4.octets());
                    (addr, AF_INET)
                },
                std::net::IpAddr::V6(ipv6) => {
                    let mut addr: WireguardIpAddress = unsafe { std::mem::zeroed() };
                    addr.v6.u.Byte = ipv6.octets();
                    (addr, AF_INET6)
                },
            };

            let wg_allowed_ip = WireguardAllowedIp {
                address,
                address_family: family,
                cidr: allowed_ip.cidr,
                flags: 0, // 0 = Add (WIREGUARD_ALLOWED_IP_REMOVE = 1)
            };
            append_struct(&mut buffer, &wg_allowed_ip);
        }
    }

    if buffer.len() != total_size {
        return Err(format!("Serializer bug: expected {} bytes, got {}", total_size, buffer.len()));
    }

    Ok(buffer)
}

fn append_struct<T>(buffer: &mut Vec<u8>, val: &T) {
    let ptr = val as *const T as *const u8;
    let size = size_of::<T>();
    let slice = unsafe { std::slice::from_raw_parts(ptr, size) };
    buffer.extend_from_slice(slice);
}

pub fn hexdump(data: &[u8], limit: usize) -> String {
    let mut s = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        if i * 16 >= limit {
            s.push_str("...\n");
            break;
        }
        for b in chunk {
            s.push_str(&format!("{:02x} ", b));
        }
        s.push('\n');
    }
    s
}