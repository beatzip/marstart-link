use crate::wireguard_config::*;
use std::mem::size_of;
use std::net::IpAddr;
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR};

/// Преобразует ParsedConfig в бинарный blob для WireGuardSetConfiguration
pub fn serialize_config(config: &ParsedConfig) -> Result<Vec<u8>, String> {
    // 1. Считаем общий размер памяти
    let mut total_size = size_of::<WireguardInterface>();
    for peer in &config.peers {
        total_size += size_of::<WireguardPeer>();
        total_size += peer.allowed_ips.len() * size_of::<WireguardAllowedIp>();
    }

    let mut blob = vec![0u8; total_size];
    let mut offset = 0;

    if !config.dns_servers.is_empty() {
        tracing::info!("DNS servers parsed: {:?}", config.dns_servers);
    }

    // 2. Заполняем Interface
    let mut iface_flags = WIREGUARD_INTERFACE_HAS_PRIVATE_KEY | WIREGUARD_INTERFACE_REPLACE_PEERS;
    if config.listen_port.is_some() {
        iface_flags |= WIREGUARD_INTERFACE_HAS_LISTEN_PORT;
    }

    let iface = WireguardInterface {
        flags: iface_flags,
        listen_port: config.listen_port.unwrap_or(0),
        private_key: config.private_key,
        public_key: [0u8; WIREGUARD_KEY_LENGTH], // Драйвер сам вычислит публичный ключ
        peers_count: config.peers.len() as u32,
    };
    
    let iface_bytes: &[u8] = unsafe { 
        std::slice::from_raw_parts((&iface as *const WireguardInterface) as *const u8, size_of::<WireguardInterface>()) 
    };
    blob[offset..offset + size_of::<WireguardInterface>()].copy_from_slice(iface_bytes);
    offset += size_of::<WireguardInterface>();

    // 3. Заполняем Peers и AllowedIPs
    for peer in &config.peers {
        let mut peer_flags = WIREGUARD_PEER_HAS_PUBLIC_KEY | WIREGUARD_PEER_REPLACE_ALLOWED_IPS;
        if peer.preshared_key.is_some() { peer_flags |= WIREGUARD_PEER_HAS_PRESHARED_KEY; }
        if peer.persistent_keepalive.is_some() { peer_flags |= WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE; }
        if peer.endpoint.is_some() { peer_flags |= WIREGUARD_PEER_HAS_ENDPOINT; }

        let endpoint = peer.endpoint.map(|e| socket_addr_to_sockaddr_inet(&e)).unwrap_or_else(|| unsafe { std::mem::zeroed() });

        let wg_peer = WireguardPeer {
            flags: peer_flags,
            reserved: 0,
            public_key: peer.public_key,
            preshared_key: peer.preshared_key.unwrap_or([0u8; WIREGUARD_KEY_LENGTH]),
            persistent_keepalive: peer.persistent_keepalive.unwrap_or(0),
            endpoint,
            tx_bytes: 0,
            rx_bytes: 0,
            last_handshake: 0,
            allowed_ips_count: peer.allowed_ips.len() as u32,
        };

        let peer_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts((&wg_peer as *const WireguardPeer) as *const u8, size_of::<WireguardPeer>())
        };
        blob[offset..offset + size_of::<WireguardPeer>()].copy_from_slice(peer_bytes);
        offset += size_of::<WireguardPeer>();

        for allowed_ip in &peer.allowed_ips {
            let (address, address_family) = match allowed_ip.address {
                IpAddr::V4(ipv4) => {
                    let mut addr: WireguardIpAddress = unsafe { std::mem::zeroed() };
                    addr.v4 = IN_ADDR { S_un: IN_ADDR_0 { S_addr: u32::from_be_bytes(ipv4.octets()) } };
                    (addr, AF_INET)
                }
                IpAddr::V6(ipv6) => {
                    let mut addr: WireguardIpAddress = unsafe { std::mem::zeroed() };
                    addr.v6 = IN6_ADDR { u: windows::Win32::Networking::WinSock::IN6_ADDR_0 { Byte: ipv6.octets() } };
                    (addr, AF_INET6)
                }
            };

            let wg_allowed_ip = WireguardAllowedIp {
                address,
                address_family,
                cidr: allowed_ip.cidr,
            };

            let ip_bytes: &[u8] = unsafe {
                std::slice::from_raw_parts((&wg_allowed_ip as *const WireguardAllowedIp) as *const u8, size_of::<WireguardAllowedIp>())
            };
            blob[offset..offset + size_of::<WireguardAllowedIp>()].copy_from_slice(ip_bytes);
            offset += size_of::<WireguardAllowedIp>();
        }
    }

    Ok(blob)
}

/// Вспомогательная функция для отладки (Hexdump)
pub fn hexdump(data: &[u8], max_bytes: usize) -> String {
    let mut s = String::new();
    let len = data.len().min(max_bytes);
    for (i, chunk) in data[..len].chunks(16).enumerate() {
        s.push_str(&format!("{:08x}  ", i * 16));
        for (j, byte) in chunk.iter().enumerate() {
            s.push_str(&format!("{:02x} ", byte));
            if j == 7 { s.push(' '); }
        }
        if chunk.len() < 16 {
            for j in chunk.len()..16 {
                s.push_str("   ");
                if j == 7 { s.push(' '); }
            }
        }
        s.push_str(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                s.push(*byte as char);
            } else {
                s.push('.');
            }
        }
        s.push_str("|\n");
    }
    if data.len() > max_bytes {
        s.push_str(&format!("... ({} more bytes)\n", data.len() - max_bytes));
    }
    s
}