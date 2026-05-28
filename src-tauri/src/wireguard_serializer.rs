use crate::wireguard_config::*;
use std::mem::size_of;
use std::net::IpAddr;
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR};

/// Сериализует ParsedConfig в бинарный blob для WireGuardSetConfiguration.
/// Layout: WireguardInterface | WireguardPeer₁ | AllowedIp₁₁ … | WireguardPeer₂ | …
pub fn serialize_config(config: &ParsedConfig) -> Result<Vec<u8>, String> {
    let mut total = size_of::<WireguardInterface>();
    for peer in &config.peers {
        total += size_of::<WireguardPeer>();
        total += peer.allowed_ips.len() * size_of::<WireguardAllowedIp>();
    }

    let mut blob = vec![0u8; total];
    let mut off = 0;

    if !config.dns_servers.is_empty() {
        tracing::info!("DNS servers in config: {:?}", config.dns_servers);
    }
    if let (Some(addr), Some(prefix)) = (config.interface_address, config.interface_prefix) {
        tracing::info!("Interface address: {}/{}", addr, prefix);
    }

    // ── Interface ──────────────────────────────────────────────────────────
    let mut iface_flags = WIREGUARD_INTERFACE_HAS_PRIVATE_KEY | WIREGUARD_INTERFACE_REPLACE_PEERS;
    if config.listen_port.is_some() {
        iface_flags |= WIREGUARD_INTERFACE_HAS_LISTEN_PORT;
    }

    let iface = WireguardInterface {
        flags:       iface_flags,
        listen_port: config.listen_port.unwrap_or(0),
        private_key: config.private_key,
        public_key:  [0u8; WIREGUARD_KEY_LENGTH], // драйвер вычислит сам
        peers_count: config.peers.len() as u32,
    };
    write_struct(&iface, &mut blob, &mut off);

    // ── Peers ──────────────────────────────────────────────────────────────
    for peer in &config.peers {
        let mut pflags = WIREGUARD_PEER_HAS_PUBLIC_KEY | WIREGUARD_PEER_REPLACE_ALLOWED_IPS;
        if peer.preshared_key.is_some()       { pflags |= WIREGUARD_PEER_HAS_PRESHARED_KEY; }
        if peer.persistent_keepalive.is_some() { pflags |= WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE; }
        if peer.endpoint.is_some()             { pflags |= WIREGUARD_PEER_HAS_ENDPOINT; }

        let endpoint = peer.endpoint
            .map(|e| socket_addr_to_sockaddr_inet(&e))
            .unwrap_or_else(|| unsafe { std::mem::zeroed() });

        let wg_peer = WireguardPeer {
            flags:                pflags,
            reserved:             0,
            public_key:           peer.public_key,
            preshared_key:        peer.preshared_key.unwrap_or([0u8; WIREGUARD_KEY_LENGTH]),
            persistent_keepalive: peer.persistent_keepalive.unwrap_or(0),
            endpoint,
            tx_bytes:             0,
            rx_bytes:             0,
            last_handshake:       0,
            allowed_ips_count:    peer.allowed_ips.len() as u32,
        };
        write_struct(&wg_peer, &mut blob, &mut off);

        // ── AllowedIPs ─────────────────────────────────────────────────────
        for aip in &peer.allowed_ips {
            // ✅ FIX: from_ne_bytes preserves network byte order in memory.
            //   from_be_bytes was causing REVERSED IP bytes → wrong routes.
            let (address, address_family) = match aip.address {
                IpAddr::V4(v4) => {
                    let mut addr: WireguardIpAddress = unsafe { std::mem::zeroed() };
                    // ✅ from_ne_bytes (NOT from_be_bytes)
                    unsafe {
                        addr.v4 = IN_ADDR {
                            S_un: IN_ADDR_0 {
                                S_addr: u32::from_ne_bytes(v4.octets()),
                            },
                        };
                    }
                    (addr, AF_INET)
                }
                IpAddr::V6(v6) => {
                    let mut addr: WireguardIpAddress = unsafe { std::mem::zeroed() };
                    unsafe {
                        addr.v6 = IN6_ADDR {
                            u: windows::Win32::Networking::WinSock::IN6_ADDR_0 {
                                Byte: v6.octets(),
                            },
                        };
                    }
                    (addr, AF_INET6)
                }
            };

            let wg_ip = WireguardAllowedIp {
                address,
                address_family,
                cidr: aip.cidr,
            };
            write_struct(&wg_ip, &mut blob, &mut off);
        }
    }

    debug_assert_eq!(off, total, "serializer produced unexpected size");
    Ok(blob)
}

/// Безопасная копия #[repr(C)] структуры в буфер
fn write_struct<T: Copy>(val: &T, buf: &mut Vec<u8>, off: &mut usize) {
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts((val as *const T) as *const u8, size_of::<T>())
    };
    buf[*off..*off + size_of::<T>()].copy_from_slice(bytes);
    *off += size_of::<T>();
}

/// Читает peer-статистику из GetConfiguration blob.
/// Возвращает Vec<(tx_bytes, rx_bytes, last_handshake_unix_secs)>
pub fn read_peer_stats(blob: &[u8]) -> Vec<(u64, u64, u64)> {
    let iface_size = size_of::<WireguardInterface>();
    let peer_size  = size_of::<WireguardPeer>();
    let aip_size   = size_of::<WireguardAllowedIp>();

    if blob.len() < iface_size { return vec![]; }

    let iface: WireguardInterface = unsafe {
        std::ptr::read_unaligned(blob.as_ptr() as *const WireguardInterface)
    };

    let mut off = iface_size;
    let mut result = Vec::new();

    for _ in 0..iface.peers_count {
        if off + peer_size > blob.len() { break; }
        let peer: WireguardPeer = unsafe {
            std::ptr::read_unaligned(blob[off..].as_ptr() as *const WireguardPeer)
        };
        off += peer_size;
        off += peer.allowed_ips_count as usize * aip_size;

        result.push((
            peer.tx_bytes,
            peer.rx_bytes,
            filetime_to_unix(peer.last_handshake),
        ));
    }

    result
}

/// Windows FILETIME (100ns intervals since 1601-01-01) → Unix seconds
pub fn filetime_to_unix(ft: u64) -> u64 {
    if ft == 0 { return 0; }
    // 100ns intervals from 1601-01-01 to 1970-01-01 = 116 444 736 000 000 000
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    ft.saturating_sub(EPOCH_DIFF) / 10_000_000
}

/// Hexdump для отладки
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
            s.push(if byte.is_ascii_graphic() || *byte == b' ' { *byte as char } else { '.' });
        }
        s.push_str("|\n");
    }
    if data.len() > max_bytes {
        s.push_str(&format!("... ({} more bytes)\n", data.len() - max_bytes));
    }
    s
}