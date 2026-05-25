use crate::wireguard_config::{
    socket_addr_to_sockaddr_inet, ParsedConfig, ParsedPeer,
    WireguardAllowedIp, WireguardInterface, WireguardIpAddress, WireguardPeer,
    WIREGUARD_INTERFACE_HAS_LISTEN_PORT, WIREGUARD_INTERFACE_HAS_PRIVATE_KEY,
    WIREGUARD_INTERFACE_REPLACE_PEERS,
    WIREGUARD_PEER_HAS_ENDPOINT, WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE,
    WIREGUARD_PEER_HAS_PRESHARED_KEY, WIREGUARD_PEER_HAS_PUBLIC_KEY,
    WIREGUARD_PEER_REPLACE_ALLOWED_IPS,
};
use std::mem;
use std::net::IpAddr;
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0};

struct AlignedBlob {
    inner: Vec<u64>,
    len_bytes: usize,
}

impl AlignedBlob {
    fn new() -> Self {
        Self { inner: Vec::new(), len_bytes: 0 }
    }

    fn push<T: Copy>(&mut self, value: &T) {
        let size = mem::size_of::<T>();
        let src = value as *const T as *const u8;
        let bytes = unsafe { std::slice::from_raw_parts(src, size) };

        let required_u64s = (self.len_bytes + size + 7) / 8;
        if self.inner.len() < required_u64s {
            self.inner.resize(required_u64s, 0);
        }

        unsafe {
            let dst = (self.inner.as_mut_ptr() as *mut u8).add(self.len_bytes);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, size);
        }
        self.len_bytes += size;
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.inner.as_ptr() as *const u8, self.len_bytes) }
    }
}

#[inline]
fn ip_to_allowed_ip(ip: IpAddr, cidr: u8) -> WireguardAllowedIp {
    let mut out: WireguardAllowedIp = unsafe { mem::zeroed() };
    match ip {
        IpAddr::V4(v4) => {
            out.address = WireguardIpAddress {
                v4: IN_ADDR {
                    S_un: IN_ADDR_0 { S_addr: u32::from_be_bytes(v4.octets()) },
                },
            };
            out.address_family = AF_INET;
        }
        IpAddr::V6(v6) => {
            out.address = WireguardIpAddress {
                v6: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: v6.octets() },
                },
            };
            out.address_family = AF_INET6;
        }
    }
    out.cidr = cidr;
    out
}

fn build_interface(config: &ParsedConfig) -> WireguardInterface {
    let mut iface: WireguardInterface = unsafe { mem::zeroed() };
    iface.flags = WIREGUARD_INTERFACE_REPLACE_PEERS | WIREGUARD_INTERFACE_HAS_PRIVATE_KEY;
    iface.private_key = config.private_key;
    if let Some(port) = config.listen_port {
        iface.listen_port = port;
        iface.flags |= WIREGUARD_INTERFACE_HAS_LISTEN_PORT;
    }
    iface.peers_count = config.peers.len() as u32;
    iface
}

fn build_peer(peer: &ParsedPeer) -> WireguardPeer {
    let mut out: WireguardPeer = unsafe { mem::zeroed() };
    out.flags = WIREGUARD_PEER_HAS_PUBLIC_KEY | WIREGUARD_PEER_REPLACE_ALLOWED_IPS;
    out.public_key = peer.public_key;

    if let Some(psk) = peer.preshared_key {
        out.preshared_key = psk;
        out.flags |= WIREGUARD_PEER_HAS_PRESHARED_KEY;
    }
    if let Some(keepalive) = peer.persistent_keepalive {
        out.persistent_keepalive = keepalive;
        out.flags |= WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE;
    }
    if let Some(endpoint) = &peer.endpoint {
        out.endpoint = socket_addr_to_sockaddr_inet(endpoint);
        out.flags |= WIREGUARD_PEER_HAS_ENDPOINT;
    }

    out.allowed_ips_count = peer.allowed_ips.len() as u32;
    out
}

pub fn serialize_config(config: &ParsedConfig) -> Result<Vec<u8>, String> {
    debug_assert_eq!(mem::align_of::<WireguardInterface>(), 8);
    debug_assert_eq!(mem::align_of::<WireguardPeer>(), 8);
    debug_assert_eq!(mem::align_of::<WireguardAllowedIp>(), 8);

    let estimated_size = mem::size_of::<WireguardInterface>()
        + config.peers.len() * mem::size_of::<WireguardPeer>()
        + config.peers.iter().map(|p| p.allowed_ips.len() * mem::size_of::<WireguardAllowedIp>()).sum::<usize>();

    let mut blob = AlignedBlob::new();
    blob.inner.reserve((estimated_size + 7) / 8);

    let iface = build_interface(config);
    blob.push(&iface);

    for peer in &config.peers {
        let peer_blob = build_peer(peer);
        blob.push(&peer_blob);

        for allowed_ip in &peer.allowed_ips {
            let ip_blob = ip_to_allowed_ip(allowed_ip.address, allowed_ip.cidr);
            blob.push(&ip_blob);
        }
    }

    Ok(blob.as_bytes().to_vec())
}

pub fn hexdump(data: &[u8], limit: usize) -> String {
    let mut out = String::new();
    for (i, byte) in data.iter().take(limit).enumerate() {
        if i % 16 == 0 {
            if i > 0 {
                out.push('\n');
            }
            out.push_str(&format!("{:04x}: ", i));
        }
        out.push_str(&format!("{:02x} ", byte));
    }
    if data.len() > limit {
        out.push_str(&format!("\n... ({} more bytes)", data.len() - limit));
    }
    out
}
