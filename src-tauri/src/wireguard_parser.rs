use crate::wireguard_config::{ParsedAllowedIp, ParsedConfig, ParsedPeer, WIREGUARD_KEY_LENGTH};
use base64::{engine::general_purpose, Engine as _};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

pub fn parse_wireguard_config(text: &str) -> Result<ParsedConfig, String> {
    let mut private_key: Option<[u8; WIREGUARD_KEY_LENGTH]> = None;
    let mut listen_port: Option<u16> = None;
    let mut interface_address: Option<std::net::IpAddr> = None;
    let mut interface_prefix: Option<u8> = None;
    let mut dns_servers: Vec<String> = Vec::new();
    let mut peers: Vec<ParsedPeer> = Vec::new();

    let mut current_peer: Option<ParsedPeerBuilder> = None;
    let mut in_interface = false;
    let mut in_peer = false;

    for (line_num, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            if let Some(peer_builder) = current_peer.take() {
                peers.push(peer_builder.build(line_num)?);
            }
            match line {
                "[Interface]" => {
                    in_interface = true;
                    in_peer = false;
                }
                "[Peer]" => {
                    in_interface = false;
                    in_peer = true;
                    current_peer = Some(ParsedPeerBuilder::new());
                }
                _ => return Err(format!("Line {}: Unknown section: {}", line_num + 1, line)),
            }
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("Line {}: Invalid format", line_num + 1));
        };
        let key = key.trim();
        let value = value.trim();

        if in_interface {
            match key {
                "PrivateKey" => private_key = Some(decode_wg_key(value, "PrivateKey", line_num)?),
                "ListenPort" => {
                    listen_port = Some(value.parse().map_err(|e| {
                        format!("Line {}: Invalid ListenPort: {}", line_num + 1, e)
                    })?)
                }
                "Address" => {
                    let Some((ip_str, prefix_str)) = value.split_once('/') else {
                        return Err(format!(
                            "Line {}: Address must be IP/prefix, got '{}'",
                            line_num + 1,
                            value
                        ));
                    };
                    interface_address = Some(ip_str.trim().parse().map_err(|e| {
                        format!(
                            "Line {}: Invalid Address IP '{}': {}",
                            line_num + 1,
                            ip_str,
                            e
                        )
                    })?);
                    interface_prefix = Some(prefix_str.trim().parse().map_err(|e| {
                        format!(
                            "Line {}: Invalid Address prefix '{}': {}",
                            line_num + 1,
                            prefix_str,
                            e
                        )
                    })?);
                }
                "DNS" => {
                    for dns in value.split(',') {
                        let dns = dns.trim();
                        if !dns.is_empty() {
                            dns_servers.push(dns.to_string());
                        }
                    }
                }
                _ => {}
            }
        } else if in_peer {
            let builder = current_peer
                .as_mut()
                .ok_or_else(|| format!("Line {}: Peer field outside [Peer]", line_num + 1))?;
            match key {
                "PublicKey" => {
                    builder.public_key = Some(decode_wg_key(value, "PublicKey", line_num)?)
                }
                "PresharedKey" => {
                    builder.preshared_key = Some(decode_wg_key(value, "PresharedKey", line_num)?)
                }
                "Endpoint" => {
                    let hostname_str = value.split(':').next().unwrap_or(value).to_string();
                    builder.endpoint_hostname = Some(hostname_str.clone());
                    builder.endpoint = Some(parse_endpoint(value, line_num)?);
                }
                "PersistentKeepalive" => {
                    builder.persistent_keepalive = Some(value.parse().map_err(|e| {
                        format!("Line {}: Invalid Keepalive: {}", line_num + 1, e)
                    })?)
                }
                "AllowedIPs" => {
                    for ip_cidr in value.split(',') {
                        let trimmed = ip_cidr.trim();
                        if !trimmed.is_empty() {
                            builder
                                .allowed_ips
                                .push(parse_allowed_ip(trimmed, line_num)?);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if let Some(peer_builder) = current_peer.take() {
        peers.push(peer_builder.build(text.lines().count())?);
    }
    let private_key = private_key.ok_or("Missing [Interface] PrivateKey")?;

    Ok(ParsedConfig {
        private_key,
        listen_port,
        interface_address,
        interface_prefix,
        dns_servers,
        peers,
    })
}

/// Semantic validation of a parsed WireGuard config.
///
/// Catches constraints that are syntactically valid but semantically broken:
/// all-zero keys, missing Endpoint/AllowedIPs for a client, duplicate peer
/// public keys, Address prefix range, and PrivateKey==PublicKey self-loop.
///
/// Called from `tunnel_apply_config` after successful `parse_wireguard_config`.
#[allow(dead_code)]
pub fn validate_config(config: &ParsedConfig) -> Result<(), String> {
    // PrivateKey must not be all zeros
    if config.private_key.iter().all(|&b| b == 0) {
        return Err(
            "PrivateKey состоит из нулей. Сгенерируйте новую пару ключей (wg genkey).".into(),
        );
    }

    // At least one [Peer] required for a client
    if config.peers.is_empty() {
        return Err(
            "Секция [Peer] отсутствует. Укажите PublicKey и Endpoint сервера.".into(),
        );
    }

    // Address field is required
    match (config.interface_address, config.interface_prefix) {
        (None, _) | (_, None) => {
            return Err(
                "Поле Address в [Interface] обязательно. Пример: Address = 10.0.0.2/32".into(),
            )
        }
        (Some(ip), Some(prefix)) => {
            let max = if ip.is_ipv4() { 32u8 } else { 128u8 };
            if prefix > max {
                return Err(format!(
                    "Address: префикс /{prefix} недопустим для {} (максимум /{max})",
                    if ip.is_ipv4() { "IPv4" } else { "IPv6" }
                ));
            }
        }
    }

    // Per-peer checks
    let mut seen_keys: Vec<[u8; WIREGUARD_KEY_LENGTH]> = Vec::new();

    for (idx, peer) in config.peers.iter().enumerate() {
        let label = format!("Peer #{}", idx + 1);

        if peer.public_key.iter().all(|&b| b == 0) {
            return Err(format!("{label}: PublicKey состоит из нулей."));
        }

        if config.private_key == peer.public_key {
            return Err(format!(
                "{label}: PublicKey совпадает с вашим PrivateKey — ошибка конфигурации."
            ));
        }

        if seen_keys.contains(&peer.public_key) {
            return Err(format!(
                "{label}: PublicKey уже используется в другом [Peer]."
            ));
        }
        seen_keys.push(peer.public_key);

        if peer.endpoint.is_none() {
            return Err(format!(
                "{label}: Endpoint отсутствует. Укажите адрес и порт сервера (host:port)."
            ));
        }

        if peer.allowed_ips.is_empty() {
            return Err(format!(
                "{label}: AllowedIPs пуст. Укажите хотя бы один маршрут, например: 0.0.0.0/0"
            ));
        }

        if let Some(psk) = &peer.preshared_key {
            if psk.iter().all(|&b| b == 0) {
                return Err(format!(
                    "{label}: PresharedKey состоит из нулей — удалите поле или замените ключ."
                ));
            }
        }
    }

    Ok(())
}

fn decode_wg_key(
    s: &str,
    field_name: &str,
    line_num: usize,
) -> Result<[u8; WIREGUARD_KEY_LENGTH], String> {
    let bytes = general_purpose::STANDARD.decode(s).map_err(|e| {
        format!(
            "Line {}: Invalid {} base64: {}",
            line_num + 1,
            field_name,
            e
        )
    })?;
    if bytes.len() != WIREGUARD_KEY_LENGTH {
        return Err(format!(
            "Line {}: {} must be 32 bytes",
            line_num + 1,
            field_name
        ));
    }
    let mut key = [0u8; WIREGUARD_KEY_LENGTH];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn parse_endpoint(s: &str, line_num: usize) -> Result<SocketAddr, String> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let mut addrs = s
        .to_socket_addrs()
        .map_err(|e| format!("Line {}: Failed to resolve '{}': {}", line_num + 1, s, e))?;
    addrs.next().ok_or_else(|| {
        format!(
            "Line {}: Endpoint '{}' resolved to no addresses",
            line_num + 1,
            s
        )
    })
}

fn parse_allowed_ip(s: &str, line_num: usize) -> Result<ParsedAllowedIp, String> {
    let Some((ip_str, cidr_str)) = s.split_once('/') else {
        return Err(format!("Line {}: Invalid AllowedIP '{}'", line_num + 1, s));
    };
    let address: IpAddr = ip_str
        .parse()
        .map_err(|e| format!("Line {}: Invalid IP '{}': {}", line_num + 1, ip_str, e))?;
    let cidr: u8 = cidr_str
        .parse()
        .map_err(|e| format!("Line {}: Invalid CIDR '{}': {}", line_num + 1, cidr_str, e))?;
    if cidr > (if address.is_ipv4() { 32 } else { 128 }) {
        return Err(format!("Line {}: CIDR too large", line_num + 1));
    }
    Ok(ParsedAllowedIp { address, cidr })
}

struct ParsedPeerBuilder {
    public_key: Option<[u8; WIREGUARD_KEY_LENGTH]>,
    preshared_key: Option<[u8; WIREGUARD_KEY_LENGTH]>,
    endpoint: Option<SocketAddr>,
    endpoint_hostname: Option<String>,
    persistent_keepalive: Option<u16>,
    allowed_ips: Vec<ParsedAllowedIp>,
}

impl ParsedPeerBuilder {
    fn new() -> Self {
        Self {
            public_key: None,
            preshared_key: None,
            endpoint: None,
            endpoint_hostname: None,
            persistent_keepalive: None,
            allowed_ips: Vec::new(),
        }
    }
    fn build(self, line_num: usize) -> Result<ParsedPeer, String> {
        let public_key = self
            .public_key
            .ok_or_else(|| format!("Line {}: Peer missing PublicKey", line_num))?;
        Ok(ParsedPeer {
            public_key,
            preshared_key: self.preshared_key,
            endpoint: self.endpoint,
            endpoint_hostname: self.endpoint_hostname,
            persistent_keepalive: self.persistent_keepalive,
            allowed_ips: self.allowed_ips,
        })
    }
}
