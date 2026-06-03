//! Low-level reachability probes.
//!
//! Two backends:
//!   * Windows IcmpSendEcho (real ICMP echo, requires no admin)
//!   * Cross-platform TCP-connect timing fallback
//!
//! Все функции async-friendly: ICMP вызывается в `spawn_blocking`,
//! TCP-проба нативно асинхронная.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct ProbeResult {
    pub rtt: Option<Duration>,
}

impl ProbeResult {
    pub fn ok(rtt: Duration) -> Self {
        Self { rtt: Some(rtt) }
    }
    pub fn lost() -> Self {
        Self { rtt: None }
    }
    pub fn is_ok(&self) -> bool {
        self.rtt.is_some()
    }
}

/// ICMP echo probe targeting a v4 address. On non-Windows / IPv6 falls back
/// to TCP probing with a sensible default port.
#[cfg(target_os = "windows")]
pub async fn ping(target: IpAddr, timeout: Duration, tcp_fallback_port: u16) -> ProbeResult {
    match target {
        IpAddr::V4(v4) => {
            let ttl = timeout;
            let result = tokio::task::spawn_blocking(move || icmp_echo_v4(v4, ttl)).await;
            match result {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("icmp probe join error: {e}");
                    ProbeResult::lost()
                }
            }
        }
        IpAddr::V6(_) => tcp_connect_probe(SocketAddr::new(target, tcp_fallback_port), timeout).await,
    }
}

#[cfg(not(target_os = "windows"))]
pub async fn ping(target: IpAddr, timeout: Duration, tcp_fallback_port: u16) -> ProbeResult {
    tcp_connect_probe(SocketAddr::new(target, tcp_fallback_port), timeout).await
}

/// Pure TCP connect-time probe. Works everywhere, no privileges required.
pub async fn tcp_connect_probe(addr: SocketAddr, timeout: Duration) -> ProbeResult {
    let start = Instant::now();
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => ProbeResult::ok(start.elapsed()),
        _ => ProbeResult::lost(),
    }
}

#[cfg(target_os = "windows")]
fn icmp_echo_v4(ip: Ipv4Addr, timeout: Duration) -> ProbeResult {
    use windows::Win32::NetworkManagement::IpHelper::{
        IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY,
    };

    unsafe {
        let handle = match IcmpCreateFile() {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("IcmpCreateFile failed: {e}");
                return ProbeResult::lost();
            }
        };

        let request: [u8; 32] = *b"game-accelerator-probe-payload32";
        let reply_size = std::mem::size_of::<ICMP_ECHO_REPLY>() + request.len() + 16;
        let mut reply_buf = vec![0u8; reply_size];

        // IPADDR is u32 in network byte order. octets [a,b,c,d] -> bytes in memory
        // must match. from_ne_bytes preserves the layout (see wireguard_config.rs note).
        let dest: u32 = u32::from_ne_bytes(ip.octets());

        let count = IcmpSendEcho(
            handle,
            dest,
            request.as_ptr() as *const _,
            request.len() as u16,
            None,
            reply_buf.as_mut_ptr() as *mut _,
            reply_buf.len() as u32,
            timeout.as_millis().min(u32::MAX as u128) as u32,
        );

        let res = if count > 0 {
            let reply = &*(reply_buf.as_ptr() as *const ICMP_ECHO_REPLY);
            ProbeResult::ok(Duration::from_millis(reply.RoundTripTime as u64))
        } else {
            ProbeResult::lost()
        };

        let _ = IcmpCloseHandle(handle);
        res
    }
}

// Stub kept compilable for non-Windows toolchain checks.
#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
fn icmp_echo_v4(_ip: Ipv4Addr, _timeout: Duration) -> ProbeResult {
    ProbeResult::lost()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tcp_probe_unreachable_returns_lost() {
        // RFC 5737 TEST-NET-1, guaranteed non-routable
        let addr: SocketAddr = "192.0.2.1:65000".parse().unwrap();
        let r = tcp_connect_probe(addr, Duration::from_millis(50)).await;
        assert!(!r.is_ok());
    }
}
