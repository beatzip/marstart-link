# LIVE TEST — Test Server Specification

> **Purpose:** Defines the minimal remote test server required to prove that
> traffic flows through Path A and Path B independently. The server must be
> able to distinguish which WireGuard tunnel carried a given packet.

---

## 1. Server Requirements

| Requirement | Detail |
|---|---|
| **OS** | Linux (preferred) or Windows Server 2019+/Windows 11 |
| **Network** | Publicly reachable (or reachable from both WireGuard endpoints) |
| **SSH access** | Yes (for running capture commands and reading logs) |
| **Root/sudo** | Yes (for `tcpdump`, `wg show`, `ip addr`) |
| **WireGuard** | `wg` userspace tool + `wireguard-tools` package |
| **Disk** | At least 100 MB free (for packet capture files) |
| **Time** | NTP synchronized (for timestamp correlation) |

### Server IP Allocation (Example)

| Role | IP Address | Tunnel IP | Listen Port |
|---|---|---|---|
| **Server** | `203.0.113.10` | `10.10.1.1` (peer of Path A) | `51820` (wg0) |
| **Server** | `198.51.100.20` | `10.10.2.1` (peer of Path B) | `51821` (wg1) |
| **Destination** | `203.0.113.10` | — | `8080` (TCP) or `53` (UDP) |

> The server can host **two separate WireGuard interfaces** (`wg0` and `wg1`),
> each with a different listening port, different peer public key, and
> different tunnel subnet. This guarantees true path independence.

---

## 2. Linux Server Setup

### 2.1. Install WireGuard Tools

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y wireguard iproute2 tcpdump net-tools

# Or RHEL/Fedora
sudo dnf install -y wireguard-tools iproute tcpdump net-tools
```

### 2.2. Create Two WireGuard Interfaces

**Interface wg0 (Path A endpoint):**

```bash
# /etc/wireguard/wg0.conf
[Interface]
Address = 10.10.1.1/24
ListenPort = 51820
PrivateKey = <REDACTED>
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT

[Peer]
# Path A client public key
PublicKey = <REDACTED>
AllowedIPs = 10.10.1.2/32, 203.0.113.0/24
```

**Interface wg1 (Path B endpoint):**

```bash
# /etc/wireguard/wg1.conf
[Interface]
Address = 10.10.2.1/24
ListenPort = 51821
PrivateKey = <REDACTED>
PostUp = iptables -A FORWARD -i wg1 -j ACCEPT
PostDown = iptables -D FORWARD -i wg1 -j ACCEPT

[Peer]
# Path B client public key
PublicKey = <REDACTED>
AllowedIPs = 10.10.2.2/32, 203.0.113.0/24
```

> **Note:** Both peers have `AllowedIPs = 203.0.113.0/24` so the server
> accepts traffic from either tunnel. The server distinguishes paths via
> the **source tunnel IP** (10.10.1.2 vs 10.10.2.2) in the packet capture.

### 2.3. Start WireGuard Interfaces

```bash
sudo wg-quick up wg0
sudo wg-quick up wg1
```

### 2.4. Verification Commands

#### Show interface details

```bash
# Show both WireGuard interfaces
sudo wg show

# Show all network interfaces and IPs
ip addr show

# Show routing table
ip route show
```

#### Expected output example

```
$ sudo wg show
interface: wg0
  public key: <Path A server public key>
  listening port: 51820
  peer: <Path A client public key>
    allowed ips: 10.10.1.0/24, 203.0.113.0/24
    latest handshake: 1 minute ago
    transfer: 10.50 KiB received, 12.30 KiB sent

interface: wg1
  public key: <Path B server public key>
  listening port: 51821
  peer: <Path B client public key>
    allowed ips: 10.10.2.0/24, 203.0.113.0/24
    latest handshake: 1 minute ago
    transfer: 8.00 KiB received, 9.50 KiB sent
```

#### Start packet capture

```bash
# Capture traffic on both WG interfaces, filtering for the test destination
sudo tcpdump -i wg0 -i wg1 -n -nn 'dst host 203.0.113.10 and dst port 8080' \
  -w /tmp/marstart-live-test.pcap &
TCPDUMP_PID=$!

# Record start time
date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"

# ... run test steps ...

# Stop capture
kill $TCPDUMP_PID
```

#### Analyze captured packets

```bash
# Show packets arriving on wg0 (Path A)
sudo tcpdump -r /tmp/marstart-live-test.pcap -n 'src host 10.10.1.2'

# Show packets arriving on wg1 (Path B)
sudo tcpdump -r /tmp/marstart-live-test.pcap -n 'src host 10.10.2.2'

# Count packets per path
echo "Path A (wg0):"
sudo tcpdump -r /tmp/marstart-live-test.pcap -n 'src host 10.10.1.2' | wc -l
echo "Path B (wg1):"
sudo tcpdump -r /tmp/marstart-live-test.pcap -n 'src host 10.10.2.2' | wc -l
```

### 2.5. Distinguishing Path A from Path B

The server distinguishes the two paths by examining:

1. **Source tunnel IP:** Packets from Path A arrive with source `10.10.1.2`
   (on `wg0`); packets from Path B arrive with source `10.10.2.2` (on `wg1`).
2. **Ingress interface:** `tcpdump` or `ss` shows which WireGuard interface
   received the packet.
3. **Peer transfer counters:** `wg show` shows per-peer `rx_bytes` /
   `tx_bytes` — only the active path should show increasing counters after a
   switch.

### 2.6. Packet Counter Evidence

```bash
# Capture before-traffic counters
echo "=== Before traffic ==="
sudo wg show wg0  | grep "transfer:"  # Path A
sudo wg show wg1  | grep "transfer:"  # Path B

# ... generate traffic to 203.0.113.10:8080 from MARSTART side ...

# Capture after-traffic counters
sleep 2
echo "=== After traffic ==="
sudo wg show wg0  | grep "transfer:"
sudo wg show wg1  | grep "transfer:"
```

Only the active path should show increased byte counters.

---

## 3. Windows Server Alternative

If a Windows server is used instead of Linux, the following tools provide
equivalent evidence:

### 3.1. Install WireGuard

```powershell
winget install WireMock.WireGuard ---
# Or download from https://www.wireguard.com/install/
```

### 3.2. Create Two WireGuard Tunnels

Use the WireGuard for Windows GUI or `wireguard.exe /installtunnelservice`:

```powershell
# Two separate tunnel configurations with different ports
wireguard.exe /installtunnelservice C:\tunnels\server-wg0.conf
wireguard.exe /installtunnelservice C:\tunnels\server-wg1.conf
```

### 3.3. Packet Capture with pktmon

```powershell
# Start packet capture on both WireGuard interfaces
pktmon start --capture --interface wg0 --interface wg1 --format ETL
# ... run test ...
pktmon stop
pktmon convert C:\Windows\pktmon\PktMon.etl --output C:\tunnels\capture.etl
```

### 3.4. Network Connection Verification

```powershell
# Show current TCP connections (filter for destination port 8080)
Get-NetTCPConnection -RemotePort 8080 -State Established

# Show which interface is being used
Get-NetRoute -DestinationPrefix "203.0.113.0/24" | Format-Table

# Show WireGuard adapter status
Get-NetAdapter -InterfaceDescription "*WireGuard*" | Format-Table Name, InterfaceDescription, InterfaceIndex, Status, LinkSpeed

# Show IP configuration
Get-NetIPAddress -InterfaceAlias "wg0","wg1" | Format-Table
```

### 3.5. Distinguishing Paths on Windows

The Windows server can distinguish paths by:

1. **`Get-NetAdapter`** — shows packet counters (`ReceivedBytes`, `SentBytes`)
   per WireGuard interface
2. **`Get-NetTCPConnection`** — shows which remote port the connection came
   from (51820 vs 51821 maps to Path A vs Path B)
3. **Packet capture** — `pktmon` or Wireshark shows the source tunnel IP

---

## 4. Test Server Configuration Template

### 4.1. Server-side: Two WireGuard interfaces

| Parameter | Path A (wg0) | Path B (wg1) |
|---|---|---|
| Listen Port | `51820` | `51821` |
| Server Tunnel IP | `10.10.1.1/24` | `10.10.2.1/24` |
| Client Tunnel IP | `10.10.1.2/32` | `10.10.2.2/32` |
| Server Private Key | (per-interface) | (per-interface) |
| Client Public Key | (Path A client) | (Path B client) |

### 4.2. Client-side: Two WireGuard configs (supplied by operator)

Each client config connects to the respective server interface:

**Path A client config:**
```ini
[Interface]
PrivateKey = <redacted>
Address = 10.10.1.2/32

[Peer]
PublicKey = <server wg0 public key>
Endpoint = <server_ip>:51820
AllowedIPs = 203.0.113.0/24
PersistentKeepalive = 25
```

**Path B client config:**
```ini
[Interface]
PrivateKey = <redacted>
Address = 10.10.2.2/32

[Peer]
PublicKey = <server wg1 public key>
Endpoint = <server_ip>:51821
AllowedIPs = 203.0.113.0/24
PersistentKeepalive = 25
```

---

## 5. Why This Configuration Works

### Packet-Path Proof Strategy

1. **Path A active:** Traffic to `203.0.113.10:8080` is routed via the Windows
   route table entry with `metric=10` pointing to Path A's WireGuard adapter.
   The server sees packets arriving on `wg0` with source IP `10.10.1.2`.

2. **Switch to Path B:** `routes_select_manual({ id: 'path-b' })` triggers
   `PathManager::activate_path("path-b")`, which sets Path A's metric to 20
   (standby) and Path B's metric to 10 (active). Now traffic flows via Path B.
   The server sees packets arriving on `wg1` with source IP `10.10.2.2`.

3. **Switch back to Path A:** Repeat with `routes_select_manual({ id: 'path-a' })`.
   The server again sees packets on `wg0`.

4. **Failover:** If the Path A WireGuard tunnel is torn down (simulated failure),
   the route for metric 10 disappears, Windows falls back to the metric-20 route
   (Path B), and traffic continues flowing through Path B.

### Key Evidence Points

| Evidence | How Collected | Expected After Switch |
|---|---|---|
| Server sees `10.10.1.2` packets | `tcpdump -i wg0` | Before switch (Path A) |
| Server sees `10.10.2.2` packets | `tcpdump -i wg1` | After switch (Path B) |
| Peer transfer counters increase | `wg show` | Only on active path |
| Windows route metric | `Get-NetRoute` | Active=10, Standby=20 |
| Source IP changes | `tcpdump` source field | `10.10.1.2` → `10.10.2.2` → `10.10.1.2` |

---

## 6. Security Note

The test server configuration requires private keys and peer public keys.
These are **real WireGuard keys** and must be treated as secrets:

- Store them in files with `600` permissions
- Never commit to Git
- Redact from all logs and reports
- Use a dedicated test server, not production infrastructure
- The `MARSTART_PATH_A_CONFIG` / `MARSTART_PATH_B_CONFIG` environment variables
  only contain **file paths**, never keys themselves
