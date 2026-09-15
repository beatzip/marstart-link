# MARSTART LINK — Live Test Handoff

> **Document Status:** HANDOFF COMPLETE — Awaiting live test execution
> **Phase 1 Status:** `PHASE 1 LIVE DATAPATH NOT VERIFIED` (deferred — awaiting prerequisites)
> **Preflight Status:** Admin ✗ | WireGuard-driver ✓installed(⊘stopped) | SDK ✓ | Binary ✓ | Configs ✗
> **No source code was added or modified for this handoff.** All documents are documentation-only.
>
> This document consolidates `LIVE_TEST_INPUTS.md`, `LIVE_TEST_SERVER.md`,
> `LIVE_TEST_WINDOWS.md`, and `LIVE_TEST_CHECKLIST.md` into a single
> end-to-end procedure.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Test Machine Setup](#2-test-machine-setup)
3. [WireGuard Server Requirements](#3-wireguard-server-requirements)
4. [Path A Inputs](#4-path-a-inputs)
5. [Path B Inputs](#5-path-b-inputs)
6. [Controlled Destination](#6-controlled-destination)
7. [Exact Windows Commands](#7-exact-windows-commands)
8. [Exact MARSTART Actions](#8-exact-mostart-actions)
9. [Evidence to Capture](#9-evidence-to-capture)
10. [Pass/Fail Criteria](#10-passfail-criteria)
11. [Cleanup](#11-cleanup)
12. [Rollback](#12-rollback)
13. [Known Limitations](#13-known-limitations)

---

## 1. Prerequisites

### Operator

- **One operator** with Administrator access to a Windows 10 or Windows 11 machine
- The operator must be able to:
  - Install WireGuard-NT 1.1 (or verify it is installed)
  - Generate WireGuard key pairs
  - Edit text configuration files
  - Run PowerShell commands
  - Access a remote Linux (or Windows) server via SSH

### Environment

This current environment is **blocked** by the following preflight findings:

| Blocker | Status | Detail |
|---|---|---|
| No Administrator / elevated token | ⚠️ Blocked | `IsAdmin: False`; `net session` → ACCESS DENIED (error 5) |
| WireGuard service stopped | ⚠️ Blocked | `wireguard.sys` + `wintun.sys` present in `System32\drivers`; service exists but stopped; `Start-Service WireGuard` fails (requires admin) |
| No WireGuard tools (`wg.exe`) | ⚠️ Blocked | No `C:\Program Files\WireGuard\` installation found |
| No two real WireGuard configs | ⚠️ Blocked | `MARSTART_PATH_A_CONFIG`, `MARSTART_PATH_B_CONFIG`, `MARSTART_MANAGED_DESTINATION` — none set |
| No two independent reachable WireGuard endpoints | ⚠️ Blocked | No WireGuard peers/servers configured |
| No controlled remote server | ⚠️ Blocked | No remote endpoint for traffic verification |

**Status:** The live test cannot begin until all six blockers are resolved.
An elevated operator must: (1) open PowerShell as Administrator, (2) install
or start the WireGuard-NT service, (3) provision two independent WireGuard
`.conf` files with valid keys + real endpoints, (4) set the three environment
variables documented in `LIVE_TEST_INPUTS.md`.

### What IS ready

| Item | Status | Detail |
|---|---|---|
| Release binary | ✅ Ready | `src-tauri\target\release\marstart-link.exe` built successfully |
| WireGuard-NT SDK | ✅ Present | `wireguard.dll` + `wintun.dll` in `src-tauri\sdk\` and `src-tauri\resources\` |
| WireGuard drivers | ✅ Installed | `wireguard.sys` (494KB) + `wintun.sys` (29KB) in `System32\drivers\` |
| Static test suite | ✅ 146/146 PASS | 5× parallel + 1× serial, all green |
| Clippy | ✅ 0 warnings | `cargo clippy --all-features --all-targets -- -D warnings` |
| Formatting | ✅ Pass | `cargo fmt --check` exit 0 |
| Release build | ✅ Pass | `cargo build --release` exit 0 |

### What must NOT be done yet

| Action | Reason |
|---|---|
| Add any new datapath features | No packet-level evidence obtained; per operator instruction "До получения packet-level evidence никаких новых datapath features не добавлять" |
| Mark Phase 1 as VERIFIED | Prerequisites not met; "PHASE 1 VERIFIED" only after successful live test |
| Add new autopilot/policy features | Control plane audit is complete (see `CONTROL_PLANE_TEST_FIX_AUDIT.md`) |

### Software (Windows test machine)

| Component | Minimum Version | Installed? |
|---|---|---|
| Windows | Windows 10 x64 1909+ or Windows 11 | (verify) |
| Rust toolchain | 1.96.0+ | (verify with `rustc --version`) |
| Node.js | 20+ (for `npm run tauri:dev`) | (verify) |
| WireGuard-NT | 1.1 | (verify with `Get-Service WireGuard`) |
| Tauri CLI | 2.0+ | (via `npm run tauri:build`) |
| PowerShell | 5.1+ (Windows) or 7+ | (verify with `$PSVersionTable`) |

### Software (Remote test server — preferred: Linux)

| Component | Minimum Version |
|---|---|
| OS | Ubuntu 20.04 LTS (or equivalent) |
| WireGuard tools | `wireguard-tools` package |
| tcpdump | for packet capture |
| iproute2 | for `ip addr`, `ip route` |
| SSH server | `sshd` (OpenSSH) |

---

## 2. Test Machine Setup

### 2.1. Build MARSTART LINK

From an **elevated** PowerShell prompt:

```powershell
cd C:\Users\User\Desktop\marstart-link-main

# Ensure dependencies are installed
npm install

# Prepare WireGuard-NT resources (downloads wireguard.dll + wintun.dll)
npm run prepare:resources

# Verify resources are in place
Get-ChildItem src-tauri\resources\wireguard.dll
Get-ChildItem src-tauri\resources\wintun.dll

# Build (dev mode for testing, or release for production)
# Dev:
npm run tauri:dev
#
# Release:
npm run tauri:build
# (After build, run embed_manifest.bat for production manifest embedding)
.\src-tauri\embed_manifest.bat src-tauri\target\release\MARSTART LINK.exe
```

> The built binary includes `requireAdministrator` in its manifest. Launching
> it will trigger a UAC prompt.

### 2.2. Verify the Binary Was Built with Admin Manifest

```powershell
# Check the manifest was applied (look for requireAdministrator)
& "C:\Users\User\Desktop\marstart-link-main\src-tauri\embed_manifest.bat" `
    "C:\Users\User\Desktop\marstart-link-main\src-tauri\target\release\MARSTART LINK.exe"
```

After elevation, the app will:
1. Load `wireguard.dll` from `resources/`
2. Initialize `AppState` with two tunnels, a `PathManager`, `RouteManager`,
   `RouteSnapshotEngine`, `Autopilot`, `LoadBalancer`, and `MonitorService`
3. Connect `RouteManager` to `PathManager` via `routes.set_paths(paths)`
4. Start the snapshot engine's periodic refresh loop

### 2.3. Confirm Test-Only Mechanism Is Available

The `connect_test` command is compiled in when targeting Windows
(`#[cfg(any(test, target_os = "windows"))]`). It reads three environment
variables (see [§4](/LIVE_TEST_INPUTS.md#5-how-the-test-operator-supplies-inputs)).

---

## 3. WireGuard Server Requirements

Two independent WireGuard endpoints are required. See
`LIVE_TEST_SERVER.md` for full specifications.

### Minimum Requirements

| Requirement | Path A | Path B |
|---|---|---|
| Server | Linux or Windows with WireGuard | Same server or different server |
| WireGuard interface | `wg0` (port 51820) | `wg1` (port 51821) |
| Server tunnel IP | `10.10.1.1` | `10.10.2.1` |
| Client tunnel IP | `10.10.1.2` | `10.10.2.2` |
| Server private key | Unique per interface | Unique per interface |
| Client public key | Unique, registered in wg0 peer | Unique, registered in wg1 peer |

### Endpoint Independence

- **Endpoint A ≠ Endpoint B**: Different IP addresses and/or different ports.
- Do **not** use one server with two names resolving to the same IP:port —
  that is a **negative test** case (document it explicitly as such).
- Both endpoints must accept incoming UDP connections from the Windows
  test machine.

### Firewall

- Allow inbound UDP on ports 51820 (Path A) and 51821 (Path B)
- Allow inbound TCP 8080 (or the chosen traffic port) for the controlled
  destination

---

## 4. Path A Inputs

The operator supplies **Path A** by setting the `MARSTART_PATH_A_CONFIG`
environment variable to an absolute file path:

```
MARSTART_PATH_A_CONFIG = C:\live-test\configs\path-a.conf
```

### Path A Config File Template

```ini
[Interface]
PrivateKey = <REDACTED — unique to Path A>
Address = 10.10.1.2/32

[Peer]
# Server wg0 public key
PublicKey = <REDACTED — server wg0 public key>
Endpoint = <server_a_endpoint_ip>:51820
AllowedIPs = 203.0.113.0/24
PersistentKeepalive = 25
PresharedKey = <REDACTED>  ; optional
```

### Path A Parameters

| Parameter | Value |
|---|---|
| Config path env var | `MARSTART_PATH_A_CONFIG` |
| Tunnel address (client) | `10.10.1.2/32` |
| Server endpoint | `<server_a_ip>:51820` |
| Server tunnel IP | `10.10.1.1/24` |
| Server interface name | `wg0` |
| Path ID (assigned by code) | `path-a` |
| Route metric (active) | `10` (`ACTIVE_METRIC`) |
| Route metric (standby) | `20` (`STANDBY_METRIC`) |

---

## 5. Path B Inputs

The operator supplies **Path B** by setting the `MARSTART_PATH_B_CONFIG`
environment variable:

```
MARSTART_PATH_B_CONFIG = C:\live-test\configs\path-b.conf
```

### Path B Config File Template

```ini
[Interface]
PrivateKey = <REDACTED — unique to Path B, different from Path A>
Address = 10.10.2.2/32

[Peer]
# Server wg1 public key (different from Path A's server public key)
PublicKey = <REDACTED — server wg1 public key>
Endpoint = <server_b_endpoint_ip>:51821
AllowedIPs = 203.0.113.0/24
PersistentKeepalive = 25
PresharedKey = <REDACTED>  ; optional
```

### Path B Parameters

| Parameter | Value |
|---|---|
| Config path env var | `MARSTART_PATH_B_CONFIG` |
| Tunnel address (client) | `10.10.2.2/32` |
| Server endpoint | `<server_b_endpoint_ip>:51821` |
| Server tunnel IP | `10.10.2.1/24` |
| Server interface name | `wg1` |
| Path ID (assigned by code) | `path-b` |
| Route metric (standby) | `20` (`STANDBY_METRIC`) |

---

## 6. Controlled Destination

The controlled destination is a real server reachable through **both** WireGuard
paths. It receives test traffic so the operator can prove which path carried
each packet.

### Managed Destination (Route Target)

```
MARSTART_MANAGED_DESTINATION = 203.0.113.0/24
```

This CIDR is installed in the Windows routing table via
`PathManager::set_destination()` + `WindowsRouteManager::install_route()`.

### Traffic Destination

| Field | Value |
|---|---|
| Destination IP | `203.0.113.10` (must be real and reachable) |
| Protocol | `TCP` (recommended — easy to verify) |
| Port | `8080` |
| Test command | `curl -v http://203.0.113.10:8080/` or `nc -vz 203.0.113.10 8080` |

### How the Server Distinguishes Paths

The server identifies the path by examining the **source tunnel IP** in captured
packets:

| Path | Source tunnel IP | Server interface | Server `wg show` peer |
|---|---|---|---|
| Path A | `10.10.1.2` | `wg0` | Path A client public key |
| Path B | `10.10.2.2` | `wg1` | Path B client public key |

**This is the primary packet-path proof**: the server's `tcpdump` must show
packets from `10.10.1.2` when Path A is active, and from `10.10.2.2` when
Path B is active.

---

## 7. Exact Windows Commands

All commands are run in an **elevated** PowerShell session.

### 7.1. Administrator Verification

```powershell
# MUST be run in a PowerShell window opened as Administrator
whoami
net session
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Get-Service WireGuard
# If stopped:
Start-Service WireGuard
Get-Service WireGuard
```

### 7.2. Set Environment Variables

```powershell
$env:MARSTART_PATH_A_CONFIG = "C:\live-test\configs\path-a.conf"
$env:MARSTART_PATH_B_CONFIG = "C:\live-test\configs\path-b.conf"
$env:MARSTART_MANAGED_DESTINATION = "203.0.113.0/24"

# Verify
Write-Host "A: $env:MARSTART_PATH_A_CONFIG"
Write-Host "B: $env:MARSTART_PATH_B_CONFIG"
Write-Host "Dest: $env:MARSTART_MANAGED_DESTINATION"
Test-Path $env:MARSTART_PATH_A_CONFIG
Test-Path $env:MARSTART_PATH_B_CONFIG
```

### 7.3. Launch the Application

```powershell
cd C:\Users\User\Desktop\marstart-link-main

# Option A: Dev mode (faster iteration)
npm run tauri:dev

# Option B: Release binary
& "src-tauri\target\release\MARSTART LINK.exe"
```

> Accept the UAC prompt when it appears.

### 7.4. Invoke Tauri Commands (DevTools Console, F12)

```javascript
// Store this helper in the console for repeated use
const invoke = (cmd, args = {}) => window.__TAURI__.invoke(cmd, args);

// Full test sequence (copy-paste into DevTools Console):

// 1. Driver check
await invoke('wireguard_driver_status');

// 2. Connect both paths (reads env vars)
await invoke('connect_test');

// 3. Check status
await invoke('get_status');

// 4. Get connection info (handshake, tx/rx bytes, endpoint)
await invoke('get_connection_info');

// 5. Get route evaluation
await invoke('routes_list');

// 6. Get snapshot (per-path health, score, RTT, loss)
await invoke('route_snapshot');

// 7. Get Windows route table
await invoke('routes_get_state');

// 8. Switch to Path B
await invoke('routes_select_manual', { id: 'path-b' });

// 9. Verify switch
await invoke('routes_list');
await invoke('route_snapshot');

// 10. Switch back to Path A
await invoke('routes_select_manual', { id: 'path-a' });

// 11. Verify switch
await invoke('routes_list');

// 12. Disconnect (cleanup)
await invoke('disconnect');
```

### 7.5. Windows Route Table Inspection

```powershell
# Show all routes to the managed destination
Get-NetRoute -DestinationPrefix "203.0.113.0/24" | Format-Table

# Show routes by metric (10 = active, 20 = standby)
Get-NetRoute -DestinationPrefix "203.0.113.0/24" | Sort-Object RouteMetric | Format-Table

# Show WireGuard adapters
Get-NetAdapter -InterfaceDescription "*WireGuard*" | Format-Table Name, InterfaceIndex, Status

# Show route details including protocol tag
Get-NetRoute -DestinationPrefix "203.0.113.0/24" | Select-Object DestinationPrefix, NextHop, RouteMetric, NextHopInterface, RouteMetric

# Show interface LUID (for cross-referencing with PathManager diagnostics)
$routes = Get-NetRoute -DestinationPrefix "203.0.113.0/24"
foreach ($r in $routes) {
    Write-Host "Dest=$($r.DestinationPrefix) Metric=$($r.RouteMetric) Iface=$($r.InterfaceAlias)"
    Get-NetAdapter -InterfaceIndex $r.InterfaceIndex | Select-Object Name, InterfaceGuid
}
```

### 7.6. Monitor Traffic on Controlled Destination

```powershell
# Generate test traffic
curl http://203.0.113.10:8080/

# Or with PowerShell
try {
    $resp = Invoke-WebRequest -Uri "http://203.0.113.10:8080/" -TimeoutSec 5 -ErrorAction Stop
    Write-Host "Traffic succeeded: $($resp.StatusCode)"
} catch {
    Write-Host "Traffic failed: $($_.Exception.Message)"
}
```

### 7.7. Packet Capture (Windows)

```powershell
# Start capture
pktmon start --capture --format ETL

# ... run traffic test ...

# Stop capture
pktmon stop
pktmon convert C:\Windows\pktmon\PktMon.etl --output C:\live-test\capture.etl
```

---

## 8. Exact MARSTART Actions

### 8.1. Architecture Summary

The following datapath is already implemented in the codebase (no changes needed):

```
[RouteManager::commit]  →  [PathManager::activate_path]
                                ↓
                    active path: metric 10  (Route A)
                    standby path: metric 20 (Route B)
                                ↓
                    [WindowsRouteManager::install_route]
                    [WindowsRouteManager::update_route_metric]
                                ↓
                    Windows routing table:
                      203.0.113.0/24 via LUID-A, metric 10
                      203.0.113.0/24 via LUID-B, metric 20
```

**Key code locations:**

| Component | File | Key Functions |
|---|---|---|
| `connect()` | `src-tauri/src/main.rs:93` | Creates WireGuardTunnel instances, registers PathManager paths, activates first |
| `connect_test()` | `src-tauri/src/main.rs:254` | Test-only: reads env vars, calls `connect()` |
| `Profile::from_test_env()` | `src-tauri/src/profiles.rs:118` | Reads `MARSTART_PATH_A_CONFIG`, `MARSTART_PATH_B_CONFIG`, `MARSTART_MANAGED_DESTINATION` |
| `RouteManager::commit()` | `src-tauri/src/routes/mod.rs:286` | Delegates to `PathManager::activate_path()` |
| `PathManager::activate_path()` | `src-tauri/src/path_manager.rs:139` | Sets active=true, metric=10; sets others metric=20 |
| `PathManager::set_destination()` | `src-tauri/src/path_manager.rs:283` | Sets destination CIDR + prefix length |
| `PathManager::connect_path()` | `src-tauri/src/path_manager.rs:221` | Sets LUID, index, TunnelState::Up |
| `PathManager::reconcile()` | `src-tauri/src/path_manager.rs:302` | Reconciles in-memory registry vs Windows route table |
| `WindowsRouteManager::install_route()` | `src-tauri/src/windows_route_manager.rs:183` | `CreateIpForwardEntry2` |
| `WindowsRouteManager::remove_route()` | `src-tauri/src/windows_route_manager.rs:243` | `DeleteIpForwardEntry2` |
| `WindowsRouteManager::update_route_metric()` | `src-tauri/src/windows_route_manager.rs:391` | Updates route metric in table |
| `WindowsRouteManager::cleanup_owned_routes()` | `src-tauri/src/windows_route_manager.rs:417` | Removes orphaned owned routes |
| `WindowsRouteManager::enumerate_windows_routes()` | `src-tauri/src/windows_route_manager.rs:323` | `GetIpForwardTable2` — reads Windows table |

### 8.2. Constants

| Constant | File | Value |
|---|---|---|
| `ACTIVE_METRIC` | `windows_route_manager.rs:48` | `10` |
| `STANDBY_METRIC` | `windows_route_manager.rs:50` | `20` |
| `MIB_IPPROTO_NETMGMT` | `windows_route_manager.rs:26` | `3` (protocol tag for ownership) |
| `DEFAULT_COOLDOWN_MS` | `routes/mod.rs:23` | `10_000` |
| `DEFAULT_SWITCH_MARGIN` | `routes/mod.rs:24` | `0.10` |
| `MAX_PATHS` (Phase 1) | `main.rs:127` | `2` |

### 8.3. Test Sequence

| Step | Action | MARSTART Command | Operator Command |
|---|---|---|---|
| 1 | Driver check | `wireguard_driver_status` | JS: `await invoke('wireguard_driver_status')` |
| 2 | Diagnostics | `tunnel_diagnostics` | JS: `await invoke('tunnel_diagnostics', {profile_id: "default"})` |
| 3 | Clean baseline | (PowerShell) | `Get-NetAdapter`, `Get-NetRoute` |
| 4 | Connect both paths | `connect_test` | JS: `await invoke('connect_test')` |
| 5 | Verify both UP | `get_status` + `get_connection_info` | JS: `await invoke('get_status')` |
| 6 | Install routes | (automatic in connect) | — |
| 7 | Verify routes | — | PowerShell: `Get-NetRoute -DestinationPrefix "203.0.113.0/24"` |
| 8 | Traffic → A | — | `curl http://203.0.113.10:8080/` |
| 9 | Switch to B | `routes_select_manual` | JS: `await invoke('routes_select_manual', { id: 'path-b' })` |
| 10 | Traffic → B | — | `curl http://203.0.113.10:8080/` |
| 11 | Switch to A | `routes_select_manual` | JS: `await invoke('routes_select_manual', { id: 'path-a' })` |
| 12 | Traffic → A | — | `curl http://203.0.113.10:8080/` |
| 13 | Fail path A | — | (external: disable adapter, revoke admin, or block endpoint) |
| 14 | Verify failover | `routes_list` | JS: `await invoke('routes_list')` |
| 15 | Reconnect (restart) | `disconnect` + `connect_test` | JS: `await invoke('disconnect')`; env vars; `await invoke('connect_test')` |
| 16 | Cleanup | `disconnect` | JS: `await invoke('disconnect')` |

### 8.4. Route Manager Integration with PathManager

In `main.rs:697`, during `AppState` initialization:

```rust
routes.set_paths(Arc::clone(&paths));
```

This means `RouteManager::commit(route_id)` calls `PathManager::activate_path(route_id)`,
which:

1. Sets the target path's `active = true`
2. Sets all other paths' `active = false`
3. Deletes and re-installs all routes with correct metrics:
   - Active path: `CreateIpForwardEntry2` with `metric = 10`
   - Standby path: `CreateIpForwardEntry2` with `metric = 20`
4. Calls `UpdateRouteMetric` to ensure metric is correct

When `routes_select_manual({ id: 'path-b' })` is called:
- `routes.select_manual("path-b")` sets `manual_override = Some("path-b")`
- `routes.commit(Some("path-b"))` triggers `PathManager::activate_path("path-b")`
- Path B's route metric changes from 20 → 10
- Path A's route metric changes from 10 → 20
- Windows automatically routes new traffic to the lower-metric route (Path B)

---

## 9. Evidence to Capture

### 9.1. Driver Evidence

Capture from `wireguard_driver_status` (Tauri command):

| Field | Type | Expected Value |
|---|---|---|
| `dll_loaded` | `bool` | `true` |
| `driver_present` | `bool` | `true` |
| `driver_version_string` | `String` | e.g. `"1.1.0.0"` |
| `is_admin` | `bool` | `true` |
| `error_code` | `u32` | `0` |

### 9.2. Path A Evidence

Capture from `route_snapshot` + `get_connection_info` + `get_paths`:

| Field | Source | Expected |
|---|---|---|
| `path_id` | `Path.id` | `"path-a"` |
| `adapter_name` | `WireGuardTunnel.adapter_name` | `"MARSTART-live-test"` |
| `interface_luid` | `WireGuardTunnel::get_adapter_luid()` | Non-zero `u64` |
| `interface_index` | `Path.interface_index` | Non-zero `u32` |
| `adapter_state` | `WireGuardTunnel::get_adapter_state()` | `Up` |
| `tunnel_state` | `Path.tunnel_state` | `Up` |
| `handshake_timestamp_unix` | `ConnectionInfo.handshake_timestamp_unix` | Non-zero (within last 30s) |
| `tx_bytes` | `ConnectionInfo.tx_bytes` | `> 0` after traffic |
| `rx_bytes` | `ConnectionInfo.rx_bytes` | `> 0` after traffic |
| `active` | `Path.active` | `true` (when Path A is active) |
| `health` | `Path.health` | `Healthy` |

### 9.3. Path B Evidence

Same fields as Path A, with:

| Field | Expected |
|---|---|
| `path_id` | `"path-b"` |
| `interface_luid` | Different from Path A |
| `interface_index` | Different from Path A |
| `active` | `false` (when Path A is active) |
| `tx_bytes` | Unchanged when Path A is active |

### 9.4. Route A Evidence (Active)

From Windows `Get-NetRoute`:

| Field | Expected |
|---|---|
| `DestinationPrefix` | `203.0.113.0/24` |
| `RouteMetric` | `10` (ACTIVE_METRIC) |
| `NextHopInterface` | Path A's WireGuard adapter |
| `Protocol` | `NET_MGMT` (3) |

### 9.5. Route B Evidence (Standby)

| Field | Expected |
|---|---|
| `DestinationPrefix` | `203.0.113.0/24` |
| `RouteMetric` | `20` (STANDBY_METRIC) |
| `NextHopInterface` | Path B's WireGuard adapter |
| `Protocol` | `NET_MGMT` (3) |

### 9.6. Packet-Path Proof (Server-side)

From `tcpdump` on the Linux server:

| Evidence | How to capture | Expected |
|---|---|---|
| Packet captured on `wg0` with source `10.10.1.2` | `tcpdump -i wg0 -n 'src 10.10.1.2'` | During Path A active |
| Packet captured on `wg1` with source `10.10.2.2` | `tcpdump -i wg1 -n 'src 10.10.2.2'` | During Path B active |
| Timestamp of first packet on new path | `tcpdump -n -tt` or `-t` flag | Within 5s of switch command |
| `wg show` peer counters increased | `wg show wg0` / `wg show wg1` | On active path only |

### 9.7. Failover Timing Evidence

| Measurement | Method |
|---|---|
| `t_failure_detected` | Timestamp when `routes_list` shows `reason: EmergencyBypass` or health changes to Bad |
| `t_switch_started` | Timestamp when `routes_select_manual` returns |
| `t_route_B_active` | Timestamp when `Get-NetRoute` shows Path B metric = 10 |
| `t_first_successful_packet_B` | Timestamp from server `tcpdump` showing first `10.10.2.2` packet after switch |
| `detection_time` | `t_switch_started - t_failure_detected` |
| `route_switch_time` | `t_route_B_active - t_switch_started` |
| `packet_recovery_time` | `t_first_successful_packet_B - t_route_B_active` |
| `total_failover_time` | `t_first_successful_packet_B - t_failure_detected` |

### 9.8. Evidence Redaction Policy

All evidence files must be redacted before sharing:

- ❌ Private keys (remove from `.conf` files)
- ❌ Preshared keys (remove from `.conf` files)
- ❌ Authentication tokens (if any)
- ❌ Full endpoint IPs (can be obfuscated to `ENDPOINT_A` / `ENDPOINT_B` in reports)

These are safe to share:
- ✅ Tunnel IPs (`10.10.1.2`, `10.10.2.2`)
- ✅ Destination CIDR (`203.0.113.0/24`)
- ✅ Route metrics (10 vs 20)
- ✅ Interface LUIDs and indices
- ✅ Handshake timestamps
- ✅ tx_bytes / rx_bytes
- ✅ Health scores and RTT
- ✅ Timestamps

---

## 10. Pass/Fail Criteria

### Must-Pass (Blockers)

| # | Criterion | Verification |
|---|---|---|
| 1 | Both WireGuard adapters created and UP | `get_status` = Connected; `Get-NetAdapter` shows 2 adapters |
| 2 | Both routes installed in Windows table | `Get-NetRoute` shows 2 entries for managed destination |
| 3 | Active route has metric 10; standby has metric 20 | `Get-NetRoute \| Sort RouteMetric` |
| 4 | Real traffic flows through Path A (source IP `10.10.1.2`) | Server `tcpdump` on `wg0` |
| 5 | After switch, traffic flows through Path B (source IP `10.10.2.2`) | Server `tcpdump` on `wg1` |
| 6 | After switch back, traffic flows through Path A again | Server `tcpdump` on `wg0` |
| 7 | Route metrics flip correctly (10↔20) on each switch | `Get-NetRoute` before/after each switch |
| 8 | No orphaned routes after disconnect | `Get-NetRoute` for managed dest = empty |
| 9 | No orphaned adapters after disconnect | `Get-NetAdapter -Name "*MARSTART*"` = empty |
| 10 | Foreign routes untouched by MARSTART operations | Pre/post `Get-NetRoute` comparison |

### Must-Pass (Failover)

| # | Criterion | Verification |
|---|---|---|
| 11 | When active path fails, traffic switches to standby | Server sees packets from new path |
| 12 | Failover timing measured and documented | All 4 timestamps captured |
| 13 | After failover, active_path is correctly updated | `routes_list` shows new current |

### Must-Pass (Restart)

| # | Criterion | Verification |
|---|---|---|
| 14 | Stale MARSTART routes detected after restart | `reconcile()` returns cleanup actions |
| 15 | Foreign routes preserved after restart | `Get-NetRoute` comparison |
| 16 | A/B state rebuilt correctly | Both adapters UP, both routes present |

### Must-Fail (Negative Tests — Expected To Fail)

| # | Criterion | Description |
|---|---|---|
| 17 | One server, two names resolving to same IP:port | Should NOT be accepted as independent paths |
| 18 | Non-elevated process | Driver operations must return ACCESS_DENIED |
| 19 | Missing env var | `connect_test` returns error with message |

### Final Verdict

- **All 16 must-pass criteria green** → Proceed to record final verdict
- **Any must-pass failure** → Fix root cause, rerun, do NOT mark VERIFIED
- **Final status** → Recorded **only** by the live test operator

```
PHASE 1 LIVE DATAPATH NOT VERIFIED
```

This status is NOT changed to VERIFIED by documentation alone. It can only
change after a successful live test with real packet-path evidence.

---

## 11. Cleanup

### 11.1. Graceful Disconnect

```javascript
// Via DevTools Console
await invoke('disconnect');
```

This triggers:
1. `WireGuardTunnel::teardown()` for the primary tunnel
2. `WireGuardTunnel::teardown()` for all extra tunnels (standby paths)
3. `PathManager::clear_paths()` — removes all routes from the Windows table

### 11.2. Verify No Orphans

```powershell
# No MARSTART routes
Get-NetRoute -DestinationPrefix "203.0.113.0/24" | Measure-Object
# Expected: 0

# No MARSTART adapters
Get-NetAdapter -Name "*MARSTART*"
# Expected: (no output)

# No orphaned processes
Get-Process | Where-Object { $_.Name -like "*marstart*" }
# Expected: (no output)

# WireGuard driver still running (expected)
Get-Service WireGuard
# Expected: Running
```

### 11.3. Manual Cleanup (if graceful disconnect fails)

```powershell
# Remove routes by destination
Get-NetRoute -DestinationPrefix "203.0.113.0/24" | Remove-NetRoute -Confirm:$false

# Disable/remove stale WireGuard adapters
Get-NetAdapter -InterfaceDescription "*WireGuard*" |
    Where-Object { $_.Name -like "MARSTART*" } |
    Disable-NetAdapter -Confirm:$false

# Restart WireGuard service
Restart-Service WireGuard
```

---

## 12. Rollback

### 12.1. When Rollback Is Needed

Rollback is needed when:

- Route B installation fails (`install_route` returns `Err`)
- Path B's WireGuard adapter creation fails
- The `connect_test` command returns an error after Path A was already
  connected

### 12.2. Current Rollback Behavior

The code at `main.rs:181-191` implements automatic rollback:

```rust
if let Err(e) = connect_result {
    // Tear down all tunnels created so far
    for t in connected.into_iter() {
        let _ = tokio::task::spawn_blocking(move || t.teardown())
            .await...;
    }
    let _ = tokio::task::spawn_blocking(move || tunnel.teardown())
        .await...;
    return Err(e);
}
```

**Key properties of the rollback:**

1. **Path A remains active** — if Path A was already connected, its tunnel
   stays up and its route remains at metric 10
2. **Path B is torn down** — the failed Path B tunnel is torn down
3. **No stale state claims Path B is active** — `active` flag is not set
   on the failed path
4. **PathManager state** — `add_path("path-b")` was called, but
   `connect_path` may not have completed; the path remains in `Down` state

### 12.3. Manual Rollback Verification

After a failed `connect_test`:

```javascript
// Verify Path A is still active
await invoke('get_status');        // Should show Connected
await invoke('routes_list');       // Should show current: "path-a"
```

```powershell
# Verify Path A route is still at metric 10
Get-NetRoute -DestinationPrefix "203.0.113.0/24" | Sort-Object RouteMetric
# Expected: Path A at metric 10, no Path B route
```

```powershell
# If orphaned state exists, clean up:
await invoke('disconnect');
# Then retry with fixed configs
```

---

## 13. Known Limitations

The following features remain **deferred** and are explicitly out of scope
for the Phase 1 live test:

| Feature | Status | Notes |
|---|---|---|
| Automatic CS2 destination discovery | ⏸ Deferred | `game_detection` module detects games but does not auto-configure SD-WAN destinations |
| Per-flow steering | ⏸ Deferred | `LoadBalancer` exists but `lb_set_strategy` only sets the strategy; no flow-table enforcement |
| FlowKey enforcement | ⏸ Deferred | `lb_register_flow` / `lb_unregister_flow` are stubs; no kernel-level flow binding |
| WFP (Windows Filtering Platform) | ⏸ Deferred | Explicitly NOT implemented per architecture decision |
| WinDivert | ⏸ Deferred | Explicitly NOT implemented per architecture decision |
| ECMP (Equal-Cost Multi-Path) | ⏸ Deferred | Explicitly NOT implemented — Windows route table uses lowest-metric only |
| Packet duplication | ⏸ Deferred | Explicitly NOT implemented |
| FEC (Forward Error Correction) | ⏸ Deferred | Not implemented |
| Multihop | ⏸ Deferred | `multihop_*` commands return "not implemented" |
| QoS | ⏸ Deferred | `qos_*` commands return "not implemented" |
| ML path selection | ⏸ Deferred | Autopilot uses rule-based FSM, not ML |
| Dynamic DNS re-resolution | ⏸ Deferred | Endpoints are static in `.conf` files; no periodic DNS refresh |
| Automatic failover | ⏸ Deferred | Autopilot `commit()` is called by `AutopilotIntent::Switch`, but failover requires the autopilot tick loop to be enabled (`autopilot_enable`) and health monitoring to be running (`monitor_start`) |

### Current Autopilot Behavior

The autopilot FSM (`src-tauri/src/autopilot/mod.rs`) runs on a 500ms tick
when enabled via `autopilot_enable`. It:

1. Reads the snapshot (health + score per route)
2. Computes a `GameSignal` (game detection)
3. Evaluates whether to switch routes based on `PolicyGate` logic
4. If `decision.intent == Switch`, calls `routes.commit(Some(route_id))`

For the live test, automatic failover can be tested by:
1. Calling `autopilot_enable` to start the tick loop
2. Calling `monitor_start` with targets for both endpoints
3. Bringing down Path A's WireGuard adapter (simulated failure)
4. Observing the autopilot detect the health degradation and switch to Path B

However, this is **optional** — the manual switch test (via
`routes_select_manual`) is the primary verification method.

---

## 14. Git Status

The working tree includes the following uncommitted changes from the
current session:

```
src-tauri/src/snapshot/mod.rs    — hysteresis fix (Unknown → health transition)
src-tauri/src/autopilot/policy.rs — config defaults (game_mode_margin, recovery_cooldown_ms)
src-tauri/src/autopilot/mod.rs   — feed_stability iterates all samples
src-tauri/src/net_probe.rs       — test address fix (192.0.2.1 → 127.0.0.1)
src-tauri/src/routes/mod.rs      — clear_target before re-seed in test
```

No new source files are needed for the live test. The existing test-only
mechanism (`connect_test` + `Profile::from_test_env()`) is sufficient.
