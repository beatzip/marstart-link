# LIVE TEST — Windows Administrator Procedure

> **Purpose:** Step-by-step procedure for preparing the Windows test machine.
> This is the machine where MARSTART LINK runs with elevated privileges.

---

## 0. Prerequisite: Open PowerShell as Administrator

```
Open PowerShell as Administrator
```

**The entire test sequence requires an elevated token.** The MARSTART LINK
binary requests `requireAdministrator` in its embedded application manifest
(`src-tauri/src-tauri.manifest`). When launched, Windows will display a UAC
prompt — click **Yes** to elevate.

---

## 1. Verify Elevation

```powershell
# Confirm the current user is elevated
whoami
# Expected: DOMAIN\username or COMPUTERNAME\username

# Confirm elevation via "net session" (succeeds only when elevated)
net session
# Expected: returns "The command completed successfully" (no error)
# If it returns "System error 5 — Access is denied", RESTART as Administrator.

# Confirm via PowerShell
([Security.Principal.WindowsPrincipal]
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
# Expected: True
```

---

## 2. Verify WireGuard Service

```powershell
# Check if the WireGuard service exists and its status
Get-Service WireGuard -ErrorAction SilentlyContinue

# Expected: Status should be "Running"
# If the service does not exist:
#   Install WireGuard-NT from https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip
#   Run the MSI installer as Administrator

# If the service exists but is Stopped:
Start-Service WireGuard
# Verify it started:
Get-Service WireGuard
# Expected: Status = Running
```

**Do not claim success until service status is verified as Running.**

---

## 3. Pre-Flight Driver Check

Run the application's built-in driver diagnostics **before** attempting to
connect two paths:

```powershell
# Launch the app in dev mode (UAC prompt will appear)
cd C:\Users\User\Desktop\marstart-link-main
npm run tauri:dev
```

Then, from the app's DevTools console (F12 → Console):

```javascript
const status = await window.__TAURI__.invoke('wireguard_driver_status');
console.log(JSON.stringify(status, null, 2));
```

Expected output (redacted for security):

```json
{
  "dll_loaded": true,
  "driver_present": true,
  "driver_version": "1.1.0.0",
  "driver_version_string": "1.1.0.0",
  "is_admin": true,
  "error_code": 0,
  "human_readable_error": "ok"
}
```

If `is_admin` is `false` or `driver_present` is `false`, do **not** proceed
with the connection test.

### Alternative: Full Diagnostics Report

```javascript
// Run the full FFI lifecycle test (creates a short-lived adapter,
// applies config, sets UP, queries state, tears down)
const report = await window.__TAURI__.invoke('tunnel_diagnostics', {
  profile_id: "default"
});
console.log(JSON.stringify(report, null, 2));
```

Key fields to verify:
- `dll_loaded: true`
- `driver_present: true`
- `is_admin: true`
- `adapter_created: true`
- `adapter_state: "Up"` (after set UP)
- `no_orphan_adapter: true` (after teardown)

---

## 4. Clean Baseline

Before starting the MARSTART test, capture the **baseline** state of the
Windows routing table, network adapters, and WireGuard driver state.

### 4.1. Capture Network Adapter State

```powershell
# Save baseline to a file for comparison
$baseline = "C:\live-test\baseline.txt"
"=== Get-NetAdapter ===" | Out-File $baseline -Encoding UTF8
Get-NetAdapter | Format-Table Name, InterfaceDescription, ifIndex, Status, LinkSpeed | Out-String | Out-File $baseline -Append -Encoding UTF8

"=== Get-NetIPInterface (IPv4) ===" | Out-File $baseline -Append -Encoding UTF8
Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like "*wireguard*" -or $_.InterfaceAlias -like "*MARSTART*" } | Format-Table | Out-String | Out-File $baseline -Append -Encoding UTF8

"=== Get-NetRoute (MARSTART/WireGuard) ===" | Out-File $baseline -Append -Encoding UTF8
Get-NetRoute | Where-Object { $_.DestinationPrefix -like "203.0.113*" -or $_.NextHopInterface -like "*wireguard*" } | Format-Table DestinationPrefix, NextHop, RouteMetric, PolicyStorePersisted, AddressFamily | Out-String | Out-File $baseline -Append -Encoding UTF8

"=== WireGuard Adapters ===" | Out-File $baseline -Append -Encoding UTF8
Get-NetAdapter -InterfaceDescription "*WireGuard*" | Format-Table | Out-String | Out-File $baseline -Append -Encoding UTF8

# Also save to a variable for reference
Get-NetAdapter -Name "*WireGuard*" -ErrorAction SilentlyContinue
Get-NetRoute | Where-Object { $_.DestinationPrefix -like "203.0.113*" }
```

### 4.2. Verify Clean State

Check that the baseline shows:

- ✅ No stale MARSTART routes (`203.0.113.0/24` or similar)
- ✅ No stale MARSTART WireGuard adapters
- ✅ No `path-a` or `path-b` interfaces

If any stale entries exist, clean them up:

```powershell
# Remove stale MARSTART routes (tagged with MIB_IPPROTO_NETMGMT = protocol 3)
# Use route.exe to remove by prefix + interface
route delete 203.0.113.0

# Remove stale WireGuard adapters
Get-NetAdapter -InterfaceDescription "*WireGuard*" | Where-Object {
    $_.Name -like "MARSTART*"
} | ForEach-Object {
    Write-Host "Removing stale adapter: $($_.Name)"
    # Requires admin — removes the adapter
    # Note: This is a best-effort cleanup
}

# Restart WireGuard service to clear any orphaned state
Restart-Service WireGuard
```

---

## 5. Set Test Environment Variables

```powershell
# Set these in the SAME elevated PowerShell session before launching the app
$env:MARSTART_PATH_A_CONFIG     = "C:\live-test\configs\path-a.conf"
$env:MARSTART_PATH_B_CONFIG     = "C:\live-test\configs\path-b.conf"
$env:MARSTART_MANAGED_DESTINATION = "203.0.113.0/24"

# Verify they are set (file paths only — no secrets visible)
Write-Host "Path A config: $env:MARSTART_PATH_A_CONFIG"
Write-Host "Path B config: $env:MARSTART_PATH_B_CONFIG"
Write-Host "Managed dest:  $env:MARSTART_MANAGED_DESTINATION"

# Verify files exist
Test-Path $env:MARSTART_PATH_A_CONFIG  # Expected: True
Test-Path $env:MARSTART_PATH_B_CONFIG  # Expected: True
```

---

## 6. Launch MARSTART LINK

```powershell
# Option A: Dev mode (faster rebuild, easier debugging)
cd C:\Users\User\Desktop\marstart-link-main
npm run tauri:dev

# Option B: Release build (more representative)
cd C:\Users\User\Desktop\marstart-link-main
npm run tauri:build
# Then launch the built binary from an elevated shell
& "C:\Users\User\Desktop\marstart-link-main\src-tauri\target\release\MARSTART LINK.exe"
```

Both options will trigger the UAC prompt (due to `requireAdministrator` in the
manifest). Accept the elevation prompt.

---

## 7. Quick Reference: Tauri Invoke Commands

All commands are invoked from the DevTools Console (F12) as:

```javascript
await window.__TAURI__.invoke('command_name', { param: value })
```

| Command | Params | Returns | Purpose |
|---|---|---|---|
| `connect_test` | none (reads env vars) | `void` | Connect both paths via env vars |
| `disconnect` | none | `void` | Disconnect all tunnels and clean up |
| `get_status` | none | `TunnelStatus` | Current connection status |
| `get_connection_info` | none | `ConnectionInfo` | Handshake, tx/rx bytes, endpoint |
| `wireguard_driver_status` | none | `DriverStatus` | Pre-flight driver check |
| `tunnel_diagnostics` | `profile_id` or `profile` (optional) | `DiagnosticsReport` | Full FFI lifecycle test |
| `routes_list` | none | `RouteEvaluation` | Current + recommended + scores + reason |
| `routes_get_state` | none | `RouteState` | Candidate list + current + cooldown |
| `routes_select_manual` | `id: string\|null` | `RouteState` | Force-select a route (or clear) |
| `routes_set_policy` | `cooldown_ms?`, `switch_margin?` | `RouteState` | Adjust cooldown and switch margin |
| `route_snapshot` | none | `Snapshot` | Per-route health, score, RTT, loss |
| `monitor_get_snapshot` | none | `Vec<AggregatedMetrics>` | Raw metrics for all targets |
| `monitor_get_state` | none | `MonitorState` | Monitor service state |
| `autopilot_get_state` | none | `AutopilotDecision\|null` | Latest autopilot decision |
| `autopilot_enable` | `config?` (optional) | `PlaceholderState` | Start autopilot tick loop |
| `autopilot_disable` | none | `PlaceholderState` | Stop autopilot tick loop |

### Key Return Type Fields

**TunnelStatus:** `Disconnected | Connecting | Connected | Error(String)`

**ConnectionInfo:** `handshake_timestamp_unix: u64`, `tx_bytes: u64`,
`rx_bytes: u64`, `endpoint: Option<String>`

**DriverStatus:** `dll_loaded: bool`, `driver_present: bool`,
`driver_version_string: String`, `is_admin: bool`, `error_code: u32`

**DiagnosticsReport:** `dll_loaded: bool`, `driver_present: bool`,
`driver_version: u32`, `is_admin: bool`, `adapter_created: bool`,
`config_applied: bool`, `adapter_state: "Up"|"Down"|"Unknown"`,
`adapter_closed: bool`, `no_orphan_adapter: bool`, `errors: Vec<String>`

**RouteEvaluation:** `current: Option<String>`, `recommended: Option<String>`,
`scores: Vec<{id, score, weighted_score, health, weight}>`, `reason: string`

**RouteScoreView fields:** `id`, `score`, `weighted_score`, `health`
(`"Good"|"Degraded"|"Bad"|"Unknown"`), `weight`

**Snapshot:** `routes: Vec<RouteSnapshot>`, `selected: Option<String>`,
`timestamp_ms: i64`

**RouteSnapshot fields:** `route_id`, `score`, `health`,
`latest_rtt_ms`, `avg_rtt_ms`, `jitter_ms`, `loss_ratio`, `stability`,
`samples`

**Metrics:** `AggregatedMetrics` includes `avg_rtt_ms`, `jitter_ms`,
`loss_ratio`, `samples`

---

## 8. Windows Route Table Verification Commands

```powershell
# Verify route was installed with correct metric
Get-NetRoute -DestinationPrefix "203.0.113.0/24" | Format-Table

# Expected: Two entries — one per WireGuard adapter
# Active path: RouteMetric = 10 (ACTIVE_METRIC)
# Standby path: RouteMetric = 20 (STANDBY_METRIC)

# Show routes tagged as MARSTART-owned (Protocol = NET_MGMT = 3)
Get-NetRoute -DestinationPrefix "203.0.113.0/24" |
    Where-Object { $_.RouteMetric -eq 10 -or $_.RouteMetric -eq 20 } |
    Format-Table DestinationPrefix, NextHop, RouteMetric, NextHopInterface

# Show WireGuard adapter details
Get-NetAdapter -InterfaceDescription "*WireGuard*" |
    Format-Table Name, InterfaceDescription, InterfaceIndex, Status

# Show LUID for a specific interface (if needed for cross-reference)
Get-NetAdapter | Where-Object { $_.Name -like "MARSTART*" } |
    Select-Object Name, InterfaceIndex, @{N="Luid";E={$_.InterfaceGuid}}

# Show interface IP configuration
Get-NetIPAddress -InterfaceAlias "*MARSTART*" -AddressFamily IPv4 |
    Format-Table IPAddress, PrefixLength, InterfaceAlias
```

---

## 9. Cleanup Procedure

### 9.1. Disconnect via Tauri Command

```javascript
// Graceful disconnect (tears down all tunnels + routes)
await window.__TAURI__.invoke('disconnect');
```

### 9.2. Verify No Orphans

After disconnect, run:

```powershell
# Check for orphaned MARSTART routes
Get-NetRoute | Where-Object {
    $_.DestinationPrefix -like "203.0.113*" -and
    ($_.RouteMetric -eq 10 -or $_.RouteMetric -eq 20)
}
# Expected: no output (all routes cleaned up)

# Check for orphaned WireGuard adapters
Get-NetAdapter -InterfaceDescription "*WireGuard*" | Where-Object {
    $_.Name -like "MARSTART*"
}
# Expected: no output

# Verify driver state is clean
Get-Service WireGuard
# Expected: Running (driver stays running, no adapters needed)
```

### 9.3. Manual Cleanup (if needed)

```powershell
# Remove any remaining MARSTART routes manually
Get-NetRoute | Where-Object {
    $_.DestinationPrefix -like "203.0.113*"
} | ForEach-Object {
    Remove-NetRoute -DestinationPrefix $_.DestinationPrefix -InterfaceIndex $_.InterfaceIndex -Confirm:$false
}

# Remove orphaned adapters
Get-NetAdapter -InterfaceDescription "*WireGuard*" | Where-Object {
    $_.InterfaceStatus -eq "Down" -and $_.Name -like "MARSTART*"
} | Disable-NetAdapter -Confirm:$false
```

---

## 10. Troubleshooting

| Symptom | Check | Fix |
|---|---|---|
| `connect_test` fails with "MARSTART_PATH_A_CONFIG env var not set" | `echo $env:MARSTART_PATH_A_CONFIG` | Set env var in the same elevated session |
| `wireguard_driver_status` shows `is_admin: false` | `net session` | Restart PowerShell as Administrator |
| `driver_present: false` | `Get-Service WireGuard` | Install WireGuard-NT, start service |
| `adapter_created: false` | `wireguard.dll` in resources/ | Run `npm run prepare:resources` |
| `Error: Access is denied` | UAC not elevated | Launch with `requireAdministrator` manifest |
| Route metric stuck at 20 | Route not deleted/recreated | Use `routes_select_manual` to re-activate |
