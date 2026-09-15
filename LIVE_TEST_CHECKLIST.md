# LIVE TEST — Verification Checklist

> **Purpose:** Master checklist of every proof point that must be satisfied
> during the Phase 1 live datapath test. Check each box as evidence is
> captured. **Do not mark Phase 1 as VERIFIED until every applicable
> section below is complete.**

---

## Section A: Prerequisites

### A.1. Operator Environment

- [ ] PowerShell opened **as Administrator** (UAC prompt accepted)
- [ ] `whoami` returns the expected user
- [ ] `net session` succeeds (no "Access is denied" error)
- [ ] `is_admin` from `wireguard_driver_status` returns `true`

### A.2. WireGuard Driver

- [ ] `Get-Service WireGuard` shows service **Running**
- [ ] `wireguard_driver_status` shows:
  - `dll_loaded: true`
  - `driver_present: true`
  - `driver_version_string` is non-empty (e.g. "1.1.0.0")
  - `is_admin: true`
  - `error_code: 0`

### A.3. Test Inputs (see LIVE_TEST_INPUTS.md)

- [ ] `MARSTART_PATH_A_CONFIG` env var set to external `.conf` file path
- [ ] `MARSTART_PATH_B_CONFIG` env var set to external `.conf` file path
- [ ] `MARSTART_MANAGED_DESTINATION` env var set (e.g. `203.0.113.0/24`)
- [ ] Path A `.conf` file exists at the specified path
- [ ] Path B `.conf` file exists at the specified path
- [ ] **Endpoint A ≠ Endpoint B** (verified by IP:port comparison)
- [ ] **Tunnel address A ≠ Tunnel address B** (e.g. 10.10.1.2 ≠ 10.10.2.2)
- [ ] **Peer public key A ≠ Peer public key B** (verified via `wg show`)
- [ ] **No `.conf` files committed to Git** (verified via `git status`)
- [ ] **No secrets in environment variables** (only file paths + CIDR)

### A.4. Controlled Destination

- [ ] Controlled destination IP is real and reachable (e.g. `203.0.113.10`)
- [ ] Destination protocol specified (TCP or UDP)
- [ ] Destination port specified (e.g. 8080)
- [ ] Destination is reachable through BOTH Path A and Path B WireGuard endpoints

---

## Section B: Clean Baseline

### B.1. Network State Capture

- [ ] `Get-NetAdapter` captured to baseline file
- [ ] `Get-NetIPInterface` captured to baseline file
- [ ] `Get-NetRoute` captured to baseline file
- [ ] WireGuard adapter list captured to baseline file

### B.2. Baseline Verification

- [ ] **No stale MARSTART routes** in baseline (no `203.0.113.0/24` with metric 10 or 20)
- [ ] **No stale MARSTART WireGuard adapters** in baseline
- [ ] **No orphaned MARSTART path-a/path-b interfaces**
- [ ] Foreign routes verified intact and untouched

---

## Section C: Driver Check

- [ ] `tunnel_diagnostics` invoked via Tauri command
- [ ] DiagnosticsReport captured:
  - `dll_loaded: true`
  - `driver_present: true`
  - `is_admin: true`
  - `adapter_created: true`
  - `config_applied: true`
  - `adapter_state: "Up"`
  - `adapter_closed: true`
  - `no_orphan_adapter: true`
  - `errors` array is empty (or contains only expected non-fatal warnings)

---

## Section D: Create Path A

### D.1. Connection

- [ ] `connect_test` invoked via Tauri command
- [ ] Command returned success (no error)

### D.2. Path A Evidence

For Path A (`path-a`):

- [ ] `path_id`: `path-a`
- [ ] `adapter_name`: contains "MARSTART"
- [ ] `interface_luid`: non-zero u64 value
- [ ] `interface_index`: non-zero u32 value
- [ ] `adapter_state`: "Up" (from `WireGuardGetAdapterState`)
- [ ] `tunnel_state`: "Up" (from PathManager::get_path)
- [ ] `handshake_timestamp_unix`: non-zero (handshake completed with server)
- [ ] `tx_bytes`: > 0 (or non-zero after traffic test)
- [ ] `rx_bytes`: > 0 (or non-zero after traffic test)
- [ ] `active`: true (Path A is the active path)
- [ ] `health`: "Healthy" (PathManager path health)

---

## Section E: Create Path B

### E.1. Connection

- [ ] Both tunnels created (Path A + Path B)
- [ ] No error from `connect_test`

### E.2. Path B Evidence

For Path B (`path-b`):

- [ ] `path_id`: `path-b`
- [ ] `adapter_name`: contains "MARSTART" (different from Path A)
- [ ] `interface_luid`: non-zero, **different from Path A's LUID**
- [ ] `interface_index`: non-zero, **different from Path A's index**
- [ ] `adapter_state`: "Up"
- [ ] `tunnel_state`: "Up"
- [ ] `handshake_timestamp_unix`: non-zero (handshake completed)
- [ ] `tx_bytes`: > 0 (after traffic)
- [ ] `rx_bytes`: > 0 (after traffic)
- [ ] `active`: false (Path B is the standby path)
- [ ] `health`: "Healthy"

### E.3. Verify Both Adapters UP

- [ ] `get_status` returns `Connected`
- [ ] Both WireGuard adapters show as **Up** in `Get-NetAdapter`
- [ ] Both adapters appear in `wg show` on the server side

---

## Section F: Route Installation

### F.1. Route A (Active)

- [ ] `install_route` returned `Ok(())` for path-a
- [ ] Windows route table shows:
  - `destination`: `203.0.113.0` (or the managed destination)
  - `prefix_length`: `24`
  - `interface_luid`: matches Path A's LUID
  - `interface_index`: matches Path A's index
  - `metric`: `10` (ACTIVE_METRIC)
  - `protocol`: `NET_MGMT` (MIB_IPPROTO_NETMGMT = 3)

### F.2. Route B (Standby)

- [ ] `install_route` returned `Ok(())` for path-b
- [ ] Windows route table shows:
  - `destination`: same managed destination
  - `prefix_length`: same
  - `interface_luid`: matches Path B's LUID (different from A)
  - `interface_index`: matches Path B's index (different from A)
  - `metric`: `20` (STANDBY_METRIC)
  - `protocol`: `NET_MGMT`

### F.3. Route Ownership

- [ ] Both routes tagged with `MIB_IPPROTO_NETMGMT` (protocol = 3)
- [ ] Routes are distinguishable from foreign routes (different LUID/metric)

---

## Section G: Real Traffic → Path A

### G.1. Traffic Generation

- [ ] Client generates TCP traffic to `203.0.113.10:8080` (e.g. `curl`, `nc`, or browser)
- [ ] Packet capture started on server before traffic
- [ ] Timestamp recorded before traffic generation

### G.2. Server-Side Evidence (Path A)

- [ ] Server `tcpdump` (or `pktmon`) captures packets on `wg0`
- [ ] Packets show **source IP `10.10.1.2`** (Path A tunnel address)
- [ ] Packets show **destination `203.0.113.10:8080`**
- [ ] Server `wg show wg0` peer counters (`rx_bytes`) increased
- [ ] Server `wg show wg1` peer counters (`rx_bytes`) unchanged (no Path B traffic)
- [ ] Timestamp in capture matches client-side timestamp (within reasonable clock skew)

### G.3. Client-Side Evidence (Path A)

- [ ] `get_connection_info` for path-a shows `tx_bytes > 0`
- [ ] `get_connection_info` for path-b shows `tx_bytes == 0` (or unchanged)
- [ ] `route_snapshot` shows path-a health = "Good"
- [ ] `routes_list` shows `current: "path-a"` and `recommended: "path-a"`

---

## Section H: Switch Route A → B

### H.1. Switch Command

- [ ] `routes_select_manual({ id: "path-b" })` invoked via Tauri command
- [ ] Command returned success

### H.2. Metric Switch Evidence

- [ ] `Get-NetRoute -DestinationPrefix "203.0.113.0/24"` shows:
  - Path A route metric changed from `10` → `20` (standby)
  - Path B route metric changed from `20` → `10` (active)
- [ ] `route_snapshot` shows path-b as selected

### H.3. Server-Side Evidence (Path B)

- [ ] Server `tcpdump` captures packets on `wg1`
- [ ] Packets show **source IP `10.10.2.2`** (Path B tunnel address)
- [ ] Packets show **destination `203.0.113.10:8080`**
- [ ] Server `wg show wg1` peer counters (`rx_bytes`) increased
- [ ] Server `wg show wg0` peer counters unchanged (no Path A traffic)
- [ ] Timestamp in capture corresponds to post-switch timeframe

### H.4. Client-Side Evidence (Path B)

- [ ] `get_connection_info` for path-b shows `tx_bytes > 0`
- [ ] `route_snapshot` shows path-b health = "Good"
- [ ] `routes_list` shows `current: "path-b"`

---

## Section I: Switch Route B → A

### I.1. Switch Command

- [ ] `routes_select_manual({ id: "path-a" })` invoked via Tauri command
- [ ] Command returned success

### I.2. Metric Switch Evidence

- [ ] `Get-NetRoute` shows:
  - Path A route metric: `10` (active again)
  - Path B route metric: `20` (standby)

### I.3. Server-Side Evidence (Path A)

- [ ] Server `tcpdump` captures packets on `wg0`
- [ ] Packets show **source IP `10.10.1.2`** (back to Path A)
- [ ] Server `wg show wg0` peer counters (`rx_bytes`) increased again
- [ ] Server `wg show wg1` peer counters unchanged

### I.4. Client-Side Evidence (Path A)

- [ ] `get_connection_info` for path-a shows `tx_bytes` increased further
- [ ] `routes_list` shows `current: "path-a"`

---

## Section J: Three-Cycle Test

### Cycle 1: A → B → A

- [ ] Switch A → B: server sees `10.10.2.2` packets (wg1)
- [ ] Switch B → A: server sees `10.10.1.2` packets (wg0)
- [ ] Packet evidence captured for both transitions

### Cycle 2: A → B → A

- [ ] Switch A → B: server sees `10.10.2.2` packets (wg1)
- [ ] Switch B → A: server sees `10.10.1.2` packets (wg0)
- [ ] Packet evidence captured for both transitions

### Cycle 3: A → B → A

- [ ] Switch A → B: server sees `10.10.2.2` packets (wg1)
- [ ] Switch B → A: server sees `10.10.1.2` packets (wg0)
- [ ] Packet evidence captured for both transitions

### All Cycles

- [ ] At least one packet capture file contains evidence from all 6 transitions
- [ ] Source IP consistently matches the active path
- [ ] Server peer counters show traffic on the correct interface only

---

## Section K: Failover Test

### K.1. Set Up

- [ ] Path A is active (metric 10)
- [ ] Path B is standby (metric 20)
- [ ] Server confirms traffic flowing through Path A (wg0)

### K.2. Simulate Path A Failure

- [ ] Simulate failure by tearing down Path A WireGuard tunnel
  - Method: `disconnect` is too broad (tears down both). Use a method that
    only takes down Path A (e.g., set adapter DOWN, or remove Path A's route,
    or block the endpoint)
  - **Note:** If the application does not expose a per-path teardown command,
    document the external method used (e.g., `netsh interface set interface
    "MARSTART-path-a" admin=disable`)

### K.3. Failover Timing

Record timestamps:

- [ ] `t_failure_detected`: when the application detects Path A is down
  (from `routes_list` showing `reason: EmergencyBypass` or health = "Bad")
- [ ] `t_switch_started`: when `activate_path("path-b")` is called
- [ ] `t_route_B_active`: when `Get-NetRoute` shows Path B metric = 10
- [ ] `t_first_successful_packet_B`: when server receives first packet on wg1 after failure

Calculate:

- [ ] `detection_time = t_switch_started - t_failure_detected`
- [ ] `route_switch_time = t_route_B_active - t_switch_started`
- [ ] `packet_recovery_time = t_first_successful_packet_B - t_route_B_active`
- [ ] `total_failover_time = t_first_successful_packet_B - t_failure_detected`

### K.4. Failover Verification

- [ ] After failure, server receives traffic from Path B (`10.10.2.2` / wg1)
- [ ] No packet loss observed on server side during failover (or documented gap)
- [ ] `routes_list` shows `current: "path-b"` after recovery
- [ ] `routes_list` shows `recommended: "path-b"` after recovery

---

## Section L: Route Ownership Test (Foreign Routes Preserved)

### L.1. Create Foreign Route

- [ ] Create a route that MARSTART did NOT create:
  ```powershell
  # Example: route to a different destination via a different interface
  route add 192.0.2.0/24 MASK 255.255.255.0 <existing_interface_ip>
  ```
- [ ] Record: `destination X`, `interface X`, `protocol` (not NET_MGMT)

### L.2. Activate / Deactivate / Reconcile

- [ ] `routes_select_manual({ id: "path-a" })` — MARSTART activates path-a
- [ ] `routes_select_manual({ id: "path-b" })` — MARSTART switches to path-b
- [ ] Observe `reconcile()` behavior if exposed, or verify via reconnect:
  - `disconnect` → `connect_test` (this triggers `clear_paths` → `reconcile`)

### L.3. Verify Foreign Route Preserved

- [ ] Foreign route **still exists** after all MARSTART operations
- [ ] Foreign route's `destination`, `interface`, and `protocol` are unchanged
- [ ] Foreign route was **not** deleted by `remove_route` or `cleanup_owned_routes`
- [ ] Foreign route was **not** modified by `update_route_metric`

---

## Section M: Rollback Test (Route Installation Failure)

### M.1. Simulate Failure

- [ ] Force Path B route installation to fail (e.g., by making the
  destination conflict with an existing route, or by temporarily
  revoking admin privileges mid-operation)

### M.2. Verify Rollback

- [ ] Path A **remains active** (metric 10)
- [ ] Path A traffic **continues** (server sees packets on wg0)
- [ ] `active_path` **remains "path-a"** in MARSTART state
- [ ] No stale state claims Path B is active
- [ ] Error is reported but system remains in a consistent state

---

## Section N: Restart Test

### N.1. Pre-Restart State

- [ ] Path A active (metric 10), Path B standby (metric 20)
- [ ] Server confirms traffic flowing through Path A

### N.2. Restart

- [ ] Terminate MARSTART LINK process
- [ ] Verify processes are gone: `Get-Process MARSTART*`
- [ ] Restart MARSTART LINK (elevated, with env vars set)
- [ ] Application starts without error

### N.3. Reconcile

- [ ] After restart, call `connect_test` (which calls `clear_paths()` first,
  removing stale routes, then re-establishes both tunnels)
- [ ] Capture `reconcile()` return value — note which actions were taken

### N.4. Post-Restart Verification

- [ ] **Stale MARSTART routes detected:** `Get-NetRoute` for managed destination
- [ ] **Foreign routes preserved:** routes not created by MARSTART are intact
- [ ] **Desired route restored:** active path has metric 10
- [ ] **A/B state rebuilt:** both WireGuard adapters UP, both routes present
- [ ] `routes_list` shows valid `current` and `recommended` values
- [ ] Traffic flows correctly through active path (server confirms)

---

## Section O: Cleanup & No Orphans

### O.1. Graceful Disconnect

- [ ] `disconnect` invoked via Tauri command
- [ ] Command returned success

### O.2. No Orphaned Routes

- [ ] `Get-NetRoute | Where-Object { DestinationPrefix -like "203.0.113*" }`
  returns **empty** (all MARSTART routes removed)

### O.3. No Orphaned Adapters

- [ ] `Get-NetAdapter -Name "*MARSTART*"` returns **empty**
- [ ] `Get-NetAdapter -InterfaceDescription "*WireGuard*"` shows no
  `MARSTART-*` named adapters

### O.4. No Orphaned Processes

- [ ] `Get-Process | Where-Object { $_.Name -like "*marstart*" }` returns empty

### O.5. Driver State Clean

- [ ] `Get-Service WireGuard` shows **Running** (driver stays loaded, no adapters)
- [ ] `wireguard_driver_status` still shows `driver_present: true`

---

## Section P: Final Verdict

> The final verdict is recorded in `LIVE_TEST_HANDOFF.md`.
> The baseline status remains:

```
PHASE 1 LIVE DATAPATH NOT VERIFIED
```

> **Preflight blocker:** Administrator rights not available, WireGuard service
> stopped, no test configs. See [§1 Prereqs](#1-prerequisites) in
> `LIVE_TEST_HANDOFF.md`.

- [ ] All sections A–O above completed
- [ ] All evidence captured (packet captures, timestamps, metric values)
- [ ] All pass/fail criteria met (see LIVE_TEST_HANDOFF.md §10)
- [ ] Final verdict determined by live test operator (not simulated)

### If any section fails:

- [ ] Capture evidence of the failure
- [ ] Identify root cause
- [ ] If a real bug is found: make minimum fix, add regression test, rerun
- [ ] Do NOT attempt to simulate the fix — rerun the full live test

---

## Appendix: Evidence Collection Summary

| Evidence Type | Where Collected | What Field |
|---|---|---|
| Driver status | `wireguard_driver_status` | `dll_loaded`, `driver_present`, `is_admin`, `driver_version_string` |
| Tunnel status | `get_status` | `TunnelStatus::Connected` |
| Connection info | `get_connection_info` | `handshake_timestamp_unix`, `tx_bytes`, `rx_bytes`, `endpoint` |
| Route evaluation | `routes_list` | `current`, `recommended`, `reason`, per-path `score`/`health` |
| Route snapshot | `route_snapshot` | per-route `health`, `score`, `latest_rtt_ms`, `avg_rtt_ms`, `loss_ratio`, `stability` |
| Windows routes | `Get-NetRoute` | `DestinationPrefix`, `NextHop`, `RouteMetric`, `NextHopInterface` |
| Windows adapters | `Get-NetAdapter` | `Name`, `InterfaceIndex`, `Status`, `LinkSpeed` |
| Server packet capture | `tcpdump`/`pktmon` | Source IP (10.10.1.2 vs 10.10.2.2), destination, timestamp |
| Server peer counters | `wg show` | `rx_bytes`, `tx_bytes` per peer |
