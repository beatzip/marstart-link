# SD-WAN Datapath — Phase 1 Implementation Notes

**Scope:** Multi-adapter WireGuard + Windows route table datapath (Option A)
**Non-goals:** WFP, WinDivert, packet interception, ECMP, flow steering, CS2 packet discovery.

---

## 1. Current Interfaces (Inspected)

### 1.1 `wireguard.rs` (1058 lines)

| Component | Location | Status |
|---|---|---|
| `WireGuardTunnel` struct | lines 210–234 | Single `adapter_handle: Mutex<Option<HANDLE>>` |
| `WireGuardTunnel::new()` | lines 244–388 | Loads 7 FFI function pointers via `GetProcAddress` |
| `connect_impl()` | lines 419–489 | Calls `WireGuardCreateAdapter` **once** |
| `teardown()` | lines 496–516 | Sets DOWN + closes handle |
| `stats()` | lines 525–541 | Calls `WireGuardGetConfiguration` |
| `connection_info()` | lines 543–556 | Returns handshake/tx/rx/endpoint |
| `run_diagnostics()` | lines 652–738 | Full lifecycle smoke test |
| `wireguard_driver_status()` | lines 782–885 | Standalone pre-flight check |
| `wireguard_delete_driver()` | lines 909–937 | Standalone driver uninstall |

**Function pointers loaded (`new()` lines 278–309):**

| Index | `GetProcAddress` name | Typedef | Used for |
|---|---|---|---|
| 1 | `WireGuardCreateAdapter` | `WireGuardCreateAdapterFunc` | Create adapter |
| 2 | `WireGuardCloseAdapter` | `WireGuardCloseAdapterFunc` | Close adapter |
| 3 | `WireGuardSetConfiguration` | `WireGuardSetConfigurationFunc` | Apply config |
| 4 | `WireGuardGetConfiguration` | `WireGuardGetConfigurationFunc` | Read stats |
| 5 | `WireGuardSetAdapterState` | `WireGuardSetAdapterStateFunc` | UP/DOWN |
| 6 | `WireGuardGetAdapterState` | `WireGuardGetAdapterStateFunc` | Query state |
| 7 | `WireGuardGetRunningDriverVersion` | `WireGuardGetRunningDriverVersionTyped` | Driver check |

**Missing (needed for Phase 1):**

| Function | Purpose |
|---|---|
| `WireGuardGetAdapterLUID` | Get adapter LUID for `MIB_IPFORWARD_ROW2.InterfaceLuid` |
| `WireGuardOpenAdapter` | Reopen existing adapter by name (crash recovery) |

### 1.2 `main.rs` (639 lines)

| Component | Lines | Status |
|---|---|---|
| `AppState` struct | 64–76 | `tunnel: Arc<Mutex<Option<WireGuardTunnel>>>` — **single tunnel** |
| `connect()` | 85–134 | Creates single tunnel via `spawn_blocking` |
| `disconnect()` | 137–152 | Takes and tears down single tunnel |
| `get_status()` | 155–162 | Returns status of single tunnel |
| `get_connection_info()` | 165–173 | Returns info of single tunnel |
| autopilot tick | 403–428 | Calls `routes.commit(route_id)` |
| `generate_handler!` | 587–628 | All Tauri commands registered |

### 1.3 `routes/mod.rs` (501 lines)

| Component | Lines | Status |
|---|---|---|
| `RouteManager` struct | 77–84 | Has `snapshot`, `inner`, `last_switch_ms`, etc. |
| `RouteManager::new()` | 87–99 | Creates `Arc<Self>` from metrics + snapshot |
| `RouteManager::commit()` | 286–295 | **Only** updates in-memory: `snapshot.set_selected(id)` + `snapshot.refresh_now()` |
| `RouteManager::evaluate()` | 177–284 | Scoring, health, cooldown logic |
| `State` → `set_candidates` → `evaluate` → `commit` | various | Control plane only — no kernel calls |

### 1.4 `utils.rs` (65 lines)

| Function | Lines | Status |
|---|---|---|
| `resolve_dll_path()` | 11–32 | Active — resolves `wireguard.dll` path |
| `parse_cidr()` | 34–46 | Active — parses CIDR notation |
| `create_forward_row()` | 49–64 | **DEAD CODE** — creates `MIB_IPFORWARD_ROW2` but never called |

### 1.5 `profiles.rs` (76 lines)

| Component | Lines | Status |
|---|---|---|
| `Profile` struct | 12–23 | `id`, `display_name`, `endpoints: Vec<EndpointSpec>`, `wg_config_path: Option<String>` |
| `EndpointSpec` | 26–35 | `id`, `addr: SocketAddr`, `label`, `weight` |
| `load_profile()` | 41–75 | Returns `endpoints: Vec::new()` — **always empty** |

### 1.6 `route_registry.rs` (87 lines)

`RouteRegistry` coordinates `MonitorService`, `RouteSnapshotEngine`, `RouteManager`, `LoadBalancer`. Does NOT coordinate paths or WireGuard.

### 1.7 `snapshot/mod.rs` (448 lines)

`RouteSnapshotEngine` — periodically computes `Snapshot` with per-route `RouteSnapshot { id, score, health, rtt, jitter, loss, stability, samples }`. `set_selected()` stores in-memory `Arc<RwLock<Option<String>>>`.

### 1.8 `wireguard_config.rs` (111 lines)

`ParsedConfig` with `peers: Vec<ParsedPeer>` — supports multiple peers per config. `WireguardAllowedIp` struct at offset +20 `flags`, size 24 bytes. Verified ABI-correct.

### 1.9 `Cargo.toml` Windows dependencies

```toml
windows = { version = "0.58", features = [
    "Win32_Foundation",
    "Win32_NetworkManagement_IpHelper",   # ← INCLUDES CreateIpForwardEntry2 etc.
    "Win32_NetworkManagement_Ndis",
    "Win32_Networking_WinSock",
    "Win32_System_LibraryLoader",
    "Win32_System_Threading",
] }
```

**Key finding:** `Win32_NetworkManagement_IpHelper` in the Rust `windows` crate v0.58 includes `netioapi.h` functions (`CreateIpForwardEntry2`, `DeleteIpForwardEntry2`, `GetIpForwardTable2`, `GetAdaptersAddresses`, `MIB_IPFORWARD_ROW2`, `InitializeIpForwardEntry`). **No Cargo.toml changes needed.**

### 1.10 `wireguard.h` (318 lines, bundled)

12 exported functions confirmed. Peer flags: `REPLACE_ALLOWED_IPS=1<<5`, `REMOVE=1<<6`, `UPDATE_ONLY=1<<7`. Interface flags: `REPLACE_PEERS=1<<3`.

WireGuard-NT README (repo, lines 22–26) confirms multi-adapter creation:
```c
WireGuardCreateAdapter(L"Adapter1", L"WireGuard", &SomeFixedGUID1);
WireGuardCreateAdapter(L"Adapter2", L"WireGuard", &SomeFixedGUID2);
```

### 1.11 `embed_manifest.bat` / `tauri.conf.json`

Manifest requires `requireAdministrator`. Needed for:
- `WireGuardCreateAdapter` (first-time driver install)
- `CreateIpForwardEntry2` / `DeleteIpForwardEntry2`

### 1.12 Existing Tests

| Module | Tests | Status |
|---|---|---|
| `wireguard.rs` tests | `diagnostics_report_serialises`, `driver_status_returns_struct`, etc. | PASS |
| `routes/mod.rs` tests | `set_candidates_populates_state`, `commit_updates_current_and_idempotent`, etc. | PASS (with pre-existing failures noted) |
| `snapshot/mod.rs` tests | `score_lower_for_better_rtt`, `health_bad_under_high_loss`, etc. | PASS |

Pre-existing test failures (control-plane only, no datapath impact):
- `autopilot::policy` tests (3)
- `autopilot::tests::stability_recorded_from_metrics` (1)
- `net_probe::tests::tcp_probe_unreachable_returns_lost` (1)
- `routes::tests::cooldown_blocks_recommended_switch` (1)
- `routes::tests::health_of_delegates_to_snapshot` (1)
- `snapshot::tests` (3)

---

## 2. Required Ownership Changes

### 2.1 New Modules

| File | Purpose |
|---|---|
| `src-tauri/src/path_manager.rs` | `Path` struct + `PathManager` — adapter lifecycle + path state |
| `src-tauri/src/windows_route_manager.rs` | `WindowsRouteManager` — FFI to Windows route table APIs |

### 2.2 Modified Modules

| File | Change |
|---|---|
| `src-tauri/src/wireguard.rs` | Add `fn_get_luid` + `fn_open` function pointers; add `get_adapter_luid()` + `open_adapter()` methods |
| `src-tauri/src/main.rs` | Replace `tunnel: Arc<Mutex<Option<WireGuardTunnel>>>` with `paths: Arc<PathManager>` in `AppState`; modify `connect()`/`disconnect()` |
| `src-tauri/src/routes/mod.rs` | Add `paths: Option<Arc<PathManager>>` to `RouteManager`; modify `commit()` to delegate to `PathManager::activate_path()` |
| `src-tauri/src/profiles.rs` | Add `wg_config_paths: Vec<String>` and `managed_destination: Option<ManagedDestination>` |
| `src-tauri/src/utils.rs` | Revive `create_forward_row()` with `NET_LUID` support; add `create_forward_row_v2_luid()` |

---

## 3. Windows APIs

### 3.1 Available (in `Win32_NetworkManagement_IpHelper`)

```rust
use windows::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2,
    DeleteIpForwardEntry2,
    GetIpForwardTable2,
    GetAdaptersAddresses,
    InitializeIpForwardEntry,
    MIB_IPFORWARD_ROW2,
    MIB_IPPROTO_NETMGMT,  // = 170 (0xAA)
    GAA_FLAG_INCLUDE_PREFIX,
};
```

### 3.2 To Load from WireGuard-NT DLL

| Function | DLL | Current code? |
|---|---|---|
| `WireGuardCreateAdapter` | `wireguard.dll` | ✅ (`fn_create`) |
| `WireGuardOpenAdapter` | `wireguard.dll` | ❌ (add `fn_open`) |
| `WireGuardCloseAdapter` | `wireguard.dll` | ✅ (`fn_close`) |
| `WireGuardSetConfiguration` | `wireguard.dll` | ✅ (`fn_set_cfg`) |
| `WireGuardGetConfiguration` | `wireguard.dll` | ✅ (`fn_get_cfg`) |
| `WireGuardGetAdapterLUID` | `wireguard.dll` | ❌ (add `fn_get_luid`) |
| `WireGuardSetAdapterState` | `wireguard.dll` | ✅ (`fn_set_state`) |
| `WireGuardGetAdapterState` | `wireguard.dll` | ✅ (`fn_get_state`) |
| `WireGuardGetRunningDriverVersion` | `wireguard.dll` | ✅ (`fn_get_drv_ver`) |

### 3.3 Route Entry Identification

`MIB_IPFORWARD_ROW2` fields used for ownership:

| Field | Purpose |
|---|---|
| `InterfaceLuid` | Tie route to specific WireGuard adapter |
| `DestinationPrefix.PrefixLength` | Prefix length (e.g. 32 for /32) |
| `DestinationPrefix.Prefix.Ipv4` | Destination IP |
| `Protocol` | `MIB_IPPROTO_NETMGMT` (170) — ownership tag |
| `Metric` | Active=10, Standby=20 |

---

## 4. Lock Strategy

### 4.1 Lock Hierarchy (outer → inner)

```
spawn_blocking closure (per-operation)
    └─ PathManager.inner (parking_lot::Mutex<HashMap<PathId, Path>>)
        └─ Path.tunnel (within Path, accessed under PathManager lock)
            └─ Path.active (AtomicBool — lock-free)
                └─ Path.tunnel_state (Mutex<TunnelStatus>)
        └─ WindowsRouteManager.inner (parking_lot::Mutex<Vec<ManagedRoute>>)
```

### 4.2 Blocking Calls

All WireGuard-NT FFI calls and Windows route APIs are **blocking**. They execute via `tokio::task::spawn_blocking` to avoid blocking the async runtime. No async mutex is held across blocking calls.

### 4.3 No Deadlock Risk

- `PathManager.inner` is a `parking_lot::Mutex` (not tokio) — held only for brief in-memory operations
- `WindowsRouteManager` operations are independent (no nested PathManager lock)
- `RouteManager` → `PathManager` call is one-directional (no back-reference)

---

## 5. Route Lifecycle

```
INSTALL:
  1. Build MIB_IPFORWARD_ROW2 (destination, /32, InterfaceLuid, NextHop=0.0.0.0, Metric)
  2. CreateIpForwardEntry2(AF_INET, &row)
  3. Track in WindowsRouteManager.owned_routes

REMOVE:
  1. Lookup matching route in owned_routes (by dest + LUID + proto)
  2. DeleteIpForwardEntry2(&row)
  3. Remove from owned_routes

SWITCH (A→B):
  1. Install B route with preferred metric (10)  [if not exists, or update metric]
  2. Verify B route exists via GetIpForwardTable2
  3. Set A route to standby metric (20) [or remove A route]
  4. Mark B active

RECONCILE:
  1. GetIpForwardTable2 → find all routes
  2. Filter Protocol == MIB_IPPROTO_NETMGMT → owned
  3. Cross-reference with owned_routes registry
  4. Remove orphaned owned routes
```

---

## 6. Adapter Lifecycle

```
CONNECT_PATH:
  1. WireGuardTunnel::new(profile_config)
  2. fn_create(adapter_name, "MARSTART LINK", guid)
  3. fn_set_cfg(handle, config_blob, size)
  4. fn_set_state(handle, UP)
  5. fn_get_luid(handle, &LUID)  ← NEW
  6. Store in Path { tunnel, interface_luid, ... }
  7. Cache InterfaceIndex via GetAdaptersAddresses

DISCONNECT_PATH:
  1. fn_set_state(handle, DOWN)
  2. fn_close(handle)
  3. Remove from PathManager
  4. Remove owned routes via WindowsRouteManager

CRASH RECOVERY:
  1. GetAdaptersAddresses → find MARSTART-* interfaces
  2. WireGuardOpenAdapter(name) → reopen handle
  3. Re-fetch LUID
  4. Re-install routes from registry
```

---

## 7. Next-Hop Semantics

**Decision: `NextHop = 0.0.0.0` (on-link).**

For a WireGuard virtual interface, the Windows routing table entry should be:

```
Destination: 203.0.113.10/32
InterfaceLuid: <WireGuard adapter LUID>
NextHop: 0.0.0.0
Metric: 10
Protocol: MIB_IPPROTO_NETMGMT
```

**Rationale:**
- `NextHop = 0.0.0.0` tells Windows "this destination is directly reachable on this interface" (on-link).
- The WireGuard driver handles encapsulation: packets sent to the WireGuard interface are encrypted and sent to the configured peer endpoint via UDP.
- No gateway IP is needed — the WireGuard adapter itself provides the L3 path.
- This is the same semantics used by WireGuard for Windows official client.

**Verification:** Confirmed via WireGuard-NT README (lines 28–56) — the adapter is an NDIS miniport; `WireGuardSetAdapterState(UP)` opens UDP sockets and begins handshake. Packets routed to the interface are processed by the WireGuard driver's `SendNetBufferLists` handler.

---

## 8. ManagedDestination

For Phase 1, the destination prefix is supplied explicitly via profile configuration:

```rust
pub struct ManagedDestination {
    pub address: Ipv4Addr,   // e.g. 203.0.113.10
    pub prefix_length: u8,   // e.g. 32 (host route)
}
```

Default (test mode): `203.0.113.10/32` (RFC 5737 TEST-NET-3).

---

## 9. Path ID Scheme

Deterministic, stable, user-controllable:

```
Path IDs derived from Profile.wg_config_paths index:
  wg_config_paths[0] → "path-a"
  wg_config_paths[1] → "path-b"
  wg_config_paths[2] → "path-c"  (future expansion)
```

If `wg_config_paths` is empty but `wg_config_paths` single `wg_config_path` exists, ID = "path-a".

The `EndpointSpec.id` from `Profile.endpoints` may override the default path ID if it matches the config index.

---

## 10. Backward Compatibility

| Component | Old behavior | New behavior | Compatible? |
|---|---|---|---|
| `connect()` | Single tunnel | Multi-path, but works with single config | ✅ If `wg_config_paths` has 1 entry, single path |
| `disconnect()` | Tears down single tunnel | Tears down all paths | ✅ |
| `get_status()` | Single tunnel status | Active path status | ✅ |
| `RouteManager::commit()` | In-memory only | In-memory + PathManager delegation | ✅ If no PathManager set, falls back to in-memory only |
| `Profile` | `endpoints`, `wg_config_path` | Adds `wg_config_paths`, `managed_destination` | ✅ `#[serde(default)]` |
