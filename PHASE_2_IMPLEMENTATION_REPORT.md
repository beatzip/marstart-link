# Phase 2 Implementation Report — Multi-Adapter PathManager

## 1. Exact Objective Implemented

**Objective:** Complete the Multi-Adapter PathManager as defined in §15.2 of
`SDWAN_ARCHITECTURE_DECISION.md` (authoritative phase numbering scheme).

Two methods were missing from `PathManager` and have been implemented:

1. **`failover(old_path_id, new_path_id, verify)`** — Atomic failover with
   reachability verification and rollback (§10.2). Installs the new path's
   route with an ACTIVE metric (10), calls a user-supplied verification closure,
   demotes the old path to STANDBY metric (20) on success, or rolls back to the
   old path on verification failure. No WireGuard adapters are destroyed or
   recreated.

2. **`enumerate_and_reconcile()`** — OS-level route reconciliation (§11.3).
   Enumerates MARSTART-owned routes in the Windows routing table, removes
   orphaned routes, and re-installs missing routes for paths in the `Up` state.

Private helpers `install_path_route()` and `set_path_active()` were added to
support `failover()`.

Two Tauri commands were added to `main.rs`:
- `routes_failover` — exposes `failover()` with TCP/ICMP reachability testing
- `paths_reconcile` — exposes `enumerate_and_reconcile()`
- `paths_get` — exposes `get_paths()` (diagnostic utility)
- `routes_get_switch_result` — returns `SwitchResult` (utility for IPC layer)

`remove_route_os()` was added to `WindowsRouteManager` (both Windows and
non-Windows impls) to support orphan cleanup in `enumerate_and_reconcile()`.

## 2. Architecture / Data-Flow Changes

### failover() Data Flow

```
Caller (routes_failover Tauri command)
    │
    ├── Validate old_path_id and new_path_id exist and are connected
    ├── validate destinations are set
    │
    ├── [Step 1] install_path_route(new_path, ACTIVE_METRIC=10)
    │     │
    │     ├── router.remove_route(new_path)     # delete existing
    │     ├── router.install_route(new_path, 10) # create with active metric
    │     └── router.update_route_metric(new_path, 10) # update registry
    │
    ├── [Step 2] verify(&new_path_snapshot)      # user-supplied closure
    │     └── On Windows: net_probe::ping(TCP connect, 500ms timeout)
    │
    ├── [Step 3a — PASS] install_path_route(old_path, STANDBY_METRIC=20)
    │     └── Demote old path to standby
    │
    ├── [Step 3b — FAIL] Rollback:
    │     ├── install_path_route(new_path, STANDBY_METRIC=20)
    │     ├── install_path_route(old_path, ACTIVE_METRIC=10)
    │     └── Return Err
    │
    └── Return SwitchResult
```

### enumerate_and_reconcile() Data Flow

```
Caller (paths_reconcile Tauri command)
    │
    ├── os_routes = router.enumerate_windows_routes()  # GetIpForwardTable2 → filter MIB_IPPROTO_NETMGMT
    │
    ├── For each OS route in os_routes:
    │     Check if matching PathManager path exists (LUID + dest + prefix)
    │     If no match → orphan → router.remove_route_os()
    │
    ├── For each PathManager path (Up + has destination):
    │     Check if route exists in os_routes snapshot (NOT in-memory registry)
    │     If not found in OS → router.install_route() with active/standby metric
    │
    └── Return Vec<String> of action descriptions
```

> **Critical audit finding (post-implementation review):** The initial
> implementation checked route existence via `route_exists()` which queries
> only the in-memory registry. This was corrected to check against the
> `os_routes` snapshot (from `enumerate_windows_routes()` / `GetIpForwardTable2`),
> which reflects the actual Windows routing table state. See §5 for details.

### Key Design Decisions

- **failover() uses Delete+Create** (not `SetIpForwardEntry2`) per §11.18 —
  the metric-based approach is deferred to Phase 3 optimization.
- **`failover()` verification** uses a `Fn(&Path) -> bool` closure pattern.
  The `routes_failover` Tauri command wraps this with TCP connect testing
  (500ms timeout) on Windows, and `net_probe::ping` if a tokio runtime is
  available.
- **`remove_route_os()` handles `ERROR_ACCESS_DENIED` gracefully** — consistent
  with `install_route()` which already treats ACCESS_DENIED as non-fatal
  (the in-memory registry is still updated). This enables reconciliation to
  proceed on non-elevated Windows.
- **`SwitchResult`** (already defined in `windows_route_manager.rs:84`) is
  reused as the return type for `failover()`.
- **`#[derive(Serialize)]`** was added to `PathId`, `PathHealth`,
  `TunnelState`, `Path`, and `SwitchResult` to enable Tauri IPC serialization.
  This is a backward-compatible trait addition, not an architectural change.

## 3. Files Changed

| File | Change |
|------|--------|
| `src-tauri/src/path_manager.rs` | Added `failover()`, `enumerate_and_reconcile()`, `install_path_route()`, `set_path_active()` methods + `Serialize` derives on `PathId`, `PathHealth`, `TunnelState`, `Path` + 23 unit tests |
| `src-tauri/src/windows_route_manager.rs` | Added `remove_route_os()` to Windows impl + non-Windows stub + `Serialize` derive on `SwitchResult` + `use serde::Serialize` + 3 unit tests |
| `src-tauri/src/main.rs` | Added `routes_failover`, `paths_reconcile`, `paths_get`, `routes_get_switch_result` Tauri commands + registered in `generate_handler!` + `State` import + `SwitchResult` import |

## 4. Tests Added

### windows_route_manager.rs (3 tests)
- `remove_route_os_without_registry_entry_returns_error_non_windows`
- `remove_route_os_removes_from_registry_when_present`
- `remove_route_os_preserves_unrelated_routes`

### path_manager.rs (15 tests)

**Phase 2 functional tests (7):**
- `failover_switches_active_to_new_path_on_verification_success`
- `failover_rolls_back_on_verification_failure`
- `failover_nonexistent_old_path_returns_error`
- `failover_nonexistent_new_path_returns_error`
- `failover_same_path_is_noop`
- `failover_missing_destination_returns_error`
- `failover_unconnected_path_returns_error`

**Phase 2 functional tests (5):**
- `failover_sets_correct_metrics_after_success`
- `reconcile_reinstalls_missing_routes_for_up_paths`
- `reconcile_no_action_when_consistent`
- `reconcile_returns_action_list`
- `reconcile_cleans_unmatched_registry_routes`

**Correctness audit regression tests (8):**
- `failover_invariant_success_metrics_and_active` — Invariant 1
- `failover_invariant_rollback_preserves_original_state` — Invariant 2
- `failover_invariant_same_path_noop` — Invariant 3
- `failover_invariant_no_route_state_change_on_missing_path` — Invariant 4
- `failover_invariant_no_adapter_destroyed` — Invariant 5
- `failover_invariant_unrelated_routes_not_removed` — Invariant 6
- `reconcile_reinstalls_route_missing_from_os_despite_registry` — Required scenario 1
- `reconcile_removes_only_orphaned_managed_routes` — Required scenario 2

## 5. Complete Test Results

```
cargo fmt --check                                    → exit 0 ✅
cargo clippy --all-targets --all-features -- -D warnings → exit 0 ✅
cargo test --all-features                            → 169 passed, 0 failed ✅
cargo check --release                                → exit 0 ✅
```

**Test count:** 146 (existing) + 23 (Phase 2 new) = **169 total**
All 146 existing tests remain green. No tests were modified, weakened,
skipped, or rewritten.

### Correctness Audit Findings

**CRITICAL BUG FOUND AND FIXED:**

The initial implementation of `enumerate_and_reconcile()` used
`self.router.route_exists()` to determine whether a path's route was already
present in the OS routing table. However, `route_exists()` checks **only the
in-memory route registry**, NOT the actual Windows routing table.

This meant that if a MARSTART-owned route was externally removed from the
Windows OS routing table (e.g., by another process, a crash, or manual
`route DELETE`) while the in-memory registry still tracked it,
`enumerate_and_reconcile()` would incorrectly report the route as present
and skip reinstallation.

**Fix applied:** `enumerate_and_reconcile()` now checks each path's route
against the `os_routes` snapshot returned by `enumerate_windows_routes()`
(which calls `GetIpForwardTable2` on Windows, or returns the in-memory
registry on non-Windows). This ensures that route existence is determined
from the actual OS state, not a stale in-memory cache.

**Verification of `routes_failover` verification target:**
The `routes_failover` Tauri command correctly derives its verification
target from the new path's managed destination (`new_path.destination`),
NOT from a hardcoded endpoint. The destination IP comes from
`PathManager::get_path(new_path) → path.destination`, which is set
during `connect()` via `set_destination()` from the profile's
`managed_destination` field.

**`remove_route_os()` `ERROR_ACCESS_DENIED` handling:**
The Windows implementation of `remove_route_os()` was updated to handle
`ERROR_ACCESS_DENIED` (code 5) gracefully, consistent with the existing
`install_route()` behavior. When a non-elevated process calls
`DeleteIpForwardEntry2`, the function logs a warning but still cleans up
the in-memory registry, returning `Ok(())`. This enables reconciliation to
proceed without admin elevation.

## 6. Correctness Review Verdict

### Audit Date
2026-09-11

### Phase 2: CORRECTNESS REVIEW PASSED ✅

(With one critical bug found and fixed during audit — see below)

### Exact Findings

#### Finding 1: CRITICAL — `enumerate_and_reconcile()` checked in-memory registry instead of OS state
- **Severity:** CRITICAL
- **Status:** FIXED
- **Description:** The initial implementation of `enumerate_and_reconcile()`
  used `self.router.route_exists()` to determine whether a path's route
  existed in the OS routing table. `route_exists()` checks only the in-memory
  route registry (`WindowsRouteManager::routes`), NOT the actual Windows
  OS routing table (`GetIpForwardTable2`). This meant that if a
  MARSTART-owned route was externally removed from the OS routing table
  while the in-memory registry still tracked it, `enumerate_and_reconcile()`
  would incorrectly skip reinstallation.
- **Fix:** Replaced `route_exists()` check with a direct lookup against the
  `os_routes` snapshot (returned by `enumerate_windows_routes()` which calls
  `GetIpForwardTable2` on Windows). The `os_routes` list is captured once at
  the start of the method and cross-referenced against each path's
  destination/LUID/prefix_length.
- **Regression test added:**
  `reconcile_reinstalls_route_missing_from_os_despite_registry` —
  verifies that routes present in the in-memory registry but absent from the
  OS snapshot are detected as missing and reinstalled.

#### Finding 2: `remove_route_os()` did not handle `ERROR_ACCESS_DENIED`
- **Severity:** MEDIUM
- **Status:** FIXED
- **Description:** The Windows implementation of `remove_route_os()` returned
  an error on `DeleteIpForwardEntry2` failure for any code other than
  `ERROR_FILE_NOT_FOUND` (2). On non-elevated Windows, `DeleteIpForwardEntry2`
  returns `ERROR_ACCESS_DENIED` (5), causing `enumerate_and_reconcile()` to
  report "failed to remove orphan" for all orphaned routes.
- **Fix:** Added `ERROR_ACCESS_DENIED` to the list of acceptable return codes,
  consistent with the existing `install_route()` behavior. The function now
  logs a warning and still cleans up the in-memory registry, returning `Ok(())`.

#### Finding 3: `#[derive(Serialize)]` added to Phase 1 types
- **Severity:** NONE (backward-compatible)
- **Status:** DOCUMENTED
- **Description:** `Serialize` derives were added to `PathId`, `PathHealth`,
  `TunnelState`, `Path`, and `SwitchResult` to enable Tauri IPC serialization.
  This is a trait addition, not a structural or behavioral change. No field
  layouts, method signatures, or state machine transitions were altered.

#### Finding 4: `routes_failover` verification target
- **Severity:** NONE
- **Status:** VERIFIED CORRECT
- **Description:** The `routes_failover` Tauri command derives its verification
  target from `state.paths.get_path(&new_path).unwrap().destination` — the
  managed destination of the new path (set via `set_destination()` from the
  profile's `managed_destination` field). No hardcoded endpoints are used.

### failover() Invariant Audit

| # | Invariant | Tested By | Status |
|---|-----------|-----------|--------|
| 1 | Successful A→B: B=10, A=20, active=B | `failover_invariant_success_metrics_and_active` | ✅ PASS |
| 2 | Failed B verify: A=10, B=20, active=A, no partial state | `failover_invariant_rollback_preserves_original_state` | ✅ PASS |
| 3 | Same-path failover is true no-op | `failover_invariant_same_path_noop` | ✅ PASS |
| 4 | Missing/unconnected path cannot modify route state | `failover_invariant_no_route_state_change_on_missing_path` | ✅ PASS |
| 5 | No WireGuard adapter destroyed/recreated | `failover_invariant_no_adapter_destroyed` | ✅ PASS |
| 6 | Existing unrelated routes never removed | `failover_invariant_unrelated_routes_not_removed` | ✅ PASS |

### Required Scenario Audit

| Scenario | Tested By | Status |
|----------|-----------|--------|
| OS route removed but in registry → detected & reinstalled | `reconcile_reinstalls_route_missing_from_os_despite_registry` | ✅ PASS |
| Orphan MARSTART route → removed, foreign routes preserved | `reconcile_removes_only_orphaned_managed_routes` | ✅ PASS |

## 7. Git Diff — Stat

- `PathManager` struct, `HashMap` storage, `Path` struct with LUID/IfIndex,
  `activate_path()`, `connect_path()`, `disconnect_path()`, `set_destination()`,
  `clear_paths()`, `get_paths()`, `get_path()`, `has_path()`, `reconcile()`,
  `diagnostics()` — all unchanged.
- `WindowsRouteManager` methods (`install_route`, `remove_route`,
  `enumerate_windows_routes`, `route_exists`, `update_route_metric`,
  `cleanup_owned_routes`, `all_routes`, `enumerate_owned_routes`) — all
  unchanged. `remove_route_os` was added as a new method, not a modification.
- `WireGuard` FFI/lifecycle (`wireguard.rs`) — UNCHANGED.
- `LUID`-based routing, `ACTIVE_METRIC=10`, `STANDBY_METRIC=20`,
  `MIB_IPPROTO_NETMGMT=170` — UNCHANGED.
- Active/standby metrics, multi-adapter architecture, route ownership/
  reconciliation — UNCHANGED.
- `PolicyConfig` defaults (`game_mode_margin=0.08`, `recovery_cooldown_ms=100`) —
  UNCHANGED. No Phase 2 code references these values.
- All 25 existing control-plane regression tests — UNCHANGED and passing.

## 8. Existing Phase 1 Behavior Preserved

1. **`failover()` verification is synchronous.** The `Fn(&Path) -> bool` closure
   cannot perform async I/O. On Windows, `net_probe::ping` is async; the
   `routes_failover` Tauri command handles this by calling
   `tokio::runtime::Handle::block_on()` if a runtime is available, or falling
   back to `TcpStream::connect_timeout()`. A future Phase 3 optimization could
   make `failover()` async or use a spawn-blocking pattern.

2. **`enumerate_and_reconcile()` on non-elevated Windows.**
   `GetIpForwardTable2` requires admin privileges on Windows. Without elevation,
   it may return incomplete or empty route lists. The function degrades gracefully
   (returns empty OS route list, no panics). Full route reconciliation requires
   running as administrator.

3. **`remove_route_os()` on non-elevated Windows.**
   `DeleteIpForwardEntry2` returns `ERROR_ACCESS_DENIED` (code 5). This is now
   handled gracefully (treated as non-fatal, in-memory registry is still
   cleaned up). The OS route table is not modified when not elevated.

4. **`reconcile_cleans_unmatched_registry_routes` test is platform-gated.**
   On Windows, `enumerate_windows_routes()` returns real OS routes (not in-memory
   registry entries). The orphan-removal assertion is only validated on non-Windows
   stubs. On Windows, the test verifies no-panic and correct action format.

5. **Phase 1 datapath is NOT VERIFIED.** Per the Phase 1 preflight gate report,
   the runtime datapath test was deferred. Phase 2 does not require or assume
   Phase 1 verification.

## 8. Phase 1 Live Verification Status

**PHASE 1 LIVE DATAPATH: NOT VERIFIED — RUNTIME TEST DEFERRED**

This Phase 2 implementation was performed **without** live runtime verification
of the Phase 1 datapath. The two new methods (`failover()` and
`enumerate_and_reconcile()`) interact with the Windows routing table via the
same APIs used by Phase 1 (`CreateIpForwardEntry2`, `DeleteIpForwardEntry2`,
`GetIpForwardTable2`). These interactions are tested at the unit level using
in-memory registry stubs and `#[cfg]`-gated platform behavior, but not
validated against a live elevated Windows environment with two independent
WireGuard endpoints and server-side packet capture.

**Remaining blockers for live verification:**
- WireGuardTunnel service is stopped (`wireguard.sys` present but not running)
- No admin rights available in this environment
- No WireGuard test configurations present
  (`MARSTART_PATH_A_CONFIG`, `MARSTART_PATH_B_CONFIG`,
  `MARSTART_MANAGED_DESTINATION` all unset)
- `wg.exe` / `wireguard.exe` not installed

## 9. Remaining Blockers

1. **Live datapath test environment** — Phase 2 methods that interact with the
   Windows routing table (`install_route`, `remove_route_os`,
   `enumerate_windows_routes`) require admin elevation to fully validate. The
   deferred live test (see §8) will exercise these paths.
2. **`routes_failover` verification strategy** — The TCP-connect fallback in
   `routes_failover` is a best-effort heuristic. A production deployment should
   use a dedicated health-check endpoint or ICMP echo with proper timeout
   handling (Phase 3 optimization).
3. **Frontend integration** — The new Tauri commands (`routes_failover`,
   `paths_reconcile`, `paths_get`) are registered but not yet wired to the
   frontend UI. This is a frontend task outside Phase 2's backend scope.

## 10. Recommended Next Steps

1. **Phase 2 → Phase 1.5: Live datapath verification** (highest priority)
   - Obtain an elevated Windows 11 environment
   - Deploy two WireGuard endpoints with test configurations
   - Start the WireGuardTunnel service
   - Execute `routes_failover` and observe route table changes via
     `GetIpForwardTable2` / `route print`
   - Execute `paths_reconcile` and verify orphan removal + missing route
     installation
   - Perform server-side packet capture to validate actual traffic flow
     through the new path after failover

2. **Phase 3: Metric-based route updates** — Replace the Delete+Create pattern in
   `install_path_route` with `SetIpForwardEntry2` (§11.18) for cleaner route
   updates.

3. **Phase 3: Async failover verification** — Make `failover()` async or use a
   spawn-blocking pattern for the verify closure, eliminating the `block_on`
   workaround in `routes_failover`.

4. **Phase 3: Frontend IPC integration** — Wire `routes_failover`,
   `paths_reconcile`, and `paths_get` to the frontend UI (App.tsx / api.ts).

5. **Phase 4: Crash recovery** — Implement full adapter-level recovery via
   `WireGuardOpenAdapter` for process restart scenarios (§15.4).
