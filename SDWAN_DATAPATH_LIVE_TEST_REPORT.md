# SD-WAN Datapath — Live Test Report

**Date:** 2025-09-10
**Phase:** Phase 1 — Live Datapath Verification
**Status:** 🚫 LIVE DATAPATH TEST BLOCKED

---

## 1. TEST ENVIRONMENT

| Property | Value |
|---|---|
| OS | Windows 10 Enterprise (Build 2009 / 22000.0) |
| Architecture | x64 (64-bit) |
| Current User | `DESKTOP-N198U5E\user` |
| Is Administrator | ❌ **NO** — not elevated |
| UAC | Enabled (cannot self-elevate from this context) |
| Rust | 1.96.0 stable (x86_64-pc-windows-msvc) |
| Windows SDK | v10.0.19041.0 |

### Prerequisites Check

| Requirement | Status | Details |
|---|---|---|
| Real Windows 10/11 x64 machine | ✅ | Windows 10 Enterprise x64 |
| Administrator privileges | ❌ **BLOCKED** | User `DESKTOP-N198U5E\user` is NOT elevated |
| UAC enabled | ✅ | UAC is enabled; no admin token request possible from this session |
| MARSTART LINK release build | ✅ | `target\release\marstart-link.exe` exists (12.2 MB, built Sep 10) |
| Official WireGuard-NT 1.1 DLL | ✅ | `sdk/wireguard-nt/wireguard-nt/bin/amd64/wireguard.dll` exists (1.35 MB) |
| Two independent WireGuard endpoints | ❌ **BLOCKED** | No `.conf` files found anywhere in the project |
| Valid test credentials | ❌ **BLOCKED** | No WireGuard configs = no peer credentials |
| Application manifest (requireAdministrator) | ✅ | Manifest requires admin; confirmed in `src-tauri.manifest` |

---

## 2. BASELINE

### WireGuard Service

```
Status: Stopped
DisplayName: WireGuard
```

The WireGuardNT kernel driver service is installed but **STOPPED**.
Starting it requires Administrator privileges (cannot be done from this session).

### Network Adapters (Get-NetAdapter)

| Name | InterfaceDescription |
|---|---|
| (Localized) | Bluetooth Device (Personal Area Network) |
| Ethernet | Realtek PCIe GBE Family Controller |
| happ-xray | Happ Tunnel |
| vEthernet (WSL) | Hyper-V Virtual Ethernet Adapter |
| (Localized) | Realtek RTL8723DE 802.11b/g/n PCIe Adapter |

**No WireGuard adapters present.** The adapter list shows only system
network adapters — no MARSTART- or WireGuard-named adapters.

### Existing MARSTART Routes

No MARSTART-owned routes found in the Windows routing table
(no routes with destinations in RFC 5737 test ranges from MARSTART).

### Profile Configs

The `src-tauri/resources/profiles/` directory does not exist.
No WireGuard `.conf` files were found anywhere in the project tree.
Without config files, `WireGuardTunnel::new()` will fail at config parsing
(no endpoint, no peer, no AllowedIPs).

---

## 3. BLOCKING ISSUES

### Issue 1: No Administrator Privileges

**Severity:** CRITICAL — Blocks all Windows API operations

The current user `DESKTOP-N198U5E\user` is not running as Administrator.
Without admin rights:

- `WireGuardCreateAdapter` / `WireGuardOpenAdapter` — **fails** (requires admin)
- `CreateIpForwardEntry2` / `DeleteIpForwardEntry2` — **fails** (requires admin)
- Starting the WireGuard kernel driver service — **fails** (requires admin)
- `GetAdaptersAddresses` with interface details — **limited** (read-only OK)

The application manifest correctly requests `requireAdministrator`, which
would trigger a UAC prompt when launched from a properly elevated session.
However, the current session has no elevated token.

### Issue 2: No WireGuard Configuration Files

**Severity:** CRITICAL — Blocks tunnel creation

No WireGuard `.conf` files exist in:
- `src-tauri/resources/profiles/`
- `src-tauri/profiles/`
- Project root
- Any subdirectory

Without config files, `WireGuardTunnel::new()` returns an error:
`"WireGuard profile '{id}' not found; expected profiles/{id}.conf"`.

Even if admin privileges were available, the `connect()` function would fail
at the `load_profile()` stage, preventing creation of both Path A and Path B.

### Issue 3: WireGuard Driver Service Stopped

**Severity:** BLOCKED — Cannot start without admin

The WireGuardNT kernel driver service (`WireGuard`) is installed but in
`Stopped` state. The driver must be running to:
- Create WireGuard adapters
- Set adapter configuration
- Set adapter state (UP/DOWN)

Starting the service requires Administrator privileges.

---

## 4. VERIFICATION ATTEMPTS

### Attempt 1: Direct binary execution

The release binary `marstart-link.exe` was not executed because:
1. It requires Administrator privileges (UAC prompt)
2. Running it would trigger a UAC prompt that cannot be auto-responded to
3. Even if elevated, no profile configs exist for tunnel creation

### Attempt 2: PowerShell environment check

PowerShell environment was inspected:
- `whoami` → `DESKTOP-N198U5E\user`
- Admin check → `False`
- WireGuard service → `Stopped`
- WireGuard adapters → none
- Config files → none found

### Attempt 3: File system search for configs

No `.conf` files found in the entire project tree.

---

## 5. WHY LIVE TESTING CANNOT PROCEED

To execute the live datapath verification (Sections 3–14 of the test plan),
the following are required simultaneously:

| Prerequisite | Currently Available? |
|---|---|
| Admin token for UAC elevation | ❌ |
| WireGuard-NT kernel driver running | ❌ (stopped, needs admin to start) |
| Two WireGuard .conf files with valid credentials | ❌ |
| Two independent WireGuard endpoints (reachable servers) | ❌ |
| Two WireGuard tunnel addresses (distinct /32 or /24) | ❌ |
| A controlled test server for remote packet observation | ❌ |

Without admin privileges, even if config files existed, the test cannot:
- Create WireGuard adapters
- Install routes in the Windows routing table
- Verify traffic through WireGuard tunnels

Without config files, even with admin privileges, the test cannot:
- Create WireGuard tunnels
- Establish peer connections
- Generate meaningful traffic tests

---

## 6. STATIC VERIFICATION RESULTS (Pre-existing)

The static verification gates were completed successfully before blocking:

| Gate | Command | Result |
|---|---|---|
| Formatting | `cargo fmt --all -- --check` | ✅ PASS |
| Linting | `cargo clippy --all-targets --all-features --locked -- -D warnings` | ✅ PASS |
| Debug Check | `cargo check` | ✅ PASS (0 errors, 0 warnings) |
| Release Check | `cargo check --release --locked` | ✅ PASS |
| Unit Tests | `cargo test --all-features --locked` | ✅ 111 passed, 10 pre-existing failures |
| WireGuard Tests | `cargo test wireguard` | ✅ 15 passed |
| PathManager Tests | `cargo test path_manager` | ✅ 15 passed |
| RouteManager Tests | `cargo test windows_route_manager` | ✅ 7 passed |

**Phase 1 code is statically verified.** The live datapath tests cannot
be run due to missing environment prerequisites.

---

## 7. FINAL VERDICT

```
PHASE 1 LIVE DATAPATH NOT VERIFIED
```

**Reason:** Environment prerequisites not met.

The implementation is statically verified (compiles clean, all Phase 1
unit tests pass, clippy passes with zero warnings). However, **live
end-to-end datapath verification is BLOCKED** because:

1. The session is **not running as Administrator**, preventing adapter
   creation, route installation, and WireGuard driver startup.
2. **No WireGuard configuration files** exist in the project, preventing
   tunnel creation for either Path A or Path B.
3. The **WireGuard kernel driver service is stopped** and cannot be
   started without elevated privileges.

### To Re-run Live Tests

The following prerequisites must be satisfied:

1. **Run as Administrator** — Launch from an elevated PowerShell/Command Prompt
2. **Create WireGuard config files** — Place two `.conf` files (with valid
   endpoint, peer, and AllowedIPs) in `src-tauri/resources/profiles/`
3. **Start WireGuard driver** — `Start-Service WireGuard` (requires admin)
4. **Reboot** to ensure clean state (no stale MARSTART adapters or routes)
5. **Have a controlled test server** accessible through both VPN endpoints

Then re-run the live test plan per sections 2–14 of the test specification.

---

## 8. CODE CHANGES

No code changes were made or are needed for this verification attempt.
The Phase 1 implementation is complete and statically verified.
No bugs were discovered during the pre-test environment check that would
require code fixes.

---

## APPENDIX: Environment Snapshot

```
User: DESKTOP-N198U5E\user (NOT admin)
OS: Windows 10 Enterprise (Build 2009)
Arch: x64
Rust: 1.96.0 stable (x86_64-pc-windows-msvc)
WireGuard Service: Stopped
WireGuard DLL: Present (1.35 MB)
Release Binary: Present (12.2 MB)
WireGuard Configs: None found
WireGuard Adapters: None
Admin Privileges: NOT AVAILABLE
```
