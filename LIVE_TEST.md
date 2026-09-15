# MARSTART LINK — LIVE TEST PROTOCOL

## Overview

This document defines two distinct test procedures:
- **STATIC/LOCAL TEST** — runs without admin rights, validates code correctness
- **LIVE WINDOWS TEST** — runs on real Windows 10/11 x64 with Administrator rights

---

## STATIC / LOCAL TEST

### Prerequisites
- Any Windows or Linux machine
- Rust 1.96.0+ toolchain
- No admin rights required

### Commands

```powershell
cd src-tauri

# 1. Format check
cargo fmt --all -- --check

# 2. Lint
cargo clippy --all-targets --all-features --locked -- -D warnings

# 3. Compile check (release)
cargo check --release --locked

# 4. WireGuard tests
cargo test --all-features --locked wireguard -- --test-threads=1 --nocapture
```

### Expected Results

| Check | Expected |
|-------|----------|
| `cargo fmt` | PASS (exit 0) |
| `cargo clippy -D warnings` | PASS (0 warnings) |
| `cargo check --release` | PASS (exit 0) |
| WireGuard tests | **15/15 PASS** |

### Test Output Verification (Local, Non-Elevated)

```
[driver_status] dll_loaded      = true
[driver_status] driver_present  = false
[driver_status] driver_version  = 0
[driver_status] is_admin        = false
[driver_status] error_code      = 2
[driver_status] human_readable  = "WireGuard-NT kernel driver (wireguard.sys) is not loaded..."

[diag_test] dll_loaded           = true
[diag_test] driver_present       = false
[diag_test] adapter_created      = false
[diag_test] no_orphan_adapter    = true
[diag_test] errors = ["connect: failed to create WireGuard adapter: ... GetLastError: 5"]
```

**This is EXPECTED** — without admin rights, `WireGuardCreateAdapter()` returns NULL
with `ERROR_ACCESS_DENIED` (code 5). The diagnostics correctly report this and
ensure no orphaned adapter remains.

---

## LIVE WINDOWS TEST

### Prerequisites

| Requirement | Details |
|-------------|---------|
| Platform | Windows 10/11 x64 |
| Privileges | Administrator rights |
| UAC | Enabled (default settings) |
| Network | Internet access |
| Test server | Disposable WireGuard peer (real or test VPN endpoint) |

### Test Profile (Injected at Runtime)

The test profile is injected via the `tunnel_diagnostics` Tauri command with
an `Option<Profile>` parameter. A temporary config file is created with
**dummy non-production keys** (runtime-generated from non-secret byte arrays).

**DO NOT commit real WireGuard keys to the repository.**

#### Test config template:
```ini
[Interface]
PrivateKey = <base64-encoded-dummy-key>
Address = 10.99.42.1/24
DNS = 1.1.1.1

[Peer]
PublicKey = <base64-encoded-real-server-key>
Endpoint = <real-test-server>:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

### LIVE TEST STEPS

#### Step 1: Manifest Verification

```powershell
# Verify the release binary has requireAdministrator
$mt = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\mt.exe"
& $mt -inputresource:"marstart-link.exe;#1" -out:verify.xml -nologo
# Expected: <requestedExecutionLevel level="requireAdministrator" uiAccess="false">
```

#### Step 2: UAC Prompt Verification

```powershell
# Launch from non-elevated shell
.\marstart-link.exe
# Expected: UAC prompt appears automatically
# After clicking "Yes": app runs elevated
```

#### Step 3: Driver Status (Pre-Connect)

Call `wireguard_driver_status` Tauri command:

**Before elevation**:
| Field | Expected |
|-------|----------|
| `dll_loaded` | `true` |
| `driver_present` | `false` |
| `driver_version` | `0` |
| `is_admin` | `false` |
| `error_code` | `2` (ERROR_FILE_NOT_FOUND) |

**After elevation, before driver install**:
| Field | Expected |
|-------|----------|
| `dll_loaded` | `true` |
| `driver_present` | `false` |
| `driver_version` | `0` |
| `is_admin` | `true` |
| `error_code` | `2` |

#### Step 4: Driver Installation (First Connect)

```powershell
# Call connect() Tauri command
# Internally: WireGuardCreateAdapter() → DriverInstall() → SetupCopyOEMInfW()
```

**Expected proof points after successful connect**:

| # | Proof Point | Method | Pass Condition |
|---|-------------|--------|----------------|
| 1 | `dll_loaded` | `wireguard_driver_status()` | `true` |
| 2 | `driver_present` | `wireguard_driver_status()` | `true` |
| 3 | `driver_version` | `wireguard_driver_status()` | `> 0` (e.g., `0x01010000` = 1.1.0.0) |
| 4 | `is_admin` | `wireguard_driver_status()` | `true` |
| 5 | `adapter_created` | `DiagnosticsReport` | `true` |
| 6 | `config_applied` | `DiagnosticsReport` | `true` |
| 7 | `adapter_state` | `DiagnosticsReport` / `get_adapter_state()` | `Up` |
| 8 | `handshake_timestamp_unix` | `DiagnosticsReport` | `> 0` (Unix seconds) |
| 9 | `tx_bytes` | `DiagnosticsReport` | `> 0` |
| 10 | `rx_bytes` | `DiagnosticsReport` | `> 0` |
| 11 | `adapter_state` (after disconnect) | `DiagnosticsReport` | `Down` or `Unknown` |
| 12 | `adapter_closed` | `DiagnosticsReport` | `true` |
| 13 | `no_orphan_adapter` | `DiagnosticsReport` | `true` |

#### Step 5: Traffic Generation

After connect succeeds and handshake is established:

```powershell
# Generate traffic through the tunnel
# Option A: Ping the peer's WireGuard IP
ping 10.99.42.2

# Option B: HTTP request through the tunnel
curl http://10.99.42.2:8080/

# Option C: iperf3 through the tunnel
iperf3 -c 10.99.42.2 -t 10
```

Then call `get_connection_info()` Tauri command:
- `tx_bytes` must be > 0
- `rx_bytes` must be > 0
- `handshake_timestamp_unix` must be > 0 (non-zero = handshake completed)

#### Step 6: Idempotency Check (Re-Connect)

```powershell
# 1. Disconnect tunnel
invoke('disconnect')
# 2. Reconnect
invoke('connect', { profile_id: "test" })
# 3. Verify driver is still loaded (no re-install)
invoke('wireguard_driver_status')
# Expected: driver_version = same as before (0x01010000)
```

#### Step 7: Teardown & Cleanup

```powershell
# 1. Disconnect tunnel
invoke('disconnect')
# 2. Verify no orphan adapter
invoke('tunnel_diagnostics', { profile_id: "test" })
# Expected: no_orphan_adapter = true, adapter_closed = true
# 3. Optional: delete driver (for clean uninstall)
invoke('wireguard_delete_driver')
# Expected: Ok(()) — driver removed via SetupUninstallOEMInfW
# 4. Verify driver is gone
invoke('wireguard_driver_status')
# Expected: driver_present = false, driver_version = 0
```

### LIVE TEST PASS/FAIL CRITERIA

```
PASS — All 13 proof points above are satisfied:
  1. dll_loaded = true
  2. driver_present = true
  3. driver_version > 0 (e.g., 0x01010000 = 1.1.0.0)
  4. is_admin = true
  5. adapter_created = true
  6. config_applied = true
  7. adapter_state = UP
  8. handshake_timestamp_unix > 0
  9. tx_bytes > 0
  10. rx_bytes > 0
  11. adapter_state = DOWN (after disconnect)
  12. adapter_closed = true
  13. no_orphan_adapter = true

FAIL — Any proof point is not satisfied.
```

### Test Server Requirements

For a valid WireGuard handshake, you need a real WireGuard peer (server)
with:
1. A valid public key
2. A listening UDP port
3. An allowed IP range that includes the client's tunnel IP
4. Valid `AllowedIPs` configuration

**Do NOT attempt to establish a handshake with two dummy keys** — this will
never produce `handshake_timestamp_unix > 0` because there is no real peer
to respond to the handshake.

### Disposable Test Server Setup

```bash
# On a disposable VM/instance:
apt-get install wireguard
wg genkey | tee server_private.key | wg pubkey > server_public.key
# Configure /etc/wireguard/wg0.conf:
cat > /etc/wireguard/wg0.conf << 'EOF'
[Interface]
PrivateKey = <contents of server_private.key>
Address = 10.99.42.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = <client_public_key_here>
AllowedIPs = 10.99.42.2/32
EOF
wg-quick up wg0
```

The client profile's `Endpoint` = `<server-ip>:51820`
The client profile's `PublicKey` = contents of `server_public.key`
The client profile's `AllowedIPs` = `0.0.0.0/0`
