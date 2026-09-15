# LIVE TEST — Required Inputs

> **Purpose:** Defines every external input the live test operator must supply.
> No input contains secrets in this file — private keys, PSKs, and
> authentication tokens remain inside the `.conf` files on the operator's
> filesystem and are never committed to Git, logged, or captured in reports.

---

## 0. Test-Only Profile Injection Mechanism

The project includes a **test-only** mechanism that allows two external
WireGuard `.conf` files to be supplied **without modifying source code** or
committing profiles to Git.

### How It Works

| Component | Location | Purpose |
|---|---|---|
| `Profile::from_test_env()` | `src-tauri/src/profiles.rs` (line ~118) | `#[cfg(any(test, target_os = "windows"))]` — reads 3 environment variables and builds a `Profile` with two `wg_config_paths` |
| `connect_test()` Tauri command | `src-tauri/src/main.rs` (line ~254) | `#[cfg(any(test, target_os = "windows"))]` — invokes `Profile::from_test_env()`, then delegates to `connect()` which creates two WireGuard adapters, registers them as `path-a` / `path-b` in `PathManager`, and activates `path-a` |

### Environment Variables

Set these **before** launching the MARSTART LINK application:

| Variable | Required | Description | Example |
|---|---|---|---|
| `MARSTART_PATH_A_CONFIG` | **Yes** | Absolute filesystem path to Path A WireGuard `.conf` file | `C:\live-test\configs\path-a.conf` |
| `MARSTART_PATH_B_CONFIG` | **Yes** | Absolute filesystem path to Path B WireGuard `.conf` file | `C:\live-test\configs\path-b.conf` |
| `MARSTART_MANAGED_DESTINATION` | **Yes** | Destination CIDR in `ip/prefix` notation | `203.0.113.10/32` |

### What the Code Does With These

1. **Reads file paths** (not secrets) from `MARSTART_PATH_A_CONFIG` and `MARSTART_PATH_B_CONFIG`
2. **Verifies** both files exist on the filesystem
3. **Builds** a `Profile` with `wg_config_paths = [path_a, path_b]`
4. **`connect()`** creates two `WireGuardTunnel` instances from these configs
5. **Path IDs** are auto-assigned: `path-a` (index 0, primary) and `path-b` (index 1, standby)
6. **Route activation:** `path-a` gets `ACTIVE_METRIC` (10), `path-b` gets `STANDBY_METRIC` (20)

### Security Properties

- **No secrets in environment variables** — only file paths and a CIDR string
- **No profiles committed to Git** — the `.gitignore` excludes `src-tauri/sdk/` and `src-tauri/resources/*.dll`; external `.conf` files are stored outside the repo
- **No source code changes required** — the operator sets env vars and launches the app

---

## 1. Path A Inputs

### A.1. profile/config path

An absolute filesystem path to a valid WireGuard configuration file (`.conf`).
This file is **not** stored in the MARSTART LINK repository. The operator places
it at the path specified in `MARSTART_PATH_A_CONFIG`.

**Required WireGuard config sections:**

```ini
[Interface]
PrivateKey = <redacted — 32-byte base64 key>
Address = <tunnel IP>/32
ListenPort = 0

[Peer]
PublicKey = <redacted — peer public key>
AllowedIPs = <managed destination>
Endpoint = <endpoint A hostname or IP>:<port>
PersistentKeepalive = 25
PresharedKey = <redacted — optional, 32-byte base64 key>
```

### A.2. endpoint

The remote WireGuard endpoint that Path A connects to.

- **Must be a unique IP:port from Path B** (see §3)
- **Format:** `hostname:port` or `ip:port`
- **Example:** `198.51.100.10:51820`

### A.3. tunnel address

The IP address assigned to this WireGuard interface (from the `[Interface]`
section's `Address` field). Must be unique per path.

- **Format:** `ip/32` (use /32 for point-to-point)
- **Example:** `10.10.1.2/32`
- **Must differ from Path B's tunnel address**

### A.4. peer public key

The public key of the remote WireGuard peer on Path A (from the `[Peer]`
section's `PublicKey` field).

- **Format:** 32-byte base64 (44 characters)
- **Must differ from Path B's peer public key**

### A.5. allowed IPs

The destination CIDR(s) that this peer is allowed to carry. This should
encompass the controlled destination.

- **Format:** `ip/prefix` (can be comma-separated for multiple)
- **Example:** `203.0.113.0/24`
- **Must route to the controlled destination** (see §2)

---

## 2. Path B Inputs

### B.1. profile/config path

An absolute filesystem path to a **second**, independent WireGuard configuration
file. Stored at `MARSTART_PATH_B_CONFIG`.

Same WireGuard config format as Path A, with values that must differ (see §3).

### B.2. endpoint

- **Must differ from Path A's endpoint** (see §3)
- **Example:** `203.0.113.10:51820`

### B.3. tunnel address

- **Must differ from Path A's tunnel address**
- **Example:** `10.10.2.2/32`

### B.4. peer public key

- **Must differ from Path A's peer public key**
- **Format:** 32-byte base128 base64 (44 characters)

### B.5. allowed IPs

- **Same managed destination as Path A** (both paths must reach the same destination)
- **Example:** `203.0.113.0/24`

---

## 3. Controlled Destination

A real reachable server that is reachable **through both** WireGuard paths.
This is the target for the packet-path proof tests.

> **Important:** The destination must be a real IP address on a routable network.
> TEST-NET addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) may
> be used for route-table manipulation tests where **no packets** need to reach
> a remote host. For real traffic tests, the destination must be genuinely
> reachable.

### D.1. destination IP

- **Format:** IPv4 address
- **Example:** `203.0.113.10`
- **Must be reachable through both Path A and Path B**

### D.2. destination protocol

- **Format:** `tcp` or `udp`
- **Recommendation:** Use `tcp` for traffic tests — reliable, easy to verify with
  `Get-NetTCPConnection` or `ss`/`netstat`. Use `udp` only if the test server
  has a UDP echo service for verification.

### D.3. destination port

- **Format:** Numeric port (1–65535)
- **Recommendation:** `8080` (TCP) — commonly allowed through firewalls and
  easy to verify

### D.4. managed destination CIDR (for `MARSTART_MANAGED_DESTINATION`)

The CIDR string passed via the `MARSTART_MANAGED_DESTINATION` environment
variable. This is the route installed in the Windows routing table.

- **Format:** `ip/prefix`
- **Example:** `203.0.113.0/24`
- **Must encompass the destination IP**

### D.5. How the Destination Maps to Route Installation

When `connect_test()` is invoked:

1. `MARSTART_MANAGED_DESTINATION` (e.g., `203.0.113.0/24`) is parsed by `parse_destination()`
2. `set_destination("path-a", 203.0.113.0, 24)` and `set_destination("path-b", 203.0.113.0, 24)` are called
3. `activate_path("path-a")` installs a route: `203.0.113.0/24 via Interface LUID-A, metric 10`
4. Path B's route: `203.0.113.0/24 via Interface LUID-B, metric 20` (standby)
5. Windows route table selects the lowest metric (10 = path-a) for traffic to `203.0.113.0/24`

---

## 4. Summary: Operator Checklist for Inputs

Before starting the live test, the operator must prepare:

- [ ] **Path A config file** at an external path (e.g. `C:\live-test\configs\path-a.conf`)
  - Unique PrivateKey, tunnel Address, peer PublicKey, Endpoint
- [ ] **Path B config file** at a different external path (e.g. `C:\live-test\configs\path-b.conf`)
  - Unique PrivateKey, tunnel Address, peer PublicKey, Endpoint
- [ ] **Endpoint A ≠ Endpoint B** (different IP:port)
- [ ] **Tunnel A ≠ Tunnel B** (different IP/32 addresses)
- [ ] **Peer public key A ≠ Peer public key B** (genuinely independent peers)
- [ ] **Controlled destination** — a real reachable server (e.g. `203.0.113.10:8080/TCP`)
  - Reachable through both WireGuard paths
- [ ] **MARSTART_MANAGED_DESTINATION** — CIDR covering the destination (e.g. `203.0.113.0/24`)
- [ ] Environment variables set:
  - `MARSTART_PATH_A_CONFIG=<path-to-path-a.conf>`
  - `MARSTART_PATH_B_CONFIG=<path-to-path-b.conf>`
  - `MARSTART_MANAGED_DESTINATION=203.0.113.0/24`
- [ ] **No config files committed to Git** — all `.conf` files stored externally

---

## 5. How the Test Operator Supplies Inputs

No source code changes are needed. The test-only mechanism is already compiled
into the Windows binary.

### Option A: Environment Variables + App Restart

```powershell
# Set in an Administrator PowerShell session before launching the app
$env:MARSTART_PATH_A_CONFIG  = "C:\live-test\configs\path-a.conf"
$env:MARSTART_PATH_B_CONFIG  = "C:\live-test\configs\path-b.conf"
$env:MARSTART_MANAGED_DESTINATION = "203.0.113.0/24"

# Launch the app (triggers UAC via requireAdministrator manifest)
& "C:\path\to\marstart-link.exe"
```

Then, from the app's devtools console (F12):

```javascript
// Connect both paths
await window.__TAURI__.invoke('connect_test');

// Check status
await window.__TAURI__.invoke('get_status');

// Get connection info (handshake, tx/rx bytes)
await window.__TAURI__.invoke('get_connection_info');

// Get route evaluation (current, recommended, scores)
await window.__TAURI__.invoke('routes_list');

// Get snapshot (health, score, RTT, loss per path)
await window.__TAURI__.invoke('route_snapshot');

// Switch to Path B manually
await window.__TAURI__.invoke('routes_select_manual', { id: 'path-b' });

// Switch back to Path A
await window.__TAURI__.invoke('routes_select_manual', { id: 'path-a' });

// Disconnect
await window.__TAURI__.invoke('disconnect');
```

### Option B: Build and Run in Dev Mode

```powershell
# Set env vars
$env:MARSTART_PATH_A_CONFIG  = "C:\live-test\configs\path-a.conf"
$env:MARSTART_PATH_B_CONFIG  = "C:\live-test\configs\path-b.conf"
$env:MARSTART_MANAGED_DESTINATION = "203.0.113.0/24"

# Build and launch in dev mode
cd C:\Users\User\Desktop\marstart-link-main
npm run tauri:dev
```

### Option C: Use `tauri-driver` for Automated Invocation

```powershell
# Install tauri-driver globally (once)
npm install -g @tauri-apps/tauri-driver

# Set env vars
$env:MARSTART_PATH_A_CONFIG  = "C:\live-test\configs\path-a.conf"
$env:MARSTART_PATH_B_CONFIG  = "C:\live-test\configs\path-b.conf"
$env:MARSTART_MANAGED_DESTINATION = "203.0.113.0/24"

# Launch app with tauri-driver
npx tauri-driver --app-path "target\debug\MARSTART LINK.exe"
```

Then use WebDriver-compatible commands to invoke Tauri commands programmatically.
