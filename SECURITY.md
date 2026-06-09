# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting a Vulnerability

We take the security of the MARSTART LINK client seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to **[shterbeatz@gmail.com]** *(or use GitHub's Private Vulnerability Reporting feature)*.

Please include the following information in your report:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Any suggested mitigations (if applicable)

We will acknowledge receipt of your vulnerability report within 48 hours and aim to send a more detailed response within 7 days, indicating the next steps in handling your report.

---

## Security Architecture & Considerations

Given the nature of this application (Network Tunneling / Game Acceleration), it requires elevated privileges and interacts with low-level Windows network components. We have implemented several security measures to protect the user's system.

### 1. Elevated Privileges (Admin Rights)
The application requires Administrator privileges to function. This is strictly necessary to:
- Load `wintun.dll` and `wireguard.dll` to create and manage virtual network adapters (TUN).
- Modify system routing tables (`SetIpForwardEntry2`) and interface metrics.
- Adjust MTU settings (`SetIpInterfaceEntry`).

**Mitigation:** Users are strongly advised to only download binaries from our official GitHub Releases to ensure no malicious code is executed with elevated privileges.

### 2. DLL Loading & Supply Chain Protection
The application dynamically loads `wireguard.dll` and `wintun.dll` via `libloading`.
- **Source Verification:** These DLLs are fetched from official sources (WireGuard LLC / Wintun) and verified via SHA-256 checksums during the build process (`build.rs`).
- **DLL Hijacking Prevention:** The DLLs are bundled within the Tauri application resources. The Rust backend resolves the DLL paths using secure, absolute paths derived from the Tauri `AppHandle` environment, preventing DLL Hijacking / Preloading attacks from the current working directory.

### 3. Tauri & IPC Security
- The frontend (WebView2) communicates with the Rust backend via Tauri's IPC (Commands).
- **Custom Protocol:** Tauri's `custom-protocol` feature is enabled in production to prevent Remote Code Execution (RCE) via external web navigation or XSS.
- **Input Validation:** All IPC inputs (such as WireGuard configuration strings, Base64 keys, CIDR routes, and endpoint addresses) are strictly validated, parsed, and sanitized in the Rust backend (`wireguard_parser`) before being passed to the C FFI (WireGuard API) or Windows API. This prevents buffer overflows, memory corruption, or injection attacks.

### 4. Memory Safety & Panic Handling
- The core logic is written in Rust, guaranteeing memory safety and preventing common C/C++ vulnerabilities (use-after-free, buffer overflows).
- **Emergency Cleanup:** A custom panic hook (`setup_panic_hook`) is implemented. If the Rust backend encounters a critical failure, the hook ensures that the WireGuard adapter is safely torn down (`WireGuardSetState(Down)`, `WireGuardCloseAdapter`), preventing network leaks, orphaned virtual adapters, or system network lockouts.

### 5. Network Traffic & Privacy
- The application establishes WireGuard tunnels based on user-provided or server-provided configurations.
- Private keys are handled in memory and are zeroed out when no longer needed. We recommend using the OS Credential Manager (via the `keyring` crate) for persistent storage of sensitive credentials, avoiding plaintext configuration files on disk.

---

## Dependency Security

We rely on the Rust ecosystem and actively monitor our supply chain:
- Core networking and cryptographic operations are delegated to audited libraries and official C APIs (WireGuard-NT, Wintun).
- We regularly run `cargo audit` in our CI/CD pipelines to detect known vulnerabilities (RUSTSEC) in our dependency tree.
- Windows API interactions are handled via the official `windows` crate, ensuring type-safe FFI boundaries.

---

*Last updated: 2026*