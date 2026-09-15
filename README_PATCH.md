Production patch for MARSTART LINK

Included changes (recovery audit after commit b481f4b):

- WireGuard-NT 1.1 FFI verified against official API for all 4 functions:
  `WireGuardCreateAdapter`, `WireGuardCloseAdapter`, `WireGuardSetConfiguration`,
  `WireGuardGetConfiguration`. Uses unified `WireGuardAdapterHandle = HANDLE`
  type across all FFI signatures; does NOT use `CloseHandle` for the adapter.
- Runtime smoke-test / diagnostic command `tunnel_diagnostics` — loads DLL,
  creates adapter, applies config, reads stats (handshake/tx/rx), closes adapter,
  verifies no orphan adapter remains. Returns structured `DiagnosticsReport`.
- DLL loading uses `LoadLibraryW` with absolute path resolved from
  `current_exe().parent().join("resources")`. This path scheme is correct for
  Tauri v2 production bundles (resources placed in `resources/` next to exe).
  SECURITY.md claimed AppHandle-based resolution — see note below.
- `.gitignore` updated to include `tauri.key.pub` / `**/tauri.key.pub` /
  `src-tauri/tauri.key.pub` patterns alongside existing `tauri.key` patterns.
- Automated `#[cfg(test)]` module in `wireguard.rs` verifying:
  `DiagnosticsReport` JSON serialisation, non-Windows fallback error, and
  graceful handling when DLLs are absent.

Files modified:
- src-tauri/src/wireguard.rs  (DiagnosticsReport, run_diagnostics, is_adapter_closed, tests)
- src-tauri/src/main.rs      (tunnel_diagnostics Tauri command, invoke_handler registration)
- .gitignore                  (tauri.key.pub patterns)

Note on resource resolution: The SECURITY.md says paths are "derived from the
Tauri AppHandle environment", but the implementation uses `current_exe()`.
For Tauri v2 production bundles, `current_exe().parent().join("resources")`
reliably resolves to the bundled resources directory. The AppHandle approach
(`app.handle().path().resource(...)`) is more idiomatic but would require
threading the `AppHandle` through the `WireGuardTunnel::new()` → `connect()`
call chain — a larger refactor deferred to a future iteration.
