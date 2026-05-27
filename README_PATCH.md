Production patch for Game Accelerator

Included changes:
- WireGuard session-scoped diagnostics command (`tunnel_get_diagnostics`)
- runtime endpoint capture for route verification
- safer emergency teardown -> `Failed` phase on partial connect errors
- UI status upgraded to include phase / handshake / DNS / game-path state
- UI diagnostics card with route, handshake, RTT/jitter/loss placeholders

Files:
- src-tauri/src/wireguard.rs
- src-tauri/src/main.rs
- src/App.tsx
