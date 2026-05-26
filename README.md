````md id="full-readme"
<div align="center">

# 🎮 Game Accelerator

### Low-Latency SD-WAN / Gaming VPN Client for Windows  
### Powered by Tauri + Rust + WireGuard-NT

<img src="https://img.shields.io/badge/platform-Windows-blue?style=for-the-badge" />
<img src="https://img.shields.io/badge/backend-Rust-orange?style=for-the-badge" />
<img src="https://img.shields.io/badge/frontend-Tauri-black?style=for-the-badge" />
<img src="https://img.shields.io/badge/status-Alpha-blueviolet?style=for-the-badge" />

</div>

---

# 🚀 About

**Game Accelerator** is an experimental Windows SD-WAN / Gaming VPN client designed for:

- competitive gaming;
- low-latency routing;
- custom VPS tunnels;
- stable packet delivery;
- lightweight desktop networking.

The project combines:

- ⚡ Rust backend performance
- 🖥️ Tauri desktop UI
- 🛡️ WireGuard-NT + Wintun
- 🌐 Windows native networking APIs

The main goal is to create a modern low-overhead networking client capable of intelligent traffic routing and future SD-WAN functionality for gaming environments.

---

# ✨ Current Features

## 🛡️ Native WireGuard-NT Integration

- Dynamic loading of WireGuard-NT and Wintun
- Direct interaction with low-level Windows networking APIs
- Tunnel initialization groundwork
- Safe runtime handling of driver interactions
- DLL loading fixes for Windows environments

---

## 🌐 Tunnel Management

- Start / stop tunnel logic
- Runtime tunnel status API
- Traffic statistics (TX/RX)
- Connection state polling
- Adapter initialization
- MTU configuration support

---

## 🛣️ Routing Management

- Route creation and updates
- Metric prioritization
- Traffic redirection groundwork
- Windows routing table integration
- Preparation for split-tunnel functionality

---

## ☁️ Custom VPS Profiles

- Add custom VPS servers
- Store local profiles
- Switch between profiles
- Profile management UI
- Foundation for future import/export support

---

## 🖥️ User Interface

Current UI direction:

- ⚫ black minimalistic layout
- 🔵 blue accent elements
- 🎯 gaming-oriented design
- 🪶 lightweight desktop rendering

Frontend stack:
- React
- Vite
- Tauri

---

## 🪵 Logging & Diagnostics

- Structured Rust logging
- Runtime diagnostics
- Panic handling foundation
- Safer adapter cleanup behavior
- Preparation for advanced telemetry

---

# 🏗️ Tech Stack

## Frontend
- React
- Vite
- Tauri

## Backend
- Rust (Edition 2021)

## Networking
- WireGuard-NT
- Wintun
- Windows IP Helper API
- windows-rs

## CI/CD
- GitHub Actions

---

# 📂 Project Structure

```text
project-root/
│
├── src/                    # Frontend (React/Vite)
├── src-tauri/              # Rust backend + networking
├── dist/                   # Frontend production build
├── .github/workflows/      # CI/CD pipelines
├── tauri.conf.json         # Tauri configuration
├── package.json
└── README.md
```

---

# 📦 Development

## Requirements

- Windows 10 / 11
- Rust stable toolchain
- Node.js 20+
- npm or pnpm
- Visual Studio Build Tools with C++ support

---

# 🔧 Installation

Install frontend dependencies:

```bash
npm install
```

---

# ▶️ Development Mode

Run Tauri development environment:

```bash
npm run tauri dev
```

---

# 🏭 Production Build

Build frontend and desktop application:

```bash
npm run build
npm run tauri build
```

---

# 🚀 GitHub Release Build

The project includes automated Windows release builds via GitHub Actions.

Workflow:
- installs Node.js and Rust;
- builds frontend assets;
- downloads WireGuard SDKs;
- compiles Tauri application;
- creates GitHub Release artifacts automatically.

Release pipeline file:

```text
.github/workflows/release.yml
```

---

# 🚧 Roadmap

## Networking
- [ ] Finalize WireGuard config serialization
- [ ] Improve DNS resolution pipeline
- [ ] Stabilize endpoint handling
- [ ] Improve adapter lifecycle management

## SD-WAN Features
- [ ] Split tunneling
- [ ] Multi-route support
- [ ] Smart route prioritization
- [ ] Dynamic latency-based routing

## VPS System
- [ ] Import/export profiles
- [ ] Encrypted profile storage
- [ ] Multi-server management
- [ ] Connection testing

## UI/UX
- [ ] Better dashboard
- [ ] Live latency graphs
- [ ] Connection quality indicators
- [ ] Real-time diagnostics panel

## Diagnostics
- [ ] Advanced logs
- [ ] Crash reports
- [ ] Adapter state diagnostics
- [ ] Route inspection tools

---

# ⚠️ Current Status

The project is currently in **Alpha**.

Core networking systems are actively being implemented and stabilized.  
Some WireGuard configuration handling and runtime networking functionality are still under development.

This is not yet considered production-ready software.

---

# 🤝 Contributing

Contributions are welcome.

Useful contribution areas:
- Rust networking
- Windows routing APIs
- WireGuard internals
- UI/UX improvements
- Diagnostics & telemetry
- Testing on real VPS environments

---

# 📜 License

License not specified yet.

---

<div align="center">

### Built for low-latency networking on Windows

</div>
````
