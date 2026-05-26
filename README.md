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

## 🚀 About

**Game Accelerator** is an experimental Windows SD-WAN / Gaming VPN client focused on:

- lower latency;
- stable routing;
- cleaner packet paths;
- lightweight desktop experience;
- direct integration with WireGuard-NT.

The project combines:

- ⚡ **Rust backend**
- 🖥️ **Tauri desktop UI**
- 🛡️ **WireGuard-NT + Wintun**
- 🎯 **Gaming-oriented routing logic**

Designed primarily for:
- competitive gaming;
- custom VPS tunnels;
- controlled routing environments;
- low-overhead networking.

---

## ✨ Current Features

### 🛡️ Native WireGuard-NT Integration
- dynamic loading of WireGuard-NT and Wintun;
- low-level Windows networking integration;
- direct interaction with Win32 networking APIs.

### 🌐 Tunnel Management
- start / stop tunnel;
- runtime tunnel status;
- traffic statistics (TX/RX);
- route metric management;
- MTU configuration.

### 🧠 Smart Routing Foundation
- custom route injection;
- metric prioritization;
- groundwork for split tunneling;
- preparation for advanced SD-WAN logic.

### 🖥️ Modern Lightweight UI
- minimal black & blue interface;
- lightweight desktop footprint;
- React + Tauri frontend;
- live connection state updates.

### ☁️ Custom VPS Profiles
- add your own VPS servers;
- manage multiple profiles;
- save and switch configurations;
- foundation for future import/export support.

---

## 📸 Interface Style

Current UI direction:

- ⚫ black minimalistic layout
- 🔵 blue accent elements
- 🎯 focus on readability and low visual noise

---

## 🏗️ Tech Stack

- **Frontend:** React + Vite + Tauri
- **Backend:** Rust
- **Network Drivers:** WireGuard-NT / Wintun
- **Windows APIs:** windows-rs
- **CI/CD:** GitHub Actions

---

## 📦 Development

### Requirements

- Windows 10 / 11
- Rust
- Node.js 20+
- Visual Studio Build Tools

### Install

```bash
npm install

Development
npm run tauri dev
Release Build
npm run build
npm run tauri build
🚧 Roadmap
 finalize WireGuard config serialization
 stabilize DNS & endpoint handling
 advanced VPS profile management
 split tunneling
 real-time network diagnostics
 improved telemetry and logs
 polished production UI
 automatic latency-based routing
⚠️ Status

Project is currently in Alpha.

Core networking components are already being integrated, but the project is still under active development and testing.

🤝 Contributions

Contributions are welcome.

Especially useful areas:

Rust networking
Windows routing
WireGuard internals
UI/UX
diagnostics & telemetry
testing on real VPS setups
<div align="center">
Built for low-latency networking on Windows
</div> ```