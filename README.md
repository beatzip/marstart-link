# 🎮 Game Accelerator

<div align="center">

## Low-Latency SD-WAN / Gaming VPN Client for Windows

Built with **Rust**, **Tauri**, **WireGuard-NT**, and **Wintun**

<br>

<img src="https://img.shields.io/badge/platform-Windows%2010%2F11-0078D6?style=for-the-badge&logo=windows&logoColor=white" />
<img src="https://img.shields.io/badge/backend-Rust-000000?style=for-the-badge&logo=rust" />
<img src="https://img.shields.io/badge/frontend-Tauri-24C8DB?style=for-the-badge&logo=tauri&logoColor=white" />
<img src="https://img.shields.io/badge/network-WireGuard--NT-blueviolet?style=for-the-badge" />
<img src="https://img.shields.io/badge/status-Alpha-181717?style=for-the-badge" />

<br><br>

**Experimental gaming-focused SD-WAN client with custom VPS routing, low-overhead networking, and modern desktop UI.**

</div>

---

# ✨ Features

## 🛡️ Native WireGuard-NT Integration

* Dynamic loading of WireGuard-NT and Wintun
* Low-level Windows networking integration
* Runtime tunnel management
* Native Win32 networking APIs
* Safer DLL loading behavior

---

## 🌐 Tunnel & Routing Management

* Tunnel start / stop handling
* Runtime status monitoring
* TX/RX statistics
* Automatic route injection
* MTU management
* Route metric prioritization
* Split-tunnel groundwork

---

## ☁️ Custom VPS Profiles

* Add your own VPS servers
* Store local profiles
* Switch configurations quickly
* Multi-profile architecture
* Future import/export support

---

## 🖥️ Modern Desktop UI

* Black minimal interface
* Blue accent styling
* Lightweight rendering
* React + Tauri frontend
* Live connection updates

---

# 📸 UI Direction

<div align="center">

| Theme           | Style            |
| --------------- | ---------------- |
| ⚫ Dark          | Minimalistic     |
| 🔵 Blue accents | Gaming-oriented  |
| 🪶 Lightweight  | Low visual noise |

</div>

---

# 🏗️ Architecture

```text
Frontend (React + Tauri)
        │
        ▼
Tauri IPC Bridge
        │
        ▼
Rust Backend
        │
 ┌───────────────┐
 │ WireGuard-NT  │
 │ Wintun        │
 │ Windows APIs  │
 └───────────────┘
```

---

# 📂 Project Structure

```text
project-root/
│
├── src/                    # Frontend (React/Vite)
├── src-tauri/              # Rust backend + networking
├── dist/                   # Frontend production build
├── .github/workflows/      # GitHub Actions pipelines
├── tauri.conf.json         # Tauri configuration
├── package.json
└── README.md
```

---

# ⚙️ Tech Stack

## Frontend

* React
* Vite
* Tauri

## Backend

* Rust (Edition 2021)

## Networking

* WireGuard-NT
* Wintun
* Windows IP Helper API
* windows-rs

## CI/CD

* GitHub Actions

---

# 🚀 Getting Started

## Requirements

* Windows 10 / 11
* Rust stable toolchain
* Node.js 20+
* Visual Studio Build Tools

---

## Install Dependencies

```bash
npm install
```

---

## Development Mode

```bash
npm run tauri dev
```

---

## Production Build

```bash
npm run build
npm run tauri build
```

---

# 🚀 Automated Releases

The repository includes a GitHub Actions pipeline for automated Windows builds.

Pipeline responsibilities:

* install Node.js & Rust
* build frontend assets
* download networking SDKs
* compile Tauri application
* publish GitHub Release artifacts

Workflow location:

```text
.github/workflows/release.yml
```

---

# 🚧 Roadmap

## Core Networking

* [ ] Finalize WireGuard serialization
* [ ] Improve DNS resolution
* [ ] Stabilize endpoint handling
* [ ] Improve adapter lifecycle management

## SD-WAN Features

* [ ] Split tunneling
* [ ] Smart route prioritization
* [ ] Multi-route balancing
* [ ] Dynamic latency routing

## VPS Features

* [ ] Encrypted profile storage
* [ ] Import/export support
* [ ] Connection testing
* [ ] Multi-server management

## UI & Diagnostics

* [ ] Real-time graphs
* [ ] Connection quality indicators
* [ ] Advanced diagnostics panel
* [ ] Better telemetry & logging

---

# ⚠️ Project Status

> **Alpha / Active Development**

Core systems are already integrated, but the project is still under active development and stabilization.

This software should currently be considered experimental.

---

# 🤝 Contributing

Contributions are welcome.

Especially useful areas:

* Rust networking
* Windows routing
* WireGuard internals
* UI/UX
* Diagnostics & telemetry
* Real-world VPS testing

---

# 📜 License

License not specified yet.

---

<div align="center">

## Built for low-latency networking on Windows

</div>
