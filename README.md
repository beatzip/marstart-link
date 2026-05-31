# 🎮 Game Accelerator

<div align="center">

**Низколатентный SD-WAN / Gaming VPN клиент для Windows**

Умная маршрутизация игрового трафика для снижения задержки, повышения стабильности соединения и уменьшения потерь пакетов.

[Русская версия](#-русская-версия) | [English version](#-english-version)

<br>

<img src="https://img.shields.io/badge/Windows-10%20%2F%2011-0078D6?style=for-the-badge&logo=windows&logoColor=white" />
<img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" />
<img src="https://img.shields.io/badge/Tauri-24C8DB?style=for-the-badge&logo=tauri&logoColor=white" />
<img src="https://img.shields.io/badge/WireGuard--NT-4B0082?style=for-the-badge" />

![GitHub stars](https://img.shields.io/github/stars/YOUR_USERNAME/sd-wan-gaming-client?style=social)
![GitHub forks](https://img.shields.io/github/forks/YOUR_USERNAME/sd-wan-gaming-client?style=social)

</div>

---

# 🇷🇺 Русская версия

## ✨ Что это такое

**Game Accelerator** — это Windows-клиент для игрового VPN / SD-WAN, созданный для сценариев, где важны:

* минимальная задержка;
* стабильный маршрут;
* низкий jitter;
* приоритет игрового трафика;
* split tunneling.

Проект ориентирован на онлайн-игры и сценарии, где важны стабильность и предсказуемость соединения:

* CS2
* Valorant
* Dota 2
* Apex Legends
* Warzone
* PUBG
* Fortnite
* другие онлайн-игры

---

## 🚀 Что уже реализовано

### ✅ Нативная поддержка WireGuard-NT

* высокая производительность;
* минимальные накладные расходы;
* работа через Windows networking stack.

### ✅ Парсинг WireGuard-конфигураций

* обработка `AllowedIPs`;
* подготовка маршрутов;
* корректная работа IPv4/IPv6;
* исправления порядка байтов IP-адресов;
* улучшенная семантика маршрутизации.

### ✅ Endpoint resolving

* разрешение доменных имён;
* поддержка IP endpoint;
* подготовка peer endpoint перед handshake.

### ✅ Route injection

* добавление маршрутов через Windows IP Helper API;
* игровой трафик через туннель;
* остальной трафик напрямую;
* база для split tunneling.

### ✅ Adapter IP assignment

* назначение IP-адреса интерфейсу;
* подготовка tunnel adapter;
* настройка интерфейса после подключения.

### ✅ DNS handling

* базовая DNS-интеграция;
* подготовка tunnel DNS;
* снижение риска DNS leak.

### ✅ Статистика соединения

* TX/RX polling;
* live statistics;
* состояние подключения;
* handshake monitoring.

### ✅ Логирование и диагностика

* runtime logs;
* networking diagnostics;
* debugging routing;
* Windows troubleshooting.

### ✅ Архитектура клиента

* Rust backend;
* Tauri shell;
* React + TypeScript frontend;
* модульная структура проекта.

---

## ✨ Основные возможности

* **Низкая задержка** — маршрутизация через собственный VPS
* **Split tunneling** — только игра через VPN
* **Контроль туннеля** — запуск, остановка, статистика
* **Профили серверов** — быстрое переключение между VPS
* **Минималистичный UI** — современный интерфейс без лишнего
* **Windows-first подход** — оптимизация под Windows 10 / 11
* **WireGuard-NT** — скорость и стабильность
* **Низкие накладные расходы** — минимальная нагрузка на систему

---

## 🧠 Архитектура

### Backend

* Rust 2021
* windows-rs
* Windows networking API

### Frontend

* React
* TypeScript
* Vite
* Tauri

### Networking

* WireGuard-NT
* Wintun
* Windows IP Helper API

---

## 🛠️ Установка

### Требования

* Windows 10 / 11 (64-bit)
* Node.js
* Rust toolchain
* собственный VPS с WireGuard

---

## 🚀 Быстрый старт

### Клонирование репозитория

```bash
git clone https://github.com/YOUR_USERNAME/sd-wan-gaming-client.git
cd sd-wan-gaming-client
```

### Установка зависимостей

```bash
npm install
```

### Запуск в development режиме

```bash
npm run tauri dev
```

### Сборка release версии

```bash
npm run tauri build
```

---

## ⚙️ Пример WireGuard-конфигурации

```ini
[Interface]
PrivateKey = YOUR_PRIVATE_KEY
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = YOUR_SERVER_PUBLIC_KEY
Endpoint = your.server.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

---

## 📋 Roadmap

### 🔄 В процессе

* split tunneling improvements;
* стабильность маршрутизации;
* улучшение handshake handling.

### 📌 Планируется

* графики ping / jitter / loss;
* realtime monitoring;
* auto route selection;
* multi-hop;
* load balancing;
* encrypted profiles;
* advanced diagnostics;
* auto optimization;
* game detection;
* QoS logic.

---

## 🧪 Диагностика

При проблемах с подключением проверяются:

* `AllowedIPs`;
* `Endpoint`;
* adapter IP assignment;
* Windows routes;
* DNS;
* WireGuard-NT status;
* Wintun adapter;
* runtime logs;
* handshake status.

---

## 🤝 Contributing

Вклад в проект приветствуется.

Особенно полезны:

* тестирование на VPS;
* Windows networking;
* Rust backend;
* Tauri frontend;
* UI/UX улучшения;
* routing debugging.

---

## 📜 License

MIT License.

См. файл `LICENSE`.

---

## ⭐ Поддержка проекта

Если проект тебе нравится — поставь звезду на GitHub.

Это помогает развитию Game Accelerator.

---

# 🇬🇧 English version

## ✨ What is this

**Game Accelerator** is a Windows gaming VPN / SD-WAN client focused on:

* low latency;
* stable routing;
* low jitter;
* game traffic prioritization;
* split tunneling.

Designed for online games and scenarios where connection stability matters:

* CS2
* Valorant
* Dota 2
* Apex Legends
* Warzone
* PUBG
* Fortnite
* other online games

---

## 🚀 Current implementation status

The project already includes:

### ✅ Native WireGuard-NT support

* high performance;
* low overhead;
* Windows networking stack integration.

### ✅ WireGuard config parsing

* `AllowedIPs` parsing;
* route preparation;
* IPv4/IPv6 handling;
* fixed IP byte-order issues;
* improved routing semantics.

### ✅ Endpoint resolving

* hostname resolving;
* IP endpoint support;
* peer endpoint preparation before handshake.

### ✅ Route injection

* Windows IP Helper API integration;
* game traffic through tunnel;
* direct route for other traffic;
* split tunneling groundwork.

### ✅ Adapter IP assignment

* tunnel adapter IP setup;
* interface initialization;
* post-connect configuration.

### ✅ DNS handling

* basic DNS integration;
* tunnel DNS preparation;
* reduced DNS leak risks.

### ✅ Connection statistics

* TX/RX polling;
* live statistics;
* connection state;
* handshake monitoring.

### ✅ Logging and diagnostics

* runtime logs;
* networking diagnostics;
* routing debugging;
* Windows troubleshooting.

### ✅ Client architecture

* Rust backend;
* Tauri shell;
* React + TypeScript frontend;
* modular project structure.

---

## ✨ Main features

* **Low latency** — routing through your VPS
* **Split tunneling** — only games use VPN
* **Tunnel control** — start / stop / statistics
* **Server profiles** — fast VPS switching
* **Minimal UI** — lightweight modern interface
* **Windows-first design** — optimized for Windows 10 / 11
* **WireGuard-NT** — speed and stability
* **Low overhead** — minimal system impact

---

## 🧠 Architecture

### Backend

* Rust 2021
* windows-rs
* Windows networking API

### Frontend

* React
* TypeScript
* Vite
* Tauri

### Networking

* WireGuard-NT
* Wintun
* Windows IP Helper API

---

## 🛠️ Installation

### Requirements

* Windows 10 / 11 (64-bit)
* Node.js
* Rust toolchain
* VPS with WireGuard

---

## 🚀 Quick start

### Clone repository

```bash
git clone https://github.com/YOUR_USERNAME/sd-wan-gaming-client.git
cd sd-wan-gaming-client
```

### Install dependencies

```bash
npm install
```

### Run development build

```bash
npm run tauri dev
```

### Build release

```bash
npm run tauri build
```

---

## ⚙️ Example WireGuard configuration

```ini
[Interface]
PrivateKey = YOUR_PRIVATE_KEY
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = YOUR_SERVER_PUBLIC_KEY
Endpoint = your.server.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

---

## 📋 Roadmap

### 🔄 In progress

* split tunneling improvements;
* routing stability;
* improved handshake handling.

### 📌 Planned

* ping / jitter / loss graphs;
* realtime monitoring;
* auto route selection;
* multi-hop;
* load balancing;
* encrypted profiles;
* advanced diagnostics;
* auto optimization;
* game detection;
* QoS logic.

---

## 🧪 Troubleshooting

When debugging connection issues, the following are checked:

* `AllowedIPs`;
* `Endpoint`;
* adapter IP assignment;
* Windows routes;
* DNS;
* WireGuard-NT status;
* Wintun adapter;
* runtime logs;
* handshake status.

---

## 🤝 Contributing

Contributions are welcome.

Especially useful areas:

* VPS testing;
* Windows networking;
* Rust backend;
* Tauri frontend;
* UI / UX improvements;
* routing debugging.

---

## 📜 License

MIT License.

See `LICENSE`.

---

## ⭐ Support the project

If you like this project, give it a GitHub star.

It helps Game Accelerator grow.
