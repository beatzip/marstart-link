# 🎮 Game Accelerator

<div align="center">

**Низколатентный SD-WAN / Gaming VPN клиент для Windows**

Снижает пинг и повышает стабильность соединения в играх через умную маршрутизацию.

<br>

<img src="https://img.shields.io/badge/Windows-10%20%2F%2011-0078D6?style=for-the-badge&logo=windows&logoColor=white" />
<img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" />
<img src="https://img.shields.io/badge/Tauri-24C8DB?style=for-the-badge&logo=tauri&logoColor=white" />
<img src="https://img.shields.io/badge/WireGuard--NT-4B0082?style=for-the-badge" />

![GitHub stars](https://img.shields.io/github/stars/YOUR_USERNAME/sd-wan-gaming-client?style=social)
![GitHub forks](https://img.shields.io/github/forks/YOUR_USERNAME/sd-wan-gaming-client?style=social)

</div>

---

## ✨ Почему Game Accelerator?

- **Меньше пинга** — умная маршрутизация через собственные VPS
- **Нативная производительность** — WireGuard-NT + Wintun
- **Лёгкий и быстрый** — современный минималистичный интерфейс
- **Split-tunnel** — игра идёт через VPN, остальной трафик — напрямую

Идеально для соревновательных игр (Valorant, CS2, Warzone, Dota 2, Apex и др.).

---

## 🚀 Быстрый старт

### Требования
- Windows 10 / 11 (64-bit)
- Собственный VPS (для лучшего результата)

### Установка

1. Скачай последнюю версию из **[Releases](https://github.com/YOUR_USERNAME/sd-wan-gaming-client/releases)**
2. Запусти установщик
3. Добавь конфигурацию своего VPS
4. Подключись и играй!

**Или собери из исходников:**

```bash
# Клонируй репозиторий
git clone https://github.com/YOUR_USERNAME/sd-wan-gaming-client.git
cd sd-wan-gaming-client

# Установка зависимостей
npm install

# Запуск в режиме разработки
npm run tauri dev

✨ Основные возможности

Нативная интеграция WireGuard-NT — максимальная скорость и минимальные overhead
Управление туннелями — запуск/остановка, статистика TX/RX
Профили VPS — быстрый переключение между серверами
Автоматическая маршрутизация — приоритет игрового трафика
Современный UI — тёмная тема, минимализм, live-статус


🖼️ Скриншоты


🛠️ Технологии

Backend: Rust 2021 + windows-rs
Frontend: React + TypeScript + Vite + Tauri
Networking: WireGuard-NT, Wintun, Windows IP Helper API


📋 Roadmap

 Split tunneling (уже в работе)
 Графики пинга и потерь пакетов в реальном времени
 Автоматический выбор лучшего маршрута
 Шифрование профилей
 Multi-hop и балансировка


🤝 Contributing
Очень приветствуются вклады! Особенно в:

Тестирование на реальных VPS
Windows networking
UI/UX улучшения

Смотри CONTRIBUTING.md

📜 License
MIT License — см. файл LICENSE.


⭐ Если проект тебе нравится — поставь звезду!  
Помоги сделать лучший gaming VPN для Windows.