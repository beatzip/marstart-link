# MARSTART LINK

<div align="center">

<img src="https://github.com/beatzip/marstart-link/blob/main/src-tauri/icons/icon.png" alt="MARSTART LINK logo" width="140" />

**Windows-клиент для управления туннелем и сетевой маршрутизацией**

Лёгкий desktop-клиент на **Tauri + Rust + React + TypeScript** для подключения, отключения и контроля состояния туннеля на Windows.

</div>

---

## О проекте

**MARSTART LINK** — это Windows-приложение для работы с туннелем и сетевыми профилями.  
В проекте уже есть базовая связка frontend + backend, логика подключения/отключения, получение статуса, а также нативная обработка сетевой части на Rust.

Приложение ориентировано на Windows 10/11 и запускается с правами администратора.

---

## Что уже есть

- подключение и отключение туннеля;
- получение текущего статуса через backend;
- работа с профилем по умолчанию;
- WireGuard-конфигурации и сетевые маршруты на стороне Rust;
- мониторинг и служебные модули для сети;
- иконка и логотип в `src-tauri/icons/`;
- упаковка приложения через Tauri.

---

## Технологии

- **Frontend:** React, TypeScript, Vite
- **Backend:** Rust 2021, Tauri 2
- **Networking:** WireGuard-NT, Wintun, Windows IP Helper API
- **Target OS:** Windows 10 / 11 (64-bit)

---

## Структура проекта

- `src/` — frontend приложения
- `src-tauri/src/` — Rust backend и сетевые модули
- `src-tauri/icons/` — иконки и логотип
- `src-tauri/resources/` — DLL-ресурсы для сборки
- `scripts/prepare-resources.ps1` — подготовка ресурсов перед release-сборкой

---

## Требования

- Windows 10 / 11 (64-bit)
- Node.js
- Rust toolchain
- npm
- права администратора при запуске

---

## Запуск в разработке

```bash
npm install
npm run tauri:dev
```

---

## Сборка release-версии

```bash
npm run tauri:build
```

Во время release-сборки скрипт:

- подготавливает ресурсы;
- копирует `wireguard.dll` и `wintun.dll` в `src-tauri/resources/`;
- собирает Tauri-приложение в установщик для Windows.

---

## Конфигурация и важные детали

- имя продукта задаётся в `src-tauri/tauri.conf.json`;
- текущий логотип лежит в `src-tauri/icons/icon.png`;
- приложение требует повышенные права, потому что в манифесте указан `requireAdministrator`;
- backend-команды сейчас включают `connect`, `disconnect` и `get_status`.

---

## Примечание по статусу

Проект находится в активной доработке.  
Перед выпуском релиза стоит ещё раз проверить, что все старые упоминания предыдущего названия заменены на **MARSTART LINK** в `package.json`, `tauri.conf.json`, `index.html`, `src/App.tsx` и CI/workflow-файлах.

---

## Лицензия

См. файл `LICENSE`.
