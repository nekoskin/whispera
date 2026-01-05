# 🌐 Whispera

**Whispera** — высокопроизводительный VPN-туннель с собственным протоколом WLESS, интеллектуальным выбором транспорта и продвинутой обфускацией трафика.

## ✨ Возможности

- **Whispera Protocol (WLESS)** — собственный лёгкий протокол с минимальным overhead
- **Мультитранспорт** — UDP, TCP, WebSocket, QUIC с автоматическим выбором
- **ML-обфускация** — адаптивная маскировка под VK, Yandex, YouTube и другие сервисы
- **DPI-устойчивость** — обход глубокой инспекции пакетов
- **ChaCha20-Poly1305** — современное шифрование

## 📦 Быстрый старт

### Windows (PowerShell)

```powershell
# Сборка
.\run.ps1 build

# Запуск сервера
.\run.ps1 server

# Запуск клиента
.\run.ps1 client

# Справка
.\run.ps1 help
```

### Linux/macOS

```bash
# Автоматическая установка сервера
sudo bash install.sh

# Или сборка вручную
make build
```

## 🔧 Конфигурация

### Клиент (`client_config.yaml`)

```yaml
server: "your-server.com:443"
protocol:
  version: 1  # Whispera v1
transport:
  mode: "auto"  # ML автовыбор
obfuscation:
  enabled: true
  profile: "ml"
```

### Сервер (`config.yaml`)

```yaml
listen:
  udp: ":51820"
  tcp: ":443"
protocol:
  version: 1
  enable_vless_compat: true  # Совместимость с VLESS
```

## 🚀 Архитектура

```
┌─────────┐    ┌──────────────────┐    ┌─────────────┐
│ Client  │───▶│ TransportSelector│───▶│   Server    │
└─────────┘    │ (ML/Manual)      │    └─────────────┘
               └──────────────────┘
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
      [UDP]         [TCP]       [WebSocket]
         │             │             │
         └─────────────┴─────────────┘
                       │
              [Whispera Protocol]
              [Obfuscation + LZ4]
```

## 📁 Структура проекта

```
whispera/
├── run.ps1              # Главный скрипт
├── scripts/             # Вспомогательные скрипты
│   ├── build-platforms.ps1
│   ├── deploy.ps1
│   └── docker.ps1
├── cmd/
│   ├── client/          # Клиент
│   └── server/          # Сервер
├── internal/
│   ├── whispera/        # Протокол WLESS
│   ├── modules/transport/  # Транспорты
│   └── obfuscation/     # Обфускация
└── client-package-tauri/  # GUI клиент
```

## 🛡️ Безопасность

- **ChaCha20-Poly1305** / AES-256-GCM шифрование
- **X25519** handshake (Whispera protocol)
- **Whispera v1** — 64-байтный padding (vs 900 в VLESS)
- **Anti-replay** защита
- **Автоматический rekeying**

## 📄 Лицензия

MIT

---

**Whispera** — ваш надёжный спутник в мире свободного интернета! 🌐✨
