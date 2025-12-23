# 🌐 Whispera

## 📦 Быстрый старт

### Установка сервера

```bash
# Автоматическая установка (рекомендуется)
sudo bash <(curl -Ls https://raw.githubusercontent.com/your-repo/whispera/main/install.sh)

# Или если репозиторий уже на сервере
cd whispera
sudo bash install.sh
```

После установки вы получите:
- IP адрес сервера
- Публичный ключ сервера
- Приватный ключ клиента
- **Quick Connect Key** — готовый ключ для подключения

### Подключение клиента

1. **Соберите Tauri клиент:**
   ```bash
   cd client-package-tauri
   npm install
   npm run tauri build
   ```

2. **Запустите клиент:**
   - Windows: Установите из `src-tauri/target/release/bundle/`
   - Linux: Запустите `.AppImage` или `.deb`
   - macOS: Откройте `.app` или `.dmg`

3. **Quick Connect:**
   - Вставьте ключ подключения в поле "Quick Connect"
   - Нажмите "Подключиться"
   - Система автоматически определит сервер и подключится

## 🔧 Управление сервером

```bash
# Статус
sudo systemctl status whispera-server

# Логи
sudo journalctl -u whispera-server -f

# Перезапуск
sudo systemctl restart whispera-server

# Обновление
sudo bash update.sh
```

## 📋 Режимы работы клиента

- **TUN Mode** — весь трафик через VPN (требует права администратора)
- **Proxy Mode** — SOCKS5 прокси на `localhost:1080` (не требует прав администратора)

## 🛠️ Разработка

### Требования
- **Go** 1.23+ (для сервера)
- **Rust** 1.70+ и **Node.js** 18+ (для Tauri клиента)

### Сборка

```bash
# Сервер
go build -o whispera-server ./cmd/server

# Клиент (для Tauri)
go build -o client-package-tauri/src-tauri/resources/whispera-client.exe ./cmd/client
```

## 📄 Дополнительная информация

- **Сервер:** Собирается автоматически при установке
- **Клиент:** Собирается как часть Tauri приложения
- **Ключи:** Генерируются автоматически при установке
- **TLS:** Автоматически настраивается (Let's Encrypt или self-signed)

---

**Whispera** — ваш надёжный спутник в мире свободного интернета! 🌐✨
