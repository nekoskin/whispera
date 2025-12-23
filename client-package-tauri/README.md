# Whispera Client - Tauri Edition

Кроссплатформенный клиент для Whispera VPN на базе Tauri 2.0.

## 🚀 Преимущества Tauri

- ✅ **Меньший размер** — от 600KB (vs 80-150MB у Electron)
- ✅ **Лучшая производительность** — использует системный WebView
- ✅ **Безопасность** — минимальная поверхность атаки
- ✅ **Кроссплатформенность** — Windows, Linux, macOS, Android, iOS
- ✅ **Любой фронтенд** — используйте существующий HTML/CSS/JS

## 📋 Требования

- **Rust** 1.70+ ([установка](https://www.rust-lang.org/tools/install))
- **Node.js** 18+ и **npm**
- **Go** 1.23+ (для сборки Go клиента)

### Установка Rust

**Windows:**
```powershell
# Через PowerShell (рекомендуется):
irm https://win.rustup.rs/x86_64 | iex

# Или скачайте rustup-init.exe с https://rustup.rs/
```

**Linux/macOS:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## 🛠 Установка

```bash
cd client-package-tauri
npm install
```

## 🚀 Разработка

```bash
npm run tauri dev
```

## 📦 Сборка

```bash
# Сначала соберите Go клиент (из корня проекта)
cd ..
go build -o client-package-tauri/src-tauri/resources/whispera-go-client.exe ./cmd/client

# Затем соберите Tauri приложение
cd client-package-tauri
npm run tauri build
```

## 📁 Структура проекта

```
client-package-tauri/
├── src/                    # Frontend (HTML/CSS/JS)
├── src-tauri/             # Rust backend
│   ├── src/
│   │   └── main.rs        # Rust код
│   ├── Cargo.toml         # Rust зависимости
│   └── tauri.conf.json    # Конфигурация Tauri
├── package.json
└── vite.config.js
```

## 🔧 Особенности

- ✅ Меньший размер приложения (от 600KB)
- ✅ Автоматическое извлечение Go клиента из ресурсов
- ✅ Использует системный WebView
- ✅ Безопасная архитектура
- ✅ Быстрое подключение по ключу

