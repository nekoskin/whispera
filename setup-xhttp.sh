#!/bin/bash

# Скрипт автоматической настройки XHTTP+VLESS с Marionette обфускацией
# Использование: sudo bash setup-xhttp.sh

set -e
# Отключаем немедленный выход при ошибке для лучшей отладки
set +e

WORK_DIR="/opt/whispera"
cd "$WORK_DIR" || exit 1

log_info() {
    echo "[INFO] $*"
}

log_success() {
    echo "[SUCCESS] $*"
}

log_error() {
    echo "[ERROR] $*" >&2
}

log_warning() {
    echo "[WARNING] $*"
}

# Проверка Go - используем новую версию из /usr/local/go (установленную install.sh)
GO_CMD=""
# Сначала проверяем /usr/local/go/bin/go (обычно это новая версия)
if [[ -f "/usr/local/go/bin/go" ]]; then
    GO_CMD="/usr/local/go/bin/go"
    GO_VERSION=$("$GO_CMD" version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+' | head -1 | sed 's/go//')
    if [[ -n "$GO_VERSION" ]]; then
        GO_MAJOR=$(echo "$GO_VERSION" | cut -d. -f1)
        GO_MINOR=$(echo "$GO_VERSION" | cut -d. -f2)
        # Проверяем, что версия >= 1.13 (ed25519 требует минимум 1.13)
        if [[ $GO_MAJOR -gt 1 ]] || [[ $GO_MAJOR -eq 1 && $GO_MINOR -ge 13 ]]; then
            log_info "Найдена Go версия $GO_VERSION в /usr/local/go/bin/go"
        else
            log_warning "Go версия $GO_VERSION слишком старая (требуется >= 1.13), пробуем другую версию..."
            GO_CMD=""
        fi
    fi
fi

# Если не нашли подходящую версию, пробуем системную
if [[ -z "$GO_CMD" ]]; then
    GO_CMD=$(which go 2>/dev/null || echo "")
    if [[ -n "$GO_CMD" ]]; then
        GO_VERSION=$("$GO_CMD" version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+' | head -1 | sed 's/go//')
        if [[ -n "$GO_VERSION" ]]; then
            GO_MAJOR=$(echo "$GO_VERSION" | cut -d. -f1)
            GO_MINOR=$(echo "$GO_VERSION" | cut -d. -f2)
            if [[ $GO_MAJOR -gt 1 ]] || [[ $GO_MAJOR -eq 1 && $GO_MINOR -ge 13 ]]; then
                log_info "Найдена Go версия $GO_VERSION в системе"
            else
                log_error "Системная версия Go $GO_VERSION слишком старая (требуется >= 1.13)"
                log_error "Установите новую версию Go или запустите install.sh для автоматической установки"
                exit 1
            fi
        fi
    fi
fi

if [[ -z "$GO_CMD" ]] || ! command -v "$GO_CMD" >/dev/null 2>&1; then
    log_error "Go не найден или версия слишком старая."
    log_error "Требуется Go >= 1.13 для поддержки crypto/ed25519"
    log_error "Запустите install.sh для автоматической установки новой версии Go"
    exit 1
fi

# Финальная проверка версии
GO_VERSION_FULL=$("$GO_CMD" version 2>&1)
log_info "Используется: $GO_VERSION_FULL"

log_info "Генерация XHTTP ключей (ed25519)..."

# Создаем временный Go скрипт для генерации ключей
XHTTP_KEYGEN_SCRIPT="$WORK_DIR/xhttp_keygen.go"
cat > "$XHTTP_KEYGEN_SCRIPT" <<'XHTTPKEYGEN'
package main
import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/hex"
    "fmt"
)
func main() {
    // Generate ed25519 key pair
    _, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return
    }
    privHex := hex.EncodeToString(priv)
    pubHex := hex.EncodeToString(priv[32:]) // Public key is last 32 bytes
    
    // Generate short ID (8 bytes)
    shortID := make([]byte, 8)
    rand.Read(shortID)
    shortIDHex := hex.EncodeToString(shortID)
    
    fmt.Printf("priv=%s\n", privHex)
    fmt.Printf("pub=%s\n", pubHex)
    fmt.Printf("shortid=%s\n", shortIDHex)
}
XHTTPKEYGEN

# Генерируем ключи
log_info "Запуск генератора ключей..."
log_info "Go команда: $GO_CMD"
log_info "Скрипт: $XHTTP_KEYGEN_SCRIPT"

# Проверяем, что скрипт создан
if [[ ! -f "$XHTTP_KEYGEN_SCRIPT" ]]; then
    log_error "Не удалось создать Go скрипт генерации ключей"
    exit 1
fi

log_info "Выполнение: $GO_CMD run $XHTTP_KEYGEN_SCRIPT"
XHTTP_KEYGEN_OUTPUT=$("$GO_CMD" run "$XHTTP_KEYGEN_SCRIPT" 2>&1)
XHTTP_KEYGEN_EXIT=$?

log_info "Код выхода Go: $XHTTP_KEYGEN_EXIT"
log_info "Полный вывод генератора:"
echo "---"
echo "$XHTTP_KEYGEN_OUTPUT"
echo "---"

if [[ $XHTTP_KEYGEN_EXIT -ne 0 ]]; then
    log_error "Ошибка выполнения Go скрипта генерации ключей (код: $XHTTP_KEYGEN_EXIT)"
    log_error "Проверьте, что Go установлен и работает: $GO_CMD version"
    rm -f "$XHTTP_KEYGEN_SCRIPT"
    exit 1
fi

rm -f "$XHTTP_KEYGEN_SCRIPT"

# Извлекаем ключи (более надежный способ)
XHTTP_PRIV=$(echo "$XHTTP_KEYGEN_OUTPUT" | grep "^priv=" | sed 's/^priv=//' | tr -d ' \r\n')
XHTTP_PUB=$(echo "$XHTTP_KEYGEN_OUTPUT" | grep "^pub=" | sed 's/^pub=//' | tr -d ' \r\n')
XHTTP_SHORT_ID=$(echo "$XHTTP_KEYGEN_OUTPUT" | grep "^shortid=" | sed 's/^shortid=//' | tr -d ' \r\n')

# Отладочная информация
log_info "Результаты извлечения ключей:"
echo "  XHTTP_PRIV: ${XHTTP_PRIV:0:20}... (длина: ${#XHTTP_PRIV}, ожидается: 128)"
echo "  XHTTP_PUB: ${XHTTP_PUB:0:20}... (длина: ${#XHTTP_PUB}, ожидается: 64)"
echo "  XHTTP_SHORT_ID: ${XHTTP_SHORT_ID:0:10}... (длина: ${#XHTTP_SHORT_ID}, ожидается: 16)"

# Проверяем ключи
# ed25519 приватный ключ: 64 байта = 128 hex символов
# ed25519 публичный ключ: 32 байта = 64 hex символа
# Short ID: 8 байт = 16 hex символов
if [[ ${#XHTTP_PRIV} -ne 128 ]] || [[ ${#XHTTP_PUB} -ne 64 ]] || [[ ${#XHTTP_SHORT_ID} -ne 16 ]]; then
    log_error "Ошибка генерации XHTTP ключей - неправильные длины"
    log_error "Ожидаемые длины: priv=128 (64 байта), pub=64 (32 байта), shortid=16 (8 байт)"
    log_error "Полученные длины: priv=${#XHTTP_PRIV}, pub=${#XHTTP_PUB}, shortid=${#XHTTP_SHORT_ID}"
    log_error "Проверка извлечения:"
    echo "  Вывод содержит 'priv=': $(echo "$XHTTP_KEYGEN_OUTPUT" | grep -c "^priv=" || echo "0")"
    echo "  Вывод содержит 'pub=': $(echo "$XHTTP_KEYGEN_OUTPUT" | grep -c "^pub=" || echo "0")"
    echo "  Вывод содержит 'shortid=': $(echo "$XHTTP_KEYGEN_OUTPUT" | grep -c "^shortid=" || echo "0")"
    log_error "Полный вывод генератора был показан выше"
    exit 1
fi

# Включаем обратно строгий режим после успешной генерации
set -e

log_success "XHTTP ключи сгенерированы"

# Сохраняем ключи
echo "$XHTTP_PRIV" > "$WORK_DIR/.env.xhttp.priv"
echo "$XHTTP_PUB" > "$WORK_DIR/.env.xhttp.pub"
echo "$XHTTP_SHORT_ID" > "$WORK_DIR/.env.xhttp.shortid"

# Получаем IP сервера
EXTERNAL_IP=$(curl -s4 https://api.ipify.org 2>/dev/null || \
              curl -s4 https://icanhazip.com 2>/dev/null || \
              curl -s4 https://ifconfig.me 2>/dev/null || \
              hostname -I | awk '{print $1}' || echo "YOUR_SERVER_IP")

# Настройка XHTTP Server Name (можно использовать домен или IP)
XHTTP_SERVER_NAME="${1:-example.com}"
XHTTP_TARGET="${EXTERNAL_IP}:4443"

# Сохраняем server name
echo "$XHTTP_SERVER_NAME" > "$WORK_DIR/.env.xhttp.server_name"

log_info "XHTTP конфигурация:"
echo "  XHTTP Public Key: $XHTTP_PUB"
echo "  XHTTP Short ID: $XHTTP_SHORT_ID"
echo "  XHTTP Server Name: $XHTTP_SERVER_NAME"
echo "  XHTTP Target: $XHTTP_TARGET"

# Обновляем systemd service файл
if [[ -f "/etc/systemd/system/whispera-server.service" ]]; then
    log_info "Обновление systemd service файла..."
    
    # Извлекаем существующие параметры
    WORK_DIR_SERVICE=$(grep "^WorkingDirectory=" /etc/systemd/system/whispera-server.service | cut -d'=' -f2)
    [[ -z "$WORK_DIR_SERVICE" ]] && WORK_DIR_SERVICE="/opt/whispera"
    
    SERVER_BINARY="$WORK_DIR_SERVICE/whispera-server"
    [[ ! -f "$SERVER_BINARY" ]] && SERVER_BINARY="/opt/whispera/whispera-server"
    
    # Извлекаем существующие ключи сервера
    SERVER_PRIV=$(grep -E "\-static-key[[:space:]]+" /etc/systemd/system/whispera-server.service 2>/dev/null | \
        sed 's/.*-static-key[[:space:]]*\([^[:space:]]*\).*/\1/' | head -1)
    if [[ -z "$SERVER_PRIV" ]] && [[ -f "$WORK_DIR/.env.server" ]]; then
        SERVER_PRIV=$(cat "$WORK_DIR/.env.server" 2>/dev/null)
    fi
    
    # Строим ExecStart
    EXEC_START="$SERVER_BINARY \\
  -listen 0.0.0.0:51820 \\
  -listen-tcp 0.0.0.0:4443 \\
  -listen-ws 0.0.0.0:8080 \\
  -listen-ws2 0.0.0.0:8443"
    
    if [[ -n "$SERVER_PRIV" ]]; then
        EXEC_START="$EXEC_START \\
  -static-key ${SERVER_PRIV}"
    fi
    
    EXEC_START="$EXEC_START \\
  -api 0.0.0.0:8081 \\
  -metrics 0.0.0.0:9101 \\
  -obfs-preset quic \\
  -audit \\
  -xhttp-target ${XHTTP_TARGET} \\
  -xhttp-server-names ${XHTTP_SERVER_NAME} \\
  -xhttp-private-key ${XHTTP_PRIV} \\
  -xhttp-short-id ${XHTTP_SHORT_ID}"
    
    # Добавляем TLS если есть сертификаты
    TLS_CERT="$WORK_DIR/tls/cert.pem"
    TLS_KEY="$WORK_DIR/tls/key.pem"
    if [[ -f "$TLS_CERT" ]] && [[ -f "$TLS_KEY" ]]; then
        EXEC_START="$EXEC_START \\
  -tls-cert ${TLS_CERT} \\
  -tls-key ${TLS_KEY} \\
  -api-tls \\
  -tls"
    fi
    
    # Пересоздаем service файл полностью (надежнее, чем редактирование)
    cat > /etc/systemd/system/whispera-server.service <<EOFSERVICE
[Unit]
Description=Whispera VPN Server
After=network-online.target whispera-ml.service
Wants=network-online.target whispera-ml.service

[Service]
Type=simple
User=root
WorkingDirectory=${WORK_DIR_SERVICE}
ExecStart=${EXEC_START}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

Environment=WHISPERA_WEB_DIR=${WORK_DIR_SERVICE}/web
Environment=WHISPERA_ML_SERVER=http://127.0.0.1:8000

# Wait for ML service to be ready before starting (increased timeout for TensorFlow loading)
ExecStartPre=/bin/bash -c 'for i in {1..60}; do if curl -s -f --max-time 2 http://127.0.0.1:8000/health >/dev/null 2>&1 || curl -s --max-time 2 http://127.0.0.1:8000/ >/dev/null 2>&1; then exit 0; fi; sleep 2; done; echo "Warning: ML service not ready, starting anyway"; exit 0'

[Install]
WantedBy=multi-user.target
EOFSERVICE
    systemctl daemon-reload
    log_success "Systemd service файл обновлен"
fi

# Обновляем connection-info.txt
log_info "Обновление connection-info.txt..."

# Загружаем существующие ключи сервера и клиента
SERVER_PUB=$(cat "$WORK_DIR/.env.server.pub" 2>/dev/null || echo "")
CLIENT_PRIV=$(cat "$WORK_DIR/.env.client" 2>/dev/null || echo "")

if [[ -z "$SERVER_PUB" ]] || [[ -z "$CLIENT_PRIV" ]]; then
    log_error "Не найдены ключи сервера или клиента!"
    log_error "SERVER_PUB: ${SERVER_PUB:0:20}... (длина: ${#SERVER_PUB})"
    log_error "CLIENT_PRIV: ${CLIENT_PRIV:0:20}... (длина: ${#CLIENT_PRIV})"
    log_error "Проверьте файлы: $WORK_DIR/.env.server.pub и $WORK_DIR/.env.client"
    exit 1
fi

# Генерируем Quick Connect URL с XHTTP параметрами
# Формат: whispera://IP:PORT?pub=SERVER_PUB&key=CLIENT_PRIV&xhttpPub=XHTTP_PUB&xhttpShortId=XHTTP_SHORT_ID&xhttpServerName=XHTTP_SERVER_NAME&xhttpFingerprint=chrome
QUICK_CONNECT_URL="whispera://${EXTERNAL_IP}:51820?pub=${SERVER_PUB}&key=${CLIENT_PRIV}&xhttpPub=${XHTTP_PUB}&xhttpShortId=${XHTTP_SHORT_ID}&xhttpServerName=${XHTTP_SERVER_NAME}&xhttpFingerprint=chrome"

cat > "$WORK_DIR/connection-info.txt" <<EOF
# Whispera Server Connection Info
# ===============================

SERVER_IP: ${EXTERNAL_IP}
SERVER_PORT: 51820 (UDP/DTLS)
SERVER_TCP_PORT: 4443 (TLS)
SERVER_WS_PORT: 8080 (wss://)
SERVER_WS2_PORT: 8443 (wss://)
API_PORT: 8081 (https://)

SERVER_PUBLIC_KEY: ${SERVER_PUB}
CLIENT_PRIVATE_KEY: ${CLIENT_PRIV}

# XHTTP Configuration (for XHTTP+VLESS with Marionette obfuscation):
XHTTP_PUBLIC_KEY: ${XHTTP_PUB}
XHTTP_SHORT_ID: ${XHTTP_SHORT_ID}
XHTTP_SERVER_NAME: ${XHTTP_SERVER_NAME}
XHTTP_TARGET: ${XHTTP_TARGET}

# Quick Connect Key for Tauri client (whispera:// format):
${QUICK_CONNECT_URL}

# WebSocket URLs:
# WS: wss://${EXTERNAL_IP}:8080/ws
# WS2: wss://${EXTERNAL_IP}:8443/ws

# Web Panel:
# URL: https://${EXTERNAL_IP}:8081
# Login: admin
# Password: admin
# All services use HTTPS/TLS (self-signed certificate)
EOF

log_success "connection-info.txt обновлен"

# Перезапускаем сервер
log_info "Перезапуск сервера..."
systemctl restart whispera-server

# Ждем запуска
sleep 3
if systemctl is-active --quiet whispera-server; then
    log_success "Сервер перезапущен успешно"
else
    log_warning "Сервер может не запуститься, проверьте логи: journalctl -u whispera-server -n 50"
fi

echo ""
log_success "✅ XHTTP+VLESS с Marionette обфускацией настроен!"
echo ""
log_info "📋 Информация для подключения:"
echo "  XHTTP Public Key: $XHTTP_PUB"
echo "  XHTTP Short ID: $XHTTP_SHORT_ID"
echo "  XHTTP Server Name: $XHTTP_SERVER_NAME"
echo ""
log_success "🔑 Quick Connect Key (скопируйте и вставьте в клиент):"
echo ""
echo "$QUICK_CONNECT_URL"
echo ""
log_info "📋 Инструкция:"
echo "  1. Скопируйте ключ выше (whispera://...)"
echo "  2. В клиенте вставьте в поле 'Ключ подключения'"
echo "  3. Нажмите 'Подключиться по ключу'"
echo ""
log_info "📄 Вся информация сохранена в: $WORK_DIR/connection-info.txt"
echo ""

