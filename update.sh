#!/bin/bash
# Whispera Update Script

WORK_DIR="/opt/whispera"
BIN_PATH="/usr/local/bin"
DAT_PATH="/usr/local/share/whispera"
CONF_PATH="/etc/whispera"

# Colors
GREEN='\033[0;32m'
PLAIN='\033[0m'
BLUE='\033[0;34m'

log_success() { echo -e "${GREEN}[OK]${PLAIN} $1"; }
log_info() { echo -e "${BLUE}[INFO]${PLAIN} $1"; }

get_public_ip() {
    local IP=$(curl -s https://api.ipify.org -m 5)
    if [[ -z "$IP" ]]; then
        IP=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -n1)
    fi
    echo "${IP:-localhost}"
}

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "Updating Whispera..."

cd "$WORK_DIR" || exit 1

echo "Building server..."
export PATH=$PATH:/usr/local/go/bin
# Clean old binary first
rm -f whispera-server
# Build
go build -trimpath -ldflags "-w -s" -o whispera-server ./cmd/server

if [[ ! -f "whispera-server" ]]; then
    echo "Build failed! No binary created."
    exit 1
fi

echo "Stopping service..."
systemctl stop whispera
sleep 2

echo "Updating binary..."
# Backup old binary to avoid "Text file busy"
if [[ -f "$BIN_PATH/whispera" ]]; then
    mv "$BIN_PATH/whispera" "$BIN_PATH/whispera.old"
fi
cp whispera-server "$BIN_PATH/whispera"
chmod +x "$BIN_PATH/whispera"

echo "Updating Web UI..."
if [[ -d "web" ]]; then
    # Clean old web files
    rm -rf "$DAT_PATH/web/*"
    mkdir -p "$DAT_PATH/web"
    cp -r web/* "$DAT_PATH/web/"
fi

echo "Updating configuration..."
# Read existing private key or generate new one
PRIVATE_KEY=$(grep "private_key:" "$CONF_PATH/config.yaml" 2>/dev/null | awk '{print $2}' | tr -d '"' | head -n1)
if [[ -z "$PRIVATE_KEY" ]] || [[ "$PRIVATE_KEY" == "\"\"" ]]; then
    PRIVATE_KEY="ebd931eb66a8f6345a7f789ea6c2f284ea8012aaddc0fa728cdcbb7891483f09"
fi

# Regenerate config with phantom enabled
cat > "$CONF_PATH/config.yaml" << EOF
server:
  name: whispera-server
  listen_addr: "0.0.0.0:8443"
  mtu: 1420
  workers: 8

transport:
  udp:
    enabled: true
    listen_addr: ":8443"
  tcp:
    enabled: false
    listen_addr: ":8443"
  websocket:
    enabled: true
    listen_addr: ":8080"

phantom:
  enabled: true
  dest: "yandex.ru:443"
  server_names:
    - "sberbank.ru"
    - "tinkoff.ru"
    - "yandex.ru"
    - "mail.ru"
    - "rambler.ru"
    - "ya.ru"
    - "vk.com"
    - "ok.ru"
    - "dzen.ru"
    - "rutube.ru"
    - "ozon.ru"
    - "wildberries.ru"
    - "avito.ru"
    - "mos.ru"
    - "gosuslugi.ru"
  private_key: "$PRIVATE_KEY"
  max_time_diff: 60
EOF

echo "Restarting service..."
systemctl start whispera

echo ""
log_success "Whispera updated successfully!"
echo -e "  Manage command: ${GREEN}whispera-mgmt${PLAIN}"
echo -e "  Config file:    ${GREEN}$CONF_PATH/config.yaml${PLAIN}"
SERVER_IP=$(get_public_ip)
echo -e "  Web Interface:  ${GREEN}http://${SERVER_IP}:8080${PLAIN}"
echo -e "Update dependencies: apt-get update"
