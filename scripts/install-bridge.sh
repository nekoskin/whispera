#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

MAIN_SERVER=""
REG_TOKEN=""
BRIDGE_TYPE="operator"
PROVIDER="unknown"
LISTEN_PORT="443"
RUSSIAN_SERVICE="vk"
DEST_SITE=""
ENABLE_OBFUSCATION="false"
ENABLE_SNI_ROTATION="true"
ENABLE_COVER_TRAFFIC="true"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/whispera"

while [[ $# -gt 0 ]]; do
    case $1 in
        --type)
            BRIDGE_TYPE="$2"
            shift 2
            ;;
        --provider)
            PROVIDER="$2"
            shift 2
            ;;
        --port)
            LISTEN_PORT="$2"
            shift 2
            ;;
        --russian-service)
            RUSSIAN_SERVICE="$2"
            shift 2
            ;;
        --dest)
            DEST_SITE="$2"
            shift 2
            ;;
        --obfuscation)
            ENABLE_OBFUSCATION="true"
            shift
            ;;
        --sni-rotation)
            ENABLE_SNI_ROTATION="true"
            shift
            ;;
        --cover-traffic)
            ENABLE_COVER_TRAFFIC="true"
            shift
            ;;
        -*)
            log_error "Unknown option: $1"
            ;;
        *)
            if [ -z "$MAIN_SERVER" ]; then
                MAIN_SERVER="$1"
            elif [ -z "$REG_TOKEN" ]; then
                REG_TOKEN="$1"
            fi
            shift
            ;;
    esac
done

if [ -z "$MAIN_SERVER" ]; then
    log_info "No server specified, trying DNS discovery..."
    
    if command -v dig &> /dev/null; then
        for domain in "whispera.local" "vpn.local" "bridge.local"; do
            SRV_RESULT=$(dig +short _whispera._tcp.$domain SRV 2>/dev/null | head -1)
            if [ -n "$SRV_RESULT" ]; then
                PORT=$(echo $SRV_RESULT | awk '{print $3}')
                HOST=$(echo $SRV_RESULT | awk '{print $4}' | sed 's/\.$//')
                MAIN_SERVER="$HOST:$PORT"
                log_info "Discovered via DNS: $MAIN_SERVER"
                break
            fi
        done
    fi
    
    if [ -z "$MAIN_SERVER" ] && command -v dig &> /dev/null; then
        TXT_RESULT=$(dig +short whispera-server.local TXT 2>/dev/null | tr -d '"')
        if [ -n "$TXT_RESULT" ]; then
            MAIN_SERVER="$TXT_RESULT"
            log_info "Discovered via TXT: $MAIN_SERVER"
        fi
    fi
    
    if [ -z "$MAIN_SERVER" ]; then
        log_error "Usage: $0 <MAIN_SERVER_ADDRESS:PORT> <REGISTRATION_TOKEN> [OPTIONS]
        
Or configure DNS SRV record:
  _whispera._tcp.yourdomain.com SRV 0 0 443 vpn.yourdomain.com"
    fi
fi

if [ -z "$REG_TOKEN" ]; then
    log_error "Registration token is required. Get it from Web Panel → Bridges → Get Token"
fi

log_info "Installing Whispera Bridge..."
log_info "Main Server: $MAIN_SERVER"
log_info "Bridge Type: $BRIDGE_TYPE"
log_info "Provider: $PROVIDER"
log_info "Listen Port: $LISTEN_PORT"
log_info "Russian Service: $RUSSIAN_SERVICE"

if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root (sudo)"
fi

ARCH=$(uname -m)
case $ARCH in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *)       log_error "Unsupported architecture: $ARCH" ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')

mkdir -p "$CONFIG_DIR"
mkdir -p "$INSTALL_DIR"

log_info "Downloading Whispera Bridge binary..."
DOWNLOAD_URL="https://github.com/your-repo/whispera/releases/latest/download/whispera-${OS}-${ARCH}"

if command -v curl &> /dev/null; then
    curl -fsSL "$DOWNLOAD_URL" -o "$INSTALL_DIR/whispera-bridge" || {
        log_warn "Failed to download from GitHub, trying alternative..."
        if [ -f "./whispera-server" ]; then
            cp ./whispera-server "$INSTALL_DIR/whispera-bridge"
        else
            log_error "Could not download binary and no local binary found"
        fi
    }
elif command -v wget &> /dev/null; then
    wget -q "$DOWNLOAD_URL" -O "$INSTALL_DIR/whispera-bridge" || {
        log_warn "Download failed"
    }
fi

chmod +x "$INSTALL_DIR/whispera-bridge"

log_info "Generating keys..."
PRIVATE_KEY=$("$INSTALL_DIR/whispera-bridge" keygen 2>/dev/null || openssl rand -base64 32)

log_info "Creating configuration..."
cat > "$CONFIG_DIR/bridge.yaml" <<EOF

relay_mode: bridge
upstream_server: "${MAIN_SERVER}"

server:
  listen_addr: ":${LISTEN_PORT}"

bridge:
  auto_register: true
  type: ${BRIDGE_TYPE}
  provider: ${PROVIDER}
  registration_token: "${REG_TOKEN}"

phantom:
  enabled: true
  private_key: "${PRIVATE_KEY}"
  use_russian_service: true
  russian_service_name: ${RUSSIAN_SERVICE}
  dest: "${DEST_SITE}"
  enable_obfuscation: ${ENABLE_OBFUSCATION}
  enable_sni_rotation: ${ENABLE_SNI_ROTATION}
  enable_cover_traffic: ${ENABLE_COVER_TRAFFIC}

logging:
  level: info
EOF

log_info "Creating systemd service..."
cat > /etc/systemd/system/whispera-bridge.service <<EOF
[Unit]
Description=Whispera Bridge
Documentation=https://github.com/your-repo/whispera
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/whispera-bridge -c ${CONFIG_DIR}/bridge.yaml
Restart=always
RestartSec=5
LimitNOFILE=65535

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${CONFIG_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

log_info "Configuring firewall..."
if command -v ufw &> /dev/null; then
    ufw allow ${LISTEN_PORT}/tcp
    ufw --force enable
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=${LISTEN_PORT}/tcp
    firewall-cmd --reload
fi

log_info "Starting Whispera Bridge..."
systemctl daemon-reload
systemctl enable whispera-bridge
systemctl start whispera-bridge

sleep 3
if systemctl is-active --quiet whispera-bridge; then
    log_info "✓ Whispera Bridge is running!"
    
    PUBLIC_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || echo "UNKNOWN")
    
    echo ""
    echo "========================================"
    echo "  Bridge Installation Complete!"
    echo "========================================"
    echo ""
    echo "  Bridge Address: ${PUBLIC_IP}:${LISTEN_PORT}"
    echo "  Main Server:    ${MAIN_SERVER}"
    echo "  Bridge Type:    ${BRIDGE_TYPE}"
    echo "  SNI Service:    ${RUSSIAN_SERVICE}"
    echo "  Camouflage:     ${DEST_SITE:-auto}"
    echo "  Obfuscation:    ${ENABLE_OBFUSCATION}"
    echo ""
    echo "  Config file: ${CONFIG_DIR}/bridge.yaml"
    echo "  Logs: journalctl -u whispera-bridge -f"
    echo ""
    echo "========================================"
else
    log_error "Bridge failed to start. Check logs: journalctl -u whispera-bridge"
fi
