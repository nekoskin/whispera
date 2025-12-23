#!/bin/bash
# Whispera Update Script
# Updates code, rebuilds, and restarts services after git pull

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Ensure required iptables rules (MASQUERADE + FORWARD) exist
ensure_iptables() {
    log_info "Checking iptables rules (NAT & FORWARD)"

    # Enable IPv4 forwarding at runtime
    if sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
        log_success "IPv4 forwarding enabled"
    else
        log_warning "Failed to enable net.ipv4.ip_forward (might require reboot)"
    fi

    # NAT: MASQUERADE for RFC2544 / RFC1918 ranges used by Whispera (198.18.0.0/15 and 10.0.0.0/8)
    for SUBNET in 198.18.0.0/15 10.0.0.0/8; do
        if ! iptables -t nat -C POSTROUTING -s "$SUBNET" -o $(ip route get 1.1.1.1 | awk '{print $5; exit}') -j MASQUERADE 2>/dev/null; then
            iptables -t nat -A POSTROUTING -s "$SUBNET" -o $(ip route get 1.1.1.1 | awk '{print $5; exit}') -j MASQUERADE
            log_success "Added MASQUERADE for $SUBNET"
        fi
    done

    # Accept FORWARD traffic related/established first (idempotent insert at line 1)
    if ! iptables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
        iptables -I FORWARD 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        log_success "FORWARD rule RELATED,ESTABLISHED inserted"
    fi

    # Accept ICMP & TCP 443 to/from Whispera subnet (198.18.0.0/30)
    for PROTO in icmp tcp; do
        RULE_EXISTS=$(iptables -C FORWARD -p $PROTO -s 198.18.0.0/30 -j ACCEPT 2>/dev/null && echo yes || echo no)
        if [[ $RULE_EXISTS == no ]]; then
            if [[ $PROTO == tcp ]]; then
                iptables -A FORWARD -p tcp --dport 443 -s 198.18.0.0/30 -j ACCEPT
                iptables -A FORWARD -p tcp --sport 443 -d 198.18.0.0/30 -j ACCEPT
            else
                iptables -A FORWARD -p icmp -s 198.18.0.0/30 -j ACCEPT
                iptables -A FORWARD -p icmp -d 198.18.0.0/30 -j ACCEPT
            fi
            log_success "FORWARD rules for $PROTO added"
        fi
    done

    # Save rules if iptables-persistent is present
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 && log_success "iptables rules saved via netfilter-persistent"
    fi
}

# Ensure Whispera TUN/WireGuard interface has 198.18.0.2/30 and route
ensure_whispera_route() {
    local IFACE
    IFACE=$(ip -br addr | awk '/^(wg[0-9]+|tun[0-9]+|whispera[0-9]*)/ {print $1; exit}')

    if [[ -z "$IFACE" ]]; then
        log_warning "Whispera TUN/WG interface not found (expected tun0 or wg0) — skipping subnet setup"
        return
    fi

    if ! ip -4 addr show dev "$IFACE" | grep -q "198.18.0.2/30"; then
        ip addr add 198.18.0.2/30 dev "$IFACE" || true
        log_success "Assigned 198.18.0.2/30 to $IFACE"
    fi

    if ! ip route show | grep -q "198.18.0.0/30 dev $IFACE"; then
        ip route add 198.18.0.0/30 dev "$IFACE" || true
        log_success "Route 198.18.0.0/30 via $IFACE added"
    fi
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (use sudo)"
    exit 1
fi

log_info "🔄 Whispera Update Script"
log_info "========================"
echo ""

# --- Network prerequisites -------------------------------------------------
ensure_iptables          # NAT + FORWARD rules
# ---------------------------------------------------------------------------

# Detect working directory
WORK_DIR="/opt/whispera"
if [[ ! -d "$WORK_DIR" ]]; then
    # Try current directory
    if [[ -f "go.mod" ]]; then
        WORK_DIR="$(pwd)"
        log_info "Using current directory: $WORK_DIR"
    else
        log_error "Whispera installation not found. Run install.sh first."
        exit 1
    fi
fi

cd "$WORK_DIR"

# Ensure Go is in PATH
if [[ -f "/usr/local/go/bin/go" ]]; then
    export PATH="/usr/local/go/bin:$PATH"
    export GOROOT="/usr/local/go"
fi

GO_CMD=$(command -v go || echo "/usr/local/go/bin/go")
if [[ ! -x "$GO_CMD" ]]; then
    log_error "Go not found. Please install Go first."
    exit 1
fi

GO_VER=$($GO_CMD version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+(\.[0-9]+)?' | sed 's/go//' || echo "unknown")
log_info "Using Go ${GO_VER} from: $GO_CMD"

# Backup current server binary (server doesn't need client)
log_info "Backing up current server binary..."
BACKUP_DIR="$WORK_DIR/backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
if [[ -f "$WORK_DIR/whispera-server" ]]; then
    cp "$WORK_DIR/whispera-server" "$BACKUP_DIR/" 2>/dev/null || true
fi
log_success "Backup created in: $BACKUP_DIR"

# Update from git
log_info "Updating code from git..."
if [[ -d ".git" ]]; then
    # Always reset go.mod and go.sum before pull (they will be regenerated by go mod tidy)
    # This prevents merge conflicts with these files
    log_info "Resetting go.mod/go.sum to prevent merge conflicts (will be regenerated)..."
    git checkout -- go.mod go.sum 2>/dev/null || {
        log_warning "Failed to reset go.mod/go.sum, trying stash..."
        git stash push -m "Auto-stash before update $(date +%Y%m%d-%H%M%S)" go.mod go.sum 2>/dev/null || true
    }
    
    # Try to pull
    GIT_PULL_OUTPUT=$(git pull 2>&1)
    GIT_PULL_EXIT=$?
    
    if [[ $GIT_PULL_EXIT -eq 0 ]]; then
        log_success "Code updated from git"
    else
        # Check if pull failed due to merge conflicts
        if echo "$GIT_PULL_OUTPUT" | grep -q "would be overwritten by merge"; then
            log_warning "Merge conflicts detected, attempting to resolve..."
            # Extract conflicting files from error message
            # Error format: "error: Your local changes to the following files would be overwritten by merge:\n        file1\n        file2"
            CONFLICT_FILES=$(echo "$GIT_PULL_OUTPUT" | sed -n '/would be overwritten by merge:/,/Please commit/p' | grep -v "would be overwritten\|Please commit" | sed 's/^[[:space:]]*//' | grep -v '^$')
            
            # Reset all conflicting files
            for file in $CONFLICT_FILES; do
                if [[ -n "$file" ]]; then
                    log_info "Resetting conflicting file: $file"
                    git checkout -- "$file" 2>/dev/null || true
                fi
            done
            
            # Try pull again
            if git pull; then
                log_success "Code updated after resolving conflicts"
            else
                log_warning "git pull failed after conflict resolution, continuing with existing code..."
            fi
        else
            log_warning "git pull failed: $GIT_PULL_OUTPUT"
            log_warning "Continuing with existing code..."
        fi
    fi
else
    log_warning "Not a git repository, skipping git pull"
fi

# Update dependencies
log_info "Updating Go dependencies..."
export GO111MODULE=on
export CGO_ENABLED=0
export GOTOOLCHAIN=local
export GOFLAGS="-mod=mod"

$GO_CMD mod tidy || {
    log_warning "go mod tidy failed, continuing..."
}

# Build server binary only (server doesn't need client)
log_info "Building Whispera server..."

# Source build functions if available
if [[ -f "scripts/lib/build.sh" ]]; then
    source "scripts/lib/build.sh"
    # Build only server, not client
    build_server "$WORK_DIR" "$WORK_DIR/whispera-server" "$GO_CMD" "false"
else
    # Fallback: simple build
    log_info "Building with go build..."
    
    $GO_CMD build -mod=mod -o "$WORK_DIR/whispera-server" ./cmd/server || {
        log_error "Server build failed"
        log_info "Restoring from backup..."
        if [[ -f "$BACKUP_DIR/whispera-server" ]]; then
            cp "$BACKUP_DIR/whispera-server" "$WORK_DIR/whispera-server"
        fi
        exit 1
    }
fi

log_success "Server build completed"

# Note: Client is built on client machines (Windows) using run-dev.bat, not on the server
# Client binary is not needed on the server

# Restart services
log_info "Restarting services..."

# Patch systemd unit
if [[ -f "/etc/systemd/system/whispera-server.service" ]]; then
    # First, check if service file is broken and fix it
    if systemctl cat whispera-server.service 2>&1 | grep -qE "Missing '='|unknown escape|Invalid" || \
       ! systemd-analyze verify whispera-server.service >/dev/null 2>&1; then
        log_warning "Detected broken systemd service file, attempting to repair..."
        
        # Extract working directory
        WORK_DIR=$(grep "^WorkingDirectory=" /etc/systemd/system/whispera-server.service 2>/dev/null | cut -d'=' -f2)
        [[ -z "$WORK_DIR" ]] && WORK_DIR="/opt/whispera"
        
        # Find server binary
        SERVER_BINARY="$WORK_DIR/whispera-server"
        [[ ! -f "$SERVER_BINARY" ]] && SERVER_BINARY="/opt/whispera/whispera-server"
        
        # Extract static key from existing file or env
        SERVER_PRIV=$(grep -E "\-static-key[[:space:]]+" /etc/systemd/system/whispera-server.service 2>/dev/null | \
            sed 's/.*-static-key[[:space:]]*\([^[:space:]]*\).*/\1/' | head -1)
        if [[ -z "$SERVER_PRIV" ]] && [[ -f "$WORK_DIR/.env.server.priv" ]]; then
            SERVER_PRIV=$(cat "$WORK_DIR/.env.server.priv" 2>/dev/null)
        fi
        
        # Build basic ExecStart
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
  -core-enable"
        
        # Extract and add XHTTP flags if present
        if [[ -f "$WORK_DIR/.env.xhttp.priv" ]] && [[ -f "$WORK_DIR/.env.xhttp.shortid" ]]; then
            XHTTP_PRIV=$(cat "$WORK_DIR/.env.xhttp.priv" 2>/dev/null)
            XHTTP_SHORT_ID=$(cat "$WORK_DIR/.env.xhttp.shortid" 2>/dev/null)
            XHTTP_SERVER_NAME=$(cat "$WORK_DIR/.env.xhttp.server_name" 2>/dev/null || echo "example.com")
            EXTERNAL_IP=$(curl -s4 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
            XHTTP_TARGET="${EXTERNAL_IP}:4443"
            EXEC_START="$EXEC_START \\
  -xhttp-target ${XHTTP_TARGET} \\
  -xhttp-server-names ${XHTTP_SERVER_NAME} \\
  -xhttp-private-key ${XHTTP_PRIV} \\
  -xhttp-short-id ${XHTTP_SHORT_ID}"
        fi
        
        # Extract and add TLS flags if present
        TLS_CERT="$WORK_DIR/tls/cert.pem"
        TLS_KEY="$WORK_DIR/tls/key.pem"
        if [[ -f "$TLS_CERT" ]] && [[ -f "$TLS_KEY" ]]; then
            EXEC_START="$EXEC_START \\
  -tls-cert ${TLS_CERT} \\
  -tls-key ${TLS_KEY} \\
  -api-tls \\
  -tls"
        fi
        
        # Backup broken file
        cp /etc/systemd/system/whispera-server.service /etc/systemd/system/whispera-server.service.broken.$(date +%Y%m%d_%H%M%S) 2>/dev/null
        
        # Regenerate service file properly
        cat > /etc/systemd/system/whispera-server.service <<EOFSERVICE
[Unit]
Description=Whispera VPN Server
After=network-online.target whispera-ml.service
Wants=network-online.target whispera-ml.service

[Service]
Type=simple
User=root
WorkingDirectory=${WORK_DIR}
ExecStart=${EXEC_START}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

Environment=WHISPERA_WEB_DIR=${WORK_DIR}/web
Environment=WHISPERA_ML_SERVER=http://127.0.0.1:8000

ExecStartPre=/bin/bash -c 'for i in {1..60}; do if curl -s -f --max-time 2 http://127.0.0.1:8000/health >/dev/null 2>&1 || curl -s --max-time 2 http://127.0.0.1:8000/ >/dev/null 2>&1; then exit 0; fi; sleep 2; done; echo "Warning: ML service not ready, starting anyway"; exit 0'

[Install]
WantedBy=multi-user.target
EOFSERVICE
        
        systemctl daemon-reload
        log_success "Service file repaired"
    fi
    
    UPDATED=0
    # ensure -audit flag
    if ! grep -qE "(ExecStart=|^[[:space:]]+).*-audit" /etc/systemd/system/whispera-server.service; then
        log_info "Enabling -audit flag for whispera-server systemd service..."
        # Use awk to handle both single-line and multi-line ExecStart properly
        # Find the last line of ExecStart (doesn't end with \) and append " -audit"
        awk '
        BEGIN { in_execstart = 0; last_line = 0 }
        /^ExecStart=/ { 
            in_execstart = 1
            last_line = NR
            if ($0 !~ /\\$/) {
                # Single-line ExecStart
                print $0 " -audit"
                in_execstart = 0
                next
            } else {
                print
                next
            }
        }
        in_execstart && /^[[:space:]]/ {
            # Continuation line
            last_line = NR
            if ($0 !~ /\\$/) {
                # Last line of ExecStart block
                print $0 " -audit"
                in_execstart = 0
                next
            } else {
                print
                next
            }
        }
        in_execstart && /^[^[:space:]]/ {
            # ExecStart block ended, add -audit to previous line if needed
            in_execstart = 0
            print
            next
        }
        { print }
        ' /etc/systemd/system/whispera-server.service > /tmp/whispera-server.service.tmp && \
        mv /tmp/whispera-server.service.tmp /etc/systemd/system/whispera-server.service && \
        UPDATED=1 || log_warning "Failed to add -audit flag, service file may need manual editing"
    fi

    # ensure -core-enable flag (для IntegrationManager/Marionette на сервере)
    if ! grep -qE "(ExecStart=|^[[:space:]]+).*-core-enable" /etc/systemd/system/whispera-server.service; then
        log_info "Enabling -core-enable flag for whispera-server systemd service..."
        awk '
        BEGIN { in_execstart = 0; last_line = 0 }
        /^ExecStart=/ {
            in_execstart = 1
            last_line = NR
            if ($0 !~ /\\$/) {
                # Single-line ExecStart
                print $0 " -core-enable"
                in_execstart = 0
                next
            } else {
                print
                next
            }
        }
        in_execstart && /^[[:space:]]/ {
            # Continuation line
            last_line = NR
            if ($0 !~ /\\$/) {
                # Last line of ExecStart block
                print $0 " -core-enable"
                in_execstart = 0
                next
            } else {
                print
                next
            }
        }
        in_execstart && /^[^[:space:]]/ {
            # ExecStart block ended
            in_execstart = 0
            print
            next
        }
        { print }
        ' /etc/systemd/system/whispera-server.service > /tmp/whispera-server.service.tmp && \
        mv /tmp/whispera-server.service.tmp /etc/systemd/system/whispera-server.service && \
        UPDATED=1 || log_warning "Failed to add -core-enable flag, service file may need manual editing"
    fi
    
    # ensure XHTTP flags if keys exist
    if [[ -f "$WORK_DIR/.env.xhttp.priv" ]] && [[ -f "$WORK_DIR/.env.xhttp.pub" ]] && [[ -f "$WORK_DIR/.env.xhttp.shortid" ]]; then
        XHTTP_PRIV=$(cat "$WORK_DIR/.env.xhttp.priv" 2>/dev/null || echo "")
        XHTTP_PUB=$(cat "$WORK_DIR/.env.xhttp.pub" 2>/dev/null || echo "")
        XHTTP_SHORT_ID=$(cat "$WORK_DIR/.env.xhttp.shortid" 2>/dev/null || echo "")
        
        # Get domain or IP for XHTTP server name
        if [[ -f "$WORK_DIR/connection-info.txt" ]]; then
            XHTTP_SERVER_NAME=$(grep "^XHTTP_SERVER_NAME:" "$WORK_DIR/connection-info.txt" 2>/dev/null | cut -d: -f2 | tr -d ' ' || echo "example.com")
            XHTTP_TARGET=$(grep "^XHTTP_TARGET:" "$WORK_DIR/connection-info.txt" 2>/dev/null | cut -d: -f2 | tr -d ' ' || echo "")
        fi
        
        if [[ -z "$XHTTP_SERVER_NAME" ]]; then
            XHTTP_SERVER_NAME="example.com"
        fi
        if [[ -z "$XHTTP_TARGET" ]]; then
            EXTERNAL_IP=$(curl -s4 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}' || echo "0.0.0.0")
            XHTTP_TARGET="${EXTERNAL_IP}:4443"
        fi
        
        if [[ -n "$XHTTP_PRIV" ]] && [[ -n "$XHTTP_SHORT_ID" ]] && [[ ${#XHTTP_PRIV} -eq 64 ]] && [[ ${#XHTTP_SHORT_ID} -eq 16 ]]; then
            # Check if XHTTP flags are already present
            if ! grep -q "ExecStart=.*-xhttp-target" /etc/systemd/system/whispera-server.service; then
                log_info "Adding XHTTP flags to whispera-server.service..."
                # Add XHTTP flags to ExecStart line
                # Try to add before -audit flag if it exists, otherwise at the end
                if grep -q "ExecStart=.*-audit" /etc/systemd/system/whispera-server.service; then
                    # Insert before -audit
                    sed -i "s#\\(ExecStart=.*\\)\\(-audit\\)#\\1-xhttp-target ${XHTTP_TARGET} -xhttp-server-names ${XHTTP_SERVER_NAME} -xhttp-private-key ${XHTTP_PRIV} -xhttp-short-id ${XHTTP_SHORT_ID} \\2#" /etc/systemd/system/whispera-server.service
                else
                    # Add at the end
                    sed -i "s#^\\(ExecStart=.*\\)\$#\\1 -xhttp-target ${XHTTP_TARGET} -xhttp-server-names ${XHTTP_SERVER_NAME} -xhttp-private-key ${XHTTP_PRIV} -xhttp-short-id ${XHTTP_SHORT_ID}#" /etc/systemd/system/whispera-server.service
                fi
                UPDATED=1
            fi
        fi
    fi
    
    # ensure -tun whispera0 flag - DISABLED for Proxy Mode
    # if ! grep -q "ExecStart=.*-tun" /etc/systemd/system/whispera-server.service; then
    #    log_info "Adding -tun whispera0 flag to whispera-server.service..."
    #    sed -i 's#^\(ExecStart=.*\)$#\1 -tun whispera0#' /etc/systemd/system/whispera-server.service
    #    UPDATED=1
    # fi
    # ensure capabilities
    if ! grep -q "CapabilityBoundingSet=.*CAP_NET_ADMIN" /etc/systemd/system/whispera-server.service; then
        log_info "Adding CAP_NET_ADMIN to CapabilityBoundingSet..."
        sed -i '/\[Service\]/a CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE' /etc/systemd/system/whispera-server.service
        UPDATED=1
    fi
    if [[ $UPDATED == 1 ]]; then
        systemctl daemon-reload
        log_success "whispera-server.service updated"
    fi
fi

# Ensure Whispera TUN/WireGuard interface has 198.18.0.2/30 and route (if iface already up)
# ensure_whispera_route

# Restart ML service if exists
if systemctl is-enabled --quiet whispera-ml 2>/dev/null; then
    log_info "Restarting ML service..."
    systemctl restart whispera-ml || {
        log_warning "ML service restart failed"
    }
    
    # Wait for ML service (increased timeout for TensorFlow loading)
    log_info "Waiting for ML service..."
    ML_SERVICE_READY=false
    for i in {1..30}; do
        sleep 3
        # Check if service is responding (accept 200 even if models are still loading)
        if curl -s -f --max-time 3 http://127.0.0.1:8000/health >/dev/null 2>&1 || \
           curl -s --max-time 3 http://127.0.0.1:8000/ >/dev/null 2>&1; then
            log_success "ML service is ready"
            ML_SERVICE_READY=true
            break
        fi
        if [[ $i -eq 30 ]]; then
            log_warning "ML service not responding after 90 seconds, continuing anyway..."
        elif [[ $((i % 5)) -eq 0 ]]; then
            log_info "ML service not yet responding (attempt $i/30)..."
        fi
    done
fi

# Restart main server
if systemctl is-enabled --quiet whispera-server 2>/dev/null; then
    log_info "Restarting Whispera server..."
    systemctl restart whispera-server || {
        log_error "Server restart failed"
        log_info "Check logs: journalctl -u whispera-server -n 50"
        exit 1
    }
    
    # Wait for server to start
    log_info "Waiting for server to start..."
    sleep 3
    for i in {1..10}; do
        if systemctl is-active --quiet whispera-server; then
            log_success "Server restarted successfully"
            break
        fi
        if [[ $i -eq 10 ]]; then
            log_error "Server failed to start"
            log_info "Check logs: journalctl -u whispera-server -n 50"
            log_info "Restoring from backup..."
            if [[ -f "$BACKUP_DIR/whispera-server" ]]; then
                cp "$BACKUP_DIR/whispera-server" "$WORK_DIR/whispera-server"
                systemctl restart whispera-server
            fi
            exit 1
        fi
        sleep 1
    done
else
    log_warning "whispera-server service not found, skipping restart"
fi

# After server is up, interface should exist -> ensure route again
# ensure_whispera_route

# Update connection-info.txt with XHTTP keys if they exist
if [[ -f "$WORK_DIR/.env.xhttp.priv" ]] && [[ -f "$WORK_DIR/.env.xhttp.pub" ]] && [[ -f "$WORK_DIR/.env.xhttp.shortid" ]]; then
    XHTTP_PRIV=$(cat "$WORK_DIR/.env.xhttp.priv" 2>/dev/null || echo "")
    XHTTP_PUB=$(cat "$WORK_DIR/.env.xhttp.pub" 2>/dev/null || echo "")
    XHTTP_SHORT_ID=$(cat "$WORK_DIR/.env.xhttp.shortid" 2>/dev/null || echo "")
    
    if [[ -n "$XHTTP_PUB" ]] && [[ -n "$XHTTP_SHORT_ID" ]] && [[ ${#XHTTP_PUB} -eq 64 ]] && [[ ${#XHTTP_SHORT_ID} -eq 16 ]]; then
        # Get existing values or defaults
        if [[ -f "$WORK_DIR/connection-info.txt" ]]; then
            EXTERNAL_IP=$(grep "^SERVER_IP:" "$WORK_DIR/connection-info.txt" 2>/dev/null | cut -d: -f2 | tr -d ' ' || echo "")
            XHTTP_SERVER_NAME=$(grep "^XHTTP_SERVER_NAME:" "$WORK_DIR/connection-info.txt" 2>/dev/null | cut -d: -f2 | tr -d ' ' || echo "example.com")
            XHTTP_TARGET=$(grep "^XHTTP_TARGET:" "$WORK_DIR/connection-info.txt" 2>/dev/null | cut -d: -f2 | tr -d ' ' || echo "")
        fi
        
        if [[ -z "$EXTERNAL_IP" ]]; then
            EXTERNAL_IP=$(curl -s4 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}' || echo "YOUR_SERVER_IP")
        fi
        if [[ -z "$XHTTP_SERVER_NAME" ]]; then
            XHTTP_SERVER_NAME="example.com"
        fi
        if [[ -z "$XHTTP_TARGET" ]]; then
            XHTTP_TARGET="${EXTERNAL_IP}:4443"
        fi
        
        # Update connection-info.txt with XHTTP info
        if [[ -f "$WORK_DIR/connection-info.txt" ]]; then
            # Remove old XHTTP lines if exist
            sed -i '/^XHTTP_/d' "$WORK_DIR/connection-info.txt"

            # Defaults for advanced XHTTP settings (can be overridden manually)
            XHTTP_MODE="stream-up"
            XHTTP_MAX_CONCURRENCY="8"
            XHTTP_ALPN="h2,http/1.1"

            # Add XHTTP section before Quick Connect
            sed -i "/^# Quick Connect/i\\
# XHTTP Configuration (for XHTTP+VLESS with Marionette obfuscation):\\
XHTTP_PUBLIC_KEY: ${XHTTP_PUB}\\
XHTTP_SHORT_ID: ${XHTTP_SHORT_ID}\\
XHTTP_SERVER_NAME: ${XHTTP_SERVER_NAME}\\
XHTTP_TARGET: ${XHTTP_TARGET}\\
XHTTP_MODE: ${XHTTP_MODE}\\
XHTTP_MAX_CONCURRENCY: ${XHTTP_MAX_CONCURRENCY}\\
XHTTP_ALPN: ${XHTTP_ALPN}\\
" "$WORK_DIR/connection-info.txt"
            log_success "Updated connection-info.txt with XHTTP configuration"
        fi
        
        # Update hosting-info.txt
        if [[ -f "$WORK_DIR/hosting-info.txt" ]]; then
            sed -i '/^XHTTP_/d' "$WORK_DIR/hosting-info.txt"
            echo "XHTTP_PUBLIC_KEY: ${XHTTP_PUB}" >> "$WORK_DIR/hosting-info.txt"
            echo "XHTTP_SHORT_ID: ${XHTTP_SHORT_ID}" >> "$WORK_DIR/hosting-info.txt"
            echo "XHTTP_SERVER_NAME: ${XHTTP_SERVER_NAME}" >> "$WORK_DIR/hosting-info.txt"
        fi
    fi
fi

# Cleanup old backups (keep last 5)
log_info "Cleaning up old backups..."
BACKUP_COUNT=$(ls -1d "$WORK_DIR/backup-"* 2>/dev/null | wc -l)
if [[ $BACKUP_COUNT -gt 5 ]]; then
    ls -1td "$WORK_DIR/backup-"* 2>/dev/null | tail -n +6 | xargs rm -rf 2>/dev/null || true
    log_info "Old backups cleaned up"
fi

echo ""
log_success "✅ Update completed successfully!"
echo ""
log_info "Service status:"
systemctl is-active --quiet whispera-server && log_success "✅ Server: RUNNING" || log_error "❌ Server: NOT RUNNING"
systemctl is-active --quiet whispera-ml 2>/dev/null && log_success "✅ ML: RUNNING" || log_warning "⚠️  ML: NOT RUNNING"
echo ""
log_info "View logs: journalctl -u whispera-server -f"
echo ""

