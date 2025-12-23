#!/bin/bash
# Whispera Automated Installation Script for Hosting
# One-command installation: curl -Ls https://... | bash
# Or: bash <(curl -Ls https://...)
#
# Usage:
#   ./install.sh                    # Install with self-signed certificate
#   ./install.sh domain.com         # Install with Let's Encrypt (interactive)
#   ./install.sh domain.com email@example.com  # Install with Let's Encrypt (non-interactive)

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

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (use sudo)"
    exit 1
fi

log_info "🚀 Whispera Automated Installation"
log_info "==================================="
echo ""

# Detect package manager
if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt-get"
    UPDATE_CMD="apt-get update -y"
    INSTALL_CMD="apt-get install -y"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    UPDATE_CMD="yum update -y"
    INSTALL_CMD="yum install -y"
elif command -v apk &>/dev/null; then
    PKG_MANAGER="apk"
    UPDATE_CMD="apk update"
    INSTALL_CMD="apk add"
else
    log_error "Unsupported package manager"
    exit 1
fi

# Install dependencies
log_info "Installing dependencies..."
$UPDATE_CMD >/dev/null 2>&1 || {
    log_warning "Package manager update failed, continuing..."
}
$INSTALL_CMD curl git golang-go iptables iproute2 openssl python3 python3-pip >/dev/null 2>&1 || {
    log_warning "Some packages may not have installed, continuing..."
    # Try to install critical packages individually
    for pkg in curl git golang-go openssl; do
        $INSTALL_CMD "$pkg" >/dev/null 2>&1 || {
            log_warning "Failed to install $pkg, may cause issues later"
        }
    done
}

# Install Go (always install latest version)
# Try to fetch latest version from go.dev
GO_VERSION=$(curl -s https://go.dev/dl/?mode=json | grep -oE 'go[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n 1 | sed 's/go//')

if [[ -z "$GO_VERSION" ]]; then
    GO_VERSION="1.23.4" # Fallback if API fails
    log_warning "Failed to detect latest Go version, using fallback: $GO_VERSION"
else
    log_info "Detected latest Go version: $GO_VERSION"
fi

        log_info "Installing Go ${GO_VERSION}..."

    GO_ARCH="amd64"
    
    # Detect architecture
    ARCH=$(uname -m)
    if [[ "$ARCH" == "aarch64" ]] || [[ "$ARCH" == "arm64" ]]; then
        GO_ARCH="arm64"
    elif [[ "$ARCH" == "x86_64" ]]; then
        GO_ARCH="amd64"
    else
        log_error "Unsupported architecture: $ARCH"
        exit 1
    fi
    
    log_info "Downloading Go ${GO_VERSION} for ${GO_ARCH}..."
    cd /tmp
    
    # Remove old Go installation
    if [[ -d "/usr/local/go" ]]; then
        log_info "Removing old Go installation..."
        rm -rf /usr/local/go
    fi
    
    # Download Go
    if ! wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O go.tar.gz; then
        log_error "Failed to download Go"
        exit 1
    fi
    
    # Install Go
    log_info "Installing Go ${GO_VERSION}..."
    tar -C /usr/local -xzf go.tar.gz
    rm -f go.tar.gz
    
    # Update PATH for current session
    export PATH=/usr/local/go/bin:$PATH
    export GOROOT=/usr/local/go
    
    # Update PATH permanently
    if ! grep -q "/usr/local/go/bin" /etc/profile; then
        echo 'export PATH=/usr/local/go/bin:$PATH' >> /etc/profile
        echo 'export GOROOT=/usr/local/go' >> /etc/profile
    fi
    
    # Verify installation
if ! /usr/local/go/bin/go version &>/dev/null; then
        log_error "Go installation verification failed"
        exit 1
    fi

NEW_VERSION=$(/usr/local/go/bin/go version | grep -oE 'go[0-9]+\.[0-9]+(\.[0-9]+)?' | sed 's/go//')
log_success "Go ${NEW_VERSION} installed successfully"

# Ensure we're using the correct Go
if [[ -f "/usr/local/go/bin/go" ]]; then
    export PATH=/usr/local/go/bin:$PATH
    export GOROOT=/usr/local/go
fi

# Final Go version check
GO_CMD=$(command -v go)
GO_VER=$($GO_CMD version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+(\.[0-9]+)?' | sed 's/go//' || echo "unknown")
log_info "Using Go ${GO_VER} from: ${GO_CMD}"

# Setup working directory
WORK_DIR="/opt/whispera"
log_info "Setting up working directory: $WORK_DIR"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# Clone or update repository
if [[ -d ".git" ]]; then
    log_info "Updating existing repository..."
    git pull >/dev/null 2>&1 || {
        log_warning "git pull failed, using existing code..."
    }
elif [[ -f "go.mod" ]]; then
    log_info "Repository found (no .git directory, but go.mod exists)"
    log_info "Using existing code..."
else
    log_info "Repository not found, attempting to auto-detect..."
    # Try to detect if we're in a git repo (maybe .git is a file for submodule)
    if [[ -f ".git" ]] || git rev-parse --git-dir >/dev/null 2>&1; then
        log_info "Git repository detected, updating..."
        git pull >/dev/null 2>&1 || {
            log_warning "git pull failed, using existing code..."
        }
    else
        log_warning "Repository not found and cannot auto-detect"
        log_info "If you're running this from a cloned repo, make sure you're in the repo directory"
        log_info "If you need to clone, use: git clone <repo-url> $WORK_DIR && cd $WORK_DIR"
        log_warning "Continuing with installation using current directory..."
        # Don't exit - continue with installation if files exist
        if [[ ! -f "go.mod" ]]; then
            log_error "go.mod not found - cannot proceed without source code"
            exit 1
        fi
    fi
fi

# Source build functions if available
if [[ -f "scripts/lib/build.sh" ]]; then
    # Ensure Go is in PATH before sourcing
    if [[ -f "/usr/local/go/bin/go" ]]; then
        export PATH="/usr/local/go/bin:$PATH"
        export GOROOT="/usr/local/go"
    fi
    
    source "scripts/lib/build.sh"
    
    # Auto-setup and build
    log_info "Building Whispera server..."
    # Use explicit path to Go if available
    GO_CMD="go"
    if [[ -f "/usr/local/go/bin/go" ]]; then
        GO_CMD="/usr/local/go/bin/go"
    fi
    build_server "$WORK_DIR" "$WORK_DIR/whispera-server" "$GO_CMD" "false"
    
    SERVER_BINARY="$WORK_DIR/whispera-server"
else
    # Fallback: simple build
    log_info "Building with go build..."
    
    # Use explicit path to Go if available
    GO_CMD="go"
    if [[ -f "/usr/local/go/bin/go" ]]; then
        GO_CMD="/usr/local/go/bin/go"
        export PATH="/usr/local/go/bin:$PATH"
        export GOROOT="/usr/local/go"
    fi
    
    export GO111MODULE=on
    export CGO_ENABLED=0
    export GOTOOLCHAIN=local
    export GOFLAGS="-mod=mod"
    export GOPROXY=https://proxy.golang.org,direct
    
    # Попытка обновить зависимости, но не падаем, если не вышло (иногда go.sum конфликтует)
    log_info "Tidying Go modules..."
    "$GO_CMD" mod tidy >/dev/null 2>&1 || {
        log_warning "go mod tidy failed, attempting build anyway..."
    }

    log_info "Compiling server binary..."
    "$GO_CMD" build -mod=mod -o "$WORK_DIR/whispera-server" ./cmd/server || {
        log_error "Build failed"
        # Попытка собрать без -mod=mod, если вендоринг сломан
        log_info "Retrying build without -mod=mod..."
        "$GO_CMD" build -o "$WORK_DIR/whispera-server" ./cmd/server || {
             log_error "Build failed again. Check go.mod/go.sum"
             exit 1
        }
    }
    
    SERVER_BINARY="$WORK_DIR/whispera-server"
fi

# Note: Client is built on client machines (Windows) using run-dev.bat, not on the server
# Client binary is not needed on the server

# Generate keys if not exist
if [[ ! -f ".env.server" ]] || [[ ! -f ".env.server.pub" ]]; then
    log_info "Generating keys..."
    if [[ -f "$WORK_DIR/whispera-keygen" ]]; then
        KEYGEN_OUTPUT=$("$WORK_DIR/whispera-keygen" -mode x25519 2>&1)
        SERVER_PRIV=$(echo "$KEYGEN_OUTPUT" | grep "priv=" | cut -d= -f2 | tr -d ' ')
        SERVER_PUB=$(echo "$KEYGEN_OUTPUT" | grep "pub=" | cut -d= -f2 | tr -d ' ')
    else
        KEYGEN_OUTPUT=$(go run ./cmd/keygen/main.go -mode x25519 2>&1)
        SERVER_PRIV=$(echo "$KEYGEN_OUTPUT" | grep "priv=" | cut -d= -f2 | tr -d ' ')
        SERVER_PUB=$(echo "$KEYGEN_OUTPUT" | grep "pub=" | cut -d= -f2 | tr -d ' ')
    fi
    
    echo "$SERVER_PRIV" > .env.server
    echo "$SERVER_PUB" > .env.server.pub
    
    # Generate client keys
    if [[ -f "$WORK_DIR/whispera-keygen" ]]; then
        CLIENT_OUTPUT=$("$WORK_DIR/whispera-keygen" -mode x25519 2>&1)
    else
        CLIENT_OUTPUT=$(go run ./cmd/keygen/main.go -mode x25519 2>&1)
    fi
    CLIENT_PRIV=$(echo "$CLIENT_OUTPUT" | grep "priv=" | cut -d= -f2 | tr -d ' ')
    CLIENT_PUB=$(echo "$CLIENT_OUTPUT" | grep "pub=" | cut -d= -f2 | tr -d ' ')
    
    echo "$CLIENT_PRIV" > .env.client
    echo "$CLIENT_PUB" > .env.client.pub
    
    # Generate XHTTP keys (ed25519 private key and short ID)
    log_info "Generating XHTTP keys (ed25519)..."
    
    # Create temporary Go script for key generation
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
    
    # Run key generation script
    if [[ -f "$GO_CMD" ]] || command -v go >/dev/null 2>&1; then
        XHTTP_KEYGEN_OUTPUT=$("$GO_CMD" run "$XHTTP_KEYGEN_SCRIPT" 2>/dev/null || echo "")
        XHTTP_PRIV=$(echo "$XHTTP_KEYGEN_OUTPUT" | grep "priv=" | cut -d= -f2 | tr -d ' ')
        XHTTP_PUB=$(echo "$XHTTP_KEYGEN_OUTPUT" | grep "pub=" | cut -d= -f2 | tr -d ' ')
        XHTTP_SHORT_ID=$(echo "$XHTTP_KEYGEN_OUTPUT" | grep "shortid=" | cut -d= -f2 | tr -d ' ')
        rm -f "$XHTTP_KEYGEN_SCRIPT"
        
        if [[ ${#XHTTP_PRIV} -eq 64 ]] && [[ ${#XHTTP_PUB} -eq 64 ]] && [[ ${#XHTTP_SHORT_ID} -eq 16 ]]; then
            echo "$XHTTP_PRIV" > .env.xhttp.priv
            echo "$XHTTP_PUB" > .env.xhttp.pub
            echo "$XHTTP_SHORT_ID" > .env.xhttp.shortid
            log_success "XHTTP keys generated (ed25519)"
        else
            log_warning "XHTTP key generation failed, will generate on first server start"
            XHTTP_PRIV=""
            XHTTP_PUB=""
            XHTTP_SHORT_ID=""
        fi
    else
        log_warning "Go not available for XHTTP key generation, will generate on first server start"
        XHTTP_PRIV=""
        XHTTP_PUB=""
        XHTTP_SHORT_ID=""
    fi
    
    log_success "Keys generated"
else
    log_info "Using existing keys..."
    SERVER_PRIV=$(cat .env.server)
    SERVER_PUB=$(cat .env.server.pub)
    CLIENT_PRIV=$(cat .env.client)
    CLIENT_PUB=$(cat .env.client.pub)
    
    # Load XHTTP keys if exist
    if [[ -f ".env.xhttp.priv" ]] && [[ -f ".env.xhttp.pub" ]] && [[ -f ".env.xhttp.shortid" ]]; then
        XHTTP_PRIV=$(cat .env.xhttp.priv)
        XHTTP_PUB=$(cat .env.xhttp.pub)
        XHTTP_SHORT_ID=$(cat .env.xhttp.shortid)
        log_info "Using existing XHTTP keys..."
    else
        XHTTP_PRIV=""
        XHTTP_PUB=""
        XHTTP_SHORT_ID=""
    fi
fi

# Setup TUN device (needed for clients, server doesn't use TUN) - DISABLED for Proxy Mode
# log_info "Setting up TUN device (for client compatibility)..."
# if [[ ! -c /dev/net/tun ]]; then
#    mkdir -p /dev/net
#    mknod /dev/net/tun c 10 200
#    chmod 666 /dev/net/tun
# fi
#
# modprobe tun 2>/dev/null || true
# echo "tun" > /etc/modules-load.d/tun.conf 2>/dev/null || true

# Setup IP forwarding (for routing traffic)
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf 2>/dev/null || true

# Setup ML Service
log_info "Setting up ML service..."

# Simple Python installation
log_info "Installing Python 3 and pip..."
if command -v apt-get &>/dev/null; then
    apt-get update >/dev/null 2>&1 || true
    apt-get install -y python3 python3-pip >/dev/null 2>&1 || {
        log_warning "Python installation may have failed, continuing..."
    }
elif command -v yum &>/dev/null; then
    yum install -y python3 python3-pip >/dev/null 2>&1 || {
        log_warning "Python installation may have failed, continuing..."
    }
elif command -v apk &>/dev/null; then
    apk add python3 py3-pip >/dev/null 2>&1 || {
        log_warning "Python installation may have failed, continuing..."
    }
fi

# Check Python version
PYTHON_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)" 2>/dev/null || echo "0")
PYTHON_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)" 2>/dev/null || echo "0")
PYTHON_VERSION="${PYTHON_MAJOR}.${PYTHON_MINOR}"

if [[ $PYTHON_MAJOR -lt 3 ]] || [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -lt 9 ]]; then
    log_error "Python $PYTHON_VERSION is too old. Python 3.9+ required."
    log_info "Installing Python 3.9 from pre-built binary..."
    
    ARCH=$(uname -m)
    if [[ "$ARCH" != "x86_64" ]]; then
        log_error "Pre-built binary only available for x86_64"
        exit 1
    fi
    
    cd /tmp
    
    # Try multiple sources for pre-built binary
    log_info "Downloading Python 3.9 binary..."
    
    # Source 1: GitHub standalone build
    PYTHON_URL1="https://github.com/indygreg/python-build-standalone/releases/download/20231007/cpython-3.9.18+20231007-x86_64-unknown-linux-gnu-install_only.tar.gz"
    # Source 2: Alternative GitHub release
    PYTHON_URL2="https://github.com/indygreg/python-build-standalone/releases/download/20240107/cpython-3.9.18+20240107-x86_64-unknown-linux-gnu-install_only.tar.gz"
    
    DOWNLOADED=false
    
    for URL in "$PYTHON_URL1" "$PYTHON_URL2"; do
        log_info "Trying to download from: $(basename $(dirname $URL))"
        if wget --timeout=30 --tries=3 "$URL" -O python39.tar.gz 2>&1; then
            if [[ -f python39.tar.gz ]] && [[ -s python39.tar.gz ]]; then
                DOWNLOADED=true
                log_success "Downloaded successfully"
                break
            else
                rm -f python39.tar.gz
            fi
        fi
    done
    
    if [[ "$DOWNLOADED" != "true" ]]; then
        log_error "Failed to download Python 3.9 binary from all sources"
        log_info "Check your internet connection and try again"
        exit 1
    fi
    
    log_info "Extracting Python 3.9 binary..."
    tar -xzf python39.tar.gz
    
    if [[ -d "python" ]]; then
        log_info "Installing Python 3.9 to /usr/local..."
        cp -r python/* /usr/local/
        
        # Create symlinks
        ln -sf /usr/local/bin/python3.9 /usr/bin/python3.9
        ln -sf /usr/local/bin/python3.9 /usr/local/bin/python3
        
        # Cleanup
        rm -rf python python39.tar.gz
        cd "$WORK_DIR"
        
        if command -v python3.9 &>/dev/null; then
            PYTHON3_CMD=python3.9
            log_success "Python 3.9 installed from binary"
        else
            log_error "Python 3.9 binary installation failed"
            exit 1
        fi
    else
        log_error "Extracted directory structure unexpected"
        exit 1
    fi
else
    PYTHON3_CMD=python3
    log_success "Python $PYTHON_VERSION is sufficient"
fi

# Ensure pip is available
if ! $PYTHON3_CMD -m pip --version >/dev/null 2>&1; then
    log_info "Installing pip for $PYTHON3_CMD..."
    curl -sS https://bootstrap.pypa.io/get-pip.py | $PYTHON3_CMD 2>&1 | grep -v "already satisfied" || true
fi

# Install ML dependencies
if [[ ! -d "$WORK_DIR/ml_engine" ]]; then
    log_error "ML engine directory not found: $WORK_DIR/ml_engine"
    log_warning "ML service will not be available"
elif [[ ! -f "$WORK_DIR/ml_engine/api_server.py" ]]; then
    log_error "ML API server file not found: $WORK_DIR/ml_engine/api_server.py"
    log_warning "ML service will not be available"
else
    log_info "Installing ML dependencies..."
    cd "$WORK_DIR/ml_engine"
    
    # Use the correct Python command
    PYTHON_CMD="${PYTHON3_CMD:-python3}"
    
    # Upgrade pip first
    $PYTHON_CMD -m pip install --upgrade pip setuptools wheel || {
        log_error "Failed to upgrade pip"
    }
    
    # Install core dependencies first (numpy, etc.) before TensorFlow
    log_info "Installing core ML dependencies..."
    $PYTHON_CMD -m pip install numpy pandas scikit-learn scipy joblib psutil 2>&1 | grep -v "already satisfied" || true
    
    # Install TensorFlow first (2.13.0+ supports newer typing-extensions)
    log_info "Installing TensorFlow (may take time)..."
    $PYTHON_CMD -m pip install "tensorflow>=2.13.0" 2>&1 | tail -10 || {
        log_warning "TensorFlow installation failed (non-critical for basic API)"
    }
    
    # Install FastAPI and related packages (will use compatible typing-extensions from TensorFlow)
    log_info "Installing FastAPI and Uvicorn..."
    $PYTHON_CMD -m pip install --ignore-installed --force-reinstall fastapi uvicorn[standard] pydantic python-multipart || {
        log_warning "Standard install failed, trying with --break-system-packages..."
        $PYTHON_CMD -m pip install --break-system-packages fastapi uvicorn[standard] pydantic python-multipart || {
            log_error "Failed to install core ML dependencies"
            log_warning "ML service will not start without these packages"
        }
    }
    
    # Verify installation
    if ! $PYTHON_CMD -c "import fastapi" 2>/dev/null; then
        log_error "FastAPI installation verification failed"
        log_info "Trying alternative installation method..."
        $PYTHON_CMD -m pip install --no-deps fastapi || $PYTHON_CMD -m pip install --user fastapi uvicorn[standard] pydantic
    else
        log_success "FastAPI installed successfully"
    fi
    
    log_success "ML dependencies installation completed"
    cd "$WORK_DIR"
fi

# Generate TLS certificates (обязательно для HTTPS)
log_info "Generating TLS certificates..."

# Check for domain parameter for Let's Encrypt
DOMAIN="${1:-}"
EMAIL="${2:-}"

TLS_CERT_DIR="$WORK_DIR/certs"
mkdir -p "$TLS_CERT_DIR"
TLS_CERT="$TLS_CERT_DIR/cert.pem"
TLS_KEY="$TLS_CERT_DIR/key.pem"
TLS_ENABLED=false
USE_LETSENCRYPT=false

# If domain is provided, offer Let's Encrypt
if [[ -n "$DOMAIN" ]]; then
    log_info "Domain provided: $DOMAIN"
    log_info "Attempting automatic Let's Encrypt certificate setup..."
    log_info "If it fails (e.g., DNS not ready), will automatically use self-signed certificate"
    log_info ""
    
    # Automatically attempt Let's Encrypt, fallback to self-signed if it fails
    USE_LETSENCRYPT=true
fi

# Setup Let's Encrypt if requested
if [[ "$USE_LETSENCRYPT" == "true" ]] && [[ -n "$DOMAIN" ]]; then
    log_info "Setting up Let's Encrypt certificate for $DOMAIN..."
    log_info "Attempting automatic certificate generation (will fallback to self-signed if it fails)..."
    
    # Install certbot if not available
    if ! command -v certbot &>/dev/null; then
        log_info "Installing Certbot..."
        if command -v apt-get &>/dev/null; then
            $INSTALL_CMD certbot >/dev/null 2>&1 || {
                log_warning "Certbot installation failed, falling back to self-signed certificate"
                USE_LETSENCRYPT=false
            }
        elif command -v yum &>/dev/null; then
            $INSTALL_CMD certbot >/dev/null 2>&1 || {
                log_warning "Certbot installation failed, falling back to self-signed certificate"
                USE_LETSENCRYPT=false
            }
        else
            log_warning "Certbot not available for this package manager, falling back to self-signed certificate"
            USE_LETSENCRYPT=false
        fi
    fi
    
    if [[ "$USE_LETSENCRYPT" == "true" ]]; then
        # Install dig if not available (needed for DNS check)
        if ! command -v dig &>/dev/null; then
            log_info "Installing dnsutils for DNS verification..."
            if command -v apt-get &>/dev/null; then
                $INSTALL_CMD dnsutils >/dev/null 2>&1 || true
            elif command -v yum &>/dev/null; then
                $INSTALL_CMD bind-utils >/dev/null 2>&1 || true
            fi
        fi
        
        # Get external IP for DNS verification
        EXTERNAL_IP_CHECK=$(curl -s4 https://api.ipify.org 2>/dev/null || \
                           curl -s4 https://icanhazip.com 2>/dev/null || \
                           curl -s4 https://ifconfig.me 2>/dev/null || \
                           hostname -I | awk '{print $1}' || echo "")
        
        # Check DNS records before attempting certificate
        log_info "Checking DNS configuration for $DOMAIN..."
        if command -v dig &>/dev/null; then
            DOMAIN_IP=$(dig +short "$DOMAIN" A 2>/dev/null | head -1 || echo "")
        else
            # Fallback: try to resolve using host or getent
            DOMAIN_IP=$(host -t A "$DOMAIN" 2>/dev/null | grep "has address" | awk '{print $4}' | head -1 || echo "")
            if [[ -z "$DOMAIN_IP" ]]; then
                DOMAIN_IP=$(getent hosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | head -1 || echo "")
            fi
        fi
        
        if [[ -z "$DOMAIN_IP" ]]; then
            log_warning "DNS A record not found for $DOMAIN"
            log_info "Skipping Let's Encrypt (DNS not configured), will use self-signed certificate"
            USE_LETSENCRYPT=false
        elif [[ "$DOMAIN_IP" == "127.0.0.1" ]] || [[ "$DOMAIN_IP" == "localhost" ]]; then
            log_warning "DNS A record for $DOMAIN points to localhost ($DOMAIN_IP)"
            log_warning "But this server's IP is: $EXTERNAL_IP_CHECK"
            log_info "Skipping Let's Encrypt (DNS points to localhost), will use self-signed certificate"
            log_info "You can get Let's Encrypt certificate later via web panel after fixing DNS"
            USE_LETSENCRYPT=false
        elif [[ -n "$EXTERNAL_IP_CHECK" ]] && [[ "$DOMAIN_IP" != "$EXTERNAL_IP_CHECK" ]]; then
            log_warning "DNS A record for $DOMAIN points to $DOMAIN_IP"
            log_warning "But this server's IP is: $EXTERNAL_IP_CHECK"
            log_info "Skipping Let's Encrypt (DNS mismatch), will use self-signed certificate"
            log_info "You can get Let's Encrypt certificate later via web panel after fixing DNS"
            USE_LETSENCRYPT=false
        else
            log_success "DNS A record verified: $DOMAIN -> $DOMAIN_IP"
        fi
        
        if [[ "$USE_LETSENCRYPT" == "true" ]]; then
            # Check if server is running and stop it temporarily (certbot needs port 80)
            if systemctl is-active --quiet whispera-server 2>/dev/null; then
                log_info "Stopping Whispera server temporarily for certificate generation..."
                systemctl stop whispera-server 2>/dev/null || true
            fi
            
                # Generate Let's Encrypt certificate
                CERT_EMAIL="${EMAIL:-admin@${DOMAIN}}"
                log_info "Obtaining Let's Encrypt certificate (email: $CERT_EMAIL)..."
                log_info "This may take 30-60 seconds. Please wait..."
                
                # Выполняем certbot с коротким таймаутом (30 секунд для быстрого fallback)
                # Используем timeout если доступен, иначе просто запускаем
                if command -v timeout >/dev/null 2>&1; then
                    # Запускаем certbot с таймаутом (30 секунд - достаточно для быстрого отказа)
                    log_info "Running certbot (timeout: 30 seconds)..."
                    CERTBOT_OUTPUT=$(timeout 30 certbot certonly --standalone \
                        --non-interactive \
                        --agree-tos \
                        --email "$CERT_EMAIL" \
                        -d "$DOMAIN" 2>&1)
                    CERTBOT_EXIT=$?
                else
                    # Fallback без timeout - используем certbot с ограничением времени через флаги
                    log_info "Running certbot (no timeout command available)..."
                    CERTBOT_OUTPUT=$(certbot certonly --standalone \
                        --non-interactive \
                        --agree-tos \
                        --email "$CERT_EMAIL" \
                        -d "$DOMAIN" \
                        --preferred-challenges http \
                        --http-01-port 80 2>&1)
                    CERTBOT_EXIT=$?
                fi
                
                # Сохраняем вывод для анализа
                echo "$CERTBOT_OUTPUT" > /tmp/certbot.log 2>&1
                
                # Показываем результат
                if [[ $CERTBOT_EXIT -eq 0 ]]; then
                    log_success "Certbot completed successfully"
                elif [[ $CERTBOT_EXIT -eq 124 ]]; then
                    log_warning "Certbot timed out (DNS may not be ready)"
                else
                    log_warning "Certbot failed (exit code: $CERTBOT_EXIT)"
                    # Показываем только ключевые ошибки
                    if echo "$CERTBOT_OUTPUT" | grep -qi "no valid A records"; then
                        log_info "DNS A record not ready - this is expected if DNS is not configured"
                    else
                        log_info "Last 5 lines of output:"
                        echo "$CERTBOT_OUTPUT" | tail -5 | sed 's/^/  /'
                    fi
                fi
            
            if [[ $CERTBOT_EXIT -eq 0 ]]; then
            
            # Copy certificates to our directory
            LE_CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
            LE_KEY="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
            
            if [[ -f "$LE_CERT" ]] && [[ -f "$LE_KEY" ]]; then
                cp "$LE_CERT" "$TLS_CERT"
                cp "$LE_KEY" "$TLS_KEY"
                chmod 644 "$TLS_CERT"
                chmod 600 "$TLS_KEY"
                TLS_ENABLED=true
                USE_LETSENCRYPT=true
                log_success "Let's Encrypt certificate obtained successfully!"
                
                # Setup automatic renewal
                log_info "Setting up automatic certificate renewal..."
                RENEW_SCRIPT="$WORK_DIR/renew-cert.sh"
                cat > "$RENEW_SCRIPT" <<'RENEW_EOF'
#!/bin/bash
# Script to renew Let's Encrypt certificate and reload Whispera server

DOMAIN="${1}"
WORK_DIR="${2}"

if [[ -z "$DOMAIN" ]] || [[ -z "$WORK_DIR" ]]; then
    echo "Usage: $0 <domain> <work_dir>"
    exit 1
fi

# Renew certificate
certbot renew --quiet

# Copy renewed certificates
cp "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "${WORK_DIR}/certs/cert.pem"
cp "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "${WORK_DIR}/certs/key.pem"
chmod 644 "${WORK_DIR}/certs/cert.pem"
chmod 600 "${WORK_DIR}/certs/key.pem"

# Reload server
if systemctl is-active --quiet whispera-server; then
    systemctl reload whispera-server || systemctl restart whispera-server
fi

echo "Certificate renewed: $(date)"
RENEW_EOF
                chmod +x "$RENEW_SCRIPT"
                
                # Add to crontab (check twice daily)
                CRON_JOB="0 0,12 * * * $RENEW_SCRIPT $DOMAIN $WORK_DIR >> /var/log/whispera-cert-renew.log 2>&1"
                (crontab -l 2>/dev/null | grep -v "$RENEW_SCRIPT"; echo "$CRON_JOB") | crontab - 2>/dev/null || {
                    echo "$CRON_JOB" | crontab - 2>/dev/null
                }
                
                log_success "Automatic certificate renewal configured"
            else
                log_warning "Let's Encrypt certificate files not found, falling back to self-signed"
                USE_LETSENCRYPT=false
                TLS_ENABLED=false
            fi
            else
                log_warning "Let's Encrypt certificate generation failed"
                log_info "Exit code: $CERTBOT_EXIT"
                
                # Check if output is empty (might indicate timeout or hang)
                if [[ -z "$CERTBOT_OUTPUT" ]]; then
                    log_error "Certbot produced no output (may have timed out or hung)"
                    log_info "Check if DNS is correctly configured and port 80 is accessible"
                fi
                
                # Check for common errors
                if echo "$CERTBOT_OUTPUT" | grep -qi "no valid A records\|no valid AAAA records\|Failed authorization procedure"; then
                    log_error "DNS A record not found or not propagated"
                    log_info ""
                    log_info "Current DNS status:"
                    log_info "  Domain: $DOMAIN"
                    log_info "  DNS points to: $DOMAIN_IP"
                    log_info "  Server IP: ${EXTERNAL_IP_CHECK:-unknown}"
                    log_info ""
                    log_info "Solution:"
                    log_info "  1. Update DNS A record in your domain provider:"
                    log_info "     $DOMAIN -> ${EXTERNAL_IP_CHECK:-YOUR_SERVER_IP}"
                    log_info "  2. Wait 5-15 minutes for DNS propagation"
                    log_info "  3. Verify DNS: dig $DOMAIN A"
                    log_info "  4. After DNS is correct, you can get certificate:"
                    log_info "     - Via web panel: Settings -> SSL/TLS Certificates"
                    log_info "     - Or manually: certbot certonly --standalone -d $DOMAIN"
                elif echo "$CERTBOT_OUTPUT" | grep -qi "Connection refused\|Failed to connect\|timeout\|Connection timed out"; then
                    log_error "Cannot connect to Let's Encrypt servers"
                    log_info "Check firewall rules - ports 80 and 443 must be open"
                    log_info "Verify: curl -I http://letsencrypt.org"
                elif echo "$CERTBOT_OUTPUT" | grep -qi "Too many requests"; then
                    log_error "Rate limit exceeded (50 requests per week per domain)"
                    log_info "Wait a few days or use --staging flag for testing"
                elif echo "$CERTBOT_OUTPUT" | grep -qi "port.*already in use\|Address already in use"; then
                    log_error "Port 80 is already in use"
                    log_info "Stop other services using port 80, or use webroot method instead of standalone"
                else
                    log_error "Unknown error occurred"
                    log_info "Full error output saved to: /tmp/certbot.log"
                    if [[ -n "$CERTBOT_OUTPUT" ]]; then
                        log_info "Last 15 lines:"
                        echo "$CERTBOT_OUTPUT" | tail -15 | sed 's/^/  /'
                    else
                        log_info "No output from certbot. Check /tmp/certbot.log manually"
                    fi
                fi
                
                log_warning ""
                log_warning "Falling back to self-signed certificate..."
                log_info "You can get Let's Encrypt certificate later via web panel or manually"
                USE_LETSENCRYPT=false
                TLS_ENABLED=false
            fi
        fi
        
        # Restart server if it was running
        if systemctl is-enabled --quiet whispera-server 2>/dev/null; then
            log_info "Whispera server will be started after installation completes"
        fi
    fi
fi

# Fallback to self-signed certificate if Let's Encrypt failed or not requested
if [[ "$TLS_ENABLED" != "true" ]]; then
    log_info "Creating self-signed TLS certificate..."
    if openssl req -x509 -newkey rsa:4096 -keyout "$TLS_KEY" -out "$TLS_CERT" \
        -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Whispera/CN=${DOMAIN:-whispera-server}" 2>/dev/null; then
        if [[ -f "$TLS_CERT" ]] && [[ -f "$TLS_KEY" ]]; then
            chmod 600 "$TLS_KEY"
            chmod 644 "$TLS_CERT"
            TLS_ENABLED=true
            log_success "Self-signed TLS certificates generated successfully"
        else
            log_error "TLS certificate files not created"
            TLS_ENABLED=false
        fi
    else
        log_error "TLS certificate generation failed!"
        log_warning "Services will run without TLS (not recommended for production)"
        TLS_ENABLED=false
    fi
fi

# Check existing certificates
if [[ -f "$TLS_CERT" ]] && [[ -f "$TLS_KEY" ]] && [[ "$TLS_ENABLED" != "true" ]]; then
    log_info "Using existing TLS certificates..."
    TLS_ENABLED=true
    log_success "TLS certificates found"
fi

if [[ "$USE_LETSENCRYPT" == "true" ]]; then
    log_success "🔒 Using Let's Encrypt trusted certificate (no browser warnings!)"
elif [[ "$TLS_ENABLED" == "true" ]]; then
    log_info "🔒 Using self-signed certificate (browsers will show security warning)"
fi

# Create ML service systemd unit
if [[ ! -f "$WORK_DIR/ml_engine/api_server.py" ]]; then
    log_warning "ML engine not found, skipping ML service setup"
else
log_info "Creating ML service systemd unit..."
    
    # Use the correct Python command
    PYTHON3_PATH=$(which ${PYTHON3_CMD:-python3} || echo "/usr/bin/python3")
    if [[ ! -x "$PYTHON3_PATH" ]]; then
        log_error "Python3 not found at $PYTHON3_PATH"
        log_warning "ML service will not be available"
    else
        # Test if fastapi and uvicorn are available
        if ! "$PYTHON3_PATH" -c "import fastapi" 2>/dev/null; then
            log_error "FastAPI not found. Installing..."
            # Install TensorFlow first (2.13.0+ supports newer typing-extensions compatible with FastAPI)
            "$PYTHON3_PATH" -m pip install "tensorflow>=2.13.0" 2>&1 | tail -5 || {
                log_warning "TensorFlow installation failed, continuing with FastAPI..."
            }
            "$PYTHON3_PATH" -m pip install --ignore-installed fastapi uvicorn[standard] pydantic || {
                "$PYTHON3_PATH" -m pip install --break-system-packages fastapi uvicorn[standard] pydantic || {
                    log_error "Failed to install FastAPI"
                }
            }
        fi
        
        if ! "$PYTHON3_PATH" -m uvicorn --help >/dev/null 2>&1; then
            log_error "Uvicorn not found. Installing..."
            "$PYTHON3_PATH" -m pip install --ignore-installed uvicorn[standard] || {
                "$PYTHON3_PATH" -m pip install --break-system-packages uvicorn[standard] || {
                    log_error "Failed to install uvicorn"
                }
            }
        fi
        
cat > /etc/systemd/system/whispera-ml.service <<EOF
[Unit]
Description=Whispera ML Engine Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$WORK_DIR/ml_engine
ExecStart=$PYTHON3_PATH -m uvicorn api_server:app --host 0.0.0.0 --port 8000 --log-level info
Restart=always
RestartSec=5
StartLimitInterval=300
StartLimitBurst=5
StandardOutput=journal
StandardError=journal

Environment=WHISPERA_ENV=production
Environment=WHISPERA_CORS_ORIGINS=*
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONIOENCODING=utf-8
Environment=LANG=en_US.UTF-8
Environment=LC_ALL=en_US.UTF-8

# Health check
ExecStartPre=/bin/sleep 2

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable whispera-ml
        
        # Ensure ML service is running
        if systemctl is-active --quiet whispera-ml; then
            systemctl restart whispera-ml
        else
            systemctl start whispera-ml
        fi

        # Wait for ML service to start with retry logic
        log_info "Waiting for ML service to start..."
        ML_SERVICE_READY=false
        # Increased timeout: 30 attempts * 3 seconds = 90 seconds (TensorFlow can take time to load)
        for i in {1..30}; do
            sleep 3
            if systemctl is-active --quiet whispera-ml; then
                # Check if service is responding (accept 200 even if models are still loading)
                if curl -s -f --max-time 3 http://127.0.0.1:8000/health >/dev/null 2>&1 || \
                   curl -s --max-time 3 http://127.0.0.1:8000/ >/dev/null 2>&1; then
                    ML_SERVICE_READY=true
                    log_success "ML service is running and responding on port 8000"
                    break
                else
                    if [[ $((i % 5)) -eq 0 ]]; then
                        log_info "ML service is running but not yet responding (attempt $i/30)..."
                    fi
                fi
            else
                if [[ $((i % 5)) -eq 0 ]]; then
                    log_info "Waiting for ML service to start (attempt $i/30)..."
                fi
            fi
        done
        
        if [[ "$ML_SERVICE_READY" != "true" ]]; then
            log_error "ML service failed to start or is not responding. Showing logs:"
            journalctl -u whispera-ml -n 50 --no-pager
            log_warning "ML service may not be available, but continuing with installation..."
        fi
    fi
fi

# Create systemd service
log_info "Creating systemd service..."

# Auto-fix existing service file if it has wrong dependency type
if [[ -f /etc/systemd/system/whispera-server.service ]]; then
    if grep -q "Requires=whispera-ml.service" /etc/systemd/system/whispera-server.service; then
        log_warning "Found incorrect 'Requires=' dependency in service file, fixing automatically..."
        sed -i 's/Requires=whispera-ml.service/Wants=whispera-ml.service/' /etc/systemd/system/whispera-server.service
        # Also ensure Wants= line exists if it was missing
        if ! grep -q "Wants=.*whispera-ml.service" /etc/systemd/system/whispera-server.service; then
            sed -i '/Wants=network-online.target/s/$/ whispera-ml.service/' /etc/systemd/system/whispera-server.service
        fi
        systemctl daemon-reload
        log_success "Service file fixed automatically"
    fi
fi

# Build ExecStart command - TLS всегда включен если сертификаты есть
# Используем 0.0.0.0 для явного IPv4 (чтобы клиенты могли подключиться)
EXEC_START="$SERVER_BINARY \\
  -listen 0.0.0.0:51820 \\
  -listen-tcp 0.0.0.0:4443 \\
  -listen-ws 0.0.0.0:8080 \\
  -listen-ws2 0.0.0.0:8443 \\
  -static-key ${SERVER_PRIV} \\
  -api 0.0.0.0:8081 \\
  -metrics 0.0.0.0:9101 \\
  -obfs-preset quic \\
  -audit"
  
# Add XHTTP configuration if keys are available
if [[ -n "$XHTTP_PRIV" ]] && [[ -n "$XHTTP_SHORT_ID" ]] && [[ -n "$XHTTP_SERVER_NAME" ]]; then
    log_info "XHTTP keys found - enabling XHTTP+VLESS with Marionette obfuscation..."
    EXEC_START="$EXEC_START \\
  -xhttp-target ${XHTTP_TARGET} \\
  -xhttp-server-names ${XHTTP_SERVER_NAME} \\
  -xhttp-private-key ${XHTTP_PRIV} \\
  -xhttp-short-id ${XHTTP_SHORT_ID}"
fi

# Автоматически включаем TLS для всех сервисов, если сертификаты есть
if [[ "$TLS_ENABLED" == "true" ]] && [[ -f "$TLS_CERT" ]] && [[ -f "$TLS_KEY" ]]; then
    log_info "TLS certificates found - enabling HTTPS for all services automatically..."
    EXEC_START="$EXEC_START \\
  -tls-cert ${TLS_CERT} \\
  -tls-key ${TLS_KEY} \\
  -api-tls \\
  -tls"
else
    if [[ "$TLS_ENABLED" != "true" ]]; then
        log_warning "TLS certificates not available - services will run in HTTP mode (not recommended for production)"
    fi
fi

cat > /etc/systemd/system/whispera-server.service <<EOF
[Unit]
Description=Whispera VPN Server
After=network-online.target whispera-ml.service
Wants=network-online.target whispera-ml.service

[Service]
Type=simple
User=root
WorkingDirectory=$WORK_DIR
ExecStart=$EXEC_START
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

Environment=WHISPERA_WEB_DIR=$WORK_DIR/web
Environment=WHISPERA_ML_SERVER=http://127.0.0.1:8000

# Wait for ML service to be ready before starting (increased timeout for TensorFlow loading)
ExecStartPre=/bin/bash -c 'for i in {1..60}; do if curl -s -f --max-time 2 http://127.0.0.1:8000/health >/dev/null 2>&1 || curl -s --max-time 2 http://127.0.0.1:8000/ >/dev/null 2>&1; then exit 0; fi; sleep 2; done; echo "Warning: ML service not ready, starting anyway"; exit 0'

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload

# Final check: ensure service file doesn't have Requires= (double-check after daemon-reload)
if grep -q "Requires=whispera-ml.service" /etc/systemd/system/whispera-server.service 2>/dev/null; then
    log_warning "Service file still has Requires=, fixing again..."
    sed -i 's/Requires=whispera-ml.service/Wants=whispera-ml.service/' /etc/systemd/system/whispera-server.service
    if ! grep -q "Wants=.*whispera-ml.service" /etc/systemd/system/whispera-server.service; then
        sed -i '/Wants=network-online.target/s/$/ whispera-ml.service/' /etc/systemd/system/whispera-server.service
    fi
    systemctl daemon-reload
fi

systemctl enable whispera-server

# Ensure ML service is enabled and running first
log_info "Ensuring ML service is enabled and running..."
systemctl enable whispera-ml
if ! systemctl is-active --quiet whispera-ml; then
    log_info "Starting ML service..."
    systemctl start whispera-ml
    
    # Wait for ML service to be ready
    log_info "Waiting for ML service to be ready..."
    for i in {1..30}; do
        sleep 3
        if curl -s -f --max-time 3 http://127.0.0.1:8000/health >/dev/null 2>&1 || \
           curl -s --max-time 3 http://127.0.0.1:8000/ >/dev/null 2>&1; then
            log_success "ML service is ready"
            break
        fi
        if [[ $i -eq 30 ]]; then
            log_warning "ML service is not responding after 90 seconds, but continuing..."
        fi
    done
fi

# Restart if already running, otherwise start
if systemctl is-active --quiet whispera-server; then
    log_info "Restarting existing service..."
    systemctl restart whispera-server
else
    log_info "Starting service..."
    systemctl start whispera-server
fi

# Wait for service to start and verify it's running
log_info "Waiting for service to start..."
sleep 3
for i in {1..10}; do
    if systemctl is-active --quiet whispera-server; then
        log_success "Service started successfully"
        break
    fi
    if [[ $i -eq 10 ]]; then
        log_warning "Service may not have started properly, check logs with: journalctl -u whispera-server -n 50"
    else
        sleep 1
    fi
done

# Get external IP
EXTERNAL_IP=$(curl -s4 https://api.ipify.org 2>/dev/null || \
              curl -s4 https://icanhazip.com 2>/dev/null || \
              curl -s4 https://ifconfig.me 2>/dev/null || \
              hostname -I | awk '{print $1}' || echo "YOUR_SERVER_IP")

# Save connection info
# Determine server address for Quick Connect (use domain if Let's Encrypt, otherwise IP)
if [[ "$USE_LETSENCRYPT" == "true" ]] && [[ -n "$DOMAIN" ]]; then
    QUICK_CONNECT_SERVER="$DOMAIN"
    XHTTP_SERVER_NAME="$DOMAIN"
else
    QUICK_CONNECT_SERVER="$EXTERNAL_IP"
    XHTTP_SERVER_NAME="${DOMAIN:-example.com}"
fi

# Set XHTTP target (use domain or IP with port 4443)
if [[ "$USE_LETSENCRYPT" == "true" ]] && [[ -n "$DOMAIN" ]]; then
    XHTTP_TARGET="${DOMAIN}:443"
else
    XHTTP_TARGET="${EXTERNAL_IP}:4443"
fi

# Load XHTTP keys if they exist (if not already loaded)
if [[ -z "$XHTTP_PUB" ]] || [[ -z "$XHTTP_SHORT_ID" ]]; then
    if [[ -f ".env.xhttp.priv" ]] && [[ -f ".env.xhttp.pub" ]] && [[ -f ".env.xhttp.shortid" ]]; then
        XHTTP_PRIV=$(cat .env.xhttp.priv 2>/dev/null || echo "")
        XHTTP_PUB=$(cat .env.xhttp.pub 2>/dev/null || echo "")
        XHTTP_SHORT_ID=$(cat .env.xhttp.shortid 2>/dev/null || echo "")
    fi
fi

# Всегда используем HTTPS если сертификаты есть (даже самоподписанные)
if [[ "$TLS_ENABLED" == "true" ]] && [[ -f "$TLS_CERT" ]] && [[ -f "$TLS_KEY" ]]; then
    WS_PROTOCOL="wss://"
    API_PROTOCOL="https://"
    WS_URL="${WS_PROTOCOL}${EXTERNAL_IP}:8080"
    WS2_URL="${WS_PROTOCOL}${EXTERNAL_IP}:8443"
    if [[ "$USE_LETSENCRYPT" == "true" ]] && [[ -n "$DOMAIN" ]]; then
        API_URL="${API_PROTOCOL}${DOMAIN}:8081"
        TLS_NOTE="All services use HTTPS/TLS with Let's Encrypt trusted certificate"
    else
        API_URL="${API_PROTOCOL}${EXTERNAL_IP}:8081"
        TLS_NOTE="All services use HTTPS/TLS (self-signed certificate)"
    fi
else
    # Fallback только если сертификатов нет вообще
    WS_PROTOCOL="wss://"
    API_PROTOCOL="https://"
    WS_URL="${WS_PROTOCOL}${EXTERNAL_IP}:8080"
    WS2_URL="${WS_PROTOCOL}${EXTERNAL_IP}:8443"
    API_URL="${API_PROTOCOL}${EXTERNAL_IP}:8081"
    TLS_NOTE="WARNING: HTTPS enabled but certificates may be missing - check server configuration"
fi

# Generate Quick Connect URL for Tauri client
# Include XHTTP parameters if available
if [[ -n "$XHTTP_PUB" ]] && [[ -n "$XHTTP_SHORT_ID" ]] && [[ -n "$XHTTP_SERVER_NAME" ]] && [[ ${#XHTTP_PUB} -eq 64 ]] && [[ ${#XHTTP_SHORT_ID} -eq 16 ]]; then
    QUICK_CONNECT_URL="whispera://${QUICK_CONNECT_SERVER}:51820?pub=${SERVER_PUB}&key=${CLIENT_PRIV}&xhttpPub=${XHTTP_PUB}&xhttpShortId=${XHTTP_SHORT_ID}&xhttpServerName=${XHTTP_SERVER_NAME}&xhttpFingerprint=chrome"
else
    QUICK_CONNECT_URL="whispera://${QUICK_CONNECT_SERVER}:51820?pub=${SERVER_PUB}&key=${CLIENT_PRIV}"
fi

cat > "$WORK_DIR/connection-info.txt" <<EOF
# Whispera Server Connection Info
# ===============================

SERVER_IP: ${EXTERNAL_IP}
SERVER_PORT: 51820 (UDP/DTLS)
SERVER_TCP_PORT: 4443 (TLS)
SERVER_WS_PORT: 8080 (${WS_PROTOCOL})
SERVER_WS2_PORT: 8443 (${WS_PROTOCOL})
API_PORT: 8081 (${API_PROTOCOL})

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
# WS: ${WS_URL}/ws
# WS2: ${WS2_URL}/ws

# Web Panel:
# URL: ${API_URL}
# Login: admin
# Password: admin
# ${TLS_NOTE}
EOF

# Create hosting-info.txt for client compatibility
cat > "$WORK_DIR/hosting-info.txt" <<EOF
SERVER_IP: ${EXTERNAL_IP}
SERVER_PORT: 51820
SERVER_TCP_PORT: 4443
SERVER_WS_PORT: 8080
SERVER_WS2_PORT: 8443
API_PORT: 8081
SERVER_PUBLIC_KEY: ${SERVER_PUB}
SERVER_PUB: ${SERVER_PUB}
XHTTP_PUBLIC_KEY: ${XHTTP_PUB}
XHTTP_SHORT_ID: ${XHTTP_SHORT_ID}
XHTTP_SERVER_NAME: ${XHTTP_SERVER_NAME}
EOF

# Display results
echo ""
log_success "🎉 Whispera Server installed successfully!"
echo ""

if [[ "$USE_LETSENCRYPT" == "true" ]]; then
    log_success "🔒 All services configured with Let's Encrypt HTTPS/TLS (trusted certificate)"
elif [[ "$TLS_ENABLED" == "true" ]]; then
    log_success "🔒 All services configured with HTTPS/TLS (self-signed certificate)"
else
    log_warning "⚠️  TLS not enabled - services running in HTTP mode"
fi

echo ""
log_info "📋 Connection Information:"
echo "  Server IP: ${EXTERNAL_IP}"
echo "  Server Port: 51820 (UDP/DTLS)"
echo "  TCP Port: 4443 (TLS)"
echo "  WebSocket: ${WS_URL}/ws"
echo "  WebSocket HTTP/2: ${WS2_URL}/ws"
echo "  Server Public Key: ${SERVER_PUB}"
echo "  Client Private Key: ${CLIENT_PRIV}"
echo ""

if [[ "$USE_LETSENCRYPT" == "true" ]]; then
    log_info "🔑 Quick Connect Key (for Tauri client):"
    echo "  ${QUICK_CONNECT_URL}"
    echo ""
    log_info "📋 Copy this key and paste it in the Tauri client 'Quick Connect' field"
    echo ""
    log_info "🌐 Web Panel:"
    echo "  URL: ${API_URL}"
    echo "  Login: admin"
    echo "  Password: admin"
    echo "  ✅ Using Let's Encrypt certificate - no browser warnings!"
elif [[ "$TLS_ENABLED" == "true" ]]; then
    log_info "🔑 Quick Connect Key (for Tauri client):"
    echo "  ${QUICK_CONNECT_URL}"
    echo ""
    log_info "📋 Copy this key and paste it in the Tauri client 'Quick Connect' field"
    echo ""
    log_info "🌐 Web Panel:"
    echo "  URL: ${API_URL}"
    echo "  Login: admin"
    echo "  Password: admin"
    echo "  Note: Using self-signed certificate - accept security warning in browser"
else
    log_info "🔑 Quick Connect Key (for Tauri client):"
    echo "  ${QUICK_CONNECT_URL}"
    echo ""
    log_info "📋 Copy this key and paste it in the Tauri client 'Quick Connect' field"
    echo ""
    log_info "🌐 Web Panel:"
    echo "  URL: ${API_URL}"
    echo "  Login: admin"
    echo "  Password: admin"
    echo "  ⚠️  WARNING: HTTP mode - not secure for production!"
fi
echo ""
log_info "📄 All information saved to: $WORK_DIR/connection-info.txt"
echo ""

# Final status check
log_info "🔍 Final Status Check:"
if systemctl is-active --quiet whispera-server; then
    log_success "✅ Whispera server is RUNNING"
else
    log_error "❌ Whispera server is NOT running"
    log_info "Check logs: journalctl -u whispera-server -n 50"
fi

if systemctl is-active --quiet whispera-ml 2>/dev/null; then
    log_success "✅ ML service is RUNNING"
else
    log_warning "⚠️  ML service is NOT running (optional)"
fi

echo ""
log_info "📊 Service Management:"
echo "  Status: systemctl status whispera-server"
echo "  Logs: journalctl -u whispera-server -f"
echo "  Restart: systemctl restart whispera-server"
echo "  Stop: systemctl stop whispera-server"
echo ""
log_success "🎉 Installation completed!"
echo ""


