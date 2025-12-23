#!/bin/bash
# Whispera Tauri Client - Cross-Platform Build Script
# Builds installers for Windows, Linux, macOS

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$SCRIPT_DIR"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Whispera Tauri - Cross-Platform Build${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check dependencies
check_dep() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}[ERROR] $1 не найден${NC}"
        return 1
    fi
    return 0
}

echo -e "${BLUE}[INFO] Проверка зависимостей...${NC}"

if ! check_dep cargo; then
    echo -e "${RED}Установите Rust: https://rustup.rs/${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Rust: $(cargo --version)${NC}"

if ! check_dep node; then
    echo -e "${RED}Установите Node.js: https://nodejs.org/${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Node.js: $(node --version)${NC}"
echo -e "${GREEN}[OK] npm: $(npm --version)${NC}"

if ! check_dep go; then
    echo -e "${YELLOW}[WARNING] Go не найден - пропустим сборку Go клиента${NC}"
    SKIP_GO=1
else
    echo -e "${GREEN}[OK] Go: $(go version)${NC}"
fi

echo ""

# Install dependencies
if [ ! -d "node_modules" ]; then
    echo -e "${BLUE}[INFO] Установка npm зависимостей...${NC}"
    npm install
fi

    # Download wintun.dll for Windows (only if building for Windows)
    if [[ "$target" == *"windows"* ]] || [[ "$target" == *"msvc"* ]]; then
        if [ ! -f "src-tauri/resources/wintun.dll" ]; then
            echo -e "${BLUE}[INFO] Загрузка wintun.dll для Windows...${NC}"
            if [ -f "download-wintun.ps1" ]; then
                powershell -ExecutionPolicy Bypass -File "download-wintun.ps1" 2>/dev/null || {
                    echo -e "${YELLOW}[WARNING] Не удалось загрузить wintun.dll автоматически${NC}"
                }
            fi
        fi
    fi

# Build Go client for Windows (needed for Tauri resources)
if [ -z "${SKIP_GO:-}" ] && [ ! -f "src-tauri/resources/whispera-go-client.exe" ]; then
    echo -e "${BLUE}[INFO] Сборка Go клиента для Windows...${NC}"
    cd "$PROJECT_ROOT"
    GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o client-package-tauri/src-tauri/resources/whispera-go-client.exe ./cmd/client
    cd "$SCRIPT_DIR"
    echo -e "${GREEN}[SUCCESS] Go клиент для Windows собран${NC}"
fi

# Install Rust targets for cross-compilation
echo -e "${BLUE}[INFO] Установка Rust targets для кроссплатформенной сборки...${NC}"
rustup target add x86_64-pc-windows-msvc 2>/dev/null || true
rustup target add x86_64-unknown-linux-gnu 2>/dev/null || true
rustup target add x86_64-apple-darwin 2>/dev/null || true
rustup target add aarch64-apple-darwin 2>/dev/null || true

# Create output directory
OUTPUT_DIR="$PROJECT_ROOT/releases"
mkdir -p "$OUTPUT_DIR"

# Build function
build_platform() {
    local target=$1
    local platform_name=$2
    local go_os=$3
    local go_arch=$4
    
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}[INFO] Сборка для $platform_name ($target)${NC}"
    echo -e "${BLUE}========================================${NC}"
    
    # Build Go client for this platform if needed
    # Tauri externalBin автоматически добавит .exe для Windows
    if [ -z "${SKIP_GO:-}" ]; then
        GO_CLIENT_NAME="whispera-go-client"
        GO_CLIENT_PATH="src-tauri/resources/$GO_CLIENT_NAME"
        
        # Для Windows Tauri добавит .exe автоматически, но нам нужно собрать с .exe
        if [ "$go_os" = "windows" ]; then
            GO_CLIENT_PATH="src-tauri/resources/${GO_CLIENT_NAME}.exe"
        fi
        
        # Only rebuild if different from Windows or doesn't exist
        if [ "$go_os" != "windows" ] || [ ! -f "$GO_CLIENT_PATH" ]; then
            echo -e "${YELLOW}[INFO] Сборка Go клиента для $platform_name...${NC}"
            cd "$PROJECT_ROOT"
            GOOS=$go_os GOARCH=$go_arch go build -ldflags="-s -w" -o "client-package-tauri/$GO_CLIENT_PATH" ./cmd/client
            cd "$SCRIPT_DIR"
        fi
    fi
    
    # Build Tauri
    echo -e "${YELLOW}[INFO] Сборка Tauri приложения...${NC}"
    npm run tauri build -- --target "$target" || {
        echo -e "${RED}[ERROR] Ошибка сборки для $platform_name${NC}"
        return 1
    }
    
    # Copy results
    local bundle_dir="src-tauri/target/$target/release/bundle"
    if [ -d "$bundle_dir" ]; then
        local platform_dir="$OUTPUT_DIR/$platform_name"
        mkdir -p "$platform_dir"
        
        # Copy all bundle files
        cp -r "$bundle_dir"/* "$platform_dir/" 2>/dev/null || true
        
        echo -e "${GREEN}[SUCCESS] $platform_name инсталляторы созданы в: $platform_dir${NC}"
        
        # List created files
        echo -e "${BLUE}Созданные файлы:${NC}"
        find "$platform_dir" -type f -name "*.msi" -o -name "*.exe" -o -name "*.AppImage" -o -name "*.deb" -o -name "*.dmg" -o -name "*.app" 2>/dev/null | while read -r file; do
            echo -e "  ${GREEN}✓${NC} $(basename "$file")"
        done
    fi
    
    return 0
}

# Main build process
echo ""
echo -e "${BLUE}Выберите платформы для сборки:${NC}"
echo "1. Windows (x86_64)"
echo "2. Linux (x86_64)"
echo "3. macOS (x86_64)"
echo "4. macOS (ARM64)"
echo "5. Все платформы"
echo ""
read -p "Введите номер (1-5) или нажмите Enter для всех: " choice
choice=${choice:-5}

case $choice in
    1)
        build_platform "x86_64-pc-windows-msvc" "windows" "windows" "amd64"
        ;;
    2)
        build_platform "x86_64-unknown-linux-gnu" "linux" "linux" "amd64"
        ;;
    3)
        build_platform "x86_64-apple-darwin" "macos" "darwin" "amd64"
        ;;
    4)
        build_platform "aarch64-apple-darwin" "macos-arm" "darwin" "arm64"
        ;;
    5)
        build_platform "x86_64-pc-windows-msvc" "windows" "windows" "amd64"
        build_platform "x86_64-unknown-linux-gnu" "linux" "linux" "amd64"
        build_platform "x86_64-apple-darwin" "macos" "darwin" "amd64"
        build_platform "aarch64-apple-darwin" "macos-arm" "darwin" "arm64"
        ;;
    *)
        echo -e "${RED}[ERROR] Неверный выбор${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Сборка завершена!${NC}"
echo -e "${GREEN}Результаты в: $OUTPUT_DIR${NC}"
echo -e "${GREEN}========================================${NC}"

