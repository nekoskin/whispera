#!/bin/bash
# Whispera Update Script

WORK_DIR="/opt/whispera"
BIN_PATH="/usr/local/bin"
DAT_PATH="/usr/local/share/whispera"

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "Updating Whispera..."

cd "$WORK_DIR" || exit 1

echo "Pulling latest changes..."
git pull origin main

echo "Building server..."
export PATH=$PATH:/usr/local/go/bin
go build -trimpath -ldflags "-w -s" -o whispera-server ./cmd/server

if [[ ! -f "whispera-server" ]]; then
    echo "Build failed!"
    exit 1
fi

echo "Stopping service..."
systemctl stop whispera

echo "Updating binary..."
cp whispera-server "$BIN_PATH/whispera"
chmod +x "$BIN_PATH/whispera"

echo "Updating Web UI..."
if [[ -d "web" ]]; then
    # Clean old web files
    rm -rf "$DAT_PATH/web/*"
    mkdir -p "$DAT_PATH/web"
    cp -r web/* "$DAT_PATH/web/"
fi

echo "Restarting service..."
systemctl start whispera

echo "Update complete!"
