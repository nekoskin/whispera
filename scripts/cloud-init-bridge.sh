#!/bin/bash

MAIN_SERVER="YOUR_MAIN_SERVER:443"    # ← Your Whispera server address
REG_TOKEN="YOUR_TOKEN"                 # ← Get from Web Panel → Bridges → Get Token
PROVIDER="auto"                        # ← yandex, vk, hetzner, digitalocean, etc.
RUSSIAN_SERVICE="vk"                   # ← SNI masquerading (vk, yandex)


set -e

echo "[Cloud-Init] Installing Whispera Bridge..."

apt-get update && apt-get upgrade -y

apt-get install -y curl wget

if [ "$PROVIDER" = "auto" ]; then
    if curl -s --max-time 2 http://169.254.169.254/latest/meta-data/ &>/dev/null; then
        PROVIDER="yandex"
    elif curl -s --max-time 2 http://169.254.169.254/v1/ &>/dev/null; then
        PROVIDER="vk"
    elif curl -s --max-time 2 http://169.254.169.254/metadata/v1/ &>/dev/null; then
        PROVIDER="digitalocean"
    elif curl -s --max-time 2 http://169.254.169.254/hetzner/v1/ &>/dev/null; then
        PROVIDER="hetzner"
    else
        PROVIDER="generic"
    fi
    echo "[Cloud-Init] Detected provider: $PROVIDER"
fi

curl -sL "https://${MAIN_SERVER%:*}/install-bridge.sh" -o /tmp/install-bridge.sh || \
    curl -sL "https://raw.githubusercontent.com/your-repo/whispera/main/scripts/install-bridge.sh" -o /tmp/install-bridge.sh

chmod +x /tmp/install-bridge.sh
/tmp/install-bridge.sh "$MAIN_SERVER" "$REG_TOKEN" \
    --provider "$PROVIDER" \
    --russian-service "$RUSSIAN_SERVICE"

echo "[Cloud-Init] Whispera Bridge installed successfully!"
