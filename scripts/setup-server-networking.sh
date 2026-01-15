#!/bin/bash

# Whispera VPN Server Network Configuration Script
# Enables IP forwarding and NAT for proper tunnel operation
# Usage: sudo ./setup-server-networking.sh <WAN_INTERFACE> [CLIENT_SUBNET]

set -e

WAN_IF="${1:-eth0}"
CLIENT_SUBNET="${2:-10.0.85.0/24}"
TUN_IF="${3:-wg0}"  # Optional: for wireguard/other tunnels

echo "=========================================="
echo "Whispera VPN Server Network Setup"
echo "=========================================="
echo "WAN Interface: $WAN_IF"
echo "Client Subnet: $CLIENT_SUBNET"
echo "TUN Interface: $TUN_IF"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root (use: sudo $0)"
    exit 1
fi

# Check if interface exists
if ! ip link show "$WAN_IF" > /dev/null 2>&1; then
    echo "❌ Error: Interface $WAN_IF not found!"
    echo "Available interfaces:"
    ip link show | grep "^[0-9]" | awk '{print "  " $2}' | sed 's/:$//'
    exit 1
fi

echo "✓ Interface $WAN_IF exists"
echo ""

# ============================================
# 1. Enable IP Forwarding (Permanent)
# ============================================
echo "1. Enabling IP forwarding..."

# Check current setting
CURRENT_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
if [ "$CURRENT_FORWARD" -eq 1 ]; then
    echo "  ✓ IP forwarding already enabled"
else
    echo "  Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1
    
    # Make permanent
    if grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf; then
        sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward = 1/' /etc/sysctl.conf
    else
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    fi
    sysctl -p > /dev/null 2>&1
    echo "  ✓ IP forwarding enabled and saved to /etc/sysctl.conf"
fi

# ============================================
# 2. Configure NAT with iptables
# ============================================
echo ""
echo "2. Configuring NAT (MASQUERADE) for traffic from $CLIENT_SUBNET..."

# Check if iptables is available
if ! command -v iptables &> /dev/null; then
    echo "  ⚠ iptables not found, trying ufw..."
    if command -v ufw &> /dev/null; then
        echo "  Using UFW instead of iptables"
        ufw default allow routed in
        ufw allow from $CLIENT_SUBNET to any
    fi
else
    # Enable MASQUERADE
    if iptables -t nat -C POSTROUTING -s "$CLIENT_SUBNET" -o "$WAN_IF" -j MASQUERADE 2>/dev/null; then
        echo "  ✓ NAT rule already exists"
    else
        echo "  Adding NAT rule..."
        iptables -t nat -A POSTROUTING -s "$CLIENT_SUBNET" -o "$WAN_IF" -j MASQUERADE
        echo "  ✓ NAT rule added"
    fi

    # Enable FORWARD for traffic from clients
    if iptables -C FORWARD -i tun0 -o "$WAN_IF" -j ACCEPT 2>/dev/null; then
        echo "  ✓ Forward rule (client->WAN) already exists"
    else
        echo "  Adding forward rule (client->WAN)..."
        iptables -A FORWARD -i tun0 -o "$WAN_IF" -j ACCEPT
        echo "  ✓ Forward rule added"
    fi

    # Enable FORWARD for return traffic
    if iptables -C FORWARD -i "$WAN_IF" -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
        echo "  ✓ Forward rule (WAN->client) already exists"
    else
        echo "  Adding forward rule (WAN->client)..."
        iptables -A FORWARD -i "$WAN_IF" -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
        echo "  ✓ Forward rule added"
    fi
fi

# ============================================
# 3. Save iptables rules (if using iptables)
# ============================================
if command -v iptables-save &> /dev/null; then
    echo ""
    echo "3. Saving iptables rules..."
    if [ -d "/etc/iptables" ]; then
        iptables-save > /etc/iptables/rules.v4
        echo "  ✓ Rules saved to /etc/iptables/rules.v4"
        
        # Setup auto-restore on boot
        if ! systemctl is-enabled iptables 2>/dev/null; then
            if [ -f "/etc/debian_version" ]; then
                echo "  Installing iptables-persistent..."
                apt-get update && apt-get install -y iptables-persistent
                echo "  ✓ iptables-persistent installed"
            fi
        fi
    fi
fi

# ============================================
# 4. Verify Settings
# ============================================
echo ""
echo "4. Verifying configuration..."
echo "  Current IP forwarding state:"
cat /proc/sys/net/ipv4/ip_forward | xargs echo "    " "ipv4.ip_forward ="

echo ""
echo "  NAT rules in effect:"
if command -v iptables &> /dev/null; then
    iptables -t nat -L POSTROUTING -v -n | grep "$CLIENT_SUBNET" | tail -1 | xargs echo "    "
    if [ $? -ne 0 ]; then
        echo "    ⚠ No NAT rules found for $CLIENT_SUBNET (this might be OK if using UFW)"
    fi
fi

echo ""
echo "  FORWARD rules in effect:"
if command -v iptables &> /dev/null; then
    iptables -L FORWARD -v -n | grep -E "tun0|$WAN_IF" | head -2 | xargs -I {} echo "    {}"
fi

# ============================================
# 5. Summary and Next Steps
# ============================================
echo ""
echo "=========================================="
echo "✓ Server network configuration complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Ensure your Whispera server is running on port 8443 (or configured port)"
echo "2. Verify clients can connect to your server"
echo "3. On client side, set environment variable:"
echo "   export WHISPERA_VPN_SERVER=<YOUR_SERVER_IP>"
echo "4. Run client and test with: netstat -abon | findstr :443"
echo ""
echo "For debugging:"
echo "  • Check server logs: journalctl -u whispera -f"
echo "  • Monitor traffic: tcpdump -i $WAN_IF 'host <CLIENT_IP>'"
echo "  • Test NAT: iptables -t nat -L POSTROUTING -v -n"
echo ""
