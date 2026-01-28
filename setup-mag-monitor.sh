#!/bin/bash

# MAG Network Monitor Setup Script
# Enables internet access for PS3 while capturing traffic

set -e

echo "=== MAG Network Monitor Setup ==="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script requires root privileges."
    echo "Please run: sudo ./setup-mag-monitor.sh"
    exit 1
fi

# Remove PlayStation DNS redirects
echo "Removing PlayStation DNS redirects..."
rm -f /etc/dnsmasq.d/playstation.conf
systemctl restart dnsmasq
echo "DNS redirects removed"

# Enable IP forwarding
echo "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1

# Detect interfaces
WIFI_IF=$(ip route | grep default | awk '{print $5}' | head -1)
ETH_IF="enp0s20f0u1"

echo "WiFi interface (internet): $WIFI_IF"
echo "Ethernet interface (PS3): $ETH_IF"

# Set up NAT
echo "Setting up NAT..."
iptables -t nat -C POSTROUTING -o "$WIFI_IF" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "$WIFI_IF" -j MASQUERADE

iptables -C FORWARD -i "$ETH_IF" -o "$WIFI_IF" -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$ETH_IF" -o "$WIFI_IF" -j ACCEPT

iptables -C FORWARD -i "$WIFI_IF" -o "$ETH_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$WIFI_IF" -o "$ETH_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "NAT configured"

echo
echo "=== Setup Complete ==="
echo
echo "PS3 now has internet access through your PC"
echo "All traffic will be visible to the network monitor"
echo
echo "Next: Start the network monitor with:"
echo "  cd /home/franco/mag3/network-monitor"
echo "  sudo java -jar target/network-monitor-1.0.jar"
echo
