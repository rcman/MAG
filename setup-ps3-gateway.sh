#!/bin/bash

# Setup PC as gateway for PS3 to capture all traffic

set -e

echo "=== PS3 Gateway Setup ==="
echo

if [ "$EUID" -ne 0 ]; then
    echo "This script requires root privileges."
    echo "Please run: sudo ./setup-ps3-gateway.sh"
    exit 1
fi

# Network configuration
PS3_IP="192.168.10.201"
PC_ETH_IP="192.168.10.200"
WIFI_IF="wlo1"
ETH_IF="enp0s20f0u1"

echo "PS3 IP: $PS3_IP"
echo "PC Ethernet IP: $PC_ETH_IP"
echo "WiFi interface: $WIFI_IF"
echo "Ethernet interface: $ETH_IF"
echo

# Enable IP forwarding
echo "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1

# Clear existing NAT rules
echo "Configuring NAT..."
iptables -t nat -F POSTROUTING 2>/dev/null || true

# Set up NAT masquerading
iptables -t nat -A POSTROUTING -o $WIFI_IF -j MASQUERADE

# Allow forwarding
iptables -P FORWARD ACCEPT

# Set up DNS forwarding (dnsmasq should handle this)
echo "Restarting dnsmasq..."
systemctl restart dnsmasq

echo
echo "=== Setup Complete ==="
echo
echo "Now configure the PS3 network settings:"
echo "  IP Address: $PS3_IP"
echo "  Subnet Mask: 255.255.255.0"
echo "  Default Gateway: $PC_ETH_IP"
echo "  Primary DNS: $PC_ETH_IP"
echo
echo "Then start the network monitor and launch MAG!"
echo
