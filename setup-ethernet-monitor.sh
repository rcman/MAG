#!/bin/bash

# Setup Ethernet interface for monitoring PS3 on 192.168.10.x network

set -e

echo "=== Ethernet Monitor Setup ==="
echo

if [ "$EUID" -ne 0 ]; then
    echo "This script requires root privileges."
    echo "Please run: sudo ./setup-ethernet-monitor.sh"
    exit 1
fi

ETH_IF="enp0s20f0u1"
STATIC_IP="192.168.10.200"
NETMASK="24"
GATEWAY="192.168.10.1"

echo "Configuring $ETH_IF with static IP $STATIC_IP..."

# Bring down the interface first
ip link set $ETH_IF down 2>/dev/null || true

# Remove any existing IP addresses
ip addr flush dev $ETH_IF 2>/dev/null || true

# Set the static IP
ip addr add ${STATIC_IP}/${NETMASK} dev $ETH_IF

# Bring the interface up
ip link set $ETH_IF up

# Enable promiscuous mode for packet capture
ip link set $ETH_IF promisc on

echo "Interface configured:"
ip addr show $ETH_IF

echo
echo "=== Setup Complete ==="
echo
echo "Ethernet interface $ETH_IF is now:"
echo "  IP: $STATIC_IP"
echo "  Network: 192.168.10.0/24"
echo "  Promiscuous mode: enabled"
echo
echo "Now start the network monitor:"
echo "  cd /home/franco/mag3/network-monitor"
echo "  sudo java -jar target/network-monitor-1.0.jar"
echo
echo "Then start MAG on the PS3 and we'll capture the traffic."
echo
