#!/bin/bash

# PlayStation DNS Server runner script
# Requires root/sudo to bind to port 53

JAR_PATH="$(dirname "$0")/target/dns-server-1.0.jar"

if [ ! -f "$JAR_PATH" ]; then
    echo "JAR not found. Building..."
    cd "$(dirname "$0")"
    mvn clean package -q
fi

# Check if running as root (needed for port 53)
if [ "$EUID" -ne 0 ]; then
    echo "Note: Port 53 requires root. Running with sudo..."
    sudo java -jar "$JAR_PATH" "$@"
else
    java -jar "$JAR_PATH" "$@"
fi
