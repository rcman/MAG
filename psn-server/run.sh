#!/bin/bash

# PSN Mock Server runner script
# Requires root/sudo to bind to ports 80 and 443

JAR_PATH="$(dirname "$0")/target/psn-server-1.0.jar"

if [ ! -f "$JAR_PATH" ]; then
    echo "JAR not found. Building..."
    cd "$(dirname "$0")"
    mvn clean package -q
fi

# Check if running as root (needed for ports 80/443)
if [ "$EUID" -ne 0 ]; then
    echo "Ports 80/443 require root. Running with sudo..."
    sudo java -jar "$JAR_PATH" "$@"
else
    java -jar "$JAR_PATH" "$@"
fi
