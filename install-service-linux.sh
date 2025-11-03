#!/bin/bash

# Install Scorpion as a systemd service

if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root"
    exit 1
fi

echo "🔧 Installing Scorpion systemd service..."

# Create scorpion user if it doesn't exist
if ! id "scorpion" &>/dev/null; then
    useradd -r -s /bin/false scorpion
    echo "✅ Created scorpion user"
fi

# Set ownership
chown -R scorpion:scorpion F:\Testing_Tool

# Copy service file
cp scorpion.service /etc/systemd/system/
systemctl daemon-reload

echo "✅ Service installed. Use these commands:"
echo "   systemctl start scorpion    # Start service"
echo "   systemctl enable scorpion   # Auto-start on boot"
echo "   systemctl status scorpion   # Check status"
echo "   journalctl -u scorpion -f   # View logs"