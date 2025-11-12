#!/bin/bash
# Post-installation script for cnetflow_gosnmp

# Reload systemd daemon if systemd is available
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

# Create config directory if it doesn't exist
mkdir -p /etc/cnetflow_gosnmp

# Set permissions
chmod 755 /usr/bin/cnetflow_gosnmp

echo "cnetflow_gosnmp has been installed successfully."
echo "Configure your settings in /etc/cnetflow_gosnmp/config.env"
echo "To start the service: systemctl start cnetflow_gosnmp"
echo "To enable at boot: systemctl enable cnetflow_gosnmp"
