#!/bin/bash
# Pre-uninstall script for cnetflow_gosnmp

# Stop and disable service if running
if [ -d /run/systemd/system ]; then
    systemctl stop cnetflow_gosnmp >/dev/null 2>&1 || true
    systemctl disable cnetflow_gosnmp >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
