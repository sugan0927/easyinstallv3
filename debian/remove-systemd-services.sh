#!/bin/bash
# Remove EasyInstall Systemd Services

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${RED}🗑️  Removing EasyInstall Systemd Services${NC}"

# Stop and disable services
systemctl stop autoheal 2>/dev/null || true
systemctl disable autoheal 2>/dev/null || true
systemctl stop glances 2>/dev/null || true
systemctl disable glances 2>/dev/null || true

# Remove service files
rm -f /lib/systemd/system/autoheal.service
rm -f /lib/systemd/system/glances.service

# Reload systemd
systemctl daemon-reload

echo -e "${GREEN}✅ Services removed${NC}"