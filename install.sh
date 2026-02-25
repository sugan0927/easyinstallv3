#!/bin/bash

# ============================================
# EasyInstall Master Installer with Integrations
# ============================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}🚀 EasyInstall Enterprise Stack with Integrations${NC}"
echo ""

# Root check
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}❌ Please run as root${NC}"
    exit 1
fi

# Install base EasyInstall
echo -e "${YELLOW}📦 Installing base EasyInstall...${NC}"
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/easyinstall/main/easyinstall(6).sh -o /tmp/easyinstall.sh
bash /tmp/easyinstall.sh
rm /tmp/easyinstall.sh

# Create integrations directory
mkdir -p /usr/share/easyinstall/integrations

# Download integrations
echo -e "${YELLOW}🔌 Downloading integrations...${NC}"

INTEGRATIONS=("docker" "kubernetes" "podman" "microvm")
BASE_URL="https://raw.githubusercontent.com/YOUR_USERNAME/easyinstall/main/integrations"

for integration in "${INTEGRATIONS[@]}"; do
    echo -e "   Downloading $integration integration..."
    curl -fsSL "$BASE_URL/$integration.sh" -o "/usr/share/easyinstall/integrations/$integration.sh"
    chmod +x "/usr/share/easyinstall/integrations/$integration.sh"
done

# Create wrapper script
cat > /usr/local/bin/easyinstall <<'EOF'
#!/bin/bash

# EasyInstall Wrapper with Integrations

BASE_CMD="/usr/local/bin/easyinstall-base"
INTEGRATIONS_DIR="/usr/share/easyinstall/integrations"

# Source integrations if available
for integration in "$INTEGRATIONS_DIR"/*.sh; do
    if [ -f "$integration" ]; then
        source "$integration"
    fi
done

# Handle integration commands
case "$1" in
    docker)
        shift
        docker_command "$@"
        ;;
    k8s|kubernetes)
        shift
        k8s_command "$@"
        ;;
    podman)
        shift
        podman_command "$@"
        ;;
    microvm)
        shift
        microvm_command "$@"
        ;;
    *)
        # Pass through to base command
        exec "$BASE_CMD" "$@"
        ;;
esac
EOF

chmod +x /usr/local/bin/easyinstall

# Create base command symlink
ln -sf /usr/local/bin/easyinstall-base /usr/local/bin/easyinstall-base 2>/dev/null || true

echo -e "${GREEN}"
echo "============================================"
echo "✅ Installation Complete with Integrations!"
echo "============================================"
echo ""
echo "Available integrations:"
echo "  docker    - Docker Compose support"
echo "  k8s       - Kubernetes support"
echo "  podman    - Podman/Containerd support"
echo "  microvm   - Firecracker/Youki isolation"
echo ""
echo "Usage examples:"
echo "  easyinstall docker create example.com wordpress"
echo "  easyinstall k8s deploy example.com"
echo "  easyinstall podman create example.com"
echo "  easyinstall microvm create-firecracker example.com"
echo ""
echo -e "${NC}"
# install.sh - EasyInstall Package Installer

echo "🚀 EasyInstall Package Installer"
echo "================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root"
    exit 1
fi

# Build the package
echo "📦 Building package..."
bash build-pkg.sh

# Install the package
echo "📦 Installing package..."
dpkg -i easyinstall_3.0_all.deb

# Fix dependencies
echo "📦 Fixing dependencies..."
apt-get install -f -y

# Run the installer
echo "🚀 Running EasyInstall..."
easyinstall

echo ""
echo "✅ Installation complete!"
echo ""
echo "Quick commands:"
echo "  easyinstall status              - Check system status"
echo "  easyinstall domain example.com  - Install WordPress"
echo "  easyinstall help                 - Show all commands"
echo "  easyinstall --pkg-status         - Check package status"
echo ""
echo "Theme/Plugin Editor: ENABLED by default"
