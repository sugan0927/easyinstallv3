#!/bin/bash

# ============================================
# EasyInstall Complete Stack Installer
# Virtual Environment Based (Python 3.11+ compatible)
# ============================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${GREEN}🚀 EasyInstall Enterprise Stack - VirtualEnv Edition${NC}"
echo ""

# Root check
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}❌ Please run as root${NC}"
    exit 1
fi

# Detect MySQL/MariaDB client
DB_CLIENT="mysql"
if command -v mariadb >/dev/null 2>&1; then
    DB_CLIENT="mariadb"
    echo -e "${GREEN}✅ MariaDB detected, using 'mariadb' command${NC}"
elif command -v mysql >/dev/null 2>&1; then
    DB_CLIENT="mysql"
    echo -e "${GREEN}✅ MySQL detected, using 'mysql' command${NC}"
else
    echo -e "${YELLOW}⚠️ No MySQL/MariaDB client found, installing MariaDB client...${NC}"
    apt update
    apt install -y mariadb-client
    DB_CLIENT="mariadb"
fi

# ============================================
# Step 1: Install Required System Packages
# ============================================
echo -e "${YELLOW}📦 Installing system dependencies...${NC}"

apt update
apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-full \
    nginx \
    redis-server \
    certbot \
    python3-certbot-nginx \
    mariadb-client \
    curl \
    wget \
    git \
    unzip \
    zip \
    tar \
    htop \
    glances \
    fail2ban \
    ufw \
    rsync \
    cron \
    jq \
    net-tools \
    dnsutils \
    whois \
    ncdu \
    tree \
    apache2-utils \
    socat \
    bc \
    figlet \
    lolcat \
    neofetch

# ============================================
# Step 2: Download and Run Base Installer
# ============================================
echo -e "${YELLOW}📥 Downloading base EasyInstall installer...${NC}"

BASE_INSTALLER_URL="https://raw.githubusercontent.com/sugan0927/easyinstall-worker./main/easyinstall.sh"

if curl -fsSL "$BASE_INSTALLER_URL" -o /tmp/easyinstall-base.sh; then
    echo -e "${GREEN}✅ Base installer downloaded successfully${NC}"
    chmod +x /tmp/easyinstall-base.sh
else
    echo -e "${RED}❌ Failed to download base installer${NC}"
    exit 1
fi

echo -e "${YELLOW}⚙️ Running base EasyInstall installation...${NC}"
bash /tmp/easyinstall-base.sh

# ============================================
# Step 3: Create Python Virtual Environment
# ============================================
echo -e "${YELLOW}🐍 Creating Python virtual environment...${NC}"

VENV_DIR="/opt/easyinstall-venv"
mkdir -p "$VENV_DIR"
python3 -m venv "$VENV_DIR"

# Activate virtual environment and install packages
source "$VENV_DIR/bin/activate"

pip install --upgrade pip
pip install \
    flask \
    flask-socketio \
    flask-login \
    bcrypt \
    paramiko \
    boto3 \
    google-auth \
    google-auth-oauthlib \
    google-auth-httplib2 \
    googleapiclient \
    redis \
    gunicorn \
    eventlet \
    python-dotenv \
    pyyaml \
    requests \
    psutil \
    python-telegram-bot \
    discord-webhook \
    slack-sdk \
    sendgrid \
    twilio \
    pillow \
    qrcode \
    pyotp \
    cryptography

deactivate

echo -e "${GREEN}✅ Virtual environment created at $VENV_DIR${NC}"

# ============================================
# Step 4: Create Directory Structure
# ============================================
echo -e "${YELLOW}📝 Creating directory structure...${NC}"

mkdir -p /usr/local/lib/easyinstall/{core,web,db,backup,cloud,monitor,docker,security,tools}
mkdir -p /etc/easyinstall/{configs,ssl,ssh,backup}
mkdir -p /var/lib/easyinstall/{data,logs,temp,backups}
mkdir -p /var/log/easyinstall
mkdir -p /opt/easyinstall-webui/{app,static,logs}
mkdir -p /opt/easyinstall-webui/app/templates

# ============================================
# Step 5: Create Database Helper Functions
# ============================================
cat > /usr/local/bin/db-helper <<'EOF'
#!/bin/bash
if command -v mariadb >/dev/null 2>&1; then
    exec mariadb "$@"
elif command -v mysql >/dev/null 2>&1; then
    exec mysql "$@"
else
    echo "No database client found"
    exit 1
fi
EOF
chmod +x /usr/local/bin/db-helper

cat > /usr/local/bin/db-dump-helper <<'EOF'
#!/bin/bash
if command -v mariadb-dump >/dev/null 2>&1; then
    exec mariadb-dump "$@"
elif command -v mysqldump >/dev/null 2>&1; then
    exec mysqldump "$@"
else
    echo "No database dump client found"
    exit 1
fi
EOF
chmod +x /usr/local/bin/db-dump-helper

# ============================================
# Step 6: Create WebUI Launcher Script
# ============================================
cat > /usr/local/bin/webui-launcher <<'EOF'
#!/bin/bash
source /opt/easyinstall-venv/bin/activate
cd /opt/easyinstall-webui/app
exec gunicorn -w 4 -k eventlet -b 127.0.0.1:5000 app:app
EOF
chmod +x /usr/local/bin/webui-launcher

# ============================================
# Step 7: Download WebUI Files
# ============================================
echo -e "${YELLOW}🌐 Downloading WebUI files...${NC}"

WEBUI_BASE="https://raw.githubusercontent.com/sugan0927/easyinstall-worker./main/webui"

# Download app.py
curl -fsSL "$WEBUI_BASE/app.py" -o /opt/easyinstall-webui/app/app.py

# Download HTML templates
curl -fsSL "$WEBUI_BASE/templates/login.html" -o /opt/easyinstall-webui/app/templates/login.html
curl -fsSL "$WEBUI_BASE/templates/dashboard.html" -o /opt/easyinstall-webui/app/templates/dashboard.html

# ============================================
# Step 8: Create Systemd Service for WebUI
# ============================================
cat > /etc/systemd/system/easyinstall-webui.service <<'EOF'
[Unit]
Description=EasyInstall WebUI
After=network.target redis-server.service
Wants=redis-server.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/easyinstall-webui/app
Environment="PATH=/opt/easyinstall-venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/usr/local/bin/webui-launcher
Restart=always
RestartSec=10
StandardOutput=append:/var/log/easyinstall/webui.log
StandardError=append:/var/log/easyinstall/webui-error.log

[Install]
WantedBy=multi-user.target
EOF

# ============================================
# Step 9: Configure Nginx
# ============================================
mkdir -p /etc/nginx/ssl

# Generate SSL certificate if not exists
if [ ! -f /etc/nginx/ssl/easyinstall.crt ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/easyinstall.key \
        -out /etc/nginx/ssl/easyinstall.crt \
        -subj "/C=US/ST=State/L=City/O=EasyInstall/CN=localhost" 2>/dev/null
fi

cat > /etc/nginx/sites-available/easyinstall-webui <<'EOF'
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name _;

    ssl_certificate /etc/nginx/ssl/easyinstall.crt;
    ssl_certificate_key /etc/nginx/ssl/easyinstall.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    access_log /var/log/nginx/easyinstall-webui-access.log;
    error_log /var/log/nginx/easyinstall-webui-error.log;

    location /static {
        alias /opt/easyinstall-webui/app/static;
        expires 30d;
    }

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_cache off;
    }

    location /socket.io {
        proxy_pass http://127.0.0.1:5000/socket.io;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;
        proxy_cache off;
    }
}
EOF

# Enable site
ln -sf /etc/nginx/sites-available/easyinstall-webui /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# ============================================
# Step 10: Initialize WebUI Database
# ============================================
echo -e "${YELLOW}🗄️ Initializing WebUI database...${NC}"

source /opt/easyinstall-venv/bin/activate
cd /opt/easyinstall-webui/app

python3 -c "
import sqlite3
import bcrypt
import secrets
import os

DB_PATH = '/var/lib/easyinstall/webui/users.db'

# Create directory
os.makedirs('/var/lib/easyinstall/webui', exist_ok=True)

# Connect to database
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# Create users table
c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL,
              email TEXT,
              role TEXT DEFAULT 'admin',
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              last_login TIMESTAMP)''')

# Create default admin user
default_password = secrets.token_urlsafe(12)
password_hash = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt())

try:
    c.execute(\"INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)\",
             ('admin', password_hash, 'admin'))
    conn.commit()
    
    # Save credentials
    with open('/var/lib/easyinstall/webui/admin_credentials.txt', 'w') as f:
        f.write(f\"Username: admin\\nPassword: {default_password}\\n\")
    os.chmod('/var/lib/easyinstall/webui/admin_credentials.txt', 0o600)
except Exception as e:
    print(f\"Warning: {e}\")

conn.close()
"

deactivate

# ============================================
# Step 11: Create Management Scripts
# ============================================
echo -e "${YELLOW}📝 Creating management scripts...${NC}"

cat > /usr/local/bin/easy-webui <<'EOF'
#!/bin/bash
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

case "$1" in
    status)
        systemctl status easyinstall-webui
        ;;
    start)
        systemctl start easyinstall-webui
        echo -e "${GREEN}✅ WebUI started${NC}"
        ;;
    stop)
        systemctl stop easyinstall-webui
        echo -e "${GREEN}✅ WebUI stopped${NC}"
        ;;
    restart)
        systemctl restart easyinstall-webui
        echo -e "${GREEN}✅ WebUI restarted${NC}"
        ;;
    logs)
        journalctl -u easyinstall-webui -f
        ;;
    url)
        IP=$(hostname -I | awk '{print $1}')
        echo -e "${GREEN}🌐 WebUI URL: https://$IP${NC}"
        if [ -f "/var/lib/easyinstall/webui/admin_credentials.txt" ]; then
            cat "/var/lib/easyinstall/webui/admin_credentials.txt"
        fi
        ;;
    password)
        if [ -f "/var/lib/easyinstall/webui/admin_credentials.txt" ]; then
            cat "/var/lib/easyinstall/webui/admin_credentials.txt"
        else
            echo -e "${RED}❌ Credentials not found${NC}"
        fi
        ;;
    *)
        echo "Usage: easy-webui {status|start|stop|restart|logs|url|password}"
        ;;
esac
EOF
chmod +x /usr/local/bin/easy-webui

# Create simple status command
cat > /usr/local/bin/easy-status <<'EOF'
#!/bin/bash
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}📊 System Status:${NC}"
echo "----------------------------------------"
echo -e "Nginx:      $(systemctl is-active nginx)"
echo -e "PHP-FPM:    $(systemctl is-active php*-fpm 2>/dev/null || echo 'inactive')"
echo -e "MariaDB:    $(systemctl is-active mariadb)"
echo -e "Redis:      $(systemctl is-active redis-server)"
echo -e "Memcached:  $(systemctl is-active memcached)"
echo -e "Fail2ban:   $(systemctl is-active fail2ban)"
echo -e "WebUI:      $(systemctl is-active easyinstall-webui)"
echo ""
echo -e "Disk Usage: $(df -h / | awk 'NR==2 {print $5}')"
echo -e "Memory:     $(free -h | awk '/Mem:/ {print $3"/"$2}')"
echo ""
echo -e "WebUI URL:  https://$(hostname -I | awk '{print $1}')"
EOF
chmod +x /usr/local/bin/easy-status

# ============================================
# Step 12: Start Services
# ============================================
echo -e "${YELLOW}🚀 Starting services...${NC}"

systemctl daemon-reload
systemctl enable redis-server
systemctl start redis-server
systemctl enable easyinstall-webui
systemctl start easyinstall-webui
nginx -t && systemctl reload nginx

# ============================================
# Step 13: Cleanup
# ============================================
rm -f /tmp/easyinstall-base.sh

# ============================================
# Step 14: Show Completion Message
# ============================================
IP_ADDRESS=$(hostname -I | awk '{print $1}')

if [ -f "/var/lib/easyinstall/webui/admin_credentials.txt" ]; then
    ADMIN_PASS=$(grep "Password:" /var/lib/easyinstall/webui/admin_credentials.txt | cut -d' ' -f2)
else
    ADMIN_PASS="Check /var/lib/easyinstall/webui/admin_credentials.txt"
fi

clear
echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════╗"
echo "║     EasyInstall - VirtualEnv Edition Complete         ║"
echo "╚════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${BLUE}📊 WebUI Access:${NC}"
echo "   URL: https://$IP_ADDRESS"
echo "   Username: admin"
echo "   Password: $ADMIN_PASS"
echo ""

echo -e "${BLUE}📁 Credentials saved:${NC}"
echo "   /var/lib/easyinstall/webui/admin_credentials.txt"
echo ""

echo -e "${GREEN}✅ Python Virtual Environment: /opt/easyinstall-venv${NC}"
echo ""

echo -e "${YELLOW}📝 Quick Commands:${NC}"
echo "  easy-status                    # Check system status"
echo "  easy-webui status              # Check WebUI status"
echo "  easy-webui url                 # Show WebUI URL"
echo "  easy-webui logs                # View WebUI logs"
echo "  easy-webui restart             # Restart WebUI"
echo ""

echo -e "${YELLOW}🌐 To create a WordPress site:${NC}"
echo "  Use the base EasyInstall command from the original installer"
echo "  Example: /usr/local/bin/easyinstall domain create test.com"
echo ""

echo -e "${GREEN}Happy Hosting! 🚀${NC}"
