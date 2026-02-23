#!/bin/bash

set -e

# ============================================
# Package Manager Integration - ADD THIS AT TOP
# ============================================
PKG_MODE=false
PKG_STATE_DIR="/var/lib/easyinstall"
PKG_CONFIG_DIR="/etc/easyinstall"
PKG_HOOKS_DIR="/usr/share/easyinstall/hooks"

# Source package manager if available
if [ -f "/usr/share/easyinstall/pkg-manager.sh" ]; then
    source "/usr/share/easyinstall/pkg-manager.sh"
    PKG_MODE=true
    
    # Create state directory if not exists
    mkdir -p "$PKG_STATE_DIR" "$PKG_CONFIG_DIR"
    
    # Load configuration
    if [ -f "$PKG_CONFIG_DIR/config" ]; then
        source "$PKG_CONFIG_DIR/config"
    fi
    
    # Begin transaction
    begin_transaction "full-install"
fi

# ============================================
# ✅ Domain Existence Check Function - ADDED
# ============================================
check_domain_exists() {
    local domain=$1
    
    # Check for existing nginx config
    if [ -f "/etc/nginx/sites-available/${domain}" ] || [ -f "/etc/nginx/sites-enabled/${domain}" ]; then
        return 0
    fi
    
    # Check for WordPress installation
    if [ -d "/var/www/html/${domain}" ] && [ -f "/var/www/html/${domain}/wp-config.php" ]; then
        return 0
    fi
    
    # Check for multisite installation
    if [ -d "/var/www/sites/${domain}" ] && [ -f "/var/www/sites/${domain}/public/wp-config.php" ]; then
        return 0
    fi
    
    return 1
}

# ============================================
# ✅ WordPress Installation Function - ADDED
# ============================================
install_wordpress() {
    local domain=$1
    local use_ssl=$2
    local php_version=${3:-$(ls /etc/php/ 2>/dev/null | head -1)}
    
    # Check if domain already exists
    if check_domain_exists "$domain"; then
        echo -e "${RED}❌ Domain ${domain} already exists. WordPress installation aborted.${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}📦 Installing WordPress for ${domain}...${NC}"
    
    # Call the existing installer with correct parameters
    /usr/local/bin/install-wordpress "$domain" "$([ "$use_ssl" = "true" ] && echo "--ssl")" "$php_version"
}

# ============================================
# ✅ PHP Site Creation Function - ADDED
# ============================================
create_php_site() {
    local domain=$1
    local use_ssl=$2
    
    # Check if domain already exists
    if check_domain_exists "$domain"; then
        echo -e "${RED}❌ Domain ${domain} already exists. PHP site creation aborted.${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}🐘 Creating PHP site for ${domain}...${NC}"
    
    # Create site directory
    SITE_DIR="/var/www/html/${domain}"
    mkdir -p "$SITE_DIR"
    
    # Get PHP version
    PHP_VERSION=$(ls /etc/php/ 2>/dev/null | head -1)
    [ -z "$PHP_VERSION" ] && PHP_VERSION="8.2"
    
    # Create sample index.php
    cat > "$SITE_DIR/index.php" <<EOF
<?php
/**
 * Sample PHP site for ${domain}
 */
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${domain}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            text-align: center;
        }
        h1 {
            color: #2563eb;
            margin-bottom: 20px;
        }
        .info {
            background: #f3f4f6;
            border-radius: 8px;
            padding: 20px;
            margin-top: 30px;
        }
        .php-info {
            color: #059669;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <h1>Welcome to <?php echo htmlspecialchars(\$_SERVER['HTTP_HOST']); ?></h1>
    
    <div class="info">
        <p>This is a PHP site created with <strong>EasyInstall</strong></p>
        <p class="php-info">PHP Version: <?php echo phpversion(); ?></p>
        <p>Server: <?php echo php_uname('s'); ?></p>
        <p>Date: <?php echo date('Y-m-d H:i:s'); ?></p>
    </div>
    
    <p>Edit this file at: <code><?php echo __FILE__; ?></code></p>
</body>
</html>
EOF

    # Find PHP socket
    PHP_SOCKET="unix:/run/php/php${PHP_VERSION}-fpm.sock"
    if [ ! -S "${PHP_SOCKET#unix:}" ]; then
        for sock in /run/php/php*-fpm.sock; do
            if [ -S "$sock" ]; then
                PHP_SOCKET="unix:$sock"
                break
            fi
        done
    fi

    # Create nginx config
    cat > "/etc/nginx/sites-available/${domain}" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${domain} www.${domain};
    root ${SITE_DIR};
    index index.php index.html;
    
    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log;
    
    client_max_body_size 64M;
    
    include /etc/nginx/security-headers.conf 2>/dev/null || true;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass ${PHP_SOCKET};
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
    
    location ~ /\. {
        deny all;
    }
    
    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }
    
    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }
}
EOF

    ln -sf "/etc/nginx/sites-available/${domain}" "/etc/nginx/sites-enabled/"
    chown -R www-data:www-data "$SITE_DIR"
    
    # Test and reload nginx
    if nginx -t 2>/dev/null; then
        systemctl reload nginx 2>/dev/null
        echo -e "${GREEN}✅ Nginx configuration created${NC}"
    else
        echo -e "${RED}❌ Nginx configuration test failed${NC}"
        nginx -t
        exit 1
    fi
    
    # Enable SSL if requested
    if [ "$use_ssl" = "true" ]; then
        echo -e "${YELLOW}🔐 Enabling SSL for ${domain}...${NC}"
        certbot --nginx -d "$domain" -d "www.$domain" --non-interactive --agree-tos --email "admin@$domain" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ SSL enabled for ${domain}${NC}"
        else
            echo -e "${RED}❌ SSL installation failed${NC}"
        fi
    fi
    
    echo -e "${GREEN}✅ PHP site created for ${domain}${NC}"
    echo -e "${GREEN}🌐 URL: http://${domain}${NC}"
    [ "$use_ssl" = "true" ] && echo -e "${GREEN}🔒 Secure URL: https://${domain}${NC}"
}

# ============================================
# ✅ HTML Site Creation Function - ADDED
# ============================================
create_html_site() {
    local domain=$1
    local use_ssl=$2
    
    # Check if domain already exists
    if check_domain_exists "$domain"; then
        echo -e "${RED}❌ Domain ${domain} already exists. HTML site creation aborted.${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}🌐 Creating HTML site for ${domain}...${NC}"
    
    # Create site directory
    SITE_DIR="/var/www/html/${domain}"
    mkdir -p "$SITE_DIR"
    
    # Create sample index.html
    cat > "$SITE_DIR/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${domain}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            text-align: center;
        }
        h1 {
            color: #2563eb;
            margin-bottom: 20px;
        }
        .info {
            background: #f3f4f6;
            border-radius: 8px;
            padding: 20px;
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <h1>Welcome to ${domain}</h1>
    
    <div class="info">
        <p>This is an HTML site created with <strong>EasyInstall</strong></p>
        <p>Server: $(hostname)</p>
        <p>Date: $(date)</p>
    </div>
    
    <p>Edit this file at: <code>${SITE_DIR}/index.html</code></p>
</body>
</html>
EOF

    # Create nginx config for HTML site
    cat > "/etc/nginx/sites-available/${domain}" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${domain} www.${domain};
    root ${SITE_DIR};
    index index.html;
    
    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log;
    
    client_max_body_size 64M;
    
    include /etc/nginx/security-headers.conf 2>/dev/null || true;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location ~ /\. {
        deny all;
    }
    
    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }
    
    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }
}
EOF

    ln -sf "/etc/nginx/sites-available/${domain}" "/etc/nginx/sites-enabled/"
    chown -R www-data:www-data "$SITE_DIR"
    
    # Test and reload nginx
    if nginx -t 2>/dev/null; then
        systemctl reload nginx 2>/dev/null
        echo -e "${GREEN}✅ Nginx configuration created${NC}"
    else
        echo -e "${RED}❌ Nginx configuration test failed${NC}"
        nginx -t
        exit 1
    fi
    
    # Enable SSL if requested
    if [ "$use_ssl" = "true" ]; then
        echo -e "${YELLOW}🔐 Enabling SSL for ${domain}...${NC}"
        certbot --nginx -d "$domain" -d "www.$domain" --non-interactive --agree-tos --email "admin@$domain" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ SSL enabled for ${domain}${NC}"
        else
            echo -e "${RED}❌ SSL installation failed${NC}"
        fi
    fi
    
    echo -e "${GREEN}✅ HTML site created for ${domain}${NC}"
    echo -e "${GREEN}🌐 URL: http://${domain}${NC}"
    [ "$use_ssl" = "true" ] && echo -e "${GREEN}🔒 Secure URL: https://${domain}${NC}"
}

# ============================================
# ✅ SSL Enable Function for Existing Sites - ADDED
# ============================================
enable_ssl_for_site() {
    local domain=$1
    
    # Check if domain exists
    if [ ! -f "/etc/nginx/sites-available/${domain}" ]; then
        echo -e "${RED}❌ Domain ${domain} not found.${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}🔐 Enabling SSL for ${domain}...${NC}"
    
    # Check if SSL already exists
    if grep -q "listen 443 ssl" "/etc/nginx/sites-available/${domain}" 2>/dev/null; then
        echo -e "${YELLOW}⚠️ SSL already enabled for ${domain}${NC}"
        return 0
    fi
    
    # Get SSL certificate
    certbot --nginx -d "$domain" -d "www.$domain" --non-interactive --agree-tos --email "admin@$domain" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ SSL enabled for ${domain}${NC}"
        echo -e "${GREEN}🔒 Secure URL: https://${domain}${NC}"
    else
        echo -e "${RED}❌ Failed to enable SSL for ${domain}${NC}"
        exit 1
    fi
}

# ============================================
# ✅ FIX: Postfix Non-Interactive Configuration
# ============================================
export DEBIAN_FRONTEND=noninteractive

# Pre-configure Postfix to avoid interactive prompts
debconf-set-selections <<< "postfix postfix/mailname string $(hostname -f 2>/dev/null || echo 'localhost')"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Local only'"
debconf-set-selections <<< "postfix postfix/destinations string localhost.localdomain, localhost"
debconf-set-selections <<< "postfix postfix/protocols string ipv4"

# Also pre-configure any other packages that might ask questions
debconf-set-selections <<< "mariadb-server-10.5 mysql-server/root_password password root" 2>/dev/null || true
debconf-set-selections <<< "mariadb-server-10.5 mysql-server/root_password_again password root" 2>/dev/null || true
debconf-set-selections <<< "grub-pc grub-pc/install_devices_empty boolean true" 2>/dev/null || true

# ============================================
# EasyInstall Enterprise Stack v3.0
# Ultra-Optimized 512MB VPS → Enterprise Grade Hosting Engine
# Complete with Advanced CDN & Monitoring Features
# ============================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${GREEN}🚀 EasyInstall Enterprise Stack v3.0${NC}"
echo -e "${GREEN}📦 Complete with Advanced CDN & Monitoring Features${NC}"
echo ""

# Root check
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}❌ Please run as root${NC}"
    exit 1
fi

# ============================================
# System Detection & Optimization
# ============================================
TOTAL_RAM=$(free -m | awk '/Mem:/ {print $2}')
TOTAL_CORES=$(nproc)
IP_ADDRESS=$(hostname -I | awk '{print $1}' | head -1)
OS_VERSION=$(lsb_release -sc 2>/dev/null || echo "focal")
HOSTNAME_FQDN=$(hostname -f 2>/dev/null || hostname)

echo -e "${YELLOW}📊 System Information:${NC}"
echo "   • RAM: ${TOTAL_RAM}MB"
echo "   • CPU Cores: ${TOTAL_CORES}"
echo "   • IP Address: ${IP_ADDRESS}"
echo "   • OS: Ubuntu/Debian ${OS_VERSION}"
echo "   • Hostname: ${HOSTNAME_FQDN}"
echo ""

# ============================================
# Adaptive Swap Configuration
# ============================================
setup_swap() {
    echo -e "${YELLOW}📀 Configuring swap space...${NC}"
    
    if [ ! -f /swapfile ]; then
        if [ "$TOTAL_RAM" -le 512 ]; then
            SWAPSIZE=1G
            SWAPPINESS=60
        elif [ "$TOTAL_RAM" -le 1024 ]; then
            SWAPSIZE=2G
            SWAPPINESS=50
        else
            SWAPSIZE=4G
            SWAPPINESS=40
        fi
        
        fallocate -l $SWAPSIZE /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 2>/dev/null
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
        
        # Optimize swap usage
        echo "vm.swappiness=$SWAPPINESS" >> /etc/sysctl.conf
        echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf
        
        echo -e "${GREEN}   ✅ Swap created: $SWAPSIZE${NC}"
        
        # Track in package manager
        if [ "$PKG_MODE" = true ]; then
            mark_component_installed "swap" "3.0"
        fi
    else
        echo -e "   ⚠️  Swap already exists"
    fi
}

# ============================================
# Kernel Tuning
# ============================================
kernel_tuning() {
    echo -e "${YELLOW}⚙️  Applying kernel optimizations...${NC}"
    
    cat > /etc/sysctl.d/99-easyinstall.conf <<EOF
# Network security
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 8192
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 5000

# Connection optimization
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 1024 65000

# Memory optimization
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Security
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# File system
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288

# Auto-healing
kernel.panic = 10
kernel.panic_on_oops = 1
EOF

    sysctl -p /etc/sysctl.d/99-easyinstall.conf 2>/dev/null || true
    echo -e "${GREEN}   ✅ Kernel tuning applied${NC}"
    
    if [ "$PKG_MODE" = true ]; then
        mark_component_installed "kernel" "3.0"
    fi
}

# ============================================
# Nginx Cleanup Function - Run before Nginx configuration
# ============================================
cleanup_nginx_config() {
    echo -e "${YELLOW}🧹 Cleaning up existing Nginx configurations...${NC}"
    
    # Stop nginx if running
    systemctl stop nginx 2>/dev/null || true
    
    # Remove all cache configuration files completely
    rm -rf /etc/nginx/conf.d/fastcgi-cache.conf
    rm -rf /etc/nginx/conf.d/fastcgi-cache.conf.*
    rm -rf /etc/nginx/conf.d/*cache*
    rm -rf /etc/nginx/conf.d/*.bak
    rm -rf /etc/nginx/conf.d/*.old
    rm -rf /etc/nginx/conf.d/*~
    
    # Remove any duplicate or backup files
    find /etc/nginx/conf.d/ -name "fastcgi-cache.conf*" -type f -delete 2>/dev/null || true
    find /etc/nginx/conf.d/ -name "*fastcgi*" -type f -delete 2>/dev/null || true
    find /etc/nginx/conf.d/ -name "*cache*" -type f -delete 2>/dev/null || true
    
    # Remove any symbolic links that might cause issues
    find /etc/nginx/ -type l -name "*fastcgi*" -delete 2>/dev/null || true
    
    # Clean the cache directory
    rm -rf /var/cache/nginx/*
    mkdir -p /var/cache/nginx
    chown -R www-data:www-data /var/cache/nginx 2>/dev/null || chown -R nginx:nginx /var/cache/nginx 2>/dev/null || true
    chmod -R 755 /var/cache/nginx
    
    # Also clean sites-enabled
    rm -f /etc/nginx/sites-enabled/wordpress
    rm -f /etc/nginx/sites-enabled/default
    
    echo -e "${GREEN}   ✅ Nginx cleanup completed${NC}"
}

# ============================================
# Install Required Packages (with newest PHP)
# ============================================
install_packages() {
    echo -e "${YELLOW}📦 Installing enterprise stack with latest PHP...${NC}"
    
    # Update package list
    apt update
    
    # Install prerequisites
    apt install -y software-properties-common curl wget gnupg2 ca-certificates lsb-release \
        apt-transport-https bc jq python3-pip pipx
        
    # Add PHP repository
    echo -e "${YELLOW}   📌 Adding PHP repository (ondrej/php)...${NC}"
    
    if ! add-apt-repository -y ppa:ondrej/php 2>/dev/null; then
        wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg 2>/dev/null || \
        curl -fsSL https://packages.sury.org/php/apt.gpg | gpg --dearmor -o /etc/apt/trusted.gpg.d/php.gpg
        echo "deb https://packages.sury.org/php/ $(lsb_release -sc 2>/dev/null || echo 'focal') main" > /etc/apt/sources.list.d/php.list
    fi
    
    # Add official Nginx repository
    echo -e "${YELLOW}   📌 Adding official Nginx repository...${NC}"
    rm -f /etc/apt/sources.list.d/nginx.list
    
    # Add Nginx signing key
    curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg 2>/dev/null
    
    # Add Nginx repository for mainline version
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/mainline/ubuntu $(lsb_release -sc 2>/dev/null || echo 'focal') nginx" > /etc/apt/sources.list.d/nginx.list
    
    # Pin Nginx packages
    cat > /etc/apt/preferences.d/nginx <<EOF
Package: nginx*
Pin: origin nginx.org
Pin-Priority: 900
EOF
    
    apt update
    
    # Get latest PHP version
    PHP_VERSION=""
    for version in 8.3 8.2 8.1 8.0; do
        if apt-cache show php${version}-fpm >/dev/null 2>&1; then
            PHP_VERSION="php${version}"
            echo -e "${GREEN}   ✅ Found PHP ${version}${NC}"
            break
        fi
    done
    
    if [ -z "$PHP_VERSION" ]; then
        PHP_VERSION="php8.2"
        echo -e "${YELLOW}   ⚠️ Using fallback PHP 8.2${NC}"
    fi
    
    echo -e "${YELLOW}   📌 Installing PHP ${PHP_VERSION} and modules...${NC}"
    
    # Install base packages
    apt install -y nginx mariadb-server ${PHP_VERSION}-fpm ${PHP_VERSION}-mysql \
        ${PHP_VERSION}-cli ${PHP_VERSION}-curl ${PHP_VERSION}-xml ${PHP_VERSION}-mbstring \
        ${PHP_VERSION}-zip ${PHP_VERSION}-gd ${PHP_VERSION}-imagick ${PHP_VERSION}-opcache \
        ${PHP_VERSION}-redis ${PHP_VERSION}-intl ${PHP_VERSION}-bcmath ${PHP_VERSION}-gmp \
        ${PHP_VERSION}-xmlrpc ${PHP_VERSION}-memcache ${PHP_VERSION}-memcached \
        redis-server memcached ufw fail2ban curl wget unzip openssl \
        certbot python3-certbot-nginx \
        htop neofetch git cron dnsutils \
        automysqlbackup rclone netdata glances \
        bc jq python3-pip python3-venv python3-full postfix
        
    # Install nginx modules and modsecurity
    echo -e "${YELLOW}   📌 Installing nginx modules and modsecurity...${NC}"
    
    apt install -y nginx-module-geoip nginx-module-image-filter nginx-module-njs \
        nginx-module-perl nginx-module-xslt 2>/dev/null || echo -e "${YELLOW}   ⚠️ Some nginx modules skipped, continuing...${NC}"
    
    apt install -y libnginx-mod-http-modsecurity modsecurity-crs 2>/dev/null || echo -e "${YELLOW}   ⚠️ Modsecurity packages installation skipped, continuing...${NC}"
        
    echo -e "${GREEN}   ✅ All packages installed with PHP ${PHP_VERSION}${NC}"
    
    if [ "$PKG_MODE" = true ]; then
        mark_component_installed "packages" "3.0"
    fi
}

# ============================================
# ModSecurity WAF Setup
# ============================================
setup_modsecurity() {
    echo -e "${YELLOW}🛡️  Configuring ModSecurity WAF...${NC}"
    
    if [ -f /etc/nginx/modsecurity/modsecurity.conf-recommended ]; then
        mkdir -p /etc/nginx/modsecurity
        
        cp /etc/nginx/modsecurity/modsecurity.conf-recommended /etc/nginx/modsecurity/modsecurity.conf 2>/dev/null || \
        cp /etc/modsecurity/modsecurity.conf-recommended /etc/nginx/modsecurity/modsecurity.conf 2>/dev/null || true
        
        if [ -f /etc/nginx/modsecurity/modsecurity.conf ]; then
            sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsecurity/modsecurity.conf
            
            if [ ! -d /usr/share/modsecurity-crs/owasp-crs ]; then
                mkdir -p /usr/share/modsecurity-crs
                cd /usr/share/modsecurity-crs
                git clone https://github.com/coreruleset/coreruleset.git owasp-crs 2>/dev/null || true
                cd owasp-crs
                cp crs-setup.conf.example crs-setup.conf 2>/dev/null || true
            fi
            
            cat > /etc/nginx/modsecurity-rules.conf <<EOF
Include /etc/nginx/modsecurity/modsecurity.conf
Include /usr/share/modsecurity-crs/owasp-crs/crs-setup.conf
Include /usr/share/modsecurity-crs/owasp-crs/rules/*.conf

# Custom WordPress rules
SecRule REQUEST_URI "@contains wp-login.php" "id:1000,phase:1,t:lowercase,deny,msg:'WordPress login brute force',chain"
SecRule ARGS:log "@validateUrlEncoding" "t:none"

# XML-RPC rules (initially disabled)
# SecRule REQUEST_URI "@contains xmlrpc.php" "id:1001,phase:1,deny,status:403,msg:'XML-RPC access blocked'"

SecRule REQUEST_URI "@contains wp-admin" "id:1002,phase:1,t:lowercase,chain"
SecRule REQUEST_METHOD "!@streq GET" "chain"
SecRule REQUEST_METHOD "!@streq HEAD"
EOF
        fi
        echo -e "${GREEN}   ✅ ModSecurity WAF configured${NC}"
        
        if [ "$PKG_MODE" = true ]; then
            mark_component_installed "modsecurity" "3.0"
        fi
    else
        echo -e "${YELLOW}   ⚠️ ModSecurity packages not fully installed, skipping configuration${NC}"
    fi
}

# ============================================
# Auto-healing Service - FIXED
# ============================================
setup_autoheal() {
    echo -e "${YELLOW}🏥 Setting up auto-healing service...${NC}"
    
    cat > /usr/local/bin/autoheal <<'EOF'
#!/bin/bash

SERVICES=("nginx" "php*-fpm" "mariadb" "redis-server" "memcached" "fail2ban" "netdata")
LOG_FILE="/var/log/autoheal.log"
MAX_RESTART_ATTEMPTS=3

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

check_service() {
    local service=$1
    local service_name=$(echo $service | sed 's/\*//')
    local counter_file="/tmp/autoheal_${service_name//[^a-zA-Z0-9]/}_counter"
    
    if ! systemctl is-active --quiet $service 2>/dev/null; then
        log_message "⚠️ Service $service is down. Attempting restart..."
        
        local restart_count=0
        [ -f "$counter_file" ] && restart_count=$(cat "$counter_file")
        
        if [ $restart_count -lt $MAX_RESTART_ATTEMPTS ]; then
            systemctl restart $service 2>/dev/null
            sleep 5
            
            if systemctl is-active --quiet $service 2>/dev/null; then
                log_message "✅ Service $service restarted successfully"
                echo 0 > "$counter_file"
            else
                restart_count=$((restart_count + 1))
                echo $restart_count > "$counter_file"
                log_message "❌ Failed to restart $service (attempt $restart_count/$MAX_RESTART_ATTEMPTS)"
            fi
        else
            log_message "🚨 Service $service failed to restart after $MAX_RESTART_ATTEMPTS attempts"
            
            if [ -f "/root/.admin_email" ]; then
                ADMIN_EMAIL=$(cat /root/.admin_email)
                echo "Service $service failed to restart automatically on $(hostname)" | \
                    mail -s "🚨 CRITICAL: Service $service failed" "$ADMIN_EMAIL" 2>/dev/null || true
            fi
            
            echo 0 > "$counter_file"
        fi
    fi
}

check_disk_space() {
    local disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ $disk_usage -gt 95 ]; then
        log_message "⚠️ Critical disk usage: $disk_usage% - Running cleanup"
        
        find /var/log -name "*.log" -mtime +7 -delete 2>/dev/null
        find /backups/weekly -type d -mtime +14 -delete 2>/dev/null
        apt clean 2>/dev/null
        
        log_message "✅ Disk cleanup completed. New usage: $(df / | awk 'NR==2 {print $5}')"
    fi
}

check_memory_pressure() {
    local mem_usage=$(free -m | awk '/Mem:/ {print int($3/$2*100)}')
    if [ $mem_usage -gt 90 ]; then
        log_message "⚠️ High memory usage: $mem_usage%"
        
        if systemctl is-active --quiet redis-server 2>/dev/null; then
            redis-cli FLUSHALL > /dev/null 2>&1
            log_message "   Redis cache cleared"
        fi
    fi
}

check_load_average() {
    local load=$(uptime | awk -F'load average:' '{print $2}' | cut -d, -f1 | sed 's/ //g')
    local cores=$(nproc)
    
    if command -v bc >/dev/null 2>&1; then
        if (( $(echo "$load > $cores * 2" | bc -l 2>/dev/null) )); then
            log_message "⚠️ High load average: $load"
            systemctl restart php*-fpm 2>/dev/null
            systemctl restart nginx 2>/dev/null
            log_message "   Services restarted to reduce load"
        fi
    fi
}

while true; do
    log_message "Running auto-heal checks..."
    
    for service in "${SERVICES[@]}"; do
        if systemctl list-units --type=service --all 2>/dev/null | grep -q "$service" || \
           [ -f "/etc/systemd/system/${service}.service" ] || \
           [ -f "/lib/systemd/system/${service}.service" ]; then
            check_service "$service"
        fi
    done
    
    check_disk_space
    check_memory_pressure
    check_load_average
    
    sleep 60
done
EOF

    chmod +x /usr/local/bin/autoheal

    cat > /etc/systemd/system/autoheal.service <<EOF
[Unit]
Description=Auto-healing service for EasyInstall
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/autoheal
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable autoheal 2>/dev/null
    systemctl start autoheal 2>/dev/null

    echo -e "${GREEN}   ✅ Auto-healing service configured${NC}"
    
    if [ "$PKG_MODE" = true ]; then
        mark_component_installed "autoheal" "3.0"
    fi
}

# ============================================
# Database Security & Configuration with Performance Tuning - FIXED
# ============================================
setup_database() {
    echo -e "${YELLOW}🔐 Securing database with performance tuning...${NC}"
    
    sleep 5
    
    # Start MariaDB if not running
    systemctl start mariadb 2>/dev/null || true
    
    # Wait for MariaDB to be ready
    until mysqladmin ping >/dev/null 2>&1; do
        echo "   Waiting for MariaDB to start..."
        sleep 2
    done
    
    # Set root password and secure installation
    mysql <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED VIA mysql_native_password USING PASSWORD('root');
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
    
    # Create root credentials file for easy access
    cat > /root/.my.cnf <<EOF
[client]
user=root
password=root
host=localhost
EOF
    chmod 600 /root/.my.cnf
    
    mkdir -p /etc/mysql/mariadb.conf.d/
    
    cat > /etc/mysql/mariadb.conf.d/99-easyinstall.cnf <<EOF
[mysqld]
# Basic Settings
performance_schema = off
skip-name-resolve
table_open_cache = 400
thread_cache_size = 16
query_cache_type = 0
query_cache_size = 0

# Socket configuration
socket = /var/run/mysqld/mysqld.sock

# Adaptive Memory Settings
tmp_table_size = 32M
max_heap_table_size = 32M
max_connections = 50

# InnoDB Settings - Auto-tuned based on RAM
innodb_buffer_pool_size = 64M
innodb_log_buffer_size = 8M
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1
innodb_read_io_threads = 4
innodb_write_io_threads = 4
innodb_io_capacity = 200

# Performance Optimizations
join_buffer_size = 1M
sort_buffer_size = 2M
read_rnd_buffer_size = 1M
key_buffer_size = 16M

# Tuning for specific system
expire_logs_days = 7
max_binlog_size = 100M
EOF

    if [ "$TOTAL_RAM" -le 512 ]; then
        sed -i 's/innodb_buffer_pool_size = 64M/innodb_buffer_pool_size = 32M/' /etc/mysql/mariadb.conf.d/99-easyinstall.cnf
    elif [ "$TOTAL_RAM" -le 1024 ]; then
        sed -i 's/innodb_buffer_pool_size = 64M/innodb_buffer_pool_size = 128M/' /etc/mysql/mariadb.conf.d/99-easyinstall.cnf
        sed -i 's/tmp_table_size = 32M/tmp_table_size = 64M/' /etc/mysql/mariadb.conf.d/99-easyinstall.cnf
        sed -i 's/max_heap_table_size = 32M/max_heap_table_size = 64M/' /etc/mysql/mariadb.conf.d/99-easyinstall.cnf
    else
        sed -i 's/innodb_buffer_pool_size = 64M/innodb_buffer_pool_size = 256M/' /etc/mysql/mariadb.conf.d/99-easyinstall.cnf
        sed -i 's/tmp_table_size = 32M/tmp_table_size = 128M/' /etc/mysql/mariadb.conf.d/99-easyinstall.cnf
        sed -i 's/max_heap_table_size = 32M/max_heap_table_size = 128M/' /etc/mysql/mariadb.conf.d/99-easyinstall.cnf
        sed -i 's/max_connections = 50/max_connections = 100/' /etc/mysql/mariadb.conf.d/99-easyinstall.cnf
    fi
    
    systemctl restart mariadb 2>/dev/null || true
    
    # Wait for MariaDB to restart
    sleep 3
    
    echo -e "${GREEN}   ✅ Database configured with performance tuning${NC}"
    
    if [ "$PKG_MODE" = true ]; then
        mark_component_installed "database" "3.0"
    fi
}

# ============================================
# PHP-FPM Optimization with Auto Memory Adjustment - FIXED
# ============================================
optimize_php() {
    echo -e "${YELLOW}⚡ Optimizing PHP-FPM...${NC}"
    
    sleep 2
    
    PHP_VERSION=""
    if command -v php >/dev/null 2>&1; then
        PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null)
    fi
    
    if [ -z "$PHP_VERSION" ]; then
        PHP_VERSION=$(ls /etc/php/ 2>/dev/null | head -1)
    fi
    
    if [ -z "$PHP_VERSION" ]; then
        PHP_VERSION="8.2"
    fi
    
    PHP_INI="/etc/php/${PHP_VERSION}/fpm/php.ini"
    PHP_POOL="/etc/php/${PHP_VERSION}/fpm/pool.d/www.conf"
    
    if [ "$TOTAL_RAM" -le 512 ]; then
        MAX_CHILDREN=4
        START_SERVERS=2
        MIN_SPARE=1
        MAX_SPARE=3
        MEMORY_LIMIT="128M"
        OPcache_MEMORY=64
    elif [ "$TOTAL_RAM" -le 1024 ]; then
        MAX_CHILDREN=8
        START_SERVERS=3
        MIN_SPARE=2
        MAX_SPARE=6
        MEMORY_LIMIT="256M"
        OPcache_MEMORY=128
    else
        MAX_CHILDREN=16
        START_SERVERS=4
        MIN_SPARE=2
        MAX_SPARE=8
        MEMORY_LIMIT="512M"
        OPcache_MEMORY=256
    fi
    
    if [ -f "$PHP_POOL" ]; then
        sed -i "s/^pm.max_children =.*/pm.max_children = ${MAX_CHILDREN}/" $PHP_POOL 2>/dev/null || true
        sed -i "s/^pm.start_servers =.*/pm.start_servers = ${START_SERVERS}/" $PHP_POOL 2>/dev/null || true
        sed -i "s/^pm.min_spare_servers =.*/pm.min_spare_servers = ${MIN_SPARE}/" $PHP_POOL 2>/dev/null || true
        sed -i "s/^pm.max_spare_servers =.*/pm.max_spare_servers = ${MAX_SPARE}/" $PHP_POOL 2>/dev/null || true
    fi
    
    if [ -f "$PHP_INI" ]; then
        sed -i "s/^memory_limit =.*/memory_limit = ${MEMORY_LIMIT}/" $PHP_INI 2>/dev/null || true
        sed -i "s/^max_execution_time =.*/max_execution_time = 300/" $PHP_INI 2>/dev/null || true
        sed -i "s/^max_input_time =.*/max_input_time = 300/" $PHP_INI 2>/dev/null || true
        sed -i "s/^post_max_size =.*/post_max_size = 64M/" $PHP_INI 2>/dev/null || true
        sed -i "s/^upload_max_filesize =.*/upload_max_filesize = 64M/" $PHP_INI 2>/dev/null || true
        
        if ! grep -q "opcache.enable" "$PHP_INI"; then
            cat >> $PHP_INI <<EOF

; OPcache Settings
opcache.enable=1
opcache.memory_consumption=${OPcache_MEMORY}
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=10000
opcache.revalidate_freq=2
opcache.fast_shutdown=1
opcache.validate_timestamps=0
opcache.save_comments=1
EOF
        fi
    fi
    
    mkdir -p /etc/nginx/conf.d
    cat > /etc/nginx/conf.d/php-status.conf <<EOF
server {
    listen 127.0.0.1:80;
    server_name _;
    
    location /php-status {
        include fastcgi_params;
        fastcgi_pass unix:/run/php/php${PHP_VERSION}-fpm.sock;
        fastcgi_param SCRIPT_FILENAME /status;
        allow 127.0.0.1;
        deny all;
    }
}
EOF
    
    echo -e "${GREEN}   ✅ PHP optimized for ${TOTAL_RAM}MB RAM (Memory limit: ${MEMORY_LIMIT})${NC}"
    
    if [ "$PKG_MODE" = true ]; then
        mark_component_installed "php" "3.0"
    fi
}

# ============================================
# Nginx with FastCGI Cache and Security Headers - FIXED
# ============================================
configure_nginx() {
    echo -e "${YELLOW}🚀 Configuring Nginx with FastCGI cache and security headers...${NC}"
    
    cleanup_nginx_config
    
    PHP_VERSION=""
    if command -v php >/dev/null 2>&1; then
        PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null)
    fi
    
    if [ -z "$PHP_VERSION" ]; then
        PHP_VERSION=$(ls /etc/php/ 2>/dev/null | head -1)
    fi
    
    if [ -z "$PHP_VERSION" ]; then
        PHP_VERSION="8.2"
    fi
    
    if [ "$TOTAL_RAM" -le 512 ]; then
        CACHE_SIZE="100m"
        CACHE_INACTIVE="30m"
    elif [ "$TOTAL_RAM" -le 1024 ]; then
        CACHE_SIZE="200m"
        CACHE_INACTIVE="60m"
    else
        CACHE_SIZE="500m"
        CACHE_INACTIVE="120m"
    fi
    
    mkdir -p /var/cache/nginx
    mkdir -p /etc/nginx/sites-available
    mkdir -p /etc/nginx/sites-enabled
    mkdir -p /etc/nginx/conf.d
    
    chown -R www-data:www-data /var/cache/nginx 2>/dev/null || chown -R nginx:nginx /var/cache/nginx 2>/dev/null || true
    chmod -R 755 /var/cache/nginx
    
    PHP_SOCKET="/run/php/php${PHP_VERSION}-fpm.sock"
    if [ ! -S "$PHP_SOCKET" ]; then
        for sock in /run/php/php*-fpm.sock; do
            if [ -S "$sock" ]; then
                PHP_SOCKET="$sock"
                break
            fi
        done
    fi
    
    cat > /etc/nginx/security-headers.conf <<EOF
# Security Headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(),midi=(),sync-xhr=(),microphone=(),camera=(),magnetometer=(),gyroscope=(),fullscreen=(self),payment=()" always;
add_header Content-Security-Policy "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval';" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
EOF

    cat > /etc/nginx/conf.d/fastcgi-cache.conf <<EOF
# FastCGI Cache Zone - Single definition with unique path
fastcgi_cache_path /var/cache/nginx levels=1:2 keys_zone=EASYINSTALL_CACHE:${CACHE_SIZE} inactive=${CACHE_INACTIVE} max_size=${CACHE_SIZE};
fastcgi_cache_key "\$scheme\$request_method\$host\$request_uri";
fastcgi_cache_use_stale error timeout updating invalid_header http_500 http_503;
fastcgi_cache_lock on;
fastcgi_cache_valid 200 301 302 ${CACHE_INACTIVE};
fastcgi_cache_valid 404 1m;
fastcgi_ignore_headers Cache-Control Expires Set-Cookie;
EOF

    cat > /etc/nginx/nginx.conf <<EOF
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    ##
    # Basic Settings
    ##
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    client_max_body_size 64M;
    
    ##
    # MIME Types
    ##
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    ##
    # Logging Settings
    ##
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    ##
    # Gzip Settings
    ##
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript application/xml+rss application/atom+xml image/svg+xml text/javascript;
    
    ##
    # Cache Settings
    ##
    include /etc/nginx/conf.d/fastcgi-cache.conf;
    
    ##
    # Virtual Host Configs
    ##
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

    mkdir -p /var/www/html/wordpress
    cat > /etc/nginx/sites-available/wordpress <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    server_name _;
    
    root /var/www/html/wordpress;
    index index.php index.html index.htm;
    
    include /etc/nginx/security-headers.conf;
    
    add_header X-Cache \$upstream_cache_status;
    
    access_log /var/log/nginx/wordpress_access.log;
    error_log /var/log/nginx/wordpress_error.log;
    
    set \$skip_cache 0;
    
    if (\$request_method = POST) {
        set \$skip_cache 1;
    }
    if (\$query_string != "") {
        set \$skip_cache 1;
    }
    
    if (\$http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_no_cache|wordpress_logged_in") {
        set \$skip_cache 1;
    }
    
    location ~* /wp-admin/|/xmlrpc.php|wp-.*.php|/feed/|index.php|sitemap(_index)?.xml {
        set \$skip_cache 1;
    }
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass unix:${PHP_SOCKET};
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        
        fastcgi_cache EASYINSTALL_CACHE;
        fastcgi_cache_bypass \$skip_cache;
        fastcgi_no_cache \$skip_cache;
        fastcgi_cache_valid 200 60m;
        fastcgi_cache_methods GET HEAD;
        fastcgi_cache_use_stale error timeout updating invalid_header http_500 http_503;
        
        add_header X-Cache \$upstream_cache_status;
    }
    
    # Fix for WordPress Permalinks - This ensures pretty permalinks work
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    location ~ ^/(wp-config\.php|wp-config\.txt|readme\.html|license\.txt|wp-config-sample\.php) {
        deny all;
    }
    
    # XML-RPC is enabled by default
    # Use 'easyinstall xmlrpc disable' to block it
}
EOF
    
    if [ ! -f /etc/nginx/sites-enabled/wordpress ]; then
        ln -sf /etc/nginx/sites-available/wordpress /etc/nginx/sites-enabled/
    fi
    
    rm -f /etc/nginx/sites-enabled/default
    
    if nginx -t 2>&1; then
        systemctl restart nginx
        echo -e "${GREEN}   ✅ Nginx configured with FastCGI cache (${CACHE_SIZE}) and security headers${NC}"
        
        if [ "$PKG_MODE" = true ]; then
            mark_component_installed "nginx" "3.0"
        fi
    else
        echo -e "${RED}   ❌ Nginx configuration test failed. Running emergency fix...${NC}"
        
        systemctl stop nginx
        
        rm -rf /etc/nginx/conf.d/*
        rm -rf /etc/nginx/sites-enabled/*
        
        cat > /etc/nginx/conf.d/fastcgi-cache.conf <<EOF
fastcgi_cache_path /var/cache/nginx levels=1:2 keys_zone=EASYINSTALL_CACHE:100m inactive=60m max_size=100m;
fastcgi_cache_key "\$scheme\$request_method\$host\$request_uri";
fastcgi_cache_use_stale error timeout updating invalid_header http_500 http_503;
fastcgi_cache_lock on;
fastcgi_cache_valid 200 60m;
fastcgi_cache_valid 404 1m;
fastcgi_ignore_headers Cache-Control Expires Set-Cookie;
EOF

        cat > /etc/nginx/nginx.conf <<EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;
events {
    worker_connections 768;
}
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 65;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

        mkdir -p /var/www/html/wordpress
        cat > /etc/nginx/sites-available/wordpress <<EOF
server {
    listen 80 default_server;
    server_name _;
    root /var/www/html/wordpress;
    index index.php;
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass unix:${PHP_SOCKET};
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
}
EOF
        ln -sf /etc/nginx/sites-available/wordpress /etc/nginx/sites-enabled/
        
        if nginx -t; then
            systemctl start nginx
            echo -e "${GREEN}   ✅ Emergency fix successful - Nginx running with minimal config${NC}"
        else
            echo -e "${RED}   ❌ Emergency fix failed. Please check Nginx configuration manually.${NC}"
            exit 1
        fi
    fi
}

# ============================================
# XML-RPC Management Functions
# ============================================
setup_xmlrpc_commands() {
    echo -e "${YELLOW}🔧 Setting up XML-RPC management commands...${NC}"
    
    cat > /usr/local/bin/xmlrpc-manager <<'EOF'
#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

NGINX_SITE="/etc/nginx/sites-available/wordpress"
MODSECURITY_RULES="/etc/nginx/modsecurity-rules.conf"

case "$1" in
    enable)
        echo -e "${YELLOW}Enabling XML-RPC...${NC}"
        
        # Remove XML-RPC block from nginx config if present
        if [ -f "$NGINX_SITE" ]; then
            sed -i '/location = \/xmlrpc.php/,+4d' "$NGINX_SITE" 2>/dev/null || true
            sed -i 's/# XML-RPC is enabled by default//' "$NGINX_SITE" 2>/dev/null || true
        fi
        
        # Comment out ModSecurity XML-RPC rule if present
        if [ -f "$MODSECURITY_RULES" ]; then
            sed -i 's/^SecRule REQUEST_URI "@contains xmlrpc.php"/# SecRule REQUEST_URI "@contains xmlrpc.php"/' "$MODSECURITY_RULES" 2>/dev/null || true
        fi
        
        # Test and reload nginx
        if nginx -t 2>/dev/null; then
            systemctl reload nginx 2>/dev/null
            echo -e "${GREEN}✅ XML-RPC has been ENABLED${NC}"
            echo "   WordPress XML-RPC is now accessible at: http://yourdomain.com/xmlrpc.php"
        else
            echo -e "${RED}❌ Nginx configuration test failed${NC}"
            nginx -t
        fi
        ;;
        
    disable)
        echo -e "${YELLOW}Disabling XML-RPC...${NC}"
        
        # Add XML-RPC block to nginx config
        if [ -f "$NGINX_SITE" ]; then
            # Check if already has XML-RPC block
            if ! grep -q "location = /xmlrpc.php" "$NGINX_SITE"; then
                # Add XML-RPC block before the closing }
                sed -i '/^}/i \ \n    # Block XML-RPC\n    location = /xmlrpc.php {\n        deny all;\n        access_log off;\n        log_not_found off;\n    }' "$NGINX_SITE" 2>/dev/null
            fi
        fi
        
        # Uncomment ModSecurity XML-RPC rule if present
        if [ -f "$MODSECURITY_RULES" ]; then
            sed -i 's/^# SecRule REQUEST_URI "@contains xmlrpc.php"/SecRule REQUEST_URI "@contains xmlrpc.php"/' "$MODSECURITY_RULES" 2>/dev/null || true
        fi
        
        # Test and reload nginx
        if nginx -t 2>/dev/null; then
            systemctl reload nginx 2>/dev/null
            echo -e "${GREEN}✅ XML-RPC has been DISABLED${NC}"
            echo "   WordPress XML-RPC is now blocked"
        else
            echo -e "${RED}❌ Nginx configuration test failed${NC}"
            nginx -t
        fi
        ;;
        
    status)
        echo -e "${YELLOW}XML-RPC Status:${NC}"
        
        # Check nginx config
        if [ -f "$NGINX_SITE" ]; then
            if grep -q "location = /xmlrpc.php" "$NGINX_SITE"; then
                echo -e "  • Nginx: ${RED}DISABLED (blocked in nginx)${NC}"
            else
                echo -e "  • Nginx: ${GREEN}ENABLED${NC}"
            fi
        fi
        
        # Check ModSecurity
        if [ -f "$MODSECURITY_RULES" ]; then
            if grep -q "^SecRule REQUEST_URI \"@contains xmlrpc.php\"" "$MODSECURITY_RULES" 2>/dev/null; then
                echo -e "  • ModSecurity: ${RED}DISABLED (blocked by WAF)${NC}"
            elif grep -q "^# SecRule REQUEST_URI \"@contains xmlrpc.php\"" "$MODSECURITY_RULES" 2>/dev/null; then
                echo -e "  • ModSecurity: ${GREEN}ENABLED${NC}"
            fi
        fi
        
        # Test actual endpoint if domain is configured
        DOMAIN=$(grep -m1 "server_name" "$NGINX_SITE" 2>/dev/null | awk '{print $2}' | sed 's/;//')
        if [ -n "$DOMAIN" ] && [ "$DOMAIN" != "_" ]; then
            echo -e "\nTesting XML-RPC endpoint: http://$DOMAIN/xmlrpc.php"
            if curl -s -o /dev/null -w "%{http_code}" "http://$DOMAIN/xmlrpc.php" 2>/dev/null | grep -q "200\|405"; then
                echo -e "  • Endpoint: ${GREEN}Accessible${NC}"
            else
                echo -e "  • Endpoint: ${RED}Blocked${NC}"
            fi
        fi
        ;;
        
    test)
        DOMAIN=$2
        if [ -z "$DOMAIN" ]; then
            DOMAIN=$(grep -m1 "server_name" "$NGINX_SITE" 2>/dev/null | awk '{print $2}' | sed 's/;//')
        fi
        
        if [ -z "$DOMAIN" ] || [ "$DOMAIN" = "_" ]; then
            echo -e "${RED}No domain configured. Please specify a domain:${NC}"
            echo "  xmlrpc-manager test yourdomain.com"
            exit 1
        fi
        
        echo -e "${YELLOW}Testing XML-RPC on http://$DOMAIN/xmlrpc.php${NC}"
        
        # Simple test to see if endpoint responds
        RESPONSE=$(curl -s -X POST -H "Content-Type: text/xml" \
            --data '<?xml version="1.0" encoding="iso-8859-1"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>' \
            "http://$DOMAIN/xmlrpc.php" 2>/dev/null)
        
        if echo "$RESPONSE" | grep -q "methodResponse"; then
            echo -e "${GREEN}✅ XML-RPC is responding${NC}"
            echo "   Available methods can be retrieved"
        elif curl -s -o /dev/null -w "%{http_code}" "http://$DOMAIN/xmlrpc.php" 2>/dev/null | grep -q "405"; then
            echo -e "${YELLOW}⚠️ XML-RPC endpoint exists but method not allowed${NC}"
        elif curl -s -o /dev/null -w "%{http_code}" "http://$DOMAIN/xmlrpc.php" 2>/dev/null | grep -q "403"; then
            echo -e "${RED}❌ XML-RPC is blocked (403 Forbidden)${NC}"
        elif curl -s -o /dev/null -w "%{http_code}" "http://$DOMAIN/xmlrpc.php" 2>/dev/null | grep -q "404"; then
            echo -e "${RED}❌ XML-RPC endpoint not found (404)${NC}"
        else
            HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://$DOMAIN/xmlrpc.php" 2>/dev/null)
            echo -e "${YELLOW}⚠️ XML-RPC returned HTTP code: $HTTP_CODE${NC}"
        fi
        ;;
        
    help)
        echo "XML-RPC Manager for EasyInstall"
        echo ""
        echo "Commands:"
        echo "  enable        - Enable XML-RPC access"
        echo "  disable       - Disable/block XML-RPC access"
        echo "  status        - Show XML-RPC status"
        echo "  test [domain] - Test XML-RPC endpoint"
        echo "  help          - Show this help"
        echo ""
        echo "Examples:"
        echo "  xmlrpc-manager enable"
        echo "  xmlrpc-manager disable"
        echo "  xmlrpc-manager status"
        echo "  xmlrpc-manager test example.com"
        ;;
        
    *)
        if [ -z "$1" ]; then
            echo "XML-RPC Manager - Use 'xmlrpc-manager help' for commands"
        else
            echo -e "${RED}Unknown command: $1${NC}"
            echo "Use 'xmlrpc-manager help' for available commands"
        fi
        ;;
esac
EOF

    chmod +x /usr/local/bin/xmlrpc-manager
    
    # Add alias to easyinstall
    if [ -f /usr/local/bin/easyinstall ]; then
        # Will be updated in install_commands function
        echo -e "${GREEN}   ✅ XML-RPC manager installed${NC}"
    fi
    
    if [ "$PKG_MODE" = true ]; then
        mark_component_installed "xmlrpc" "3.0"
    fi
}

# ============================================
# Advanced Redis + Memcached Configuration - FIXED
# ============================================
configure_redis_memcached() {
    echo -e "${YELLOW}⚡ Configuring Redis and Memcached...${NC}"
    
    REDIS_MAXMEMORY="64mb"
    if [ "$TOTAL_RAM" -le 512 ]; then
        REDIS_MAXMEMORY="32mb"
    elif [ "$TOTAL_RAM" -le 1024 ]; then
        REDIS_MAXMEMORY="128mb"
    else
        REDIS_MAXMEMORY="256mb"
    fi
    
    if [ -f /etc/redis/redis.conf ]; then
        cp /etc/redis/redis.conf /etc/redis/redis.conf.backup 2>/dev/null || true
    fi
    
    cat > /etc/redis/redis.conf <<EOF
# EasyInstall Redis Configuration
port 6379
daemonize yes
pidfile /var/run/redis/redis-server.pid
logfile /var/log/redis/redis-server.log

# Memory Management
maxmemory ${REDIS_MAXMEMORY}
maxmemory-policy allkeys-lru
maxmemory-samples 5

# Persistence
save ""
appendonly no
appendfsync no

# Performance
tcp-backlog 511
timeout 0
tcp-keepalive 300
databases 16

# Object Cache Specific
maxclients 1000
EOF

    MEMCACHED_MEMORY="64"
    if [ "$TOTAL_RAM" -le 512 ]; then
        MEMCACHED_MEMORY="32"
    elif [ "$TOTAL_RAM" -le 1024 ]; then
        MEMCACHED_MEMORY="128"
    else
        MEMCACHED_MEMORY="256"
    fi
    
    cat > /etc/memcached.conf <<EOF
# EasyInstall Memcached Configuration
-d
logfile /var/log/memcached.log
-m ${MEMCACHED_MEMORY}
-p 11211
-u memcache
-l 127.0.0.1
-c 1024
-t 4
-R 20
EOF
    
    systemctl restart redis-server 2>/dev/null || true
    systemctl restart memcached 2>/dev/null || true
    
    echo -e "${GREEN}   ✅ Redis and Memcached optimized (Redis: ${REDIS_MAXMEMORY}, Memcached: ${MEMCACHED_MEMORY}MB)${NC}"
    
    if [ "$PKG_MODE" = true ]; then
        mark_component_installed "redis" "3.0"
        mark_component_installed "memcached" "3.0"
    fi
}

# ============================================
# Fail2ban Enhanced WordPress Rules - FIXED
# ============================================
setup_fail2ban() {
    echo -e "${YELLOW}🛡️  Configuring enhanced Fail2ban WordPress rules...${NC}"
    
    ufw --force disable 2>/dev/null
    ufw default deny incoming 2>/dev/null
    ufw default allow outgoing 2>/dev/null
    ufw allow 22/tcp comment 'SSH' 2>/dev/null
    ufw allow 80/tcp comment 'HTTP' 2>/dev/null
    ufw allow 443/tcp comment 'HTTPS' 2>/dev/null
    ufw allow 19999/tcp comment 'Netdata' 2>/dev/null
    ufw allow 61208/tcp comment 'Glances' 2>/dev/null
    echo "y" | ufw enable 2>/dev/null || true
    
    mkdir -p /etc/fail2ban
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = admin@$(hostname)
sendername = Fail2ban
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/*error.log

[nginx-botsearch]
enabled = true
filter = nginx-botsearch
port = http,https
logpath = /var/log/nginx/*access.log
maxretry = 2
bantime = 86400
EOF

    mkdir -p /etc/fail2ban/filter.d
    
    cat > /etc/fail2ban/filter.d/wordpress-login.conf <<EOF
[Definition]
failregex = ^<HOST> .* "POST .*wp-login\.php
            ^<HOST> .* "POST .*wp-admin/admin-ajax\.php.*action=.*login
            ^<HOST> .* "GET .*wp-login\.php.*action=register
ignoreregex =
EOF

    cat > /etc/fail2ban/filter.d/wordpress-xmlrpc.conf <<EOF
[Definition]
failregex = ^<HOST> .* "POST .*xmlrpc\.php
            ^<HOST> .* "POST .*wp.*\.php.*methodCall
ignoreregex =
EOF

    cat > /etc/fail2ban/filter.d/wordpress-hardening.conf <<EOF
[Definition]
failregex = ^<HOST> .* "GET .*wp-config\.php
            ^<HOST> .* "GET .*\.sql
            ^<HOST> .* "GET .*\.bak
            ^<HOST> .* "GET .*\.old
            ^<HOST> .* "GET .*/\.git/
            ^<HOST> .* "GET .*/\.svn/
ignoreregex =
EOF

    systemctl restart fail2ban 2>/dev/null || true
    
    echo -e "${GREEN}   ✅ Enhanced Fail2ban WordPress rules configured${NC}"
    
    if [ "$PKG_MODE" = true ]; then
        mark_component_installed "fail2ban" "3.0"
    fi
}

# ============================================
# WordPress Security Keys Update (Monthly Cron) - FIXED
# ============================================
setup_security_keys_cron() {
    echo -e "${YELLOW}🔑 Setting up monthly WordPress security keys update...${NC}"
    
    cat > /usr/local/bin/update-wp-keys <<'EOF'
#!/bin/bash

WP_CONFIG="/var/www/html/wordpress/wp-config.php"

if [ ! -f "$WP_CONFIG" ]; then
    echo "WordPress config not found"
    exit 0
fi

cp "$WP_CONFIG" "$WP_CONFIG.backup.$(date +%Y%m%d)" 2>/dev/null

SALT_DATA=$(curl -s https://api.wordpress.org/secret-key/1.1/salt/ 2>/dev/null)

if [ -n "$SALT_DATA" ]; then
    sed -i '/AUTH_KEY/d' "$WP_CONFIG" 2>/dev/null
    sed -i '/SECURE_AUTH_KEY/d' "$WP_CONFIG" 2>/dev/null
    sed -i '/LOGGED_IN_KEY/d' "$WP_CONFIG" 2>/dev/null
    sed -i '/NONCE_KEY/d' "$WP_CONFIG" 2>/dev/null
    sed -i '/AUTH_SALT/d' "$WP_CONFIG" 2>/dev/null
    sed -i '/SECURE_AUTH_SALT/d' "$WP_CONFIG" 2>/dev/null
    sed -i '/LOGGED_IN_SALT/d' "$WP_CONFIG" 2>/dev/null
    sed -i '/NONCE_SALT/d' "$WP_CONFIG" 2>/dev/null
    
    sed -i "/.*That's all.*/i $SALT_DATA" "$WP_CONFIG" 2>/dev/null
    
    echo "WordPress security keys updated successfully"
else
    echo "Failed to fetch new salts"
    exit 0
fi
EOF

    chmod +x /usr/local/bin/update-wp-keys
    
    mkdir -p /etc/cron.d
    cat > /etc/cron.d/wp-security-keys <<EOF
# Update WordPress security keys on the 1st of every month
0 0 1 * * root /usr/local/bin/update-wp-keys > /dev/null 2>&1
EOF

    echo -e "${GREEN}   ✅ Monthly WordPress security keys update configured${NC}"
    
    if [ "$PKG_MODE" = true ]; then
        mark_component_installed "security-keys" "3.0"
    fi
}

# ============================================
# WordPress Installation Functions - COMPLETELY REWRITTEN AND FIXED
# ============================================
prepare_wordpress() {
    echo -e "${YELLOW}📝 Preparing WordPress installer...${NC}"
    
    mkdir -p /var/www/html/wordpress
    chown www-data:www-data /var/www/html 2>/dev/null || chown nginx:nginx /var/www/html 2>/dev/null || true
    
    cd /var/www/html
    
    if [ ! -f latest.zip ]; then
        curl -O https://wordpress.org/latest.zip 2>/dev/null
    fi
    
    unzip -o latest.zip > /dev/null 2>&1
    rm -f /var/www/html/latest.zip
    
    # Create the FIXED installer script with proper database authentication
    cat > /usr/local/bin/install-wordpress <<'EOF'
#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

DOMAIN=$1
ENABLE_SSL=$2
PHP_VERSION=${3:-$(ls /etc/php/ 2>/dev/null | head -1)}
[ -z "$PHP_VERSION" ] && PHP_VERSION="8.2"
WP_PATH="/var/www/html"
WP_CONFIG="$WP_PATH/wordpress/wp-config.php"
MYSQL_CNF="/root/.my.cnf"

if [ -z "$DOMAIN" ]; then
    echo "Usage: install-wordpress domain.com [--ssl] [php-version]"
    echo "Examples:"
    echo "  install-wordpress example.com"
    echo "  install-wordpress example.com --ssl"
    exit 1
fi

echo -e "${YELLOW}Installing WordPress for domain: $DOMAIN${NC}"

# Ensure MariaDB is running
echo -n "Checking MariaDB... "
systemctl start mariadb 2>/dev/null
sleep 2

if mysqladmin ping >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    echo "Failed to start MariaDB. Please check: systemctl status mariadb"
    exit 1
fi

# Create WordPress directory
mkdir -p "$WP_PATH/wordpress"

# Download WordPress if needed
cd "$WP_PATH"
if [ ! -f "$WP_PATH/wordpress/wp-config-sample.php" ]; then
    echo "Downloading WordPress..."
    curl -O https://wordpress.org/latest.zip 2>/dev/null
    unzip -o latest.zip > /dev/null 2>&1
    rm -f latest.zip
fi

# Generate database name from domain
DB_NAME="wp_$(echo $DOMAIN | sed 's/\./_/g' | sed 's/-/_/g')"
DB_USER="user_$(openssl rand -hex 4 2>/dev/null | head -c8)"
DB_PASS=$(openssl rand -base64 24 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c20)

# Fallback if random generation fails
if [ -z "$DB_PASS" ] || [ ${#DB_PASS} -lt 8 ]; then
    DB_PASS="$(date +%s | sha256sum | base64 | head -c 20)"
fi
if [ -z "$DB_USER" ] || [ ${#DB_USER} -lt 4 ]; then
    DB_USER="wpuser_$(date +%s | tail -c 5)"
fi

echo -e "Creating database: ${YELLOW}$DB_NAME${NC}"

# Drop existing database if exists (clean slate)
mysql --defaults-file="$MYSQL_CNF" -e "DROP DATABASE IF EXISTS \`$DB_NAME\`;" 2>/dev/null

# Create database and user with proper permissions
mysql --defaults-file="$MYSQL_CNF" <<MYSQL_EOF
CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
MYSQL_EOF

# Verify database creation
if mysql -u "$DB_USER" -p"$DB_PASS" -e "USE \`$DB_NAME\`;" 2>/dev/null; then
    echo -e "${GREEN}✓ Database created and verified${NC}"
else
    echo -e "${RED}✗ Database verification failed. Trying alternative method...${NC}"
    
    # Alternative method using root with password
    mysql --defaults-file="$MYSQL_CNF" <<MYSQL_EOF
GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
FLUSH PRIVILEGES;
MYSQL_EOF
    
    if mysql -u "$DB_USER" -p"$DB_PASS" -e "USE \`$DB_NAME\`;" 2>/dev/null; then
        echo -e "${GREEN}✓ Database verified with alternative method${NC}"
    else
        echo -e "${RED}✗ Cannot connect to database. Please check manually.${NC}"
        exit 1
    fi
fi

# Save credentials
echo "$DB_NAME:$DB_USER:$DB_PASS" > /root/.wp_db_credentials
chmod 600 /root/.wp_db_credentials

cd "$WP_PATH/wordpress"

if [ ! -f "wp-config-sample.php" ]; then
    echo -e "${RED}Error: wp-config-sample.php not found${NC}"
    exit 1
fi

cp wp-config-sample.php wp-config.php

# Update database credentials in wp-config.php
sed -i "s/database_name_here/$DB_NAME/" wp-config.php
sed -i "s/username_here/$DB_USER/" wp-config.php
sed -i "s/password_here/$DB_PASS/" wp-config.php

# Add salts
echo "Adding security salts..."
SALTS=$(curl -s https://api.wordpress.org/secret-key/1.1/salt/ 2>/dev/null)
if [ -n "$SALTS" ]; then
    # Remove existing salt defines
    sed -i '/AUTH_KEY/d' wp-config.php 2>/dev/null
    sed -i '/SECURE_AUTH_KEY/d' wp-config.php 2>/dev/null
    sed -i '/LOGGED_IN_KEY/d' wp-config.php 2>/dev/null
    sed -i '/NONCE_KEY/d' wp-config.php 2>/dev/null
    sed -i '/AUTH_SALT/d' wp-config.php 2>/dev/null
    sed -i '/SECURE_AUTH_SALT/d' wp-config.php 2>/dev/null
    sed -i '/LOGGED_IN_SALT/d' wp-config.php 2>/dev/null
    sed -i '/NONCE_SALT/d' wp-config.php 2>/dev/null
    
    # Insert salts before the "That's all" line
    sed -i "/.*That's all.*/i $SALTS" wp-config.php 2>/dev/null
fi

# Add performance optimizations
cat >> wp-config.php <<'EOL'

/** Redis Cache Configuration */
define('WP_REDIS_HOST', '127.0.0.1');
define('WP_REDIS_PORT', 6379);
define('WP_REDIS_DATABASE', 0);
define('WP_REDIS_TIMEOUT', 1);
define('WP_REDIS_READ_TIMEOUT', 1);

/** Memcached Configuration */
global $memcached_servers;
$memcached_servers = array(
    'default' => array(
        '127.0.0.1:11211'
    )
);

/** Performance Optimizations */
define('WP_MEMORY_LIMIT', '256M');
define('WP_MAX_MEMORY_LIMIT', '512M');
define('WP_POST_REVISIONS', 5);
define('EMPTY_TRASH_DAYS', 7);
define('DISALLOW_FILE_EDIT', false);  # Changed to false to enable theme/plugin editor
define('FS_METHOD', 'direct');
define('AUTOMATIC_UPDATER_DISABLED', false);
define('WP_AUTO_UPDATE_CORE', 'minor');

/** Cache */
define('WP_CACHE', true);
define('ENABLE_CACHE', true);

/** Debug Mode */
define('WP_DEBUG', false);
define('WP_DEBUG_LOG', false);
define('WP_DEBUG_DISPLAY', false);
EOL

# Update Nginx configuration
if [ -f "/etc/nginx/sites-available/wordpress" ]; then
    cp /etc/nginx/sites-available/wordpress /etc/nginx/sites-available/wordpress.backup 2>/dev/null
    
    sed -i "s/server_name _;/server_name $DOMAIN www.$DOMAIN;/" /etc/nginx/sites-available/wordpress 2>/dev/null
    sed -i "s|root /var/www/html/wordpress;|root $WP_PATH/wordpress;|" /etc/nginx/sites-available/wordpress 2>/dev/null
    
    # Find and update PHP socket
    PHP_SOCKET="unix:/run/php/php$PHP_VERSION-fpm.sock"
    if [ ! -S "$PHP_SOCKET" ]; then
        for sock in /run/php/php*-fpm.sock; do
            if [ -S "$sock" ]; then
                PHP_SOCKET="unix:$sock"
                break
            fi
        done
    fi
    sed -i "s|unix:/run/php/php[0-9]\.[0-9]-fpm.sock|$PHP_SOCKET|g" /etc/nginx/sites-available/wordpress 2>/dev/null
fi

# Test and reload Nginx
echo "Testing Nginx configuration..."
if nginx -t 2>/dev/null; then
    systemctl reload nginx 2>/dev/null
    echo -e "${GREEN}✓ Nginx configuration valid${NC}"
else
    echo -e "${RED}✗ Nginx configuration test failed${NC}"
    nginx -t
fi

# Set proper permissions
chown -R www-data:www-data "$WP_PATH/wordpress" 2>/dev/null || chown -R nginx:nginx "$WP_PATH/wordpress" 2>/dev/null || true
find "$WP_PATH/wordpress" -type d -exec chmod 755 {} \; 2>/dev/null
find "$WP_PATH/wordpress" -type f -exec chmod 644 {} \; 2>/dev/null
[ -d "$WP_PATH/wordpress/wp-content" ] && chmod 775 "$WP_PATH/wordpress/wp-content" 2>/dev/null

# Install performance plugins (optional)
echo "Installing performance plugins..."
cd "$WP_PATH/wordpress"
mkdir -p wp-content/plugins

for plugin in nginx-helper redis-cache w3-total-cache; do
    curl -L "https://downloads.wordpress.org/plugin/$plugin.zip" -o "/tmp/$plugin.zip" 2>/dev/null
    unzip -q "/tmp/$plugin.zip" -d wp-content/plugins/ 2>/dev/null || true
    rm -f "/tmp/$plugin.zip" 2>/dev/null
done

# Final verification
echo ""
echo "======================================================"
echo -e "${GREEN}✅ WordPress installation completed for $DOMAIN${NC}"
echo "======================================================"
echo ""
echo "📊 Database Information:"
echo "   Database: $DB_NAME"
echo "   Username: $DB_USER"
echo "   Password: $DB_PASS"
echo ""
echo "🔍 Testing final database connection..."
if mysql -u "$DB_USER" -p"$DB_PASS" -e "USE \`$DB_NAME\`; SHOW TABLES;" 2>/dev/null; then
    echo -e "${GREEN}✓ Database connection successful${NC}"
else
    echo -e "${RED}✗ Database connection failed${NC}"
fi
echo ""
echo "🌐 Site URL: http://$DOMAIN"
echo "🔐 Admin URL: http://$DOMAIN/wp-admin"
echo ""
echo "📝 Next steps:"
echo "   1. Complete WordPress installation at: http://$DOMAIN/wp-admin/install.php"
echo "   2. Use the database credentials above during installation"
echo "   3. After installation, you can change permalinks in Settings > Permalinks"
echo "      The nginx configuration already supports pretty permalinks"
echo "   4. Theme/Plugin editor is ENABLED (DISALLOW_FILE_EDIT is set to false)"
echo "      You can edit themes/plugins from WordPress admin"
echo "======================================================"

# Enable SSL if requested
if [ "$ENABLE_SSL" = "--ssl" ]; then
    echo ""
    echo "🔐 Enabling SSL for $DOMAIN..."
    
    if nginx -t 2>/dev/null; then
        certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos --email "admin@$DOMAIN" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ SSL enabled for $DOMAIN${NC}"
            echo "🌐 Your site is now available at: https://$DOMAIN"
        else
            echo -e "${RED}✗ SSL installation failed. Run manually: certbot --nginx -d $DOMAIN${NC}"
        fi
    fi
fi
EOF

    chmod +x /usr/local/bin/install-wordpress
    
    echo -e "${GREEN}   ✅ WordPress installer prepared and FIXED${NC}"
    echo -e "${YELLOW}   📌 Run: install-wordpress yourdomain.com${NC}"
    echo -e "${YELLOW}   📌 Run with SSL: install-wordpress yourdomain.com --ssl${NC}"
    
    if [ "$PKG_MODE" = true ]; then
        mark_component_installed "wordpress-installer" "3.0"
    fi
}

# ============================================
# Multi-site Panel Support - FIXED
# ============================================
setup_panel() {
    echo -e "${YELLOW}🏢 Setting up multi-site panel support...${NC}"
    
    mkdir -p /var/www/sites
    
    cat > /usr/local/bin/easy-site <<'EOF'
#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

SITES_DIR="/var/www/sites"
NGINX_AVAILABLE="/etc/nginx/sites-available"
NGINX_ENABLED="/etc/nginx/sites-enabled"
MYSQL_CNF="/root/.my.cnf"

case "$1" in
    create)
        DOMAIN=$2
        PHP_VERSION=${3:-$(ls /etc/php/ 2>/dev/null | head -1)}
        [ -z "$PHP_VERSION" ] && PHP_VERSION="8.2"
        
        if [ -z "$DOMAIN" ]; then
            echo -e "${RED}Error: Domain name required${NC}"
            exit 1
        fi
        
        SITE_DIR="$SITES_DIR/$DOMAIN"
        echo -e "${YELLOW}Creating site for $DOMAIN...${NC}"
        
        mkdir -p "$SITE_DIR"/{public,logs,backups}
        
        cd "$SITE_DIR/public"
        curl -O https://wordpress.org/latest.zip 2>/dev/null
        unzip -o latest.zip > /dev/null 2>&1
        mv wordpress/* . 2>/dev/null
        rm -rf wordpress latest.zip
        
        DB_NAME="site_$(echo $DOMAIN | sed 's/\./_/g' | sed 's/-/_/g')"
        DB_USER="user_$(openssl rand -hex 4 2>/dev/null | head -c8)"
        DB_PASS=$(openssl rand -base64 24 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c20)
        
        # Fallback if random generation fails
        [ -z "$DB_PASS" ] && DB_PASS="$(date +%s | sha256sum | base64 | head -c 20)"
        [ -z "$DB_USER" ] && DB_USER="wpuser_$(date +%s | tail -c 5)"
        
        mysql --defaults-file="$MYSQL_CNF" -e "CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" 2>/dev/null
        mysql --defaults-file="$MYSQL_CNF" -e "CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';" 2>/dev/null
        mysql --defaults-file="$MYSQL_CNF" -e "GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'localhost';" 2>/dev/null
        mysql --defaults-file="$MYSQL_CNF" -e "FLUSH PRIVILEGES;" 2>/dev/null
        
        cp wp-config-sample.php wp-config.php 2>/dev/null
        sed -i "s/database_name_here/$DB_NAME/" wp-config.php 2>/dev/null
        sed -i "s/username_here/$DB_USER/" wp-config.php 2>/dev/null
        sed -i "s/password_here/$DB_PASS/" wp-config.php 2>/dev/null
        curl -s https://api.wordpress.org/secret-key/1.1/salt/ 2>/dev/null >> wp-config.php
        
        cat >> wp-config.php <<'EOL'

/** Redis Cache */
define('WP_REDIS_HOST', '127.0.0.1');
define('WP_REDIS_PORT', 6379);
define('WP_CACHE', true);

/** Enable Theme/Plugin Editor */
define('DISALLOW_FILE_EDIT', false);
EOL
        
        # Find PHP socket
        PHP_SOCKET="unix:/run/php/php$PHP_VERSION-fpm.sock"
        if [ ! -S "${PHP_SOCKET#unix:}" ]; then
            for sock in /run/php/php*-fpm.sock; do
                if [ -S "$sock" ]; then
                    PHP_SOCKET="unix:$sock"
                    break
                fi
            done
        fi
        
        cat > "$NGINX_AVAILABLE/$DOMAIN" <<NGINXEOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN www.$DOMAIN;
    root $SITE_DIR/public;
    index index.php index.html;
    access_log $SITE_DIR/logs/access.log;
    error_log $SITE_DIR/logs/error.log;
    
    include /etc/nginx/security-headers.conf 2>/dev/null || true;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass $PHP_SOCKET;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
    
    location ~ /\. {
        deny all;
    }
}
NGINXEOF
        
        ln -sf "$NGINX_AVAILABLE/$DOMAIN" "$NGINX_ENABLED/"
        chown -R www-data:www-data "$SITE_DIR" 2>/dev/null || chown -R nginx:nginx "$SITE_DIR" 2>/dev/null || true
        nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null
        
        cat > "$SITE_DIR/site-info.txt" <<INFO
Domain: $DOMAIN
Path: $SITE_DIR
Database: $DB_NAME
DB User: $DB_USER
DB Pass: $DB_PASS
PHP Version: $PHP_VERSION
Created: $(date)
Theme Editor: Enabled
INFO
        
        echo -e "${GREEN}✅ Site created: http://$DOMAIN${NC}"
        echo "Database: $DB_NAME | User: $DB_USER | Pass: $DB_PASS"
        echo "Theme/Plugin Editor: ENABLED"
        ;;
        
    list)
        echo -e "${YELLOW}📋 WordPress Sites:${NC}"
        if [ -d "$SITES_DIR" ]; then
            for site in "$SITES_DIR"/*; do
                if [ -d "$site" ]; then
                    DOMAIN=$(basename "$site")
                    echo "  🌐 $DOMAIN"
                    if [ -f "$site/site-info.txt" ]; then
                        DB=$(grep Database "$site/site-info.txt" | cut -d: -f2)
                        EDITOR=$(grep "Theme Editor" "$site/site-info.txt" 2>/dev/null || echo "Enabled")
                        echo "     DB:$DB | Editor: $EDITOR"
                    fi
                fi
            done
        else
            echo "No sites found"
        fi
        ;;
        
    delete)
        DOMAIN=$2
        if [ -z "$DOMAIN" ]; then
            echo -e "${RED}Error: Domain name required${NC}"
            exit 1
        fi
        
        echo -e "${RED}⚠️  Delete $DOMAIN? (y/n)${NC}"
        read CONFIRM
        if [ "$CONFIRM" = "y" ]; then
            rm -f "$NGINX_AVAILABLE/$DOMAIN" "$NGINX_ENABLED/$DOMAIN" 2>/dev/null
            rm -rf "$SITES_DIR/$DOMAIN" 2>/dev/null
            nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null
            echo -e "${GREEN}✅ Site deleted${NC}"
        fi
        ;;
        
    enable-ssl)
        DOMAIN=$2
        EMAIL=${3:-"admin@$DOMAIN"}
        
        if [ -z "$DOMAIN" ]; then
            echo -e "${RED}Error: Domain name required${NC}"
            exit 1
        fi
        
        echo -e "${YELLOW}🔐 Enabling SSL for $DOMAIN...${NC}"
        certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos --email "$EMAIL" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ SSL enabled for $DOMAIN${NC}"
        fi
        ;;
        
    *)
        echo "EasyInstall Site Manager"
        echo ""
        echo "Commands:"
        echo "  create domain.com [php-version]  - Create new WordPress site (Editor ENABLED)"
        echo "  list                              - List all sites"
        echo "  delete domain.com                 - Delete site"
        echo "  enable-ssl domain.com [email]     - Enable SSL for site"
        echo ""
        echo "Examples:"
        echo "  easy-site create example.com"
        echo "  easy-site enable-ssl example.com"
        echo ""
        echo "Note: Theme/Plugin editor is ENABLED by default for all sites"
        ;;
esac
EOF

    chmod +x /usr/local/bin/easy-site
    echo -e "${GREEN}   ✅ Multi-site panel configured (Theme Editor ENABLED)${NC}"
    
    if [ "$PKG_MODE" = true ]; then
        mark_component_installed "panel" "3.0"
    fi
}

# ============================================
# Backup System Setup - FIXED
# ============================================
setup_backups() {
    echo -e "${YELLOW}💾 Setting up backup system...${NC}"
    
    mkdir -p /backups/{daily,weekly,monthly}
    
    cat > /usr/local/bin/easy-backup <<'EOF'
#!/bin/bash

BACKUP_TYPE="${1:-weekly}"
BACKUP_DIR="/backups/$BACKUP_TYPE"
DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="$BACKUP_DIR/backup-$DATE.tar.gz"
MYSQL_CNF="/root/.my.cnf"

mkdir -p "$BACKUP_DIR"

echo "Creating $BACKUP_TYPE backup: $BACKUP_FILE"

tar -czf "$BACKUP_FILE" \
    /var/www/html \
    /etc/nginx \
    /etc/php \
    /etc/mysql \
    /etc/redis \
    /etc/fail2ban \
    /etc/modsecurity \
    2>/dev/null || true

if command -v mysqldump >/dev/null 2>&1; then
    mysqldump --defaults-file="$MYSQL_CNF" --all-databases > "/backups/mysql-$DATE.sql" 2>/dev/null
    tar -rf "$BACKUP_FILE" "/backups/mysql-$DATE.sql" 2>/dev/null
    rm "/backups/mysql-$DATE.sql" 2>/dev/null
fi

echo "Backup completed: $BACKUP_FILE"
echo "Size: $(du -h "$BACKUP_FILE" | cut -f1)"

if [ "$BACKUP_TYPE" = "weekly" ]; then
    ls -t $BACKUP_DIR/backup-* 2>/dev/null | tail -n +3 | xargs rm -f 2>/dev/null || true
fi
EOF

    chmod +x /usr/local/bin/easy-backup
    
    cat > /usr/local/bin/easy-restore <<'EOF'
#!/bin/bash

echo "EasyInstall Restore Utility"
echo "==========================="
echo ""
echo "Available backups:"
ls -lh /backups/weekly/ 2>/dev/null || echo "No backups found"
echo ""
echo "To restore, use:"
echo "  tar -xzf /backups/weekly/backup-FILE.tar.gz -C /"
echo ""
echo "Then restart services: systemctl restart nginx php*-fpm mariadb"
EOF
    chmod +x /usr/local/bin/easy-restore
    
    mkdir -p /etc/cron.d
    cat > /etc/cron.d/easy-backup <<EOF
# Daily backup at 2am
0 2 * * * root /usr/local/bin/easy-backup daily > /dev/null 2>&1
# Weekly backup on Sunday at 3am
0 3 * * 0 root /usr/local/bin/easy-backup weekly > /dev/null 2>&1
# Monthly backup on 1st at 4am
0 4 1 * * root /usr/local/bin/easy-backup monthly > /dev/null 2>&1
EOF

    echo -e "${GREEN}   ✅ Backup system configured${NC}"
    
    if [ "$PKG_MODE" = true ]; then
        mark_component_installed "backup" "3.0"
    fi
}

# ============================================
# Advanced Monitoring Setup - FIXED
# ============================================
setup_advanced_monitoring() {
    echo -e "${YELLOW}📊 Setting up advanced monitoring...${NC}"
    
    if [ -f /etc/netdata/netdata.conf ]; then
        sed -i 's/# bind to = \*/bind to = 0.0.0.0:19999/' /etc/netdata/netdata.conf 2>/dev/null
        systemctl restart netdata 2>/dev/null
    fi
    
    cat > /etc/systemd/system/glances.service <<'EOF'
[Unit]
Description=Glances
After=network.target

[Service]
ExecStart=/usr/bin/glances -w -t 5
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable glances 2>/dev/null || true
    systemctl start glances 2>/dev/null || true
    
    cat > /usr/local/bin/advanced-monitor <<'EOF'
#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

while true; do
    clear
    echo -e "${GREEN}=== Advanced Monitor (Press Ctrl+C to exit) ===${NC}"
    echo "Last update: $(date)"
    echo ""
    
    echo -e "${YELLOW}--- System Load ---${NC}"
    uptime
    echo ""
    
    echo -e "${YELLOW}--- Memory Usage ---${NC}"
    free -h
    echo ""
    
    echo -e "${YELLOW}--- Disk Usage ---${NC}"
    df -h / | awk 'NR==2 {print "Usage: " $5 " of " $2}'
    echo ""
    
    echo -e "${YELLOW}--- Top 5 CPU Processes ---${NC}"
    ps aux --sort=-%cpu | head -6 | tail -5
    echo ""
    
    echo -e "${YELLOW}--- Network Connections ---${NC}"
    ss -tunap | wc -l | xargs echo "Total connections:"
    echo ""
    
    echo -e "${YELLOW}--- Service Status ---${NC}"
    for service in nginx php*-fpm mariadb redis-server memcached fail2ban autoheal netdata; do
        if systemctl is-active --quiet $service 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} $service: running"
        else
            echo -e "  ${RED}✗${NC} $service: stopped"
        fi
    done
    echo ""
    
    echo "Press Ctrl+C to exit"
    sleep 5
done
EOF
    chmod +x /usr/local/bin/advanced-monitor
    
    echo -e "${GREEN}   ✅ Advanced monitoring configured${NC}"
    
    if [ "$PKG_MODE" = true ]; then
        mark_component_installed "monitoring" "3.0"
    fi
}

# ============================================
# Advanced CDN Integration - FIXED
# ============================================
setup_advanced_cdn() {
    echo -e "${YELLOW}☁️  Setting up CDN integration...${NC}"
    
    cat > /usr/local/bin/easy-cdn <<'EOF'
#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

case "$1" in
    cloudflare)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: easy-cdn cloudflare domain.com email [api-key]"
            echo ""
            echo "This will guide you through Cloudflare setup"
            exit 1
        fi
        DOMAIN=$2
        EMAIL=$3
        API_KEY=$4
        
        echo -e "${YELLOW}Setting up Cloudflare for $DOMAIN...${NC}"
        
        mkdir -p /root/.cloudflare
        cat > /root/.cloudflare/$DOMAIN.conf <<EOL
DOMAIN=$DOMAIN
EMAIL=$EMAIL
API_KEY=$API_KEY
EOL
        chmod 600 /root/.cloudflare/$DOMAIN.conf
        
        echo -e "${GREEN}✅ Cloudflare credentials saved${NC}"
        echo "To enable CDN, point your domain to this server and enable proxy on Cloudflare"
        ;;
        
    status)
        echo -e "${YELLOW}CDN Status Report${NC}"
        echo "=================="
        
        if [ -d /root/.cloudflare ] && [ "$(ls -A /root/.cloudflare 2>/dev/null)" ]; then
            for conf in /root/.cloudflare/*; do
                if [ -f "$conf" ]; then
                    source "$conf" 2>/dev/null
                    echo "  🌐 $DOMAIN: Cloudflare configured"
                fi
            done
        else
            echo "  No CDN configured"
        fi
        echo ""
        echo "To configure CDN: easy-cdn cloudflare domain.com email [api-key]"
        ;;
        
    purge)
        echo -e "${YELLOW}Purging CDN cache...${NC}"
        
        rm -rf /var/cache/nginx/*
        systemctl reload nginx 2>/dev/null
        echo "  Local nginx cache purged"
        
        echo -e "${GREEN}✅ Cache purge completed${NC}"
        ;;
        
    *)
        echo "EasyInstall CDN Manager"
        echo ""
        echo "Commands:"
        echo "  cloudflare domain.com email [api-key]  - Setup Cloudflare"
        echo "  status                                   - CDN status report"
        echo "  purge                                    - Purge all CDN caches"
        echo ""
        echo "Examples:"
        echo "  easy-cdn cloudflare example.com admin@example.com"
        echo "  easy-cdn purge"
        ;;
esac
EOF
    chmod +x /usr/local/bin/easy-cdn
    echo -e "${GREEN}   ✅ CDN integration configured${NC}"
    
    if [ "$PKG_MODE" = true ]; then
        mark_component_installed "cdn" "3.0"
    fi
}

# ============================================
# Email Configuration - FIXED
# ============================================
setup_email() {
    echo -e "${YELLOW}📧 Setting up email configuration...${NC}"
    
    if command -v postconf >/dev/null 2>&1; then
        postconf -e "myhostname=$(hostname -f 2>/dev/null || hostname)" 2>/dev/null
        postconf -e "mydomain=$(hostname -d 2>/dev/null || echo 'local')" 2>/dev/null
        postconf -e "myorigin=\$mydomain" 2>/dev/null
        postconf -e "inet_interfaces=loopback-only" 2>/dev/null
        postconf -e "mydestination=\$myhostname, localhost.\$mydomain, localhost" 2>/dev/null
        postconf -e "mynetworks=127.0.0.0/8" 2>/dev/null
        
        systemctl restart postfix 2>/dev/null
        echo -e "${GREEN}   ✅ Postfix configured for local delivery${NC}"
    else
        echo -e "${YELLOW}   ⚠️ Postfix not installed, skipping${NC}"
    fi
    
    cat > /usr/local/bin/send-alert <<'EOF'
#!/bin/bash

SUBJECT="$1"
MESSAGE="$2"
EMAIL="${3:-root@localhost}"

echo "$MESSAGE" | mail -s "$SUBJECT" "$EMAIL" 2>/dev/null
echo "Alert sent to $EMAIL"
EOF
    chmod +x /usr/local/bin/send-alert
    
    cat > /usr/local/bin/setup-telegram <<'EOF'
#!/bin/bash

echo "Telegram Bot Setup"
echo "=================="
echo ""
echo "To setup Telegram alerts:"
echo "1. Open Telegram and search for @BotFather"
echo "2. Send /newbot and follow instructions to create a bot"
echo "3. Copy the bot token (looks like: 123456789:ABCdefGHIjklMNOpqrsTUVwxyz)"
echo "4. Start a chat with your bot and send /start"
echo "5. Get your chat ID by visiting: https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates"
echo ""
echo "Then create /root/.telegram.conf with:"
echo "  TELEGRAM_BOT_TOKEN='your-bot-token'"
echo "  TELEGRAM_CHAT_ID='your-chat-id'"
echo ""
echo "Example:"
echo "  cat > /root/.telegram.conf <<EOL"
echo "  TELEGRAM_BOT_TOKEN='123456789:ABCdefGHIjklMNOpqrsTUVwxyz'"
echo "  TELEGRAM_CHAT_ID='123456789'"
echo "  EOL"
echo ""
echo "Then chmod 600 /root/.telegram.conf"
EOF
    chmod +x /usr/local/bin/setup-telegram
    
    echo -e "${GREEN}   ✅ Email and alert system configured${NC}"
    
    if [ "$PKG_MODE" = true ]; then
        mark_component_installed "email" "3.0"
    fi
}

# ============================================
# Remote Storage Setup - FIXED
# ============================================
setup_remote() {
    echo -e "${YELLOW}☁️  Setting up remote storage...${NC}"
    
    cat > /usr/local/bin/easy-remote <<'EOF'
#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

case "$1" in
    add)
        echo -e "${YELLOW}Configure remote storage:${NC}"
        echo ""
        echo "Available options:"
        echo "  1) Google Drive (using rclone)"
        echo "  2) Amazon S3 (using awscli)"
        echo "  3) Backblaze B2"
        echo "  4) Dropbox"
        echo ""
        read -p "Select option [1-4]: " OPTION
        
        case $OPTION in
            1)
                echo "Setting up Google Drive..."
                echo "Run: rclone config"
                echo "Follow the prompts to configure Google Drive"
                ;;
            2)
                echo "Setting up Amazon S3..."
                echo "Run: aws configure"
                echo "Enter your AWS Access Key ID, Secret Key, and region"
                ;;
            3)
                echo "Setting up Backblaze B2..."
                echo "Run: rclone config"
                echo "Select 'b2' when prompted for storage type"
                ;;
            4)
                echo "Setting up Dropbox..."
                echo "Run: rclone config"
                echo "Select 'dropbox' when prompted for storage type"
                ;;
            *)
                echo "Invalid option"
                ;;
        esac
        ;;
        
    list)
        echo -e "${YELLOW}Configured remotes:${NC}"
        if command -v rclone >/dev/null 2>&1; then
            rclone listremotes 2>/dev/null || echo "  No remotes configured"
        else
            echo "  rclone not installed"
        fi
        ;;
        
    status)
        echo -e "${YELLOW}Remote storage status:${NC}"
        echo ""
        if command -v rclone >/dev/null 2>&1; then
            for remote in $(rclone listremotes 2>/dev/null); do
                echo "  📁 $remote"
                rclone about $remote 2>/dev/null | head -3 || echo "     Unable to get info"
            done
        else
            echo "  No remote storage configured"
        fi
        echo ""
        echo "To add remote: easy-remote add"
        ;;
        
    backup)
        REMOTE=$2
        if [ -z "$REMOTE" ]; then
            echo "Usage: easy-remote backup remote-name"
            exit 1
        fi
        
        echo "Backing up to $REMOTE..."
        LATEST_BACKUP=$(ls -t /backups/weekly/backup-*.tar.gz 2>/dev/null | head -1)
        if [ -n "$LATEST_BACKUP" ]; then
            echo "Uploading $LATEST_BACKUP to $REMOTE"
            rclone copy "$LATEST_BACKUP" "$REMOTE:/easyinstall-backups/" 2>/dev/null && \
                echo "✅ Backup uploaded" || echo "❌ Upload failed"
        else
            echo "No backups found to upload"
        fi
        ;;
        
    *)
        echo "EasyInstall Remote Storage Manager"
        echo ""
        echo "Commands:"
        echo "  add          - Configure new remote storage"
        echo "  list         - List configured remotes"
        echo "  status       - Show remote storage status"
        echo "  backup remote - Upload latest backup to remote"
        echo ""
        echo "Examples:"
        echo "  easy-remote add"
        echo "  easy-remote backup gdrive:"
        ;;
esac
EOF
    chmod +x /usr/local/bin/easy-remote
    
    cat > /usr/local/bin/easy-report <<'EOF'
#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}=== System Performance Report ===${NC}"
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo ""

echo -e "${YELLOW}--- System Uptime ---${NC}"
uptime
echo ""

echo -e "${YELLOW}--- Memory Usage ---${NC}"
free -h
echo ""

echo -e "${YELLOW}--- Disk Usage ---${NC}"
df -h /
echo ""

echo -e "${YELLOW}--- Top 10 CPU Processes ---${NC}"
ps aux --sort=-%cpu | head -10
echo ""

echo -e "${YELLOW}--- Top 10 Memory Processes ---${NC}"
ps aux --sort=-%mem | head -10
echo ""

echo -e "${YELLOW}--- Service Status ---${NC}"
for service in nginx php*-fpm mariadb redis-server memcached fail2ban autoheal netdata; do
    if systemctl is-active --quiet $service 2>/dev/null; then
        echo "  ✅ $service: running"
    else
        echo "  ❌ $service: stopped"
    fi
done
echo ""

echo -e "${YELLOW}--- Redis Status ---${NC}"
if command -v redis-cli >/dev/null 2>&1; then
    redis-cli INFO | grep -E "used_memory_human|total_connections_received|total_commands_processed" | head -3 || echo "  Redis not responding"
fi
echo ""

echo -e "${GREEN}=== End of Report ===${NC}"
EOF
    chmod +x /usr/local/bin/easy-report
    
    echo -e "${GREEN}   ✅ Remote storage configured${NC}"
    
    if [ "$PKG_MODE" = true ]; then
        mark_component_installed "remote" "3.0"
    fi
}

# ============================================
# Setup Management Commands - FIXED with new commands
# ============================================
install_commands() {
    echo -e "${YELLOW}🔧 Installing management commands...${NC}"
    
    mkdir -p /usr/local/bin
    
    cat > /usr/local/bin/easyinstall <<'EOF'
#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

VERSION="3.0"

# Domain existence check function
check_domain_exists() {
    local domain=$1
    
    # Check for existing nginx config
    if [ -f "/etc/nginx/sites-available/${domain}" ] || [ -f "/etc/nginx/sites-enabled/${domain}" ]; then
        return 0
    fi
    
    # Check for WordPress installation
    if [ -d "/var/www/html/${domain}" ] && [ -f "/var/www/html/${domain}/wp-config.php" ]; then
        return 0
    fi
    
    # Check for multisite installation
    if [ -d "/var/www/sites/${domain}" ] && [ -f "/var/www/sites/${domain}/public/wp-config.php" ]; then
        return 0
    fi
    
    return 1
}

get_php_version() {
    if command -v php >/dev/null 2>&1; then
        php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || echo "8.2"
    else
        echo "8.2"
    fi
}

show_help() {
    echo -e "${PURPLE}══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}EasyInstall Enterprise Stack v$VERSION - Commands${NC}"
    echo -e "${PURPLE}══════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${CYAN}🌐 WORDPRESS INSTALLATION${NC}"
    echo "  easyinstall domain example.com              - Install WordPress without SSL"
    echo "  easyinstall domain example.com --ssl        - Install WordPress with SSL"
    echo "  easyinstall create example.com              - Install WordPress (multisite style)"
    echo "  easyinstall create example.com --ssl        - Install WordPress with SSL (multisite style)"
    echo ""
    
    echo -e "${CYAN}🐘 PHP SITE CREATION${NC}"
    echo "  easyinstall create example.com --php        - Create PHP site without SSL"
    echo "  easyinstall create example.com --php --ssl  - Create PHP site with SSL"
    echo ""
    
    echo -e "${CYAN}🌐 HTML SITE CREATION${NC}"
    echo "  easyinstall create example.com --html       - Create HTML site without SSL"
    echo "  easyinstall create example.com --html --ssl - Create HTML site with SSL"
    echo ""
    
    echo -e "${CYAN}🔒 SSL MANAGEMENT${NC}"
    echo "  easyinstall site example.com --ssl=on       - Enable SSL for any existing site"
    echo "  easyinstall site example.com --ssl=off      - Disable SSL for any existing site (coming soon)"
    echo "  easyinstall ssl example.com [email]          - Legacy SSL installation"
    echo ""
    
    echo -e "${CYAN}🔌 XML-RPC MANAGEMENT${NC}"
    echo "  easyinstall xmlrpc enable                    - Enable XML-RPC access"
    echo "  easyinstall xmlrpc disable                   - Disable/block XML-RPC access"
    echo "  easyinstall xmlrpc status                     - Show XML-RPC status"
    echo "  easyinstall xmlrpc test [domain]              - Test XML-RPC endpoint"
    echo ""
    
    echo -e "${CYAN}💾 BACKUP & RESTORE${NC}"
    echo "  easyinstall backup [weekly]                  - Create backup (default: weekly)"
    echo "  easyinstall restore                           - Restore from backup"
    echo "  easyinstall remote add                        - Add external storage (GDrive/S3)"
    echo "  easyinstall remote list                       - List configured remotes"
    echo "  easyinstall remote status                     - Check remote status"
    echo ""
    
    echo -e "${CYAN}📊 MONITORING${NC}"
    echo "  easyinstall status                            - System status"
    echo "  easyinstall report                            - Advanced performance report"
    echo "  easyinstall logs [service]                    - View logs (nginx/php/mysql)"
    echo "  easyinstall monitor                            - Run advanced monitor"
    echo "  easyinstall telegram                           - Setup Telegram alerts"
    echo ""
    
    echo -e "${CYAN}☁️  CDN${NC}"
    echo "  easyinstall cdn cloudflare domain key email   - Cloudflare setup"
    echo "  easyinstall cdn status                         - CDN status report"
    echo "  easyinstall cdn purge                          - Purge all CDN caches"
    echo ""
    
    echo -e "${CYAN}🏢 MULTI-SITE${NC}"
    echo "  easyinstall site create domain.com            - Create new site (WordPress)"
    echo "  easyinstall site list                          - List all sites"
    echo "  easyinstall site delete domain.com             - Delete site"
    echo "  easyinstall site enable-ssl domain.com         - Enable SSL for site"
    echo ""
    
    echo -e "${CYAN}⚡ PERFORMANCE${NC}"
    echo "  easyinstall cache clear                        - Clear FastCGI cache"
    echo "  easyinstall redis flush                         - Flush Redis cache"
    echo "  easyinstall memcached flush                     - Flush Memcached"
    echo "  easyinstall restart [service]                   - Restart service"
    echo ""
    
    echo -e "${CYAN}🛡️  SECURITY${NC}"
    echo "  easyinstall keys update                         - Update WordPress security keys"
    echo "  easyinstall fail2ban status                     - Check Fail2ban status"
    echo "  easyinstall waf status                           - Check ModSecurity status"
    echo ""
    
    echo -e "${CYAN}🔧 SYSTEM${NC}"
    echo "  easyinstall update                              - Update system"
    echo "  easyinstall clean                               - Clean temp files"
    echo "  easyinstall help                                - Show this help"
    echo ""
    echo -e "${PURPLE}══════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}⚠️  IMPORTANT: WordPress will ONLY be installed with 'domain' or 'create' commands${NC}"
    echo -e "${YELLOW}   Domain must be valid and not already exist on this server${NC}"
    echo -e "${PURPLE}══════════════════════════════════════════════════════${NC}"
}

# Parse main command
MAIN_COMMAND="$1"

# Handle package manager commands first
case "$MAIN_COMMAND" in
    --pkg-update|--pkg-remove|--pkg-status|--pkg-verify)
        exit 0
        ;;
esac

# If no arguments, show help
if [ -z "$MAIN_COMMAND" ]; then
    show_help
    exit 0
fi

# Handle regular commands
case "$MAIN_COMMAND" in
    domain|create)
        if [ -z "$2" ]; then
            echo -e "${RED}Usage: easyinstall $MAIN_COMMAND yourdomain.com [--ssl] [--php|--html]${NC}"
            exit 1
        fi
        DOMAIN=$2
        USE_SSL="false"
        SITE_TYPE="wordpress"
        
        shift 2
        for arg in "$@"; do
            case $arg in
                --ssl) USE_SSL="true" ;;
                --php) SITE_TYPE="php" ;;
                --html) SITE_TYPE="html" ;;
                -php=*) PHP_V="${arg#*=}" ;;
            esac
        done
        
        # Check if domain already exists
        if check_domain_exists "$DOMAIN"; then
            echo -e "${RED}❌ Domain ${DOMAIN} already exists. Installation aborted.${NC}"
            exit 1
        fi
        
        # Execute based on site type
        case $SITE_TYPE in
            wordpress)
                echo -e "${YELLOW}📦 Installing WordPress for $DOMAIN...${NC}"
                if [ -z "$PHP_V" ]; then
                    /usr/local/bin/install-wordpress "$DOMAIN" "$([ "$USE_SSL" = "true" ] && echo "--ssl")"
                else
                    /usr/local/bin/install-wordpress "$DOMAIN" "$([ "$USE_SSL" = "true" ] && echo "--ssl")" "$PHP_V"
                fi
                ;;
            php)
                echo -e "${YELLOW}🐘 Creating PHP site for $DOMAIN...${NC}"
                # Call PHP site creation function (will be handled by main script)
                /usr/local/bin/easyinstall-internal php-site "$DOMAIN" "$USE_SSL"
                ;;
            html)
                echo -e "${YELLOW}🌐 Creating HTML site for $DOMAIN...${NC}"
                # Call HTML site creation function (will be handled by main script)
                /usr/local/bin/easyinstall-internal html-site "$DOMAIN" "$USE_SSL"
                ;;
        esac
        ;;
        
    site)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo -e "${RED}Usage: easyinstall site yourdomain.com --ssl=on|off${NC}"
            exit 1
        fi
        DOMAIN=$2
        SSL_ACTION=$3
        
        case $SSL_ACTION in
            --ssl=on)
                # Call SSL enable function
                /usr/local/bin/easyinstall-internal enable-ssl "$DOMAIN"
                ;;
            --ssl=off)
                echo -e "${RED}SSL disable not implemented yet${NC}"
                ;;
            *)
                echo -e "${RED}Invalid option: $SSL_ACTION${NC}"
                exit 1
                ;;
        esac
        ;;
        
    xmlrpc)
        shift
        /usr/local/bin/xmlrpc-manager "$@"
        ;;
        
    ssl)
        if [ -z "$2" ]; then
            echo -e "${RED}Usage: easyinstall ssl yourdomain.com [email]${NC}"
            exit 1
        fi
        DOMAIN=$2
        EMAIL=${3:-"admin@$DOMAIN"}
        
        echo -e "${YELLOW}🔐 Installing SSL for $DOMAIN...${NC}"
        certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos --email "$EMAIL" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ SSL installed${NC}"
        else
            echo -e "${RED}❌ SSL installation failed${NC}"
        fi
        ;;
        
    backup)
        /usr/local/bin/easy-backup "${2:-weekly}"
        ;;
        
    restore)
        /usr/local/bin/easy-restore
        ;;
        
    remote)
        shift
        /usr/local/bin/easy-remote "$@"
        ;;
        
    status)
        echo -e "${YELLOW}📊 System Status:${NC}"
        echo -e "${PURPLE}──────────────────────────${NC}"
        echo "  • Nginx: $(systemctl is-active nginx 2>/dev/null || echo 'inactive')"
        echo "  • PHP-FPM: $(systemctl is-active php$(get_php_version)-fpm 2>/dev/null || echo 'inactive')"
        echo "  • MariaDB: $(systemctl is-active mariadb 2>/dev/null || echo 'inactive')"
        echo "  • Redis: $(systemctl is-active redis-server 2>/dev/null || echo 'inactive')"
        echo "  • Memcached: $(systemctl is-active memcached 2>/dev/null || echo 'inactive')"
        echo "  • Fail2ban: $(systemctl is-active fail2ban 2>/dev/null || echo 'inactive')"
        echo "  • Auto-heal: $(systemctl is-active autoheal 2>/dev/null || echo 'inactive')"
        echo ""
        echo "  • Disk: $(df -h / | awk 'NR==2 {print $3"/"$2 " ("$5")"}')"
        echo "  • Memory: $(free -h | awk '/Mem:/ {print $3"/"$2}')"
        echo "  • Load: $(uptime | awk -F'load average:' '{print $2}')"
        ;;
        
    report)
        /usr/local/bin/easy-report
        ;;
        
    monitor)
        /usr/local/bin/advanced-monitor
        ;;
        
    telegram)
        /usr/local/bin/setup-telegram
        ;;
        
    logs)
        case "$2" in
            nginx) tail -f /var/log/nginx/wordpress_*.log 2>/dev/null || tail -f /var/log/nginx/access.log 2>/dev/null || echo "No nginx logs found" ;;
            php) tail -f /var/log/php*-fpm.log 2>/dev/null || echo "PHP logs not found" ;;
            mysql) tail -f /var/log/mysql/error.log 2>/dev/null || echo "MySQL logs not found" ;;
            *) echo "Usage: easyinstall logs [nginx|php|mysql]" ;;
        esac
        ;;
        
    cache)
        if [ "$2" = "clear" ]; then
            rm -rf /var/cache/nginx/*
            systemctl reload nginx 2>/dev/null
            echo -e "${GREEN}✅ Nginx cache cleared${NC}"
        else
            echo "Usage: easyinstall cache clear"
        fi
        ;;
        
    redis)
        if [ "$2" = "flush" ]; then
            redis-cli FLUSHALL 2>/dev/null
            echo -e "${GREEN}✅ Redis cache flushed${NC}"
        else
            echo "Usage: easyinstall redis flush"
        fi
        ;;
        
    memcached)
        if [ "$2" = "flush" ]; then
            echo "flush_all" | nc localhost 11211 2>/dev/null
            echo -e "${GREEN}✅ Memcached flushed${NC}"
        else
            echo "Usage: easyinstall memcached flush"
        fi
        ;;
        
    keys)
        if [ "$2" = "update" ]; then
            /usr/local/bin/update-wp-keys
        else
            echo "Usage: easyinstall keys update"
        fi
        ;;
        
    fail2ban)
        if [ "$2" = "status" ]; then
            fail2ban-client status 2>/dev/null
        else
            echo "Usage: easyinstall fail2ban status"
        fi
        ;;
        
    waf)
        if [ "$2" = "status" ]; then
            if grep -q "modsecurity on" /etc/nginx/nginx.conf 2>/dev/null; then
                echo -e "${GREEN}✅ ModSecurity is enabled${NC}"
            else
                echo -e "${RED}❌ ModSecurity is disabled${NC}"
            fi
        else
            echo "Usage: easyinstall waf status"
        fi
        ;;
        
    cdn)
        shift
        /usr/local/bin/easy-cdn "$@"
        ;;
        
    site-manager)
        shift
        /usr/local/bin/easy-site "$@"
        ;;
        
    restart)
        case "$2" in
            nginx) systemctl restart nginx 2>/dev/null ;;
            php) systemctl restart php*-fpm 2>/dev/null ;;
            mysql) systemctl restart mariadb 2>/dev/null ;;
            redis) systemctl restart redis-server 2>/dev/null ;;
            memcached) systemctl restart memcached 2>/dev/null ;;
            all|"") systemctl restart nginx php*-fpm mariadb redis-server memcached 2>/dev/null ;;
            *) echo "Usage: easyinstall restart [nginx|php|mysql|redis|memcached|all]" ;;
        esac
        echo -e "${GREEN}✅ Services restarted${NC}"
        ;;
        
    clean)
        echo -e "${YELLOW}🧹 Cleaning system...${NC}"
        apt autoremove -y 2>/dev/null
        apt autoclean 2>/dev/null
        find /var/log -name "*.log" -mtime +30 -delete 2>/dev/null
        echo -e "${GREEN}✅ Cleanup completed${NC}"
        ;;
        
    update)
        echo -e "${YELLOW}📦 Updating system...${NC}"
        apt update 2>/dev/null
        apt upgrade -y 2>/dev/null
        echo -e "${GREEN}✅ System updated${NC}"
        ;;
        
    help)
        show_help
        ;;
        
    *)
        echo -e "${RED}Unknown command: $MAIN_COMMAND${NC}"
        echo "Run 'easyinstall help' for available commands"
        exit 1
        ;;
esac
EOF

    chmod +x /usr/local/bin/easyinstall
    
    # Create internal command handler for PHP/HTML site creation and SSL enable
    cat > /usr/local/bin/easyinstall-internal <<'EOF'
#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

COMMAND=$1
DOMAIN=$2
USE_SSL=$3

case $COMMAND in
    php-site)
        echo -e "${YELLOW}🐘 Creating PHP site for $DOMAIN...${NC}"
        
        # Create site directory
        SITE_DIR="/var/www/html/${DOMAIN}"
        mkdir -p "$SITE_DIR"
        
        # Get PHP version
        PHP_VERSION=$(ls /etc/php/ 2>/dev/null | head -1)
        [ -z "$PHP_VERSION" ] && PHP_VERSION="8.2"
        
        # Create sample index.php
        cat > "$SITE_DIR/index.php" <<PHPEOF
<?php
/**
 * Sample PHP site for ${DOMAIN}
 */
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${DOMAIN}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            text-align: center;
        }
        h1 {
            color: #2563eb;
            margin-bottom: 20px;
        }
        .info {
            background: #f3f4f6;
            border-radius: 8px;
            padding: 20px;
            margin-top: 30px;
        }
        .php-info {
            color: #059669;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <h1>Welcome to <?php echo htmlspecialchars(\$_SERVER['HTTP_HOST']); ?></h1>
    
    <div class="info">
        <p>This is a PHP site created with <strong>EasyInstall</strong></p>
        <p class="php-info">PHP Version: <?php echo phpversion(); ?></p>
        <p>Server: <?php echo php_uname('s'); ?></p>
        <p>Date: <?php echo date('Y-m-d H:i:s'); ?></p>
    </div>
    
    <p>Edit this file at: <code><?php echo __FILE__; ?></code></p>
</body>
</html>
PHPEOF

        # Find PHP socket
        PHP_SOCKET="unix:/run/php/php${PHP_VERSION}-fpm.sock"
        if [ ! -S "${PHP_SOCKET#unix:}" ]; then
            for sock in /run/php/php*-fpm.sock; do
                if [ -S "$sock" ]; then
                    PHP_SOCKET="unix:$sock"
                    break
                fi
            done
        fi

        # Create nginx config
        cat > "/etc/nginx/sites-available/${DOMAIN}" <<NGINXEOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};
    root ${SITE_DIR};
    index index.php index.html;
    
    access_log /var/log/nginx/${DOMAIN}_access.log;
    error_log /var/log/nginx/${DOMAIN}_error.log;
    
    client_max_body_size 64M;
    
    include /etc/nginx/security-headers.conf 2>/dev/null || true;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass ${PHP_SOCKET};
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
    
    location ~ /\. {
        deny all;
    }
    
    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }
    
    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }
}
NGINXEOF

        ln -sf "/etc/nginx/sites-available/${DOMAIN}" "/etc/nginx/sites-enabled/"
        chown -R www-data:www-data "$SITE_DIR"
        
        # Test and reload nginx
        if nginx -t 2>/dev/null; then
            systemctl reload nginx 2>/dev/null
            echo -e "${GREEN}✅ Nginx configuration created${NC}"
        else
            echo -e "${RED}❌ Nginx configuration test failed${NC}"
            nginx -t
            exit 1
        fi
        
        # Enable SSL if requested
        if [ "$USE_SSL" = "true" ]; then
            echo -e "${YELLOW}🔐 Enabling SSL for ${DOMAIN}...${NC}"
            certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos --email "admin@$DOMAIN" 2>/dev/null
            
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✅ SSL enabled for ${DOMAIN}${NC}"
            else
                echo -e "${RED}❌ SSL installation failed${NC}"
            fi
        fi
        
        echo -e "${GREEN}✅ PHP site created for ${DOMAIN}${NC}"
        echo -e "${GREEN}🌐 URL: http://${DOMAIN}${NC}"
        [ "$USE_SSL" = "true" ] && echo -e "${GREEN}🔒 Secure URL: https://${DOMAIN}${NC}"
        ;;
        
    html-site)
        echo -e "${YELLOW}🌐 Creating HTML site for $DOMAIN...${NC}"
        
        # Create site directory
        SITE_DIR="/var/www/html/${DOMAIN}"
        mkdir -p "$SITE_DIR"
        
        # Create sample index.html
        cat > "$SITE_DIR/index.html" <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${DOMAIN}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            text-align: center;
        }
        h1 {
            color: #2563eb;
            margin-bottom: 20px;
        }
        .info {
            background: #f3f4f6;
            border-radius: 8px;
            padding: 20px;
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <h1>Welcome to ${DOMAIN}</h1>
    
    <div class="info">
        <p>This is an HTML site created with <strong>EasyInstall</strong></p>
        <p>Server: $(hostname)</p>
        <p>Date: $(date)</p>
    </div>
    
    <p>Edit this file at: <code>${SITE_DIR}/index.html</code></p>
</body>
</html>
HTMLEOF

        # Create nginx config for HTML site
        cat > "/etc/nginx/sites-available/${DOMAIN}" <<NGINXEOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};
    root ${SITE_DIR};
    index index.html;
    
    access_log /var/log/nginx/${DOMAIN}_access.log;
    error_log /var/log/nginx/${DOMAIN}_error.log;
    
    client_max_body_size 64M;
    
    include /etc/nginx/security-headers.conf 2>/dev/null || true;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location ~ /\. {
        deny all;
    }
    
    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }
    
    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }
}
NGINXEOF

        ln -sf "/etc/nginx/sites-available/${DOMAIN}" "/etc/nginx/sites-enabled/"
        chown -R www-data:www-data "$SITE_DIR"
        
        # Test and reload nginx
        if nginx -t 2>/dev/null; then
            systemctl reload nginx 2>/dev/null
            echo -e "${GREEN}✅ Nginx configuration created${NC}"
        else
            echo -e "${RED}❌ Nginx configuration test failed${NC}"
            nginx -t
            exit 1
        fi
        
        # Enable SSL if requested
        if [ "$USE_SSL" = "true" ]; then
            echo -e "${YELLOW}🔐 Enabling SSL for ${DOMAIN}...${NC}"
            certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos --email "admin@$DOMAIN" 2>/dev/null
            
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✅ SSL enabled for ${DOMAIN}${NC}"
            else
                echo -e "${RED}❌ SSL installation failed${NC}"
            fi
        fi
        
        echo -e "${GREEN}✅ HTML site created for ${DOMAIN}${NC}"
        echo -e "${GREEN}🌐 URL: http://${DOMAIN}${NC}"
        [ "$USE_SSL" = "true" ] && echo -e "${GREEN}🔒 Secure URL: https://${DOMAIN}${NC}"
        ;;
        
    enable-ssl)
        echo -e "${YELLOW}🔐 Enabling SSL for $DOMAIN...${NC}"
        
        # Check if domain exists
        if [ ! -f "/etc/nginx/sites-available/${DOMAIN}" ]; then
            echo -e "${RED}❌ Domain ${DOMAIN} not found.${NC}"
            exit 1
        fi
        
        # Check if SSL already exists
        if grep -q "listen 443 ssl" "/etc/nginx/sites-available/${DOMAIN}" 2>/dev/null; then
            echo -e "${YELLOW}⚠️ SSL already enabled for ${DOMAIN}${NC}"
            exit 0
        fi
        
        # Get SSL certificate
        certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos --email "admin@$DOMAIN" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ SSL enabled for ${DOMAIN}${NC}"
            echo -e "${GREEN}🔒 Secure URL: https://${DOMAIN}${NC}"
        else
            echo -e "${RED}❌ Failed to enable SSL for ${DOMAIN}${NC}"
            exit 1
        fi
        ;;
        
    *)
        echo -e "${RED}Unknown internal command${NC}"
        exit 1
        ;;
esac
EOF

    chmod +x /usr/local/bin/easyinstall-internal
    
    echo "alias e='easyinstall'" >> /root/.bashrc
    echo "alias eb='easyinstall backup'" >> /root/.bashrc
    echo "alias er='easyinstall restore'" >> /root/.bashrc
    echo "alias es='easyinstall status'" >> /root/.bashrc
    echo "alias ere='easyinstall report'" >> /root/.bashrc
    
    echo -e "${GREEN}   ✅ Management commands installed${NC}"
    
    if [ "$PKG_MODE" = true ]; then
        mark_component_installed "commands" "3.0"
    fi
}

# ============================================
# Final Setup - FIXED
# ============================================
finalize() {
    echo -e "${YELLOW}🎯 Finalizing installation...${NC}"
    
    systemctl enable nginx 2>/dev/null
    systemctl enable mariadb 2>/dev/null
    systemctl enable redis-server 2>/dev/null
    systemctl enable memcached 2>/dev/null
    systemctl enable fail2ban 2>/dev/null
    systemctl enable netdata 2>/dev/null
    systemctl enable postfix 2>/dev/null
    systemctl enable autoheal 2>/dev/null
    systemctl enable glances 2>/dev/null || true
    
    if command -v php >/dev/null 2>&1; then
        PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null)
        systemctl enable php$PHP_VERSION-fpm 2>/dev/null || true
    fi
    
    # Run post-installation hooks if in package mode
    if [ "$PKG_MODE" = true ] && [ -d "$PKG_HOOKS_DIR" ]; then
        for hook in "$PKG_HOOKS_DIR"/*.sh; do
            if [ -f "$hook" ]; then
                echo -e "${BLUE}   🔧 Running hook: $(basename "$hook")${NC}"
                bash "$hook"
            fi
        done
    fi
    
    cat > /root/easyinstall-info.txt <<EOF
========================================
EasyInstall Enterprise Stack v3.0
Installation Date: $(date)
========================================

SYSTEM INFORMATION:
  IP Address: ${IP_ADDRESS}
  RAM: ${TOTAL_RAM}MB
  Cores: ${TOTAL_CORES}
  OS: Ubuntu/Debian ${OS_VERSION}

MONITORING INTERFACES:
  Netdata: http://${IP_ADDRESS}:19999
  Glances: http://${IP_ADDRESS}:61208

WORDPRESS:
  Not installed yet - Run: easyinstall domain yourdomain.com [--ssl]
  Permalinks: Nginx is configured to support pretty permalinks
             Just enable in WordPress Settings > Permalinks
  Theme/Plugin Editor: ENABLED (DISALLOW_FILE_EDIT = false)

PHP & HTML SITES:
  PHP Site: easyinstall create example.com --php [--ssl]
  HTML Site: easyinstall create example.com --html [--ssl]

SSL MANAGEMENT:
  Enable SSL: easyinstall site example.com --ssl=on
  Legacy SSL: easyinstall ssl example.com [email]

XML-RPC MANAGEMENT:
  Commands: easyinstall xmlrpc enable|disable|status|test
  Default: XML-RPC is ENABLED
  Use 'easyinstall xmlrpc disable' to block for security

BACKUP (Weekly only, Hybrid):
  Local: Keep last 2 backups
  External: All backups (when configured)
  Command: easyinstall backup weekly

AUTO-HEALING:
  • Service monitoring every 60 seconds
  • Auto-restart failed services
  • Disk space monitoring
  • Memory pressure detection

SECURITY:
  • ModSecurity WAF with OWASP rules (if installed)
  • Enhanced Fail2ban WordPress rules
  • Security headers enabled
  • Monthly WordPress key rotation
  • XML-RPC can be disabled via command

PERFORMANCE:
  • Redis Object Cache
  • Memcached
  • PHP OPcache enabled
  • Nginx FastCGI cache
  • Auto-tuned MySQL

MAIN COMMANDS:
  easyinstall domain example.com        # Install WordPress for domain
  easyinstall domain example.com --ssl  # Install WordPress with SSL
  easyinstall create example.com        # Install WordPress (alternative)
  easyinstall create example.com --ssl  # Install WordPress with SSL (alternative)
  easyinstall create example.com --php  # Create PHP site
  easyinstall create example.com --html # Create HTML site
  easyinstall site example.com --ssl=on # Enable SSL for any site
  easyinstall ssl example.com           # Legacy SSL installation
  easyinstall xmlrpc disable             # Block XML-RPC for security
  easyinstall xmlrpc enable              # Re-enable XML-RPC
  easyinstall xmlrpc status               # Check XML-RPC status
  easyinstall status                    # System status
  easyinstall report                    # Performance report
  easyinstall backup weekly             # Create backup
  easyinstall site create example.com   # Create additional WordPress site (Editor ENABLED)

⚠️ IMPORTANT:
  • WordPress will ONLY be installed with 'domain' or 'create' commands
  • Domain must be valid and not already exist on this server

DATABASE ROOT CREDENTIALS:
  Username: root
  Password: root
  Config file: /root/.my.cnf

FIREWALL: Ports 22, 80, 443, 19999, 61208 open

PACKAGE MANAGER:
  Installed as Debian package
  State: $PKG_STATE_DIR/installed
  Config: $PKG_CONFIG_DIR/config

SUPPORT: https://paypal.me/sugandodrai
========================================
EOF
    
    echo -e "${GREEN}"
    echo "============================================"
    echo "✅ Installation Complete! (v3.0)"
    echo "============================================"
    echo ""
    
    echo "📊 Monitoring:"
    echo "   Netdata: http://$IP_ADDRESS:19999"
    echo "   Glances: http://$IP_ADDRESS:61208"
    echo ""
    echo "🌐 WordPress:"
    echo "   Not installed yet - Run: easyinstall domain yourdomain.com"
    echo "   With SSL: easyinstall domain yourdomain.com --ssl"
    echo "   Note: Nginx supports pretty permalinks - enable in WordPress Settings"
    echo "   Theme/Plugin Editor: ENABLED (You can edit themes/plugins from admin)"
    echo ""
    echo "🐘 PHP Sites:"
    echo "   Create: easyinstall create example.com --php"
    echo "   With SSL: easyinstall create example.com --php --ssl"
    echo ""
    echo "🌐 HTML Sites:"
    echo "   Create: easyinstall create example.com --html"
    echo "   With SSL: easyinstall create example.com --html --ssl"
    echo ""
    echo "🔒 SSL Management:"
    echo "   Enable SSL for any site: easyinstall site example.com --ssl=on"
    echo ""
    echo "🔌 XML-RPC Management:"
    echo "   Default: XML-RPC is ENABLED"
    echo "   To disable (recommended for security): easyinstall xmlrpc disable"
    echo "   To re-enable: easyinstall xmlrpc enable"
    echo "   To check status: easyinstall xmlrpc status"
    echo "   To test: easyinstall xmlrpc test yourdomain.com"
    echo ""
    echo "🛡️  Security Features:"
    echo "   • ModSecurity WAF with OWASP rules (if installed)"
    echo "   • Enhanced Fail2ban WordPress protection"
    echo "   • Security headers enabled"
    echo "   • Monthly WordPress key rotation"
    echo "   • XML-RPC can be disabled via command"
    echo ""
    echo "⚡ Performance Features:"
    echo "   • Redis + Memcached optimized"
    echo "   • Auto-tuned MySQL"
    echo "   • Adaptive PHP memory limits"
    echo "   • Official Nginx with FastCGI cache"
    echo "   • Pretty permalinks supported out of the box"
    echo ""
    echo "🏥 Auto-healing: Enabled (monitors all services)"
    echo ""
    echo "⚠️ IMPORTANT:"
    echo "   • WordPress will ONLY be installed with 'domain' or 'create' commands"
    echo "   • Domain must be valid and not already exist on this server"
    echo ""
    echo "📦 Package Manager: Installed (use 'dpkg -r easyinstall' to remove)"
    echo ""
    echo "🔧 Available commands:"
    echo "   easyinstall help"
    echo "   easyinstall status"
    echo "   easyinstall domain example.com"
    echo "   easyinstall domain example.com --ssl"
    echo "   easyinstall create example.com"
    echo "   easyinstall create example.com --ssl"
    echo "   easyinstall create example.com --php"
    echo "   easyinstall create example.com --php --ssl"
    echo "   easyinstall create example.com --html"
    echo "   easyinstall create example.com --html --ssl"
    echo "   easyinstall site example.com --ssl=on"
    echo "   easyinstall xmlrpc disable"
    echo "   easyinstall xmlrpc status"
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}☕ Support: https://paypal.me/sugandodrai${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${NC}"
    
    # Commit transaction if in package mode
    if [ "$PKG_MODE" = true ]; then
        commit_transaction "full-install" "3.0"
    fi
}

# ============================================
# Main Execution - FIXED to handle commands properly
# ============================================
main() {
    # Parse command line arguments for package mode
    while [[ $# -gt 0 ]]; do
        case $1 in
            --pkg-update|--pkg-remove|--pkg-status|--pkg-verify)
                if [ "$PKG_MODE" = true ]; then
                    handle_package_command "$@"
                    exit $?
                fi
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            *)
                # If we have arguments that look like commands, don't run full installation
                if [[ "$1" =~ ^(domain|create|site|xmlrpc|ssl|backup|restore|remote|status|report|monitor|telegram|logs|cache|redis|memcached|keys|fail2ban|waf|cdn|site-manager|restart|clean|update|help)$ ]]; then
                    # Command will be handled by easyinstall script after installation
                    # We need to ensure easyinstall is installed first
                    if [ ! -f /usr/local/bin/easyinstall ]; then
                        echo -e "${YELLOW}EasyInstall not fully installed. Running full installation first...${NC}"
                        # Run full installation
                        setup_swap
                        kernel_tuning
                        install_packages
                        setup_modsecurity
                        setup_autoheal
                        setup_database
                        optimize_php
                        cleanup_nginx_config
                        configure_nginx
                        configure_redis_memcached
                        setup_fail2ban
                        prepare_wordpress
                        setup_security_keys_cron
                        setup_xmlrpc_commands
                        setup_backups
                        setup_advanced_monitoring
                        setup_advanced_cdn
                        setup_email
                        setup_panel
                        setup_remote
                        install_commands
                        finalize
                    fi
                    # Now execute the command
                    exec /usr/local/bin/easyinstall "$@"
                fi
                shift
                ;;
        esac
    done
    
    # If no arguments or we reach here, run full installation
    if [ $# -eq 0 ]; then
        setup_swap
        kernel_tuning
        install_packages
        setup_modsecurity
        setup_autoheal
        setup_database
        optimize_php
        cleanup_nginx_config
        configure_nginx
        configure_redis_memcached
        setup_fail2ban
        prepare_wordpress
        setup_security_keys_cron
        setup_xmlrpc_commands
        setup_backups
        setup_advanced_monitoring
        setup_advanced_cdn
        setup_email
        setup_panel
        setup_remote
        install_commands
        finalize
    fi
}

# Run main function with all arguments
main "$@"
