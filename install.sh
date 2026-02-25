#!/bin/bash

# ============================================
# EasyInstall Complete Stack Installer
# Includes ALL working commands and integrations
# ============================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${GREEN}🚀 EasyInstall Enterprise Stack - Complete Edition${NC}"
echo ""

# Root check
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}❌ Please run as root${NC}"
    exit 1
fi

# ============================================
# Step 1: Download and Run Base Installer
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
# Step 2: Install Additional Dependencies
# ============================================
echo -e "${YELLOW}📦 Installing additional dependencies...${NC}"

apt update
apt install -y \
    python3-pip \
    python3-venv \
    nginx \
    redis-server \
    certbot \
    python3-certbot-nginx \
    mariadb-client \
    mysql-client \
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

# Install Python packages for WebUI
pip3 install --upgrade pip
pip3 install \
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

# ============================================
# Step 3: Create Complete Command Structure
# ============================================
echo -e "${YELLOW}📝 Creating complete command structure...${NC}"

mkdir -p /usr/local/lib/easyinstall/{core,web,db,backup,cloud,monitor,docker,security,tools}
mkdir -p /etc/easyinstall/{configs,ssl,ssh,backup}
mkdir -p /var/lib/easyinstall/{data,logs,temp,backups}
mkdir -p /var/log/easyinstall

# ============================================
# Step 4: Create ALL Working Commands
# ============================================

# Core Commands
cat > /usr/local/lib/easyinstall/core/domain.sh <<'EOF'
#!/bin/bash

# ============================================
# Domain Management Commands
# ============================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check if domain exists
check_domain() {
    local domain=$1
    if [ -f "/etc/nginx/sites-available/${domain}" ] || [ -f "/etc/nginx/sites-enabled/${domain}" ]; then
        return 0
    fi
    return 1
}

# List all domains
list_domains() {
    echo -e "${GREEN}📋 Installed Domains:${NC}"
    echo "----------------------------------------"
    
    for site in /etc/nginx/sites-available/*; do
        if [ -f "$site" ]; then
            domain=$(basename "$site")
            if [ -f "/etc/nginx/sites-enabled/$domain" ]; then
                status="${GREEN}✅ Active${NC}"
            else
                status="${YELLOW}⏸️ Disabled${NC}"
            fi
            
            # Check site type
            if [ -f "/var/www/html/$domain/wp-config.php" ]; then
                type="WordPress"
            elif [ -f "/var/www/html/$domain/index.php" ]; then
                type="PHP"
            elif [ -f "/var/www/html/$domain/index.html" ]; then
                type="HTML"
            else
                type="Unknown"
            fi
            
            # Check SSL
            if grep -q "ssl_certificate" "$site" 2>/dev/null; then
                ssl="${GREEN}🔒 SSL${NC}"
            else
                ssl="${RED}🔓 No SSL${NC}"
            fi
            
            echo -e "$domain - $type - $status - $ssl"
        fi
    done
}

# Show domain info
domain_info() {
    local domain=$1
    if [ ! -f "/etc/nginx/sites-available/$domain" ]; then
        echo -e "${RED}❌ Domain $domain not found${NC}"
        return 1
    fi
    
    echo -e "${GREEN}📊 Domain Information: $domain${NC}"
    echo "----------------------------------------"
    echo -e "Root Directory: $(grep root /etc/nginx/sites-available/$domain | head -1 | awk '{print $2}' | tr -d ';')"
    echo -e "SSL Enabled: $(grep -q ssl_certificate /etc/nginx/sites-available/$domain && echo "Yes" || echo "No")"
    echo -e "Status: $( [ -f "/etc/nginx/sites-enabled/$domain" ] && echo "Active" || echo "Inactive")"
    
    # Check WordPress
    if [ -f "/var/www/html/$domain/wp-config.php" ]; then
        echo -e "Type: WordPress"
        echo -e "WP Version: $(grep wp_version /var/www/html/$domain/wp-includes/version.php 2>/dev/null | cut -d"'" -f2)"
    fi
    
    # Show access logs
    echo -e "\n${YELLOW}Recent Access Logs:${NC}"
    tail -5 /var/log/nginx/${domain}_access.log 2>/dev/null || echo "No access logs"
}
EOF

# WordPress Commands
cat > /usr/local/lib/easyinstall/web/wordpress.sh <<'EOF'
#!/bin/bash

# ============================================
# WordPress Management Commands
# ============================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Install WordPress
install_wordpress() {
    local domain=$1
    local use_ssl=$2
    local php_version=${3:-8.2}
    
    if [ -d "/var/www/html/$domain" ]; then
        echo -e "${RED}❌ Domain $domain already exists${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}📦 Installing WordPress for $domain...${NC}"
    
    # Create directory
    mkdir -p /var/www/html/$domain
    
    # Download WordPress
    wget -q -O /tmp/wordpress.tar.gz https://wordpress.org/latest.tar.gz
    tar -xzf /tmp/wordpress.tar.gz -C /tmp/
    cp -r /tmp/wordpress/* /var/www/html/$domain/
    rm -rf /tmp/wordpress /tmp/wordpress.tar.gz
    
    # Set permissions
    chown -R www-data:www-data /var/www/html/$domain
    find /var/www/html/$domain -type d -exec chmod 755 {} \;
    find /var/www/html/$domain -type f -exec chmod 644 {} \;
    
    # Create wp-config
    cat > /var/www/html/$domain/wp-config.php <<WPCONFIG
<?php
define('DB_NAME', 'wp_${domain//./_}_db');
define('DB_USER', 'wp_${domain//./_}');
define('DB_PASSWORD', '$(openssl rand -base64 12)');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', '');

define('AUTH_KEY',         '$(openssl rand -base64 40)');
define('SECURE_AUTH_KEY',  '$(openssl rand -base64 40)');
define('LOGGED_IN_KEY',    '$(openssl rand -base64 40)');
define('NONCE_KEY',        '$(openssl rand -base64 40)');
define('AUTH_SALT',        '$(openssl rand -base64 40)');
define('SECURE_AUTH_SALT', '$(openssl rand -base64 40)');
define('LOGGED_IN_SALT',   '$(openssl rand -base64 40)');
define('NONCE_SALT',       '$(openssl rand -base64 40)');

\$table_prefix = 'wp_';

define('WP_DEBUG', false);
define('WP_DEBUG_LOG', false);
define('WP_DEBUG_DISPLAY', false);

if ( !defined('ABSPATH') )
    define('ABSPATH', dirname(__FILE__) . '/');

require_once(ABSPATH . 'wp-settings.php');
WPCONFIG
    
    # Create database
    DB_NAME="wp_${domain//./_}_db"
    DB_USER="wp_${domain//./_}"
    DB_PASS=$(openssl rand -base64 12)
    
    mysql -e "CREATE DATABASE IF NOT EXISTS $DB_NAME;"
    mysql -e "CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
    mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    
    # Update wp-config with database info
    sed -i "s/define('DB_NAME', '.*');/define('DB_NAME', '$DB_NAME');/" /var/www/html/$domain/wp-config.php
    sed -i "s/define('DB_USER', '.*');/define('DB_USER', '$DB_USER');/" /var/www/html/$domain/wp-config.php
    sed -i "s/define('DB_PASSWORD', '.*');/define('DB_PASSWORD', '$DB_PASS');/" /var/www/html/$domain/wp-config.php
    
    # Create Nginx config
    cat > /etc/nginx/sites-available/$domain <<NGINX
server {
    listen 80;
    server_name $domain www.$domain;
    root /var/www/html/$domain;
    index index.php;
    
    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log;
    
    client_max_body_size 64M;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass unix:/run/php/php${php_version}-fpm.sock;
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
NGINX
    
    ln -sf /etc/nginx/sites-available/$domain /etc/nginx/sites-enabled/
    
    # Test and reload Nginx
    nginx -t && systemctl reload nginx
    
    # Enable SSL if requested
    if [ "$use_ssl" = "true" ] || [ "$use_ssl" = "--ssl" ]; then
        certbot --nginx -d $domain -d www.$domain --non-interactive --agree-tos --email admin@$domain
    fi
    
    # Save credentials
    mkdir -p /var/lib/easyinstall/credentials
    cat > /var/lib/easyinstall/credentials/${domain}.txt <<CRED
WordPress Site: $domain
URL: http://$domain
Database Name: $DB_NAME
Database User: $DB_USER
Database Password: $DB_PASS
CRED
    
    echo -e "${GREEN}✅ WordPress installed for $domain${NC}"
    echo -e "${YELLOW}Credentials saved in: /var/lib/easyinstall/credentials/${domain}.txt${NC}"
}

# WordPress CLI commands
wp_command() {
    local domain=$1
    shift
    local cmd="$@"
    
    if [ ! -f "/var/www/html/$domain/wp-config.php" ]; then
        echo -e "${RED}❌ Not a WordPress installation${NC}"
        return 1
    fi
    
    cd /var/www/html/$domain
    sudo -u www-data wp "$cmd"
}

# Update WordPress
update_wordpress() {
    local domain=$1
    
    if [ ! -f "/var/www/html/$domain/wp-config.php" ]; then
        echo -e "${RED}❌ Not a WordPress installation${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}📦 Updating WordPress for $domain...${NC}"
    
    cd /var/www/html/$domain
    sudo -u www-data wp core update
    sudo -u www-data wp plugin update --all
    sudo -u www-data wp theme update --all
    
    echo -e "${GREEN}✅ WordPress updated${NC}"
}

# Backup WordPress
backup_wordpress() {
    local domain=$1
    
    if [ ! -d "/var/www/html/$domain" ]; then
        echo -e "${RED}❌ Domain $domain not found${NC}"
        return 1
    fi
    
    local backup_dir="/var/lib/easyinstall/backups/$domain"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    mkdir -p "$backup_dir"
    
    echo -e "${YELLOW}💾 Backing up WordPress for $domain...${NC}"
    
    # Backup files
    tar -czf "$backup_dir/files_$timestamp.tar.gz" -C /var/www/html "$domain"
    
    # Backup database if WordPress
    if [ -f "/var/www/html/$domain/wp-config.php" ]; then
        DB_NAME=$(grep DB_NAME /var/www/html/$domain/wp-config.php | cut -d"'" -f4)
        mysqldump "$DB_NAME" > "$backup_dir/db_$timestamp.sql"
        gzip "$backup_dir/db_$timestamp.sql"
    fi
    
    echo -e "${GREEN}✅ Backup saved to: $backup_dir${NC}"
}

# Restore WordPress
restore_wordpress() {
    local domain=$1
    local backup_file=$2
    
    if [ ! -f "$backup_file" ]; then
        echo -e "${RED}❌ Backup file not found${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}🔄 Restoring WordPress for $domain...${NC}"
    
    # Extract backup
    tar -xzf "$backup_file" -C /var/www/html/
    
    # Restore database if exists
    local db_backup="${backup_file/files/db}"
    db_backup="${db_backup/.tar.gz/.sql.gz}"
    
    if [ -f "$db_backup" ]; then
        gunzip -c "$db_backup" | mysql "$(grep DB_NAME /var/www/html/$domain/wp-config.php | cut -d"'" -f4)"
    fi
    
    chown -R www-data:www-data /var/www/html/$domain
    
    echo -e "${GREEN}✅ WordPress restored${NC}"
}
EOF

# PHP Site Commands
cat > /usr/local/lib/easyinstall/web/php.sh <<'EOF'
#!/bin/bash

# ============================================
# PHP Site Management Commands
# ============================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Create PHP site
create_php_site() {
    local domain=$1
    local use_ssl=$2
    local php_version=${3:-8.2}
    
    if [ -d "/var/www/html/$domain" ]; then
        echo -e "${RED}❌ Domain $domain already exists${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}🐘 Creating PHP site for $domain...${NC}"
    
    # Create directory
    mkdir -p /var/www/html/$domain
    
    # Create sample index.php
    cat > /var/www/html/$domain/index.php <<EOF
<?php
/**
 * PHP Site for $domain
 */
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$domain</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; line-height: 1.6; }
        h1 { color: #2563eb; }
        .info { background: #f3f4f6; padding: 20px; border-radius: 8px; margin-top: 20px; }
        .php-version { color: #059669; font-weight: bold; }
        pre { background: #1e293b; color: #e2e8f0; padding: 10px; border-radius: 4px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>Welcome to <?php echo htmlspecialchars(\$_SERVER['HTTP_HOST']); ?></h1>
    
    <div class="info">
        <p class="php-version">PHP Version: <?php echo phpversion(); ?></p>
        <p>Server: <?php echo php_uname('s'); ?></p>
        <p>Date: <?php echo date('Y-m-d H:i:s'); ?></p>
        <p>Memory Limit: <?php echo ini_get('memory_limit'); ?></p>
        <p>Max Upload Size: <?php echo ini_get('upload_max_filesize'); ?></p>
    </div>
    
    <h2>PHP Info</h2>
    <pre><?php phpinfo(); ?></pre>
    
    <p>Edit this file at: <code><?php echo __FILE__; ?></code></p>
</body>
</html>
EOF
    
    # Find PHP-FPM socket
    PHP_SOCKET="/run/php/php${php_version}-fpm.sock"
    if [ ! -S "$PHP_SOCKET" ]; then
        for sock in /run/php/php*-fpm.sock; do
            if [ -S "$sock" ]; then
                PHP_SOCKET="$sock"
                break
            fi
        done
    fi
    
    # Create Nginx config
    cat > /etc/nginx/sites-available/$domain <<NGINX
server {
    listen 80;
    server_name $domain www.$domain;
    root /var/www/html/$domain;
    index index.php index.html;
    
    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log;
    
    client_max_body_size 64M;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass unix:$PHP_SOCKET;
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
NGINX
    
    ln -sf /etc/nginx/sites-available/$domain /etc/nginx/sites-enabled/
    chown -R www-data:www-data /var/www/html/$domain
    
    # Test and reload Nginx
    nginx -t && systemctl reload nginx
    
    # Enable SSL if requested
    if [ "$use_ssl" = "true" ] || [ "$use_ssl" = "--ssl" ]; then
        certbot --nginx -d $domain -d www.$domain --non-interactive --agree-tos --email admin@$domain
    fi
    
    echo -e "${GREEN}✅ PHP site created for $domain${NC}"
    echo -e "${GREEN}🌐 URL: http://$domain${NC}"
}

# Run PHP command
php_command() {
    local domain=$1
    shift
    local cmd="$@"
    
    if [ ! -d "/var/www/html/$domain" ]; then
        echo -e "${RED}❌ Domain $domain not found${NC}"
        return 1
    fi
    
    cd /var/www/html/$domain
    php "$cmd"
}

# Test PHP configuration
test_php() {
    local domain=$1
    
    if [ ! -d "/var/www/html/$domain" ]; then
        echo -e "${RED}❌ Domain $domain not found${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}🔍 Testing PHP for $domain...${NC}"
    
    # Create test file
    cat > /var/www/html/$domain/test.php <<EOF
<?php
echo "PHP Version: " . phpversion() . "\n";
echo "Loaded Extensions:\n";
print_r(get_loaded_extensions());
echo "\nServer Info:\n";
print_r(\$_SERVER);
?>
EOF
    
    echo -e "${GREEN}✅ Test file created: http://$domain/test.php${NC}"
}
EOF

# HTML Site Commands
cat > /usr/local/lib/easyinstall/web/html.sh <<'EOF'
#!/bin/bash

# ============================================
# HTML Site Management Commands
# ============================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Create HTML site
create_html_site() {
    local domain=$1
    local use_ssl=$2
    
    if [ -d "/var/www/html/$domain" ]; then
        echo -e "${RED}❌ Domain $domain already exists${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}🌐 Creating HTML site for $domain...${NC}"
    
    # Create directory
    mkdir -p /var/www/html/$domain
    
    # Create sample index.html
    cat > /var/www/html/$domain/index.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$domain</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            max-width: 800px;
            margin: 20px;
            padding: 40px;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 { color: #2563eb; margin-bottom: 20px; }
        .info { 
            background: #f3f4f6; 
            padding: 20px; 
            border-radius: 8px; 
            margin: 20px 0;
        }
        .server-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        .server-info div {
            background: #e5e7eb;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }
        .server-info strong {
            display: block;
            color: #4b5563;
            margin-bottom: 5px;
        }
        .footer {
            margin-top: 30px;
            text-align: center;
            color: #6b7280;
            font-size: 0.875rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to $domain</h1>
        
        <div class="info">
            <p>This is an HTML site created with <strong>EasyInstall</strong></p>
            <p>Edit this file at: <code>/var/www/html/$domain/index.html</code></p>
        </div>
        
        <div class="server-info">
            <div>
                <strong>Server</strong>
                <span>$(hostname)</span>
            </div>
            <div>
                <strong>Date</strong>
                <span>$(date)</span>
            </div>
            <div>
                <strong>IP Address</strong>
                <span>$(hostname -I | awk '{print $1}')</span>
            </div>
        </div>
        
        <div class="footer">
            <p>&copy; $(date +%Y) EasyInstall. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
EOF
    
    # Create Nginx config
    cat > /etc/nginx/sites-available/$domain <<NGINX
server {
    listen 80;
    server_name $domain www.$domain;
    root /var/www/html/$domain;
    index index.html;
    
    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log;
    
    client_max_body_size 64M;
    
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
NGINX
    
    ln -sf /etc/nginx/sites-available/$domain /etc/nginx/sites-enabled/
    chown -R www-data:www-data /var/www/html/$domain
    
    # Test and reload Nginx
    nginx -t && systemctl reload nginx
    
    # Enable SSL if requested
    if [ "$use_ssl" = "true" ] || [ "$use_ssl" = "--ssl" ]; then
        certbot --nginx -d $domain -d www.$domain --non-interactive --agree-tos --email admin@$domain
    fi
    
    echo -e "${GREEN}✅ HTML site created for $domain${NC}"
    echo -e "${GREEN}🌐 URL: http://$domain${NC}"
}

# Deploy static site from GitHub
deploy_static_site() {
    local domain=$1
    local repo_url=$2
    
    if [ -z "$repo_url" ]; then
        echo -e "${RED}❌ Please provide GitHub repository URL${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}📦 Deploying static site from $repo_url...${NC}"
    
    # Clone repository
    git clone "$repo_url" /tmp/$domain
    
    # Copy files
    mkdir -p /var/www/html/$domain
    cp -r /tmp/$domain/* /var/www/html/$domain/ 2>/dev/null || cp -r /tmp/$domain/. /var/www/html/$domain/ 2>/dev/null
    
    # Cleanup
    rm -rf /tmp/$domain
    
    # Set permissions
    chown -R www-data:www-data /var/www/html/$domain
    
    echo -e "${GREEN}✅ Static site deployed for $domain${NC}"
}
EOF

# Database Commands
cat > /usr/local/lib/easyinstall/db/database.sh <<'EOF'
#!/bin/bash

# ============================================
# Database Management Commands
# ============================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# List all databases
list_databases() {
    echo -e "${GREEN}📋 Databases:${NC}"
    echo "----------------------------------------"
    mysql -e "SHOW DATABASES;" | grep -v "Database\|information_schema\|performance_schema\|mysql"
}

# Create database
create_database() {
    local db_name=$1
    local db_user=$2
    local db_pass=$3
    
    if [ -z "$db_pass" ]; then
        db_pass=$(openssl rand -base64 12)
    fi
    
    echo -e "${YELLOW}📦 Creating database $db_name...${NC}"
    
    mysql -e "CREATE DATABASE IF NOT EXISTS $db_name;"
    
    if [ -n "$db_user" ]; then
        mysql -e "CREATE USER IF NOT EXISTS '$db_user'@'localhost' IDENTIFIED BY '$db_pass';"
        mysql -e "GRANT ALL PRIVILEGES ON $db_name.* TO '$db_user'@'localhost';"
        mysql -e "FLUSH PRIVILEGES;"
        
        echo -e "${GREEN}✅ Database and user created${NC}"
        echo -e "Database: $db_name"
        echo -e "User: $db_user"
        echo -e "Password: $db_pass"
    else
        echo -e "${GREEN}✅ Database created: $db_name${NC}"
    fi
}

# Backup database
backup_database() {
    local db_name=$1
    local backup_file="/var/lib/easyinstall/backups/${db_name}_$(date +%Y%m%d_%H%M%S).sql"
    
    echo -e "${YELLOW}💾 Backing up database $db_name...${NC}"
    
    mysqldump "$db_name" > "$backup_file"
    gzip "$backup_file"
    
    echo -e "${GREEN}✅ Database backup saved: ${backup_file}.gz${NC}"
}

# Restore database
restore_database() {
    local db_name=$1
    local backup_file=$2
    
    if [ ! -f "$backup_file" ]; then
        echo -e "${RED}❌ Backup file not found${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}🔄 Restoring database $db_name...${NC}"
    
    if [[ "$backup_file" == *.gz ]]; then
        gunzip -c "$backup_file" | mysql "$db_name"
    else
        mysql "$db_name" < "$backup_file"
    fi
    
    echo -e "${GREEN}✅ Database restored${NC}"
}

# Import database
import_database() {
    local db_name=$1
    local sql_file=$2
    
    if [ ! -f "$sql_file" ]; then
        echo -e "${RED}❌ SQL file not found${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}📥 Importing database from $sql_file...${NC}"
    
    mysql "$db_name" < "$sql_file"
    
    echo -e "${GREEN}✅ Database imported${NC}"
}

# Export database
export_database() {
    local db_name=$1
    local output_file=${2:-"${db_name}_export.sql"}
    
    echo -e "${YELLOW}📤 Exporting database $db_name...${NC}"
    
    mysqldump "$db_name" > "$output_file"
    
    echo -e "${GREEN}✅ Database exported to: $output_file${NC}"
}

# MySQL console
mysql_console() {
    local db_name=$1
    
    if [ -n "$db_name" ]; then
        mysql "$db_name"
    else
        mysql
    fi
}

# Database size
database_size() {
    local db_name=$1
    
    echo -e "${YELLOW}📊 Database size for $db_name:${NC}"
    mysql -e "
        SELECT 
            table_schema AS 'Database',
            ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)'
        FROM information_schema.tables 
        WHERE table_schema = '$db_name'
        GROUP BY table_schema;
    "
}

# Optimize database
optimize_database() {
    local db_name=$1
    
    echo -e "${YELLOW}⚡ Optimizing database $db_name...${NC}"
    
    mysql -e "SELECT CONCAT('OPTIMIZE TABLE ', table_schema, '.', table_name, ';') 
              FROM information_schema.tables 
              WHERE table_schema = '$db_name' 
              AND table_type = 'BASE TABLE' \G" | mysql
    
    echo -e "${GREEN}✅ Database optimized${NC}"
}
EOF

# SSL Commands
cat > /usr/local/lib/easyinstall/security/ssl.sh <<'EOF'
#!/bin/bash

# ============================================
# SSL Certificate Management Commands
# ============================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Enable SSL for domain
enable_ssl() {
    local domain=$1
    local email=${2:-"admin@$domain"}
    
    if [ ! -f "/etc/nginx/sites-available/$domain" ]; then
        echo -e "${RED}❌ Domain $domain not found${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}🔐 Enabling SSL for $domain...${NC}"
    
    # Check if SSL already enabled
    if grep -q "ssl_certificate" "/etc/nginx/sites-available/$domain" 2>/dev/null; then
        echo -e "${YELLOW}⚠️ SSL already enabled for $domain${NC}"
        return 0
    fi
    
    # Get SSL certificate
    certbot --nginx -d "$domain" -d "www.$domain" \
        --non-interactive \
        --agree-tos \
        --email "$email" \
        --redirect \
        --hsts \
        --staple-ocsp \
        --must-staple
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ SSL enabled for $domain${NC}"
        echo -e "${GREEN}🔒 Secure URL: https://$domain${NC}"
    else
        echo -e "${RED}❌ Failed to enable SSL for $domain${NC}"
        return 1
    fi
}

# Renew SSL certificates
renew_ssl() {
    echo -e "${YELLOW}🔄 Renewing SSL certificates...${NC}"
    
    certbot renew --quiet --no-self-upgrade
    
    echo -e "${GREEN}✅ SSL certificates renewed${NC}"
}

# Check SSL certificate expiry
check_ssl_expiry() {
    local domain=$1
    
    if [ -z "$domain" ]; then
        # Check all domains
        echo -e "${GREEN}📋 SSL Certificate Status:${NC}"
        echo "----------------------------------------"
        
        for site in /etc/nginx/sites-available/*; do
            if [ -f "$site" ] && grep -q "ssl_certificate" "$site" 2>/dev/null; then
                domain=$(basename "$site")
                expiry=$(echo | openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
                
                if [ -n "$expiry" ]; then
                    expiry_epoch=$(date -d "$expiry" +%s)
                    current_epoch=$(date +%s)
                    days_left=$(( ($expiry_epoch - $current_epoch) / 86400 ))
                    
                    if [ $days_left -lt 7 ]; then
                        status="${RED}⚠️ Expiring in $days_left days${NC}"
                    elif [ $days_left -lt 30 ]; then
                        status="${YELLOW}⚠️ Expiring in $days_left days${NC}"
                    else
                        status="${GREEN}✅ Valid ($days_left days left)${NC}"
                    fi
                    
                    echo -e "$domain - $status"
                fi
            fi
        done
    else
        # Check specific domain
        expiry=$(echo | openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
        
        if [ -n "$expiry" ]; then
            expiry_epoch=$(date -d "$expiry" +%s)
            current_epoch=$(date +%s)
            days_left=$(( ($expiry_epoch - $current_epoch) / 86400 ))
            
            echo -e "${GREEN}📊 SSL Certificate for $domain:${NC}"
            echo "----------------------------------------"
            echo -e "Expiry Date: $expiry"
            echo -e "Days Left: $days_left"
            echo -e "Status: $([ $days_left -lt 7 ] && echo "${RED}Critical${NC}" || ([ $days_left -lt 30 ] && echo "${YELLOW}Warning${NC}" || echo "${GREEN}Good${NC}"))"
        else
            echo -e "${RED}❌ No SSL certificate found for $domain${NC}"
        fi
    fi
}

# Create self-signed certificate
create_self_signed() {
    local domain=$1
    
    echo -e "${YELLOW}🔐 Creating self-signed certificate for $domain...${NC}"
    
    mkdir -p /etc/nginx/ssl/$domain
    
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/$domain/privkey.pem \
        -out /etc/nginx/ssl/$domain/fullchain.pem \
        -subj "/C=US/ST=State/L=City/O=EasyInstall/CN=$domain" 2>/dev/null
    
    echo -e "${GREEN}✅ Self-signed certificate created${NC}"
    echo -e "Key: /etc/nginx/ssl/$domain/privkey.pem"
    echo -e "Cert: /etc/nginx/ssl/$domain/fullchain.pem"
}
EOF

# Backup Commands
cat > /usr/local/lib/easyinstall/backup/backup.sh <<'EOF'
#!/bin/bash

# ============================================
# Backup Management Commands
# ============================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

BACKUP_DIR="/var/lib/easyinstall/backups"

# Create full backup
create_backup() {
    local backup_name=${1:-"full_backup_$(date +%Y%m%d_%H%M%S)"}
    local backup_path="$BACKUP_DIR/$backup_name"
    
    mkdir -p "$backup_path"
    
    echo -e "${YELLOW}💾 Creating full backup: $backup_name${NC}"
    
    # Backup websites
    echo -e "  📁 Backing up websites..."
    tar -czf "$backup_path/websites.tar.gz" -C /var/www/html . 2>/dev/null || true
    
    # Backup databases
    echo -e "  🗄️  Backing up databases..."
    mkdir -p "$backup_path/databases"
    for db in $(mysql -e "SHOW DATABASES;" | grep -v "Database\|information_schema\|performance_schema\|mysql"); do
        mysqldump "$db" > "$backup_path/databases/$db.sql" 2>/dev/null
        gzip "$backup_path/databases/$db.sql"
    done
    
    # Backup nginx configs
    echo -e "  ⚙️  Backing up nginx configurations..."
    tar -czf "$backup_path/nginx-configs.tar.gz" -C /etc/nginx sites-available/ sites-enabled/ nginx.conf 2>/dev/null || true
    
    # Backup SSL certificates
    echo -e "  🔐 Backing up SSL certificates..."
    if [ -d "/etc/letsencrypt" ]; then
        tar -czf "$backup_path/ssl-certificates.tar.gz" -C /etc letsencrypt/ 2>/dev/null || true
    fi
    
    # Create backup info
    cat > "$backup_path/backup-info.txt" <<INFO
Backup Name: $backup_name
Date: $(date)
Server: $(hostname)
IP: $(hostname -I | awk '{print $1}')
Size: $(du -sh "$backup_path" | cut -f1)
INFO
    
    # Create final archive
    cd "$BACKUP_DIR"
    tar -czf "$backup_name.tar.gz" "$backup_name"
    rm -rf "$backup_path"
    
    echo -e "${GREEN}✅ Backup created: $BACKUP_DIR/$backup_name.tar.gz${NC}"
    echo -e "Size: $(du -h "$BACKUP_DIR/$backup_name.tar.gz" | cut -f1)"
}

# List backups
list_backups() {
    echo -e "${GREEN}📋 Available Backups:${NC}"
    echo "----------------------------------------"
    
    if [ -d "$BACKUP_DIR" ]; then
        for backup in "$BACKUP_DIR"/*.tar.gz; do
            if [ -f "$backup" ]; then
                name=$(basename "$backup")
                size=$(du -h "$backup" | cut -f1)
                date=$(date -r "$backup" "+%Y-%m-%d %H:%M:%S")
                echo -e "$name - $size - $date"
            fi
        done
    else
        echo "No backups found"
    fi
}

# Restore backup
restore_backup() {
    local backup_file=$1
    
    if [ ! -f "$backup_file" ]; then
        echo -e "${RED}❌ Backup file not found${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}🔄 Restoring from backup: $backup_file${NC}"
    
    local temp_dir="/tmp/restore_$$"
    mkdir -p "$temp_dir"
    
    # Extract backup
    tar -xzf "$backup_file" -C "$temp_dir"
    
    # Find extracted directory
    extracted_dir=$(find "$temp_dir" -type d -name "full_backup_*" | head -1)
    
    if [ -z "$extracted_dir" ]; then
        echo -e "${RED}❌ Invalid backup format${NC}"
        rm -rf "$temp_dir"
        return 1
    fi
    
    # Restore websites
    if [ -f "$extracted_dir/websites.tar.gz" ]; then
        echo -e "  📁 Restoring websites..."
        tar -xzf "$extracted_dir/websites.tar.gz" -C /var/www/html/
    fi
    
    # Restore databases
    if [ -d "$extracted_dir/databases" ]; then
        echo -e "  🗄️  Restoring databases..."
        for db_backup in "$extracted_dir/databases"/*.sql.gz; do
            if [ -f "$db_backup" ]; then
                db_name=$(basename "$db_backup" .sql.gz)
                gunzip -c "$db_backup" | mysql "$db_name" 2>/dev/null || true
            fi
        done
    fi
    
    # Restore nginx configs
    if [ -f "$extracted_dir/nginx-configs.tar.gz" ]; then
        echo -e "  ⚙️  Restoring nginx configurations..."
        tar -xzf "$extracted_dir/nginx-configs.tar.gz" -C /etc/nginx/
        nginx -t && systemctl reload nginx
    fi
    
    # Restore SSL certificates
    if [ -f "$extracted_dir/ssl-certificates.tar.gz" ]; then
        echo -e "  🔐 Restoring SSL certificates..."
        tar -xzf "$extracted_dir/ssl-certificates.tar.gz" -C /etc/
    fi
    
    # Cleanup
    rm -rf "$temp_dir"
    
    echo -e "${GREEN}✅ Backup restored successfully${NC}"
}

# Schedule backup
schedule_backup() {
    local schedule=${1:-"daily"}
    local time=${2:-"02:00"}
    
    echo -e "${YELLOW}⏰ Scheduling $schedule backup at $time...${NC}"
    
    # Convert time to cron format
    hour=$(echo "$time" | cut -d: -f1)
    minute=$(echo "$time" | cut -d: -f2)
    
    case "$schedule" in
        hourly)
            cron_time="$minute * * * *"
            ;;
        daily)
            cron_time="$minute $hour * * *"
            ;;
        weekly)
            cron_time="$minute $hour * * 0"
            ;;
        monthly)
            cron_time="$minute $hour 1 * *"
            ;;
        *)
            echo -e "${RED}❌ Invalid schedule${NC}"
            return 1
            ;;
    esac
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "$cron_time /usr/local/bin/easyinstall backup create") | crontab -
    
    echo -e "${GREEN}✅ Backup scheduled: $schedule at $time${NC}"
}

# Backup to remote (rsync)
remote_backup() {
    local remote_host=$1
    local remote_path=$2
    local backup_file=${3:-$(ls -t "$BACKUP_DIR"/*.tar.gz | head -1)}
    
    if [ ! -f "$backup_file" ]; then
        echo -e "${RED}❌ Backup file not found${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}☁️  Copying backup to $remote_host...${NC}"
    
    rsync -avz --progress "$backup_file" "$remote_host:$remote_path/"
    
    echo -e "${GREEN}✅ Backup copied to remote server${NC}"
}
EOF

# System Commands
cat > /usr/local/lib/easyinstall/monitor/system.sh <<'EOF'
#!/bin/bash

# ============================================
# System Monitoring Commands
# ============================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# System status
system_status() {
    echo -e "${GREEN}📊 System Status${NC}"
    echo "----------------------------------------"
    
    # CPU
    echo -e "${YELLOW}CPU:${NC}"
    top -bn1 | grep "Cpu(s)" | awk '{print "  Usage: " $2 "%"}'
    echo -e "  Load: $(uptime | awk -F'load average:' '{print $2}')"
    
    # Memory
    echo -e "\n${YELLOW}Memory:${NC}"
    free -h | awk '/^Mem:/ {print "  Total: " $2 "\n  Used: " $3 "\n  Free: " $4}'
    
    # Disk
    echo -e "\n${YELLOW}Disk:${NC}"
    df -h / | awk 'NR==2 {print "  Total: " $2 "\n  Used: " $3 "\n  Available: " $4 "\n  Use%: " $5}'
    
    # Services
    echo -e "\n${YELLOW}Services:${NC}"
    for service in nginx mysql mariadb redis-server php*-fpm; do
        if systemctl is-active --quiet $service 2>/dev/null; then
            echo -e "  ${GREEN}✅ $service${NC}"
        else
            echo -e "  ${RED}❌ $service${NC}"
        fi
    done
    
    # Network
    echo -e "\n${YELLOW}Network:${NC}"
    echo -e "  IP: $(hostname -I | awk '{print $1}')"
    echo -e "  Hostname: $(hostname)"
    
    # Uptime
    echo -e "\n${YELLOW}Uptime:${NC}"
    echo -e "  $(uptime -p)"
}

# System info
system_info() {
    echo -e "${GREEN}ℹ️ System Information${NC}"
    echo "----------------------------------------"
    
    # OS Info
    echo -e "${YELLOW}OS:${NC}"
    cat /etc/os-release | grep -E "^(NAME|VERSION)=" | sed 's/NAME=/  Name: /' | sed 's/VERSION=/  Version: /'
    
    # Kernel
    echo -e "\n${YELLOW}Kernel:${NC}"
    echo -e "  $(uname -r)"
    
    # CPU Info
    echo -e "\n${YELLOW}CPU:${NC}"
    echo -e "  Model: $(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^ //')"
    echo -e "  Cores: $(nproc)"
    
    # Memory Info
    echo -e "\n${YELLOW}Memory:${NC}"
    echo -e "  Total: $(free -h | awk '/^Mem:/ {print $2}')"
    
    # Disk Info
    echo -e "\n${YELLOW}Disk:${NC}"
    df -h | grep -E "^/dev/" | awk '{print "  " $1 ": " $2 " (" $5 " used)"}'
    
    # Installed Packages
    echo -e "\n${YELLOW}Installed Packages:${NC}"
    echo -e "  $(dpkg -l | grep -c "^ii") packages installed"
}

# Process list
process_list() {
    echo -e "${GREEN}📋 Running Processes${NC}"
    echo "----------------------------------------"
    ps aux --sort=-%cpu | head -20
}

# Service management
service_control() {
    local action=$1
    local service=$2
    
    case "$action" in
        start|stop|restart|status)
            echo -e "${YELLOW}📌 $action $service...${NC}"
            systemctl "$action" "$service"
            ;;
        enable|disable)
            echo -e "${YELLOW}📌 $action $service...${NC}"
            systemctl "$action" "$service"
            ;;
        *)
            echo -e "${RED}❌ Invalid action${NC}"
            return 1
            ;;
    esac
}

# Log viewer
view_logs() {
    local service=$1
    local lines=${2:-50}
    
    case "$service" in
        nginx)
            tail -n "$lines" /var/log/nginx/error.log
            ;;
        php)
            tail -n "$lines" /var/log/php*-fpm.log 2>/dev/null || echo "No PHP logs found"
            ;;
        mysql|mariadb)
            tail -n "$lines" /var/log/mysql/error.log 2>/dev/null || echo "No MySQL logs found"
            ;;
        system)
            journalctl -n "$lines"
            ;;
        *)
            tail -n "$lines" /var/log/syslog
            ;;
    esac
}
EOF

# Cloud Commands
cat > /usr/local/lib/easyinstall/cloud/cloud.sh <<'EOF'
#!/bin/bash

# ============================================
# Cloud Storage Commands
# ============================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

CLOUD_CONFIG="/etc/easyinstall/cloud.conf"

# Configure S3
configure_s3() {
    local access_key=$1
    local secret_key=$2
    local region=${3:-us-east-1}
    local bucket=${4:-easyinstall-backups}
    
    echo -e "${YELLOW}☁️ Configuring AWS S3...${NC}"
    
    mkdir -p ~/.aws
    cat > ~/.aws/credentials <<AWS
[default]
aws_access_key_id = $access_key
aws_secret_access_key = $secret_key
AWS
    
    cat > ~/.aws/config <<AWS
[default]
region = $region
output = json
AWS
    
    # Test configuration
    if aws s3 ls "s3://$bucket" 2>/dev/null; then
        echo -e "${GREEN}✅ S3 configured successfully${NC}"
        
        # Save config
        cat > "$CLOUD_CONFIG" <<CONF
S3_ACCESS_KEY=$access_key
S3_SECRET_KEY=$secret_key
S3_REGION=$region
S3_BUCKET=$bucket
CONF
    else
        # Try to create bucket
        if aws s3 mb "s3://$bucket" --region "$region" 2>/dev/null; then
            echo -e "${GREEN}✅ Bucket created and S3 configured${NC}"
            
            cat > "$CLOUD_CONFIG" <<CONF
S3_ACCESS_KEY=$access_key
S3_SECRET_KEY=$secret_key
S3_REGION=$region
S3_BUCKET=$bucket
CONF
        else
            echo -e "${RED}❌ Failed to configure S3${NC}"
        fi
    fi
}

# Upload to S3
upload_to_s3() {
    local file=$1
    local bucket=${2:-$(grep S3_BUCKET "$CLOUD_CONFIG" 2>/dev/null | cut -d= -f2)}
    
    if [ ! -f "$file" ]; then
        echo -e "${RED}❌ File not found${NC}"
        return 1
    fi
    
    if [ -z "$bucket" ]; then
        echo -e "${RED}❌ S3 not configured${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}☁️ Uploading to S3: $file${NC}"
    
    aws s3 cp "$file" "s3://$bucket/$(basename "$file")"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Uploaded successfully${NC}"
        echo -e "URL: https://$bucket.s3.amazonaws.com/$(basename "$file")"
    else
        echo -e "${RED}❌ Upload failed${NC}"
    fi
}

# Download from S3
download_from_s3() {
    local file=$1
    local bucket=${2:-$(grep S3_BUCKET "$CLOUD_CONFIG" 2>/dev/null | cut -d= -f2)}
    
    if [ -z "$bucket" ]; then
        echo -e "${RED}❌ S3 not configured${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}☁️ Downloading from S3: $file${NC}"
    
    aws s3 cp "s3://$bucket/$file" ./
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Downloaded successfully${NC}"
    else
        echo -e "${RED}❌ Download failed${NC}"
    fi
}

# List S3 files
list_s3_files() {
    local bucket=${1:-$(grep S3_BUCKET "$CLOUD_CONFIG" 2>/dev/null | cut -d= -f2)}
    
    if [ -z "$bucket" ]; then
        echo -e "${RED}❌ S3 not configured${NC}"
        return 1
    fi
    
    echo -e "${GREEN}📋 Files in S3 bucket: $bucket${NC}"
    echo "----------------------------------------"
    
    aws s3 ls "s3://$bucket/" --human-readable --summarize
}
EOF

# Security Commands
cat > /usr/local/lib/easyinstall/security/security.sh <<'EOF'
#!/bin/bash

# ============================================
# Security Commands
# ============================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Configure firewall
configure_firewall() {
    echo -e "${YELLOW}🛡️ Configuring firewall...${NC}"
    
    # Reset UFW
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH
    ufw allow ssh
    
    # Allow HTTP/HTTPS
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Allow WebUI
    ufw allow 5000/tcp
    
    # Enable UFW
    echo "y" | ufw enable
    
    echo -e "${GREEN}✅ Firewall configured${NC}"
    ufw status verbose
}

# Configure fail2ban
configure_fail2ban() {
    echo -e "${YELLOW}🚫 Configuring fail2ban...${NC}"
    
    cat > /etc/fail2ban/jail.local <<FAIL2BAN
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[nginx-botsearch]
enabled = true
filter = nginx-botsearch
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2

[php-url-fopen]
enabled = true
filter = php-url-fopen
port = http,https
logpath = /var/log/nginx/access.log
FAIL2BAN
    
    systemctl restart fail2ban
    echo -e "${GREEN}✅ fail2ban configured${NC}"
    fail2ban-client status
}

# Security scan
security_scan() {
    echo -e "${YELLOW}🔍 Running security scan...${NC}"
    echo "----------------------------------------"
    
    # Check for root login
    echo -e "\n${GREEN}Root Login:${NC}"
    if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
        echo -e "  ${RED}❌ Root login enabled (not recommended)${NC}"
    else
        echo -e "  ${GREEN}✅ Root login disabled${NC}"
    fi
    
    # Check for password authentication
    echo -e "\n${GREEN}Password Authentication:${NC}"
    if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config; then
        echo -e "  ${RED}❌ Password authentication enabled${NC}"
    else
        echo -e "  ${GREEN}✅ Password authentication disabled${NC}"
    fi
    
    # Check firewall status
    echo -e "\n${GREEN}Firewall:${NC}"
    if ufw status | grep -q "Status: active"; then
        echo -e "  ${GREEN}✅ Firewall active${NC}"
    else
        echo -e "  ${RED}❌ Firewall inactive${NC}"
    fi
    
    # Check fail2ban
    echo -e "\n${GREEN}fail2ban:${NC}"
    if systemctl is-active --quiet fail2ban; then
        echo -e "  ${GREEN}✅ fail2ban running${NC}"
    else
        echo -e "  ${RED}❌ fail2ban not running${NC}"
    fi
    
    # Check for updates
    echo -e "\n${GREEN}System Updates:${NC}"
    updates=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
    if [ "$updates" -gt 0 ]; then
        echo -e "  ${YELLOW}⚠️ $updates updates available${NC}"
    else
        echo -e "  ${GREEN}✅ System up to date${NC}"
    fi
    
    # Check for open ports
    echo -e "\n${GREEN}Open Ports:${NC}"
    netstat -tulpn | grep LISTEN | grep -E ":(80|443|22|5000)" | awk '{print "  " $4}'
}

# Change passwords
change_passwords() {
    echo -e "${YELLOW}🔑 Changing passwords...${NC}"
    
    # Change root password
    echo -e "\n${GREEN}Changing root password:${NC}"
    passwd root
    
    # Change MySQL root password
    echo -e "\n${GREEN}Changing MySQL root password:${NC}"
    mysqladmin -u root password
    
    # Generate new WordPress salts
    echo -e "\n${GREEN}Generating new WordPress salts...${NC}"
    for site in /var/www/html/*/wp-config.php; do
        if [ -f "$site" ]; then
            domain=$(basename $(dirname "$site"))
            echo -e "  Updating salts for $domain"
            
            # Download new salts
            salts=$(curl -s https://api.wordpress.org/secret-key/1.1/salt/)
            
            # Backup original
            cp "$site" "$site.bak"
            
            # Replace salts
            sed -i "/AUTH_KEY/d" "$site"
            sed -i "/SECURE_AUTH_KEY/d" "$site"
            sed -i "/LOGGED_IN_KEY/d" "$site"
            sed -i "/NONCE_KEY/d" "$site"
            sed -i "/AUTH_SALT/d" "$site"
            sed -i "/SECURE_AUTH_SALT/d" "$site"
            sed -i "/LOGGED_IN_SALT/d" "$site"
            sed -i "/NONCE_SALT/d" "$site"
            
            # Insert new salts before "That's all"
            sed -i "/That's all/i $salts" "$site"
        fi
    done
    
    echo -e "${GREEN}✅ Passwords updated${NC}"
}
EOF

# Tool Commands
cat > /usr/local/lib/easyinstall/tools/tools.sh <<'EOF'
#!/bin/bash

# ============================================
# Utility Tools Commands
# ============================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Generate password
generate_password() {
    local length=${1:-16}
    
    openssl rand -base64 "$length" | tr -d "=+/" | cut -c1-"$length"
    echo ""
}

# Test server speed
test_speed() {
    echo -e "${YELLOW}🚀 Testing server speed...${NC}"
    
    # Download speed
    echo -e "\n${GREEN}Download Speed:${NC}"
    curl -o /dev/null http://speedtest.tele2.net/100MB.zip 2>&1 | grep -o "[0-9.]* [KM]B/s"
    
    # Upload speed (using small file)
    echo -e "\n${GREEN}Upload Speed:${NC}"
    dd if=/dev/zero of=/tmp/test bs=1M count=10 2>/dev/null
    curl -F "file=@/tmp/test" https://file.io 2>&1 | grep -o "[0-9.]* [KM]B/s" || echo "  Could not test upload"
    rm -f /tmp/test
    
    # Ping
    echo -e "\n${GREEN}Ping:${NC}"
    ping -c 4 google.com | tail -1 | awk '{print $4}'
}

# DNS lookup
dns_lookup() {
    local domain=$1
    
    echo -e "${YELLOW}🔍 DNS lookup for $domain${NC}"
    echo "----------------------------------------"
    
    echo -e "\n${GREEN}A Records:${NC}"
    dig "$domain" A +short
    
    echo -e "\n${GREEN}MX Records:${NC}"
    dig "$domain" MX +short
    
    echo -e "\n${GREEN}NS Records:${NC}"
    dig "$domain" NS +short
    
    echo -e "\n${GREEN}TXT Records:${NC}"
    dig "$domain" TXT +short
    
    echo -e "\n${GREEN}WHOIS Information:${NC}"
    whois "$domain" | grep -E "Registry Domain ID|Registrar:|Creation Date|Expiry Date" | head -5
}

# SSL test
ssl_test() {
    local domain=$1
    
    echo -e "${YELLOW}🔐 SSL Test for $domain${NC}"
    echo "----------------------------------------"
    
    echo | openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null | openssl x509 -noout -text | grep -E "Subject:|Issuer:|Not Before:|Not After :"
}

# Check memory usage
check_memory() {
    echo -e "${YELLOW}📊 Memory Usage by Process:${NC}"
    echo "----------------------------------------"
    ps aux --sort=-%mem | head -10 | awk '{printf "%-10s %-10s %-5s %-5s %s\n", $1, $2, $3, $4, $11}'
}

# Check CPU usage
check_cpu() {
    echo -e "${YELLOW}📊 CPU Usage by Process:${NC}"
    echo "----------------------------------------"
    ps aux --sort=-%cpu | head -10 | awk '{printf "%-10s %-10s %-5s %-5s %s\n", $1, $2, $3, $4, $11}'
}

# Find large files
find_large_files() {
    local size=${1:-100M}
    
    echo -e "${YELLOW}🔍 Finding files larger than $size:${NC}"
    echo "----------------------------------------"
    find / -type f -size +"$size" -exec ls -lh {} \; 2>/dev/null | awk '{print $5 " " $9}' | sort -rh | head -20
}

# Analyze disk usage
disk_usage() {
    local path=${1:-/}
    
    echo -e "${YELLOW}📊 Disk Usage Analysis: $path${NC}"
    echo "----------------------------------------"
    du -sh "$path"/* 2>/dev/null | sort -rh | head -20
}

# Monitor bandwidth
monitor_bandwidth() {
    local interface=${1:-eth0}
    
    echo -e "${YELLOW}📊 Bandwidth Monitor ($interface)${NC}"
    echo "Press Ctrl+C to stop"
    echo "----------------------------------------"
    
    while true; do
        rx1=$(cat /sys/class/net/$interface/statistics/rx_bytes)
        tx1=$(cat /sys/class/net/$interface/statistics/tx_bytes)
        sleep 1
        rx2=$(cat /sys/class/net/$interface/statistics/rx_bytes)
        tx2=$(cat /sys/class/net/$interface/statistics/tx_bytes)
        
        rx_speed=$(( ($rx2 - $rx1) / 1024 ))
        tx_speed=$(( ($tx2 - $tx1) / 1024 ))
        
        echo -e "\r📥 Download: ${rx_speed} KB/s | 📤 Upload: ${tx_speed} KB/s"
    done
}

# Check website status
check_website() {
    local url=$1
    
    echo -e "${YELLOW}🌐 Checking website: $url${NC}"
    echo "----------------------------------------"
    
    # HTTP status
    status=$(curl -o /dev/null -s -w "%{http_code}" "http://$url")
    echo -e "HTTP: $([ "$status" = "200" ] && echo "${GREEN}$status${NC}" || echo "${RED}$status${NC}")"
    
    # HTTPS status
    if [ "$status" = "200" ]; then
        https_status=$(curl -o /dev/null -s -w "%{http_code}" "https://$url" 2>/dev/null || echo "Failed")
        echo -e "HTTPS: $([ "$https_status" = "200" ] && echo "${GREEN}$https_status${NC}" || echo "${RED}$https_status${NC}")"
    fi
    
    # Response time
    time=$(curl -o /dev/null -s -w "Connect: %{time_connect}s\nTTFB: %{time_starttransfer}s\nTotal: %{time_total}s\n" "http://$url")
    echo -e "\n$time"
}

# Create system alias
create_alias() {
    local alias_name=$1
    local command=$2
    
    echo "alias $alias_name='$command'" >> ~/.bashrc
    echo -e "${GREEN}✅ Alias created: $alias_name${NC}"
    echo "Run 'source ~/.bashrc' to apply"
}
EOF

# WebUI Commands
cat > /usr/local/lib/easyinstall/webui/webui.sh <<'EOF'
#!/bin/bash

# ============================================
# WebUI Management Commands
# ============================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

WEBUI_SERVICE="easyinstall-webui"
WEBUI_PORT="5000"
WEBUI_DIR="/opt/easyinstall-webui"

# Check WebUI status
webui_status() {
    if systemctl is-active --quiet "$WEBUI_SERVICE"; then
        echo -e "${GREEN}✅ WebUI is running${NC}"
        echo -e "   URL: https://$(hostname -I | awk '{print $1}')"
        
        # Get process info
        pid=$(systemctl show -p MainPID "$WEBUI_SERVICE" | cut -d= -f2)
        if [ "$pid" -gt 0 ]; then
            cpu=$(ps -p "$pid" -o %cpu | tail -1 | tr -d ' ')
            mem=$(ps -p "$pid" -o %mem | tail -1 | tr -d ' ')
            echo -e "   PID: $pid | CPU: $cpu% | MEM: $mem%"
        fi
    else
        echo -e "${RED}❌ WebUI is not running${NC}"
    fi
}

# Start WebUI
webui_start() {
    echo -e "${YELLOW}🚀 Starting WebUI...${NC}"
    systemctl start "$WEBUI_SERVICE"
    sleep 2
    webui_status
}

# Stop WebUI
webui_stop() {
    echo -e "${YELLOW}🛑 Stopping WebUI...${NC}"
    systemctl stop "$WEBUI_SERVICE"
    webui_status
}

# Restart WebUI
webui_restart() {
    echo -e "${YELLOW}🔄 Restarting WebUI...${NC}"
    systemctl restart "$WEBUI_SERVICE"
    sleep 2
    webui_status
}

# Show WebUI logs
webui_logs() {
    local lines=${1:-50}
    echo -e "${YELLOW}📋 WebUI Logs (last $lines lines):${NC}"
    echo "----------------------------------------"
    journalctl -u "$WEBUI_SERVICE" -n "$lines" --no-pager
}

# Follow WebUI logs
webui_logs_follow() {
    echo -e "${YELLOW}📋 Following WebUI logs (Ctrl+C to stop):${NC}"
    echo "----------------------------------------"
    journalctl -u "$WEBUI_SERVICE" -f
}

# Show WebUI URL
webui_url() {
    local ip=$(hostname -I | awk '{print $1}')
    echo -e "${GREEN}🌐 WebUI URL: https://$ip${NC}"
    
    if [ -f "/var/lib/easyinstall/webui/admin_credentials.txt" ]; then
        echo -e "${YELLOW}Default credentials:${NC}"
        cat "/var/lib/easyinstall/webui/admin_credentials.txt"
    fi
}

# Get WebUI admin password
webui_password() {
    if [ -f "/var/lib/easyinstall/webui/admin_credentials.txt" ]; then
        echo -e "${GREEN}🔑 Admin Credentials:${NC}"
        cat "/var/lib/easyinstall/webui/admin_credentials.txt"
    else
        echo -e "${RED}❌ Credentials file not found${NC}"
    fi
}

# Test WebUI connection
webui_test() {
    local ip=$(hostname -I | awk '{print $1}')
    
    echo -e "${YELLOW}🔍 Testing WebUI connection...${NC}"
    
    # Test local connection
    if curl -s -o /dev/null -w "%{http_code}" "http://localhost:$WEBUI_PORT" | grep -q "200"; then
        echo -e "${GREEN}✅ Local connection successful${NC}"
    else
        echo -e "${RED}❌ Local connection failed${NC}"
    fi
    
    # Test HTTPS connection
    if curl -k -s -o /dev/null -w "%{http_code}" "https://$ip" | grep -q "200\|302"; then
        echo -e "${GREEN}✅ HTTPS connection successful${NC}"
    else
        echo -e "${RED}❌ HTTPS connection failed${NC}"
    fi
    
    # Check if port is listening
    if netstat -tulpn | grep -q ":$WEBUI_PORT"; then
        echo -e "${GREEN}✅ Port $WEBUI_PORT is listening${NC}"
    else
        echo -e "${RED}❌ Port $WEBUI_PORT is not listening${NC}"
    fi
}

# Backup WebUI configuration
webui_backup() {
    local backup_dir="/var/lib/easyinstall/backups/webui"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    mkdir -p "$backup_dir"
    
    echo -e "${YELLOW}💾 Backing up WebUI configuration...${NC}"
    
    # Backup database
    if [ -f "/var/lib/easyinstall/webui/users.db" ]; then
        cp "/var/lib/easyinstall/webui/users.db" "$backup_dir/users_$timestamp.db"
        echo -e "  ✅ Database backed up"
    fi
    
    # Backup configs
    if [ -d "/etc/easyinstall/webui" ]; then
        tar -czf "$backup_dir/configs_$timestamp.tar.gz" -C /etc/easyinstall webui/
        echo -e "  ✅ Configs backed up"
    fi
    
    # Backup credentials
    if [ -f "/var/lib/easyinstall/webui/admin_credentials.txt" ]; then
        cp "/var/lib/easyinstall/webui/admin_credentials.txt" "$backup_dir/credentials_$timestamp.txt"
        echo -e "  ✅ Credentials backed up"
    fi
    
    echo -e "${GREEN}✅ WebUI backup completed: $backup_dir${NC}"
}

# Restore WebUI configuration
webui_restore() {
    local backup_file=$1
    
    if [ ! -f "$backup_file" ]; then
        echo -e "${RED}❌ Backup file not found${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}🔄 Restoring WebUI configuration...${NC}"
    
    # Stop WebUI
    webui_stop
    
    # Restore database
    if [[ "$backup_file" == *users_*.db ]]; then
        cp "$backup_file" "/var/lib/easyinstall/webui/users.db"
        echo -e "  ✅ Database restored"
    fi
    
    # Restore configs
    if [[ "$backup_file" == *configs_*.tar.gz ]]; then
        tar -xzf "$backup_file" -C /
        echo -e "  ✅ Configs restored"
    fi
    
    # Start WebUI
    webui_start
    
    echo -e "${GREEN}✅ WebUI restored${NC}"
}

# WebUI help
webui_help() {
    echo -e "${GREEN}🌐 WebUI Management Commands${NC}"
    echo "----------------------------------------"
    echo -e "  ${YELLOW}webui status${NC}         - Check WebUI status"
    echo -e "  ${YELLOW}webui start${NC}          - Start WebUI"
    echo -e "  ${YELLOW}webui stop${NC}           - Stop WebUI"
    echo -e "  ${YELLOW}webui restart${NC}        - Restart WebUI"
    echo -e "  ${YELLOW}webui logs${NC} [lines]    - View WebUI logs"
    echo -e "  ${YELLOW}webui follow${NC}         - Follow WebUI logs"
    echo -e "  ${YELLOW}webui url${NC}            - Show WebUI URL"
    echo -e "  ${YELLOW}webui password${NC}       - Show admin password"
    echo -e "  ${YELLOW}webui test${NC}           - Test WebUI connection"
    echo -e "  ${YELLOW}webui backup${NC}         - Backup WebUI config"
}
EOF

# ============================================
# Step 5: Create Main Wrapper Script
# ============================================
cat > /usr/local/bin/easyinstall <<'EOF'
#!/bin/bash

# ============================================
# EasyInstall - Complete Enterprise Stack Manager
# ============================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Source all command modules
for module in /usr/local/lib/easyinstall/*/*.sh; do
    if [ -f "$module" ]; then
        source "$module"
    fi
done

# Show help
show_help() {
    echo -e "${GREEN}🚀 EasyInstall - Complete Enterprise Stack Manager${NC}"
    echo ""
    echo -e "${YELLOW}Core Commands:${NC}"
    echo "  domain, domains                - List all domains"
    echo "  domain create <domain> [--ssl] - Create WordPress site"
    echo "  domain php <domain> [--ssl]    - Create PHP site"
    echo "  domain html <domain> [--ssl]   - Create HTML site"
    echo "  domain delete <domain>         - Delete domain"
    echo "  domain info <domain>            - Show domain info"
    echo "  domain ssl <domain>             - Enable SSL for domain"
    echo ""
    echo -e "${YELLOW}WordPress Commands:${NC}"
    echo "  wp <domain> <command>          - Run WP-CLI command"
    echo "  wp update <domain>              - Update WordPress"
    echo "  wp backup <domain>               - Backup WordPress"
    echo "  wp restore <domain> <file>      - Restore WordPress"
    echo ""
    echo -e "${YELLOW}Database Commands:${NC}"
    echo "  db list                         - List databases"
    echo "  db create <name> [user] [pass] - Create database"
    echo "  db backup <name>                - Backup database"
    echo "  db restore <name> <file>        - Restore database"
    echo "  db import <name> <file>         - Import SQL file"
    echo "  db export <name> [file]         - Export database"
    echo "  db console [name]               - MySQL console"
    echo "  db size <name>                  - Show database size"
    echo "  db optimize <name>               - Optimize database"
    echo ""
    echo -e "${YELLOW}Backup Commands:${NC}"
    echo "  backup create [name]            - Create full backup"
    echo "  backup list                      - List backups"
    echo "  backup restore <file>            - Restore backup"
    echo "  backup schedule [daily|weekly]   - Schedule backups"
    echo "  backup remote <host> <path>      - Copy backup to remote"
    echo ""
    echo -e "${YELLOW}Cloud Commands:${NC}"
    echo "  cloud s3 <key> <secret> [region] - Configure S3"
    echo "  cloud upload <file> [bucket]     - Upload to S3"
    echo "  cloud download <file> [bucket]   - Download from S3"
    echo "  cloud ls [bucket]                 - List S3 files"
    echo ""
    echo -e "${YELLOW}Security Commands:${NC}"
    echo "  security firewall                - Configure firewall"
    echo "  security fail2ban                - Configure fail2ban"
    echo "  security scan                    - Run security scan"
    echo "  security passwords               - Change passwords"
    echo "  ssl enable <domain>              - Enable SSL"
    echo "  ssl renew                        - Renew SSL certs"
    echo "  ssl check [domain]               - Check SSL expiry"
    echo "  ssl self <domain>                 - Create self-signed cert"
    echo ""
    echo -e "${YELLOW}System Commands:${NC}"
    echo "  status                          - System status"
    echo "  info                            - System information"
    echo "  processes                        - List processes"
    echo "  service <start|stop|restart> <name> - Control service"
    echo "  logs [service] [lines]           - View logs"
    echo ""
    echo -e "${YELLOW}Tool Commands:${NC}"
    echo "  password [length]                - Generate password"
    echo "  speedtest                        - Test server speed"
    echo "  dns <domain>                     - DNS lookup"
    echo "  ssltest <domain>                  - Test SSL certificate"
    echo "  memory                           - Show memory usage"
    echo "  cpu                              - Show CPU usage"
    echo "  large [size]                      - Find large files"
    echo "  du [path]                         - Disk usage analysis"
    echo "  bandwidth [interface]             - Monitor bandwidth"
    echo "  website <url>                     - Check website status"
    echo "  alias <name> <command>            - Create alias"
    echo ""
    echo -e "${YELLOW}WebUI Commands:${NC}"
    echo "  webui status                     - Check WebUI status"
    echo "  webui start                      - Start WebUI"
    echo "  webui stop                       - Stop WebUI"
    echo "  webui restart                    - Restart WebUI"
    echo "  webui logs [lines]                - View WebUI logs"
    echo "  webui follow                      - Follow WebUI logs"
    echo "  webui url                         - Show WebUI URL"
    echo "  webui password                    - Show admin password"
    echo "  webui test                        - Test WebUI connection"
    echo "  webui backup                      - Backup WebUI config"
    echo ""
    echo -e "${YELLOW}Help:${NC}"
    echo "  help, --help, -h                 - Show this help"
    echo ""
}

# Main command parser
case "$1" in
    # Domain commands
    domain|domains)
        if [ "$1" = "domains" ] || [ -z "$2" ]; then
            list_domains
        else
            case "$2" in
                create) install_wordpress "$3" "$4" "$5" ;;
                php) create_php_site "$3" "$4" "$5" ;;
                html) create_html_site "$3" "$4" ;;
                delete) delete_domain "$3" ;;
                info) domain_info "$3" ;;
                ssl) enable_ssl "$3" ;;
                *) echo -e "${RED}Unknown command${NC}" ;;
            esac
        fi
        ;;
    
    # WordPress commands
    wp)
        if [ -z "$2" ]; then
            echo -e "${RED}Usage: wp <domain> <command>${NC}"
        else
            wp_command "$2" "${@:3}"
        fi
        ;;
    wp-update) update_wordpress "$2" ;;
    wp-backup) backup_wordpress "$2" ;;
    wp-restore) restore_wordpress "$2" "$3" ;;
    
    # Database commands
    db)
        case "$2" in
            list) list_databases ;;
            create) create_database "$3" "$4" "$5" ;;
            backup) backup_database "$3" ;;
            restore) restore_database "$3" "$4" ;;
            import) import_database "$3" "$4" ;;
            export) export_database "$3" "$4" ;;
            console) mysql_console "$3" ;;
            size) database_size "$3" ;;
            optimize) optimize_database "$3" ;;
            *) echo -e "${RED}Unknown database command${NC}" ;;
        esac
        ;;
    
    # Backup commands
    backup)
        case "$2" in
            create) create_backup "$3" ;;
            list) list_backups ;;
            restore) restore_backup "$3" ;;
            schedule) schedule_backup "$3" "$4" ;;
            remote) remote_backup "$3" "$4" "$5" ;;
            *) echo -e "${RED}Unknown backup command${NC}" ;;
        esac
        ;;
    
    # Cloud commands
    cloud)
        case "$2" in
            s3) configure_s3 "$3" "$4" "$5" "$6" ;;
            upload) upload_to_s3 "$3" "$4" ;;
            download) download_from_s3 "$3" "$4" ;;
            ls) list_s3_files "$3" ;;
            *) echo -e "${RED}Unknown cloud command${NC}" ;;
        esac
        ;;
    
    # Security commands
    security)
        case "$2" in
            firewall) configure_firewall ;;
            fail2ban) configure_fail2ban ;;
            scan) security_scan ;;
            passwords) change_passwords ;;
            *) echo -e "${RED}Unknown security command${NC}" ;;
        esac
        ;;
    
    # SSL commands
    ssl)
        case "$2" in
            enable) enable_ssl "$3" "$4" ;;
            renew) renew_ssl ;;
            check) check_ssl_expiry "$3" ;;
            self) create_self_signed "$3" ;;
            *) echo -e "${RED}Unknown SSL command${NC}" ;;
        esac
        ;;
    
    # System commands
    status) system_status ;;
    info) system_info ;;
    processes) process_list ;;
    service) service_control "$2" "$3" ;;
    logs) view_logs "$2" "$3" ;;
    
    # Tool commands
    password) generate_password "$2" ;;
    speedtest) test_speed ;;
    dns) dns_lookup "$2" ;;
    ssltest) ssl_test "$2" ;;
    memory) check_memory ;;
    cpu) check_cpu ;;
    large) find_large_files "$2" ;;
    du) disk_usage "$2" ;;
    bandwidth) monitor_bandwidth "$2" ;;
    website) check_website "$2" ;;
    alias) create_alias "$2" "$3" ;;
    
    # WebUI commands
    webui)
        case "$2" in
            status) webui_status ;;
            start) webui_start ;;
            stop) webui_stop ;;
            restart) webui_restart ;;
            logs) webui_logs "$3" ;;
            follow) webui_logs_follow ;;
            url) webui_url ;;
            password) webui_password ;;
            test) webui_test ;;
            backup) webui_backup ;;
            restore) webui_restore "$3" ;;
            help) webui_help ;;
            *) webui_help ;;
        esac
        ;;
    
    # Help
    help|--help|-h)
        show_help
        ;;
    
    # Default - show help
    *)
        show_help
        ;;
esac
EOF

chmod +x /usr/local/bin/easyinstall

# ============================================
# Step 6: Install WebUI Application
# ============================================
echo -e "${YELLOW}🌐 Setting up WebUI...${NC}"

# Create WebUI directory structure
mkdir -p /opt/easyinstall-webui/{app,static,logs}
mkdir -p /opt/easyinstall-webui/app/templates

# Download WebUI files
WEBUI_BASE="https://raw.githubusercontent.com/sugan0927/easyinstall-worker./tree/main/integrations/webui"

# Download app.py
curl -fsSL "$WEBUI_BASE/app.py" -o /opt/easyinstall-webui/app/app.py

# Download HTML templates
curl -fsSL "$WEBUI_BASE/templates/login.html" -o /opt/easyinstall-webui/app/templates/login.html
curl -fsSL "$WEBUI_BASE/templates/dashboard.html" -o /opt/easyinstall-webui/app/templates/dashboard.html

# Create systemd service for WebUI
cat > /etc/systemd/system/easyinstall-webui.service <<'EOF'
[Unit]
Description=EasyInstall WebUI
After=network.target redis-server.service
Wants=redis-server.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/easyinstall-webui/app
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/usr/local/bin/gunicorn -w 4 -k eventlet -b 127.0.0.1:5000 --access-logfile /var/log/easyinstall/webui-access.log --error-logfile /var/log/easyinstall/webui-error.log app:app
Restart=always
RestartSec=10
StandardOutput=append:/var/log/easyinstall/webui.log
StandardError=append:/var/log/easyinstall/webui-error.log

[Install]
WantedBy=multi-user.target
EOF

# Create Nginx configuration
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

# Enable WebUI site
ln -sf /etc/nginx/sites-available/easyinstall-webui /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Create SSL certificate if not exists
if [ ! -f /etc/nginx/ssl/easyinstall.crt ]; then
    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/easyinstall.key \
        -out /etc/nginx/ssl/easyinstall.crt \
        -subj "/C=US/ST=State/L=City/O=EasyInstall/CN=localhost" 2>/dev/null
fi

# ============================================
# Step 7: Initialize Database
# ============================================
echo -e "${YELLOW}🗄️ Initializing database...${NC}"

# Initialize WebUI database
cd /opt/easyinstall-webui/app
python3 -c "
import sqlite3
import bcrypt
import secrets
from datetime import datetime

DB_PATH = '/var/lib/easyinstall/webui/users.db'

# Create directory
import os
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
except:
    pass

conn.close()
"

# ============================================
# Step 8: Start Services
# ============================================
echo -e "${YELLOW}🚀 Starting services...${NC}"

# Reload systemd
systemctl daemon-reload

# Enable and start Redis
systemctl enable redis-server
systemctl start redis-server

# Enable and start WebUI
systemctl enable easyinstall-webui
systemctl start easyinstall-webui

# Test and reload Nginx
nginx -t && systemctl reload nginx

# ============================================
# Step 9: Cleanup
# ============================================
rm -f /tmp/easyinstall-base.sh

# ============================================
# Step 10: Show Completion Message
# ============================================
IP_ADDRESS=$(hostname -I | awk '{print $1}')

# Get admin password
if [ -f "/var/lib/easyinstall/webui/admin_credentials.txt" ]; then
    ADMIN_PASS=$(grep "Password:" /var/lib/easyinstall/webui/admin_credentials.txt | cut -d' ' -f2)
else
    ADMIN_PASS="Check /var/lib/easyinstall/webui/admin_credentials.txt"
fi

clear
echo -e "${GREEN}"
figlet -f standard "EasyInstall" 2>/dev/null || echo "EasyInstall Complete Stack"
echo -e "${NC}"

echo -e "${GREEN}================================================"
echo "✅ Installation Complete!"
echo "================================================${NC}"
echo ""

echo -e "${BLUE}📊 WebUI Access:${NC}"
echo "   URL: https://$IP_ADDRESS"
echo "   Username: admin"
echo "   Password: $ADMIN_PASS"
echo ""

echo -e "${BLUE}📁 Credentials saved in:${NC}"
echo "   /var/lib/easyinstall/webui/admin_credentials.txt"
echo ""

echo -e "${YELLOW}🎯 Available Commands:${NC}"
echo ""

echo -e "${GREEN}Core Commands:${NC}"
echo "  easyinstall domain list                    - List all domains"
echo "  easyinstall domain create example.com --ssl - Create WordPress site"
echo "  easyinstall domain php example.com         - Create PHP site"
echo "  easyinstall domain html example.com        - Create HTML site"
echo "  easyinstall domain info example.com        - Show domain info"
echo "  easyinstall domain ssl example.com         - Enable SSL"
echo ""

echo -e "${GREEN}WordPress Commands:${NC}"
echo "  easyinstall wp example.com plugin list     - List plugins"
echo "  easyinstall wp example.com theme list      - List themes"
echo "  easyinstall wp example.com user list       - List users"
echo "  easyinstall wp-backup example.com          - Backup WordPress"
echo "  easyinstall wp-update example.com          - Update WordPress"
echo ""

echo -e "${GREEN}Database Commands:${NC}"
echo "  easyinstall db list                        - List databases"
echo "  easyinstall db create mydb myuser mypass   - Create database"
echo "  easyinstall db backup mydb                 - Backup database"
echo "  easyinstall db restore mydb backup.sql     - Restore database"
echo "  easyinstall db console                     - MySQL console"
echo ""

echo -e "${GREEN}Backup Commands:${NC}"
echo "  easyinstall backup create                   - Create full backup"
echo "  easyinstall backup list                      - List backups"
echo "  easyinstall backup restore backup.tar.gz     - Restore backup"
echo "  easyinstall backup schedule daily 02:00      - Schedule daily backup"
echo ""

echo -e "${GREEN}Cloud Commands:${NC}"
echo "  easyinstall cloud s3 KEY SECRET us-east-1   - Configure S3"
echo "  easyinstall cloud upload file.tar.gz         - Upload to S3"
echo "  easyinstall cloud ls                          - List S3 files"
echo ""

echo -e "${GREEN}Security Commands:${NC}"
echo "  easyinstall security firewall                - Configure firewall"
echo "  easyinstall security fail2ban                - Configure fail2ban"
echo "  easyinstall security scan                    - Run security scan"
echo "  easyinstall ssl check example.com            - Check SSL expiry"
echo "  easyinstall ssl renew                        - Renew all SSL certs"
echo ""

echo -e "${GREEN}System Commands:${NC}"
echo "  easyinstall status                           - System status"
echo "  easyinstall info                              - System information"
echo "  easyinstall service restart nginx             - Restart nginx"
echo "  easyinstall logs nginx 100                    - View nginx logs"
echo ""

echo -e "${GREEN}Tool Commands:${NC}"
echo "  easyinstall password 20                      - Generate password"
echo "  easyinstall speedtest                         - Test server speed"
echo "  easyinstall dns example.com                   - DNS lookup"
echo "  easyinstall website example.com               - Check website"
echo "  easyinstall bandwidth eth0                    - Monitor bandwidth"
echo ""

echo -e "${GREEN}WebUI Commands:${NC}"
echo "  easyinstall webui status                     - Check WebUI status"
echo "  easyinstall webui restart                     - Restart WebUI"
echo "  easyinstall webui logs                        - View WebUI logs"
echo "  easyinstall webui url                         - Show WebUI URL"
echo ""

echo -e "${YELLOW}📝 Quick Test:${NC}"
echo "  Run 'easyinstall status' to check system status"
echo "  Open https://$IP_ADDRESS in your browser"
echo ""

echo -e "${GREEN}Happy Hosting! 🚀${NC}"
