#!/bin/bash

# ============================================
# EasyInstall Docker WordPress Installer
# ============================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Docker WordPress Installation Function
docker_install_wordpress() {
    local DOMAIN=$1
    local USE_SSL=${2:-false}
    local DB_NAME="wordpress"
    local DB_USER="wpuser"
    local DB_PASS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c20)
    local ADMIN_EMAIL=${3:-"admin@$DOMAIN"}
    
    echo -e "${YELLOW}🐳 Installing WordPress in Docker for $DOMAIN...${NC}"
    
    # Check if domain already has Docker setup
    if [ -d "/opt/easyinstall/docker/$DOMAIN" ]; then
        echo -e "${RED}❌ Docker setup for $DOMAIN already exists${NC}"
        exit 1
    fi
    
    # Create directory structure
    mkdir -p "/opt/easyinstall/docker/$DOMAIN"/{data,logs,config}
    cd "/opt/easyinstall/docker/$DOMAIN"
    
    # Create docker-compose.yml
    cat > docker-compose.yml <<EOF
version: '3.8'

services:
  # MariaDB Database
  db:
    image: mariadb:10.11
    container_name: ${DOMAIN//./-}-db
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: ${DB_PASS}
      MYSQL_DATABASE: ${DB_NAME}
      MYSQL_USER: ${DB_USER}
      MYSQL_PASSWORD: ${DB_PASS}
    volumes:
      - ./data/db:/var/lib/mysql
      - ./logs/db:/var/log/mysql
    networks:
      - wordpress-network
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      timeout: 20s
      retries: 10

  # WordPress with PHP-FPM
  wordpress:
    image: wordpress:php8.2-fpm
    container_name: ${DOMAIN//./-}-wp
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
    environment:
      WORDPRESS_DB_HOST: db:3306
      WORDPRESS_DB_USER: ${DB_USER}
      WORDPRESS_DB_PASSWORD: ${DB_PASS}
      WORDPRESS_DB_NAME: ${DB_NAME}
      WORDPRESS_TABLE_PREFIX: wp_
      WORDPRESS_DEBUG: 0
      WORDPRESS_CONFIG_EXTRA: |
        define('WP_REDIS_HOST', 'redis');
        define('WP_REDIS_PORT', 6379);
        define('WP_CACHE', true);
        define('DISALLOW_FILE_EDIT', false);
        define('WP_MEMORY_LIMIT', '256M');
        define('WP_MAX_MEMORY_LIMIT', '512M');
    volumes:
      - ./data/wordpress:/var/www/html
      - ./config/php.ini:/usr/local/etc/php/conf.d/custom.ini
    networks:
      - wordpress-network

  # Nginx Web Server
  nginx:
    image: nginx:alpine
    container_name: ${DOMAIN//./-}-nginx
    restart: unless-stopped
    depends_on:
      - wordpress
    volumes:
      - ./data/wordpress:/var/www/html
      - ./config/nginx.conf:/etc/nginx/conf.d/default.conf
      - ./logs/nginx:/var/log/nginx
    ports:
      - "80:80"
      - "443:443"
    networks:
      - wordpress-network

  # Redis Cache
  redis:
    image: redis:7-alpine
    container_name: ${DOMAIN//./-}-redis
    restart: unless-stopped
    command: redis-server --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru
    volumes:
      - ./data/redis:/data
    networks:
      - wordpress-network

  # phpMyAdmin (Optional - remove in production)
  phpmyadmin:
    image: phpmyadmin/phpmyadmin
    container_name: ${DOMAIN//./-}-pma
    restart: unless-stopped
    depends_on:
      - db
    environment:
      PMA_HOST: db
      PMA_PORT: 3306
      PMA_USER: ${DB_USER}
      PMA_PASSWORD: ${DB_PASS}
      UPLOAD_LIMIT: 64M
    ports:
      - "8080:80"
    networks:
      - wordpress-network
    profiles:
      - dev

networks:
  wordpress-network:
    driver: bridge
EOF

    # Create nginx.conf
    cat > config/nginx.conf <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};
    root /var/www/html;
    index index.php index.html;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    client_max_body_size 64M;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript application/xml+rss application/atom+xml image/svg+xml text/javascript;

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \.php$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass wordpress:9000;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param PATH_INFO \$fastcgi_path_info;
        fastcgi_param HTTPS \$https if_not_empty;
        
        # Cache settings
        fastcgi_cache_bypass \$skip_cache;
        fastcgi_no_cache \$skip_cache;
        fastcgi_cache WORDPRESS;
        fastcgi_cache_valid 200 60m;
    }

    # Cache static files
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|woff|woff2|ttf|svg|eot)$ {
        expires 365d;
        add_header Cache-Control "public, immutable";
    }

    # Deny access to sensitive files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
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

    location ~ ^/(wp-config\.php|wp-config\.txt|readme\.html|license\.txt|wp-config-sample\.php) {
        deny all;
    }
}
EOF

    # Create php.ini
    cat > config/php.ini <<EOF
memory_limit = 256M
upload_max_filesize = 64M
post_max_size = 64M
max_execution_time = 300
max_input_time = 300
max_input_vars = 3000
date.timezone = UTC

; OPcache
opcache.enable = 1
opcache.memory_consumption = 128
opcache.interned_strings_buffer = 8
opcache.max_accelerated_files = 10000
opcache.revalidate_freq = 2
opcache.fast_shutdown = 1

; Error reporting
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log
EOF

    # Create .env file with credentials
    cat > .env <<EOF
DOMAIN=$DOMAIN
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
ADMIN_EMAIL=$ADMIN_EMAIL
EOF
    chmod 600 .env

    # Save credentials to file
    cat > credentials.txt <<EOF
====================================
WordPress Docker Installation
Domain: $DOMAIN
Date: $(date)
====================================

Database Information:
  Database: $DB_NAME
  Username: $DB_USER
  Password: $DB_PASS
  Host: db:3306

WordPress Information:
  URL: http://$DOMAIN
  Admin URL: http://$DOMAIN/wp-admin
  Theme/Plugin Editor: ENABLED

phpMyAdmin (Development Only):
  URL: http://$DOMAIN:8080
  Username: $DB_USER
  Password: $DB_PASS

Redis Cache:
  Host: redis
  Port: 6379

Docker Commands:
  Start:   docker-compose up -d
  Stop:    docker-compose down
  Logs:    docker-compose logs -f
  Status:  docker-compose ps
  Shell:   docker-compose exec wordpress bash

====================================
EOF
    chmod 600 credentials.txt

    # Create start/stop scripts
    cat > start.sh <<EOF
#!/bin/bash
cd "\$(dirname "\$0")"
docker-compose up -d
echo "✅ WordPress started at http://$DOMAIN"
EOF
    chmod +x start.sh

    cat > stop.sh <<EOF
#!/bin/bash
cd "\$(dirname "\$0")"
docker-compose down
echo "✅ WordPress stopped"
EOF
    chmod +x stop.sh

    cat > logs.sh <<EOF
#!/bin/bash
cd "\$(dirname "\$0")"
docker-compose logs -f
EOF
    chmod +x logs.sh

    # Start the containers
    echo -e "${YELLOW}🚀 Starting Docker containers...${NC}"
    docker-compose up -d

    # Wait for containers to be ready
    echo -e "${YELLOW}⏳ Waiting for WordPress to be ready...${NC}"
    sleep 10

    # Check if containers are running
    if docker-compose ps | grep -q "Up"; then
        echo -e "${GREEN}✅ Docker containers started successfully${NC}"
    else
        echo -e "${RED}❌ Failed to start containers. Check logs with: docker-compose logs${NC}"
        exit 1
    fi

    # Enable SSL if requested
    if [ "$USE_SSL" = "true" ]; then
        echo -e "${YELLOW}🔐 Setting up SSL with Traefik...${NC}"
        
        # Create traefik directory
        mkdir -p ../traefik
        
        # Create traefik docker-compose
        cat > ../traefik/docker-compose.yml <<EOF
version: '3.8'

services:
  traefik:
    image: traefik:v2.10
    container_name: traefik
    restart: unless-stopped
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.email=$ADMIN_EMAIL"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge=true"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "./letsencrypt:/letsencrypt"
    networks:
      - wordpress-network

networks:
  wordpress-network:
    external: true
EOF

        # Add Traefik labels to WordPress service
        cd "/opt/easyinstall/docker/$DOMAIN"
        
        # Update docker-compose.yml with Traefik labels
        cat >> docker-compose.yml <<EOF

  # Traefik for SSL (commented by default)
  # Uncomment below lines in nginx service for SSL
  # labels:
  #   - "traefik.enable=true"
  #   - "traefik.http.routers.${DOMAIN//./-}.rule=Host(\`$DOMAIN\`)"
  #   - "traefik.http.routers.${DOMAIN//./-}.entrypoints=websecure"
  #   - "traefik.http.routers.${DOMAIN//./-}.tls.certresolver=letsencrypt"
EOF

        echo -e "${YELLOW}📝 To enable SSL:${NC}"
        echo "  1. Start Traefik: cd ../traefik && docker-compose up -d"
        echo "  2. Uncomment Traefik labels in docker-compose.yml"
        echo "  3. Run: docker-compose up -d"
        echo "  4. Access: https://$DOMAIN"
    fi

    # Display information
    echo -e "${GREEN}"
    echo "============================================"
    echo "✅ WordPress Docker Installation Complete!"
    echo "============================================"
    echo ""
    echo -e "${CYAN}📊 Installation Details:${NC}"
    echo "  Domain: $DOMAIN"
    echo "  Path: /opt/easyinstall/docker/$DOMAIN"
    echo ""
    echo -e "${CYAN}🗄️  Database:${NC}"
    echo "  Database: $DB_NAME"
    echo "  Username: $DB_USER"
    echo "  Password: $DB_PASS"
    echo "  phpMyAdmin: http://$DOMAIN:8080 (dev only)"
    echo ""
    echo -e "${CYAN}🌐 WordPress:${NC}"
    echo "  URL: http://$DOMAIN"
    echo "  Admin: http://$DOMAIN/wp-admin"
    echo "  Theme/Plugin Editor: ENABLED"
    echo ""
    echo -e "${CYAN}🐳 Docker Commands:${NC}"
    echo "  Start:   cd /opt/easyinstall/docker/$DOMAIN && ./start.sh"
    echo "  Stop:    cd /opt/easyinstall/docker/$DOMAIN && ./stop.sh"
    echo "  Logs:    cd /opt/easyinstall/docker/$DOMAIN && ./logs.sh"
    echo "  Status:  cd /opt/easyinstall/docker/$DOMAIN && docker-compose ps"
    echo "  Shell:   cd /opt/easyinstall/docker/$DOMAIN && docker-compose exec wordpress bash"
    echo ""
    echo -e "${CYAN}🔒 SSL Setup (Optional):${NC}"
    echo "  cd /opt/easyinstall/docker/traefik && docker-compose up -d"
    echo "  Then uncomment Traefik labels in docker-compose.yml"
    echo "  Run: docker-compose up -d"
    echo ""
    echo -e "${GREEN}Credentials saved in: /opt/easyinstall/docker/$DOMAIN/credentials.txt${NC}"
    echo -e "${NC}"
}

# Docker WordPress Command Handler
docker_wordpress_command() {
    case "$1" in
        install)
            if [ -z "$2" ]; then
                echo -e "${RED}Usage: easyinstall docker wordpress install domain.com [--ssl]${NC}"
                exit 1
            fi
            DOMAIN=$2
            USE_SSL="false"
            if [ "$3" = "--ssl" ] || [ "$3" = "-ssl" ]; then
                USE_SSL="true"
            fi
            docker_install_wordpress "$DOMAIN" "$USE_SSL"
            ;;
        list)
            echo -e "${YELLOW}📋 Docker WordPress Installations:${NC}"
            if [ -d "/opt/easyinstall/docker" ]; then
                for dir in /opt/easyinstall/docker/*/; do
                    if [ -f "$dir/docker-compose.yml" ] && [ -f "$dir/credentials.txt" ]; then
                        DOMAIN=$(basename "$dir")
                        if grep -q "RUNNING" <<< "$(cd "$dir" && docker-compose ps 2>/dev/null | grep -c "Up")"; then
                            STATUS="${GREEN}Running${NC}"
                        else
                            STATUS="${RED}Stopped${NC}"
                        fi
                        echo "  🌐 $DOMAIN - $STATUS"
                    fi
                done
            else
                echo "  No Docker WordPress installations found"
            fi
            ;;
        status)
            if [ -z "$2" ]; then
                echo -e "${RED}Usage: easyinstall docker wordpress status domain.com${NC}"
                exit 1
            fi
            DOMAIN=$2
            if [ -d "/opt/easyinstall/docker/$DOMAIN" ]; then
                cd "/opt/easyinstall/docker/$DOMAIN"
                docker-compose ps
            else
                echo -e "${RED}❌ Installation not found: $DOMAIN${NC}"
            fi
            ;;
        logs)
            if [ -z "$2" ]; then
                echo -e "${RED}Usage: easyinstall docker wordpress logs domain.com [service]${NC}"
                exit 1
            fi
            DOMAIN=$2
            SERVICE=${3:-wordpress}
            if [ -d "/opt/easyinstall/docker/$DOMAIN" ]; then
                cd "/opt/easyinstall/docker/$DOMAIN"
                docker-compose logs -f "$SERVICE"
            else
                echo -e "${RED}❌ Installation not found: $DOMAIN${NC}"
            fi
            ;;
        stop)
            if [ -z "$2" ]; then
                echo -e "${RED}Usage: easyinstall docker wordpress stop domain.com${NC}"
                exit 1
            fi
            DOMAIN=$2
            if [ -d "/opt/easyinstall/docker/$DOMAIN" ]; then
                cd "/opt/easyinstall/docker/$DOMAIN"
                docker-compose down
                echo -e "${GREEN}✅ WordPress stopped: $DOMAIN${NC}"
            else
                echo -e "${RED}❌ Installation not found: $DOMAIN${NC}"
            fi
            ;;
        start)
            if [ -z "$2" ]; then
                echo -e "${RED}Usage: easyinstall docker wordpress start domain.com${NC}"
                exit 1
            fi
            DOMAIN=$2
            if [ -d "/opt/easyinstall/docker/$DOMAIN" ]; then
                cd "/opt/easyinstall/docker/$DOMAIN"
                docker-compose up -d
                echo -e "${GREEN}✅ WordPress started: $DOMAIN${NC}"
            else
                echo -e "${RED}❌ Installation not found: $DOMAIN${NC}"
            fi
            ;;
        delete)
            if [ -z "$2" ]; then
                echo -e "${RED}Usage: easyinstall docker wordpress delete domain.com${NC}"
                exit 1
            fi
            DOMAIN=$2
            if [ -d "/opt/easyinstall/docker/$DOMAIN" ]; then
                echo -e "${RED}⚠️  Are you sure you want to delete $DOMAIN? (y/n)${NC}"
                read -r CONFIRM
                if [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ]; then
                    cd "/opt/easyinstall/docker/$DOMAIN"
                    docker-compose down -v
                    cd ..
                    rm -rf "$DOMAIN"
                    echo -e "${GREEN}✅ WordPress installation deleted: $DOMAIN${NC}"
                fi
            else
                echo -e "${RED}❌ Installation not found: $DOMAIN${NC}"
            fi
            ;;
        help|*)
            echo "EasyInstall Docker WordPress Commands:"
            echo ""
            echo "Commands:"
            echo "  install domain.com [--ssl]  - Install WordPress in Docker"
            echo "  list                         - List all Docker WordPress installations"
            echo "  status domain.com             - Show container status"
            echo "  logs domain.com [service]     - View logs (services: wordpress, nginx, db, redis)"
            echo "  start domain.com              - Start WordPress"
            echo "  stop domain.com               - Stop WordPress"
            echo "  delete domain.com             - Delete WordPress installation"
            echo ""
            echo "Examples:"
            echo "  easyinstall docker wordpress install example.com"
            echo "  easyinstall docker wordpress install example.com --ssl"
            echo "  easyinstall docker wordpress logs example.com nginx"
            echo "  easyinstall docker wordpress list"
            ;;
    esac
}
