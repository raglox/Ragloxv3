#!/bin/bash

# ========================================
# RAGLOX Production Deployment Script
# Domain: raglox.com
# Date: 2026-01-08
# ========================================

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOMAIN="raglox.com"
API_DOMAIN="api.raglox.com"
WWW_DOMAIN="www.raglox.com"
EMAIL="admin@raglox.com"  # Change this to your email

BACKEND_PORT=8000
FRONTEND_PORT=3000

WORK_DIR="/opt/raglox/webapp"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  RAGLOX Production Deployment${NC}"
echo -e "${BLUE}  Domain: $DOMAIN${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Function to print status
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# ========================================
# Step 1: Check Prerequisites
# ========================================
echo -e "${BLUE}Step 1: Checking Prerequisites...${NC}"

# Check if running as root/sudo
if [ "$EUID" -ne 0 ]; then 
    print_error "This script must be run as root or with sudo"
    exit 1
fi

print_status "Running with sufficient privileges"

# Check domain resolution
DOMAIN_IP=$(dig +short $DOMAIN A 2>/dev/null | head -1)
if [ -z "$DOMAIN_IP" ]; then
    print_error "Domain $DOMAIN does not resolve"
    exit 1
fi
print_status "Domain $DOMAIN resolves to $DOMAIN_IP"

# Check if domain points to this server
SERVER_IP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127.0.0.1 | grep "$DOMAIN_IP" || echo "")
if [ -z "$SERVER_IP" ]; then
    print_warning "Domain may not point to this server"
    print_warning "Domain IP: $DOMAIN_IP"
    print_warning "Server IPs: $(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127.0.0.1 | tr '\n' ' ')"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    print_status "Domain points to this server ($SERVER_IP)"
fi

echo ""

# ========================================
# Step 2: Handle Existing nginx-proxy
# ========================================
echo -e "${BLUE}Step 2: Handling Existing nginx-proxy...${NC}"

if docker ps | grep -q "nginx-proxy"; then
    print_warning "Found existing nginx-proxy container"
    print_warning "This container is using ports 80 and 443"
    
    echo ""
    echo "Options:"
    echo "  1. Stop and remove nginx-proxy (recommended for clean setup)"
    echo "  2. Keep nginx-proxy and add RAGLOX configuration to it"
    echo "  3. Cancel deployment"
    echo ""
    
    read -p "Choose option (1/2/3): " -n 1 -r
    echo
    
    case $REPLY in
        1)
            print_status "Stopping nginx-proxy..."
            docker stop nginx-proxy 2>/dev/null || true
            docker rm nginx-proxy 2>/dev/null || true
            print_status "nginx-proxy removed"
            USE_SYSTEM_NGINX=true
            ;;
        2)
            print_status "Will configure nginx-proxy for RAGLOX"
            USE_SYSTEM_NGINX=false
            ;;
        3)
            echo "Deployment cancelled"
            exit 0
            ;;
        *)
            print_error "Invalid option"
            exit 1
            ;;
    esac
else
    USE_SYSTEM_NGINX=true
    print_status "No nginx-proxy found, will use system Nginx"
fi

echo ""

# ========================================
# Step 3: Install/Update Nginx
# ========================================
if [ "$USE_SYSTEM_NGINX" = true ]; then
    echo -e "${BLUE}Step 3: Installing/Updating Nginx...${NC}"
    
    apt-get update -qq
    apt-get install -y nginx certbot python3-certbot-nginx
    
    print_status "Nginx installed"
    
    # Stop Nginx temporarily for certbot
    systemctl stop nginx
    print_status "Nginx stopped (will restart after SSL setup)"
else
    echo -e "${BLUE}Step 3: Skipping Nginx installation (using nginx-proxy)${NC}"
fi

echo ""

# ========================================
# Step 4: Configure Backend
# ========================================
echo -e "${BLUE}Step 4: Configuring Backend...${NC}"

# Ensure Backend is running on 0.0.0.0:8000
if ! ps aux | grep -q "[u]vicorn.*main.*8000"; then
    print_warning "Backend not running, starting it..."
    
    cd $WORK_DIR
    source webapp/venv/bin/activate
    
    pkill -f "uvicorn.*main" 2>/dev/null || true
    sleep 2
    
    nohup python3 -m uvicorn src.api.main:app \
        --host 0.0.0.0 \
        --port $BACKEND_PORT \
        --timeout-graceful-shutdown 5 \
        --log-level info \
        > /tmp/backend_production.log 2>&1 &
    
    BACKEND_PID=$!
    echo $BACKEND_PID > /tmp/backend.pid
    
    sleep 5
    
    if ps -p $BACKEND_PID > /dev/null; then
        print_status "Backend started (PID: $BACKEND_PID)"
    else
        print_error "Backend failed to start"
        tail -20 /tmp/backend_production.log
        exit 1
    fi
else
    print_status "Backend already running"
fi

# Test Backend
if curl -s http://127.0.0.1:$BACKEND_PORT/ | grep -q "RAGLOX"; then
    print_status "Backend health check passed"
else
    print_error "Backend health check failed"
    exit 1
fi

echo ""

# ========================================
# Step 5: Build Frontend for Production
# ========================================
echo -e "${BLUE}Step 5: Building Frontend for Production...${NC}"

cd $WORK_DIR/webapp/frontend

# Update API endpoint in .env
cat > .env.production << EOF
# Production Environment Configuration
VITE_API_URL=https://$API_DOMAIN
VITE_APP_URL=https://$DOMAIN
VITE_ENVIRONMENT=production
EOF

print_status "Production environment configured"

# Build Frontend
if [ -d "dist" ]; then
    rm -rf dist
fi

npm run build

if [ -d "dist" ]; then
    print_status "Frontend built successfully"
else
    print_error "Frontend build failed"
    exit 1
fi

echo ""

# ========================================
# Step 6: Setup Nginx Configuration
# ========================================
if [ "$USE_SYSTEM_NGINX" = true ]; then
    echo -e "${BLUE}Step 6: Configuring Nginx...${NC}"
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/raglox << 'NGINX_EOF'
# RAGLOX Production Configuration
# Generated: 2026-01-08

# Rate limiting
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=5r/s;

# Backend upstream
upstream raglox_backend {
    server 127.0.0.1:8000 fail_timeout=30s max_fails=3;
    keepalive 32;
}

# ========================================
# API Subdomain (api.raglox.com)
# ========================================
server {
    listen 80;
    listen [::]:80;
    server_name api.raglox.com;
    
    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name api.raglox.com;
    
    # SSL Configuration (will be managed by Certbot)
    # ssl_certificate /etc/letsencrypt/live/api.raglox.com/fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/api.raglox.com/privkey.pem;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Logging
    access_log /var/log/nginx/raglox_api_access.log combined;
    error_log /var/log/nginx/raglox_api_error.log warn;
    
    # Client settings
    client_max_body_size 50M;
    client_body_buffer_size 128k;
    client_header_buffer_size 16k;
    large_client_header_buffers 4 32k;
    
    # Root location - proxy to Backend
    location / {
        # Rate limiting
        limit_req zone=api_limit burst=20 nodelay;
        
        proxy_pass http://raglox_backend;
        proxy_http_version 1.1;
        
        # Proxy headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
        
        # WebSocket support
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        send_timeout 60s;
        
        # Buffering
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        proxy_busy_buffers_size 8k;
        
        # CORS (Backend handles this, but as backup)
        add_header Access-Control-Allow-Origin "$http_origin" always;
        add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS, PATCH" always;
        add_header Access-Control-Allow-Headers "Authorization, Content-Type, X-Requested-With" always;
        add_header Access-Control-Allow-Credentials "true" always;
        add_header Access-Control-Max-Age "3600" always;
        
        # Handle preflight
        if ($request_method = OPTIONS) {
            return 204;
        }
    }
    
    # Auth endpoints - stricter rate limiting
    location ~ ^/api/v1/auth/(login|register) {
        limit_req zone=auth_limit burst=10 nodelay;
        
        proxy_pass http://raglox_backend;
        proxy_http_version 1.1;
        
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # CORS
        add_header Access-Control-Allow-Origin "$http_origin" always;
        add_header Access-Control-Allow-Methods "POST, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Authorization, Content-Type" always;
        add_header Access-Control-Allow-Credentials "true" always;
        
        if ($request_method = OPTIONS) {
            return 204;
        }
    }
    
    # Health check
    location = /nginx-health {
        access_log off;
        return 200 "Nginx API proxy is healthy\n";
        add_header Content-Type text/plain;
    }
}

# ========================================
# Main Domain (raglox.com & www.raglox.com)
# ========================================
server {
    listen 80;
    listen [::]:80;
    server_name raglox.com www.raglox.com;
    
    # Redirect to HTTPS
    return 301 https://raglox.com$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name www.raglox.com;
    
    # Redirect www to non-www
    return 301 https://raglox.com$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name raglox.com;
    
    # SSL Configuration (will be managed by Certbot)
    # ssl_certificate /etc/letsencrypt/live/raglox.com/fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/raglox.com/privkey.pem;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Logging
    access_log /var/log/nginx/raglox_frontend_access.log combined;
    error_log /var/log/nginx/raglox_frontend_error.log warn;
    
    # Document root
    root /opt/raglox/webapp/webapp/frontend/dist;
    index index.html;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;
    
    # Static assets
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
    
    # API proxy (to api.raglox.com)
    location /api {
        proxy_pass https://api.raglox.com;
        proxy_http_version 1.1;
        
        proxy_set_header Host api.raglox.com;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_ssl_verify off;  # Self-signed cert initially
    }
    
    # SPA fallback
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    # Health check
    location = /health {
        access_log off;
        return 200 "Frontend is healthy\n";
        add_header Content-Type text/plain;
    }
}
NGINX_EOF

    # Enable site
    ln -sf /etc/nginx/sites-available/raglox /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # Test configuration
    if nginx -t; then
        print_status "Nginx configuration valid"
    else
        print_error "Nginx configuration invalid"
        nginx -t
        exit 1
    fi
    
    print_status "Nginx configured for raglox.com"
else
    echo -e "${BLUE}Step 6: Skipping Nginx configuration (using nginx-proxy)${NC}"
    # TODO: Add nginx-proxy configuration here if needed
fi

echo ""

# ========================================
# Step 7: Setup SSL/TLS with Let's Encrypt
# ========================================
if [ "$USE_SYSTEM_NGINX" = true ]; then
    echo -e "${BLUE}Step 7: Setting up SSL/TLS...${NC}"
    
    # Start Nginx for certbot
    systemctl start nginx
    
    print_warning "About to request SSL certificates from Let's Encrypt"
    print_warning "This requires:"
    print_warning "  1. Domain points to this server"
    print_warning "  2. Ports 80 and 443 are accessible from internet"
    print_warning "  3. Valid email address for certificate notifications"
    echo ""
    
    read -p "Continue with SSL setup? (y/N) " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Request certificates
        certbot --nginx \
            -d $DOMAIN \
            -d $WWW_DOMAIN \
            -d $API_DOMAIN \
            --non-interactive \
            --agree-tos \
            --email $EMAIL \
            --redirect
        
        if [ $? -eq 0 ]; then
            print_status "SSL certificates obtained successfully"
            
            # Test auto-renewal
            certbot renew --dry-run
            print_status "Auto-renewal configured"
        else
            print_warning "SSL certificate request failed"
            print_warning "You can run certbot manually later:"
            print_warning "  sudo certbot --nginx -d $DOMAIN -d $WWW_DOMAIN -d $API_DOMAIN"
        fi
    else
        print_warning "Skipping SSL setup"
        print_warning "Site will use HTTP only (not recommended for production)"
    fi
    
    # Reload Nginx
    systemctl reload nginx
    print_status "Nginx reloaded"
else
    echo -e "${BLUE}Step 7: Skipping SSL setup (using nginx-proxy)${NC}"
fi

echo ""

# ========================================
# Step 8: Setup Systemd Services
# ========================================
echo -e "${BLUE}Step 8: Setting up Systemd services...${NC}"

# Backend service
cat > /etc/systemd/system/raglox-backend.service << 'SERVICE_EOF'
[Unit]
Description=RAGLOX Backend API
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=hosam
WorkingDirectory=/opt/raglox/webapp
Environment="PATH=/opt/raglox/webapp/webapp/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/opt/raglox/webapp/webapp/venv/bin/python3 -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --timeout-graceful-shutdown 5 --log-level info
Restart=always
RestartSec=5
StandardOutput=append:/var/log/raglox/backend.log
StandardError=append:/var/log/raglox/backend-error.log

[Install]
WantedBy=multi-user.target
SERVICE_EOF

# Create log directory
mkdir -p /var/log/raglox
chown hosam:hosam /var/log/raglox

# Reload systemd
systemctl daemon-reload

print_status "Systemd services created"

# Enable and start
systemctl enable raglox-backend
systemctl restart raglox-backend

sleep 3

if systemctl is-active --quiet raglox-backend; then
    print_status "Backend service is running"
else
    print_error "Backend service failed to start"
    journalctl -u raglox-backend -n 20
fi

echo ""

# ========================================
# Step 9: Final Tests
# ========================================
echo -e "${BLUE}Step 9: Running final tests...${NC}"

# Test Backend
if curl -s http://127.0.0.1:8000/ | grep -q "RAGLOX"; then
    print_status "Backend localhost test passed"
else
    print_warning "Backend localhost test failed"
fi

# Test domain (if SSL is setup)
if [ "$USE_SYSTEM_NGINX" = true ]; then
    sleep 5
    
    # Test API
    if curl -s -k https://api.$DOMAIN/ | grep -q "RAGLOX"; then
        print_status "API domain test passed (https://api.$DOMAIN)"
    else
        print_warning "API domain test failed"
    fi
    
    # Test Frontend
    if curl -s -k https://$DOMAIN/ | grep -q "html"; then
        print_status "Frontend domain test passed (https://$DOMAIN)"
    else
        print_warning "Frontend domain test failed"
    fi
fi

echo ""

# ========================================
# Summary
# ========================================
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Your RAGLOX application is now available at:"
echo ""
echo -e "  Frontend:  ${BLUE}https://$DOMAIN${NC}"
echo -e "  API:       ${BLUE}https://$API_DOMAIN${NC}"
echo ""
echo "Services:"
echo "  - Backend: systemctl status raglox-backend"
echo "  - Nginx: systemctl status nginx"
echo ""
echo "Logs:"
echo "  - Backend: tail -f /var/log/raglox/backend.log"
echo "  - Nginx Access: tail -f /var/log/nginx/raglox_*_access.log"
echo "  - Nginx Error: tail -f /var/log/nginx/raglox_*_error.log"
echo ""
echo "Next steps:"
echo "  1. Test registration: https://$DOMAIN/register"
echo "  2. Test API: https://$API_DOMAIN/docs"
echo "  3. Update CORS settings in Backend if needed"
echo "  4. Configure backup strategy"
echo ""
echo -e "${GREEN}Happy deploying!${NC}"
echo ""
