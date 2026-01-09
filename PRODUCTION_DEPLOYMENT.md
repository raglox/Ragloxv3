# RAGLOX Production Deployment Guide

**Domain**: raglox.com  
**Generated**: 2026-01-08  
**Status**: Production-Ready  

---

## 🎯 Overview

This guide covers complete production deployment of RAGLOX V3 on **raglox.com** with:
- ✅ Nginx reverse proxy
- ✅ SSL/TLS (HTTPS) with Let's Encrypt
- ✅ Systemd service management
- ✅ Production-optimized configuration
- ✅ Automatic frontend build
- ✅ Domain-based routing

---

## 📋 Prerequisites

### 1. Domain Configuration ✅

**Verified Status:**
- `raglox.com` → 208.115.230.194 ✅
- `www.raglox.com` → 208.115.230.194 ✅
- `api.raglox.com` → (needs DNS A record)

### 2. Server Requirements

- Ubuntu 20.04+ or similar
- Root/sudo access
- Ports 80 and 443 accessible from internet
- At least 2GB RAM
- 10GB disk space

### 3. Existing Services

**Current Status:**
- Backend: Running on `0.0.0.0:8000`
- Frontend: Dev server on port 3000
- Database: PostgreSQL on `localhost:54322`
- Redis: Running on `localhost:6379`
- **nginx-proxy container**: Using ports 80 and 443 ⚠️

---

## 🚀 Quick Deployment

### Option A: Automated Deployment (Recommended)

```bash
# Run as root/sudo
sudo bash /opt/raglox/webapp/deploy_production.sh
```

The script will:
1. ✅ Verify domain resolution
2. ⚠️ Handle existing nginx-proxy container
3. ✅ Install/configure Nginx
4. ✅ Configure Backend for production
5. ✅ Build Frontend for production
6. ✅ Setup SSL certificates (Let's Encrypt)
7. ✅ Create systemd services
8. ✅ Run final tests

**Estimated time**: 10-15 minutes

---

## 🛠️ Manual Deployment

If you prefer step-by-step control:

### Step 1: Handle nginx-proxy Container

The server currently has `nginx-proxy` container using ports 80 and 443.

**Option A: Remove nginx-proxy** (Clean setup)
```bash
docker stop nginx-proxy
docker rm nginx-proxy
```

**Option B: Keep nginx-proxy** (Advanced)
```bash
# Add RAGLOX configuration to nginx-proxy
# (See nginx-proxy documentation)
```

### Step 2: Install Nginx & Certbot

```bash
sudo apt-get update
sudo apt-get install -y nginx certbot python3-certbot-nginx
```

### Step 3: Configure Backend

Ensure Backend is production-ready:

```bash
cd /opt/raglox/webapp

# Update Backend configuration
# CORS should allow: https://raglox.com, https://api.raglox.com

# Start Backend
source webapp/venv/bin/activate
python3 -m uvicorn src.api.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --timeout-graceful-shutdown 5 \
    --log-level info
```

### Step 4: Build Frontend

```bash
cd /opt/raglox/webapp/webapp/frontend

# Create production environment
cat > .env.production << EOF
VITE_API_URL=https://api.raglox.com
VITE_APP_URL=https://raglox.com
VITE_ENVIRONMENT=production
EOF

# Build
npm run build

# Verify
ls -lh dist/
```

### Step 5: Configure Nginx

```bash
# Copy the Nginx configuration
sudo cp /opt/raglox/webapp/nginx/raglox.conf /etc/nginx/sites-available/raglox

# Or use the one created by deploy_production.sh

# Enable site
sudo ln -sf /etc/nginx/sites-available/raglox /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test configuration
sudo nginx -t

# Start Nginx
sudo systemctl start nginx
sudo systemctl enable nginx
```

### Step 6: Setup SSL Certificates

```bash
# Request certificates
sudo certbot --nginx \
    -d raglox.com \
    -d www.raglox.com \
    -d api.raglox.com \
    --non-interactive \
    --agree-tos \
    --email admin@raglox.com \
    --redirect

# Test auto-renewal
sudo certbot renew --dry-run
```

### Step 7: Setup Systemd Service

```bash
# Create service file
sudo nano /etc/systemd/system/raglox-backend.service

# Paste content from deploy_production.sh

# Reload and enable
sudo systemctl daemon-reload
sudo systemctl enable raglox-backend
sudo systemctl start raglox-backend

# Check status
sudo systemctl status raglox-backend
```

---

## 🔧 Configuration Details

### Nginx Configuration

**Main features:**
- Rate limiting (10 req/s for API, 5 req/s for auth)
- CORS headers
- HTTPS redirect
- Gzip compression
- Static asset caching
- WebSocket support
- Security headers

**File location:** `/etc/nginx/sites-available/raglox`

### Backend Configuration

**Production settings:**
```python
# In src.api.main:app

# CORS should be updated to:
origins = [
    "https://raglox.com",
    "https://www.raglox.com",
    "https://api.raglox.com",
]
```

**Environment variables:**
```bash
DATABASE_URL=postgresql://raglox:password@localhost:54322/raglox
REDIS_URL=redis://localhost:6379/0
ENVIRONMENT=production
```

### Frontend Configuration

**Production environment** (`.env.production`):
```env
VITE_API_URL=https://api.raglox.com
VITE_APP_URL=https://raglox.com
VITE_ENVIRONMENT=production
```

---

## 🧪 Testing

### Automated Test Suite

```bash
# Test all endpoints
cd /opt/raglox/webapp
./test_external_access.sh raglox.com
```

### Manual Tests

**1. Frontend:**
```bash
curl https://raglox.com/
# Should return HTML

curl https://raglox.com/health
# Should return "Frontend is healthy"
```

**2. API:**
```bash
curl https://api.raglox.com/
# Should return: {"name":"RAGLOX","version":"3.0.0"...}

curl https://api.raglox.com/docs
# Should return Swagger UI HTML
```

**3. Registration:**
```bash
curl -X POST https://api.raglox.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test123!@#","full_name":"Test User","organization_name":"Test Org"}'
# Should return JWT token
```

**4. SSL Certificate:**
```bash
openssl s_client -connect raglox.com:443 -servername raglox.com < /dev/null
# Should show Let's Encrypt certificate
```

---

## 📊 Service Management

### Backend Service

```bash
# Status
sudo systemctl status raglox-backend

# Start/Stop/Restart
sudo systemctl start raglox-backend
sudo systemctl stop raglox-backend
sudo systemctl restart raglox-backend

# Logs
sudo journalctl -u raglox-backend -f
# Or
tail -f /var/log/raglox/backend.log
```

### Nginx Service

```bash
# Status
sudo systemctl status nginx

# Reload (after config changes)
sudo nginx -t && sudo systemctl reload nginx

# Restart
sudo systemctl restart nginx

# Logs
tail -f /var/log/nginx/raglox_*_access.log
tail -f /var/log/nginx/raglox_*_error.log
```

---

## 🔐 Security Considerations

### SSL/TLS

- ✅ Certificates auto-renew every 90 days
- ✅ Strong ciphers enabled
- ✅ HSTS header configured
- ✅ HTTP → HTTPS redirect

### Rate Limiting

- API: 10 requests/second per IP
- Auth endpoints: 5 requests/second per IP
- Burst: 20 requests for API, 10 for auth

### CORS

**Update Backend CORS:**
```python
# In src/api/main.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://raglox.com",
        "https://www.raglox.com",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Security Headers

All responses include:
- `Strict-Transport-Security`
- `X-Frame-Options: SAMEORIGIN`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`

---

## 📝 Log Management

### Log Locations

```
/var/log/raglox/backend.log          # Backend stdout
/var/log/raglox/backend-error.log    # Backend stderr
/var/log/nginx/raglox_api_access.log # API access
/var/log/nginx/raglox_api_error.log  # API errors
/var/log/nginx/raglox_frontend_access.log # Frontend access
/var/log/nginx/raglox_frontend_error.log  # Frontend errors
```

### Log Rotation

Nginx logs rotate automatically. For Backend logs:

```bash
# Create logrotate config
sudo nano /etc/logrotate.d/raglox

# Add:
/var/log/raglox/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    missingok
    create 0640 hosam hosam
    sharedscripts
    postrotate
        systemctl reload raglox-backend > /dev/null 2>&1 || true
    endscript
}
```

---

## 🔄 Updates & Maintenance

### Update Backend

```bash
cd /opt/raglox/webapp
git pull origin development
source webapp/venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart raglox-backend
```

### Update Frontend

```bash
cd /opt/raglox/webapp/webapp/frontend
git pull origin development
npm install
npm run build
# No restart needed, Nginx serves static files
```

### Database Migrations

```bash
cd /opt/raglox/webapp
source webapp/venv/bin/activate
# Run your migration script
sudo systemctl restart raglox-backend
```

---

## 🆘 Troubleshooting

### Issue: SSL Certificate Failed

```bash
# Check DNS
dig raglox.com A
dig api.raglox.com A

# Check ports
sudo netstat -tlnp | grep -E ':80|:443'

# Manually request certificate
sudo certbot certonly --standalone -d raglox.com -d www.raglox.com -d api.raglox.com
```

### Issue: Backend Not Starting

```bash
# Check logs
sudo journalctl -u raglox-backend -n 50

# Check database connection
psql -h localhost -p 54322 -U raglox -d raglox

# Check Redis connection
redis-cli -h localhost -p 6379 ping
```

### Issue: 502 Bad Gateway

```bash
# Check Backend is running
sudo systemctl status raglox-backend

# Check Backend is listening
ss -tlnp | grep :8000

# Test Backend directly
curl http://127.0.0.1:8000/

# Check Nginx error log
sudo tail -50 /var/log/nginx/raglox_api_error.log
```

### Issue: CORS Errors

```bash
# Update Backend CORS settings
# Edit src/api/main.py
# Restart Backend
sudo systemctl restart raglox-backend
```

---

## 📈 Monitoring

### Health Checks

```bash
# Frontend health
curl https://raglox.com/health

# Backend health
curl https://api.raglox.com/

# Nginx health
curl https://api.raglox.com/nginx-health
```

### Performance Monitoring

```bash
# Nginx status (if enabled)
curl https://raglox.com/nginx_status

# Backend metrics (if implemented)
curl https://api.raglox.com/metrics
```

---

## 🚀 Post-Deployment Checklist

- [ ] Domain points to server (raglox.com, www, api)
- [ ] SSL certificates obtained and valid
- [ ] Backend service running and auto-starts
- [ ] Frontend built and accessible
- [ ] Registration works
- [ ] Login works
- [ ] Mission creation works
- [ ] Database accessible
- [ ] Redis accessible
- [ ] Logs rotating properly
- [ ] Backups configured
- [ ] Monitoring setup
- [ ] CORS configured correctly
- [ ] Security headers present
- [ ] Rate limiting working

---

## 📞 Support

For issues:

1. Check logs (see Log Management section)
2. Run test suite: `./test_external_access.sh raglox.com`
3. Review this documentation
4. Check Nginx error logs
5. Check Backend service logs

---

## 🎉 Success Criteria

Your deployment is successful when:

✅ `https://raglox.com/` loads the frontend  
✅ `https://api.raglox.com/` returns RAGLOX version info  
✅ `https://api.raglox.com/docs` shows Swagger UI  
✅ User registration works via frontend  
✅ Login works and returns JWT  
✅ Mission creation works  
✅ SSL certificates are valid  
✅ All services auto-start on reboot  

---

**Last Updated**: 2026-01-08  
**Version**: 1.0.0  
**Status**: Ready for Production Deployment 🚀
