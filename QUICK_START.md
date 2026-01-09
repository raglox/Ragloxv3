# 🚀 RAGLOX Production Deployment - Quick Start

**Date**: 2026-01-08  
**Domain**: raglox.com  
**Status**: Ready to Deploy

---

## ⚡ TL;DR - Quick Deployment

```bash
# As root/sudo
sudo bash /opt/raglox/webapp/deploy_production.sh
```

**Time**: ~15 minutes  
**Result**: Production-ready RAGLOX on https://raglox.com

---

## 📊 Current Status

### ✅ Verified
- Domain `raglox.com` → 208.115.230.194
- Backend running on port 8000
- Database (PostgreSQL) working
- Redis working
- All APIs functional (locally)

### ⚠️ Requires Action
- **nginx-proxy** container using ports 80/443
- Need to setup production Nginx OR configure nginx-proxy
- Need SSL certificates (Let's Encrypt)
- Need to build production Frontend

---

## 🎯 Deployment Options

### Option 1: Automated (Recommended)

**Run the deployment script:**
```bash
sudo bash /opt/raglox/webapp/deploy_production.sh
```

**What it does:**
1. Checks prerequisites
2. Handles nginx-proxy (asks for permission)
3. Installs/configures Nginx
4. Builds Frontend for production
5. Requests SSL certificates
6. Creates systemd services
7. Tests everything

**Interactive prompts:**
- Remove nginx-proxy? (yes/no)
- Setup SSL? (yes/no)
- Email for SSL notifications

---

### Option 2: Manual Step-by-Step

If you prefer control, follow: `PRODUCTION_DEPLOYMENT.md`

---

## 🔍 Pre-Deployment Checklist

Before running the script, verify:

```bash
# 1. Check domain resolution
dig raglox.com A
# Should return: 208.115.230.194

# 2. Check Backend is running
curl http://127.0.0.1:8000/
# Should return: {"name":"RAGLOX",...}

# 3. Check database
psql -h localhost -p 54322 -U raglox -d raglox -c "SELECT 1"
# Should return: 1

# 4. Check Redis
redis-cli -h localhost -p 6379 ping
# Should return: PONG
```

**All checks pass?** → Ready to deploy!

---

## 📝 What The Script Does

### Phase 1: Preparation (2 min)
- ✅ Verify domain points to server
- ✅ Check prerequisites
- ⚠️ Handle nginx-proxy container

### Phase 2: Nginx Setup (3 min)
- ✅ Install Nginx + Certbot
- ✅ Create Nginx configuration
  - `raglox.com` → Frontend (SPA)
  - `api.raglox.com` → Backend API
  - `www.raglox.com` → Redirect to raglox.com

### Phase 3: Application (5 min)
- ✅ Configure Backend for production
- ✅ Build Frontend (npm run build)
- ✅ Setup environment variables

### Phase 4: SSL (3 min)
- ✅ Request Let's Encrypt certificates
- ✅ Configure auto-renewal
- ✅ Enable HTTPS redirect

### Phase 5: Services (2 min)
- ✅ Create systemd service for Backend
- ✅ Enable auto-start on boot
- ✅ Setup log rotation

### Phase 6: Testing
- ✅ Test Backend health
- ✅ Test Frontend access
- ✅ Test API endpoints
- ✅ Test SSL certificates

---

## 🌐 After Deployment

Your RAGLOX will be available at:

### Frontend
```
https://raglox.com
https://www.raglox.com (redirects to raglox.com)
```

**Features:**
- User registration/login
- Dashboard
- Mission management
- Real-time updates

### API
```
https://api.raglox.com
https://api.raglox.com/docs (Swagger UI)
```

**Endpoints:**
- `/api/v1/auth/*` - Authentication
- `/api/v1/missions/*` - Mission management
- `/api/v1/users/*` - User management
- `/api/v1/organizations/*` - Organization management

---

## 🔧 Post-Deployment Configuration

### 1. Update CORS Settings

Edit `/opt/raglox/webapp/src/api/main.py`:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://raglox.com",
        "https://www.raglox.com",
        # Add more if needed
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

Then restart:
```bash
sudo systemctl restart raglox-backend
```

### 2. Configure Environment Variables

**Backend** (`/opt/raglox/webapp/.env`):
```env
DATABASE_URL=postgresql://raglox:password@localhost:54322/raglox
REDIS_URL=redis://localhost:6379/0
ENVIRONMENT=production
JWT_SECRET=<your-secret-key>
STRIPE_SECRET_KEY=<your-stripe-key>  # If using billing
```

**Frontend** (`.env.production` - already created by script):
```env
VITE_API_URL=https://api.raglox.com
VITE_APP_URL=https://raglox.com
VITE_ENVIRONMENT=production
```

### 3. Test Everything

```bash
# Run test suite
cd /opt/raglox/webapp
./test_external_access.sh raglox.com
```

**Expected result:**
```
Total Tests:  10
Passed:       10
Failed:       0
Skipped:      0

✅ ALL TESTS PASSED!
```

---

## 📊 Monitoring & Management

### Service Status

```bash
# Backend
sudo systemctl status raglox-backend

# Nginx
sudo systemctl status nginx

# All services
sudo systemctl list-units | grep raglox
```

### Logs

```bash
# Backend logs
tail -f /var/log/raglox/backend.log

# Nginx access logs
tail -f /var/log/nginx/raglox_*_access.log

# Nginx error logs
tail -f /var/log/nginx/raglox_*_error.log

# System logs
sudo journalctl -u raglox-backend -f
```

### Restart Services

```bash
# Backend only
sudo systemctl restart raglox-backend

# Nginx only
sudo nginx -t && sudo systemctl reload nginx

# Both
sudo systemctl restart raglox-backend nginx
```

---

## 🆘 Troubleshooting

### Issue: Script fails at nginx-proxy

**Solution:**
```bash
# Manually remove nginx-proxy
docker stop nginx-proxy
docker rm nginx-proxy

# Re-run script
sudo bash deploy_production.sh
```

### Issue: SSL certificate request fails

**Possible causes:**
1. Domain doesn't point to server
2. Ports 80/443 blocked by firewall
3. Another service using port 80/443

**Solution:**
```bash
# Check DNS
dig raglox.com A

# Check ports
sudo ss -tlnp | grep -E ':80|:443'

# Check firewall
sudo iptables -L -n | grep -E '80|443'

# Manually request SSL
sudo certbot --nginx -d raglox.com -d www.raglox.com -d api.raglox.com
```

### Issue: Frontend shows "API Error"

**Check:**
1. Backend is running: `sudo systemctl status raglox-backend`
2. Nginx proxy is working: `curl https://api.raglox.com/`
3. CORS is configured: Check Backend logs

**Fix CORS:**
```bash
# Edit Backend
nano /opt/raglox/webapp/src/api/main.py

# Add raglox.com to allowed origins
# Restart
sudo systemctl restart raglox-backend
```

### Issue: 502 Bad Gateway

**Solution:**
```bash
# Check Backend
sudo systemctl restart raglox-backend
sleep 3
curl http://127.0.0.1:8000/

# Check Nginx config
sudo nginx -t

# Check logs
sudo tail -50 /var/log/nginx/raglox_api_error.log
```

---

## 🔐 Security Notes

### Immediately After Deployment

1. **Change default credentials** (if any)
2. **Update JWT secret** in `.env`
3. **Configure CORS** (restrict to raglox.com only)
4. **Setup backups** for database
5. **Enable fail2ban** (optional but recommended)

### SSL/TLS

- ✅ Auto-renewal enabled (runs twice daily)
- ✅ HTTPS redirect enforced
- ✅ HSTS enabled
- ✅ Strong ciphers only

### Rate Limiting

Currently configured:
- API: 10 requests/second per IP
- Auth: 5 requests/second per IP

To adjust, edit `/etc/nginx/sites-available/raglox`

---

## 📈 Performance Optimization

### After Deployment

1. **Enable Gzip** (already configured)
2. **Enable caching** for static assets (configured)
3. **Add CDN** (optional, for global reach)
4. **Database optimization** (indexes, query optimization)
5. **Redis optimization** (memory limits, persistence)

### Monitoring Setup (Optional)

Consider adding:
- Prometheus + Grafana
- Uptime monitors
- Log aggregation (ELK stack)
- Error tracking (Sentry)

---

## 🔄 Updates & Maintenance

### Update Application

```bash
# Pull latest code
cd /opt/raglox/webapp
git pull origin development

# Update Backend
source webapp/venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart raglox-backend

# Update Frontend
cd webapp/frontend
npm install
npm run build
# Nginx automatically serves new build
```

### Update SSL Certificates

Automatic renewal, but to test:
```bash
sudo certbot renew --dry-run
```

Manual renewal:
```bash
sudo certbot renew
sudo systemctl reload nginx
```

---

## ✅ Deployment Success Checklist

After running the script, verify:

- [ ] `https://raglox.com/` loads (Frontend)
- [ ] `https://api.raglox.com/` returns JSON
- [ ] `https://api.raglox.com/docs` shows Swagger
- [ ] User registration works
- [ ] User login works
- [ ] Mission creation works
- [ ] SSL certificate is valid (green padlock)
- [ ] Backend service auto-starts
- [ ] Logs are being written
- [ ] No errors in Nginx logs
- [ ] Test suite passes

**All checked?** 🎉 **Deployment successful!**

---

## 📞 Support & Documentation

### Files Created

1. **deploy_production.sh** - Automated deployment script
2. **PRODUCTION_DEPLOYMENT.md** - Detailed deployment guide
3. **test_external_access.sh** - Testing suite
4. **NETWORK_ARCHITECTURE.md** - Network topology
5. **EXTERNAL_ACCESS_FINAL_REPORT.md** - Troubleshooting guide

### Quick Commands

```bash
# View all documentation
ls -lh /opt/raglox/webapp/*.md

# View deployment script
cat /opt/raglox/webapp/deploy_production.sh

# Run tests
./test_external_access.sh raglox.com
```

---

## 🎯 Next Steps

After successful deployment:

1. **Test the application thoroughly**
2. **Configure monitoring and alerts**
3. **Setup automated backups**
4. **Review and tighten security**
5. **Add team members**
6. **Start using RAGLOX!** 🚀

---

**Ready to deploy?**

```bash
sudo bash /opt/raglox/webapp/deploy_production.sh
```

**Questions?** Check `PRODUCTION_DEPLOYMENT.md` for detailed guide.

**Issues?** Check `EXTERNAL_ACCESS_FINAL_REPORT.md` for troubleshooting.

---

**Last Updated**: 2026-01-08  
**Version**: 1.0.0  
**Status**: ✅ Ready for Production
