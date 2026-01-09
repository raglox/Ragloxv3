# RAGLOX V3 - Network Architecture & External Access Guide

**Generated**: 2026-01-08 18:00 UTC  
**Status**: Production Configuration  
**Author**: RAGLOX Development Team

---

## 📋 Table of Contents

1. [System Overview](#system-overview)
2. [Network Topology](#network-topology)
3. [Current Issues](#current-issues)
4. [Solution Architecture](#solution-architecture)
5. [Configuration Steps](#configuration-steps)
6. [Testing & Verification](#testing--verification)
7. [Troubleshooting](#troubleshooting)

---

## 🖥️ System Overview

### Services Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RAGLOX V3 System                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  Port 3000   ┌──────────────┐            │
│  │   Frontend   │◄────────────►│    Vite Dev  │            │
│  │  (React TS)  │              │    Server    │            │
│  └───────┬──────┘              └──────────────┘            │
│          │                                                   │
│          │ Proxy: /api → :8000                              │
│          ▼                                                   │
│  ┌──────────────┐  Port 8000                               │
│  │   Backend    │  ┌────────────────────────────┐          │
│  │  (FastAPI)   │──┤  PostgreSQL (Port 54322)   │          │
│  │              │  ├────────────────────────────┤          │
│  │   Uvicorn    │──┤  Redis (Port 6379)         │          │
│  └──────────────┘  └────────────────────────────┘          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Network Interfaces

| Interface | IP Address | Purpose |
|-----------|------------|---------|
| enp94s0f0 | 208.115.230.196/32 | Primary WAN Interface |
| br0 | 208.115.230.194/28 | Bridge Network |
| enp94s0f1 | 10.21.0.1/31 | Secondary Interface |
| docker0 | 172.17.0.1/16 | Docker Default Bridge |
| Various Docker | 172.18.0.1/16, 172.28.0.1/16, etc. | Docker Custom Networks |

---

## 🌐 Network Topology

### Current State (Problematic)

```
Internet ─── Router ─┬─► 208.115.230.196 (enp94s0f0) ──┐
                     │                                   │
                     └─► 208.115.230.194 (br0) ─────────┤
                                                          │
                                                          ▼
                                              ┌────────────────────┐
                                              │  Backend :8000     │
                                              │  Bound to 0.0.0.0  │
                                              └────────────────────┘
                                                          │
                                                          │
                    ┌─────────────────────────────────────┘
                    │
                    ▼
          ❌ Connection Timeout from External IPs
          ✅ Works from localhost
```

### Problem Analysis

#### Issue 1: br0 Bridge Routing
- **Symptom**: Backend bound to `0.0.0.0:8000` but unreachable from external IPs
- **Root Cause**: `br0` bridge (208.115.230.194) acts as default gateway but doesn't forward to localhost-bound services
- **Impact**: External requests to 208.115.230.194:8000 or 208.115.230.196:8000 timeout

#### Issue 2: Multiple IP Addresses
- **Symptom**: Two public IPs on different interfaces
- **Root Cause**: Server has both direct WAN interface (enp94s0f0) and bridge (br0)
- **Impact**: Routing confusion and access issues

#### Issue 3: Docker Network Interference
- **Symptom**: Multiple Docker networks (manus-network, supabase_network, etc.)
- **Root Cause**: Complex multi-container setup with Supabase
- **Impact**: Potential port conflicts and routing complexity

---

## 🔧 Current Issues (Detailed)

### 1. External Access Fails

**Test Results:**
```bash
# ✅ Works
curl http://localhost:8000/
curl http://127.0.0.1:8000/
curl http://0.0.0.0:8000/

# ❌ Fails (timeout)
curl http://208.115.230.194:8000/
curl http://208.115.230.196:8000/
```

**Backend Process:**
```
python3 -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000
LISTEN 0  2048  0.0.0.0:8000  0.0.0.0:*
```

### 2. Frontend Access

**Status:** Frontend works on `http://208.115.230.194:3000/` (confirmed via earlier tests)

**Configuration:**
- Vite dev server listening on `:::3000` (IPv6)
- Proxy configured: `/api → http://127.0.0.1:8000`

**Issue:** Frontend accessible but backend API calls from frontend fail due to localhost proxy

---

## ✅ Solution Architecture

### Option A: Direct Binding (Recommended for Development)

**Concept:** Make Backend directly accessible on the public IP

```bash
# Change Backend binding from 0.0.0.0 to specific IP
uvicorn src.api.main:app --host 208.115.230.194 --port 8000
```

**Pros:**
- Simple and straightforward
- No additional infrastructure
- Works immediately

**Cons:**
- Need to restart Backend
- Tied to specific IP
- Not ideal for multi-interface servers

### Option B: Nginx Reverse Proxy (Recommended for Production)

**Concept:** Use Nginx as reverse proxy to handle routing

```nginx
server {
    listen 208.115.230.194:8000;
    listen 208.115.230.196:8000;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

**Pros:**
- Professional solution
- Supports multiple IPs
- Can add SSL/TLS
- Better logging and monitoring

**Cons:**
- Requires Nginx installation
- Additional configuration
- More complexity

### Option C: iptables NAT Forwarding (System-Level)

**Concept:** Use iptables to forward external traffic to localhost

```bash
# Forward traffic from public IPs to localhost
iptables -t nat -A PREROUTING -p tcp -d 208.115.230.194 --dport 8000 -j DNAT --to-destination 127.0.0.1:8000
iptables -t nat -A PREROUTING -p tcp -d 208.115.230.196 --dport 8000 -j DNAT --to-destination 127.0.0.1:8000

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1
```

**Pros:**
- Works at kernel level
- No application changes needed
- Transparent to applications

**Cons:**
- Requires root permissions (currently blocked)
- Complex to debug
- May interfere with Docker networking

---

## 🛠️ Configuration Steps

### Immediate Fix (Option A - Quick)

**Step 1:** Stop current Backend
```bash
cd /opt/raglox/webapp
pkill -f "uvicorn.*main"
```

**Step 2:** Restart Backend on br0 IP
```bash
cd /opt/raglox/webapp
source webapp/venv/bin/activate
python3 -m uvicorn src.api.main:app --host 208.115.230.194 --port 8000 > /tmp/backend_external.log 2>&1 &
```

**Step 3:** Test
```bash
curl http://208.115.230.194:8000/
```

### Production Fix (Option B - Nginx)

**Step 1:** Install Nginx (if not present)
```bash
apt-get update && apt-get install -y nginx
```

**Step 2:** Create Configuration
```bash
cat > /etc/nginx/sites-available/raglox << 'EOF'
server {
    listen 208.115.230.194:8000;
    listen 208.115.230.196:8000;
    
    server_name _;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # CORS headers (if needed)
        add_header Access-Control-Allow-Origin "*" always;
        add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Authorization, Content-Type" always;
        
        # Preflight requests
        if ($request_method = OPTIONS) {
            return 204;
        }
    }
}
EOF
```

**Step 3:** Enable and Start
```bash
ln -s /etc/nginx/sites-available/raglox /etc/nginx/sites-enabled/
nginx -t
systemctl restart nginx
```

**Step 4:** Keep Backend on localhost
```bash
# Backend remains on 0.0.0.0:8000 or 127.0.0.1:8000
# Nginx handles external access
```

---

## ✅ Testing & Verification

### Test Script

```bash
#!/bin/bash

echo "=== RAGLOX V3 NETWORK VERIFICATION ==="
echo ""

# Test Backend Directly
echo "1. Backend Direct Access (localhost):"
curl -s http://localhost:8000/ | jq -r '.name'

# Test Backend via Public IP (after fix)
echo "2. Backend via Public IP (208.115.230.194):"
curl -s http://208.115.230.194:8000/ | jq -r '.name'

# Test Registration
echo "3. Registration Test:"
curl -s -X POST http://208.115.230.194:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"verify@test.com","password":"Test123!@#","full_name":"Verify Test","organization_name":"Verify Org"}' \
  | jq -r '.user.email // .detail'

# Test Mission Creation
echo "4. Mission Creation Test:"
TOKEN=$(curl -s -X POST http://208.115.230.194:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"verify@test.com","password":"Test123!@#"}' \
  | jq -r '.access_token')

curl -s -X POST http://208.115.230.194:8000/api/v1/missions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Network Verify","scope":["127.0.0.1"],"goals":["reconnaissance"]}' \
  | jq -r '.mission_id // .detail'

# Test Frontend
echo "5. Frontend Access:"
curl -sI http://208.115.230.194:3000/ | head -1

echo ""
echo "=== VERIFICATION COMPLETE ==="
```

### Expected Results

All tests should return successful responses:

1. **Backend Direct**: `RAGLOX`
2. **Backend Public IP**: `RAGLOX`
3. **Registration**: Email address or success message
4. **Mission Creation**: UUID or success message
5. **Frontend**: `HTTP/1.1 200 OK`

---

## 🔍 Troubleshooting

### Issue: Backend unreachable from public IP

**Diagnosis:**
```bash
# Check binding
ss -tlnp | grep :8000

# Check routing
ip route show

# Test connectivity
for IP in 127.0.0.1 208.115.230.194 208.115.230.196; do
    echo "Testing $IP:8000"
    timeout 2 curl -s "http://$IP:8000/" 2>&1 | head -1
done
```

**Solution:** Apply Option A or B from Configuration Steps

### Issue: Frontend proxy fails

**Diagnosis:**
```bash
# Check Vite config
cat webapp/frontend/vite.config.ts | grep -A10 "proxy"

# Test proxy
curl -s http://208.115.230.194:3000/api/v1/auth/me
```

**Solution:** Update Vite proxy to use public IP:
```typescript
proxy: {
  '/api': {
    target: 'http://208.115.230.194:8000',  // Changed from localhost
    changeOrigin: true
  }
}
```

### Issue: Connection timeout

**Check Firewall:**
```bash
# Check iptables
iptables -L INPUT -n | grep 8000
iptables -L INPUT -n | grep 3000

# Check nftables
nft list ruleset | grep -E "8000|3000"
```

**Ensure ports are open:**
```bash
# Add rules (if needed, requires root)
iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
iptables -A INPUT -p tcp --dport 3000 -j ACCEPT
```

---

## 📊 Current System State

### Services Status

| Service | Port | Status | Accessible |
|---------|------|--------|------------|
| Backend | 8000 | ✅ Running | ✅ Localhost only |
| Frontend | 3000 | ✅ Running | ✅ Public IP |
| PostgreSQL | 54322 | ✅ Running | Internal only |
| Redis | 6379 | ✅ Running | Internal only |

### Network Bindings

```
Backend:  0.0.0.0:8000  → Needs fix for external access
Frontend: :::3000       → Works externally
```

---

## 🎯 Recommended Action Plan

### For Development (Immediate)

1. **Apply Option A**: Bind Backend to 208.115.230.194:8000
2. **Update Frontend proxy** to use public IP
3. **Test** registration and mission creation
4. **Document** changes

### For Production (Long-term)

1. **Install Nginx** as reverse proxy
2. **Configure SSL/TLS** with Let's Encrypt
3. **Set up proper logging** and monitoring
4. **Implement rate limiting** and security
5. **Use systemd** for service management

---

## 📝 Notes

- **Security**: Current setup has CORS enabled with `origins=['*']`. Lock this down in production.
- **Performance**: Direct binding is faster than proxy, but Nginx adds features like caching and load balancing.
- **Monitoring**: Add health checks and monitoring for all services.
- **Backup**: Ensure database backups are automated.

---

## 📞 Support

For issues or questions:
- Repository: https://github.com/HosamN-ALI/Ragloxv3
- Issues: https://github.com/HosamN-ALI/Ragloxv3/issues

---

**Last Updated**: 2026-01-08 18:00 UTC  
**Version**: 1.0.0  
**Status**: ✅ Complete Analysis
