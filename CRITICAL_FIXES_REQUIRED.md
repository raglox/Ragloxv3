# 🔴 CRITICAL FIXES REQUIRED

**Date**: 2026-01-08  
**Priority**: HIGH  
**Status**: Requires Immediate Attention

---

## 📊 Summary

Based on E2E testing and user screenshot analysis, there are **3 critical issues** that must be fixed:

### Issues Overview
| Issue | Priority | Impact | Status |
|-------|----------|--------|--------|
| 1. Invalid Token Rejection | HIGH | Security | ⚠️ Needs Fix |
| 2. Frontend Auth Headers Missing | HIGH | Functionality | ⚠️ Needs Fix |
| 3. Mission Execution/VM Integration | HIGH | Core Feature | ⚠️ Needs Testing |

---

## 🔴 Issue 1: Invalid Token Rejection (Test 11.2 Failure)

### Problem
API doesn't clearly reject invalid tokens with specific error messages.

### Evidence from E2E Test
```bash
# Test 11.2: Invalid Token
curl -s http://raglox.com/api/v1/missions \
  -H "Authorization: Bearer invalid-token-12345"

# Current Response (Generic):
{"detail": "Could not validate credentials"}

# Expected Response (Specific):
{"detail": "Invalid token: signature verification failed", "type": "invalid_token"}
```

### Root Cause
File: `src/api/auth_routes.py` (lines ~260-280)

The token validation doesn't differentiate between:
- Expired tokens
- Invalid signature
- Malformed tokens
- Missing tokens

### Fix Required

**Location**: `src/api/auth_routes.py` - `decode_token()` function

```python
# Current Code (approximate):
def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

# Required Fix:
def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401, 
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=401, 
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=401, 
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )
```

### Steps to Fix
1. Edit `src/api/auth_routes.py`
2. Locate `decode_token()` function (around line 260)
3. Add specific exception handling for JWT errors
4. Add proper WWW-Authenticate headers
5. Test with invalid token
6. Restart backend

### Validation
```bash
# Test after fix:
curl -s http://raglox.com/api/v1/missions \
  -H "Authorization: Bearer invalid-token-12345" | jq '.'

# Should return:
{
  "detail": "Invalid token: Signature verification failed"
}
```

---

## 🔴 Issue 2: Frontend Authorization Headers Missing

### Problem
From screenshot: Multiple API requests to `/approvals` endpoint are being sent **without Authorization headers**, resulting in 401 errors.

### Evidence from Screenshot
```
Request URL: http://raglox.com/api/v1/missions/6ef9d18c-.../approvals?poll=10
Status: 401 Unauthorized
Response Headers:
  - Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With
  - Content-Type: application/json

Missing:
  - Authorization: Bearer <token>
```

### Root Cause
Frontend API service is not attaching the auth token to polling requests.

**Likely Location**: `webapp/frontend/client/src/lib/api.ts`

The polling mechanism for mission updates/approvals is missing token attachment.

### Fix Required

**File**: `webapp/frontend/client/src/lib/api.ts`

```typescript
// Current Code (suspected):
async function pollApprovals(missionId: string) {
  const response = await fetch(
    `${API_URL}/missions/${missionId}/approvals?poll=10`
  );
  return response.json();
}

// Required Fix:
async function pollApprovals(missionId: string) {
  const token = getAuthToken(); // Get stored token
  if (!token) {
    throw new Error('Authentication required');
  }
  
  const response = await fetch(
    `${API_URL}/missions/${missionId}/approvals?poll=10`,
    {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    }
  );
  
  if (!response.ok) {
    if (response.status === 401) {
      // Token expired, redirect to login
      window.location.href = '/login';
    }
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }
  
  return response.json();
}
```

### Steps to Fix
1. Open `webapp/frontend/client/src/lib/api.ts`
2. Find all API request functions (search for `fetch(`)
3. Ensure ALL requests include Authorization header:
   ```typescript
   headers: {
     'Authorization': `Bearer ${authToken}`,
     'Content-Type': 'application/json'
   }
   ```
4. Add token validation before making requests
5. Handle 401 responses by redirecting to login
6. Rebuild frontend: `cd webapp/frontend && npm run build`
7. Test all API calls in browser DevTools

### Validation
1. Open browser DevTools > Network tab
2. Perform mission actions
3. Check ALL requests have `Authorization: Bearer <token>` header
4. No 401 errors should appear

---

## 🔴 Issue 3: Mission Execution & Firecracker VM Integration

### Problem
Mission failed with: "bluegaza.com has failed and currently has no active targets"

This suggests:
1. VM provisioning might have failed silently
2. Target scanning inside VM not working
3. VM tools (nmap, etc.) not available in rootfs

### Firecracker VM Architecture

```
┌─────────────────────────────────────────┐
│         RAGLOX Backend (Host)           │
│                                         │
│  ┌───────────────────────────────────┐ │
│  │   Mission Controller              │ │
│  │   - Creates mission               │ │
│  │   - Provisions VM (Firecracker)   │ │
│  │   - Executes tasks in VM          │ │
│  └─────────────┬─────────────────────┘ │
│                │                         │
│                ├──> Firecracker Client  │
│                │    (API: port 8080)    │
│                │                         │
└────────────────┼─────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│      Firecracker MicroVM Manager        │
│           (Port 8080)                   │
│                                         │
│  Creates VMs with:                      │
│  - Kernel: Linux kernel                 │
│  - rootfs: Ubuntu + Hacking Tools       │
│  - Network: TAP device (172.30.0.x)     │
│  - SSH: Accessible from backend         │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│         MicroVM (per user)              │
│         IP: 172.30.0.x                  │
│                                         │
│  Tools Installed:                       │
│  - nmap                                 │
│  - masscan                              │
│  - metasploit                           │
│  - nuclei                               │
│  - sqlmap                               │
│  - gobuster                             │
│  - nikto                                │
│  - Python 3 + libraries                 │
│                                         │
│  Mission Execution:                     │
│  1. Recon Specialist → nmap scan        │
│  2. Vuln Specialist → nuclei scan       │
│  3. Attack Specialist → exploit         │
└─────────────────────────────────────────┘
```

### Required Checks

#### 1. Verify Firecracker Manager is Running
```bash
# Check if Firecracker Manager API is accessible
curl -s http://208.115.230.194:8080/health || echo "Firecracker Manager not responding"

# Check VMs
curl -s http://208.115.230.194:8080/vms | jq '.'
```

#### 2. Verify VM Tools
```bash
# Get a test VM IP
VM_IP="172.30.0.2"  # From user metadata

# SSH into VM and check tools
ssh root@$VM_IP "nmap --version && nuclei --version && which metasploit"
```

#### 3. Test Mission Execution Flow
```bash
# Create test script
cat > /tmp/test_vm_mission.sh << 'TEST'
#!/bin/bash

echo "Testing VM Mission Execution"

# 1. Create test mission
TOKEN="<your_token>"
MISSION_RESPONSE=$(curl -s -X POST http://raglox.com/api/v1/missions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "VM Test Mission",
    "scope": ["8.8.8.8", "1.1.1.1"],
    "goals": ["reconnaissance"]
  }')

MISSION_ID=$(echo "$MISSION_RESPONSE" | jq -r '.mission_id')
echo "Mission ID: $MISSION_ID"

# 2. Start mission
curl -s -X POST "http://raglox.com/api/v1/missions/${MISSION_ID}/start" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# 3. Wait and check progress
sleep 30

# 4. Get mission details
curl -s "http://raglox.com/api/v1/missions/${MISSION_ID}" \
  -H "Authorization: Bearer $TOKEN" | jq '{
    status: .status,
    targets_discovered: .statistics.targets_discovered,
    vulns_found: .statistics.vulns_found
  }'

# 5. Check backend logs for VM execution
sudo journalctl -u raglox-backend -n 100 --no-pager | \
  grep -E "VM|ssh|nmap|scan|${MISSION_ID}"

TEST

bash /tmp/test_vm_mission.sh
```

### Expected VM Execution Flow

1. **Mission Start**:
   ```
   User starts mission → Backend checks VM status
   ```

2. **VM Provisioning** (if needed):
   ```
   Backend → Firecracker Manager API
   POST /vms/create
   {
     "user_id": "xxx",
     "cpu": 2,
     "memory": 1024,
     "rootfs": "raglox-hacking-tools-v1"
   }
   
   Response:
   {
     "vm_id": "xxx",
     "ip": "172.30.0.2",
     "status": "running",
     "ssh_port": 22
   }
   ```

3. **Task Execution**:
   ```
   Backend connects to VM via SSH (172.30.0.2:22)
   
   Executes:
   - Recon: nmap -sn 192.168.1.0/24
   - Scan: nmap -sV -p- target_ip
   - Vuln: nuclei -t cves/ -u http://target
   ```

4. **Results Collection**:
   ```
   VM returns scan results via SSH
   Backend parses results
   Stores in PostgreSQL
   Updates mission statistics
   ```

### Troubleshooting Steps

#### If VM Not Created:
```bash
# Check Firecracker Manager
curl http://208.115.230.194:8080/health

# Check backend VM creation logs
sudo journalctl -u raglox-backend -f | grep -i "VM\|firecracker"

# Manually create test VM
curl -X POST http://208.115.230.194:8080/vms/create \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "test-user-123",
    "cpu": 2,
    "memory": 1024,
    "rootfs": "raglox-tools"
  }'
```

#### If Tools Missing in VM:
```bash
# SSH into VM
VM_IP=$(curl -s http://raglox.com/api/v1/auth/me \
  -H "Authorization: Bearer $TOKEN" | jq -r '.vm_ip')

ssh root@$VM_IP

# Inside VM:
which nmap
which nuclei
which metasploit
python3 --version

# If tools missing, rootfs needs to be rebuilt
# Check with system admin for rootfs image
ls -lh /var/lib/firecracker/rootfs/
```

#### If SSH Fails:
```bash
# Test SSH connectivity
ssh -v root@172.30.0.2

# Check SSH keys
ls -la ~/.ssh/

# Backend should have SSH key for VM access
# Check: /opt/raglox/webapp/.ssh/ or /root/.ssh/
```

---

## 🔧 Quick Fix Commands

### Fix 1: Invalid Token Errors
```bash
cd /opt/raglox/webapp

# Backup
cp src/api/auth_routes.py src/api/auth_routes.py.backup

# Edit the file (add specific JWT exception handling)
# Then restart:
sudo systemctl restart raglox-backend
```

### Fix 2: Frontend Auth Headers
```bash
cd /opt/raglox/webapp/webapp/frontend

# Edit client/src/lib/api.ts
# Add Authorization headers to ALL fetch calls

# Rebuild
npm run build

# Nginx will serve new build automatically
```

### Fix 3: Test VM Mission
```bash
# Run comprehensive VM test
bash /tmp/test_vm_mission.sh

# Check results
sudo journalctl -u raglox-backend -n 200 | grep -i "nmap\|scan\|target"
```

---

## 📋 Priority Action Items

### Immediate (Today)
1. ✅ Fix invalid token error messages
2. ✅ Fix Frontend Authorization headers
3. ✅ Test VM mission execution end-to-end

### High Priority (This Week)
1. Document Firecracker integration fully
2. Create automated VM health checks
3. Add VM tool verification on startup
4. Improve error messages for mission failures

### Medium Priority
1. Add monitoring for VM resources
2. Implement VM auto-recovery
3. Add VM execution logs to UI
4. Create VM debugging tools

---

## 📞 Support Resources

### Documentation
- Firecracker Client: `src/infrastructure/cloud_provider/firecracker_client.py`
- VM Manager: `src/infrastructure/cloud_provider/vm_manager.py`
- Mission Controller: `src/controller/mission.py`
- Frontend API: `webapp/frontend/client/src/lib/api.ts`

### Logs
```bash
# Backend logs
sudo journalctl -u raglox-backend -f

# Nginx logs
tail -f /var/log/nginx/raglox_frontend_error.log
tail -f /var/log/nginx/raglox_api_error.log

# Check specific mission
sudo journalctl -u raglox-backend | grep "mission_id"
```

### Testing
```bash
# E2E tests
bash /tmp/e2e_full_test.sh

# VM-specific test
bash /tmp/test_vm_mission.sh

# Manual API test
curl -X POST http://raglox.com/api/v1/missions/{id}/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

---

## ✅ Success Criteria

### When Fixed:
- [ ] Invalid token returns specific error message
- [ ] All Frontend requests include Authorization header
- [ ] No 401 errors in browser DevTools
- [ ] Mission executes successfully with targets found
- [ ] VM is created and accessible
- [ ] Tools (nmap, nuclei) execute inside VM
- [ ] Results are collected and displayed
- [ ] E2E tests pass 100% (52/52)

---

**Status**: Requires Implementation  
**Priority**: HIGH  
**Estimated Time**: 2-4 hours  
**Complexity**: Medium  

---

**Next Steps**:
1. Implement Fix 1 (Token errors)
2. Implement Fix 2 (Frontend headers)
3. Test Fix 3 (VM mission execution)
4. Re-run E2E tests
5. Update documentation

---

**End of Critical Fixes Report**
