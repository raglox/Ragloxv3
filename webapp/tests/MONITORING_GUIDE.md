# 🔍 RAGLOX Intensive Tests - Monitoring Guide

## Current Status
- **Test Started:** $(date)
- **Process:** Running in background
- **Log File:** `tests/intensive_real_attack_tests.log`
- **Results File:** `tests/intensive_real_results.json` (created when complete)

## Quick Commands

### 1. Quick Status Check (Fastest)
```bash
cd /root/RAGLOX_V3/webapp/webapp
python3 tests/quick_status.py
```

### 2. Detailed Status
```bash
cd /root/RAGLOX_V3/webapp/webapp
./tests/monitor_intensive_tests.sh
```

### 3. Watch Live Log
```bash
cd /root/RAGLOX_V3/webapp/webapp
tail -f tests/intensive_real_attack_tests.log
```

### 4. Continuous Monitoring (Every 30s)
```bash
cd /root/RAGLOX_V3/webapp/webapp
./tests/watch_tests.sh
```

### 5. Check if Still Running
```bash
pgrep -f intensive_real_attack_tests.py
```

## Test Phases

The tests run through these phases:
1. 📡 **PHASE 1: RECONNAISSANCE**
   - Ping Sweep
   - Port Scan
   - Service Detection

2. 🔍 **PHASE 2: VULNERABILITY SCANNING**
   - Nuclei Scan
   - Nmap Vuln Scan

3. 🌐 **PHASE 3: WEB APPLICATION TESTING**
   - HTTP Analysis
   - Directory Enumeration

4. 🔐 **PHASE 4: SSH TESTING**
   - SSH Banner Grab

5. 🤖 **PHASE 5: AGENT INTEGRATION**
   - Agent Network Scan
   - Agent Port Scan
   - Agent LLM Analysis
   - Knowledge Base Integration

## Expected Timeline

- **PHASE 1 (RECON):** 2-5 minutes
- **PHASE 2 (VULN SCAN):** 3-10 minutes (Nuclei takes time)
- **PHASE 3 (WEB):** 1-2 minutes
- **PHASE 4 (SSH):** < 1 minute
- **PHASE 5 (AGENT):** 2-5 minutes

**Total Expected Time:** 10-25 minutes

## When Tests Complete

The results will be saved to:
- `tests/intensive_real_results.json` - Full JSON results
- `tests/intensive_real_attack_tests.log` - Detailed execution log

## View Final Results

```bash
cd /root/RAGLOX_V3/webapp/webapp
cat tests/intensive_real_results.json | python3 -m json.tool
```

Or use the quick status script:
```bash
python3 tests/quick_status.py
```

## Troubleshooting

### If Test Seems Stuck
Some commands (especially `nmap -sV -sC` and `nuclei`) can take several minutes. Check running processes:

```bash
ps aux | grep -E "(nmap|nuclei|python3.*intensive)" | grep -v grep
```

### If You Need to Stop Tests
```bash
pkill -f intensive_real_attack_tests.py
```

### If You Need to Restart
```bash
cd /root/RAGLOX_V3/webapp/webapp
pkill -f intensive_real_attack_tests.py
rm tests/intensive_real_attack_tests.log tests/intensive_real_results.json
nohup bash -c "PYTHONPATH=/root/RAGLOX_V3/webapp python3 tests/intensive_real_attack_tests.py > tests/intensive_real_attack_tests.log 2>&1" &
```

## Notes

- Tests are running against `raglox-vulnerable-target` container
- All tools are REAL (nmap, nuclei, hydra, netcat)
- No mock data is used
- Results include metrics on tool usage, execution time, and success rates
