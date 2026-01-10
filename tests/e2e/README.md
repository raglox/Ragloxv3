# RAGLOX v3.0 - Phase 5.2 End-to-End Integration Testing

## 📋 Overview

This directory contains **End-to-End (E2E) Integration Tests** for RAGLOX v3.0. These tests validate complete mission lifecycles using real infrastructure (Redis, PostgreSQL, FAISS) and optionally real LLM (DeepSeek) and vulnerable Docker targets.

---

## 🎯 Test Missions

### **Mission 01 [EASY]: Web Reconnaissance & XSS**
- **File**: `test_mission_01_easy_web_recon.py`
- **Duration**: 10-15 minutes
- **Difficulty**: Easy
- **Objectives**:
  - Port scanning and service identification
  - Web application reconnaissance
  - XSS vulnerability discovery
  - XSS exploitation
- **Target**: `192.168.1.100` (DVWA)

### **Mission 02 [MEDIUM]: SQL Injection Exploitation**
- **File**: `test_mission_02_medium_sqli.py`
- **Duration**: 20-30 minutes
- **Difficulty**: Medium
- **Objectives**:
  - SQL injection vulnerability discovery
  - Database access via SQLi
  - Credential extraction
  - Database schema enumeration
- **Target**: `192.168.1.200` (Juice Shop)

### **Mission 03 [HARD]: Multi-Stage Pivot Attack**
- **File**: `test_mission_03_hard_pivot.py`
- **Duration**: 45-60 minutes
- **Difficulty**: Hard
- **Objectives**:
  - Initial RCE exploitation
  - Privilege escalation
  - Pivot to internal network
  - Lateral movement
  - Multi-target compromise
- **Targets**: `192.168.100.10`, `10.10.0.0/24`

### **Mission 04 [EXPERT]: Active Directory Takeover**
- **File**: `test_mission_04_expert_active_directory.py`
- **Duration**: 60-90 minutes
- **Difficulty**: Expert
- **Objectives**:
  - Initial domain foothold
  - Active Directory enumeration
  - Kerberoasting attack
  - Lateral movement across domain
  - Domain Admin privilege escalation
  - DCSync attack execution
  - Golden Ticket generation
  - Persistence mechanisms
- **Targets**: `192.168.200.50`, `corp.local`, `10.20.0.0/24`

---

## 🚀 Quick Start

### **1. Prerequisites**

```bash
# Ensure services are running
docker ps | grep redis     # Redis should be running
docker ps | grep postgres  # PostgreSQL should be running

# Check Python environment
python3 --version  # Should be 3.10+
pip list | grep pytest

# Optional: Docker for vulnerable targets
docker --version
docker-compose --version
```

### **2. Start Vulnerable Targets (Optional)**

```bash
# Start all E2E testing infrastructure
cd /opt/raglox/webapp
docker-compose -f docker-compose.e2e.yml up -d

# Verify targets are running
docker-compose -f docker-compose.e2e.yml ps

# Check target availability
curl http://localhost:8001  # Mission 01 - DVWA
curl http://localhost:8002  # Mission 02 - Juice Shop
curl http://localhost:8003  # Mission 03 - External Web
curl http://localhost:8004  # Mission 04 - Domain Web
```

### **3. Run Tests**

#### **Run All E2E Tests**
```bash
cd /opt/raglox/webapp
python3 -m pytest tests/e2e/ -v -s
```

#### **Run Specific Mission**
```bash
# Mission 01 (Easy)
pytest tests/e2e/test_mission_01_easy_web_recon.py -v -s

# Mission 02 (Medium)
pytest tests/e2e/test_mission_02_medium_sqli.py -v -s

# Mission 03 (Hard)
pytest tests/e2e/test_mission_03_hard_pivot.py -v -s

# Mission 04 (Expert)
pytest tests/e2e/test_mission_04_expert_active_directory.py -v -s
```

#### **Run by Difficulty Level**
```bash
# Easy tests only
pytest tests/e2e/ -m easy -v

# Medium tests
pytest tests/e2e/ -m medium -v

# Hard tests
pytest tests/e2e/ -m hard -v

# Expert tests
pytest tests/e2e/ -m expert -v
```

#### **Run with Real LLM (DeepSeek)**
```bash
# Set DeepSeek API key
export DEEPSEEK_API_KEY="your-api-key-here"

# Run tests that require real LLM
pytest tests/e2e/ -m real_llm -v
```

---

## 🔧 Configuration

### **Environment Variables**

```bash
# Required
export REDIS_URL="redis://localhost:6379/0"
export POSTGRES_URL="postgresql://test:test@localhost:54322/raglox_test"

# Optional - DeepSeek LLM
export DEEPSEEK_API_KEY="your-deepseek-api-key"

# Optional - Custom target IPs
export MISSION01_TARGET="192.168.1.100"
export MISSION02_TARGET="192.168.1.200"
export MISSION03_EXTERNAL="192.168.100.10"
export MISSION04_EXTERNAL="192.168.200.50"
```

### **Docker Compose Networks**

The `docker-compose.e2e.yml` creates three isolated networks:

1. **external_network** (`192.168.1.0/24`)
   - Simulated external/public network
   - Accessible from host
   - Mission 01, 02 targets

2. **internal_network** (`10.10.0.0/24`)
   - Simulated internal/DMZ network
   - Isolated (no external access)
   - Mission 03 internal targets

3. **domain_network** (`10.20.0.0/24`)
   - Simulated Active Directory domain
   - Isolated (no external access)
   - Mission 04 domain infrastructure

---

## 📊 Test Markers

Use pytest markers to filter tests:

```bash
# By test type
pytest tests/e2e/ -m e2e           # All E2E tests
pytest tests/e2e/ -m slow          # Slow tests (>60s)

# By difficulty
pytest tests/e2e/ -m easy          # Easy missions
pytest tests/e2e/ -m medium        # Medium missions
pytest tests/e2e/ -m hard          # Hard missions
pytest tests/e2e/ -m expert        # Expert missions

# By requirements
pytest tests/e2e/ -m real_llm      # Requires DeepSeek API
pytest tests/e2e/ -m real_infra    # Requires Docker targets
```

---

## 🧪 Test Fixtures

### **Core Fixtures** (from `conftest.py`)

- `settings`: RAGLOX settings configuration
- `blackboard`: Redis Blackboard connection
- `knowledge`: Loaded knowledge base
- `orchestrator`: AgentWorkflowOrchestrator instance
- `environment`: Complete test environment

### **Mission Data Fixtures**

- `easy_mission_data`: Mission 01 configuration
- `medium_mission_data`: Mission 02 configuration
- `hard_mission_data`: Mission 03 configuration
- `expert_mission_data`: Mission 04 configuration

### **Helper Functions**

```python
# Create mission objects
from tests.e2e.conftest import create_mission

mission = create_mission(easy_mission_data)

# Create targets/sessions/credentials
from tests.e2e.conftest import (
    create_target,
    create_session,
    create_credential,
    create_vulnerability
)

target = create_target(ip="192.168.1.100", hostname="web-server")
session = create_session("192.168.1.100", "www-data")
cred = create_credential("admin", "password123")

# Execute phases
from tests.e2e.conftest import execute_phase

result = await execute_phase(orchestrator, context, WorkflowPhase.RECONNAISSANCE)

# Validation helpers
from tests.e2e.conftest import (
    validate_mission_success,
    calculate_success_rate,
    assert_phase_success,
    assert_goal_achieved
)

assert_phase_success(result, "Reconnaissance")
assert_goal_achieved(mission, "Port Scanning Complete")
```

---

## 📈 Expected Results

### **Mission 01 [EASY]**
- ✅ Duration: 10-15 minutes
- ✅ Goals: 4/4 achieved
- ✅ Sessions: 1
- ✅ Vulnerabilities: 2+

### **Mission 02 [MEDIUM]**
- ✅ Duration: 20-30 minutes
- ✅ Goals: 4/4 achieved
- ✅ Sessions: 1
- ✅ Credentials: 3+

### **Mission 03 [HARD]**
- ✅ Duration: 45-60 minutes
- ✅ Goals: 6/6 achieved
- ✅ Sessions: 3+
- ✅ Credentials: 3+
- ✅ Lateral movements: 2+

### **Mission 04 [EXPERT]**
- ✅ Duration: 60-90 minutes
- ✅ Goals: 9/9 achieved
- ✅ Sessions: 4+
- ✅ Credentials: 3+ (including Domain Admin)
- ✅ DCSync: Successful
- ✅ Golden Ticket: Generated
- ✅ Persistence: 3+ mechanisms

---

## 🐛 Troubleshooting

### **Tests Fail: Redis Connection**
```bash
# Check Redis is running
redis-cli ping

# Start Redis if needed
redis-server --daemonize yes
```

### **Tests Fail: PostgreSQL Connection**
```bash
# Check PostgreSQL
psql -h localhost -p 54322 -U test -d raglox_test

# Verify connection string
export POSTGRES_URL="postgresql://test:test@localhost:54322/raglox_test"
```

### **Docker Targets Not Accessible**
```bash
# Check containers are running
docker-compose -f docker-compose.e2e.yml ps

# Restart infrastructure
docker-compose -f docker-compose.e2e.yml down
docker-compose -f docker-compose.e2e.yml up -d

# Check logs
docker-compose -f docker-compose.e2e.yml logs -f
```

### **Tests Timeout**
```bash
# Increase timeout for slow tests
pytest tests/e2e/ --timeout=300

# Skip slow tests
pytest tests/e2e/ -m "not slow"
```

### **DeepSeek API Errors**
```bash
# Verify API key
echo $DEEPSEEK_API_KEY

# Test API connectivity
curl -X POST https://api.deepseek.com/v1/chat/completions \
  -H "Authorization: Bearer $DEEPSEEK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"deepseek-chat","messages":[{"role":"user","content":"test"}]}'

# Skip LLM tests
pytest tests/e2e/ -m "not real_llm"
```

---

## 🧹 Cleanup

```bash
# Stop and remove all E2E infrastructure
docker-compose -f docker-compose.e2e.yml down -v

# Remove networks
docker network prune -f

# Clean up test data
rm -rf data/test_*
```

---

## 📝 Test Development

### **Adding New Mission Tests**

1. Create test file: `test_mission_XX_name.py`
2. Use fixtures from `conftest.py`
3. Add pytest markers: `@pytest.mark.e2e`, `@pytest.mark.easy/medium/hard/expert`
4. Follow mission structure:
   - Phase 0: Mission Creation
   - Phase 1: Initialization
   - Phase 2: Strategic Planning
   - Phase 3: Reconnaissance
   - Phase 4: Initial Access
   - Phase 5: Post-Exploitation
   - Phase 6: Lateral Movement (if needed)
   - Phase 7: Goal Achievement
   - Phase 8: Reporting
   - Final Validation

### **Example Test Structure**

```python
@pytest.mark.asyncio
@pytest.mark.e2e
@pytest.mark.easy
async def test_mission_XX(environment, easy_mission_data):
    """Test Mission XX: Description"""
    orchestrator = environment['orchestrator']
    blackboard = environment['blackboard']
    
    # Create mission
    mission = create_mission(easy_mission_data)
    
    # Start workflow
    context = await orchestrator.start_workflow(
        mission_id=mission.id,
        mission_goals=list(mission.goals.keys()),
        scope=mission.scope
    )
    
    # Execute phases
    result = await execute_phase(orchestrator, context, WorkflowPhase.INITIALIZATION)
    assert_phase_success(result, "Initialization")
    
    # ... more phases ...
    
    # Validate success
    assert validate_mission_success(mission)
```

---

## 📚 References

- **RAGLOX Documentation**: `/opt/raglox/webapp/docs/`
- **Phase 5.1 Report**: `PHASE5_1_WORKFLOW_ORCHESTRATOR_FINAL_100.md`
- **Phase 5.2 Plan**: `PHASE5_ADVANCED_FEATURES_PLAN.md`
- **API Documentation**: `src/api/main.py`

---

## 🎉 Success Criteria

Phase 5.2 E2E Testing is considered **COMPLETE** when:

- ✅ All 4 mission tests pass (Easy, Medium, Hard, Expert)
- ✅ 100% goal achievement across all missions
- ✅ Real infrastructure integration working (Redis, PostgreSQL, FAISS)
- ✅ Optional: DeepSeek LLM integration tested
- ✅ Optional: Docker vulnerable targets deployed and tested
- ✅ Complete documentation and reports generated

---

**Date**: 2026-01-10  
**Version**: RAGLOX v3.0 Phase 5.2  
**Status**: IN PROGRESS  
**Framework**: ZERO MOCKS - Real Infrastructure Only
