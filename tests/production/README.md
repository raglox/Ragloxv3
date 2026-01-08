# RAGLOX V3 - Production Testing Infrastructure

This directory contains the infrastructure and tests for production-like testing of RAGLOX V3.

## 📋 Overview

The production testing infrastructure provides:
- **Real Infrastructure**: PostgreSQL, Redis, API (no mocks)
- **Test Targets**: DVWA, WebGoat, Juice Shop, Nginx
- **Isolated Network**: Separate network for test targets
- **Automated Setup**: Scripts to start/stop/verify infrastructure

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   raglox-test-network                       │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │  PostgreSQL  │  │    Redis     │  │  RAGLOX API  │    │
│  │   :5433      │  │    :6380     │  │    :8001     │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                            │                │
└────────────────────────────────────────────┼────────────────┘
                                             │
                         ┌───────────────────┴────────────────────┐
                         │      test-target-network               │
                         │      192.168.100.0/24                  │
                         │                                        │
                         │  ┌──────────────┐  ┌──────────────┐  │
                         │  │     DVWA     │  │   WebGoat    │  │
                         │  │ .100.10:8080 │  │ .100.11:8081 │  │
                         │  └──────────────┘  └──────────────┘  │
                         │                                        │
                         │  ┌──────────────┐  ┌──────────────┐  │
                         │  │  Juice Shop  │  │    Nginx     │  │
                         │  │ .100.12:8082 │  │ .100.13:8083 │  │
                         │  └──────────────┘  └──────────────┘  │
                         └────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

1. **Docker & Docker Compose**
   ```bash
   # Check Docker is installed
   docker --version
   docker-compose --version
   ```

2. **OpenAI API Key** (optional, for LLM tests)
   ```bash
   export OPENAI_API_KEY="sk-your-key-here"
   ```

### Setup Infrastructure

```bash
# From the webapp directory
cd /root/RAGLOX_V3/webapp

# Run setup script
./tests/production/setup-infrastructure.sh
```

The script will:
- ✅ Check Docker installation
- ✅ Start all services
- ✅ Wait for health checks
- ✅ Verify connectivity
- ✅ Show status and access points

### Access Points

Once started, services are available at:

| Service | URL | Credentials |
|---------|-----|-------------|
| PostgreSQL | `localhost:5433` | User: `raglox_test`<br>Pass: `test_password_secure_123`<br>DB: `raglox_test_production` |
| Redis | `localhost:6380` | No password |
| RAGLOX API | http://localhost:8001 | Register via API |
| DVWA | http://localhost:8080 | admin/password |
| WebGoat | http://localhost:8081/WebGoat | Register in app |
| Juice Shop | http://localhost:8082 | Register in app |
| Nginx | http://localhost:8083 | No auth |

## 🧪 Running Tests

### 1. Integration Tests
Test component interactions with real services:

```bash
# Run all integration tests
pytest tests/production/ -m "production and integration" -v

# Run specific integration test
pytest tests/production/test_integration_real.py::TestProductionIntegration::test_user_registration_real_database -v
```

### 2. End-to-End Tests
Test complete workflows:

```bash
# Run all E2E tests
pytest tests/production/ -m "production and e2e" -v

# Run specific E2E test
pytest tests/production/test_e2e_real.py::TestProductionE2E::test_complete_reconnaissance_mission -v
```

### 3. Performance Tests
Test system under load:

```bash
pytest tests/production/ -m "production and performance" -v
```

### 4. Security Tests
Test security measures:

```bash
pytest tests/production/ -m "production and security" -v
```

### 5. Chaos Tests
Test failure recovery:

```bash
pytest tests/production/ -m "production and chaos" -v
```

### Run All Production Tests
```bash
pytest tests/production/ -m production -v --timeout=3600
```

## 📊 Test Markers

Tests are organized using pytest markers:

| Marker | Description | Example |
|--------|-------------|---------|
| `production` | All production tests | `@pytest.mark.production` |
| `integration` | Integration tests | `@pytest.mark.integration` |
| `e2e` | End-to-end tests | `@pytest.mark.e2e` |
| `performance` | Performance tests | `@pytest.mark.performance` |
| `security` | Security tests | `@pytest.mark.security` |
| `chaos` | Chaos tests | `@pytest.mark.chaos` |
| `slow` | Tests >1 minute | `@pytest.mark.slow` |

## 🔧 Configuration

### Environment Variables

Configuration is in `.env.test`:

```bash
# Database
DATABASE_HOST=localhost
DATABASE_PORT=5433
DATABASE_NAME=raglox_test_production
DATABASE_USER=raglox_test
DATABASE_PASSWORD=test_password_secure_123

# Redis
REDIS_HOST=localhost
REDIS_PORT=6380
REDIS_DB=0

# API
API_HOST=localhost
API_PORT=8001

# LLM
LLM_ENABLED=true
LLM_PROVIDER=openai
LLM_MODEL=gpt-3.5-turbo
OPENAI_API_KEY=sk-your-key-here

# Test Targets
TEST_TARGET_DVWA=192.168.100.10
TEST_TARGET_WEBGOAT=192.168.100.11
TEST_TARGET_JUICESHOP=192.168.100.12
TEST_TARGET_NGINX=192.168.100.13
```

### Python Configuration

Use `ProductionTestConfig` in tests:

```python
from tests.production import get_config

config = get_config()
print(config.api_base_url)  # http://localhost:8001
print(config.database_url)  # postgresql://...
print(config.test_target_hosts)  # ['192.168.100.10', ...]
```

## 🛠️ Management Commands

### Start Infrastructure
```bash
docker-compose -f docker-compose.test-production.yml up -d
```

### Stop Infrastructure
```bash
docker-compose -f docker-compose.test-production.yml down
```

### Stop and Remove Volumes
```bash
docker-compose -f docker-compose.test-production.yml down -v
```

### View Logs
```bash
# All services
docker-compose -f docker-compose.test-production.yml logs -f

# Specific service
docker-compose -f docker-compose.test-production.yml logs -f raglox-api-test
```

### Check Status
```bash
docker-compose -f docker-compose.test-production.yml ps
```

### Restart Service
```bash
docker-compose -f docker-compose.test-production.yml restart raglox-api-test
```

## 🐛 Troubleshooting

### Issue: Services not starting

**Solution:**
```bash
# Check Docker is running
docker info

# Check for port conflicts
netstat -an | grep -E "5433|6380|8001|8080|8081|8082|8083"

# Check logs
docker-compose -f docker-compose.test-production.yml logs
```

### Issue: Database connection failed

**Solution:**
```bash
# Check PostgreSQL is healthy
docker exec raglox-postgres-test pg_isready -U raglox_test

# Test connection manually
docker exec raglox-postgres-test psql -U raglox_test -d raglox_test_production -c "SELECT 1"

# Check logs
docker-compose -f docker-compose.test-production.yml logs postgres-test
```

### Issue: API not responding

**Solution:**
```bash
# Check API health
curl http://localhost:8001/health

# Check API logs
docker-compose -f docker-compose.test-production.yml logs raglox-api-test

# Restart API
docker-compose -f docker-compose.test-production.yml restart raglox-api-test
```

### Issue: Test targets not accessible

**Solution:**
```bash
# Check containers are running
docker-compose -f docker-compose.test-production.yml ps

# Test DVWA
curl http://localhost:8080

# Check network connectivity
docker network ls
docker network inspect test-target-network
```

## 📈 Monitoring

### View Resource Usage
```bash
docker stats
```

### View Network Info
```bash
docker network inspect raglox-test-network
docker network inspect test-target-network
```

### Check Database Size
```bash
docker exec raglox-postgres-test psql -U raglox_test -d raglox_test_production -c "SELECT pg_size_pretty(pg_database_size('raglox_test_production'))"
```

### Check Redis Memory
```bash
docker exec raglox-redis-test redis-cli INFO memory
```

## 🧹 Cleanup

### Clean Test Data
```bash
# Truncate database tables
docker exec raglox-postgres-test psql -U raglox_test -d raglox_test_production -c "TRUNCATE TABLE missions, users, organizations CASCADE"

# Flush Redis
docker exec raglox-redis-test redis-cli FLUSHDB
```

### Clean Docker Resources
```bash
# Stop and remove containers
docker-compose -f docker-compose.test-production.yml down

# Remove volumes
docker-compose -f docker-compose.test-production.yml down -v

# Remove images (optional)
docker-compose -f docker-compose.test-production.yml down --rmi all
```

## 📚 Additional Resources

- **Docker Compose File**: `docker-compose.test-production.yml`
- **Test Configuration**: `config.py`
- **Base Test Classes**: `base.py` (to be created in Week 2)
- **Setup Script**: `setup-infrastructure.sh`

## 🎯 Next Steps

1. ✅ **Week 1**: Infrastructure setup (current)
2. ⏳ **Week 2**: Create base classes and integration tests
3. ⏳ **Week 3**: Write E2E tests
4. ⏳ **Week 4**: Add performance and security tests
5. ⏳ **Week 5**: Implement chaos tests and monitoring
6. ⏳ **Week 6**: Set up CI/CD and documentation

## ❓ Support

For issues or questions:
1. Check the troubleshooting section above
2. Review logs: `docker-compose logs`
3. Check Docker status: `docker ps`
4. Verify network: `docker network inspect test-target-network`

---

**Status**: Week 1 Complete - Infrastructure Ready ✅
