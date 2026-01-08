# RAGLOX v3.0 - Test Suite Documentation

## 📚 Overview

This document provides comprehensive documentation for the RAGLOX v3.0 test suite, including test structure, execution instructions, and best practices for maintaining and extending the tests.

---

## 🗂️ Test Structure

### Test Files

```
tests/
├── test_auth_lazy_provisioning.py      # 11 tests - Lazy provisioning for auth
├── test_mission_lazy_execution.py      # 15 tests - Lazy execution for missions
├── test_integration_lazy_flow.py       # 2 tests - End-to-end integration
├── test_auth_routes_extended.py        # 35 tests - Auth routes comprehensive
├── test_user_repository_extended.py    # 43 tests - User repository comprehensive
└── README_TESTS.md                     # This file
```

**Total**: 106 tests

---

## 🚀 Running Tests

### Prerequisites

```bash
# Install dependencies
pip install pytest pytest-cov pytest-asyncio

# Ensure you're in the project root
cd /root/RAGLOX_V3/webapp
```

### Basic Test Execution

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_auth_routes_extended.py -v

# Run specific test
pytest tests/test_auth_routes_extended.py::test_login_successful_with_valid_credentials -v

# Run tests matching pattern
pytest tests/ -k "login" -v
```

### Coverage Reports

```bash
# Generate coverage for all source files
pytest tests/ --cov=src --cov-report=html --cov-report=term-missing -v

# Generate coverage for specific modules
pytest tests/ \
  --cov=src.api.auth_routes \
  --cov=src.controller.mission \
  --cov=src.core.database.user_repository \
  --cov-report=html \
  --cov-report=json \
  --cov-report=term-missing \
  -v

# View HTML coverage report
# Open htmlcov/index.html in browser
```

### Advanced Options

```bash
# Run with verbose output and show print statements
pytest tests/ -v -s

# Run with short traceback
pytest tests/ -v --tb=short

# Run only failed tests from last run
pytest tests/ --lf -v

# Run tests in parallel (requires pytest-xdist)
pytest tests/ -n auto -v

# Stop on first failure
pytest tests/ -x -v
```

---

## 📋 Test Categories

### 1. Lazy Provisioning Tests

**Files**: 
- `test_auth_lazy_provisioning.py` (11 tests)
- `test_mission_lazy_execution.py` (15 tests)
- `test_integration_lazy_flow.py` (2 tests)

**Purpose**: Test the lazy provisioning feature where VMs are created on-demand

**Key Scenarios**:
- User registration without immediate VM creation
- VM status detection (not_created, stopped, ready)
- Automatic provisioning on first command
- Simulation mode during provisioning
- VM wake-up from stopped state

**Example**:
```python
@pytest.mark.asyncio
async def test_execute_command_not_created_starts_provisioning(
    mission_controller, mock_user_repo, mock_vm_manager
):
    """Test that executing command with not_created VM starts provisioning."""
    # Arrange: User with no VM
    user = create_mock_user(vm_status="not_created")
    
    # Act: Execute command
    result = await mission_controller.execute_command(
        mission_id="test-mission",
        command="ls -la"
    )
    
    # Assert: Provisioning started
    assert result["status"] == "provisioning"
    mock_vm_manager.provision_vm.assert_called_once()
```

### 2. Authentication & Authorization Tests

**File**: `test_auth_routes_extended.py` (35 tests)

**Purpose**: Comprehensive testing of authentication and authorization flows

**Categories**:
- **Login/Logout** (8 tests): Credentials validation, session management
- **Password Management** (6 tests): Change, reset, token validation
- **Token Management** (6 tests): JWT creation, validation, expiry, Redis storage
- **Profile Management** (4 tests): User info retrieval, profile updates
- **Admin Operations** (8 tests): User CRUD, role management, organization isolation
- **Security** (3 tests): Account locking, inactive accounts, organization boundaries

**Example**:
```python
@pytest.mark.asyncio
async def test_login_account_locking_after_5_failed_attempts(
    auth_routes, mock_user_repo
):
    """Test account locks after 5 failed login attempts."""
    # Arrange: User with 4 failed attempts
    user = create_mock_user(login_attempts=4)
    mock_user_repo.get_by_email_global.return_value = user
    
    # Act: 5th failed attempt
    response = await auth_routes.login({
        "email": "test@example.com",
        "password": "wrong_password"
    })
    
    # Assert: Account locked
    assert response["error"] == "account_locked"
    assert user.locked_until is not None
```

### 3. User Repository Tests

**File**: `test_user_repository_extended.py` (43 tests)

**Purpose**: Test database operations for user management

**Categories**:
- **CRUD Operations** (12 tests): Create, read, update, delete users
- **Authentication** (8 tests): Login tracking, failed attempts, password management
- **Email Verification** (4 tests): Token generation, verification, validation
- **Role Management** (4 tests): Role updates, validation, queries
- **Metadata Management** (6 tests): VM metadata, custom fields, persistence
- **Organization Management** (6 tests): User listing, transfer, isolation
- **Entity Methods** (3 tests): Helper methods, data serialization

**Example**:
```python
@pytest.mark.asyncio
async def test_update_vm_metadata_status_id_ip(
    user_repo, mock_pool, sample_user_data
):
    """Test updating VM metadata with vm_status, vm_id, vm_ip."""
    # Arrange
    user_id = sample_user_data["id"]
    vm_metadata = {
        "vm_status": "running",
        "vm_id": "vm-12345",
        "vm_ip": "10.0.0.5"
    }
    
    # Act
    result = await user_repo.update(user_id, {"metadata": vm_metadata})
    
    # Assert
    assert result.metadata["vm_status"] == "running"
    assert result.metadata["vm_id"] == "vm-12345"
```

---

## 🔧 Test Fixtures

### Common Fixtures

#### 1. Mock Database Pool
```python
@pytest.fixture
def mock_pool():
    """Mock database connection pool."""
    pool = MagicMock()
    pool.fetchrow = AsyncMock()
    pool.fetch = AsyncMock()
    pool.fetchval = AsyncMock()
    pool.execute = AsyncMock()
    return pool
```

#### 2. Sample User Data
```python
@pytest.fixture
def sample_user_data() -> Dict[str, Any]:
    """Sample user data for testing."""
    return {
        "id": uuid4(),
        "email": "test@example.com",
        "username": "testuser",
        "password_hash": "$2b$12$hashed_password",
        "organization_id": uuid4(),
        "role": "operator",
        "is_active": True,
        "metadata": {},
        "created_at": datetime.utcnow()
    }
```

#### 3. Sample User Entity
```python
@pytest.fixture
def sample_user(sample_user_data) -> User:
    """Sample User entity."""
    return User(**sample_user_data)
```

### Fixture Scope

- **Function scope** (default): New instance for each test
- **Class scope**: Shared across test class
- **Module scope**: Shared across test file
- **Session scope**: Shared across entire test session

---

## 🎭 Mocking Strategy

### 1. Database Mocking

```python
# Mock database pool
mock_pool = MagicMock()
mock_pool.fetchrow = AsyncMock(return_value=user_data)

# Mock repository
mock_user_repo = MagicMock()
mock_user_repo.get_by_email = AsyncMock(return_value=user)
```

### 2. External Service Mocking

```python
# Mock VM manager
mock_vm_manager = MagicMock()
mock_vm_manager.provision_vm = AsyncMock(return_value={
    "vm_id": "vm-123",
    "status": "creating"
})

# Mock Redis
mock_redis = MagicMock()
mock_redis.get = AsyncMock(return_value=None)
mock_redis.setex = AsyncMock()
```

### 3. Time Mocking

```python
from unittest.mock import patch
from datetime import datetime, timedelta

# Mock datetime
with patch('module.datetime') as mock_datetime:
    mock_datetime.utcnow.return_value = datetime(2024, 1, 1)
    # Test code here
```

---

## ✅ Test Best Practices

### 1. Test Structure (AAA Pattern)

```python
@pytest.mark.asyncio
async def test_example():
    # Arrange: Set up test data and mocks
    user = create_mock_user()
    mock_repo.get.return_value = user
    
    # Act: Execute the code being tested
    result = await service.process_user(user.id)
    
    # Assert: Verify the results
    assert result.status == "success"
    mock_repo.get.assert_called_once_with(user.id)
```

### 2. Test Naming Convention

```python
# Pattern: test_<function>_<scenario>_<expected_result>
test_login_with_valid_credentials_returns_token()
test_login_with_invalid_password_returns_error()
test_login_with_locked_account_returns_locked_error()
```

### 3. Test Independence

```python
# ❌ Bad: Tests depend on each other
def test_create_user():
    global user_id
    user_id = create_user()

def test_update_user():
    update_user(user_id)  # Depends on previous test

# ✅ Good: Each test is independent
def test_create_user():
    user_id = create_user()
    assert user_id is not None

def test_update_user():
    user_id = create_user()  # Create own test data
    result = update_user(user_id)
    assert result.success
```

### 4. Async Test Handling

```python
# Always use @pytest.mark.asyncio for async tests
@pytest.mark.asyncio
async def test_async_function():
    result = await async_function()
    assert result is not None

# Use AsyncMock for async mocks
mock_function = AsyncMock(return_value="result")
```

### 5. Exception Testing

```python
# Test expected exceptions
@pytest.mark.asyncio
async def test_invalid_input_raises_error():
    with pytest.raises(ValueError, match="Invalid input"):
        await function_that_raises("invalid")
```

---

## 🐛 Debugging Tests

### 1. Print Debugging

```bash
# Run with print statements visible
pytest tests/test_file.py -v -s
```

### 2. Breakpoint Debugging

```python
# Add breakpoint in test
@pytest.mark.asyncio
async def test_example():
    user = create_user()
    breakpoint()  # Execution stops here
    result = await process(user)
```

### 3. Verbose Output

```bash
# Show full diff on assertion failures
pytest tests/ -vv

# Show local variables on failure
pytest tests/ -l
```

### 4. Failed Test Rerun

```bash
# Rerun only failed tests
pytest tests/ --lf

# Rerun failed tests first, then all
pytest tests/ --ff
```

---

## 📊 Coverage Analysis

### Understanding Coverage Reports

```
Name                                   Stmts   Miss Branch BrPart  Cover
------------------------------------------------------------------------
src/api/auth_routes.py                   418     68    100     33    79%
src/controller/mission.py                756    537    240     14    27%
src/core/database/user_repository.py     135     20     16      3    85%
```

**Metrics**:
- **Stmts**: Total statements
- **Miss**: Uncovered statements
- **Branch**: Total branches (if/else, etc.)
- **BrPart**: Partially covered branches
- **Cover**: Overall coverage percentage

### Viewing HTML Coverage

```bash
# Generate HTML report
pytest tests/ --cov=src --cov-report=html

# Open in browser
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
start htmlcov/index.html  # Windows
```

### Coverage Targets

- **Critical modules**: 85%+ coverage
- **Business logic**: 80%+ coverage
- **Utility functions**: 70%+ coverage
- **Overall project**: 70%+ coverage

---

## 🔄 Adding New Tests

### 1. Create Test File

```python
# tests/test_new_feature.py
"""
Tests for new feature.

Test Categories:
1. Basic functionality (5 tests)
2. Edge cases (3 tests)
3. Error handling (2 tests)
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

# Import module to test
from src.module import NewFeature
```

### 2. Add Fixtures

```python
@pytest.fixture
def new_feature():
    """Create NewFeature instance for testing."""
    return NewFeature(config={"setting": "value"})

@pytest.fixture
def mock_dependency():
    """Mock external dependency."""
    mock = MagicMock()
    mock.method = AsyncMock(return_value="result")
    return mock
```

### 3. Write Tests

```python
@pytest.mark.asyncio
async def test_new_feature_basic_functionality(new_feature, mock_dependency):
    """Test basic functionality of new feature."""
    # Arrange
    input_data = {"key": "value"}
    
    # Act
    result = await new_feature.process(input_data)
    
    # Assert
    assert result.success is True
    assert result.data == expected_data
```

### 4. Run and Verify

```bash
# Run new tests
pytest tests/test_new_feature.py -v

# Check coverage
pytest tests/test_new_feature.py --cov=src.module --cov-report=term-missing -v
```

---

## 🎯 Test Maintenance

### Regular Tasks

1. **Run full test suite** before commits
   ```bash
   pytest tests/ -v
   ```

2. **Update tests** when changing code
   - Modify tests to match new behavior
   - Add tests for new features
   - Remove tests for removed features

3. **Review coverage** regularly
   ```bash
   pytest tests/ --cov=src --cov-report=html
   ```

4. **Refactor tests** when needed
   - Extract common setup to fixtures
   - Remove duplicate test code
   - Improve test names and documentation

### CI/CD Integration

```yaml
# Example GitHub Actions workflow
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests
        run: pytest tests/ --cov=src --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v2
```

---

## 📚 Additional Resources

### Documentation
- [pytest documentation](https://docs.pytest.org/)
- [pytest-async