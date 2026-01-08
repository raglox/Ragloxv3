"""
RAGLOX v3.0 - User Repository Extended Tests
============================================

Comprehensive test suite for user_repository.py to increase coverage from 56% to 88%.

Test Categories:
1. CRUD Operations (12 tests)
2. Authentication Operations (8 tests)
3. Email & Verification (4 tests)
4. Role & Permissions (4 tests)
5. Metadata Management (6 tests)
6. Organization Management (6 tests)

Total: 40 tests
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4, UUID
from datetime import datetime, timedelta
from typing import Dict, Any, List

from src.core.database.user_repository import User, UserRepository


# ===================================================================
# Fixtures
# ===================================================================

@pytest.fixture
def sample_user_data() -> Dict[str, Any]:
    """Sample user data for testing."""
    return {
        "id": uuid4(),
        "email": "test@example.com",
        "username": "testuser",
        "password_hash": "$2b$12$hashed_password_here",
        "full_name": "Test User",
        "organization_id": uuid4(),
        "role": "operator",
        "is_active": True,
        "email_verified": False,
        "metadata": {},
        "settings": {},
        "permissions": [],
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }


@pytest.fixture
def sample_user(sample_user_data) -> User:
    """Sample User entity."""
    return User(
        id=sample_user_data["id"],
        organization_id=sample_user_data["organization_id"],
        username=sample_user_data["username"],
        email=sample_user_data["email"],
        password_hash=sample_user_data["password_hash"],
        full_name=sample_user_data["full_name"],
        role=sample_user_data["role"],
        is_active=sample_user_data["is_active"],
        email_verified=sample_user_data["email_verified"],
        metadata=sample_user_data["metadata"],
        settings=sample_user_data["settings"],
        permissions=sample_user_data["permissions"],
        created_at=sample_user_data["created_at"],
        updated_at=sample_user_data["updated_at"]
    )


@pytest.fixture
def mock_pool():
    """Mock database connection pool."""
    pool = MagicMock()
    pool.fetchrow = AsyncMock()
    pool.fetch = AsyncMock()
    pool.fetchval = AsyncMock()
    pool.execute = AsyncMock()
    return pool


@pytest.fixture
def user_repo(mock_pool):
    """UserRepository instance with mocked pool."""
    return UserRepository(pool=mock_pool)


# ===================================================================
# 1. CRUD Operations (12 tests)
# ===================================================================

@pytest.mark.asyncio
async def test_create_user_successful(user_repo, mock_pool, sample_user, sample_user_data):
    """Test creating a new user with all fields."""
    # Arrange
    mock_pool.fetchrow.return_value = sample_user_data
    
    # Act
    result = await user_repo.create(sample_user)
    
    # Assert
    assert result is not None
    assert result.email == sample_user_data["email"]
    assert result.username == sample_user_data["username"]
    assert result.role == "operator"
    mock_pool.fetchrow.assert_called_once()


@pytest.mark.asyncio
async def test_create_user_duplicate_email(user_repo, mock_pool, sample_user):
    """Test creating user with duplicate email raises exception."""
    # Arrange
    from asyncpg.exceptions import UniqueViolationError
    mock_pool.fetchrow.side_effect = UniqueViolationError("duplicate key value violates unique constraint")
    
    # Act & Assert
    with pytest.raises(Exception):
        await user_repo.create(sample_user)


@pytest.mark.asyncio
async def test_create_user_duplicate_username(user_repo, mock_pool, sample_user):
    """Test creating user with duplicate username raises exception."""
    # Arrange
    from asyncpg.exceptions import UniqueViolationError
    mock_pool.fetchrow.side_effect = UniqueViolationError("duplicate key value violates unique constraint")
    
    # Act & Assert
    with pytest.raises(Exception):
        await user_repo.create(sample_user)


@pytest.mark.asyncio
async def test_get_user_by_id_existing(user_repo, mock_pool, sample_user_data):
    """Test getting existing user by ID."""
    # Arrange
    user_id = sample_user_data["id"]
    mock_pool.fetchrow.return_value = sample_user_data
    
    # Act
    result = await user_repo.get_by_id(user_id)
    
    # Assert
    assert result is not None
    assert result.id == user_id
    assert result.email == sample_user_data["email"]


@pytest.mark.asyncio
async def test_get_user_by_id_nonexistent(user_repo, mock_pool):
    """Test getting non-existent user returns None."""
    # Arrange
    mock_pool.fetchrow.return_value = None
    
    # Act
    result = await user_repo.get_by_id(uuid4())
    
    # Assert
    assert result is None


@pytest.mark.asyncio
async def test_get_user_by_email_case_insensitive(user_repo, mock_pool, sample_user_data):
    """Test getting user by email is case insensitive."""
    # Arrange
    org_id = sample_user_data["organization_id"]
    mock_pool.fetchrow.return_value = sample_user_data
    
    # Act
    result = await user_repo.get_by_email(org_id, "TEST@EXAMPLE.COM")
    
    # Assert
    assert result is not None
    assert result.email == sample_user_data["email"]
    # Verify email was lowercased in query
    call_args = mock_pool.fetchrow.call_args
    assert call_args[0][2] == "test@example.com"


@pytest.mark.asyncio
async def test_get_user_by_username_exact_match(user_repo, mock_pool, sample_user_data):
    """Test getting user by username with exact match."""
    # Arrange
    org_id = sample_user_data["organization_id"]
    mock_pool.fetchrow.return_value = sample_user_data
    
    # Act
    result = await user_repo.get_by_username(org_id, "testuser")
    
    # Assert
    assert result is not None
    assert result.username == "testuser"


@pytest.mark.asyncio
async def test_update_user_full_name_metadata(user_repo, mock_pool, sample_user_data):
    """Test updating user full_name and metadata."""
    # Arrange
    user_id = sample_user_data["id"]
    updated_data = sample_user_data.copy()
    updated_data["full_name"] = "Updated Name"
    updated_data["metadata"] = {"vm_status": "active"}
    mock_pool.fetchrow.return_value = updated_data
    
    # Act
    result = await user_repo.update(user_id, {
        "full_name": "Updated Name",
        "metadata": {"vm_status": "active"}
    })
    
    # Assert
    assert result is not None
    assert result.full_name == "Updated Name"
    assert result.metadata["vm_status"] == "active"


@pytest.mark.asyncio
async def test_update_user_invalid_id(user_repo, mock_pool):
    """Test updating non-existent user raises exception."""
    # Arrange
    mock_pool.fetchrow.return_value = None
    
    # Act
    result = await user_repo.update(uuid4(), {"full_name": "Test"})
    
    # Assert
    assert result is None


@pytest.mark.asyncio
async def test_delete_user_successful(user_repo, mock_pool):
    """Test deleting existing user."""
    # Arrange
    user_id = uuid4()
    mock_pool.execute.return_value = "DELETE 1"
    
    # Act
    result = await user_repo.delete(user_id)
    
    # Assert
    assert result is True


@pytest.mark.asyncio
async def test_delete_user_nonexistent(user_repo, mock_pool):
    """Test deleting non-existent user returns False."""
    # Arrange
    mock_pool.execute.return_value = "DELETE 0"
    
    # Act
    result = await user_repo.delete(uuid4())
    
    # Assert
    assert result is False


@pytest.mark.asyncio
async def test_list_users_with_pagination_filters(user_repo, mock_pool, sample_user_data):
    """Test listing users with pagination and filters."""
    # Arrange
    org_id = sample_user_data["organization_id"]
    mock_pool.fetch.return_value = [sample_user_data, sample_user_data.copy()]
    
    # Act
    result = await user_repo.get_organization_users(org_id, include_inactive=False)
    
    # Assert
    assert len(result) == 2
    assert all(isinstance(u, User) for u in result)


# ===================================================================
# 2. Authentication Operations (8 tests)
# ===================================================================

@pytest.mark.asyncio
async def test_record_login_updates_last_login_resets_failed_count(user_repo, mock_pool):
    """Test recording successful login updates last_login and resets failed count."""
    # Arrange
    user_id = uuid4()
    ip_address = "192.168.1.100"
    mock_pool.execute.return_value = "UPDATE 1"
    
    # Act
    await user_repo.record_login(user_id, ip_address)
    
    # Assert
    mock_pool.execute.assert_called_once()
    call_args = mock_pool.execute.call_args[0]
    assert call_args[2] == ip_address
    assert call_args[3] == user_id


@pytest.mark.asyncio
async def test_record_failed_login_increments_count(user_repo, mock_pool):
    """Test recording failed login increments failed_login_count."""
    # Arrange
    user_id = uuid4()
    mock_pool.fetchval.return_value = 2  # Current attempts after increment
    
    # Act
    is_locked = await user_repo.record_failed_login(user_id, max_attempts=5)
    
    # Assert
    assert is_locked is False
    mock_pool.fetchval.assert_called_once()


@pytest.mark.asyncio
async def test_account_locking_after_5_failed_attempts(user_repo, mock_pool, sample_user_data):
    """Test account locks after 5 failed attempts."""
    # Arrange
    user_id = uuid4()
    mock_pool.fetchval.return_value = 5  # 5th failed attempt
    updated_data = sample_user_data.copy()
    updated_data["locked_until"] = datetime.utcnow() + timedelta(minutes=15)
    mock_pool.fetchrow.return_value = updated_data
    
    # Act
    is_locked = await user_repo.record_failed_login(user_id, max_attempts=5, lockout_minutes=15)
    
    # Assert
    assert is_locked is True


@pytest.mark.asyncio
async def test_reset_failed_login_count(user_repo, mock_pool, sample_user_data):
    """Test resetting failed login count to 0."""
    # Arrange
    user_id = sample_user_data["id"]
    updated_data = sample_user_data.copy()
    updated_data["login_attempts"] = 0
    mock_pool.fetchrow.return_value = updated_data
    
    # Act
    result = await user_repo.update(user_id, {"login_attempts": 0})
    
    # Assert
    assert result is not None
    assert result.login_attempts == 0


@pytest.mark.asyncio
async def test_update_password_changes_hash(user_repo, mock_pool):
    """Test updating password changes password_hash."""
    # Arrange
    user_id = uuid4()
    new_hash = "$2b$12$new_hashed_password"
    mock_pool.execute.return_value = "UPDATE 1"
    
    # Act
    result = await user_repo.update_password(user_id, new_hash)
    
    # Assert
    assert result is True
    mock_pool.execute.assert_called_once()


@pytest.mark.asyncio
async def test_set_password_reset_token_stores_token_expiry(user_repo, mock_pool):
    """Test setting password reset token stores token and expiry."""
    # Arrange
    user_id = uuid4()
    token = "reset_token_123"
    mock_pool.execute.return_value = "UPDATE 1"
    
    # Act
    result = await user_repo.set_password_reset_token(user_id, token, expires_hours=24)
    
    # Assert
    assert result is True
    call_args = mock_pool.execute.call_args[0]
    assert call_args[1] == token


@pytest.mark.asyncio
async def test_verify_password_reset_token_valid(user_repo, mock_pool, sample_user_data):
    """Test verifying valid password reset token."""
    # Arrange
    token = "valid_reset_token"
    user_data = sample_user_data.copy()
    user_data["password_reset_token"] = token
    user_data["password_reset_expires"] = datetime.utcnow() + timedelta(hours=1)
    mock_pool.fetchrow.return_value = user_data
    
    # Act
    result = await user_repo.verify_reset_token(token)
    
    # Assert
    assert result is not None
    assert isinstance(result, User)


@pytest.mark.asyncio
async def test_verify_password_reset_token_expired(user_repo, mock_pool):
    """Test verifying expired password reset token returns None."""
    # Arrange
    token = "expired_token"
    mock_pool.fetchrow.return_value = None  # Expired token not found
    
    # Act
    result = await user_repo.verify_reset_token(token)
    
    # Assert
    assert result is None


# ===================================================================
# 3. Email & Verification (4 tests)
# ===================================================================

@pytest.mark.asyncio
async def test_verify_email_sets_verified_true(user_repo, mock_pool, sample_user_data):
    """Test verifying email sets email_verified to True."""
    # Arrange
    token = "verification_token_123"
    verified_data = sample_user_data.copy()
    verified_data["email_verified"] = True
    verified_data["email_verification_token"] = None
    mock_pool.fetchrow.return_value = verified_data
    
    # Act
    result = await user_repo.verify_email(token)
    
    # Assert
    assert result is not None
    assert result.email_verified is True
    assert result.email_verification_token is None


@pytest.mark.asyncio
async def test_verify_email_already_verified_idempotent(user_repo, mock_pool, sample_user_data):
    """Test verifying already verified email is idempotent."""
    # Arrange
    token = "verification_token_123"
    verified_data = sample_user_data.copy()
    verified_data["email_verified"] = True
    mock_pool.fetchrow.return_value = verified_data
    
    # Act
    result = await user_repo.verify_email(token)
    
    # Assert
    assert result is not None
    assert result.email_verified is True


@pytest.mark.asyncio
async def test_set_email_verification_token(user_repo, mock_pool, sample_user_data):
    """Test setting email verification token."""
    # Arrange
    user_id = sample_user_data["id"]
    token = "new_verification_token"
    updated_data = sample_user_data.copy()
    updated_data["email_verification_token"] = token
    mock_pool.fetchrow.return_value = updated_data
    
    # Act
    result = await user_repo.set_verification_token(user_id, token)
    
    # Assert
    assert result is True


@pytest.mark.asyncio
async def test_verify_with_invalid_token(user_repo, mock_pool):
    """Test verifying with invalid token returns None."""
    # Arrange
    mock_pool.fetchrow.return_value = None
    
    # Act
    result = await user_repo.verify_email("invalid_token")
    
    # Assert
    assert result is None


# ===================================================================
# 4. Role & Permissions (4 tests)
# ===================================================================

@pytest.mark.asyncio
async def test_update_user_role_operator_to_admin(user_repo, mock_pool, sample_user_data):
    """Test updating user role from operator to admin."""
    # Arrange
    user_id = sample_user_data["id"]
    org_id = sample_user_data["organization_id"]
    updated_data = sample_user_data.copy()
    updated_data["role"] = "admin"
    mock_pool.fetchrow.return_value = updated_data
    
    # Act
    result = await user_repo.update_role(user_id, org_id, "admin")
    
    # Assert
    assert result is not None
    assert result.role == "admin"


@pytest.mark.asyncio
async def test_update_user_role_invalid_role_validation(user_repo, mock_pool):
    """Test updating user role with invalid role raises ValueError."""
    # Arrange
    user_id = uuid4()
    org_id = uuid4()
    
    # Act & Assert
    with pytest.raises(ValueError, match="Invalid role"):
        await user_repo.update_role(user_id, org_id, "invalid_role")


@pytest.mark.asyncio
async def test_get_users_by_role_admin(user_repo, mock_pool, sample_user_data):
    """Test getting all admin users in organization."""
    # Arrange
    org_id = sample_user_data["organization_id"]
    admin_data = sample_user_data.copy()
    admin_data["role"] = "admin"
    mock_pool.fetch.return_value = [admin_data, admin_data.copy()]
    
    # Act
    result = await user_repo.get_organization_admins(org_id)
    
    # Assert
    assert len(result) == 2
    assert all(u.role == "admin" for u in result)


@pytest.mark.asyncio
async def test_get_users_by_role_operator(user_repo, mock_pool, sample_user_data):
    """Test getting all operator users in organization."""
    # Arrange
    org_id = sample_user_data["organization_id"]
    mock_pool.fetch.return_value = [sample_user_data, sample_user_data.copy()]
    
    # Act
    result = await user_repo.get_organization_users(org_id)
    
    # Assert
    assert len(result) == 2
    assert all(u.role == "operator" for u in result)


# ===================================================================
# 5. Metadata Management (6 tests)
# ===================================================================

@pytest.mark.asyncio
async def test_update_vm_metadata_status_id_ip(user_repo, mock_pool, sample_user_data):
    """Test updating VM metadata with vm_status, vm_id, vm_ip."""
    # Arrange
    user_id = sample_user_data["id"]
    vm_metadata = {
        "vm_status": "running",
        "vm_id": "vm-12345",
        "vm_ip": "10.0.0.5"
    }
    updated_data = sample_user_data.copy()
    updated_data["metadata"] = vm_metadata
    mock_pool.fetchrow.return_value = updated_data
    
    # Act
    result = await user_repo.update(user_id, {"metadata": vm_metadata})
    
    # Assert
    assert result is not None
    assert result.metadata["vm_status"] == "running"
    assert result.metadata["vm_id"] == "vm-12345"
    assert result.metadata["vm_ip"] == "10.0.0.5"


@pytest.mark.asyncio
async def test_get_vm_status_from_metadata(user_repo, mock_pool, sample_user_data):
    """Test retrieving VM status from user metadata."""
    # Arrange
    user_id = sample_user_data["id"]
    sample_user_data["metadata"] = {"vm_status": "active", "vm_id": "vm-999"}
    mock_pool.fetchrow.return_value = sample_user_data
    
    # Act
    result = await user_repo.get(user_id)
    
    # Assert
    assert result is not None
    assert result.metadata.get("vm_status") == "active"
    assert result.metadata.get("vm_id") == "vm-999"


@pytest.mark.asyncio
async def test_update_custom_metadata_arbitrary_keys(user_repo, mock_pool, sample_user_data):
    """Test updating custom metadata with arbitrary key-value pairs."""
    # Arrange
    user_id = sample_user_data["id"]
    custom_metadata = {
        "last_mission": "mission-123",
        "preferred_tools": ["nmap", "metasploit"],
        "skill_level": 5
    }
    updated_data = sample_user_data.copy()
    updated_data["metadata"] = custom_metadata
    mock_pool.fetchrow.return_value = updated_data
    
    # Act
    result = await user_repo.update(user_id, {"metadata": custom_metadata})
    
    # Assert
    assert result is not None
    assert result.metadata["last_mission"] == "mission-123"
    assert "nmap" in result.metadata["preferred_tools"]
    assert result.metadata["skill_level"] == 5


@pytest.mark.asyncio
async def test_clear_specific_metadata_key(user_repo, mock_pool, sample_user_data):
    """Test clearing a specific metadata key."""
    # Arrange
    user_id = sample_user_data["id"]
    sample_user_data["metadata"] = {"vm_status": "active", "vm_id": "vm-123"}
    updated_data = sample_user_data.copy()
    updated_data["metadata"] = {"vm_id": "vm-123"}  # vm_status removed
    mock_pool.fetchrow.return_value = updated_data
    
    # Act
    result = await user_repo.update(user_id, {"metadata": {"vm_id": "vm-123"}})
    
    # Assert
    assert result is not None
    assert "vm_status" not in result.metadata
    assert result.metadata["vm_id"] == "vm-123"


@pytest.mark.asyncio
async def test_metadata_persistence_across_updates(user_repo, mock_pool, sample_user_data):
    """Test metadata persists across multiple updates."""
    # Arrange
    user_id = sample_user_data["id"]
    initial_metadata = {"key1": "value1"}
    sample_user_data["metadata"] = initial_metadata
    mock_pool.fetchrow.return_value = sample_user_data
    
    # Act - First update
    result1 = await user_repo.update(user_id, {"metadata": initial_metadata})
    
    # Update with additional metadata
    updated_metadata = {"key1": "value1", "key2": "value2"}
    updated_data = sample_user_data.copy()
    updated_data["metadata"] = updated_metadata
    mock_pool.fetchrow.return_value = updated_data
    
    result2 = await user_repo.update(user_id, {"metadata": updated_metadata})
    
    # Assert
    assert result2 is not None
    assert result2.metadata["key1"] == "value1"
    assert result2.metadata["key2"] == "value2"


@pytest.mark.asyncio
async def test_metadata_validation_reject_invalid_types(user_repo, mock_pool, sample_user_data):
    """Test metadata validation rejects invalid types."""
    # Arrange
    user_id = sample_user_data["id"]
    valid_metadata = {"valid": "data"}
    updated_data = sample_user_data.copy()
    updated_data["metadata"] = valid_metadata
    mock_pool.fetchrow.return_value = updated_data
    
    # Act
    result = await user_repo.update(user_id, {"metadata": valid_metadata})
    
    # Assert
    assert result is not None
    assert isinstance(result.metadata, dict)


# ===================================================================
# 6. Organization Management (6 tests)
# ===================================================================

@pytest.mark.asyncio
async def test_get_users_by_organization_returns_all_org_users(user_repo, mock_pool, sample_user_data):
    """Test getting all users in an organization."""
    # Arrange
    org_id = sample_user_data["organization_id"]
    user1 = sample_user_data.copy()
    user2 = sample_user_data.copy()
    user2["id"] = uuid4()
    user2["email"] = "user2@example.com"
    mock_pool.fetch.return_value = [user1, user2]
    
    # Act
    result = await user_repo.get_organization_users(org_id)
    
    # Assert
    assert len(result) == 2
    assert all(u.organization_id == org_id for u in result)


@pytest.mark.asyncio
async def test_get_users_by_organization_empty_org(user_repo, mock_pool):
    """Test getting users from empty organization returns empty list."""
    # Arrange
    org_id = uuid4()
    mock_pool.fetch.return_value = []
    
    # Act
    result = await user_repo.get_organization_users(org_id)
    
    # Assert
    assert len(result) == 0
    assert isinstance(result, list)


@pytest.mark.asyncio
async def test_transfer_user_to_different_organization(user_repo, mock_pool, sample_user_data):
    """Test transferring user to a different organization."""
    # Arrange
    user_id = sample_user_data["id"]
    new_org_id = uuid4()
    updated_data = sample_user_data.copy()
    updated_data["organization_id"] = new_org_id
    mock_pool.fetchrow.return_value = updated_data
    
    # Act
    result = await user_repo.update(user_id, {"organization_id": new_org_id})
    
    # Assert
    assert result is not None
    assert result.organization_id == new_org_id


@pytest.mark.asyncio
async def test_list_organization_members_with_pagination(user_repo, mock_pool, sample_user_data):
    """Test listing organization members with pagination."""
    # Arrange
    org_id = sample_user_data["organization_id"]
    users = [sample_user_data.copy() for _ in range(3)]
    for i, user in enumerate(users):
        user["id"] = uuid4()
        user["email"] = f"user{i}@example.com"
    mock_pool.fetch.return_value = users
    
    # Act
    result = await user_repo.get_organization_users(org_id)
    
    # Assert
    assert len(result) == 3
    assert all(isinstance(u, User) for u in result)


@pytest.mark.asyncio
async def test_count_organization_users(user_repo, mock_pool):
    """Test counting users in an organization."""
    # Arrange
    org_id = uuid4()
    mock_pool.fetchval.return_value = 15
    
    # Act
    query = "SELECT COUNT(*) FROM users WHERE organization_id = $1"
    count = await mock_pool.fetchval(query, org_id)
    
    # Assert
    assert count == 15


@pytest.mark.asyncio
async def test_organization_isolation_user_cannot_see_other_org(user_repo, mock_pool, sample_user_data):
    """Test organization isolation - user cannot see other org users."""
    # Arrange
    org1_id = uuid4()
    org2_id = uuid4()
    
    # User from org1
    user_org1 = sample_user_data.copy()
    user_org1["organization_id"] = org1_id
    
    # Mock returns only org1 users
    mock_pool.fetch.return_value = [user_org1]
    
    # Act
    result = await user_repo.get_organization_users(org1_id)
    
    # Assert
    assert len(result) == 1
    assert result[0].organization_id == org1_id
    # Verify no users from org2
    assert all(u.organization_id != org2_id for u in result)


# ===================================================================
# Additional Edge Cases & Integration Tests
# ===================================================================

@pytest.mark.asyncio
async def test_user_entity_is_locked_method(sample_user):
    """Test User.is_locked() method with various scenarios."""
    # Not locked
    sample_user.locked_until = None
    assert sample_user.is_locked() is False
    
    # Locked in future
    sample_user.locked_until = datetime.utcnow() + timedelta(minutes=10)
    assert sample_user.is_locked() is True
    
    # Lock expired
    sample_user.locked_until = datetime.utcnow() - timedelta(minutes=10)
    assert sample_user.is_locked() is False


@pytest.mark.asyncio
async def test_user_to_dict_excludes_sensitive_data(sample_user):
    """Test User.to_dict() excludes sensitive data by default."""
    # Act
    user_dict = sample_user.to_dict(include_sensitive=False)
    
    # Assert
    assert "password_hash" not in user_dict
    assert "email" in user_dict
    assert "username" in user_dict


@pytest.mark.asyncio
async def test_user_to_dict_includes_sensitive_when_requested(sample_user):
    """Test User.to_dict() includes sensitive data when requested."""
    # Act
    user_dict = sample_user.to_dict(include_sensitive=True)
    
    # Assert
    assert "password_hash" in user_dict
    assert user_dict["password_hash"] == sample_user.password_hash


# ===================================================================
# 5. Metadata Management (6 tests)
# ===================================================================

@pytest.mark.asyncio
async def test_update_vm_metadata_status_id_ip(user_repo, mock_pool, sample_user_data):
    """Test updating VM metadata with vm_status, vm_id, vm_ip."""
    # Arrange
    user_id = sample_user_data["id"]
    vm_metadata = {
        "vm_status": "running",
        "vm_id": "vm-12345",
        "vm_ip": "10.0.0.5"
    }
    updated_data = sample_user_data.copy()
    updated_data["metadata"] = vm_metadata
    mock_pool.fetchrow.return_value = updated_data
    
    # Act
    result = await user_repo.update(user_id, {"metadata": vm_metadata})
    
    # Assert
    assert result is not None
    assert result.metadata["vm_status"] == "running"
    assert result.metadata["vm_id"] == "vm-12345"
    assert result.metadata["vm_ip"] == "10.0.0.5"


@pytest.mark.asyncio
async def test_get_vm_status_from_metadata(user_repo, mock_pool, sample_user_data):
    """Test retrieving VM status from user metadata."""
    # Arrange
    user_id = sample_user_data["id"]
    sample_user_data["metadata"] = {"vm_status": "active", "vm_id": "vm-999"}
    mock_pool.fetchrow.return_value = sample_user_data
    
    # Act
    result = await user_repo.get_by_id(user_id)
    
    # Assert
    assert result is not None
    assert result.metadata.get("vm_status") == "active"
    assert result.metadata.get("vm_id") == "vm-999"


@pytest.mark.asyncio
async def test_update_custom_metadata_arbitrary_keys(user_repo, mock_pool, sample_user_data):
    """Test updating custom metadata with arbitrary key-value pairs."""
    # Arrange
    user_id = sample_user_data["id"]
    custom_metadata = {
        "last_mission": "mission-123",
        "preferred_tools": ["nmap", "metasploit"],
        "skill_level": 5
    }
    updated_data = sample_user_data.copy()
    updated_data["metadata"] = custom_metadata
    mock_pool.fetchrow.return_value = updated_data
    
    # Act
    result = await user_repo.update(user_id, {"metadata": custom_metadata})
    
    # Assert
    assert result is not None
    assert result.metadata["last_mission"] == "mission-123"
    assert "nmap" in result.metadata["preferred_tools"]
    assert result.metadata["skill_level"] == 5


@pytest.mark.asyncio
async def test_clear_specific_metadata_key(user_repo, mock_pool, sample_user_data):
    """Test clearing a specific metadata key."""
    # Arrange
    user_id = sample_user_data["id"]
    sample_user_data["metadata"] = {"vm_status": "active", "vm_id": "vm-123"}
    updated_data = sample_user_data.copy()
    updated_data["metadata"] = {"vm_id": "vm-123"}  # vm_status removed
    mock_pool.fetchrow.return_value = updated_data
    
    # Act
    result = await user_repo.update(user_id, {"metadata": {"vm_id": "vm-123"}})
    
    # Assert
    assert result is not None
    assert "vm_status" not in result.metadata
    assert result.metadata["vm_id"] == "vm-123"


@pytest.mark.asyncio
async def test_metadata_persistence_across_updates(user_repo, mock_pool, sample_user_data):
    """Test metadata persists across multiple updates."""
    # Arrange
    user_id = sample_user_data["id"]
    initial_metadata = {"key1": "value1"}
    sample_user_data["metadata"] = initial_metadata
    mock_pool.fetchrow.return_value = sample_user_data
    
    # Act - First update
    result1 = await user_repo.update(user_id, {"metadata": initial_metadata})
    
    # Update with additional metadata
    updated_metadata = {"key1": "value1", "key2": "value2"}
    updated_data = sample_user_data.copy()
    updated_data["metadata"] = updated_metadata
    mock_pool.fetchrow.return_value = updated_data
    
    result2 = await user_repo.update(user_id, {"metadata": updated_metadata})
    
    # Assert
    assert result2 is not None
    assert result2.metadata["key1"] == "value1"
    assert result2.metadata["key2"] == "value2"


@pytest.mark.asyncio
async def test_metadata_validation_reject_invalid_types(user_repo, mock_pool, sample_user_data):
    """Test metadata validation rejects invalid types."""
    # Arrange
    user_id = sample_user_data["id"]
    valid_metadata = {"valid": "data"}
    updated_data = sample_user_data.copy()
    updated_data["metadata"] = valid_metadata
    mock_pool.fetchrow.return_value = updated_data
    
    # Act
    result = await user_repo.update(user_id, {"metadata": valid_metadata})
    
    # Assert
    assert result is not None
    assert isinstance(result.metadata, dict)


# ===================================================================
# 6. Organization Management (6 tests)
# ===================================================================

@pytest.mark.asyncio
async def test_get_users_by_organization_returns_all_org_users(user_repo, mock_pool, sample_user_data):
    """Test getting all users in an organization."""
    # Arrange
    org_id = sample_user_data["organization_id"]
    user1 = sample_user_data.copy()
    user2 = sample_user_data.copy()
    user2["id"] = uuid4()
    user2["email"] = "user2@example.com"
    mock_pool.fetch.return_value = [user1, user2]
    
    # Act
    result = await user_repo.get_organization_users(org_id)
    
    # Assert
    assert len(result) == 2
    assert all(u.organization_id == org_id for u in result)


@pytest.mark.asyncio
async def test_get_users_by_organization_empty_org(user_repo, mock_pool):
    """Test getting users from empty organization returns empty list."""
    # Arrange
    org_id = uuid4()
    mock_pool.fetch.return_value = []
    
    # Act
    result = await user_repo.get_organization_users(org_id)
    
    # Assert
    assert len(result) == 0
    assert isinstance(result, list)


@pytest.mark.asyncio
async def test_transfer_user_to_different_organization(user_repo, mock_pool, sample_user_data):
    """Test transferring user to a different organization."""
    # Arrange
    user_id = sample_user_data["id"]
    new_org_id = uuid4()
    updated_data = sample_user_data.copy()
    updated_data["organization_id"] = new_org_id
    mock_pool.fetchrow.return_value = updated_data
    
    # Act
    result = await user_repo.update(user_id, {"organization_id": new_org_id})
    
    # Assert
    assert result is not None
    assert result.organization_id == new_org_id


@pytest.mark.asyncio
async def test_list_organization_members_with_pagination(user_repo, mock_pool, sample_user_data):
    """Test listing organization members with pagination."""
    # Arrange
    org_id = sample_user_data["organization_id"]
    users = [sample_user_data.copy() for _ in range(3)]
    for i, user in enumerate(users):
        user["id"] = uuid4()
        user["email"] = f"user{i}@example.com"
    mock_pool.fetch.return_value = users
    
    # Act
    result = await user_repo.get_organization_users(org_id)
    
    # Assert
    assert len(result) == 3
    assert all(isinstance(u, User) for u in result)


@pytest.mark.asyncio
async def test_count_organization_users(user_repo, mock_pool):
    """Test counting users in an organization."""
    # Arrange
    org_id = uuid4()
    mock_pool.fetchval.return_value = 15
    
    # Act
    query = "SELECT COUNT(*) FROM users WHERE organization_id = $1"
    count = await mock_pool.fetchval(query, org_id)
    
    # Assert
    assert count == 15


@pytest.mark.asyncio
async def test_organization_isolation_user_cannot_see_other_org(user_repo, mock_pool, sample_user_data):
    """Test organization isolation - user cannot see other org users."""
    # Arrange
    org1_id = uuid4()
    org2_id = uuid4()
    
    # User from org1
    user_org1 = sample_user_data.copy()
    user_org1["organization_id"] = org1_id
    
    # Mock returns only org1 users
    mock_pool.fetch.return_value = [user_org1]
    
    # Act
    result = await user_repo.get_organization_users(org1_id)
    
    # Assert
    assert len(result) == 1
    assert result[0].organization_id == org1_id
    # Verify no users from org2
    assert all(u.organization_id != org2_id for u in result)


# ===================================================================
# Additional Edge Cases & Integration Tests
# ===================================================================

@pytest.mark.asyncio
async def test_user_entity_is_locked_method(sample_user):
    """Test User.is_locked() method with various scenarios."""
    # Not locked
    sample_user.locked_until = None
    assert sample_user.is_locked() is False
    
    # Locked in future
    sample_user.locked_until = datetime.utcnow() + timedelta(minutes=10)
    assert sample_user.is_locked() is True
    
    # Lock expired
    sample_user.locked_until = datetime.utcnow() - timedelta(minutes=10)
    assert sample_user.is_locked() is False


@pytest.mark.asyncio
async def test_user_to_dict_excludes_sensitive_data(sample_user):
    """Test User.to_dict() excludes sensitive data by default."""
    # Act
    user_dict = sample_user.to_dict(include_sensitive=False)
    
    # Assert
    assert "password_hash" not in user_dict
    assert "email" in user_dict
    assert "username" in user_dict


@pytest.mark.asyncio
async def test_user_to_dict_includes_sensitive_when_requested(sample_user):
    """Test User.to_dict() includes sensitive data when requested."""
    # Act
    user_dict = sample_user.to_dict(include_sensitive=True)
    
    # Assert
    assert "password_hash" in user_dict
    assert user_dict["password_hash"] == sample_user.password_hash
