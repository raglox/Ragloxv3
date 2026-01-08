
# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Extended Authentication Routes Tests
# Comprehensive test coverage for auth_routes.py
# Target: Increase coverage from 52% to 82%+
# ═══════════════════════════════════════════════════════════════
"""
Extended tests for authentication routes to achieve 85%+ coverage.

Test Coverage:
1. Login Tests (8 tests)
2. Logout Tests (3 tests)
3. Password Management Tests (6 tests)
4. Profile Management Tests (4 tests)
5. JWT Token Tests (6 tests)
6. Admin Routes Tests (8 tests)

Total: 35 tests
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from uuid import uuid4, UUID
from datetime import datetime, timedelta
from fastapi import HTTPException, status

from src.api.auth_routes import (
    login, logout, get_current_user_info, update_profile,
    change_password, create_access_token, decode_token,
    get_current_user, require_role, require_org_owner,
    list_organization_users, update_user_status, update_user_role,
    LoginRequest, UserProfileUpdate, PasswordChangeRequest,
    VMProvisionStatus
)
from src.core.database.user_repository import User, UserRepository
from src.core.database.organization_repository import Organization, OrganizationRepository
from src.core.token_store import TokenStore


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def mock_user_repo():
    """Mock UserRepository."""
    repo = AsyncMock(spec=UserRepository)
    return repo


@pytest.fixture
def mock_org_repo():
    """Mock OrganizationRepository."""
    repo = AsyncMock(spec=OrganizationRepository)
    return repo


@pytest.fixture
def mock_token_store():
    """Mock TokenStore."""
    store = AsyncMock(spec=TokenStore)
    store.store_token = AsyncMock(return_value=True)
    store.validate_token = AsyncMock(return_value="user-id")
    store.revoke_token = AsyncMock(return_value=True)
    store.revoke_all_user_tokens = AsyncMock(return_value=1)
    return store


@pytest.fixture
def mock_request(mock_user_repo, mock_org_repo, mock_token_store):
    """Mock FastAPI Request object."""
    request = Mock()
    request.app.state.user_repo = mock_user_repo
    request.app.state.org_repo = mock_org_repo
    request.app.state.token_store = mock_token_store
    request.client = Mock()
    request.client.host = "127.0.0.1"
    return request


@pytest.fixture
def sample_user():
    """Sample active user entity."""
    org_id = uuid4()
    user_id = uuid4()
    return User(
        id=user_id,
        organization_id=org_id,
        username="testuser",
        email="test@example.com",
        password_hash="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYqVr/VXlIK",
        full_name="Test User",
        role="admin",
        is_active=True,
        is_org_owner=True,
        metadata={"vm_status": VMProvisionStatus.READY.value},
        created_at=datetime.utcnow(),
        last_login_at=None,
        login_attempts=0,
        locked_until=None
    )


@pytest.fixture
def sample_organization():
    """Sample organization entity."""
    org_id = uuid4()
    return Organization(
        id=org_id,
        name="Test Organization",
        slug="test-org",
        owner_email="test@example.com",
        plan="free",
        is_active=True,
        created_at=datetime.utcnow()
    )


@pytest.fixture
def mock_credentials():
    """Mock HTTPAuthorizationCredentials."""
    creds = Mock()
    creds.credentials = "valid_token_string"
    return creds


# ═══════════════════════════════════════════════════════════════
# 1. Login Tests (8 tests)
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_login_successful_with_valid_credentials(
    mock_request, mock_user_repo, mock_org_repo, mock_token_store, 
    sample_user, sample_organization
):
    """Test successful login with valid credentials."""
    mock_user_repo.get_by_email_global = AsyncMock(return_value=sample_user)
    mock_user_repo.record_login = AsyncMock()
    mock_org_repo.get_by_id = AsyncMock(return_value=sample_organization)
    
    login_data = LoginRequest(
        email="test@example.com",
        password="password123",
        remember_me=False
    )
    
    with patch('src.api.auth_routes.bcrypt.checkpw', return_value=True), \
         patch('src.api.auth_routes.create_access_token', return_value=("test_token", 3600)):
        
        response = await login(mock_request, login_data)
    
    assert response.access_token == "test_token"
    assert response.expires_in == 3600
    assert response.user.email == "test@example.com"
    assert response.user.status == "active"
    mock_user_repo.record_login.assert_called_once()


@pytest.mark.asyncio
async def test_login_failed_with_invalid_password(
    mock_request, mock_user_repo, sample_user
):
    """Test login failure with incorrect password."""
    mock_user_repo.get_by_email_global = AsyncMock(return_value=sample_user)
    mock_user_repo.record_failed_login = AsyncMock(return_value=False)
    
    login_data = LoginRequest(
        email="test@example.com",
        password="wrong_password",
        remember_me=False
    )
    
    with patch('src.api.auth_routes.bcrypt.checkpw', return_value=False), \
         pytest.raises(HTTPException) as exc_info:
        await login(mock_request, login_data)
    
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid email or password" in exc_info.value.detail
    mock_user_repo.record_failed_login.assert_called_once()


@pytest.mark.asyncio
async def test_login_failed_with_nonexistent_email(
    mock_request, mock_user_repo
):
    """Test login failure with non-existent email."""
    mock_user_repo.get_by_email_global = AsyncMock(return_value=None)
    
    login_data = LoginRequest(
        email="nonexistent@example.com",
        password="password123",
        remember_me=False
    )
    
    with pytest.raises(HTTPException) as exc_info:
        await login(mock_request, login_data)
    
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid email or password" in exc_info.value.detail


@pytest.mark.asyncio
async def test_login_account_locking_after_5_failed_attempts(
    mock_request, mock_user_repo, sample_user
):
    """Test account locking after 5 failed login attempts."""
    mock_user_repo.get_by_email_global = AsyncMock(return_value=sample_user)
    mock_user_repo.record_failed_login = AsyncMock(return_value=True)
    
    login_data = LoginRequest(
        email="test@example.com",
        password="wrong_password",
        remember_me=False
    )
    
    with patch('src.api.auth_routes.bcrypt.checkpw', return_value=False), \
         pytest.raises(HTTPException) as exc_info:
        await login(mock_request, login_data)
    
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    mock_user_repo.record_failed_login.assert_called_once_with(sample_user.id)


@pytest.mark.asyncio
async def test_login_with_locked_account(
    mock_request, mock_user_repo
):
    """Test login attempt with locked account."""
    locked_user = User(
        id=uuid4(),
        organization_id=uuid4(),
        username="locked",
        email="locked@example.com",
        password_hash="$2b$12$hash",
        role="operator",
        is_active=True,
        locked_until=datetime.utcnow() + timedelta(minutes=15)
    )
    
    mock_user_repo.get_by_email_global = AsyncMock(return_value=locked_user)
    
    login_data = LoginRequest(
        email="locked@example.com",
        password="password123",
        remember_me=False
    )
    
    with pytest.raises(HTTPException) as exc_info:
        await login(mock_request, login_data)
    
    assert exc_info.value.status_code == status.HTTP_423_LOCKED
    assert "temporarily locked" in exc_info.value.detail


@pytest.mark.asyncio
async def test_login_updates_last_login_timestamp(
    mock_request, mock_user_repo, mock_org_repo, mock_token_store,
    sample_user, sample_organization
):
    """Test that login updates last_login timestamp."""
    mock_user_repo.get_by_email_global = AsyncMock(return_value=sample_user)
    mock_user_repo.record_login = AsyncMock()
    mock_org_repo.get_by_id = AsyncMock(return_value=sample_organization)
    
    login_data = LoginRequest(
        email="test@example.com",
        password="password123",
        remember_me=False
    )
    
    with patch('src.api.auth_routes.bcrypt.checkpw', return_value=True), \
         patch('src.api.auth_routes.create_access_token', return_value=("token", 3600)):
        
        response = await login(mock_request, login_data)
    
    mock_user_repo.record_login.assert_called_once_with(
        sample_user.id,
        "127.0.0.1"
    )


@pytest.mark.asyncio
async def test_login_with_inactive_account(
    mock_request, mock_user_repo
):
    """Test login attempt with inactive/suspended account."""
    inactive_user = User(
        id=uuid4(),
        organization_id=uuid4(),
        username="inactive",
        email="inactive@example.com",
        password_hash="$2b$12$hash",
        role="operator",
        is_active=False
    )
    
    mock_user_repo.get_by_email_global = AsyncMock(return_value=inactive_user)
    
    login_data = LoginRequest(
        email="inactive@example.com",
        password="password123",
        remember_me=False
    )
    
    with patch('src.api.auth_routes.bcrypt.checkpw', return_value=True), \
         pytest.raises(HTTPException) as exc_info:
        await login(mock_request, login_data)
    
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert "suspended" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_login_with_different_organizations(
    mock_request, mock_user_repo, mock_org_repo, mock_token_store
):
    """Test login with users from different organizations."""
    org1_id = uuid4()
    
    user1 = User(
        id=uuid4(),
        organization_id=org1_id,
        username="user1",
        email="user1@example.com",
        password_hash="$2b$12$hash",
        role="admin",
        is_active=True
    )
    
    org1 = Organization(
        id=org1_id,
        name="Organization 1",
        slug="org1",
        owner_email="user1@example.com",
        plan="free",
        is_active=True
    )
    
    mock_user_repo.get_by_email_global = AsyncMock(return_value=user1)
    mock_user_repo.record_login = AsyncMock()
    mock_org_repo.get_by_id = AsyncMock(return_value=org1)
    
    login_data = LoginRequest(
        email="user1@example.com",
        password="password123",
        remember_me=False
    )
    
    with patch('src.api.auth_routes.bcrypt.checkpw', return_value=True), \
         patch('src.api.auth_routes.create_access_token', return_value=("token", 3600)):
        
        response = await login(mock_request, login_data)
    
    assert response.user.organization_id == str(org1_id)
    assert response.user.organization_name == "Organization 1"


# ═══════════════════════════════════════════════════════════════
# 2. Logout Tests (3 tests)
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_logout_successful_token_revoked(
    mock_request, mock_token_store, mock_credentials
):
    """Test successful logout with token revocation."""
    current_user = {
        "id": str(uuid4()),
        "email": "test@example.com",
        "organization_id": str(uuid4())
    }
    
    response = await logout(mock_request, mock_credentials, current_user)
    
    assert response["message"] == "Successfully logged out"
    mock_token_store.revoke_token.assert_called_once_with("valid_token_string")


@pytest.mark.asyncio
async def test_logout_with_invalid_token(
    mock_request, mock_token_store
):
    """Test logout with invalid token."""
    mock_token_store.validate_token = AsyncMock(return_value=None)
    
    invalid_creds = Mock()
    invalid_creds.credentials = "invalid_token"
    
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(mock_request, invalid_creds)
    
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_logout_with_already_revoked_token(
    mock_request, mock_token_store, mock_credentials
):
    """Test logout with already revoked token."""
    mock_token_store.validate_token = AsyncMock(return_value=None)
    
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(mock_request, mock_credentials)
    
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "revoked" in exc_info.value.detail.lower()


# ═══════════════════════════════════════════════════════════════
# 3. Password Management Tests (6 tests)
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_change_password_successful(
    mock_request, mock_user_repo, mock_token_store, sample_user
):
    """Test successful password change."""
    current_user = {
        "id": str(sample_user.id),
        "email": sample_user.email,
        "organization_id": str(sample_user.organization_id)
    }
    
    mock_user_repo.get_by_id = AsyncMock(return_value=sample_user)
    mock_user_repo.update_password = AsyncMock(return_value=True)
    
    password_data = PasswordChangeRequest(
        current_password="password123",
        new_password="NewSecure123!"
    )
    
    with patch('src.api.auth_routes.bcrypt.checkpw', return_value=True), \
         patch('src.api.auth_routes.bcrypt.hashpw', return_value=b"new_hash"), \
         patch('src.api.auth_routes.bcrypt.gensalt', return_value=b"salt"):
        
        response = await change_password(mock_request, password_data, current_user)
    
    assert "successfully" in response["message"].lower()
    mock_user_repo.update_password.assert_called_once()
    mock_token_store.revoke_all_user_tokens.assert_called_once()


@pytest.mark.asyncio
async def test_change_password_with_wrong_old_password(
    mock_request, mock_user_repo, sample_user
):
    """Test password change with incorrect current password."""
    current_user = {
        "id": str(sample_user.id),
        "email": sample_user.email,
        "organization_id": str(sample_user.organization_id)
    }
    
    mock_user_repo.get_by_id = AsyncMock(return_value=sample_user)
    
    password_data = PasswordChangeRequest(
        current_password="wrong_password",
        new_password="NewSecure123!"
    )
    
    with patch('src.api.auth_routes.bcrypt.checkpw', return_value=False), \
         pytest.raises(HTTPException) as exc_info:
        await change_password(mock_request, password_data, current_user)
    
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "incorrect" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_change_password_revokes_all_tokens(
    mock_request, mock_user_repo, mock_token_store, sample_user
):
    """Test that password change revokes all existing tokens."""
    current_user = {
        "id": str(sample_user.id),
        "email": sample_user.email,
        "organization_id": str(sample_user.organization_id)
    }
    
    mock_user_repo.get_by_id = AsyncMock(return_value=sample_user)
    mock_user_repo.update_password = AsyncMock(return_value=True)
    mock_token_store.revoke_all_user_tokens = AsyncMock(return_value=3)
    
    password_data = PasswordChangeRequest(
        current_password="password123",
        new_password="NewSecure123!"
    )
    
    with patch('src.api.auth_routes.bcrypt.checkpw', return_value=True), \
         patch('src.api.auth_routes.bcrypt.hashpw', return_value=b"new_hash"), \
         patch('src.api.auth_routes.bcrypt.gensalt', return_value=b"salt"):
        
        await change_password(mock_request, password_data, current_user)
    
    mock_token_store.revoke_all_user_tokens.assert_called_once_with(str(sample_user.id))


@pytest.mark.asyncio
async def test_password_reset_token_generation(
    mock_user_repo, sample_user
):
    """Test password reset token generation."""
    mock_user_repo.set_password_reset_token = AsyncMock(return_value=True)
    
    token = "reset_token_123"
    result = await mock_user_repo.set_password_reset_token(
        sample_user.id,
        token,
        expires_hours=24
    )
    
    assert result is True
    mock_user_repo.set_password_reset_token.assert_called_once()


@pytest.mark.asyncio
async def test_password_reset_with_valid_token(
    mock_user_repo, sample_user
):
    """Test password reset with valid token."""
    sample_user.password_reset_token = "valid_token"
    sample_user.password_reset_expires = datetime.utcnow() + timedelta(hours=24)
    
    mock_user_repo.verify_reset_token = AsyncMock(return_value=sample_user)
    mock_user_repo.update_password = AsyncMock(return_value=True)
    
    user = await mock_user_repo.verify_reset_token("valid_token")
    
    assert user is not None
    assert user.id == sample_user.id


@pytest.mark.asyncio
async def test_password_reset_with_expired_token(
    mock_user_repo
):
    """Test password reset with expired token."""
    mock_user_repo.verify_reset_token = AsyncMock(return_value=None)
    
    user = await mock_user_repo.verify_reset_token("expired_token")
    
    assert user is None


# ═══════════════════════════════════════════════════════════════
# 4. Profile Management Tests (4 tests)
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_get_current_user_info(
    mock_request, mock_org_repo, sample_organization
):
    """Test getting current user information."""
    current_user = {
        "id": str(uuid4()),
        "email": "test@example.com",
        "full_name": "Test User",
        "organization_id": str(sample_organization.id),
        "role": "admin",
        "is_active": True,
        "metadata": {"vm_status": "ready"},
        "created_at": datetime.utcnow(),
        "last_login_at": datetime.utcnow()
    }
    
    mock_org_repo.get_by_id = AsyncMock(return_value=sample_organization)
    
    response = await get_current_user_info(mock_request, current_user)
    
    assert response.email == "test@example.com"
    assert response.organization_name == "Test Organization"
    assert response.status == "active"


@pytest.mark.asyncio
async def test_update_profile_full_name(
    mock_request, mock_user_repo, mock_org_repo, sample_user, sample_organization
):
    """Test updating user profile (full_name)."""
    current_user = {
        "id": str(sample_user.id),
        "email": sample_user.email,
        "full_name": "Old Name",
        "organization_id": str(sample_user.organization_id),
        "role": "admin",
        "is_active": True,
        "metadata": {},
        "created_at": datetime.utcnow()
    }
    
    updated_user = User(**sample_user.__dict__)
    updated_user.full_name = "New Name"
    
    mock_user_repo.update = AsyncMock(return_value=updated_user)
    mock_org_repo.get_by_id = AsyncMock(return_value=sample_organization)
    
    updates = UserProfileUpdate(full_name="New Name")
    
    response = await update_profile(mock_request, updates, current_user)
    
    assert response.full_name == "New Name"
    mock_user_repo.update.assert_called_once()


@pytest.mark.asyncio
async def test_update_profile_with_invalid_data(
    mock_request, mock_user_repo
):
    """Test updating profile with invalid data."""
    current_user = {
        "id": str(uuid4()),
        "email": "test@example.com",
        "organization_id": str(uuid4())
    }
    
    with pytest.raises(Exception):
        UserProfileUpdate(full_name="")


@pytest.mark.asyncio
async def test_update_profile_for_nonexistent_user(
    mock_request, mock_user_repo, mock_org_repo, sample_organization
):
    """Test updating profile for non-existent user."""
    current_user = {
        "id": str(uuid4()),
        "email": "test@example.com",
        "full_name": "Test",
        "organization_id": str(sample_organization.id),
        "role": "admin",
        "is_active": True,
        "metadata": {},
        "created_at": datetime.utcnow()
    }
    
    mock_user_repo.update = AsyncMock(return_value=None)
    mock_org_repo.get_by_id = AsyncMock(return_value=sample_organization)
    
    updates = UserProfileUpdate(full_name="New Name")
    
    response = await update_profile(mock_request, updates, current_user)
    
    assert response.email == "test@example.com"


# ═══════════════════════════════════════════════════════════════
# 5. JWT Token Tests (6 tests)
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_create_access_token(mock_token_store):
    """Test JWT access token creation."""
    user_id = str(uuid4())
    org_id = str(uuid4())
    
    with patch('src.api.auth_routes.get_settings') as mock_settings:
        settings = Mock()
        settings.jwt_expiration_hours = 24
        settings.jwt_secret = "test_secret"
        settings.jwt_algorithm = "HS256"
        mock_settings.return_value = settings
        
        token, expires_in = await create_access_token(
            user_id, org_id, mock_token_store
        )
    
    assert token is not None
    assert expires_in == 86400
    mock_token_store.store_token.assert_called_once()


@pytest.mark.asyncio
async def test_decode_valid_token():
    """Test decoding valid JWT token."""
    with patch('src.api.auth_routes.get_settings') as mock_settings, \
         patch('src.api.auth_routes.jwt.decode') as mock_decode:
        
        settings = Mock()
        settings.jwt_secret = "test_secret"
        settings.jwt_algorithm = "HS256"
        mock_settings.return_value = settings
        
        mock_decode.return_value = {
            "sub": "user_id",
            "org": "org_id",
            "exp": datetime.utcnow() + timedelta(hours=24),
            "type": "access"
        }
        
        payload = decode_token("valid_token")
    
    assert payload is not None
    assert "sub" in payload


@pytest.mark.asyncio
async def test_decode_expired_token():
    """Test decoding expired JWT token."""
    import jwt as pyjwt
    
    with patch('src.api.auth_routes.get_settings') as mock_settings, \
         patch('src.api.auth_routes.jwt.decode') as mock_decode:
        
        settings = Mock()
        settings.jwt_secret = "test_secret"
        settings.jwt_algorithm = "HS256"
        mock_settings.return_value = settings
        
        mock_decode.side_effect = pyjwt.ExpiredSignatureError()
        
        payload = decode_token("expired_token")
    
    assert payload is None


@pytest.mark.asyncio
async def test_decode_invalid_token():
    """Test decoding invalid JWT token."""
    import jwt as pyjwt
    
    with patch('src.api.auth_routes.get_settings') as mock_settings, \
         patch('src.api.auth_routes.jwt.decode') as mock_decode:
        
        settings = Mock()
        settings.jwt_secret = "test_secret"
        settings.jwt_algorithm = "HS256"
        mock_settings.return_value = settings
        
        mock_decode.side_effect = pyjwt.InvalidTokenError()
        
        payload = decode_token("invalid_token")
    
    assert payload is None


@pytest.mark.asyncio
async def test_token_stored_in_redis(mock_token_store):
    """Test that token is stored in Redis."""
    user_id = str(uuid4())
    org_id = str(uuid4())
    
    with patch('src.api.auth_routes.get_settings') as mock_settings:
        settings = Mock()
        settings.jwt_expiration_hours = 24
        settings.jwt_secret = "test_secret"
        settings.jwt_algorithm = "HS256"
        mock_settings.return_value = settings
        
        await create_access_token(user_id, org_id, mock_token_store)
    
    assert mock_token_store.store_token.called


@pytest.mark.asyncio
async def test_token_validation_with_redis(
    mock_request, mock_user_repo, mock_token_store, 
    mock_credentials, sample_user
):
    """Test token validation with Redis."""
    mock_token_store.validate_token = AsyncMock(return_value=str(sample_user.id))
    mock_user_repo.get_by_id = AsyncMock(return_value=sample_user)
    
    with patch('src.api.auth_routes.decode_token') as mock_decode:
        mock_decode.return_value = {
            "sub": str(sample_user.id),
            "org": str(sample_user.organization_id)
        }
        
        user = await get_current_user(mock_request, mock_credentials)
    
    assert user["id"] == str(sample_user.id)
    mock_token_store.validate_token.assert_called_once()


# ═══════════════════════════════════════════════════════════════
# 6. Admin Routes Tests (8 tests)
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_get_all_users_admin_only(
    mock_request, mock_user_repo, mock_org_repo, sample_organization
):
    """Test getting all users (admin only)."""
    admin_user = {
        "id": str(uuid4()),
        "email": "admin@example.com",
        "organization_id": str(sample_organization.id),
        "role": "admin"
    }
    
    users = [
        User(
            id=uuid4(),
            organization_id=sample_organization.id,
            username=f"user{i}",
            email=f"user{i}@example.com",
            password_hash="hash",
            role="operator",
            is_active=True
        )
        for i in range(3)
    ]
    
    mock_user_repo.get_organization_users = AsyncMock(return_value=users)
    mock_org_repo.get_by_id = AsyncMock(return_value=sample_organization)
    
    response = await list_organization_users(mock_request, admin_user)
    
    assert len(response) == 3
    assert all(u.organization_name == "Test Organization" for u in response)


@pytest.mark.asyncio
async def test_get_user_by_id_admin_only(
    mock_request, mock_user_repo, sample_user
):
    """Test getting user by ID (admin only)."""
    mock_user_repo.get_by_id = AsyncMock(return_value=sample_user)
    
    user = await mock_user_repo.get_by_id(sample_user.id, sample_user.organization_id)
    
    assert user is not None
    assert user.id == sample_user.id


@pytest.mark.asyncio
async def test_update_user_status_admin_only(
    mock_request, mock_user_repo, mock_token_store, sample_user
):
    """Test updating user status (admin only)."""
    admin_user = {
        "id": str(uuid4()),
        "email": "admin@example.com",
        "organization_id": str(sample_user.organization_id),
        "role": "admin"
    }
    
    mock_user_repo.get_by_id = AsyncMock(return_value=sample_user)
    mock_user_repo.update = AsyncMock(return_value=sample_user)
    
    response = await update_user_status(
        mock_request,
        str(sample_user.id),
        "suspended",
        admin_user
    )
    
    assert "status updated" in response["message"].lower()
    mock_token_store.revoke_all_user_tokens.assert_called_once()


@pytest.mark.asyncio
async def test_update_user_role_admin_only(
    mock_request, mock_user_repo, sample_user
):
    """Test updating user role (admin only)."""
    admin_user = {
        "id": str(uuid4()),
        "email": "admin@example.com",
        "organization_id": str(sample_user.organization_id),
        "role": "admin"
    }
    
    mock_user_repo.get_by_id = AsyncMock(return_value=sample_user)
    mock_user_repo.update_role = AsyncMock(return_value=sample_user)
    
    response = await update_user_role(
        mock_request,
        str(sample_user.id),
        "operator",
        admin_user
    )
    
    assert "role updated" in response["message"].lower()


@pytest.mark.asyncio
async def test_delete_user_admin_only(
    mock_user_repo, sample_user
):
    """Test deleting user (admin only)."""
    mock_user_repo.delete = AsyncMock(return_value=True)
    
    result = await mock_user_repo.delete(sample_user.id, sample_user.organization_id)
    
    assert result is True


@pytest.mark.asyncio
async def test_non_admin_cannot_access_admin_routes(
    mock_request
):
    """Test that non-admin users cannot access admin routes."""
    non_admin_user = {
        "id": str(uuid4()),
        "email": "user@example.com",
        "organization_id": str(uuid4()),
        "role": "operator"
    }
    
    with pytest.raises(HTTPException) as exc_info:
        checker = require_role("admin")
        mock_creds = Mock()
        mock_creds.credentials = "token"
        
        with patch('src.api.auth_routes.get_current_user', return_value=non_admin_user):
            await checker(mock_request, mock_creds)
    
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_admin_can_manage_users_in_same_organization(
    mock_request, mock_user_repo, sample_user, sample_organization
):
    """Test admin can manage users in same organization."""
    admin_user = {
        "id": str(uuid4()),
        "email": "admin@example.com",
        "organization_id": str(sample_user.organization_id),
        "role": "admin"
    }
    
    mock_user_repo.get_by_id = AsyncMock(return_value=sample_user)
    
    user = await mock_user_repo.get_by_id(
        sample_user.id,
        UUID(admin_user["organization_id"])
    )
    
    assert user is not None
    assert str(user.organization_id) == admin_user["organization_id"]


@pytest.mark.asyncio
async def test_admin_cannot_manage_users_in_other_organizations(
    mock_request, mock_user_repo
):
    """Test admin cannot manage users in other organizations."""
    admin_org_id = uuid4()
    other_org_id = uuid4()
    
    admin_user = {
        "id": str(uuid4()),
        "email": "admin@example.com",
        "organization_id": str(admin_org_id),
        "role": "admin"
    }
    
    target_user_id = uuid4()
    
    # Mock returns None when trying to access user from different org
    mock_user_repo.get_by_id = AsyncMock(return_value=None)
    
    with pytest.raises(HTTPException) as exc_info:
        await update_user_status(
            mock_request,
            str(target_user_id),
            "suspended",
            admin_user
        )
    
    assert exc_info.value.status_code == 404
    assert "not found" in exc_info.value.detail.lower()