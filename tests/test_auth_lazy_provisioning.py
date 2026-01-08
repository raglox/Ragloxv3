
# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Lazy Provisioning Tests (Auth Routes)
# Tests for user registration and VM provisioning endpoints
# ═══════════════════════════════════════════════════════════════
"""
Tests for Lazy Provisioning in authentication routes.

Coverage:
- User registration without auto-provisioning
- VM status after registration (should be 'not_created')
- get_vm_status() endpoint
- provision_user_vm() endpoint with mocked OneProvider
- reprovision_vm() endpoint
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from uuid import uuid4, UUID
from datetime import datetime

from src.api.auth_routes import (
    register, login, get_vm_status, reprovision_vm,
    provision_user_vm, VMConfiguration, VMProvisionStatus,
    RegisterRequest, LoginRequest
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
    return store


@pytest.fixture
def mock_request(mock_user_repo, mock_org_repo, mock_token_store):
    """Mock FastAPI Request object."""
    request = Mock()
    request.app.state.user_repo = mock_user_repo
    request.app.state.org_repo = mock_org_repo
    request.app.state.token_store = mock_token_store
    request.client.host = "127.0.0.1"
    return request


@pytest.fixture
def sample_user():
    """Sample user entity."""
    org_id = uuid4()
    user_id = uuid4()
    return User(
        id=user_id,
        organization_id=org_id,
        username="testuser",
        email="test@example.com",
        password_hash="$2b$12$hashed_password",
        full_name="Test User",
        role="admin",
        is_active=True,
        is_org_owner=True,
        metadata={"vm_status": VMProvisionStatus.NOT_CREATED.value},
        created_at=datetime.utcnow()
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


# ═══════════════════════════════════════════════════════════════
# Test: User Registration with Lazy Provisioning
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_register_user_without_auto_provisioning(
    mock_request,
    mock_user_repo,
    mock_org_repo,
    mock_token_store,
    sample_user,
    sample_organization
):
    """
    Test that user registration does NOT automatically provision VM.
    
    Expected behavior:
    - User is created with vm_status = 'not_created'
    - No background task is started for VM provisioning
    - User receives access token immediately
    """
    # Setup mocks
    mock_user_repo.get_by_email_global = AsyncMock(return_value=None)
    mock_user_repo.create = AsyncMock(return_value=sample_user)
    mock_org_repo.create = AsyncMock(return_value=sample_organization)
    mock_token_store.store_token = AsyncMock(return_value=True)
    
    # Create registration request
    register_data = RegisterRequest(
        email="test@example.com",
        password="SecurePass123!",
        full_name="Test User",
        organization_name="Test Organization"
    )
    
    # Mock BackgroundTasks
    background_tasks = Mock()
    background_tasks.add_task = Mock()
    
    # Execute registration
    with patch('src.api.auth_routes.bcrypt.hashpw') as mock_hash, \
         patch('src.api.auth_routes.bcrypt.gensalt') as mock_salt, \
         patch('src.api.auth_routes.create_access_token') as mock_create_token:
        
        mock_hash.return_value = b"hashed_password"
        mock_salt.return_value = b"salt"
        mock_create_token.return_value = ("test_token", 3600)
        
        response = await register(
            request=mock_request,
            data=register_data,
            background_tasks=background_tasks
        )
    
    # Assertions
    assert response.access_token == "test_token"
    assert response.user.vm_status == VMProvisionStatus.NOT_CREATED.value
    assert response.user.vm_ip is None
    assert response.user.status == "active"
    
    # Verify NO background task was added for VM provisioning
    background_tasks.add_task.assert_not_called()
    
    # Verify user was created with correct metadata
    mock_user_repo.create.assert_called_once()
    created_user = mock_user_repo.create.call_args[0][0]
    assert created_user.metadata["vm_status"] == VMProvisionStatus.NOT_CREATED.value


@pytest.mark.asyncio
async def test_register_sets_vm_status_not_created(
    mock_request,
    mock_user_repo,
    mock_org_repo,
    mock_token_store,
    sample_user,
    sample_organization
):
    """
    Test that newly registered users have vm_status = 'not_created'.
    """
    mock_user_repo.get_by_email_global = AsyncMock(return_value=None)
    mock_user_repo.create = AsyncMock(return_value=sample_user)
    mock_org_repo.create = AsyncMock(return_value=sample_organization)
    
    register_data = RegisterRequest(
        email="newuser@example.com",
        password="SecurePass123!",
        full_name="New User",
        organization_name="New Org"
    )
    
    background_tasks = Mock()
    
    with patch('src.api.auth_routes.bcrypt.hashpw'), \
         patch('src.api.auth_routes.bcrypt.gensalt'), \
         patch('src.api.auth_routes.create_access_token', return_value=("token", 3600)):
        
        response = await register(
            request=mock_request,
            data=register_data,
            background_tasks=background_tasks
        )
    
    # Verify vm_status is set correctly
    assert response.user.vm_status == VMProvisionStatus.NOT_CREATED.value
    
    # Verify user object passed to create() has correct metadata
    created_user = mock_user_repo.create.call_args[0][0]
    assert "vm_status" in created_user.metadata
    assert created_user.metadata["vm_status"] == VMProvisionStatus.NOT_CREATED.value


# ═══════════════════════════════════════════════════════════════
# Test: get_vm_status() Endpoint
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_get_vm_status_not_created(mock_request):
    """
    Test get_vm_status() returns correct status for not_created VM.
    """
    # Mock current user with not_created status
    current_user = {
        "id": str(uuid4()),
        "email": "test@example.com",
        "metadata": {
            "vm_status": VMProvisionStatus.NOT_CREATED.value
        }
    }
    
    response = await get_vm_status(
        request=mock_request,
        user=current_user
    )
    
    assert response["vm_status"] == VMProvisionStatus.NOT_CREATED.value
    assert response["vm_id"] is None
    assert response["vm_ip"] is None
    assert "will be created when you start your first mission" in response["message"]


@pytest.mark.asyncio
async def test_get_vm_status_ready(mock_request):
    """
    Test get_vm_status() returns correct status for ready VM.
    """
    current_user = {
        "id": str(uuid4()),
        "email": "test@example.com",
        "metadata": {
            "vm_status": VMProvisionStatus.READY.value,
            "vm_id": "vm-12345",
            "vm_ip": "192.168.1.100"
        }
    }
    
    response = await get_vm_status(
        request=mock_request,
        user=current_user
    )
    
    assert response["vm_status"] == VMProvisionStatus.READY.value
    assert response["vm_id"] == "vm-12345"
    assert response["vm_ip"] == "192.168.1.100"
    assert "ready" in response["message"].lower()


@pytest.mark.asyncio
async def test_get_vm_status_stopped(mock_request):
    """
    Test get_vm_status() returns correct status for stopped VM.
    """
    current_user = {
        "id": str(uuid4()),
        "email": "test@example.com",
        "metadata": {
            "vm_status": VMProvisionStatus.STOPPED.value,
            "vm_id": "vm-12345",
            "vm_ip": "192.168.1.100"
        }
    }
    
    response = await get_vm_status(
        request=mock_request,
        user=current_user
    )
    
    assert response["vm_status"] == VMProvisionStatus.STOPPED.value
    assert "sleep mode" in response["message"].lower()


# ═══════════════════════════════════════════════════════════════
# Test: provision_user_vm() Background Task
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_provision_user_vm_success(mock_user_repo):
    """
    Test successful VM provisioning with mocked OneProvider.
    """
    user_id = str(uuid4())
    org_id = str(uuid4())
    vm_config = VMConfiguration()
    
    # Mock VM instance
    mock_vm = Mock()
    mock_vm.vm_id = "vm-12345"
    mock_vm.ipv4 = "192.168.1.100"
    mock_vm.ipv6 = None
    
    # Mock VMManager
    mock_vm_manager = AsyncMock()
    mock_vm_manager.create_vm = AsyncMock(return_value=mock_vm)
    mock_vm_manager.get_vm = AsyncMock(return_value=mock_vm)
    
    # Mock OneProviderClient
    mock_client = Mock()
    
    with patch('src.api.auth_routes.get_settings') as mock_settings, \
         patch('src.infrastructure.cloud_provider.oneprovider_client.OneProviderClient', return_value=mock_client), \
         patch('src.infrastructure.cloud_provider.vm_manager.VMManager', return_value=mock_vm_manager), \
         patch('asyncio.sleep', new_callable=AsyncMock):
        
        # Configure settings
        settings = Mock()
        settings.oneprovider_enabled = True
        settings.oneprovider_api_key = "test_key"
        settings.oneprovider_client_key = "test_client"
        settings.oneprovider_project_uuid = "project-123"
        settings.oneprovider_default_plan = 86
        settings.oneprovider_default_os = 1197
        settings.oneprovider_default_location = 34
        mock_settings.return_value = settings
        
        # Execute provisioning
        await provision_user_vm(
            user_id=user_id,
            organization_id=org_id,
            vm_config=vm_config,
            user_repo=mock_user_repo
        )
    
    # Verify VM was created
    mock_vm_manager.create_vm.assert_called_once()
    
    # Verify user metadata was updated with VM details
    assert mock_user_repo.update.call_count >= 2  # At least CREATING and READY
    
    # Check final update call
    final_call = mock_user_repo.update.call_args_list[-1]
    final_metadata = final_call[0][1]["metadata"]
    
    assert final_metadata["vm_status"] == VMProvisionStatus.READY.value
    assert final_metadata["vm_id"] == "vm-12345"
    assert final_metadata["vm_ip"] == "192.168.1.100"
    assert "vm_ssh_password" in final_metadata


@pytest.mark.asyncio
async def test_provision_user_vm_disabled(mock_user_repo):
    """
    Test that provisioning is skipped when OneProvider is disabled.
    """
    user_id = str(uuid4())
    org_id = str(uuid4())
    vm_config = VMConfiguration()
    
    with patch('src.api.auth_routes.get_settings') as mock_settings:
        settings = Mock()
        settings.oneprovider_enabled = False
        mock_settings.return_value = settings
        
        await provision_user_vm(
            user_id=user_id,
            organization_id=org_id,
            vm_config=vm_config,
            user_repo=mock_user_repo
        )
    
    # Verify metadata was cleared (vm_status set to None)
    mock_user_repo.update.assert_called()
    update_call = mock_user_repo.update.call_args[0][1]
    assert update_call["metadata"]["vm_status"] is None


@pytest.mark.asyncio
async def test_provision_user_vm_failure(mock_user_repo):
    """
    Test VM provisioning failure handling.
    """
    user_id = str(uuid4())
    org_id = str(uuid4())
    vm_config = VMConfiguration()
    
    # Mock VMManager that raises exception
    mock_vm_manager = AsyncMock()
    mock_vm_manager.create_vm = AsyncMock(side_effect=Exception("VM creation failed"))
    
    with patch('src.api.auth_routes.get_settings') as mock_settings, \
         patch('src.infrastructure.cloud_provider.oneprovider_client.OneProviderClient'), \
         patch('src.infrastructure.cloud_provider.vm_manager.VMManager', return_value=mock_vm_manager):
        
        settings = Mock()
        settings.oneprovider_enabled = True
        settings.oneprovider_api_key = "test_key"
        settings.oneprovider_client_key = "test_client"
        settings.oneprovider_project_uuid = "project-123"
        settings.oneprovider_default_plan = 86
        settings.oneprovider_default_os = 1197
        settings.oneprovider_default_location = 34
        mock_settings.return_value = settings
        
        await provision_user_vm(
            user_id=user_id,
            organization_id=org_id,
            vm_config=vm_config,
            user_repo=mock_user_repo
        )
    
    # Verify status was set to FAILED
    final_call = mock_user_repo.update.call_args_list[-1]
    final_metadata = final_call[0][1]["metadata"]
    assert final_metadata["vm_status"] == VMProvisionStatus.FAILED.value


# ═══════════════════════════════════════════════════════════════
# Test: reprovision_vm() Endpoint
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_reprovision_vm_success(mock_request, mock_user_repo):
    """
    Test successful VM re-provisioning.
    """
    user_id = uuid4()
    org_id = uuid4()
    
    current_user = {
        "id": str(user_id),
        "organization_id": str(org_id),
        "email": "test@example.com",
        "metadata": {
            "vm_status": VMProvisionStatus.FAILED.value
        }
    }
    
    background_tasks = Mock()
    background_tasks.add_task = Mock()
    
    response = await reprovision_vm(
        request=mock_request,
        background_tasks=background_tasks,
        vm_config=None,
        user=current_user
    )
    
    assert response["message"] == "VM re-provisioning started"
    
    # Verify status was reset to PENDING
    mock_user_repo.update.assert_called_once()
    update_call = mock_user_repo.update.call_args
    assert update_call[0][0] == user_id
    assert update_call[0][1]["metadata"]["vm_status"] == VMProvisionStatus.PENDING.value
    
    # Verify background task was started
    background_tasks.add_task.assert_called_once()


@pytest.mark.asyncio
async def test_reprovision_vm_already_creating(mock_request, mock_user_repo):
    """
    Test that re-provisioning is rejected if VM is already being created.
    """
    from fastapi import HTTPException
    
    current_user = {
        "id": str(uuid4()),
        "organization_id": str(uuid4()),
        "email": "test@example.com",
        "metadata": {
            "vm_status": VMProvisionStatus.CREATING.value
        }
    }
    
    background_tasks = Mock()
    
    with pytest.raises(HTTPException) as exc_info:
        await reprovision_vm(
            request=mock_request,
            background_tasks=background_tasks,
            vm_config=None,
            user=current_user
        )
    
    assert exc_info.value.status_code == 409
    assert "currently being provisioned" in exc_info.value.detail


@pytest.mark.asyncio
async def test_get_vm_status_no_metadata(mock_request):
    """
    Test get_vm_status() when user has no metadata.
    """
    current_user = {
        "id": str(uuid4()),
        "email": "test@example.com",
        "metadata": {}
    }
    
    response = await get_vm_status(
        request=mock_request,
        user=current_user
    )
    
    assert response["vm_status"] is None
    assert response["vm_id"] is None
    assert response["vm_ip"] is None