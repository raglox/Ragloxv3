# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Lazy Provisioning Integration Tests
# End-to-end tests for the complete lazy provisioning flow
# ═══════════════════════════════════════════════════════════════
"""
Integration tests for Lazy Provisioning complete flow.

Coverage:
- Complete flow: register → vm_status = not_created
- First mission → lazy provision starts
- Execute command → simulation mode during provisioning
- VM becomes ready → execute via SSH
- VM hibernation and wake-up cycle
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from uuid import uuid4, UUID
from datetime import datetime

from src.api.auth_routes import (
    register, get_vm_status, provision_user_vm,
    RegisterRequest, VMConfiguration, VMProvisionStatus
)
from src.controller.mission import MissionController
from src.core.models import MissionCreate
from src.core.blackboard import Blackboard
from src.core.config import Settings


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def mock_settings():
    """Mock Settings."""
    settings = Mock(spec=Settings)
    settings.redis_host = "localhost"
    settings.redis_port = 6379
    settings.redis_db = 0
    settings.redis_password = None
    settings.jwt_secret = "test_secret"
    settings.jwt_algorithm = "HS256"
    settings.jwt_expiration_hours = 24
    settings.oneprovider_enabled = True
    settings.oneprovider_api_key = "test_key"
    settings.oneprovider_client_key = "test_client"
    settings.oneprovider_project_uuid = "project-123"
    settings.oneprovider_default_plan = 86
    settings.oneprovider_default_os = 1197
    settings.oneprovider_default_location = 34
    return settings


@pytest.fixture
def mock_blackboard():
    """Mock Blackboard."""
    blackboard = AsyncMock(spec=Blackboard)
    blackboard.redis = AsyncMock()
    blackboard._redis = True
    blackboard.health_check = AsyncMock(return_value=True)
    blackboard.connect = AsyncMock()
    blackboard.create_mission = AsyncMock(return_value=str(uuid4()))
    blackboard.get_mission = AsyncMock()
    blackboard.update_mission_status = AsyncMock()
    blackboard.publish_dict = AsyncMock()
    return blackboard


@pytest.fixture
def mock_user_repo():
    """Mock UserRepository."""
    repo = AsyncMock()
    repo.get_by_email_global = AsyncMock(return_value=None)
    repo.create = AsyncMock()
    repo.get = AsyncMock()
    repo.update = AsyncMock()
    repo.get_by_id = AsyncMock()
    return repo


@pytest.fixture
def mock_org_repo():
    """Mock OrganizationRepository."""
    repo = AsyncMock()
    repo.create = AsyncMock()
    repo.get_by_id = AsyncMock()
    return repo


@pytest.fixture
def mock_token_store():
    """Mock TokenStore."""
    store = AsyncMock()
    store.store_token = AsyncMock(return_value=True)
    store.validate_token = AsyncMock(return_value="user-id")
    return store


@pytest.fixture
def mock_environment_manager():
    """Mock EnvironmentManager."""
    manager = AsyncMock()
    manager.list_user_environments = AsyncMock(return_value=[])
    manager.create_environment = AsyncMock()
    return manager


@pytest.fixture
def mock_request(mock_user_repo, mock_org_repo, mock_token_store):
    """Mock FastAPI Request."""
    request = Mock()
    request.app.state.user_repo = mock_user_repo
    request.app.state.org_repo = mock_org_repo
    request.app.state.token_store = mock_token_store
    request.client.host = "127.0.0.1"
    return request


# ═══════════════════════════════════════════════════════════════
# Integration Test: Complete Lazy Provisioning Flow
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
@pytest.mark.skip(reason="Simulation mode removed")
async def test_complete_lazy_provisioning_flow(
    mock_request,
    mock_user_repo,
    mock_org_repo,
    mock_token_store,
    mock_blackboard,
    mock_settings,
    mock_environment_manager
):
    """
    Test the complete lazy provisioning flow from registration to command execution.
    
    Flow:
    1. User registers → vm_status = 'not_created'
    2. User creates first mission
    3. User executes command → triggers lazy provisioning
    4. Command runs in simulation mode while VM provisions
    5. VM becomes ready
    6. Subsequent commands execute via SSH
    """
    user_id = uuid4()
    org_id = uuid4()
    mission_id = str(uuid4())
    
    # Step 1: User Registration
    from src.core.database.user_repository import User
    from src.core.database.organization_repository import Organization
    
    sample_org = Organization(
        id=org_id,
        name="Test Org",
        slug="test-org",
        owner_email="test@example.com",
        plan="free",
        is_active=True,
        created_at=datetime.utcnow()
    )
    
    sample_user = User(
        id=user_id,
        organization_id=org_id,
        username="testuser",
        email="test@example.com",
        password_hash="$2b$12$hashed",
        full_name="Test User",
        role="admin",
        is_active=True,
        is_org_owner=True,
        metadata={"vm_status": VMProvisionStatus.NOT_CREATED.value},
        created_at=datetime.utcnow()
    )
    
    mock_org_repo.create.return_value = sample_org
    mock_user_repo.create.return_value = sample_user
    
    register_data = RegisterRequest(
        email="test@example.com",
        password="SecurePass123!",
        full_name="Test User",
        organization_name="Test Org"
    )
    
    background_tasks = Mock()
    background_tasks.add_task = Mock()
    
    with patch('src.api.auth_routes.bcrypt.hashpw'), \
         patch('src.api.auth_routes.bcrypt.gensalt'), \
         patch('src.api.auth_routes.create_access_token', return_value=("token", 3600)):
        
        register_response = await register(
            request=mock_request,
            data=register_data,
            background_tasks=background_tasks
        )
    
    # Verify user registered with not_created status
    assert register_response.user.vm_status == VMProvisionStatus.NOT_CREATED.value
    assert register_response.user.vm_ip is None
    background_tasks.add_task.assert_not_called()
    
    # Step 2: Create First Mission
    controller = MissionController(
        blackboard=mock_blackboard,
        settings=mock_settings,
        environment_manager=mock_environment_manager
    )
    
    mission_data = MissionCreate(
        name="Test Mission",
        description="First mission",
        scope=["192.168.1.0/24"],
        goals=["Gain access"]
    )
    
    created_mission_id = await controller.create_mission(
        mission_data=mission_data,
        organization_id=str(org_id),
        created_by=str(user_id)
    )
    
    assert created_mission_id is not None
    
    # Step 3: Execute First Command → Triggers Lazy Provisioning
    mock_blackboard.get_mission.return_value = {
        "id": created_mission_id,
        "created_by": str(user_id),
        "organization_id": str(org_id)
    }
    
    mock_user_repo.get.return_value = {
        "id": str(user_id),
        "organization_id": str(org_id),
        "metadata": {"vm_status": VMProvisionStatus.NOT_CREATED.value}
    }
    
    with patch('src.core.database.user_repository.UserRepository', return_value=mock_user_repo), \
         patch('src.api.auth_routes.provision_user_vm') as mock_provision, \
         patch('asyncio.create_task') as mock_create_task, \
         patch('src.api.websocket.broadcast_terminal_output', new_callable=AsyncMock):
        
        output = await controller._execute_shell_command(created_mission_id, "ls -la")
        
        # Verify simulation mode was used
        assert "[SIMULATION MODE" in output
        
        # Verify provisioning was triggered
        assert mock_user_repo.update.called or mock_create_task.called
    
    # Step 4: VM Provisioning Completes
    vm_ip = "192.168.1.100"
    vm_id = "vm-12345"
    
    mock_user_repo.get.return_value = {
        "id": str(user_id),
        "organization_id": str(org_id),
        "metadata": {
            "vm_status": VMProvisionStatus.READY.value,
            "vm_id": vm_id,
            "vm_ip": vm_ip,
            "vm_ssh_user": "root",
            "vm_ssh_password": "test_password",
            "vm_ssh_port": 22
        }
    }
    
    # Step 5: Execute Command via SSH
    mock_env = Mock()
    mock_env.status.value = "connected"
    mock_env.ssh_manager = Mock()
    mock_env.connection_id = "conn-123"
    mock_env.environment_id = "env-123"
    mock_environment_manager.create_environment.return_value = mock_env
    
    mock_result = Mock()
    mock_result.status = "success"
    mock_result.stdout = "total 24\ndrwxr-xr-x 4 root root 4096"
    mock_result.stderr = ""
    mock_result.exit_code = 0
    
    with patch('src.core.database.user_repository.UserRepository', return_value=mock_user_repo), \
         patch('src.infrastructure.orchestrator.agent_executor.AgentExecutor') as mock_executor_class, \
         patch('src.api.websocket.broadcast_terminal_output', new_callable=AsyncMock):
        
        mock_executor = AsyncMock()
        mock_executor.execute_command = AsyncMock(return_value=mock_result)
        mock_executor_class.return_value = mock_executor
        
        output = await controller._execute_shell_command(created_mission_id, "ls -la")
        
        # Verify real execution (not simulation)
        assert "[SIMULATION MODE" not in output
        assert "total 24" in output
        mock_executor.execute_command.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.skip(reason="Simulation mode removed")
async def test_registration_to_first_command_flow(
    mock_request,
    mock_user_repo,
    mock_org_repo,
    mock_blackboard,
    mock_settings,
    mock_environment_manager
):
    """
    Test simplified flow: register → create mission → execute command.
    """
    user_id = uuid4()
    org_id = uuid4()
    
    from src.core.database.user_repository import User
    from src.core.database.organization_repository import Organization
    
    sample_user = User(
        id=user_id,
        organization_id=org_id,
        username="user",
        email="user@test.com",
        password_hash="hash",
        full_name="User",
        role="admin",
        is_active=True,
        is_org_owner=True,
        metadata={"vm_status": "not_created"},
        created_at=datetime.utcnow()
    )
    
    sample_org = Organization(
        id=org_id,
        name="Org",
        slug="org",
        owner_email="user@test.com",
        plan="free",
        is_active=True,
        created_at=datetime.utcnow()
    )
    
    mock_user_repo.create.return_value = sample_user
    mock_org_repo.create.return_value = sample_org
    
    # Register
    register_data = RegisterRequest(
        email="user@test.com",
        password="Pass123!",
        full_name="User",
        organization_name="Org"
    )
    
    background_tasks = Mock()
    
    with patch('src.api.auth_routes.bcrypt.hashpw'), \
         patch('src.api.auth_routes.bcrypt.gensalt'), \
         patch('src.api.auth_routes.create_access_token', return_value=("token", 3600)):
        
        response = await register(mock_request, register_data, background_tasks)
    
    assert response.user.vm_status == "not_created"
    
    # Create mission and execute command
    controller = MissionController(mock_blackboard, mock_settings, mock_environment_manager)
    
    mission_id = await controller.create_mission(
        MissionCreate(name="M", description="D", scope=["10.0.0.0/24"], goals=["G"]),
        str(org_id),
        str(user_id)
    )
    
    mock_blackboard.get_mission.return_value = {
        "id": mission_id,
        "created_by": str(user_id)
    }
    
    mock_user_repo.get.return_value = {
        "id": str(user_id),
        "metadata": {"vm_status": "not_created"}
    }
    
    with patch('src.core.database.user_repository.UserRepository', return_value=mock_user_repo), \
         patch('src.api.websocket.broadcast_terminal_output', new_callable=AsyncMock):
        
        output = await controller._execute_shell_command(mission_id, "whoami")
        assert "[SIMULATION MODE" in output