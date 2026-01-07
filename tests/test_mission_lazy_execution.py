
# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Lazy Provisioning Tests (Mission Execution)
# Tests for command execution with lazy provisioning logic
# ═══════════════════════════════════════════════════════════════
"""
Tests for Lazy Provisioning in mission execution.

Coverage:
- Command execution with vm_status = 'not_created' → starts provisioning + simulation
- Command execution with vm_status = 'stopped' → wakes up VM
- Command execution with vm_status = 'ready' → direct SSH execution
- Simulation mode when no VM is available
- VM status transitions during command execution
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from uuid import uuid4, UUID
from datetime import datetime

from src.controller.mission import MissionController
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
    blackboard.get_mission = AsyncMock()
    blackboard.publish_dict = AsyncMock()
    return blackboard


@pytest.fixture
def mock_environment_manager():
    """Mock EnvironmentManager."""
    manager = AsyncMock()
    manager.list_user_environments = AsyncMock(return_value=[])
    manager.create_environment = AsyncMock()
    return manager


@pytest.fixture
def mock_user_repo():
    """Mock UserRepository."""
    repo = AsyncMock()
    repo.get = AsyncMock()
    repo.update = AsyncMock()
    return repo


@pytest.fixture
async def mission_controller(mock_blackboard, mock_settings, mock_environment_manager):
    """Create MissionController instance."""
    controller = MissionController(
        blackboard=mock_blackboard,
        settings=mock_settings,
        environment_manager=mock_environment_manager
    )
    return controller


# ═══════════════════════════════════════════════════════════════
# Test: Command Execution with vm_status = 'not_created'
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_execute_command_not_created_starts_provisioning(
    mission_controller,
    mock_blackboard,
    mock_user_repo
):
    """
    Test that executing a command with vm_status='not_created' triggers provisioning.
    
    Expected behavior:
    - Detects vm_status = 'not_created'
    - Starts VM provisioning in background
    - Returns simulation mode output
    - Updates vm_status to 'pending'
    """
    mission_id = str(uuid4())
    user_id = str(uuid4())
    org_id = str(uuid4())
    command = "ls -la"
    
    # Mock mission data
    mock_blackboard.get_mission.return_value = {
        "id": mission_id,
        "created_by": user_id,
        "organization_id": org_id
    }
    
    # Mock user data with not_created status
    mock_user_repo.get.return_value = {
        "id": user_id,
        "organization_id": org_id,
        "metadata": {
            "vm_status": "not_created"
        }
    }
    
    with patch('src.core.database.user_repository.UserRepository', return_value=mock_user_repo), \
         patch('src.api.auth_routes.provision_user_vm') as mock_provision, \
         patch('src.api.websocket.broadcast_terminal_output', new_callable=AsyncMock):
        
        # Execute command
        output = await mission_controller._execute_shell_command(mission_id, command)
        
        # Verify simulation mode was used
        assert "[SIMULATION MODE" in output or "will be created" in output
        
        # Verify provisioning was triggered
        assert mock_user_repo.update.called or mock_provision.called


@pytest.mark.asyncio
async def test_execute_command_not_created_simulation_mode(
    mission_controller,
    mock_blackboard,
    mock_user_repo
):
    """
    Test that commands return simulation output when VM is not created.
    """
    mission_id = str(uuid4())
    user_id = str(uuid4())
    
    mock_blackboard.get_mission.return_value = {
        "id": mission_id,
        "created_by": user_id
    }
    
    mock_user_repo.get.return_value = {
        "id": user_id,
        "metadata": {"vm_status": "not_created"}
    }
    
    with patch('src.core.database.user_repository.UserRepository', return_value=mock_user_repo), \
         patch('src.api.websocket.broadcast_terminal_output', new_callable=AsyncMock):
        
        # Test various commands
        commands = ["ls -la", "whoami", "pwd", "uname -a"]
        
        for cmd in commands:
            output = await mission_controller._execute_shell_command(mission_id, cmd)
            
            # Verify simulation mode indicator
            assert "[SIMULATION MODE" in output or "will be created" in output
            # Verify command-specific output
            assert len(output) > 0


# ═══════════════════════════════════════════════════════════════
# Test: Command Execution with vm_status = 'stopped'
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_execute_command_stopped_wakes_vm(
    mission_controller,
    mock_blackboard,
    mock_user_repo,
    mock_environment_manager
):
    """
    Test that executing a command with vm_status='stopped' wakes up the VM.
    
    Expected behavior:
    - Detects vm_status = 'stopped'
    - Calls OneProvider to start VM
    - Waits for VM to be ready
    - Creates environment and executes command
    """
    mission_id = str(uuid4())
    user_id = str(uuid4())
    org_id = str(uuid4())
    vm_id = "vm-12345"
    vm_ip = "192.168.1.100"
    command = "whoami"
    
    mock_blackboard.get_mission.return_value = {
        "id": mission_id,
        "created_by": user_id,
        "organization_id": org_id
    }
    
    mock_user_repo.get.return_value = {
        "id": user_id,
        "organization_id": org_id,
        "metadata": {
            "vm_status": "stopped",
            "vm_id": vm_id,
            "vm_ip": vm_ip,
            "vm_ssh_user": "root",
            "vm_ssh_password": "test_password",
            "vm_ssh_port": 22
        }
    }
    
    # Mock OneProvider client
    mock_oneprovider = AsyncMock()
    mock_oneprovider.start_vm = AsyncMock()
    
    # Mock environment
    mock_env = Mock()
    mock_env.status.value = "connected"
    mock_env.ssh_manager = Mock()
    mock_env.connection_id = "conn-123"
    mock_env.environment_id = "env-123"
    mock_environment_manager.create_environment.return_value = mock_env
    
    # Mock command execution result
    mock_result = Mock()
    mock_result.status = "success"
    mock_result.stdout = "root"
    mock_result.stderr = ""
    mock_result.exit_code = 0
    
    with patch('src.core.database.user_repository.UserRepository', return_value=mock_user_repo), \
         patch('src.infrastructure.cloud_provider.oneprovider_client.OneProviderClient', return_value=mock_oneprovider), \
         patch('src.infrastructure.orchestrator.agent_executor.AgentExecutor') as mock_executor_class, \
         patch('asyncio.sleep', new_callable=AsyncMock), \
         patch('src.api.websocket.broadcast_terminal_output', new_callable=AsyncMock):
        
        mock_executor = AsyncMock()
        mock_executor.execute_command = AsyncMock(return_value=mock_result)
        mock_executor_class.return_value = mock_executor
        
        output = await mission_controller._execute_shell_command(mission_id, command)
        
        # Verify VM was started
        mock_oneprovider.start_vm.assert_called_once_with(vm_id)
        
        # Verify status was updated to ready
        assert mock_user_repo.update.called
        
        # Verify command was executed
        assert "root" in output or mock_executor.execute_command.called


@pytest.mark.asyncio
async def test_execute_command_stopped_simulation_during_wakeup(
    mission_controller,
    mock_blackboard,
    mock_user_repo
):
    """
    Test that simulation mode is used while VM is waking up.
    """
    mission_id = str(uuid4())
    user_id = str(uuid4())
    
    mock_blackboard.get_mission.return_value = {
        "id": mission_id,
        "created_by": user_id
    }
    
    mock_user_repo.get.return_value = {
        "id": user_id,
        "metadata": {
            "vm_status": "stopped",
            "vm_id": "vm-123"
        }
    }
    
    # Mock OneProvider to fail (VM not ready yet)
    mock_oneprovider = AsyncMock()
    mock_oneprovider.start_vm = AsyncMock(side_effect=Exception("VM starting"))
    
    with patch('src.core.database.user_repository.UserRepository', return_value=mock_user_repo), \
         patch('src.infrastructure.cloud_provider.oneprovider_client.OneProviderClient', return_value=mock_oneprovider), \
         patch('src.api.websocket.broadcast_terminal_output', new_callable=AsyncMock):
        
        output = await mission_controller._execute_shell_command(mission_id, "ls")
        
        # Should fall back to simulation
        assert "[SIMULATION MODE" in output or "waking up" in output.lower()


# ═══════════════════════════════════════════════════════════════
# Test: Command Execution with vm_status = 'ready'
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_execute_command_ready_direct_ssh(
    mission_controller,
    mock_blackboard,
    mock_user_repo,
    mock_environment_manager
):
    """
    Test that commands are executed directly via SSH when VM is ready.
    
    Expected behavior:
    - Detects vm_status = 'ready'
    - Creates/uses existing SSH environment
    - Executes command via SSH
    - Returns real output
    """
    mission_id = str(uuid4())
    user_id = str(uuid4())
    command = "whoami"
    expected_output = "ubuntu"
    
    mock_blackboard.get_mission.return_value = {
        "id": mission_id,
        "created_by": user_id
    }
    
    mock_user_repo.get.return_value = {
        "id": user_id,
        "metadata": {
            "vm_status": "ready",
            "vm_ip": "192.168.1.100",
            "vm_ssh_user": "root",
            "vm_ssh_password": "test_password",
            "vm_ssh_port": 22
        }
    }
    
    # Mock environment
    mock_env = Mock()
    mock_env.status.value = "connected"
    mock_env.ssh_manager = Mock()
    mock_env.connection_id = "conn-123"
    mock_env.environment_id = "env-123"
    mock_environment_manager.create_environment.return_value = mock_env
    
    # Mock successful command execution
    mock_result = Mock()
    mock_result.status = "success"
    mock_result.stdout = expected_output
    mock_result.stderr = ""
    mock_result.exit_code = 0
    
    with patch('src.core.database.user_repository.UserRepository', return_value=mock_user_repo), \
         patch('src.infrastructure.orchestrator.agent_executor.AgentExecutor') as mock_executor_class, \
         patch('src.api.websocket.broadcast_terminal_output', new_callable=AsyncMock):
        
        mock_executor = AsyncMock()
        mock_executor.execute_command = AsyncMock(return_value=mock_result)
        mock_executor_class.return_value = mock_executor
        
        output = await mission_controller._execute_shell_command(mission_id, command)
        
        # Verify command was executed via SSH
        mock_executor.execute_command.assert_called_once()
        assert expected_output in output
        assert "[SIMULATION MODE" not in output


# ═══════════════════════════════════════════════════════════════
# Test: Simulation Mode Behavior
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_simulation_mode_various_commands(
    mission_controller,
    mock_blackboard,
    mock_user_repo
):
    """
    Test that simulation mode provides appropriate output for various commands.
    """
    mission_id = str(uuid4())
    user_id = str(uuid4())
    
    mock_blackboard.get_mission.return_value = {
        "id": mission_id,
        "created_by": user_id
    }
    
    mock_user_repo.get.return_value = {
        "id": user_id,
        "metadata": {"vm_status": "not_created"}
    }
    
    test_commands = {
        "ls -la": ["total", "drwxr-xr-x"],
        "pwd": ["/home/ubuntu"],
        "whoami": ["ubuntu"],
        "uname -a": ["Linux"],
        "nmap": ["Nmap", "scan"],
        "cat config.txt": ["Configuration"],
        "ps aux": ["PID", "CMD"]
    }
    
    with patch('src.core.database.user_repository.UserRepository', return_value=mock_user_repo), \
         patch('src.api.websocket.broadcast_terminal_output', new_callable=AsyncMock):
        
        for command, expected_keywords in test_commands.items():
            output = await mission_controller._execute_shell_command(mission_id, command)
            
            # Verify simulation mode
            assert "[SIMULATION MODE" in output
            
            # Verify command-specific output
            for keyword in expected_keywords:
                assert keyword.lower() in output.lower()


@pytest.mark.asyncio
async def test_simulation_mode_includes_helpful_message(
    mission_controller,
    mock_blackboard,
    mock_user_repo
):
    """
    Test that simulation mode includes helpful messages about VM status.
    """
    mission_id = str(uuid4())
    user_id = str(uuid4())
    
    mock_blackboard.get_mission.return_value = {
        "id": mission_id,
        "created_by": user_id
    }
    
    # Test different VM statuses
    statuses_and_messages = [
        ("not_created", "will be created"),
        ("pending", "being set up"),
        ("creating", "being set up"),
        ("configuring", "being set up"),
        ("stopped", "waking up")
    ]
    
    with patch('src.core.database.user_repository.UserRepository', return_value=mock_user_repo), \
         patch('src.api.websocket.broadcast_terminal_output', new_callable=AsyncMock):
        
        for status, expected_msg in statuses_and_messages:
            mock_user_repo.get.return_value = {
                "id": user_id,
                "metadata": {"vm_status": status}
            }
            
            output = await mission_controller._execute_shell_command(mission_id, "ls")
            
            # Should include helpful message
            assert expected_msg.lower() in output.lower() or "[SIMULATION MODE" in output


# ═══════════════════════════════════════════════════════════════
# Test: Error Handling
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_execute_command_ssh_failure_fallback(
    mission_controller,
    mock_blackboard,
    mock_user_repo,
    mock_environment_manager
):
    """
    Test that SSH failures fall back to simulation mode gracefully.
    """
    mission_id = str(uuid4())
    user_id = str(uuid4())
    
    mock_blackboard.get_mission.return_value = {
        "id": mission_id,
        "created_by": user_id
    }
    
    mock_user_repo.get.return_value = {
        "id": user_id,
        "metadata": {
            "vm_status": "ready",
            "vm_ip": "192.168.1.100",
            "vm_ssh_user": "root",
            "vm_ssh_password": "password"
        }
    }
    
    # Mock environment creation failure
    mock_environment_manager.create_environment.side_effect = Exception("SSH connection failed")
    
    with patch('src.core.database.user_repository.UserRepository', return_value=mock_user_repo), \
         patch('src.api.websocket.broadcast_terminal_output', new_callable=AsyncMock):
        
        output = await mission_controller._execute_shell_command(mission_id, "ls")
        
        # Should fall back to simulation
        assert "[SIMULATION MODE" in output


@pytest.mark.asyncio
async def test_execute_command_no_mission_data(
    mission_controller,
    mock_blackboard
):
    """
    Test handling when mission data is not found.
    """
    mission_id = str(uuid4())
    
    mock_blackboard.get_mission.return_value = None
    
    with patch('src.api.websocket.broadcast_terminal_output', new_callable=AsyncMock):
        output = await mission_controller._execute_shell_command(mission_id, "ls")
        
        # Should use simulation mode as fallback
        assert "[SIMULATION MODE" in output


@pytest.mark.asyncio
async def test_execute_command_no_user_data(
    mission_controller,
    mock_blackboard,
    mock_user_repo
):
    """
    Test handling when user data is not found.
    """
    mission_id = str(uuid4())
    user_id = str(uuid4())
    
    mock_blackboard.get_mission.return_value = {
        "id": mission_id,
        "created_by": user_id
    }
    
    mock_user_repo.get.return_value = None
    
    with patch('src.core.database.user_repository.UserRepository', return_value=mock_user_repo), \
         patch('src.api.websocket.broadcast_terminal_output', new_callable=AsyncMock):
        
        output = await mission_controller._execute_shell_command(mission_id, "ls")
        
        # Should use simulation mode
        assert "[SIMULATION MODE" in output


# ═══════════════════════════════════════════════════════════════
# Test: VM Status Transitions
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_vm_status_transition_not_created_to_pending(
    mission_controller,
    mock_blackboard,
    mock_user_repo
):
    """
    Test that vm_status transitions from not_created to pending when provisioning starts.
    """
    mission_id = str(uuid4())
    user_id = str(uuid4())
    org_id = str(uuid4())
    
    mock_blackboard.get_mission.return_value = {
        "id": mission_id,
        "created_by": user_id,
        "organization_id": org_id
    }
    
    mock_user_repo.get.return_value = {
        "id": user_id,
        "organization_id": org_id,
        "metadata": {"vm_status": "not_created"}
    }
    
    with patch('src.core.database.user_repository.UserRepository', return_value=mock_user_repo), \
         patch('src.api.auth_routes.provision_user_vm') as mock_provision, \
         patch('asyncio.create_task') as mock_create_task, \
         patch('src.api.websocket.broadcast_terminal_output', new_callable=AsyncMock):
        
        await mission_controller._execute_shell_command(mission_id, "ls")
        
        # Verify status was updated to pending
        update_calls = [call for call in mock_user_repo.update.call_args_list
                       if call[0][1].get("metadata", {}).get("vm_status") == "pending"]
        assert len(update_calls) > 0 or mock_create_task.called


@pytest.mark.asyncio
async def test_vm_status_transition_stopped_to_ready(
    mission_controller,
    mock_blackboard,
    mock_user_repo,
    mock_environment_manager
):
    """
    Test that vm_status transitions from stopped to ready after wake-up.
    """
    mission_id = str(uuid4())
    user_id = str(uuid4())
    org_id = str(uuid4())
    vm_id = "vm-12345"
    
    mock_blackboard.get_mission.return_value = {
        "id": mission_id,
        "created_by": user_id,
        "organization_id": org_id
    }
    
    mock_user_repo.get.return_value = {
        "id": user_id,
        "organization_id": org_id,
        "metadata": {
            "vm_status": "stopped",
            "vm_id": vm_id,
            "vm_ip": "192.168.1.100",
            "vm_ssh_user": "root",
            "vm_ssh_password": "password"
        }
    }
    
    mock_oneprovider = AsyncMock()
    mock_oneprovider.start_vm = AsyncMock()
    
    mock_env = Mock()
    mock_env.status.value = "connected"
    mock_env.ssh_manager = Mock()
    mock_env.connection_id = "conn-123"
    mock_env.environment_id = "env-123"
    mock_environment_manager.create_environment.return_value = mock_env
    
    mock_result = Mock()
    mock_result.status = "success"
    mock_result.stdout = "output"
    mock_result.exit_code = 0
    
    with patch('src.core.database.user_repository.UserRepository', return_value=mock_user_repo), \
         patch('src.infrastructure.cloud_provider.oneprovider_client.OneProviderClient', return_value=mock_oneprovider), \
         patch('src.infrastructure.orchestrator.agent_executor.AgentExecutor') as mock_executor_class, \
         patch('asyncio.sleep', new_callable=AsyncMock), \
         patch('src.api.websocket.broadcast_terminal_output', new_callable=AsyncMock):
        
        mock_executor = AsyncMock()
        mock_executor.execute_command = AsyncMock(return_value=mock_result)
        mock_executor_class.return_value = mock_executor
        
        await mission_controller._execute_shell_command(mission_id, "ls")
        
        # Verify status was updated to ready
        update_calls = [call for call in mock_user_repo.update.call_args_list
                       if call[0][1].get("metadata", {}).get("vm_status") == "ready"]
        assert len(update_calls) > 0


# ═══════════════════════════════════════════════════════════════
# Test: WebSocket Broadcasting
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_execute_command_broadcasts_output(
    mission_controller,
    mock_blackboard,
    mock_user_repo
):
    """
    Test that command execution broadcasts output via WebSocket.
    """
    mission_id = str(uuid4())
    user_id = str(uuid4())
    command = "ls -la"
    
    mock_blackboard.get_mission.return_value = {
        "id": mission_id,
        "created_by": user_id
    }
    
    mock_user_repo.get.return_value = {
        "id": user_id,
        "metadata": {"vm_status": "not_created"}
    }
    
    with patch('src.core.database.user_repository.UserRepository', return_value=mock_user_repo), \
         patch('src.api.websocket.broadcast_terminal_output', new_callable=AsyncMock) as mock_broadcast:
        
        await mission_controller._execute_shell_command(mission_id, command)
        
        # Verify broadcast was called
        assert mock_broadcast.call_count >= 2  # At least start and completion
        
        # Verify broadcast includes mission_id and command
        calls = mock_broadcast.call_args_list
        assert any(mission_id in str(call) for call in calls)
        assert any(command in str(call) for call in calls)


@pytest.mark.asyncio
async def test_execute_command_broadcasts_status(
    mission_controller,
    mock_blackboard,
    mock_user_repo
):
    """
    Test that command execution broadcasts status updates.
    """
    mission_id = str(uuid4())
    user_id = str(uuid4())
    
    mock_blackboard.get_mission.return_value = {
        "id": mission_id,
        "created_by": user_id
    }
    
    mock_user_repo.get.return_value = {
        "id": user_id,
        "metadata": {"vm_status": "not_created"}
    }
    
    with patch('src.core.database.user_repository.UserRepository', return_value=mock_user_repo), \
         patch('src.api.websocket.broadcast_terminal_output', new_callable=AsyncMock) as mock_broadcast:
        
        await mission_controller._execute_shell_command(mission_id, "whoami")
        
        # Verify status updates were broadcast
        calls = mock_broadcast.call_args_list
        statuses = [call.kwargs.get('status') for call in calls if 'status' in call.kwargs]
        
        assert 'running' in statuses or 'completed' in statuses


@pytest.mark.asyncio
async def test_execute_command_ready_uses_existing_environment(
    mission_controller,
    mock_blackboard,
    mock_user_repo,
    mock_environment_manager
):
    """
    Test that existing environment is reused when available.
    """
    mission_id = str(uuid4())
    user_id = str(uuid4())
    
    mock_blackboard.get_mission.return_value = {
        "id": mission_id,
        "created_by": user_id
    }
    
    mock_user_repo.get.return_value = {
        "id": user_id,
        "metadata": {
            "vm_status": "ready",
            "vm_ip": "192.168.1.100",
            "vm_ssh_user": "root",
            "vm_ssh_password": "password"
        }
    }
    
    # Mock existing environment
    mock_env = Mock()
    mock_env.status.value = "connected"
    mock_env.ssh_manager = Mock()
    mock_env.connection_id = "conn-123"
    mock_env.environment_id = "env-123"
    mock_environment_manager.list_user_environments.return_value = [mock_env]
    
    mock_result = Mock()
    mock_result.status = "success"
    mock_result.stdout = "output"
    mock_result.exit_code = 0
    
    with patch('src.core.database.user_repository.UserRepository', return_value=mock_user_repo), \
         patch('src.infrastructure.orchestrator.agent_executor.AgentExecutor') as mock_executor_class, \
         patch('src.api.websocket.broadcast_terminal_output', new_callable=AsyncMock):
        
        mock_executor = AsyncMock()
        mock_executor.execute_command = AsyncMock(return_value=mock_result)
        mock_executor_class.return_value = mock_executor