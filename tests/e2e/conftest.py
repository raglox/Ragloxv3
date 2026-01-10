"""
RAGLOX v3.0 - Phase 5.2 End-to-End Integration Testing
Pytest Configuration and Shared Fixtures

This module provides:
- Common test fixtures for E2E tests
- Helper functions for mission lifecycle
- Mock/stub utilities for external services
- Test data generators
- Assertion helpers
"""

import pytest
import asyncio
import uuid
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

# RAGLOX Core
from src.core.workflow_orchestrator import AgentWorkflowOrchestrator
from src.core.blackboard import Blackboard
from src.core.knowledge import EmbeddedKnowledge
from src.core.models import (
    Mission, MissionStatus, MissionCreate,
    WorkflowPhase, PhaseStatus, PhaseResult,
    TaskStatus, SpecialistType, TaskType,
    GoalStatus
)
from src.core.config import get_settings, Settings


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PYTEST CONFIGURATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "e2e: mark test as end-to-end integration test"
    )
    config.addinivalue_line(
        "markers", "easy: mark test as easy difficulty level"
    )
    config.addinivalue_line(
        "markers", "medium: mark test as medium difficulty level"
    )
    config.addinivalue_line(
        "markers", "hard: mark test as hard difficulty level"
    )
    config.addinivalue_line(
        "markers", "expert: mark test as expert difficulty level"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow-running (>60s)"
    )
    config.addinivalue_line(
        "markers", "real_llm: mark test as requiring real LLM API (DeepSeek)"
    )
    config.addinivalue_line(
        "markers", "real_infra: mark test as requiring real infrastructure (Docker/VMs)"
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CORE FIXTURES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
async def settings() -> Settings:
    """Get RAGLOX settings."""
    return get_settings()


@pytest.fixture(scope="function")
async def blackboard(settings: Settings) -> Blackboard:
    """Create and connect to Blackboard (Redis)."""
    bb = Blackboard(settings)
    await bb.connect()
    print(f"✅ Blackboard connected: {settings.redis_url}")
    
    yield bb
    
    # Cleanup
    try:
        await bb.disconnect()
        print("✅ Blackboard disconnected")
    except:
        pass


@pytest.fixture(scope="function")
async def knowledge() -> EmbeddedKnowledge:
    """Load knowledge base."""
    kb = EmbeddedKnowledge()
    kb.load()
    print(f"✅ Knowledge Base loaded: {kb.stats.total_rx_modules} modules")
    
    return kb


@pytest.fixture(scope="function")
async def orchestrator(
    settings: Settings,
    blackboard: Blackboard,
    knowledge: EmbeddedKnowledge
) -> AgentWorkflowOrchestrator:
    """Create AgentWorkflowOrchestrator instance."""
    orch = AgentWorkflowOrchestrator(
        settings=settings,
        blackboard=blackboard,
        knowledge=knowledge
    )
    print(f"✅ Orchestrator initialized")
    
    return orch


@pytest.fixture(scope="function")
async def environment(
    orchestrator: AgentWorkflowOrchestrator,
    blackboard: Blackboard,
    knowledge: EmbeddedKnowledge,
    settings: Settings
) -> Dict[str, Any]:
    """Complete E2E test environment."""
    return {
        'orchestrator': orchestrator,
        'blackboard': blackboard,
        'knowledge': knowledge,
        'settings': settings
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MISSION DATA FIXTURES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@pytest.fixture
def easy_mission_data() -> Dict[str, Any]:
    """Mission data for easy web reconnaissance."""
    return {
        "name": "Mission 01 [EASY]: Web Recon",
        "description": "Basic web server reconnaissance and XSS exploitation",
        "scope": ["192.168.1.100"],
        "goals": {
            "Port Scanning Complete": GoalStatus.PENDING,
            "Web Service Identified": GoalStatus.PENDING,
            "XSS Vulnerability Found": GoalStatus.PENDING,
            "XSS Exploitation Successful": GoalStatus.PENDING
        },
        "constraints": {
            "stealth_level": "low",
            "max_duration_hours": 1,
            "require_approval": False
        }
    }


@pytest.fixture
def medium_mission_data() -> Dict[str, Any]:
    """Mission data for medium SQL injection."""
    return {
        "name": "Mission 02 [MEDIUM]: SQL Injection",
        "description": "SQL injection exploitation and data exfiltration",
        "scope": ["192.168.1.200"],
        "goals": {
            "SQL Injection Found": GoalStatus.PENDING,
            "Database Access Obtained": GoalStatus.PENDING,
            "Admin Credentials Extracted": GoalStatus.PENDING,
            "Database Schema Mapped": GoalStatus.PENDING
        },
        "constraints": {
            "stealth_level": "medium",
            "max_duration_hours": 1,
            "require_approval": False
        }
    }


@pytest.fixture
def hard_mission_data() -> Dict[str, Any]:
    """Mission data for hard pivot attack."""
    return {
        "name": "Mission 03 [HARD]: Multi-Stage Pivot",
        "description": "Multi-stage attack with pivot and lateral movement",
        "scope": ["192.168.100.10", "10.10.0.0/24"],
        "goals": {
            "Initial RCE on Web Server": GoalStatus.PENDING,
            "Privilege Escalation to Root": GoalStatus.PENDING,
            "Pivot to Internal Network": GoalStatus.PENDING,
            "Compromise Database Server": GoalStatus.PENDING,
            "Access File Server (SMB)": GoalStatus.PENDING,
            "Obtain Domain Admin Credentials": GoalStatus.PENDING
        },
        "constraints": {
            "stealth_level": "medium",
            "max_duration_hours": 2,
            "require_approval": False
        }
    }


@pytest.fixture
def expert_mission_data() -> Dict[str, Any]:
    """Mission data for expert AD takeover."""
    return {
        "name": "Mission 04 [EXPERT]: Active Directory Takeover",
        "description": "Full Active Directory domain compromise with Golden Ticket",
        "scope": ["192.168.200.50", "corp.local", "10.20.0.0/24"],
        "goals": {
            "Initial Foothold on Domain Machine": GoalStatus.PENDING,
            "Active Directory Enumeration": GoalStatus.PENDING,
            "Kerberoasting Attack Success": GoalStatus.PENDING,
            "Service Account Compromise": GoalStatus.PENDING,
            "Lateral Movement (3+ Systems)": GoalStatus.PENDING,
            "Domain Admin Privileges": GoalStatus.PENDING,
            "DCSync Attack Execution": GoalStatus.PENDING,
            "Golden Ticket Generation": GoalStatus.PENDING,
            "Persistence Mechanism Established": GoalStatus.PENDING
        },
        "constraints": {
            "stealth_level": "high",
            "max_duration_hours": 3,
            "require_approval": False
        }
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HELPER FUNCTIONS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def create_mission(mission_data: Dict[str, Any]) -> Mission:
    """Create a Mission object from test data."""
    return Mission(
        id=uuid.uuid4(),
        name=mission_data["name"],
        description=mission_data.get("description", ""),
        status=MissionStatus.CREATED,
        scope=mission_data["scope"],
        goals=mission_data["goals"],
        constraints=mission_data.get("constraints", {})
    )


def create_target(
    ip: str,
    hostname: Optional[str] = None,
    os: Optional[str] = None,
    ports: Optional[List[Dict]] = None,
    vulnerabilities: Optional[List[str]] = None,
    **kwargs
) -> Dict[str, Any]:
    """Create a target dictionary."""
    target = {
        "id": str(uuid.uuid4()),
        "ip": ip,
        "hostname": hostname or f"host-{ip.replace('.', '-')}",
        "os": os or "Unknown",
        "ports": ports or [],
        "vulnerabilities": vulnerabilities or [],
    }
    target.update(kwargs)
    return target


def create_session(
    target_ip: str,
    user: str,
    session_type: str = "reverse_shell",
    privileges: str = "low",
    **kwargs
) -> Dict[str, Any]:
    """Create a session dictionary."""
    session = {
        "id": f"session-{str(uuid.uuid4())[:8]}",
        "target_ip": target_ip,
        "type": session_type,
        "user": user,
        "privileges": privileges,
        "stability": "stable",
    }
    session.update(kwargs)
    return session


def create_credential(
    username: str,
    password: str,
    cred_type: str = "password",
    **kwargs
) -> Dict[str, Any]:
    """Create a credential dictionary."""
    cred = {
        "id": f"cred-{str(uuid.uuid4())[:8]}",
        "username": username,
        "password": password,
        "type": cred_type,
        "validity": "confirmed",
    }
    cred.update(kwargs)
    return cred


def create_vulnerability(
    cve: str,
    severity: str,
    target_id: str,
    cvss_score: float = 7.5,
    **kwargs
) -> Dict[str, Any]:
    """Create a vulnerability dictionary."""
    vuln = {
        "id": f"vuln-{str(uuid.uuid4())[:8]}",
        "cve": cve,
        "severity": severity,
        "cvss_score": cvss_score,
        "target_id": target_id,
        "exploit_available": True,
    }
    vuln.update(kwargs)
    return vuln


async def execute_phase(
    orchestrator: AgentWorkflowOrchestrator,
    context: Any,
    phase: WorkflowPhase
) -> PhaseResult:
    """Execute a workflow phase and return result."""
    phase_result = orchestrator._create_phase_result(phase)
    
    phase_methods = {
        WorkflowPhase.INITIALIZATION: orchestrator._phase_initialization,
        WorkflowPhase.STRATEGIC_PLANNING: orchestrator._phase_strategic_planning,
        WorkflowPhase.RECONNAISSANCE: orchestrator._phase_reconnaissance,
        WorkflowPhase.INITIAL_ACCESS: orchestrator._phase_initial_access,
        WorkflowPhase.POST_EXPLOITATION: orchestrator._phase_post_exploitation,
        WorkflowPhase.LATERAL_MOVEMENT: orchestrator._phase_lateral_movement,
        WorkflowPhase.GOAL_ACHIEVEMENT: orchestrator._phase_goal_achievement,
        WorkflowPhase.REPORTING: orchestrator._phase_reporting,
        WorkflowPhase.CLEANUP: orchestrator._phase_cleanup,
    }
    
    phase_method = phase_methods.get(phase)
    if not phase_method:
        raise ValueError(f"Unknown phase: {phase}")
    
    context.current_phase = phase
    result = await phase_method(context, phase_result)
    
    return result


def validate_mission_success(mission: Mission) -> bool:
    """Validate that all mission goals are achieved."""
    return all(
        status == GoalStatus.ACHIEVED 
        for status in mission.goals.values()
    )


def calculate_success_rate(mission: Mission) -> float:
    """Calculate mission success rate percentage."""
    achieved = sum(
        1 for status in mission.goals.values() 
        if status == GoalStatus.ACHIEVED
    )
    total = len(mission.goals)
    return (achieved / total * 100) if total > 0 else 0.0


def print_mission_summary(
    mission: Mission,
    context: Any,
    duration: float
):
    """Print formatted mission summary."""
    print("\n" + "="*100)
    print("📈 MISSION SUMMARY")
    print("="*100)
    
    success_rate = calculate_success_rate(mission)
    
    print(f"\n✅ Mission: {mission.name}")
    print(f"   Status: {mission.status.value}")
    print(f"   Duration: {duration:.2f} seconds")
    print(f"   Success Rate: {success_rate:.1f}%")
    
    print(f"\n🎯 Goals ({len(mission.goals)}):")
    for goal_name, status in mission.goals.items():
        icon = "✅" if status == GoalStatus.ACHIEVED else "❌"
        print(f"   {icon} {goal_name}: {status.value}")
    
    if hasattr(context, 'discovered_targets'):
        print(f"\n📊 Statistics:")
        print(f"   Targets Discovered: {len(context.discovered_targets)}")
        
        if hasattr(context, 'established_sessions'):
            print(f"   Sessions Established: {len(context.established_sessions)}")
        
        if hasattr(context, 'discovered_creds'):
            print(f"   Credentials Harvested: {len(context.discovered_creds)}")
        
        if hasattr(context, 'discovered_vulns'):
            print(f"   Vulnerabilities Found: {len(context.discovered_vulns)}")
    
    print("="*100 + "\n")


def assert_phase_success(result: PhaseResult, phase_name: str):
    """Assert that a phase completed successfully."""
    assert result.status in [
        PhaseStatus.COMPLETED,
        PhaseStatus.IN_PROGRESS
    ], f"{phase_name} failed with status: {result.status}"
    
    print(f"✅ {phase_name}: {result.status.value}")


def assert_goal_achieved(mission: Mission, goal_name: str):
    """Assert that a specific goal is achieved."""
    assert goal_name in mission.goals, f"Goal '{goal_name}' not found in mission"
    assert mission.goals[goal_name] == GoalStatus.ACHIEVED, \
        f"Goal '{goal_name}' not achieved: {mission.goals[goal_name]}"
    
    print(f"✅ Goal Achieved: {goal_name}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DOCKER/INFRASTRUCTURE HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def check_docker_available() -> bool:
    """Check if Docker is available."""
    import subprocess
    try:
        result = subprocess.run(
            ["docker", "version"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except:
        return False


def check_service_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a service is listening on a port."""
    import socket
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False


async def wait_for_service(
    host: str,
    port: int,
    timeout: float = 30.0,
    interval: float = 1.0
) -> bool:
    """Wait for a service to become available."""
    import asyncio
    start = asyncio.get_event_loop().time()
    
    while (asyncio.get_event_loop().time() - start) < timeout:
        if check_service_port(host, port):
            return True
        await asyncio.sleep(interval)
    
    return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LLM INTEGRATION HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def check_deepseek_available() -> bool:
    """Check if DeepSeek API is configured."""
    deepseek_key = os.getenv("DEEPSEEK_API_KEY")
    return deepseek_key is not None and len(deepseek_key) > 0


def skip_if_no_deepseek():
    """Skip test if DeepSeek API is not available."""
    if not check_deepseek_available():
        pytest.skip("DeepSeek API key not configured (DEEPSEEK_API_KEY)")


def skip_if_no_docker():
    """Skip test if Docker is not available."""
    if not check_docker_available():
        pytest.skip("Docker is not available")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PYTEST HOOKS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Hook to capture test results."""
    outcome = yield
    rep = outcome.get_result()
    
    # Store test result for later use
    setattr(item, f"rep_{rep.when}", rep)


def pytest_collection_modifyitems(config, items):
    """Modify test collection based on markers."""
    # Auto-skip tests requiring real infrastructure
    for item in items:
        if "real_llm" in item.keywords:
            if not check_deepseek_available():
                item.add_marker(
                    pytest.mark.skip(reason="DeepSeek API not configured")
                )
        
        if "real_infra" in item.keywords:
            if not check_docker_available():
                item.add_marker(
                    pytest.mark.skip(reason="Docker not available")
                )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TEST DATA GENERATORS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def generate_random_ip(prefix: str = "192.168.1") -> str:
    """Generate random IP address."""
    import random
    return f"{prefix}.{random.randint(1, 254)}"


def generate_random_hostname(prefix: str = "target") -> str:
    """Generate random hostname."""
    import random
    return f"{prefix}-{random.randint(1000, 9999)}"


def generate_test_targets(count: int = 5) -> List[Dict[str, Any]]:
    """Generate multiple test targets."""
    return [
        create_target(
            ip=generate_random_ip(),
            hostname=generate_random_hostname(),
            os="Linux" if i % 2 == 0 else "Windows"
        )
        for i in range(count)
    ]
