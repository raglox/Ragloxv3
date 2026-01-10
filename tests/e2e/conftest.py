# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - E2E Test Fixtures (Enterprise-Grade)
# Shared fixtures for E2E testing with real services
# ═══════════════════════════════════════════════════════════════

"""
Enterprise-Grade E2E Test Fixtures

Provides real service connections for comprehensive testing:
- PostgreSQL database
- Redis cache
- Blackboard
- Specialists
- Mission Intelligence
- Orchestration

Requirements:
- PostgreSQL running on localhost:5432
- Redis running on localhost:6379
- Valid credentials in environment variables
"""

import asyncio
import pytest
import os
from typing import AsyncGenerator, Dict, Any
from uuid import uuid4

# Import RAGLOX components
from src.core.blackboard import Blackboard
from src.core.config import Settings, get_settings
from src.core.models import (
    Mission, MissionStatus, MissionCreate,
    Target, TargetStatus,
    Vulnerability, Severity,
    Credential, CredentialType, PrivilegeLevel,
)
from src.core.reasoning import (
    MissionIntelligence,
    MissionIntelligenceBuilder,
    SpecialistOrchestrator,
    create_mission_intelligence,
)
from src.core.planning import MissionPlanner
from src.core.advanced import (
    AdvancedRiskAssessmentEngine,
    RealtimeAdaptationEngine,
    IntelligentTaskPrioritizer,
    VisualizationDashboardAPI,
)

# Check if real services are available
REAL_SERVICES_AVAILABLE = os.getenv("USE_REAL_SERVICES", "false").lower() == "true"
POSTGRES_AVAILABLE = os.getenv("POSTGRES_AVAILABLE", "false").lower() == "true"
REDIS_AVAILABLE = os.getenv("REDIS_AVAILABLE", "false").lower() == "true"


# ═══════════════════════════════════════════════════════════════
# Service Check Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="session")
def check_services():
    """Check if real services are available."""
    services = {
        "postgres": POSTGRES_AVAILABLE,
        "redis": REDIS_AVAILABLE,
        "all": REAL_SERVICES_AVAILABLE,
    }
    
    if not REAL_SERVICES_AVAILABLE:
        pytest.skip("Real services not enabled. Set USE_REAL_SERVICES=true to run E2E tests.")
    
    return services


# ═══════════════════════════════════════════════════════════════
# Configuration Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="session")
def e2e_settings() -> Settings:
    """Get settings for E2E tests."""
    settings = get_settings()
    
    # Ensure we're using real services
    assert settings.database_url, "DATABASE_URL must be set for E2E tests"
    assert settings.redis_url, "REDIS_URL must be set for E2E tests"
    
    return settings


# ═══════════════════════════════════════════════════════════════
# Core Service Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="function")
async def redis_client(e2e_settings: Settings, check_services):
    """
    Provide a Redis client for E2E tests.
    """
    import redis.asyncio as aioredis
    client = await aioredis.from_url(
        e2e_settings.redis_url,
        encoding="utf-8",
        decode_responses=True
    )
    
    try:
        yield client
    finally:
        await client.close()


@pytest.fixture(scope="function")
async def database_conn(e2e_settings: Settings, check_services):
    """
    Provide a database connection for E2E tests.
    
    For now, we're just providing None as the codebase doesn't use
    a direct database connection - it uses Redis/Blackboard for state.
    """
    # TODO: Add actual database connection if needed
    yield None


@pytest.fixture(scope="function")
async def blackboard(e2e_settings: Settings, check_services) -> AsyncGenerator[Blackboard, None]:
    """
    Provide a real Blackboard instance connected to PostgreSQL and Redis.
    
    This is a function-scoped fixture, so each test gets a fresh Blackboard.
    """
    bb = Blackboard(settings=e2e_settings)
    
    try:
        # Connect to Redis
        await bb.connect()
        
        yield bb
    finally:
        # Cleanup
        await bb.disconnect()


@pytest.fixture(scope="function")
async def test_mission(blackboard: Blackboard) -> Mission:
    """Create a test mission with real data."""
    from src.core.models import Mission
    from uuid import uuid4
    from datetime import datetime
    
    mission = Mission(
        id=uuid4(),
        name=f"E2E Test Mission {uuid4().hex[:8]}",
        description="Enterprise-grade E2E test mission",
        status=MissionStatus.CREATED,
        scope=["192.168.1.0/24", "10.0.0.0/24"],
        goals={"gain_access": "pending", "privilege_escalation": "pending", "lateral_movement": "pending"},
        constraints={
            "max_duration_hours": 2,
            "stealth_level": "high",
            "allowed_techniques": ["exploit", "password_spray"],
        },
        created_at=datetime.utcnow()
    )
    
    # Store in blackboard
    await blackboard.create_mission(mission)
    
    return mission


# ═══════════════════════════════════════════════════════════════
# Intelligence Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="function")
async def mission_intelligence(
    test_mission: Mission,
    blackboard: Blackboard
) -> MissionIntelligence:
    """Create MissionIntelligence with real data."""
    intel = create_mission_intelligence(test_mission.id)
    
    # Add some test targets
    from src.core.reasoning.mission_intelligence import TargetIntel
    
    target1 = TargetIntel(
        target_id=f"target-{uuid4()}",
        ip="192.168.1.10",
        hostname="web-server-01",
        os="Linux",
        os_version="Ubuntu 22.04",
        open_ports=[
            {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.2"},
            {"port": 80, "protocol": "tcp", "service": "http", "version": "nginx 1.18"},
            {"port": 443, "protocol": "tcp", "service": "https", "version": "nginx 1.18"},
        ],
        subnet="192.168.1.0/24",
        hardening_level="medium",
    )
    
    target2 = TargetIntel(
        target_id=f"target-{uuid4()}",
        ip="192.168.1.20",
        hostname="db-server-01",
        os="Linux",
        os_version="Ubuntu 22.04",
        open_ports=[
            {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.2"},
            {"port": 3306, "protocol": "tcp", "service": "mysql", "version": "MySQL 8.0"},
        ],
        subnet="192.168.1.0/24",
        hardening_level="high",
        security_products=["fail2ban", "iptables"],
    )
    
    intel.add_target(target1)
    intel.add_target(target2)
    
    # Add vulnerabilities
    from src.core.reasoning.mission_intelligence import VulnerabilityIntel
    
    vuln1 = VulnerabilityIntel(
        vuln_id="CVE-2024-1234",
        target_id=target1.target_id,
        name="Critical RCE in nginx",
        description="Remote code execution vulnerability",
        severity="critical",
        cvss_score=9.8,
        is_exploitable=True,
        exploit_available=True,
        exploit_complexity="low",
        affected_service="nginx",
        affected_port=80,
    )
    
    vuln2 = VulnerabilityIntel(
        vuln_id="CVE-2024-5678",
        target_id=target2.target_id,
        name="SQL Injection in MySQL",
        severity="high",
        cvss_score=8.5,
        is_exploitable=True,
        exploit_available=False,
        exploit_complexity="medium",
        affected_service="mysql",
        affected_port=3306,
    )
    
    intel.add_vulnerability(vuln1)
    intel.add_vulnerability(vuln2)
    
    # Add credentials
    from src.core.reasoning.mission_intelligence import CredentialIntel
    
    cred1 = CredentialIntel(
        cred_id=f"cred-{uuid4()}",
        username="admin",
        credential_type="password",
        privilege_level="admin",
        is_privileged=True,
        is_valid=True,
        source_target=target1.target_id,
    )
    
    intel.add_credential(cred1)
    
    return intel


@pytest.fixture(scope="function")
async def intelligence_builder(
    test_mission: Mission,
    blackboard: Blackboard,
    mission_intelligence: MissionIntelligence
) -> MissionIntelligenceBuilder:
    """Create MissionIntelligenceBuilder with real Blackboard."""
    builder = MissionIntelligenceBuilder(
        mission_id=test_mission.id,
        blackboard=blackboard,
    )
    
    # Pre-populate with existing intelligence
    builder.intelligence = mission_intelligence
    
    return builder


# ═══════════════════════════════════════════════════════════════
# Orchestration Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="function")
async def specialist_orchestrator(
    test_mission: Mission,
    blackboard: Blackboard,
    mission_intelligence: MissionIntelligence
) -> SpecialistOrchestrator:
    """Create SpecialistOrchestrator with real services."""
    from src.specialists.recon import ReconSpecialist
    from src.specialists.attack import AttackSpecialist
    from src.core.models import SpecialistType
    
    # Create mock specialists (real ones require full infrastructure)
    class MockReconSpecialist:
        specialist_type = SpecialistType.RECON
        
    class MockAttackSpecialist:
        specialist_type = SpecialistType.ATTACK
    
    specialists = {
        SpecialistType.RECON: MockReconSpecialist(),
        SpecialistType.ATTACK: MockAttackSpecialist(),
    }
    
    orchestrator = SpecialistOrchestrator(
        mission_id=test_mission.id,
        blackboard=blackboard,
        specialists=specialists,
        mission_intelligence=mission_intelligence,
    )
    
    return orchestrator


@pytest.fixture(scope="function")
async def mission_planner(
    test_mission: Mission,
    mission_intelligence: MissionIntelligence
) -> MissionPlanner:
    """Create MissionPlanner."""
    planner = MissionPlanner(
        mission_id=test_mission.id,
        mission_intelligence=mission_intelligence,
    )
    
    return planner


# ═══════════════════════════════════════════════════════════════
# Advanced Features Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="function")
async def risk_assessment_engine(
    mission_intelligence: MissionIntelligence
) -> AdvancedRiskAssessmentEngine:
    """Create AdvancedRiskAssessmentEngine."""
    from src.core.advanced.risk_assessment import ThreatActor
    
    engine = AdvancedRiskAssessmentEngine(
        mission_intelligence=mission_intelligence,
        threat_actor_profile=ThreatActor.APT,
    )
    
    return engine


@pytest.fixture(scope="function")
async def adaptation_engine(
    mission_intelligence: MissionIntelligence
) -> RealtimeAdaptationEngine:
    """Create RealtimeAdaptationEngine."""
    engine = RealtimeAdaptationEngine(
        mission_intelligence=mission_intelligence
    )
    
    return engine


@pytest.fixture(scope="function")
async def task_prioritizer() -> IntelligentTaskPrioritizer:
    """Create IntelligentTaskPrioritizer."""
    return IntelligentTaskPrioritizer()


@pytest.fixture(scope="function")
async def visualization_api(
    mission_intelligence: MissionIntelligence,
    specialist_orchestrator: SpecialistOrchestrator
) -> VisualizationDashboardAPI:
    """Create VisualizationDashboardAPI."""
    api = VisualizationDashboardAPI(
        mission_intelligence=mission_intelligence,
        orchestrator=specialist_orchestrator,
    )
    
    return api


# ═══════════════════════════════════════════════════════════════
# Data Population Helpers
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="function")
async def populate_blackboard_with_targets(
    blackboard: Blackboard,
    test_mission: Mission
) -> list:
    """Populate Blackboard with test targets."""
    targets = []
    
    # Create targets in Blackboard
    target_data_list = [
        {
            "ip": "192.168.1.10",
            "hostname": "web-server-01",
            "os": "Linux",
            "status": TargetStatus.SCANNED,
        },
        {
            "ip": "192.168.1.20",
            "hostname": "db-server-01",
            "os": "Linux",
            "status": TargetStatus.DISCOVERED,
        },
        {
            "ip": "192.168.1.30",
            "hostname": "mail-server-01",
            "os": "Windows",
            "status": TargetStatus.DISCOVERED,
        },
    ]
    
    for target_data in target_data_list:
        target = await blackboard.create_target(
            mission_id=test_mission.id,
            ip=target_data["ip"],
            hostname=target_data.get("hostname"),
            os=target_data.get("os"),
            status=target_data.get("status", TargetStatus.DISCOVERED),
        )
        targets.append(target)
    
    return targets


@pytest.fixture(scope="function")
async def populate_blackboard_with_vulnerabilities(
    blackboard: Blackboard,
    test_mission: Mission,
    populate_blackboard_with_targets: list
) -> list:
    """Populate Blackboard with test vulnerabilities."""
    vulnerabilities = []
    
    targets = populate_blackboard_with_targets
    
    if not targets:
        return vulnerabilities
    
    # Add vulnerabilities to first target
    target = targets[0]
    
    vuln_data_list = [
        {
            "cve_id": "CVE-2024-1111",
            "name": "Critical RCE",
            "severity": Severity.CRITICAL,
            "cvss_score": 9.8,
        },
        {
            "cve_id": "CVE-2024-2222",
            "name": "SQL Injection",
            "severity": Severity.HIGH,
            "cvss_score": 8.5,
        },
    ]
    
    for vuln_data in vuln_data_list:
        vuln = await blackboard.create_vulnerability(
            mission_id=test_mission.id,
            target_id=target.id,
            cve_id=vuln_data["cve_id"],
            name=vuln_data["name"],
            severity=vuln_data["severity"],
            cvss_score=vuln_data.get("cvss_score"),
        )
        vulnerabilities.append(vuln)
    
    return vulnerabilities


# ═══════════════════════════════════════════════════════════════
# Assertion Helpers
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def assert_mission_intelligence_valid():
    """Helper to assert MissionIntelligence is valid."""
    def _assert(intel: MissionIntelligence):
        assert intel.mission_id
        assert intel.intel_version >= 1
        assert intel.created_at
        assert intel.last_updated
        
        # Check collections
        assert isinstance(intel.targets, dict)
        assert isinstance(intel.vulnerabilities, dict)
        assert isinstance(intel.credentials, dict)
        assert isinstance(intel.tactical_recommendations, list)
        
        # Check statistics
        assert intel.total_targets >= 0
        assert intel.total_vulnerabilities >= 0
        assert intel.total_credentials >= 0
        
    return _assert


@pytest.fixture
def assert_orchestration_result_valid():
    """Helper to assert OrchestrationResult is valid."""
    def _assert(result):
        assert result.plan_id
        assert result.mission_id
        assert result.phase
        assert result.total_tasks >= 0
        assert result.completed_tasks >= 0
        assert result.failed_tasks >= 0
        assert result.execution_time_seconds >= 0
        assert isinstance(result.task_results, list)
        
    return _assert


@pytest.fixture
def assert_risk_assessment_valid():
    """Helper to assert RiskAssessment is valid."""
    def _assert(assessment):
        assert assessment.assessment_id
        assert 0 <= assessment.overall_risk_score <= 10
        assert assessment.risk_level
        assert isinstance(assessment.factors, list)
        assert assessment.created_at
        
    return _assert
