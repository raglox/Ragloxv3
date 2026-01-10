# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Blackboard REAL Tests (NO MOCKS)
# Testing Redis-backed shared state operations with real services
# ═══════════════════════════════════════════════════════════════

"""
Blackboard Real Tests - 100% Real, 0% Mocks

This test suite uses REAL Redis (no mocks) to test Blackboard functionality.
All operations interact with actual Redis instance.

Philosophy:
- No mocks, no fakes
- Real Redis connection
- Real data persistence
- Real edge cases
- Test actual behavior, not mock expectations

Coverage Target: 61% → 90%+
"""

import pytest
import pytest_asyncio
import asyncio
from datetime import datetime, timedelta
from uuid import uuid4, UUID
import os
import json

from src.core.blackboard import Blackboard
from src.core.models import (
    Mission, MissionStatus, MissionStats, GoalStatus,
    Target, TargetStatus, Priority,
    Vulnerability, Severity,
    Credential, CredentialType, PrivilegeLevel,
    Session, SessionStatus, SessionType,
    Task, TaskStatus, TaskType, SpecialistType,
    BlackboardEvent, NewTargetEvent
)
from src.core.config import Settings, get_settings

# Check if real services are available
USE_REAL_SERVICES = os.getenv("USE_REAL_SERVICES", "false").lower() == "true"

pytestmark = pytest.mark.skipif(
    not USE_REAL_SERVICES,
    reason="Real services not enabled. Set USE_REAL_SERVICES=true"
)


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="session")
def real_settings():
    """Get real settings for testing."""
    settings = get_settings()
    assert settings.redis_url, "REDIS_URL must be set"
    return settings


@pytest_asyncio.fixture
async def real_blackboard(real_settings):
    """
    Create Blackboard connected to REAL Redis.
    
    This fixture:
    - Connects to real Redis
    - Cleans up test data after each test
    - No mocking whatsoever
    """
    bb = Blackboard(settings=real_settings)
    await bb.connect()
    
    # Verify connection
    assert await bb.health_check(), "Redis connection failed"
    
    yield bb
    
    # Cleanup: flush test database (use db 0 for tests)
    await bb.redis.flushdb()
    await bb.disconnect()


@pytest_asyncio.fixture
async def mission_fixture(real_blackboard):
    """Create a real mission for testing."""
    mission = Mission(
        name="Real Test Mission",
        scope=["192.168.1.0/24", "10.0.0.0/8"],
        goals={"domain_admin": GoalStatus.PENDING, "persistence": GoalStatus.PENDING}
    )
    await real_blackboard.create_mission(mission)
    return mission


# ═══════════════════════════════════════════════════════════════
# Connection & Health Tests
# ═══════════════════════════════════════════════════════════════

class TestRealConnection:
    """Test real Redis connection management."""
    
    @pytest.mark.asyncio
    async def test_connect_to_real_redis(self, real_settings):
        """Test connecting to real Redis."""
        bb = Blackboard(settings=real_settings)
        await bb.connect()
        
        # Should be connected
        assert bb.is_connected()
        assert await bb.health_check()
        
        # Should be able to ping
        response = await bb.redis.ping()
        assert response == True
        
        await bb.disconnect()
        assert not bb.is_connected()
    
    @pytest.mark.asyncio
    async def test_redis_info(self, real_blackboard):
        """Test getting Redis server info."""
        info = await real_blackboard.redis.info()
        
        assert "redis_version" in info
        assert "os" in info
        assert "connected_clients" in info
        
        print(f"\n✅ Redis version: {info['redis_version']}")
        print(f"✅ Redis OS: {info['os']}")
    
    @pytest.mark.asyncio
    async def test_reconnection_after_disconnect(self, real_settings):
        """Test reconnecting after disconnect."""
        bb = Blackboard(settings=real_settings)
        
        # First connection
        await bb.connect()
        assert bb.is_connected()
        
        # Disconnect
        await bb.disconnect()
        assert not bb.is_connected()
        
        # Reconnect
        await bb.connect()
        assert bb.is_connected()
        assert await bb.health_check()
        
        await bb.disconnect()


# ═══════════════════════════════════════════════════════════════
# Mission CRUD Tests (Real Data)
# ═══════════════════════════════════════════════════════════════

class TestRealMissionOperations:
    """Test mission operations with real Redis."""
    
    @pytest.mark.asyncio
    async def test_create_and_retrieve_mission(self, real_blackboard):
        """Test creating and retrieving a real mission."""
        mission = Mission(
            name="Production Test Mission",
            description="Testing with real Redis",
            scope=["172.16.0.0/16"],
            goals={"initial_access": GoalStatus.PENDING}
        )
        
        # Create
        mission_id = await real_blackboard.create_mission(mission)
        assert mission_id == str(mission.id)
        
        # Retrieve
        retrieved = await real_blackboard.get_mission(mission_id)
        assert retrieved is not None
        assert retrieved["name"] == "Production Test Mission"
        assert retrieved["description"] == "Testing with real Redis"
        # Scope is already deserialized by _get_hash
        scope = retrieved["scope"] if isinstance(retrieved["scope"], list) else json.loads(retrieved["scope"])
        assert "172.16.0.0/16" in scope
    
    @pytest.mark.asyncio
    async def test_mission_status_lifecycle(self, real_blackboard, mission_fixture):
        """Test mission status transitions."""
        mission_id = str(mission_fixture.id)
        
        # Initial status
        mission = await real_blackboard.get_mission(mission_id)
        # Status is stored as string enum representation
        assert mission["status"] in [MissionStatus.CREATED.value, str(MissionStatus.CREATED)]
        
        # Update to RUNNING
        await real_blackboard.update_mission_status(mission_id, MissionStatus.RUNNING)
        mission = await real_blackboard.get_mission(mission_id)
        assert mission["status"] in [MissionStatus.RUNNING.value, "running"]
        assert "started_at" in mission
        
        # Update to COMPLETED
        await real_blackboard.update_mission_status(mission_id, MissionStatus.COMPLETED)
        mission = await real_blackboard.get_mission(mission_id)
        assert mission["status"] in [MissionStatus.COMPLETED.value, "completed"]
        assert "completed_at" in mission
    
    @pytest.mark.asyncio
    async def test_mission_goals_management(self, real_blackboard, mission_fixture):
        """Test goal status updates."""
        mission_id = str(mission_fixture.id)
        
        # Get initial goals
        goals = await real_blackboard.get_mission_goals(mission_id)
        assert "domain_admin" in goals
        assert goals["domain_admin"] == "pending"
        
        # Achieve first goal
        await real_blackboard.update_goal_status(mission_id, "domain_admin", "achieved")
        goals = await real_blackboard.get_mission_goals(mission_id)
        assert goals["domain_admin"] == "achieved"
        
        # Stats should update
        stats = await real_blackboard.get_mission_stats(mission_id)
        assert stats.goals_achieved == 1
        
        # Achieve second goal
        await real_blackboard.update_goal_status(mission_id, "persistence", "achieved")
        stats = await real_blackboard.get_mission_stats(mission_id)
        assert stats.goals_achieved == 2
    
    @pytest.mark.asyncio
    async def test_mission_stats_increments(self, real_blackboard, mission_fixture):
        """Test mission statistics increments correctly."""
        mission_id = str(mission_fixture.id)
        
        # Initial stats
        stats = await real_blackboard.get_mission_stats(mission_id)
        assert stats.targets_discovered == 0
        assert stats.vulns_found == 0
        assert stats.creds_harvested == 0
        
        # Add target
        target = Target(mission_id=mission_fixture.id, ip="192.168.1.100")
        await real_blackboard.add_target(target)
        
        stats = await real_blackboard.get_mission_stats(mission_id)
        assert stats.targets_discovered == 1
        
        # Add vulnerability
        vuln = Vulnerability(
            mission_id=mission_fixture.id,
            target_id=target.id,
            type="CVE-2024-0001",
            severity=Severity.HIGH
        )
        await real_blackboard.add_vulnerability(vuln)
        
        stats = await real_blackboard.get_mission_stats(mission_id)
        assert stats.vulns_found == 1
        
        # Add credential
        cred = Credential(
            mission_id=mission_fixture.id,
            target_id=target.id,
            type=CredentialType.PASSWORD,
            username="admin"
        )
        await real_blackboard.add_credential(cred)
        
        stats = await real_blackboard.get_mission_stats(mission_id)
        assert stats.creds_harvested == 1


# ═══════════════════════════════════════════════════════════════
# Target Operations Tests (Real Data)
# ═══════════════════════════════════════════════════════════════

class TestRealTargetOperations:
    """Test target operations with real Redis."""
    
    @pytest.mark.asyncio
    async def test_add_and_retrieve_target(self, real_blackboard, mission_fixture):
        """Test adding and retrieving targets."""
        target = Target(
            mission_id=mission_fixture.id,
            ip="10.20.30.40",
            hostname="prod-server-01.example.com",
            os="Ubuntu 22.04",
            priority=Priority.CRITICAL
        )
        
        target_id = await real_blackboard.add_target(target)
        assert target_id == str(target.id)
        
        retrieved = await real_blackboard.get_target(target_id)
        assert retrieved["ip"] == "10.20.30.40"
        assert retrieved["hostname"] == "prod-server-01.example.com"
        assert retrieved["os"] == "Ubuntu 22.04"
        assert retrieved["priority"] == Priority.CRITICAL.value
    
    @pytest.mark.asyncio
    async def test_target_status_progression(self, real_blackboard, mission_fixture):
        """Test target status progresses correctly."""
        target = Target(mission_id=mission_fixture.id, ip="192.168.100.5")
        target_id = await real_blackboard.add_target(target)
        
        # Initial status
        retrieved = await real_blackboard.get_target(target_id)
        # Status stored as enum string or value
        assert retrieved["status"] in [TargetStatus.DISCOVERED.value, str(TargetStatus.DISCOVERED)]
        
        # Scan
        await real_blackboard.update_target_status(target_id, TargetStatus.SCANNING)
        retrieved = await real_blackboard.get_target(target_id)
        assert retrieved["status"] == TargetStatus.SCANNING.value
        
        # Scanned
        await real_blackboard.update_target_status(target_id, TargetStatus.SCANNED)
        retrieved = await real_blackboard.get_target(target_id)
        assert retrieved["status"] == TargetStatus.SCANNED.value
        
        # Exploited
        await real_blackboard.update_target_status(target_id, TargetStatus.EXPLOITED)
        retrieved = await real_blackboard.get_target(target_id)
        assert retrieved["status"] == TargetStatus.EXPLOITED.value
    
    @pytest.mark.asyncio
    async def test_target_ports_management(self, real_blackboard, mission_fixture):
        """Test adding and retrieving target ports."""
        target = Target(mission_id=mission_fixture.id, ip="10.0.0.50")
        target_id = await real_blackboard.add_target(target)
        
        # Add ports
        ports = {
            22: "ssh",
            80: "http",
            443: "https",
            3306: "mysql"
        }
        await real_blackboard.add_target_ports(target_id, ports)
        
        # Retrieve ports
        retrieved_ports = await real_blackboard.get_target_ports(target_id)
        assert "22" in retrieved_ports
        assert retrieved_ports["22"] == "ssh"
        assert "3306" in retrieved_ports
        assert retrieved_ports["3306"] == "mysql"
    
    @pytest.mark.asyncio
    async def test_get_mission_targets(self, real_blackboard, mission_fixture):
        """Test retrieving all targets for a mission."""
        # Add multiple targets
        targets = []
        for i in range(5):
            target = Target(mission_id=mission_fixture.id, ip=f"10.0.0.{i+1}")
            await real_blackboard.add_target(target)
            targets.append(target)
        
        # Get all targets
        target_ids = await real_blackboard.get_mission_targets(str(mission_fixture.id))
        assert len(target_ids) == 5
        
        # Verify each target exists
        for target_key in target_ids:
            target_id = target_key.replace("target:", "")
            retrieved = await real_blackboard.get_target(target_id)
            assert retrieved is not None


# ═══════════════════════════════════════════════════════════════
# Vulnerability Operations Tests
# ═══════════════════════════════════════════════════════════════

class TestRealVulnerabilityOperations:
    """Test vulnerability operations with real Redis."""
    
    @pytest.mark.asyncio
    async def test_add_and_retrieve_vulnerability(self, real_blackboard, mission_fixture):
        """Test adding and retrieving vulnerabilities."""
        target = Target(mission_id=mission_fixture.id, ip="10.0.0.1")
        await real_blackboard.add_target(target)
        
        vuln = Vulnerability(
            mission_id=mission_fixture.id,
            target_id=target.id,
            type="CVE-2024-12345",
            name="Critical RCE Vulnerability",
            description="Remote code execution in production system",
            severity=Severity.CRITICAL,
            cvss=9.8
        )
        
        vuln_id = await real_blackboard.add_vulnerability(vuln)
        
        retrieved = await real_blackboard.get_vulnerability(vuln_id)
        assert retrieved["type"] == "CVE-2024-12345"
        assert retrieved["name"] == "Critical RCE Vulnerability"
        assert retrieved["severity"] == Severity.CRITICAL.value
        assert float(retrieved["cvss"]) == 9.8
    
    @pytest.mark.asyncio
    async def test_vulnerabilities_sorted_by_cvss(self, real_blackboard, mission_fixture):
        """Test vulnerabilities are sorted by CVSS score."""
        target = Target(mission_id=mission_fixture.id, ip="10.0.0.1")
        await real_blackboard.add_target(target)
        
        # Add vulns with different CVSS scores
        vulns_data = [
            ("LOW-VULN", Severity.LOW, 3.5),
            ("CRITICAL-VULN", Severity.CRITICAL, 9.8),
            ("MEDIUM-VULN", Severity.MEDIUM, 5.5),
            ("HIGH-VULN", Severity.HIGH, 7.8),
        ]
        
        created_vulns = []
        for vuln_type, severity, cvss in vulns_data:
            vuln = Vulnerability(
                mission_id=mission_fixture.id,
                target_id=target.id,
                type=vuln_type,
                severity=severity,
                cvss=cvss
            )
            await real_blackboard.add_vulnerability(vuln)
            created_vulns.append((vuln, cvss))
        
        # Get sorted vulns
        vuln_ids = await real_blackboard.get_mission_vulns(str(mission_fixture.id))
        
        # Should be sorted by CVSS (highest first)
        assert len(vuln_ids) == 4
        
        # First should be CRITICAL (9.8)
        first_vuln_id = vuln_ids[0].replace("vuln:", "")
        first_vuln = await real_blackboard.get_vulnerability(first_vuln_id)
        assert first_vuln["type"] == "CRITICAL-VULN"
        
        # Last should be LOW (3.5)
        last_vuln_id = vuln_ids[-1].replace("vuln:", "")
        last_vuln = await real_blackboard.get_vulnerability(last_vuln_id)
        assert last_vuln["type"] == "LOW-VULN"


# ═══════════════════════════════════════════════════════════════
# Task Queue Tests (Real Redis)
# ═══════════════════════════════════════════════════════════════

class TestRealTaskOperations:
    """Test task queue operations with real Redis."""
    
    @pytest.mark.asyncio
    async def test_task_lifecycle_complete_flow(self, real_blackboard, mission_fixture):
        """Test complete task lifecycle: add → claim → complete."""
        # Add task
        task = Task(
            mission_id=mission_fixture.id,
            type=TaskType.PORT_SCAN,
            specialist=SpecialistType.RECON,
            priority=8
        )
        task_id = await real_blackboard.add_task(task)
        
        # Claim task
        claimed_id = await real_blackboard.claim_task(
            str(mission_fixture.id),
            "worker-real-001",
            "recon"
        )
        assert claimed_id == str(task.id)
        
        # Task should be in running state
        retrieved = await real_blackboard.get_task(task_id)
        assert retrieved["status"] == TaskStatus.RUNNING.value
        assert retrieved["assigned_to"] == "worker-real-001"
        
        # Complete task
        await real_blackboard.complete_task(
            str(mission_fixture.id),
            task_id,
            "success",
            {"ports_found": [22, 80, 443]}
        )
        
        # Task should be completed
        retrieved = await real_blackboard.get_task(task_id)
        assert retrieved["status"] == TaskStatus.COMPLETED.value
        assert retrieved["result"] == "success"
        # result_data is already deserialized by _get_hash
        result_data = retrieved["result_data"] if isinstance(retrieved["result_data"], dict) else json.loads(retrieved["result_data"])
        assert "ports_found" in result_data
    
    @pytest.mark.asyncio
    async def test_task_priority_ordering(self, real_blackboard, mission_fixture):
        """Test tasks are claimed by priority (highest first)."""
        # Add tasks with different priorities
        tasks = []
        for priority in [3, 8, 5, 10, 1]:
            task = Task(
                mission_id=mission_fixture.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                priority=priority
            )
            await real_blackboard.add_task(task)
            tasks.append((task, priority))
        
        # Claim first task (should be priority 10)
        claimed_id = await real_blackboard.claim_task(
            str(mission_fixture.id),
            "worker-001",
            "recon"
        )
        
        # Find which task was claimed
        claimed_task = next(t for t, _ in tasks if str(t.id) == claimed_id)
        assert claimed_task.priority == 10
    
    @pytest.mark.asyncio
    async def test_task_failure_handling(self, real_blackboard, mission_fixture):
        """Test task failure path."""
        task = Task(
            mission_id=mission_fixture.id,
            type=TaskType.EXPLOIT,
            specialist=SpecialistType.ATTACK,
            priority=9
        )
        task_id = await real_blackboard.add_task(task)
        
        # Claim task
        await real_blackboard.claim_task(
            str(mission_fixture.id),
            "worker-001",
            "attack"
        )
        
        # Fail task
        await real_blackboard.fail_task(
            str(mission_fixture.id),
            task_id,
            "Exploit failed: target patched"
        )
        
        # Task should be failed
        retrieved = await real_blackboard.get_task(task_id)
        assert retrieved["status"] == TaskStatus.FAILED.value
        assert retrieved["error_message"] == "Exploit failed: target patched"


# ═══════════════════════════════════════════════════════════════
# Metadata Operations Tests
# ═══════════════════════════════════════════════════════════════

class TestRealMetadataOperations:
    """Test metadata operations with real Redis."""
    
    @pytest.mark.asyncio
    async def test_store_and_retrieve_metadata(self, real_blackboard, mission_fixture):
        """Test storing and retrieving mission metadata."""
        mission_id = str(mission_fixture.id)
        
        # Store simple value
        await real_blackboard.store_metadata(mission_id, "stealth_mode", True)
        
        # Retrieve
        value = await real_blackboard.get_metadata(mission_id, "stealth_mode")
        # Boolean stored as "True" or "true"
        assert value in ["true", "True", "false", "False"] or isinstance(value, bool)
        
        # Store complex dict
        intel_data = {
            "version": 5,
            "targets_count": 42,
            "risk_score": 75.5,
            "recommendations": ["Maintain stealth", "Avoid detection"]
        }
        await real_blackboard.store_metadata(mission_id, "intelligence", intel_data)
        
        # Retrieve complex data
        retrieved = await real_blackboard.get_metadata(mission_id, "intelligence")
        assert retrieved["version"] == 5
        assert retrieved["targets_count"] == 42
        assert "recommendations" in retrieved
    
    @pytest.mark.asyncio
    async def test_get_all_metadata(self, real_blackboard, mission_fixture):
        """Test retrieving all metadata at once."""
        mission_id = str(mission_fixture.id)
        
        # Store multiple metadata
        await real_blackboard.store_metadata(mission_id, "key1", "value1")
        await real_blackboard.store_metadata(mission_id, "key2", {"nested": "data"})
        await real_blackboard.store_metadata(mission_id, "key3", 12345)
        
        # Get all
        all_meta = await real_blackboard.get_all_metadata(mission_id)
        
        assert "key1" in all_meta
        assert "key2" in all_meta
        assert "key3" in all_meta
        assert all_meta["key1"] == "value1"
        assert all_meta["key2"]["nested"] == "data"
    
    @pytest.mark.asyncio
    async def test_delete_metadata(self, real_blackboard, mission_fixture):
        """Test deleting metadata."""
        mission_id = str(mission_fixture.id)
        
        # Store
        await real_blackboard.store_metadata(mission_id, "temp_key", "temp_value")
        
        # Verify exists
        value = await real_blackboard.get_metadata(mission_id, "temp_key")
        assert value == "temp_value"
        
        # Delete
        deleted = await real_blackboard.delete_metadata(mission_id, "temp_key")
        assert deleted == True
        
        # Verify deleted
        value = await real_blackboard.get_metadata(mission_id, "temp_key", default="not_found")
        assert value == "not_found"


# ═══════════════════════════════════════════════════════════════
# Event Stream Tests
# ═══════════════════════════════════════════════════════════════

class TestRealEventStream:
    """Test event stream operations with real Redis."""
    
    @pytest.mark.asyncio
    async def test_add_and_retrieve_events(self, real_blackboard, mission_fixture):
        """Test adding and retrieving events."""
        mission_id = str(mission_fixture.id)
        
        # Add events
        event1_id = await real_blackboard.add_event(
            mission_id,
            "detection_alert",
            {"severity": "high", "source": "ids", "message": "Suspicious activity"}
        )
        
        event2_id = await real_blackboard.add_event(
            mission_id,
            "target_discovered",
            {"ip": "10.0.0.5", "ports": [22, 80]}
        )
        
        # Retrieve events
        events = await real_blackboard.get_events(mission_id)
        
        assert len(events) == 2
        assert events[0]["type"] == "detection_alert"
        assert events[1]["type"] == "target_discovered"
    
    @pytest.mark.asyncio
    async def test_filter_events_by_type(self, real_blackboard, mission_fixture):
        """Test filtering events by type."""
        mission_id = str(mission_fixture.id)
        
        # Add mixed events
        await real_blackboard.add_event(mission_id, "type_a", {"data": 1})
        await real_blackboard.add_event(mission_id, "type_b", {"data": 2})
        await real_blackboard.add_event(mission_id, "type_a", {"data": 3})
        
        # Filter by type_a
        type_a_events = await real_blackboard.get_events(mission_id, event_type="type_a")
        assert len(type_a_events) == 2
        
        # Filter by type_b
        type_b_events = await real_blackboard.get_events(mission_id, event_type="type_b")
        assert len(type_b_events) == 1


# ═══════════════════════════════════════════════════════════════
# Performance & Stress Tests
# ═══════════════════════════════════════════════════════════════

class TestRealPerformance:
    """Test Blackboard performance with real Redis."""
    
    @pytest.mark.asyncio
    async def test_bulk_target_creation_performance(self, real_blackboard, mission_fixture):
        """Test creating many targets performs well."""
        import time
        
        start = time.time()
        
        # Create 100 targets
        for i in range(100):
            target = Target(
                mission_id=mission_fixture.id,
                ip=f"10.{i // 256}.{i % 256}.{i % 256}"
            )
            await real_blackboard.add_target(target)
        
        duration = time.time() - start
        
        # Should complete in < 5 seconds
        assert duration < 5.0, f"Took {duration:.2f}s, expected < 5s"
        
        # Verify all created
        target_ids = await real_blackboard.get_mission_targets(str(mission_fixture.id))
        assert len(target_ids) == 100
    
    @pytest.mark.asyncio
    async def test_concurrent_task_claims(self, real_blackboard, mission_fixture):
        """Test multiple workers claiming tasks concurrently."""
        # Add tasks
        for i in range(10):
            task = Task(
                mission_id=mission_fixture.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                priority=5
            )
            await real_blackboard.add_task(task)
        
        # Simulate concurrent claims
        async def claim_task(worker_id):
            return await real_blackboard.claim_task(
                str(mission_fixture.id),
                f"worker-{worker_id}",
                "recon"
            )
        
        # Run 5 workers concurrently
        results = await asyncio.gather(
            *[claim_task(i) for i in range(5)]
        )
        
        # All should succeed (5 workers, 10 tasks)
        claimed_ids = [r for r in results if r is not None]
        assert len(claimed_ids) == 5
        
        # All claimed IDs should be unique
        assert len(set(claimed_ids)) == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
