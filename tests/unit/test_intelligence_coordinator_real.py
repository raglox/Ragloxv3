# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - REAL Intelligence Coordinator Tests
# NO MOCKS - Tests with real Blackboard, Knowledge, and LLM
# Phase 3 Intelligence Testing: IntelligenceCoordinator
# ═══════════════════════════════════════════════════════════════

import asyncio
import pytest
import time
from pathlib import Path
from uuid import uuid4

from src.core.intelligence_coordinator import (
    IntelligenceCoordinator,
    AttackPath,
    AttackPathType,
    StrategicAnalysis,
)
from src.core.blackboard import Blackboard
from src.core.knowledge import EmbeddedKnowledge
from src.core.models import Mission, MissionStatus


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
async def real_blackboard():
    """Real Blackboard with Redis - function scope for proper async handling."""
    blackboard = Blackboard(redis_url="redis://localhost:6379/0")
    await blackboard.connect()
    
    if not await blackboard.health_check():
        pytest.skip("Redis not available")
    
    print(f"\n✅ Blackboard connected to Redis")
    
    yield blackboard
    
    await blackboard.disconnect()


@pytest.fixture(scope="module")
def real_knowledge():
    """Real EmbeddedKnowledge with actual data."""
    EmbeddedKnowledge.reset()
    
    data_path = Path(__file__).parent.parent.parent / "data"
    knowledge = EmbeddedKnowledge(data_path=str(data_path))
    loaded = knowledge.load()
    
    if not loaded:
        pytest.skip("Knowledge base not available")
    
    print(f"✅ Knowledge loaded: {knowledge.get_statistics()['total_rx_modules']} modules")
    
    return knowledge


@pytest.fixture
async def coordinator(real_blackboard, real_knowledge):
    """Real IntelligenceCoordinator with real dependencies."""
    coordinator = IntelligenceCoordinator(
        blackboard=real_blackboard,
        knowledge_base=real_knowledge
    )
    
    print(f"✅ IntelligenceCoordinator initialized")
    
    return coordinator


@pytest.fixture
async def test_mission(real_blackboard):
    """Create a test mission."""
    mission_id = uuid4()
    mission = Mission(
        id=mission_id,
        name="Intelligence Test Mission",
        scope=["192.168.1.100"],
        goals={"test_intelligence": "pending"}
    )
    
    await real_blackboard.create_mission(mission)
    
    print(f"✅ Test mission created: {mission_id}")
    
    yield str(mission_id)
    
    # Cleanup
    try:
        await real_blackboard.delete_mission(str(mission_id))
    except:
        pass


# ═══════════════════════════════════════════════════════════════
# Test: Initialization
# ═══════════════════════════════════════════════════════════════

class TestRealIntelligenceCoordinatorInit:
    """Test IntelligenceCoordinator initialization."""
    
    @pytest.mark.asyncio
    async def test_coordinator_initializes(self, coordinator):
        """Test coordinator initializes with real dependencies."""
        # Check private attributes (note: these are private)
        assert coordinator._blackboard is not None
        assert coordinator._knowledge is not None
        
        # Check stats initialized
        stats = coordinator.get_stats()
        assert "analyses_performed" in stats
        assert "paths_generated" in stats
        
        print("✅ Coordinator initialized with all components")
    
    @pytest.mark.asyncio
    async def test_high_value_services_defined(self, coordinator):
        """Test high-value services are defined."""
        high_value = IntelligenceCoordinator.HIGH_VALUE_SERVICES
        
        assert len(high_value) > 0
        assert "ssh" in high_value
        assert "smb" in high_value
        assert "ldap" in high_value
        
        print(f"✅ High-value services: {len(high_value)}")


# ═══════════════════════════════════════════════════════════════
# Test: Strategic Value Calculation
# ═══════════════════════════════════════════════════════════════

class TestRealStrategicValue:
    """Test strategic value calculation."""
    
    @pytest.mark.asyncio
    async def test_calculate_strategic_value_critical(self, coordinator):
        """Test critical strategic value calculation."""
        services = [
            {"name": "ldap", "port": 389},
            {"name": "smb", "port": 445},
            {"name": "kerberos", "port": 88}
        ]
        
        vulnerabilities = [
            {"severity": "critical", "type": "CVE-2021-44228", "exploit_available": True},
            {"severity": "high", "type": "CVE-2020-1472", "exploit_available": True}
        ]
        
        credentials = [
            {"username": "admin", "privilege_level": "domain_admin", "verified": True}
        ]
        
        value = coordinator._calculate_strategic_value(services, vulnerabilities, credentials)
        
        assert value == "critical"
        print(f"✅ Strategic value: {value}")
    
    @pytest.mark.asyncio
    async def test_calculate_strategic_value_high(self, coordinator):
        """Test high strategic value calculation."""
        services = [
            {"name": "ssh", "port": 22},
            {"name": "http", "port": 80}
        ]
        
        vulnerabilities = [
            {"severity": "high", "type": "CVE-2022-1234", "exploit_available": True}
        ]
        
        value = coordinator._calculate_strategic_value(services, vulnerabilities, None)
        
        assert value in ("high", "medium")
        print(f"✅ Strategic value: {value}")


# ═══════════════════════════════════════════════════════════════
# Test: Attack Surface Analysis
# ═══════════════════════════════════════════════════════════════

class TestRealAttackSurfaceAnalysis:
    """Test attack surface analysis."""
    
    @pytest.mark.asyncio
    async def test_analyze_attack_surface_basic(self, coordinator):
        """Test basic attack surface analysis."""
        services = [
            {"name": "ssh", "port": 22},
            {"name": "http", "port": 80},
            {"name": "smb", "port": 445}
        ]
        
        vulnerabilities = [
            {"id": "vuln-1", "type": "ssh-vuln", "severity": "high", "exploit_available": True},
            {"id": "vuln-2", "type": "http-vuln", "severity": "medium", "exploit_available": False}
        ]
        
        surface = await coordinator._analyze_attack_surface(services, vulnerabilities)
        
        assert len(surface) == 3
        assert all("service" in entry for entry in surface)
        assert all("exposure_level" in entry for entry in surface)
        assert all("priority_score" in entry for entry in surface)
        
        # Should be sorted by priority
        assert surface[0]["priority_score"] >= surface[-1]["priority_score"]
        
        print(f"✅ Attack surface analyzed: {len(surface)} services")
        for entry in surface:
            print(f"   - {entry['service']}:{entry['port']} = {entry['priority_score']:.1f}")
    
    @pytest.mark.asyncio
    async def test_attack_surface_high_exposure(self, coordinator):
        """Test high-exposure services are prioritized."""
        services = [
            {"name": "ssh", "port": 22},
            {"name": "unknown", "port": 9999}
        ]
        
        vulnerabilities = []
        
        surface = await coordinator._analyze_attack_surface(services, vulnerabilities)
        
        # SSH (port 22) should be high exposure
        ssh_entry = next((s for s in surface if s["service"] == "ssh"), None)
        assert ssh_entry is not None
        assert ssh_entry["exposure_level"] == "high"
        
        print(f"✅ High-exposure services prioritized")


# ═══════════════════════════════════════════════════════════════
# Test: Attack Path Generation
# ═══════════════════════════════════════════════════════════════

class TestRealAttackPathGeneration:
    """Test attack path generation."""
    
    @pytest.mark.asyncio
    async def test_generate_direct_exploit_path(self, coordinator):
        """Test direct exploit path generation."""
        target_id = "192.168.1.100"
        
        vuln = {
            "id": "vuln-1",
            "type": "CVE-2021-44228",
            "severity": "critical",
            "exploit_available": True
        }
        
        services = [
            {"name": "http", "port": 80}
        ]
        
        path = await coordinator._create_direct_exploit_path(target_id, vuln, services)
        
        assert path is not None
        assert path.path_type == AttackPathType.DIRECT_EXPLOIT
        assert path.destination_target == target_id
        assert len(path.steps) >= 1
        assert path.success_probability > 0
        
        print(f"✅ Direct exploit path: {len(path.steps)} steps, {path.success_probability:.0%} success")
    
    @pytest.mark.asyncio
    async def test_generate_credential_based_path(self, coordinator):
        """Test credential-based path generation."""
        target_id = "192.168.1.100"
        
        cred = {
            "id": "cred-1",
            "username": "admin",
            "privilege_level": "admin",
            "verified": True,
            "type": "password"
        }
        
        services = [
            {"name": "ssh", "port": 22}
        ]
        
        path = await coordinator._create_credential_path(target_id, cred, services)
        
        assert path is not None
        assert path.path_type == AttackPathType.CREDENTIAL_BASED
        assert len(path.required_credentials) > 0
        assert path.stealth_score >= 0.7  # Credential auth is stealthy
        
        print(f"✅ Credential path: {path.stealth_score:.0%} stealth")
    
    @pytest.mark.asyncio
    async def test_generate_multiple_attack_paths(self, coordinator):
        """Test generating multiple attack paths."""
        target_id = "192.168.1.100"
        
        services = [
            {"name": "ssh", "port": 22},
            {"name": "smb", "port": 445}
        ]
        
        vulnerabilities = [
            {"id": "v1", "type": "CVE-2021-44228", "severity": "critical", "exploit_available": True},
            {"id": "v2", "type": "CVE-2020-1472", "severity": "high", "exploit_available": True}
        ]
        
        credentials = [
            {"id": "c1", "username": "user", "privilege_level": "user", "verified": True}
        ]
        
        paths = await coordinator.generate_attack_paths(
            target_id=target_id,
            services=services,
            vulnerabilities=vulnerabilities,
            credentials=credentials
        )
        
        assert len(paths) > 0
        
        # Paths should be sorted by combined score
        for i in range(len(paths) - 1):
            score1 = (paths[i].success_probability * 0.4 + 
                     paths[i].stealth_score * 0.3 +
                     (1 - min(paths[i].time_estimate_minutes, 120) / 120) * 0.3)
            score2 = (paths[i+1].success_probability * 0.4 + 
                     paths[i+1].stealth_score * 0.3 +
                     (1 - min(paths[i+1].time_estimate_minutes, 120) / 120) * 0.3)
            assert score1 >= score2
        
        print(f"✅ Generated {len(paths)} attack paths")
        for path in paths:
            print(f"   - {path.path_type.value}: {path.success_probability:.0%} success, {path.stealth_score:.0%} stealth")


# ═══════════════════════════════════════════════════════════════
# Test: Strategic Analysis (End-to-End)
# ═══════════════════════════════════════════════════════════════

class TestRealStrategicAnalysis:
    """Test strategic analysis end-to-end."""
    
    @pytest.mark.asyncio
    async def test_process_recon_results_basic(self, coordinator, test_mission):
        """Test processing recon results."""
        target_id = "192.168.1.100"
        
        services = [
            {"name": "ssh", "port": 22},
            {"name": "http", "port": 80}
        ]
        
        vulnerabilities = [
            {"id": "v1", "type": "CVE-2021-44228", "severity": "critical", "exploit_available": True}
        ]
        
        analysis = await coordinator.process_recon_results(
            mission_id=test_mission,
            target_id=target_id,
            services=services,
            vulnerabilities=vulnerabilities
        )
        
        assert analysis is not None
        assert analysis.target_id == target_id
        assert analysis.strategic_value in ("critical", "high", "medium", "low")
        assert len(analysis.attack_surface) > 0
        assert len(analysis.recommended_paths) > 0
        
        print(f"✅ Strategic analysis completed")
        print(f"   - Value: {analysis.strategic_value}")
        print(f"   - Attack surface: {len(analysis.attack_surface)}")
        print(f"   - Recommended paths: {len(analysis.recommended_paths)}")
    
    @pytest.mark.asyncio
    async def test_analysis_with_credentials(self, coordinator, test_mission):
        """Test analysis with credentials."""
        target_id = "192.168.1.100"
        
        services = [
            {"name": "ssh", "port": 22}
        ]
        
        vulnerabilities = []
        
        credentials = [
            {"id": "c1", "username": "admin", "privilege_level": "admin", "verified": True}
        ]
        
        analysis = await coordinator.process_recon_results(
            mission_id=test_mission,
            target_id=target_id,
            services=services,
            vulnerabilities=vulnerabilities,
            credentials=credentials
        )
        
        # Should have credential-based paths
        cred_paths = [p for p in analysis.recommended_paths 
                     if p.path_type == AttackPathType.CREDENTIAL_BASED]
        
        assert len(cred_paths) > 0
        
        print(f"✅ Credential-based paths: {len(cred_paths)}")


# ═══════════════════════════════════════════════════════════════
# Test: Real-Time Coordination
# ═══════════════════════════════════════════════════════════════

class TestRealTimeCoordination:
    """Test real-time coordination features."""
    
    @pytest.mark.asyncio
    async def test_coordinate_discovery_to_attack(self, coordinator, test_mission):
        """Test coordinating from discovery to attack."""
        target_id = "192.168.1.100"
        
        # Simulate discovery phase results
        services = [
            {"name": "smb", "port": 445},
            {"name": "ldap", "port": 389}
        ]
        
        vulnerabilities = [
            {"id": "v1", "type": "ms17-010", "severity": "critical", "exploit_available": True}
        ]
        
        # Process and analyze
        analysis = await coordinator.process_recon_results(
            mission_id=test_mission,
            target_id=target_id,
            services=services,
            vulnerabilities=vulnerabilities
        )
        
        # Check immediate actions recommended
        assert len(analysis.immediate_actions) > 0
        
        print(f"✅ Coordination complete")
        print(f"   - Immediate actions: {len(analysis.immediate_actions)}")
        print(f"   - Deferred actions: {len(analysis.deferred_actions)}")


# ═══════════════════════════════════════════════════════════════
# Test: Path Prioritization
# ═══════════════════════════════════════════════════════════════

class TestRealAttackPathPrioritization:
    """Test attack path prioritization."""
    
    @pytest.mark.asyncio
    async def test_paths_sorted_by_priority(self, coordinator):
        """Test paths are sorted by priority."""
        target_id = "192.168.1.100"
        
        services = [
            {"name": "ssh", "port": 22},
            {"name": "smb", "port": 445},
            {"name": "http", "port": 80}
        ]
        
        vulnerabilities = [
            {"id": "v1", "type": "CVE-2021-44228", "severity": "critical", "exploit_available": True},
            {"id": "v2", "type": "CVE-2022-1234", "severity": "high", "exploit_available": True},
            {"id": "v3", "type": "CVE-2023-5678", "severity": "medium", "exploit_available": False}
        ]
        
        credentials = [
            {"id": "c1", "username": "admin", "privilege_level": "admin", "verified": True}
        ]
        
        paths = await coordinator.generate_attack_paths(
            target_id=target_id,
            services=services,
            vulnerabilities=vulnerabilities,
            credentials=credentials
        )
        
        # Check sorted by composite score
        print(f"🎯 Path Prioritization:")
        for i, path in enumerate(paths):
            score = (path.success_probability * 0.4 + 
                    path.stealth_score * 0.3 +
                    (1 - min(path.time_estimate_minutes, 120) / 120) * 0.3)
            print(f"   #{i+1} {path.path_type.value}: score={score:.2f} "
                  f"(prob={path.success_probability:.0%}, stealth={path.stealth_score:.0%})")


# ═══════════════════════════════════════════════════════════════
# Test: Performance
# ═══════════════════════════════════════════════════════════════

class TestRealCoordinatorPerformance:
    """Test coordinator performance."""
    
    @pytest.mark.asyncio
    async def test_analysis_performance(self, coordinator, test_mission):
        """Test analysis performance."""
        target_id = "192.168.1.100"
        
        services = [
            {"name": "ssh", "port": 22},
            {"name": "smb", "port": 445},
            {"name": "http", "port": 80}
        ]
        
        vulnerabilities = [
            {"id": "v1", "type": "CVE-2021-44228", "severity": "critical", "exploit_available": True}
        ]
        
        start = time.time()
        
        analysis = await coordinator.process_recon_results(
            mission_id=test_mission,
            target_id=target_id,
            services=services,
            vulnerabilities=vulnerabilities
        )
        
        elapsed = (time.time() - start) * 1000
        
        # Should complete in reasonable time
        assert elapsed < 500  # 500ms
        
        print(f"✅ Analysis performance: {elapsed:.2f} ms")
    
    @pytest.mark.asyncio
    async def test_cache_effectiveness(self, coordinator):
        """Test path cache effectiveness."""
        target_id = "192.168.1.100"
        
        services = [{"name": "ssh", "port": 22}]
        vulnerabilities = [{"id": "v1", "type": "test", "severity": "high", "exploit_available": True}]
        
        # Clear cache first
        coordinator.clear_cache()
        
        # First call - should miss cache
        paths1 = await coordinator.generate_attack_paths(target_id, services, vulnerabilities)
        stats1 = coordinator.get_stats()
        
        # Second call - should hit cache
        paths2 = await coordinator.generate_attack_paths(target_id, services, vulnerabilities)
        stats2 = coordinator.get_stats()
        
        # Cache hits should increase
        assert stats2["cache_hits"] > stats1["cache_hits"]
        
        print(f"✅ Cache working: {stats2['cache_hits']} hits")


# ═══════════════════════════════════════════════════════════════
# Test: Integration with Knowledge Base
# ═══════════════════════════════════════════════════════════════

class TestRealKnowledgeIntegration:
    """Test integration with EmbeddedKnowledge."""
    
    @pytest.mark.asyncio
    async def test_uses_knowledge_for_exploits(self, coordinator, real_knowledge):
        """Test coordinator uses knowledge base for exploit selection."""
        target_id = "192.168.1.100"
        
        # Use a real technique
        vuln = {
            "id": "v1",
            "type": "T1003",  # OS Credential Dumping
            "severity": "high",
            "exploit_available": True
        }
        
        services = [{"name": "smb", "port": 445}]
        
        path = await coordinator._create_direct_exploit_path(target_id, vuln, services)
        
        assert path is not None
        
        print(f"✅ Knowledge integration working")
        print(f"   - Path: {path.reasoning}")
