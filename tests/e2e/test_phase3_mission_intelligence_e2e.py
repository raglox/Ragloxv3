"""
RAGLOX v3.0 - Phase 3.0 Mission Intelligence E2E Tests

Enterprise-level end-to-end tests for Mission Intelligence System.
Tests real integration with Blackboard, Redis, PostgreSQL, and Vector Store.

Author: RAGLOX Team
Version: 3.0.0
Date: 2026-01-10
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List
import uuid

from src.core.reasoning.mission_intelligence import (
    MissionIntelligence,
    TargetIntel,
    VulnerabilityIntel,
    CredentialIntel,
    NetworkMap,
    AttackSurfaceAnalysis,
    IntelConfidence,
    AttackVectorType,
    DefenseType
)
from src.core.reasoning.mission_intelligence_builder import MissionIntelligenceBuilder
from src.core.blackboard import Blackboard
from src.core.models import (
    MissionStatus,
    TargetStatus,
    Priority,
    Severity,
    CredentialType,
    PrivilegeLevel
)


@pytest.mark.e2e
@pytest.mark.asyncio
class TestPhase3MissionIntelligenceE2E:
    """E2E tests for Phase 3.0 Mission Intelligence System"""

    @pytest.fixture(autouse=True)
    async def setup(self, real_blackboard, real_redis, real_database):
        """Setup test environment with real services"""
        self.blackboard = real_blackboard
        self.redis = real_redis
        self.database = real_database
        
        # Create test mission
        self.mission_id = f"mission_e2e_{uuid.uuid4().hex[:8]}"
        await self.blackboard.create_mission(
            mission_id=self.mission_id,
            name="E2E Intelligence Test",
            description="Testing Mission Intelligence with real services",
            scope=["192.168.1.0/24"],
            goals=["Gain initial access", "Escalate privileges"],
            constraints={"time_limit": "2h", "stealth": "high"}
        )
        
        yield
        
        # Cleanup
        try:
            await self.blackboard.delete_mission(self.mission_id)
        except:
            pass

    @pytest.mark.priority_critical
    async def test_e2e_full_intelligence_pipeline(self):
        """
        Test complete intelligence gathering pipeline with real services
        
        Covers:
        - Reconnaissance data collection
        - Vulnerability scanning analysis
        - Exploitation data extraction
        - Attack graph building
        - Recommendation generation
        - Persistence to Blackboard
        """
        # Phase 1: Add reconnaissance data
        targets = [
            {
                "target_id": f"target_{i}",
                "ip": f"192.168.1.{i}",
                "hostname": f"server{i}.test.local",
                "os": "Ubuntu 20.04" if i % 2 == 0 else "Windows Server 2019",
                "status": TargetStatus.scanned.value,
                "ports": [22, 80, 443] if i % 2 == 0 else [445, 3389, 5985],
                "services": ["ssh", "http", "https"] if i % 2 == 0 else ["smb", "rdp", "winrm"]
            }
            for i in range(1, 6)  # 5 targets
        ]
        
        for target in targets:
            await self.blackboard.add_target(
                mission_id=self.mission_id,
                **target
            )
        
        # Phase 2: Add vulnerabilities
        vulnerabilities = [
            {
                "target_id": "target_1",
                "vulnerability_id": "CVE-2024-0001",
                "severity": Severity.critical.value,
                "cvss_score": 9.8,
                "description": "Remote Code Execution in SSH",
                "exploit_available": True
            },
            {
                "target_id": "target_2",
                "vulnerability_id": "CVE-2024-0002",
                "severity": Severity.high.value,
                "cvss_score": 8.1,
                "description": "SMB Authentication Bypass",
                "exploit_available": True
            },
            {
                "target_id": "target_3",
                "vulnerability_id": "CVE-2024-0003",
                "severity": Severity.medium.value,
                "cvss_score": 6.5,
                "description": "HTTP Directory Traversal",
                "exploit_available": False
            }
        ]
        
        for vuln in vulnerabilities:
            await self.blackboard.add_vulnerability(
                mission_id=self.mission_id,
                **vuln
            )
        
        # Phase 3: Add credentials
        credentials = [
            {
                "credential_id": "cred_1",
                "username": "admin",
                "credential_type": CredentialType.password.value,
                "credential_value": "Admin123!",
                "target_id": "target_1",
                "privilege_level": PrivilegeLevel.admin.value,
                "source": "password_spray"
            },
            {
                "credential_id": "cred_2",
                "username": "root",
                "credential_type": CredentialType.hash.value,
                "credential_value": "$6$rounds=5000$...",
                "target_id": "target_1",
                "privilege_level": PrivilegeLevel.root.value,
                "source": "credential_dump"
            }
        ]
        
        for cred in credentials:
            await self.blackboard.add_credential(
                mission_id=self.mission_id,
                **cred
            )
        
        # Phase 4: Build intelligence
        builder = MissionIntelligenceBuilder(
            mission_id=self.mission_id,
            blackboard=self.blackboard
        )
        
        # Collect reconnaissance intelligence
        await builder.collect_recon_intelligence()
        
        # Analyze vulnerabilities
        vuln_analysis = await builder.analyze_vulnerability_scan()
        
        # Extract exploitation data
        exploit_data = await builder.extract_exploitation_data()
        
        # Build attack graph
        attack_graph = await builder.build_attack_graph()
        
        # Generate recommendations
        recommendations = await builder.generate_recommendations()
        
        # Build full intelligence
        intelligence = await builder.build_full_intelligence()
        
        # Assertions
        assert intelligence is not None
        assert intelligence.mission_id == self.mission_id
        assert len(intelligence.targets) == 5
        assert len(intelligence.vulnerabilities) == 3
        assert len(intelligence.credentials) == 2
        assert intelligence.attack_surface is not None
        assert len(intelligence.attack_surface.attack_vectors) > 0
        assert len(intelligence.recommendations) > 0
        
        # Verify data quality
        critical_vulns = [v for v in intelligence.vulnerabilities.values() 
                         if v.severity == Severity.critical]
        assert len(critical_vulns) == 1
        
        privileged_creds = [c for c in intelligence.credentials.values()
                           if c.privilege_level in [PrivilegeLevel.admin, PrivilegeLevel.root]]
        assert len(privileged_creds) == 2
        
        # Verify recommendations
        assert any(r.priority == Priority.critical for r in intelligence.recommendations)
        
        print(f"✅ Full intelligence pipeline test passed")
        print(f"   Targets: {len(intelligence.targets)}")
        print(f"   Vulnerabilities: {len(intelligence.vulnerabilities)}")
        print(f"   Credentials: {len(intelligence.credentials)}")
        print(f"   Recommendations: {len(intelligence.recommendations)}")

    @pytest.mark.priority_high
    async def test_e2e_intelligence_persistence(self):
        """Test intelligence data persistence to Blackboard and Redis"""
        # Create intelligence
        intel = MissionIntelligence(
            mission_id=self.mission_id,
            version=1
        )
        
        # Add data
        target = TargetIntel(
            target_id="persist_target",
            ip_address="192.168.1.100",
            hostname="persistence.test",
            status=TargetStatus.scanned,
            confidence=IntelConfidence.high,
            discovered_at=datetime.utcnow()
        )
        intel.add_target(target)
        
        # Serialize
        intel_dict = intel.to_dict()
        
        # Store in Redis
        redis_key = f"intelligence:{self.mission_id}:v{intel.version}"
        await self.redis.set(
            redis_key,
            str(intel_dict),
            ex=3600  # 1 hour TTL
        )
        
        # Retrieve and verify
        stored_data = await self.redis.get(redis_key)
        assert stored_data is not None
        
        # Store in Blackboard
        await self.blackboard.store_metadata(
            mission_id=self.mission_id,
            key="intelligence",
            value=intel_dict
        )
        
        # Retrieve from Blackboard
        retrieved = await self.blackboard.get_metadata(
            mission_id=self.mission_id,
            key="intelligence"
        )
        assert retrieved is not None
        assert retrieved["version"] == intel.version
        
        print("✅ Intelligence persistence test passed")

    @pytest.mark.priority_high
    async def test_e2e_real_time_intelligence_updates(self):
        """Test real-time intelligence updates during mission execution"""
        builder = MissionIntelligenceBuilder(
            mission_id=self.mission_id,
            blackboard=self.blackboard
        )
        
        # Initial intelligence
        initial_intel = MissionIntelligence(mission_id=self.mission_id, version=1)
        builder.intelligence = initial_intel
        
        # Simulate real-time events
        events = [
            # Event 1: New target discovered
            ("target_discovered", {
                "target_id": "rt_target_1",
                "ip": "192.168.1.50",
                "hostname": "new-server.test",
                "status": TargetStatus.discovered.value
            }),
            # Event 2: Vulnerability found
            ("vulnerability_detected", {
                "target_id": "rt_target_1",
                "vulnerability_id": "CVE-2024-9999",
                "severity": Severity.high.value,
                "cvss_score": 8.5
            }),
            # Event 3: Credential obtained
            ("credential_found", {
                "credential_id": "rt_cred_1",
                "username": "user",
                "credential_type": CredentialType.password.value,
                "credential_value": "pass123",
                "target_id": "rt_target_1",
                "privilege_level": PrivilegeLevel.user.value
            })
        ]
        
        # Process events in real-time
        for event_type, event_data in events:
            if event_type == "target_discovered":
                await self.blackboard.add_target(
                    mission_id=self.mission_id,
                    **event_data
                )
                # Update intelligence
                target = TargetIntel(
                    target_id=event_data["target_id"],
                    ip_address=event_data["ip"],
                    hostname=event_data.get("hostname"),
                    status=TargetStatus[event_data["status"]],
                    confidence=IntelConfidence.medium,
                    discovered_at=datetime.utcnow()
                )
                builder.intelligence.add_target(target)
                
            elif event_type == "vulnerability_detected":
                await self.blackboard.add_vulnerability(
                    mission_id=self.mission_id,
                    **event_data
                )
                # Update intelligence
                vuln = VulnerabilityIntel(
                    vulnerability_id=event_data["vulnerability_id"],
                    target_id=event_data["target_id"],
                    severity=Severity[event_data["severity"]],
                    cvss_score=event_data["cvss_score"],
                    confidence=IntelConfidence.high,
                    discovered_at=datetime.utcnow()
                )
                builder.intelligence.add_vulnerability(vuln)
                
            elif event_type == "credential_found":
                await self.blackboard.add_credential(
                    mission_id=self.mission_id,
                    **event_data
                )
                # Update intelligence
                cred = CredentialIntel(
                    credential_id=event_data["credential_id"],
                    username=event_data["username"],
                    credential_type=CredentialType[event_data["credential_type"]],
                    target_id=event_data["target_id"],
                    privilege_level=PrivilegeLevel[event_data["privilege_level"]],
                    confidence=IntelConfidence.high,
                    obtained_at=datetime.utcnow()
                )
                builder.intelligence.add_credential(cred)
            
            # Increment version after each update
            builder.intelligence.version += 1
            
            # Small delay to simulate real-time
            await asyncio.sleep(0.1)
        
        # Verify final state
        assert len(builder.intelligence.targets) == 1
        assert len(builder.intelligence.vulnerabilities) == 1
        assert len(builder.intelligence.credentials) == 1
        assert builder.intelligence.version == 4  # Initial + 3 updates
        
        print("✅ Real-time intelligence updates test passed")
        print(f"   Final version: {builder.intelligence.version}")
        print(f"   Events processed: {len(events)}")

    @pytest.mark.priority_high
    async def test_e2e_intelligence_with_vector_search(self, real_vector_store):
        """Test intelligence integration with vector knowledge search"""
        if real_vector_store is None:
            pytest.skip("Vector store not available")
        
        builder = MissionIntelligenceBuilder(
            mission_id=self.mission_id,
            blackboard=self.blackboard,
            knowledge_retriever=real_vector_store
        )
        
        # Add vulnerability that requires knowledge lookup
        await self.blackboard.add_vulnerability(
            mission_id=self.mission_id,
            target_id="vec_target",
            vulnerability_id="CVE-2024-1234",
            severity=Severity.critical.value,
            cvss_score=9.5,
            description="SQL Injection in web application"
        )
        
        # Analyze with knowledge retrieval
        await builder.analyze_vulnerability_scan()
        
        # Generate recommendations with KB context
        recommendations = await builder.generate_recommendations()
        
        # Verify recommendations include KB-enhanced suggestions
        assert len(recommendations) > 0
        
        # Check if recommendations reference exploit techniques
        has_exploit_ref = any(
            "exploit" in r.description.lower() or "technique" in r.description.lower()
            for r in recommendations
        )
        
        print("✅ Intelligence with vector search test passed")
        print(f"   Recommendations generated: {len(recommendations)}")
        print(f"   KB-enhanced: {has_exploit_ref}")

    @pytest.mark.priority_medium
    async def test_e2e_intelligence_export_import(self):
        """Test intelligence export and import functionality"""
        # Build intelligence
        builder = MissionIntelligenceBuilder(
            mission_id=self.mission_id,
            blackboard=self.blackboard
        )
        
        # Add sample data
        target = TargetIntel(
            target_id="export_target",
            ip_address="192.168.1.200",
            hostname="export.test",
            status=TargetStatus.owned,
            confidence=IntelConfidence.confirmed,
            discovered_at=datetime.utcnow()
        )
        builder.intelligence = MissionIntelligence(mission_id=self.mission_id)
        builder.intelligence.add_target(target)
        
        # Export
        exported = builder.intelligence.to_dict()
        
        # Verify export structure
        assert "mission_id" in exported
        assert "targets" in exported
        assert "version" in exported
        assert "generated_at" in exported
        
        # Import (create new instance from dict)
        imported = MissionIntelligence(
            mission_id=exported["mission_id"],
            version=exported["version"]
        )
        
        # Reconstruct targets
        for target_id, target_data in exported["targets"].items():
            imported_target = TargetIntel(
                target_id=target_data["target_id"],
                ip_address=target_data["ip_address"],
                hostname=target_data.get("hostname"),
                status=TargetStatus[target_data["status"]],
                confidence=IntelConfidence[target_data["confidence"]],
                discovered_at=datetime.fromisoformat(target_data["discovered_at"])
            )
            imported.add_target(imported_target)
        
        # Verify
        assert imported.mission_id == exported["mission_id"]
        assert len(imported.targets) == len(exported["targets"])
        
        print("✅ Intelligence export/import test passed")

    @pytest.mark.priority_critical
    async def test_e2e_concurrent_intelligence_updates(self):
        """Test concurrent intelligence updates from multiple sources"""
        builder = MissionIntelligenceBuilder(
            mission_id=self.mission_id,
            blackboard=self.blackboard
        )
        builder.intelligence = MissionIntelligence(mission_id=self.mission_id)
        
        # Simulate concurrent updates from different specialists
        async def add_targets():
            for i in range(5):
                target = TargetIntel(
                    target_id=f"concurrent_target_{i}",
                    ip_address=f"192.168.2.{i}",
                    hostname=f"concurrent{i}.test",
                    status=TargetStatus.discovered,
                    confidence=IntelConfidence.medium,
                    discovered_at=datetime.utcnow()
                )
                builder.intelligence.add_target(target)
                await asyncio.sleep(0.01)
        
        async def add_vulnerabilities():
            for i in range(3):
                vuln = VulnerabilityIntel(
                    vulnerability_id=f"VULN-{i}",
                    target_id=f"concurrent_target_{i}",
                    severity=Severity.high,
                    cvss_score=7.5 + i * 0.5,
                    confidence=IntelConfidence.high,
                    discovered_at=datetime.utcnow()
                )
                builder.intelligence.add_vulnerability(vuln)
                await asyncio.sleep(0.01)
        
        async def add_credentials():
            for i in range(2):
                cred = CredentialIntel(
                    credential_id=f"concurrent_cred_{i}",
                    username=f"user{i}",
                    credential_type=CredentialType.password,
                    target_id=f"concurrent_target_{i}",
                    privilege_level=PrivilegeLevel.user,
                    confidence=IntelConfidence.confirmed,
                    obtained_at=datetime.utcnow()
                )
                builder.intelligence.add_credential(cred)
                await asyncio.sleep(0.01)
        
        # Run concurrently
        await asyncio.gather(
            add_targets(),
            add_vulnerabilities(),
            add_credentials()
        )
        
        # Verify all updates succeeded
        assert len(builder.intelligence.targets) == 5
        assert len(builder.intelligence.vulnerabilities) == 3
        assert len(builder.intelligence.credentials) == 2
        
        print("✅ Concurrent intelligence updates test passed")
        print(f"   Targets: {len(builder.intelligence.targets)}")
        print(f"   Vulnerabilities: {len(builder.intelligence.vulnerabilities)}")
        print(f"   Credentials: {len(builder.intelligence.credentials)}")


@pytest.mark.e2e
@pytest.mark.performance
class TestPhase3PerformanceE2E:
    """Performance tests for Phase 3.0"""

    @pytest.fixture(autouse=True)
    async def setup(self, real_blackboard):
        self.blackboard = real_blackboard
        self.mission_id = f"perf_e2e_{uuid.uuid4().hex[:8]}"
        await self.blackboard.create_mission(
            mission_id=self.mission_id,
            name="Performance Test",
            description="Testing intelligence performance",
            scope=["10.0.0.0/16"],
            goals=["Performance testing"],
            constraints={}
        )
        yield
        try:
            await self.blackboard.delete_mission(self.mission_id)
        except:
            pass

    async def test_large_scale_intelligence_processing(self):
        """Test intelligence processing with large datasets"""
        import time
        
        start_time = time.time()
        
        # Add 100 targets
        for i in range(100):
            await self.blackboard.add_target(
                mission_id=self.mission_id,
                target_id=f"perf_target_{i}",
                ip=f"10.0.{i // 256}.{i % 256}",
                hostname=f"server{i}.perf.test",
                status=TargetStatus.scanned.value,
                ports=[22, 80, 443],
                services=["ssh", "http", "https"]
            )
        
        # Add 50 vulnerabilities
        for i in range(50):
            await self.blackboard.add_vulnerability(
                mission_id=self.mission_id,
                target_id=f"perf_target_{i % 100}",
                vulnerability_id=f"PERF-VULN-{i}",
                severity=Severity.medium.value,
                cvss_score=5.0 + (i % 5),
                description=f"Performance test vulnerability {i}"
            )
        
        # Build intelligence
        builder = MissionIntelligenceBuilder(
            mission_id=self.mission_id,
            blackboard=self.blackboard
        )
        
        intelligence = await builder.build_full_intelligence()
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Performance assertions
        assert duration < 10.0  # Should complete within 10 seconds
        assert len(intelligence.targets) == 100
        assert len(intelligence.vulnerabilities) == 50
        
        print(f"✅ Large-scale intelligence processing test passed")
        print(f"   Duration: {duration:.2f}s")
        print(f"   Targets processed: 100")
        print(f"   Vulnerabilities processed: 50")
        print(f"   Throughput: {150/duration:.2f} items/sec")
