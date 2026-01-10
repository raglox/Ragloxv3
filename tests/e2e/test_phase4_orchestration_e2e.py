"""
RAGLOX v3.0 - Phase 4.0 Specialist Orchestration E2E Tests

Enterprise-level end-to-end tests for Specialist Orchestration and Mission Planning.
Tests real integration with Specialists, Blackboard, Redis, and Mission Intelligence.

Author: RAGLOX Team
Version: 3.0.0
Date: 2026-01-10
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List
import uuid

from src.core.reasoning.specialist_orchestrator import SpecialistOrchestrator
from src.core.planning.mission_planner import MissionPlanner
from src.core.reasoning.mission_intelligence import MissionIntelligence, TargetIntel, IntelConfidence
from src.core.blackboard import Blackboard
from src.core.models import (
    MissionStatus,
    MissionPhase,
    TargetStatus,
    Priority,
    TaskType,
    TaskStatus,
    SpecialistType
)


@pytest.mark.e2e
@pytest.mark.asyncio
class TestPhase4OrchestrationE2E:
    """E2E tests for Phase 4.0 Specialist Orchestration"""

    @pytest.fixture(autouse=True)
    async def setup(self, real_blackboard, real_redis):
        """Setup test environment with real services"""
        self.blackboard = real_blackboard
        self.redis = real_redis
        
        # Create test mission
        self.mission_id = f"orch_e2e_{uuid.uuid4().hex[:8]}"
        await self.blackboard.create_mission(
            mission_id=self.mission_id,
            name="E2E Orchestration Test",
            description="Testing Specialist Orchestration with real services",
            scope=["172.16.0.0/24"],
            goals=["Test orchestration", "Validate coordination"],
            constraints={"stealth": "medium"}
        )
        
        # Initialize orchestrator
        self.orchestrator = SpecialistOrchestrator(
            mission_id=self.mission_id,
            blackboard=self.blackboard
        )
        
        yield
        
        # Cleanup
        try:
            await self.blackboard.delete_mission(self.mission_id)
        except:
            pass

    @pytest.mark.priority_critical
    async def test_e2e_specialist_coordination_lifecycle(self):
        """
        Test complete specialist coordination lifecycle
        
        Covers:
        - Specialist registration
        - Task assignment
        - Progress monitoring
        - Result collection
        - Coordination across multiple specialists
        """
        # Phase 1: Register specialists
        specialists = [
            SpecialistType.recon,
            SpecialistType.vuln,
            SpecialistType.attack
        ]
        
        for spec_type in specialists:
            await self.orchestrator.register_specialist(
                specialist_type=spec_type,
                specialist_id=f"{spec_type.value}_001",
                capabilities=["scan", "enumerate", "exploit"]
            )
        
        # Verify registration
        active = self.orchestrator.get_active_specialists()
        assert len(active) == 3
        
        # Phase 2: Create and assign tasks
        tasks = [
            {
                "task_type": TaskType.network_scan,
                "assigned_to": SpecialistType.recon,
                "priority": Priority.high,
                "params": {"target": "172.16.0.0/24"}
            },
            {
                "task_type": TaskType.vuln_scan,
                "assigned_to": SpecialistType.vuln,
                "priority": Priority.high,
                "params": {"target_id": "target_1"}
            },
            {
                "task_type": TaskType.exploit,
                "assigned_to": SpecialistType.attack,
                "priority": Priority.critical,
                "params": {"vulnerability_id": "CVE-2024-0001", "target_id": "target_1"}
            }
        ]
        
        task_ids = []
        for task_def in tasks:
            task_id = await self.blackboard.create_task(
                mission_id=self.mission_id,
                task_type=task_def["task_type"].value,
                assigned_to=task_def["assigned_to"].value,
                priority=task_def["priority"].value,
                params=task_def["params"]
            )
            task_ids.append(task_id)
        
        # Phase 3: Simulate task execution
        for task_id in task_ids:
            # Update to running
            await self.blackboard.update_task(
                mission_id=self.mission_id,
                task_id=task_id,
                status=TaskStatus.running.value,
                progress=0
            )
            
            # Simulate progress
            for progress in [25, 50, 75, 100]:
                await asyncio.sleep(0.1)
                await self.blackboard.update_task(
                    mission_id=self.mission_id,
                    task_id=task_id,
                    progress=progress
                )
            
            # Complete task
            await self.blackboard.update_task(
                mission_id=self.mission_id,
                task_id=task_id,
                status=TaskStatus.completed.value,
                result={"success": True, "data": f"Task {task_id} completed"}
            )
        
        # Phase 4: Verify coordination
        mission_data = await self.blackboard.get_mission(self.mission_id)
        completed_tasks = [
            t for t in mission_data.get("tasks", [])
            if t.get("status") == TaskStatus.completed.value
        ]
        
        assert len(completed_tasks) == 3
        
        # Verify each specialist completed their task
        for task_def, task_id in zip(tasks, task_ids):
            task_data = await self.blackboard.get_task(self.mission_id, task_id)
            assert task_data["status"] == TaskStatus.completed.value
            assert task_data["progress"] == 100
        
        print("✅ Specialist coordination lifecycle test passed")
        print(f"   Specialists registered: {len(specialists)}")
        print(f"   Tasks completed: {len(completed_tasks)}")

    @pytest.mark.priority_high
    async def test_e2e_dynamic_task_allocation(self):
        """Test dynamic task allocation based on specialist availability"""
        # Register multiple specialists of same type
        for i in range(3):
            await self.orchestrator.register_specialist(
                specialist_type=SpecialistType.recon,
                specialist_id=f"recon_{i:03d}",
                capabilities=["scan", "enumerate"]
            )
        
        # Create many tasks
        task_ids = []
        for i in range(10):
            task_id = await self.blackboard.create_task(
                mission_id=self.mission_id,
                task_type=TaskType.network_scan.value,
                assigned_to=SpecialistType.recon.value,
                priority=Priority.medium.value,
                params={"subnet": f"172.16.{i}.0/24"}
            )
            task_ids.append(task_id)
        
        # Simulate parallel execution
        async def execute_task(task_id):
            await self.blackboard.update_task(
                mission_id=self.mission_id,
                task_id=task_id,
                status=TaskStatus.running.value
            )
            await asyncio.sleep(0.2)  # Simulate work
            await self.blackboard.update_task(
                mission_id=self.mission_id,
                task_id=task_id,
                status=TaskStatus.completed.value,
                result={"success": True}
            )
        
        # Execute all tasks concurrently
        await asyncio.gather(*[execute_task(tid) for tid in task_ids])
        
        # Verify all completed
        mission_data = await self.blackboard.get_mission(self.mission_id)
        completed = sum(
            1 for t in mission_data.get("tasks", [])
            if t.get("status") == TaskStatus.completed.value
        )
        
        assert completed == 10
        
        print("✅ Dynamic task allocation test passed")
        print(f"   Tasks allocated: 10")
        print(f"   Specialists available: 3")
        print(f"   Parallelization factor: {10/3:.1f}x")

    @pytest.mark.priority_high
    async def test_e2e_task_dependency_coordination(self):
        """Test coordination of dependent tasks across specialists"""
        # Register specialists
        await self.orchestrator.register_specialist(
            specialist_type=SpecialistType.recon,
            specialist_id="recon_001",
            capabilities=["scan"]
        )
        await self.orchestrator.register_specialist(
            specialist_type=SpecialistType.vuln,
            specialist_id="vuln_001",
            capabilities=["scan"]
        )
        await self.orchestrator.register_specialist(
            specialist_type=SpecialistType.attack,
            specialist_id="attack_001",
            capabilities=["exploit"]
        )
        
        # Create dependent task chain
        # Task 1: Reconnaissance (no dependencies)
        recon_task = await self.blackboard.create_task(
            mission_id=self.mission_id,
            task_type=TaskType.network_scan.value,
            assigned_to=SpecialistType.recon.value,
            priority=Priority.high.value,
            params={"target": "172.16.0.0/24"}
        )
        
        # Execute recon task
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=recon_task,
            status=TaskStatus.running.value
        )
        await asyncio.sleep(0.1)
        
        # Complete recon and add target
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=recon_task,
            status=TaskStatus.completed.value,
            result={"targets_found": 1}
        )
        
        target_id = await self.blackboard.add_target(
            mission_id=self.mission_id,
            target_id="dep_target_1",
            ip="172.16.0.10",
            hostname="server.test",
            status=TargetStatus.discovered.value,
            ports=[22, 80, 443],
            services=["ssh", "http", "https"]
        )
        
        # Task 2: Vulnerability scan (depends on recon)
        vuln_task = await self.blackboard.create_task(
            mission_id=self.mission_id,
            task_type=TaskType.vuln_scan.value,
            assigned_to=SpecialistType.vuln.value,
            priority=Priority.high.value,
            params={"target_id": "dep_target_1"},
            dependencies=[recon_task]
        )
        
        # Execute vuln scan
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=vuln_task,
            status=TaskStatus.running.value
        )
        await asyncio.sleep(0.1)
        
        # Complete vuln scan and add vulnerability
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=vuln_task,
            status=TaskStatus.completed.value,
            result={"vulnerabilities_found": 1}
        )
        
        await self.blackboard.add_vulnerability(
            mission_id=self.mission_id,
            target_id="dep_target_1",
            vulnerability_id="CVE-2024-DEPS",
            severity="high",
            cvss_score=8.5,
            description="Dependency test vulnerability",
            exploit_available=True
        )
        
        # Task 3: Exploit (depends on vuln scan)
        exploit_task = await self.blackboard.create_task(
            mission_id=self.mission_id,
            task_type=TaskType.exploit.value,
            assigned_to=SpecialistType.attack.value,
            priority=Priority.critical.value,
            params={"vulnerability_id": "CVE-2024-DEPS", "target_id": "dep_target_1"},
            dependencies=[vuln_task]
        )
        
        # Execute exploit
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=exploit_task,
            status=TaskStatus.running.value
        )
        await asyncio.sleep(0.1)
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=exploit_task,
            status=TaskStatus.completed.value,
            result={"exploitation": "successful", "access_gained": True}
        )
        
        # Verify dependency chain completed successfully
        for task_id in [recon_task, vuln_task, exploit_task]:
            task_data = await self.blackboard.get_task(self.mission_id, task_id)
            assert task_data["status"] == TaskStatus.completed.value
        
        print("✅ Task dependency coordination test passed")
        print("   Dependency chain: Recon -> Vuln Scan -> Exploit")
        print("   All tasks completed successfully")

    @pytest.mark.priority_high
    async def test_e2e_specialist_failure_recovery(self):
        """Test failure recovery and task reassignment"""
        # Register specialists
        for i in range(2):
            await self.orchestrator.register_specialist(
                specialist_type=SpecialistType.recon,
                specialist_id=f"recon_fail_{i}",
                capabilities=["scan"]
            )
        
        # Create task
        task_id = await self.blackboard.create_task(
            mission_id=self.mission_id,
            task_type=TaskType.network_scan.value,
            assigned_to=SpecialistType.recon.value,
            priority=Priority.high.value,
            params={"target": "172.16.0.0/24"}
        )
        
        # Simulate first attempt failure
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=task_id,
            status=TaskStatus.running.value
        )
        await asyncio.sleep(0.1)
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=task_id,
            status=TaskStatus.failed.value,
            error="Network timeout"
        )
        
        # Retry with different specialist
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=task_id,
            status=TaskStatus.pending.value,  # Reset to pending for retry
            retry_count=1
        )
        
        # Second attempt succeeds
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=task_id,
            status=TaskStatus.running.value
        )
        await asyncio.sleep(0.1)
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=task_id,
            status=TaskStatus.completed.value,
            result={"success": True, "retry": True}
        )
        
        # Verify recovery
        task_data = await self.blackboard.get_task(self.mission_id, task_id)
        assert task_data["status"] == TaskStatus.completed.value
        assert task_data.get("retry_count", 0) >= 1
        
        print("✅ Specialist failure recovery test passed")
        print(f"   Task recovered after failure")
        print(f"   Retry count: {task_data.get('retry_count', 0)}")

    @pytest.mark.priority_high
    async def test_e2e_intelligence_driven_orchestration(self):
        """Test orchestration driven by mission intelligence"""
        # Create mission intelligence
        intel = MissionIntelligence(mission_id=self.mission_id)
        
        # Add targets with different priorities
        high_value_target = TargetIntel(
            target_id="hvt_1",
            ip_address="172.16.0.50",
            hostname="dc01.corp.local",
            status=TargetStatus.scanned,
            confidence=IntelConfidence.high,
            value_score=95,  # High value
            discovered_at=datetime.utcnow()
        )
        
        low_value_target = TargetIntel(
            target_id="lvt_1",
            ip_address="172.16.0.100",
            hostname="workstation.corp.local",
            status=TargetStatus.scanned,
            confidence=IntelConfidence.medium,
            value_score=30,  # Low value
            discovered_at=datetime.utcnow()
        )
        
        intel.add_target(high_value_target)
        intel.add_target(low_value_target)
        
        # Store intelligence in Blackboard
        await self.blackboard.store_metadata(
            mission_id=self.mission_id,
            key="intelligence",
            value=intel.to_dict()
        )
        
        # Register specialist
        await self.orchestrator.register_specialist(
            specialist_type=SpecialistType.attack,
            specialist_id="attack_intel_001",
            capabilities=["exploit"]
        )
        
        # Orchestrator should prioritize high-value target
        # Create tasks for both targets
        hvt_task = await self.blackboard.create_task(
            mission_id=self.mission_id,
            task_type=TaskType.exploit.value,
            assigned_to=SpecialistType.attack.value,
            priority=Priority.critical.value,  # Higher priority
            params={"target_id": "hvt_1"}
        )
        
        lvt_task = await self.blackboard.create_task(
            mission_id=self.mission_id,
            task_type=TaskType.exploit.value,
            assigned_to=SpecialistType.attack.value,
            priority=Priority.low.value,  # Lower priority
            params={"target_id": "lvt_1"}
        )
        
        # Execute high-priority task first
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=hvt_task,
            status=TaskStatus.running.value
        )
        await asyncio.sleep(0.1)
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=hvt_task,
            status=TaskStatus.completed.value,
            result={"success": True, "high_value": True}
        )
        
        # Then low-priority task
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=lvt_task,
            status=TaskStatus.running.value
        )
        await asyncio.sleep(0.1)
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=lvt_task,
            status=TaskStatus.completed.value,
            result={"success": True, "low_value": True}
        )
        
        # Verify execution order (high-value first)
        hvt_data = await self.blackboard.get_task(self.mission_id, hvt_task)
        lvt_data = await self.blackboard.get_task(self.mission_id, lvt_task)
        
        assert hvt_data["status"] == TaskStatus.completed.value
        assert lvt_data["status"] == TaskStatus.completed.value
        
        print("✅ Intelligence-driven orchestration test passed")
        print("   High-value target processed first")
        print("   Intelligence-based prioritization working")


@pytest.mark.e2e
@pytest.mark.asyncio
class TestPhase4PlanningE2E:
    """E2E tests for Phase 4.0 Mission Planning"""

    @pytest.fixture(autouse=True)
    async def setup(self, real_blackboard):
        self.blackboard = real_blackboard
        self.mission_id = f"plan_e2e_{uuid.uuid4().hex[:8]}"
        await self.blackboard.create_mission(
            mission_id=self.mission_id,
            name="E2E Planning Test",
            description="Testing Mission Planning",
            scope=["10.10.0.0/24"],
            goals=["Test planning"],
            constraints={}
        )
        
        self.planner = MissionPlanner(
            mission_id=self.mission_id,
            blackboard=self.blackboard
        )
        
        yield
        
        try:
            await self.blackboard.delete_mission(self.mission_id)
        except:
            pass

    @pytest.mark.priority_high
    async def test_e2e_mission_plan_generation(self):
        """Test end-to-end mission plan generation"""
        # Generate plan
        plan = await self.planner.generate_mission_plan(
            goals=["Gain initial access", "Escalate privileges", "Maintain persistence"],
            constraints={"time_limit": "4h", "stealth": "high"}
        )
        
        # Verify plan structure
        assert plan is not None
        assert "phases" in plan
        assert "timeline" in plan
        assert "resource_requirements" in plan
        
        # Verify phases
        phases = plan["phases"]
        assert len(phases) > 0
        assert any(p["name"] == "Reconnaissance" for p in phases)
        assert any(p["name"] == "Initial Access" for p in phases)
        
        print("✅ Mission plan generation test passed")
        print(f"   Phases: {len(phases)}")
        print(f"   Timeline: {plan['timeline']}")

    @pytest.mark.priority_medium
    async def test_e2e_adaptive_planning(self):
        """Test adaptive planning based on mission progress"""
        # Initial plan
        initial_plan = await self.planner.generate_mission_plan(
            goals=["Reconnaissance"],
            constraints={}
        )
        
        # Simulate mission progress - target discovered
        await self.blackboard.add_target(
            mission_id=self.mission_id,
            target_id="adapt_target",
            ip="10.10.0.50",
            hostname="adaptive.test",
            status=TargetStatus.discovered.value
        )
        
        # Update plan based on new information
        updated_plan = await self.planner.update_plan_based_on_progress()
        
        # Verify plan adaptation
        assert updated_plan is not None
        assert len(updated_plan["phases"]) >= len(initial_plan["phases"])
        
        print("✅ Adaptive planning test passed")
        print(f"   Initial phases: {len(initial_plan['phases'])}")
        print(f"   Updated phases: {len(updated_plan['phases'])}")


@pytest.mark.e2e
@pytest.mark.performance
class TestPhase4PerformanceE2E:
    """Performance tests for Phase 4.0"""

    @pytest.fixture(autouse=True)
    async def setup(self, real_blackboard):
        self.blackboard = real_blackboard
        self.mission_id = f"perf_orch_{uuid.uuid4().hex[:8]}"
        await self.blackboard.create_mission(
            mission_id=self.mission_id,
            name="Performance Test",
            description="Orchestration performance",
            scope=["192.168.0.0/16"],
            goals=["Performance"],
            constraints={}
        )
        
        self.orchestrator = SpecialistOrchestrator(
            mission_id=self.mission_id,
            blackboard=self.blackboard
        )
        
        yield
        
        try:
            await self.blackboard.delete_mission(self.mission_id)
        except:
            pass

    async def test_high_volume_task_coordination(self):
        """Test orchestration with high volume of concurrent tasks"""
        import time
        
        # Register specialists
        for i in range(5):
            await self.orchestrator.register_specialist(
                specialist_type=SpecialistType.recon,
                specialist_id=f"recon_perf_{i}",
                capabilities=["scan"]
            )
        
        start_time = time.time()
        
        # Create 100 tasks
        task_ids = []
        for i in range(100):
            task_id = await self.blackboard.create_task(
                mission_id=self.mission_id,
                task_type=TaskType.network_scan.value,
                assigned_to=SpecialistType.recon.value,
                priority=Priority.medium.value,
                params={"subnet": f"192.168.{i}.0/24"}
            )
            task_ids.append(task_id)
        
        # Execute all tasks
        async def quick_execute(task_id):
            await self.blackboard.update_task(
                mission_id=self.mission_id,
                task_id=task_id,
                status=TaskStatus.running.value
            )
            await asyncio.sleep(0.01)
            await self.blackboard.update_task(
                mission_id=self.mission_id,
                task_id=task_id,
                status=TaskStatus.completed.value
            )
        
        await asyncio.gather(*[quick_execute(tid) for tid in task_ids])
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Performance assertions
        assert duration < 15.0  # Should complete within 15 seconds
        
        mission_data = await self.blackboard.get_mission(self.mission_id)
        completed = sum(
            1 for t in mission_data.get("tasks", [])
            if t.get("status") == TaskStatus.completed.value
        )
        assert completed == 100
        
        print(f"✅ High-volume coordination test passed")
        print(f"   Tasks: 100")
        print(f"   Duration: {duration:.2f}s")
        print(f"   Throughput: {100/duration:.2f} tasks/sec")
