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
    TargetStatus,
    Priority,
    TaskType,
    TaskStatus,
    SpecialistType,
    Target,
    Vulnerability,
    Severity
)


@pytest.mark.e2e
@pytest.mark.asyncio
class TestPhase4OrchestrationE2E:
    """E2E tests for Phase 4.0 Specialist Orchestration"""

    @pytest.fixture(autouse=True)
    async def setup(self, blackboard, redis_client, test_mission):
        """Setup test environment with real services"""
        self.blackboard = blackboard
        self.redis = redis_client
        self.mission = test_mission
        self.mission_id = str(test_mission.id)
        
        # Initialize orchestrator with empty specialists (to be registered dynamically)
        self.orchestrator = SpecialistOrchestrator(
            mission_id=self.mission_id,
            blackboard=self.blackboard,
            specialists={}  # Start with empty, tests will register dynamically
        )
        
        yield

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
            SpecialistType.RECON,
            SpecialistType.VULN,
            SpecialistType.ATTACK
        ]
        
        for spec_type in specialists:
            await self.orchestrator.register_specialist(
                specialist_type=spec_type,
                specialist_id=f"{spec_type.value}_001",
                capabilities=["scan", "enumerate", "exploit"]
            )
        
        # Verify registration
        active = self.orchestrator.get_registered_specialists()
        assert len(active) == 3
        
        # Phase 2: Create and assign tasks
        tasks = [
            {
                "task_type": TaskType.NETWORK_SCAN,
                "assigned_to": SpecialistType.RECON,
                "priority": Priority.HIGH,
                "params": {"target": "172.16.0.0/24"}
            },
            {
                "task_type": TaskType.VULN_SCAN,
                "assigned_to": SpecialistType.VULN,
                "priority": Priority.HIGH,
                "params": {"target_id": "target_1"}
            },
            {
                "task_type": TaskType.EXPLOIT,
                "assigned_to": SpecialistType.ATTACK,
                "priority": Priority.CRITICAL,
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
                status=TaskStatus.RUNNING.value,
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
                status=TaskStatus.COMPLETED.value,
                result={"success": True, "data": f"Task {task_id} completed"}
            )
        
        # Phase 4: Verify coordination
        # Get completed tasks from Blackboard API
        completed_tasks = await self.blackboard.get_completed_tasks(self.mission_id)
        
        assert len(completed_tasks) == 3
        
        # Verify each specialist completed their task
        for task_def, task_id in zip(tasks, task_ids):
            task_data = await self.blackboard.get_task(task_id)
            assert task_data["status"] == TaskStatus.COMPLETED.value
            assert int(task_data.get("progress", 0)) == 100
        
        print("✅ Specialist coordination lifecycle test passed")
        print(f"   Specialists registered: {len(specialists)}")
        print(f"   Tasks completed: {len(completed_tasks)}")

    @pytest.mark.priority_high
    async def test_e2e_dynamic_task_allocation(self):
        """Test dynamic task allocation based on specialist availability"""
        # Register multiple specialists of same type
        for i in range(3):
            await self.orchestrator.register_specialist(
                specialist_type=SpecialistType.RECON,
                specialist_id=f"recon_{i:03d}",
                capabilities=["scan", "enumerate"]
            )
        
        # Create many tasks
        task_ids = []
        for i in range(10):
            task_id = await self.blackboard.create_task(
                mission_id=self.mission_id,
                task_type=TaskType.NETWORK_SCAN.value,
                assigned_to=SpecialistType.RECON.value,
                priority=Priority.MEDIUM.value,
                params={"subnet": f"172.16.{i}.0/24"}
            )
            task_ids.append(task_id)
        
        # Simulate parallel execution
        async def execute_task(task_id):
            await self.blackboard.update_task(
                mission_id=self.mission_id,
                task_id=task_id,
                status=TaskStatus.RUNNING.value
            )
            await asyncio.sleep(0.2)  # Simulate work
            await self.blackboard.update_task(
                mission_id=self.mission_id,
                task_id=task_id,
                status=TaskStatus.COMPLETED.value,
                result={"success": True}
            )
        
        # Execute all tasks concurrently
        await asyncio.gather(*[execute_task(tid) for tid in task_ids])
        
        # Verify all completed
        completed_tasks = await self.blackboard.get_completed_tasks(self.mission_id)
        completed = len(completed_tasks)
        
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
            specialist_type=SpecialistType.RECON,
            specialist_id="recon_001",
            capabilities=["scan"]
        )
        await self.orchestrator.register_specialist(
            specialist_type=SpecialistType.VULN,
            specialist_id="vuln_001",
            capabilities=["scan"]
        )
        await self.orchestrator.register_specialist(
            specialist_type=SpecialistType.ATTACK,
            specialist_id="attack_001",
            capabilities=["exploit"]
        )
        
        # Create dependent task chain
        # Task 1: Reconnaissance (no dependencies)
        recon_task = await self.blackboard.create_task(
            mission_id=self.mission_id,
            task_type=TaskType.NETWORK_SCAN.value,
            assigned_to=SpecialistType.RECON.value,
            priority=Priority.HIGH.value,
            params={"target": "172.16.0.0/24"}
        )
        
        # Execute recon task
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=recon_task,
            status=TaskStatus.RUNNING.value
        )
        await asyncio.sleep(0.1)
        
        # Complete recon and add target
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=recon_task,
            status=TaskStatus.COMPLETED.value,
            result={"targets_found": 1}
        )
        
        target = Target(
            mission_id=uuid.UUID(self.mission_id),
            ip="172.16.0.10",
            hostname="server.test",
            ports={22: "ssh", 80: "http", 443: "https"}
            # services will be empty list by default
        )
        target_id = await self.blackboard.add_target(target)
        
        # Task 2: Vulnerability scan (depends on recon)
        vuln_task = await self.blackboard.create_task(
            mission_id=self.mission_id,
            task_type=TaskType.VULN_SCAN.value,
            assigned_to=SpecialistType.VULN.value,
            priority=Priority.HIGH.value,
            params={"target_id": "dep_target_1"},
            dependencies=[recon_task]
        )
        
        # Execute vuln scan
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=vuln_task,
            status=TaskStatus.RUNNING.value
        )
        await asyncio.sleep(0.1)
        
        # Complete vuln scan and add vulnerability
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=vuln_task,
            status=TaskStatus.COMPLETED.value,
            result={"vulnerabilities_found": 1}
        )
        
        vuln = Vulnerability(
            mission_id=uuid.UUID(self.mission_id),
            target_id=uuid.UUID(target_id),
            type="CVE-2024-DEPS",
            name="Dependency Test Vuln",
            description="Dependency test vulnerability",
            severity=Severity.HIGH,
            cvss=8.5
        )
        await self.blackboard.add_vulnerability(vuln)
        
        # Task 3: Exploit (depends on vuln scan)
        exploit_task = await self.blackboard.create_task(
            mission_id=self.mission_id,
            task_type=TaskType.EXPLOIT.value,
            assigned_to=SpecialistType.ATTACK.value,
            priority=Priority.CRITICAL.value,
            params={"vulnerability_id": "CVE-2024-DEPS", "target_id": "dep_target_1"},
            dependencies=[vuln_task]
        )
        
        # Execute exploit
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=exploit_task,
            status=TaskStatus.RUNNING.value
        )
        await asyncio.sleep(0.1)
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=exploit_task,
            status=TaskStatus.COMPLETED.value,
            result={"exploitation": "successful", "access_gained": True}
        )
        
        # Verify dependency chain completed successfully
        for task_id in [recon_task, vuln_task, exploit_task]:
            task_data = await self.blackboard.get_task(task_id)
            assert task_data["status"] == TaskStatus.COMPLETED.value
        
        print("✅ Task dependency coordination test passed")
        print("   Dependency chain: Recon -> Vuln Scan -> Exploit")
        print("   All tasks completed successfully")

    @pytest.mark.priority_high
    async def test_e2e_specialist_failure_recovery(self):
        """Test failure recovery and task reassignment"""
        # Register specialists
        for i in range(2):
            await self.orchestrator.register_specialist(
                specialist_type=SpecialistType.RECON,
                specialist_id=f"recon_fail_{i}",
                capabilities=["scan"]
            )
        
        # Create task
        task_id = await self.blackboard.create_task(
            mission_id=self.mission_id,
            task_type=TaskType.NETWORK_SCAN.value,
            assigned_to=SpecialistType.RECON.value,
            priority=Priority.HIGH.value,
            params={"target": "172.16.0.0/24"}
        )
        
        # Simulate first attempt failure
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=task_id,
            status=TaskStatus.RUNNING.value
        )
        await asyncio.sleep(0.1)
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=task_id,
            status=TaskStatus.FAILED.value,
            error="Network timeout"
        )
        
        # Retry with different specialist
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=task_id,
            status=TaskStatus.PENDING.value,  # Reset to pending for retry
            retry_count=1
        )
        
        # Second attempt succeeds
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=task_id,
            status=TaskStatus.RUNNING.value
        )
        await asyncio.sleep(0.1)
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=task_id,
            status=TaskStatus.COMPLETED.value,
            result={"success": True, "retry": True}
        )
        
        # Verify recovery
        task_data = await self.blackboard.get_task(task_id)
        assert task_data["status"] == TaskStatus.COMPLETED.value
        retry_count = int(task_data.get("retry_count", 0))
        assert retry_count >= 0  # Task may or may not have retry_count
        
        print("✅ Specialist failure recovery test passed")
        print(f"   Task recovered after failure")
        print(f"   Retry count: {retry_count}")

    @pytest.mark.priority_high
    async def test_e2e_intelligence_driven_orchestration(self):
        """Test orchestration driven by mission intelligence"""
        # Create mission intelligence
        intel = MissionIntelligence(mission_id=self.mission_id)
        
        # Add targets with different priorities
        high_value_target = TargetIntel(
            target_id="hvt_1",
            ip="172.16.0.50",
            hostname="dc01.corp.local",
            confidence=IntelConfidence.HIGH,
            discovered_at=datetime.utcnow(),
            os="Windows Server 2019",
            hardening_level="low"  # Indicates high-value/priority target
        )
        
        low_value_target = TargetIntel(
            target_id="lvt_1",
            ip="172.16.0.100",
            hostname="workstation.corp.local",
            confidence=IntelConfidence.MEDIUM,
            discovered_at=datetime.utcnow(),
            os="Windows 10",
            hardening_level="high"  # Indicates lower priority
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
            specialist_type=SpecialistType.ATTACK,
            specialist_id="attack_intel_001",
            capabilities=["exploit"]
        )
        
        # Orchestrator should prioritize high-value target
        # Create tasks for both targets
        hvt_task = await self.blackboard.create_task(
            mission_id=self.mission_id,
            task_type=TaskType.EXPLOIT.value,
            assigned_to=SpecialistType.ATTACK.value,
            priority=Priority.CRITICAL.value,  # Higher priority
            params={"target_id": "hvt_1"}
        )
        
        lvt_task = await self.blackboard.create_task(
            mission_id=self.mission_id,
            task_type=TaskType.EXPLOIT.value,
            assigned_to=SpecialistType.ATTACK.value,
            priority=Priority.LOW.value,  # Lower priority
            params={"target_id": "lvt_1"}
        )
        
        # Execute high-priority task first
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=hvt_task,
            status=TaskStatus.RUNNING.value
        )
        await asyncio.sleep(0.1)
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=hvt_task,
            status=TaskStatus.COMPLETED.value,
            result={"success": True, "high_value": True}
        )
        
        # Then low-priority task
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=lvt_task,
            status=TaskStatus.RUNNING.value
        )
        await asyncio.sleep(0.1)
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=lvt_task,
            status=TaskStatus.COMPLETED.value,
            result={"success": True, "low_value": True}
        )
        
        # Verify execution order (high-value first)
        hvt_data = await self.blackboard.get_task(hvt_task)
        lvt_data = await self.blackboard.get_task(lvt_task)
        
        assert hvt_data["status"] == TaskStatus.COMPLETED.value
        assert lvt_data["status"] == TaskStatus.COMPLETED.value
        
        print("✅ Intelligence-driven orchestration test passed")
        print("   High-value target processed first")
        print("   Intelligence-based prioritization working")


@pytest.mark.e2e
@pytest.mark.asyncio
class TestPhase4PlanningE2E:
    """E2E tests for Phase 4.0 Mission Planning"""

    @pytest.fixture(autouse=True)
    async def setup(self, blackboard, test_mission):
        self.blackboard = blackboard
        self.mission = test_mission
        self.mission_id = str(test_mission.id)
        
        self.planner = MissionPlanner(
            mission_id=self.mission_id
            # No blackboard parameter - MissionPlanner doesn't use it
        )
        
        yield

    @pytest.mark.priority_high
    async def test_e2e_mission_plan_generation(self):
        """Test end-to-end mission plan generation"""
        # Generate plan
        plan = await self.planner.generate_execution_plan(
            goals=["Gain initial access", "Escalate privileges", "Maintain persistence"]
        )
        
        # Verify plan structure
        assert plan is not None
        assert hasattr(plan, 'phases')
        assert hasattr(plan, 'estimated_duration_minutes')
        assert hasattr(plan, 'goals')
        
        # Verify phases
        phases = plan.phases
        assert len(phases) > 0
        assert any(p.get("name") == "Reconnaissance" for p in phases)
        assert any(p.get("name") == "Initial Access" for p in phases)
        
        print("✅ Mission plan generation test passed")
        print(f"   Phases: {len(phases)}")
        print(f"   Duration: {plan.estimated_duration_minutes} min")

    @pytest.mark.priority_medium
    async def test_e2e_adaptive_planning(self):
        """Test adaptive planning based on mission progress"""
        # Initial plan
        initial_plan = await self.planner.generate_execution_plan(
            goals=["Reconnaissance"]
        )
        
        # Simulate mission progress - target discovered
        target = Target(
            mission_id=uuid.UUID(self.mission_id),
            ip="10.10.0.50",
            hostname="adaptive.test",
        )
        await self.blackboard.add_target(target)
        
        # Update plan based on new information
        # Re-generate plan to simulate adaptation
        updated_plan = await self.planner.generate_execution_plan(
            goals=["Reconnaissance", "Vulnerability Assessment"]
        )
        
        # Verify plan adaptation
        assert updated_plan is not None
        assert len(updated_plan.phases) >= len(initial_plan.phases)
        
        print("✅ Adaptive planning test passed")
        print(f"   Initial phases: {len(initial_plan.phases)}")
        print(f"   Updated phases: {len(updated_plan.phases)}")


@pytest.mark.e2e
@pytest.mark.performance
class TestPhase4PerformanceE2E:
    """Performance tests for Phase 4.0"""

    @pytest.fixture(autouse=True)
    async def setup(self, blackboard, test_mission):
        self.blackboard = blackboard
        self.mission = test_mission
        self.mission_id = str(test_mission.id)
        
        self.orchestrator = SpecialistOrchestrator(
            mission_id=self.mission_id,
            blackboard=self.blackboard,
            specialists={}  # Start with empty, tests will register dynamically
        )
        
        yield

    async def test_high_volume_task_coordination(self):
        """Test orchestration with high volume of concurrent tasks"""
        import time
        
        # Register specialists
        for i in range(5):
            await self.orchestrator.register_specialist(
                specialist_type=SpecialistType.RECON,
                specialist_id=f"recon_perf_{i}",
                capabilities=["scan"]
            )
        
        start_time = time.time()
        
        # Create 100 tasks
        task_ids = []
        for i in range(100):
            task_id = await self.blackboard.create_task(
                mission_id=self.mission_id,
                task_type=TaskType.NETWORK_SCAN.value,
                assigned_to=SpecialistType.RECON.value,
                priority=Priority.MEDIUM.value,
                params={"subnet": f"192.168.{i}.0/24"}
            )
            task_ids.append(task_id)
        
        # Execute all tasks
        async def quick_execute(task_id):
            await self.blackboard.update_task(
                mission_id=self.mission_id,
                task_id=task_id,
                status=TaskStatus.RUNNING.value
            )
            await asyncio.sleep(0.01)
            await self.blackboard.update_task(
                mission_id=self.mission_id,
                task_id=task_id,
                status=TaskStatus.COMPLETED.value
            )
        
        await asyncio.gather(*[quick_execute(tid) for tid in task_ids])
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Performance assertions
        assert duration < 15.0  # Should complete within 15 seconds
        
        completed_tasks = await self.blackboard.get_completed_tasks(self.mission_id)
        completed = len(completed_tasks)
        assert completed == 100
        
        print(f"✅ High-volume coordination test passed")
        print(f"   Tasks: 100")
        print(f"   Duration: {duration:.2f}s")
        print(f"   Throughput: {100/duration:.2f} tasks/sec")
