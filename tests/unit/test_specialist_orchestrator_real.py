# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - REAL SpecialistOrchestrator Tests (FIXED)
# NO MOCKS - Tests with real Blackboard, Intelligence, and Specialists
# Phase 4 Orchestration Testing: SpecialistOrchestrator
# Fixed to match actual API signatures and use real MissionIntelligence
# ═══════════════════════════════════════════════════════════════

import asyncio
import pytest
import time
from pathlib import Path
from uuid import uuid4
from datetime import datetime

from src.core.reasoning.specialist_orchestrator import (
    SpecialistOrchestrator,
    MissionPhase,
    CoordinationPattern,
    ExecutionStrategy,
    CoordinationTask,
    OrchestrationPlan,
    TaskDependency,
)
from src.core.reasoning.mission_intelligence import (
    MissionIntelligence,
    TargetIntel,
    VulnerabilityIntel,
    CredentialIntel,
    IntelConfidence,
)
from src.core.blackboard import Blackboard
from src.core.models import Mission, SpecialistType, TaskType, TaskStatus


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
async def real_blackboard():
    """Real Blackboard with Redis."""
    blackboard = Blackboard(redis_url="redis://localhost:6379/0")
    await blackboard.connect()
    
    if not await blackboard.health_check():
        pytest.skip("Redis not available")
    
    print(f"\n✅ Blackboard connected to Redis")
    
    yield blackboard
    
    await blackboard.disconnect()


@pytest.fixture
async def test_mission(real_blackboard):
    """Create a test mission."""
    mission_id = uuid4()
    mission = Mission(
        id=mission_id,
        name="Orchestration Test Mission",
        scope=["192.168.1.100", "192.168.1.101"],
        goals={"test_orchestration": "pending"}
    )
    
    await real_blackboard.create_mission(mission)
    
    print(f"✅ Test mission created: {mission_id}")
    
    yield str(mission_id)
    
    # Cleanup
    try:
        await real_blackboard.delete_mission(str(mission_id))
    except:
        pass


@pytest.fixture
def real_mission_intelligence():
    """Create REAL mission intelligence with actual data."""
    intel = MissionIntelligence(mission_id="test-mission")
    
    # Add real targets
    target1 = TargetIntel(
        target_id="192.168.1.100",
        ip="192.168.1.100",
        hostname="server1.local",
        os="Windows Server 2019",
        services=[
            {"name": "smb", "port": 445, "version": "SMBv3"},
            {"name": "rdp", "port": 3389}
        ],
        is_compromised=False,
        confidence=IntelConfidence.CONFIRMED,
        discovered_at=datetime.utcnow()
    )
    
    target2 = TargetIntel(
        target_id="192.168.1.101",
        ip="192.168.1.101",
        hostname="server2.local",
        os="Ubuntu 20.04",
        services=[
            {"name": "ssh", "port": 22},
            {"name": "http", "port": 80}
        ],
        is_compromised=False,
        confidence=IntelConfidence.CONFIRMED,
        discovered_at=datetime.utcnow()
    )
    
    intel.add_target(target1)
    intel.add_target(target2)
    
    # Add real vulnerabilities
    vuln1 = VulnerabilityIntel(
        vuln_id="vuln-001",
        target_id="192.168.1.100",
        name="Log4Shell RCE",
        description="Log4Shell RCE vulnerability",
        severity="critical",
        cvss_score=10.0,
        is_exploitable=True,
        exploit_available=True,
        confidence=IntelConfidence.CONFIRMED,
        discovered_at=datetime.utcnow()
    )
    
    vuln2 = VulnerabilityIntel(
        vuln_id="vuln-002",
        target_id="192.168.1.101",
        name="SSH weak ciphers",
        description="SSH configured with weak encryption ciphers",
        severity="high",
        cvss_score=7.5,
        is_exploitable=False,
        exploit_available=False,
        confidence=IntelConfidence.HIGH,
        discovered_at=datetime.utcnow()
    )
    
    intel.add_vulnerability(vuln1)
    intel.add_vulnerability(vuln2)
    
    # Add credentials
    cred1 = CredentialIntel(
        cred_id="cred-001",
        username="admin",
        password="Admin123!",
        credential_type="password",
        source_target="192.168.1.100",
        privilege_level="admin",
        is_valid=True,
        is_privileged=True,
        confidence=IntelConfidence.CONFIRMED,
        discovered_at=datetime.utcnow()
    )
    
    intel.add_credential(cred1)
    
    print(f"✅ Real intelligence created: {intel.total_targets} targets, "
          f"{intel.total_vulnerabilities} vulns, {intel.total_credentials} creds")
    
    return intel


@pytest.fixture
async def orchestrator(real_blackboard, test_mission, real_mission_intelligence):
    """Real SpecialistOrchestrator with real dependencies."""
    orchestrator = SpecialistOrchestrator(
        mission_id=test_mission,
        blackboard=real_blackboard,
        specialists={},  # Start with no specialists
        mission_intelligence=real_mission_intelligence
    )
    
    print(f"✅ SpecialistOrchestrator initialized")
    
    return orchestrator


# ═══════════════════════════════════════════════════════════════
# Test: Initialization
# ═══════════════════════════════════════════════════════════════

class TestRealOrchestratorInit:
    """Test Orchestrator initialization."""
    
    @pytest.mark.asyncio
    async def test_orchestrator_initializes(self, orchestrator):
        """Test orchestrator initializes with real dependencies."""
        assert orchestrator.mission_id is not None
        assert orchestrator.blackboard is not None
        assert orchestrator.mission_intelligence is not None
        
        # Check stats initialized
        stats = orchestrator.get_statistics()
        assert "plans_generated" in stats
        assert "plans_executed" in stats
        assert stats["plans_generated"] == 0
        assert stats["plans_executed"] == 0
        
        print("✅ Orchestrator initialized with all components")
    
    @pytest.mark.asyncio
    async def test_empty_specialists_at_start(self, orchestrator):
        """Test orchestrator starts with no specialists."""
        count = orchestrator.get_specialist_count()
        assert count == 0
        
        specialists = orchestrator.get_registered_specialists()
        assert len(specialists) == 0
        
        print("✅ Orchestrator starts empty")


# ═══════════════════════════════════════════════════════════════
# Test: Specialist Registration
# ═══════════════════════════════════════════════════════════════

class TestRealSpecialistRegistration:
    """Test dynamic specialist registration."""
    
    @pytest.mark.asyncio
    async def test_register_single_specialist(self, orchestrator):
        """Test registering a single specialist."""
        await orchestrator.register_specialist(
            specialist_type=SpecialistType.RECON,
            specialist_id="recon-001",
            capabilities=["nmap", "masscan"]
        )
        
        count = orchestrator.get_specialist_count()
        assert count == 1
        
        specialists = orchestrator.get_registered_specialists()
        assert SpecialistType.RECON in specialists
        
        print("✅ Single specialist registered")
    
    @pytest.mark.asyncio
    async def test_register_multiple_specialists(self, orchestrator):
        """Test registering multiple specialists."""
        await orchestrator.register_specialist(
            specialist_type=SpecialistType.RECON,
            specialist_id="recon-001",
            capabilities=["nmap"]
        )
        
        await orchestrator.register_specialist(
            specialist_type=SpecialistType.VULN,
            specialist_id="vuln-001",
            capabilities=["nuclei"]
        )
        
        await orchestrator.register_specialist(
            specialist_type=SpecialistType.ATTACK,
            specialist_id="attack-001",
            capabilities=["metasploit"]
        )
        
        count = orchestrator.get_specialist_count()
        assert count == 3
        
        specialists = orchestrator.get_registered_specialists()
        assert SpecialistType.RECON in specialists
        assert SpecialistType.VULN in specialists
        assert SpecialistType.ATTACK in specialists
        
        print(f"✅ {count} specialists registered")


# ═══════════════════════════════════════════════════════════════
# Test: Phase Determination
# ═══════════════════════════════════════════════════════════════

class TestRealPhaseDetermination:
    """Test mission phase determination based on real intelligence."""
    
    @pytest.mark.asyncio
    async def test_determine_reconnaissance_phase(self, orchestrator):
        """Test reconnaissance phase determination."""
        # Set intelligence: no targets discovered yet
        orchestrator.mission_intelligence.targets.clear()
        orchestrator.mission_intelligence.total_targets = 0
        orchestrator.mission_intelligence.compromised_targets = 0
        
        phase = await orchestrator.determine_current_phase()
        
        assert phase == MissionPhase.RECONNAISSANCE
        print(f"✅ Phase determined: {phase.value}")
    
    @pytest.mark.asyncio
    async def test_determine_vulnerability_assessment_phase(self, orchestrator):
        """Test vulnerability assessment phase determination."""
        # Have targets but no vulnerabilities
        orchestrator.mission_intelligence.vulnerabilities.clear()
        orchestrator.mission_intelligence.total_vulnerabilities = 0
        orchestrator.mission_intelligence.exploitable_vulnerabilities = 0
        
        phase = await orchestrator.determine_current_phase()
        
        assert phase == MissionPhase.VULNERABILITY_ASSESSMENT
        print(f"✅ Phase determined: {phase.value}")
    
    @pytest.mark.asyncio
    async def test_determine_initial_access_phase(self, orchestrator):
        """Test initial access phase determination."""
        # Have targets and vulns, but nothing compromised
        # (Already set up in fixture)
        
        phase = await orchestrator.determine_current_phase()
        
        assert phase == MissionPhase.INITIAL_ACCESS
        print(f"✅ Phase determined: {phase.value}")


# ═══════════════════════════════════════════════════════════════
# Test: Execution Plan Generation (REAL API)
# ═══════════════════════════════════════════════════════════════

class TestRealPlanGeneration:
    """Test execution plan generation with real API."""
    
    @pytest.mark.asyncio
    async def test_generate_reconnaissance_plan(self, orchestrator):
        """Test generating reconnaissance plan."""
        # Register recon specialist
        await orchestrator.register_specialist(
            specialist_type=SpecialistType.RECON,
            specialist_id="recon-001",
            capabilities=["nmap"]
        )
        
        # Clear targets to force recon phase
        orchestrator.mission_intelligence.targets.clear()
        
        # Generate plan (no targets parameter - uses intelligence)
        plan = await orchestrator.generate_execution_plan(
            phase=MissionPhase.RECONNAISSANCE,
            execution_strategy=ExecutionStrategy.BALANCED
        )
        
        assert plan is not None
        assert plan.phase == MissionPhase.RECONNAISSANCE
        assert len(plan.tasks) > 0
        assert plan.coordination_pattern in CoordinationPattern
        assert plan.execution_strategy == ExecutionStrategy.BALANCED
        
        # Check task types are correct
        task_types = [t.task_type for t in plan.tasks]
        assert TaskType.NETWORK_SCAN in task_types or TaskType.PORT_SCAN in task_types
        
        print(f"✅ Recon plan generated: {len(plan.tasks)} tasks")
        print(f"   - Pattern: {plan.coordination_pattern.value}")
        print(f"   - Strategy: {plan.execution_strategy.value}")
        print(f"   - Task types: {[t.value for t in task_types]}")
    
    @pytest.mark.asyncio
    async def test_generate_exploitation_plan(self, orchestrator):
        """Test generating exploitation plan with real vulnerabilities."""
        # Register attack specialist
        await orchestrator.register_specialist(
            specialist_type=SpecialistType.ATTACK,
            specialist_id="attack-001",
            capabilities=["metasploit"]
        )
        
        # Ensure we have targets and vulnerabilities (from fixture)
        assert orchestrator.mission_intelligence.total_targets > 0
        assert orchestrator.mission_intelligence.total_vulnerabilities > 0
        
        # Generate plan for initial access
        plan = await orchestrator.generate_execution_plan(
            phase=MissionPhase.INITIAL_ACCESS,
            execution_strategy=ExecutionStrategy.BALANCED
        )
        
        assert plan is not None
        assert plan.phase == MissionPhase.INITIAL_ACCESS
        assert len(plan.tasks) > 0
        
        # Check tasks target exploitable vulns
        exploit_tasks = [t for t in plan.tasks if t.task_type == TaskType.EXPLOIT]
        assert len(exploit_tasks) > 0
        
        print(f"✅ Exploitation plan generated: {len(plan.tasks)} tasks")
        print(f"   - Exploit tasks: {len(exploit_tasks)}")


# ═══════════════════════════════════════════════════════════════
# Test: Task Execution (Sequential)
# ═══════════════════════════════════════════════════════════════

class TestRealSequentialExecution:
    """Test sequential task execution."""
    
    @pytest.mark.asyncio
    async def test_execute_sequential_tasks(self, orchestrator):
        """Test sequential execution of tasks."""
        # Register specialist
        await orchestrator.register_specialist(
            specialist_type=SpecialistType.RECON,
            specialist_id="recon-001",
            capabilities=["nmap"]
        )
        
        # Create tasks with proper TaskType
        tasks = [
            CoordinationTask(
                task_id=str(uuid4()),
                specialist_type=SpecialistType.RECON,
                task_type=TaskType.NETWORK_SCAN,
                target_id="192.168.1.100",
                mission_id=orchestrator.mission_id,
                phase=MissionPhase.RECONNAISSANCE
            ),
            CoordinationTask(
                task_id=str(uuid4()),
                specialist_type=SpecialistType.RECON,
                task_type=TaskType.PORT_SCAN,
                target_id="192.168.1.101",
                mission_id=orchestrator.mission_id,
                phase=MissionPhase.RECONNAISSANCE
            )
        ]
        
        start = time.time()
        results = await orchestrator._execute_sequential(tasks)
        elapsed = (time.time() - start) * 1000
        
        assert len(results) == 2
        assert all(r.get("status") == "completed" for r in results)
        
        print(f"✅ Sequential execution: {len(results)} tasks in {elapsed:.2f} ms")


# ═══════════════════════════════════════════════════════════════
# Test: Task Execution (Parallel)
# ═══════════════════════════════════════════════════════════════

class TestRealParallelExecution:
    """Test parallel task execution."""
    
    @pytest.mark.asyncio
    async def test_execute_parallel_tasks(self, orchestrator):
        """Test parallel execution of tasks."""
        # Register specialist
        await orchestrator.register_specialist(
            specialist_type=SpecialistType.RECON,
            specialist_id="recon-001",
            capabilities=["nmap"]
        )
        
        # Create multiple tasks
        tasks = [
            CoordinationTask(
                task_id=str(uuid4()),
                specialist_type=SpecialistType.RECON,
                task_type=TaskType.NETWORK_SCAN,
                target_id=f"192.168.1.{100+i}",
                mission_id=orchestrator.mission_id,
                phase=MissionPhase.RECONNAISSANCE
            )
            for i in range(5)
        ]
        
        start = time.time()
        results = await orchestrator._execute_parallel(tasks, max_parallel=3)
        elapsed = (time.time() - start) * 1000
        
        assert len(results) == 5
        assert all(r.get("status") == "completed" for r in results)
        
        print(f"✅ Parallel execution: {len(results)} tasks in {elapsed:.2f} ms")


# ═══════════════════════════════════════════════════════════════
# Test: Task Dependencies
# ═══════════════════════════════════════════════════════════════

class TestRealTaskDependencies:
    """Test task dependency management."""
    
    @pytest.mark.asyncio
    async def test_topological_sort(self, orchestrator):
        """Test topological sorting of tasks with dependencies."""
        # Create tasks with dependencies
        task1 = CoordinationTask(
            task_id="task-1",
            specialist_type=SpecialistType.RECON,
            task_type=TaskType.NETWORK_SCAN,
            dependencies=[],
            mission_id=orchestrator.mission_id
        )
        
        task2 = CoordinationTask(
            task_id="task-2",
            specialist_type=SpecialistType.RECON,
            task_type=TaskType.PORT_SCAN,
            dependencies=["task-1"],  # Depends on task-1
            mission_id=orchestrator.mission_id
        )
        
        task3 = CoordinationTask(
            task_id="task-3",
            specialist_type=SpecialistType.RECON,
            task_type=TaskType.VULN_SCAN,
            dependencies=["task-2"],  # Depends on task-2
            mission_id=orchestrator.mission_id
        )
        
        tasks = [task3, task1, task2]  # Intentionally unsorted
        
        sorted_tasks = orchestrator._topological_sort(tasks)
        
        # Check order: task1 → task2 → task3
        assert sorted_tasks[0].task_id == "task-1"
        assert sorted_tasks[1].task_id == "task-2"
        assert sorted_tasks[2].task_id == "task-3"
        
        print(f"✅ Topological sort: {' → '.join(t.task_id for t in sorted_tasks)}")


# ═══════════════════════════════════════════════════════════════
# Test: Coordination Patterns (REAL API)
# ═══════════════════════════════════════════════════════════════

class TestRealCoordinationPatterns:
    """Test coordination pattern selection."""
    
    @pytest.mark.asyncio
    async def test_parallel_pattern_for_recon(self, orchestrator):
        """Test parallel pattern for reconnaissance."""
        await orchestrator.register_specialist(
            specialist_type=SpecialistType.RECON,
            specialist_id="recon-001",
            capabilities=["nmap"]
        )
        
        # Create tasks without dependencies
        tasks = [
            CoordinationTask(
                task_id=f"task-{i}",
                specialist_type=SpecialistType.RECON,
                task_type=TaskType.NETWORK_SCAN,
                mission_id=orchestrator.mission_id
            )
            for i in range(3)
        ]
        
        pattern = await orchestrator._select_coordination_pattern(
            phase=MissionPhase.RECONNAISSANCE,
            tasks=tasks
        )
        
        # Recon without dependencies should be parallel
        assert pattern == CoordinationPattern.PARALLEL
        
        print(f"✅ Pattern selected: {pattern.value}")
    
    @pytest.mark.asyncio
    async def test_pipeline_pattern_with_dependencies(self, orchestrator):
        """Test pipeline pattern when tasks have dependencies."""
        await orchestrator.register_specialist(
            specialist_type=SpecialistType.RECON,
            specialist_id="recon-001",
            capabilities=["nmap"]
        )
        
        # Create tasks WITH dependencies
        tasks = [
            CoordinationTask(
                task_id="task-1",
                specialist_type=SpecialistType.RECON,
                task_type=TaskType.NETWORK_SCAN,
                dependencies=[],
                mission_id=orchestrator.mission_id
            ),
            CoordinationTask(
                task_id="task-2",
                specialist_type=SpecialistType.RECON,
                task_type=TaskType.PORT_SCAN,
                dependencies=["task-1"],  # Has dependency
                mission_id=orchestrator.mission_id
            )
        ]
        
        pattern = await orchestrator._select_coordination_pattern(
            phase=MissionPhase.RECONNAISSANCE,
            tasks=tasks
        )
        
        # Tasks with dependencies should use pipeline
        assert pattern == CoordinationPattern.PIPELINE
        
        print(f"✅ Pattern selected: {pattern.value} (has dependencies)")


# ═══════════════════════════════════════════════════════════════
# Test: Execution Strategies
# ═══════════════════════════════════════════════════════════════

class TestRealExecutionStrategies:
    """Test execution strategy effects."""
    
    @pytest.mark.asyncio
    async def test_aggressive_strategy(self, orchestrator):
        """Test aggressive execution strategy."""
        await orchestrator.register_specialist(
            specialist_type=SpecialistType.RECON,
            specialist_id="recon-001",
            capabilities=["nmap"]
        )
        
        orchestrator.mission_intelligence.targets.clear()
        
        plan = await orchestrator.generate_execution_plan(
            phase=MissionPhase.RECONNAISSANCE,
            execution_strategy=ExecutionStrategy.AGGRESSIVE
        )
        
        assert plan.execution_strategy == ExecutionStrategy.AGGRESSIVE
        # Aggressive should have more parallel tasks
        assert plan.max_parallel_tasks >= 10
        
        print(f"✅ Aggressive strategy: max_parallel={plan.max_parallel_tasks}")
    
    @pytest.mark.asyncio
    async def test_stealthy_strategy(self, orchestrator):
        """Test stealthy execution strategy."""
        await orchestrator.register_specialist(
            specialist_type=SpecialistType.RECON,
            specialist_id="recon-001",
            capabilities=["nmap"]
        )
        
        orchestrator.mission_intelligence.targets.clear()
        
        plan = await orchestrator.generate_execution_plan(
            phase=MissionPhase.RECONNAISSANCE,
            execution_strategy=ExecutionStrategy.STEALTHY
        )
        
        assert plan.execution_strategy == ExecutionStrategy.STEALTHY
        # Stealthy should have fewer parallel tasks
        assert plan.max_parallel_tasks == 1
        
        print(f"✅ Stealthy strategy: max_parallel={plan.max_parallel_tasks}")


# ═══════════════════════════════════════════════════════════════
# Test: Full Plan Execution
# ═══════════════════════════════════════════════════════════════

class TestRealPlanExecution:
    """Test full execution plan."""
    
    @pytest.mark.asyncio
    async def test_execute_full_plan(self, orchestrator):
        """Test executing a full orchestration plan."""
        # Register specialists
        await orchestrator.register_specialist(
            specialist_type=SpecialistType.RECON,
            specialist_id="recon-001",
            capabilities=["nmap"]
        )
        
        # Clear targets to force recon phase
        orchestrator.mission_intelligence.targets.clear()
        
        # Generate plan
        plan = await orchestrator.generate_execution_plan(
            phase=MissionPhase.RECONNAISSANCE,
            execution_strategy=ExecutionStrategy.BALANCED
        )
        
        # Execute plan
        start = time.time()
        result = await orchestrator.execute_plan(plan)
        elapsed = (time.time() - start) * 1000
        
        assert result is not None
        assert result.total_tasks > 0
        assert result.completed_tasks <= result.total_tasks
        assert result.execution_time_seconds > 0
        
        print(f"✅ Plan executed:")
        print(f"   - Total tasks: {result.total_tasks}")
        print(f"   - Completed: {result.completed_tasks}")
        print(f"   - Failed: {result.failed_tasks}")
        print(f"   - Time: {elapsed:.2f} ms")


# ═══════════════════════════════════════════════════════════════
# Test: Phase-Specific Coordination
# ═══════════════════════════════════════════════════════════════

class TestRealPhaseCoordination:
    """Test phase-specific coordination methods."""
    
    @pytest.mark.asyncio
    async def test_coordinate_recon_phase(self, orchestrator):
        """Test reconnaissance phase coordination."""
        await orchestrator.register_specialist(
            specialist_type=SpecialistType.RECON,
            specialist_id="recon-001",
            capabilities=["nmap"]
        )
        
        # Clear targets for recon phase
        orchestrator.mission_intelligence.targets.clear()
        
        result = await orchestrator.coordinate_recon_phase()
        
        assert result is not None
        assert result.phase == MissionPhase.RECONNAISSANCE
        
        print(f"✅ Recon phase coordinated: {result.completed_tasks} tasks completed")


# ═══════════════════════════════════════════════════════════════
# Test: Performance & Statistics
# ═══════════════════════════════════════════════════════════════

class TestRealOrchestratorPerformance:
    """Test orchestrator performance."""
    
    @pytest.mark.asyncio
    async def test_plan_generation_performance(self, orchestrator):
        """Test plan generation performance."""
        await orchestrator.register_specialist(
            specialist_type=SpecialistType.RECON,
            specialist_id="recon-001",
            capabilities=["nmap"]
        )
        
        orchestrator.mission_intelligence.targets.clear()
        
        start = time.time()
        
        plan = await orchestrator.generate_execution_plan(
            phase=MissionPhase.RECONNAISSANCE,
            execution_strategy=ExecutionStrategy.BALANCED
        )
        
        elapsed = (time.time() - start) * 1000
        
        # Should be fast (< 100ms)
        assert elapsed < 100
        
        print(f"✅ Plan generation: {elapsed:.2f} ms")
    
    @pytest.mark.asyncio
    async def test_statistics_tracking(self, orchestrator):
        """Test statistics tracking."""
        stats_before = orchestrator.get_statistics()
        
        await orchestrator.register_specialist(
            specialist_type=SpecialistType.RECON,
            specialist_id="recon-001",
            capabilities=["nmap"]
        )
        
        orchestrator.mission_intelligence.targets.clear()
        
        plan = await orchestrator.generate_execution_plan(
            phase=MissionPhase.RECONNAISSANCE
        )
        
        stats_after = orchestrator.get_statistics()
        
        # Plans generated should increase
        assert stats_after["plans_generated"] > stats_before["plans_generated"]
        
        print(f"✅ Statistics tracked: {stats_after['plans_generated']} plans generated")


# ═══════════════════════════════════════════════════════════════
# Test: Orchestration Status
# ═══════════════════════════════════════════════════════════════

class TestRealOrchestratorStatus:
    """Test orchestrator status reporting."""
    
    @pytest.mark.asyncio
    async def test_get_orchestration_status(self, orchestrator):
        """Test getting orchestration status."""
        status = await orchestrator.get_orchestration_status()
        
        assert "mission_id" in status
        assert "statistics" in status
        assert status["mission_id"] == orchestrator.mission_id
        
        print(f"✅ Status retrieved: {status['active_tasks']} active tasks")


# ═══════════════════════════════════════════════════════════════
# Test: Real Intelligence Integration
# ═══════════════════════════════════════════════════════════════

class TestRealIntelligenceIntegration:
    """Test integration with real MissionIntelligence."""
    
    @pytest.mark.asyncio
    async def test_plan_uses_real_targets(self, orchestrator):
        """Test that plans use real target data."""
        await orchestrator.register_specialist(
            specialist_type=SpecialistType.ATTACK,
            specialist_id="attack-001",
            capabilities=["metasploit"]
        )
        
        # Ensure intelligence has targets and vulnerabilities
        assert orchestrator.mission_intelligence.total_targets == 2
        assert orchestrator.mission_intelligence.total_vulnerabilities == 2
        
        # Generate exploitation plan
        plan = await orchestrator.generate_execution_plan(
            phase=MissionPhase.INITIAL_ACCESS
        )
        
        # Check that tasks reference real targets
        exploit_tasks = [t for t in plan.tasks if t.task_type == TaskType.EXPLOIT]
        if len(exploit_tasks) > 0:
            # Should have target_id from intelligence
            assert any(t.target_id in ["192.168.1.100", "192.168.1.101"] 
                      for t in exploit_tasks)
        
        print(f"✅ Plan uses real intelligence: {len(exploit_tasks)} exploit tasks")
    
    @pytest.mark.asyncio
    async def test_phase_progression_with_intelligence(self, orchestrator):
        """Test phase progression based on intelligence state."""
        # Start with no targets
        orchestrator.mission_intelligence.targets.clear()
        orchestrator.mission_intelligence.total_targets = 0
        orchestrator.mission_intelligence.compromised_targets = 0
        
        phase1 = await orchestrator.determine_current_phase()
        assert phase1 == MissionPhase.RECONNAISSANCE
        
        # Add targets back
        target = TargetIntel(
            target_id="192.168.1.100",
            ip="192.168.1.100",
            hostname="test.local",
            confidence=IntelConfidence.CONFIRMED,
            discovered_at=datetime.utcnow()
        )
        orchestrator.mission_intelligence.add_target(target)
        
        # Clear vulnerabilities
        orchestrator.mission_intelligence.vulnerabilities.clear()
        orchestrator.mission_intelligence.total_vulnerabilities = 0
        orchestrator.mission_intelligence.exploitable_vulnerabilities = 0
        
        phase2 = await orchestrator.determine_current_phase()
        assert phase2 == MissionPhase.VULNERABILITY_ASSESSMENT
        
        # Add vulnerability back
        vuln = VulnerabilityIntel(
            vuln_id="vuln-001",
            target_id="192.168.1.100",
            name="Test Vulnerability",
            severity="high",
            is_exploitable=True,
            exploit_available=True,
            confidence=IntelConfidence.CONFIRMED,
            discovered_at=datetime.utcnow()
        )
        orchestrator.mission_intelligence.add_vulnerability(vuln)
        
        phase3 = await orchestrator.determine_current_phase()
        assert phase3 == MissionPhase.INITIAL_ACCESS
        
        print(f"✅ Phase progression: {phase1.value} → {phase2.value} → {phase3.value}")
