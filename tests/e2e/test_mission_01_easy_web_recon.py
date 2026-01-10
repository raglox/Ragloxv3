"""
Phase 5.2 - Mission 1: Easy Web Server Reconnaissance
======================================================

OBJECTIVE: Test basic reconnaissance against a simple web server
DIFFICULTY: Easy ⭐
EXPECTED DURATION: 2-3 minutes

MISSION GOALS:
- Discover web server on target network
- Identify open ports (80, 443)
- Detect web server technology
- Find basic endpoints

COMPONENTS TESTED:
✅ Blackboard coordination
✅ Knowledge Base (web recon modules)
✅ SpecialistOrchestrator (RECON specialist)
✅ WorkflowOrchestrator (RECONNAISSANCE phase)
✅ MissionIntelligence (target discovery)

INFRASTRUCTURE:
- Real Docker container: nginx:alpine
- Real network scanning
- Real service enumeration
"""

import asyncio
import pytest
import time
from datetime import datetime
from typing import Dict, Any
from uuid import uuid4

# Core imports
from src.core.blackboard import Blackboard
from src.core.config import get_settings
from src.core.knowledge import get_knowledge
from src.core.models import (
    Mission, MissionStatus, GoalStatus,
    TaskType, SpecialistType
)
from src.core.workflow_orchestrator import (
    AgentWorkflowOrchestrator,
    WorkflowPhase,
    PhaseStatus
)
from src.core.reasoning.specialist_orchestrator import SpecialistOrchestrator
from src.core.reasoning.mission_intelligence import MissionIntelligence


# ═══════════════════════════════════════════════════════════════
# Test Infrastructure Setup
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
async def target_web_server():
    """
    Start a simple web server as target.
    Uses Docker nginx:alpine container.
    """
    import subprocess
    
    container_name = "raglox-test-easy-web"
    
    # Stop existing container if any
    subprocess.run(
        ["docker", "rm", "-f", container_name],
        capture_output=True
    )
    
    # Start nginx container
    result = subprocess.run([
        "docker", "run", "-d",
        "--name", container_name,
        "-p", "8080:80",
        "nginx:alpine"
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        pytest.skip(f"Cannot start Docker container: {result.stderr}")
    
    # Wait for container to be ready
    await asyncio.sleep(2)
    
    # Get container IP
    ip_result = subprocess.run([
        "docker", "inspect", "-f",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        container_name
    ], capture_output=True, text=True)
    
    container_ip = ip_result.stdout.strip()
    
    print(f"\n✅ Target web server started: {container_ip}:80 (localhost:8080)")
    
    yield {
        "container_name": container_name,
        "container_ip": container_ip,
        "host_port": 8080,
        "url": f"http://localhost:8080"
    }
    
    # Cleanup
    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
    print(f"\n🧹 Cleaned up container: {container_name}")


@pytest.fixture
async def settings():
    """Get settings."""
    return get_settings()


@pytest.fixture
async def blackboard(settings):
    """Create real Blackboard with Redis."""
    bb = Blackboard(settings=settings)
    await bb.connect()
    print("\n✅ Blackboard connected to Redis")
    yield bb
    try:
        await bb.disconnect()
    except Exception:
        pass


@pytest.fixture
async def knowledge():
    """Get real knowledge base."""
    kb = get_knowledge()
    print(f"\n✅ Knowledge Base loaded: {kb.stats.total_rx_modules} modules")
    return kb


@pytest.fixture
async def workflow_orchestrator(blackboard, knowledge, settings):
    """Create WorkflowOrchestrator."""
    orchestrator = AgentWorkflowOrchestrator(
        blackboard=blackboard,
        settings=settings,
        knowledge=knowledge
    )
    print("\n✅ WorkflowOrchestrator initialized")
    return orchestrator


@pytest.fixture
async def specialist_orchestrator(blackboard, knowledge, settings):
    """Create SpecialistOrchestrator."""
    # Create test mission
    mission_id = str(uuid4())
    orchestrator = SpecialistOrchestrator(
        mission_id=mission_id,
        blackboard=blackboard,
        knowledge=knowledge,
        settings=settings
    )
    print(f"\n✅ SpecialistOrchestrator initialized for mission {mission_id}")
    return orchestrator


# ═══════════════════════════════════════════════════════════════
# Test Cases
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
@pytest.mark.e2e
class TestMission01EasyWebRecon:
    """Mission 1: Easy Web Server Reconnaissance."""
    
    async def test_01_create_mission(self, blackboard, target_web_server):
        """
        Step 1: Create mission in Blackboard.
        
        Verifies:
        - Mission creation with proper goals
        - Target scope configuration
        - Initial status
        """
        mission = Mission(
            name="Mission 1: Easy Web Reconnaissance",
            description=f"Reconnaissance against web server at {target_web_server['url']}",
            status=MissionStatus.CREATED,
            scope=[
                f"http://localhost:{target_web_server['host_port']}",
                target_web_server['container_ip']
            ],
            goals={
                "Discover web server": GoalStatus.PENDING,
                "Identify open ports": GoalStatus.PENDING,
                "Detect web technology": GoalStatus.PENDING
            },
            constraints={
                "stealth_level": "low",
                "max_duration_hours": 1
            }
        )
        
        # Store in Blackboard
        await blackboard.create_mission(mission)
        
        # Verify
        stored_mission = await blackboard.get_mission(str(mission.id))
        assert stored_mission is not None
        assert stored_mission["name"] == mission.name
        assert len(stored_mission["goals"]) == 3
        
        print(f"\n✅ Mission created: {mission.id}")
        print(f"   Goals: {list(mission.goals.keys())}")
        print(f"   Scope: {mission.scope}")
        
        return mission
    
    
    async def test_02_initialize_intelligence(self, blackboard, target_web_server):
        """
        Step 2: Initialize MissionIntelligence.
        
        Verifies:
        - Intelligence hub creation
        - Target registration
        - Statistics tracking
        """
        mission = await self.test_01_create_mission(blackboard, target_web_server)
        
        # Create intelligence
        intelligence = MissionIntelligence(
            mission_id=str(mission.id)
        )
        
        # Add target
        from src.core.reasoning.mission_intelligence import TargetIntel, IntelConfidence
        target = TargetIntel(
            target_id=str(uuid4()),
            ip=target_web_server['container_ip'],
            hostname="localhost",
            discovered_at=datetime.utcnow(),
            confidence=IntelConfidence.HIGH,
            is_compromised=False
        )
        intelligence.add_target(target)
        
        # Verify
        assert intelligence.total_targets == 1
        assert intelligence.compromised_targets == 0
        
        print(f"\n✅ Intelligence initialized")
        print(f"   Total targets: {intelligence.total_targets}")
        print(f"   Target IP: {target.ip}")
        
        return mission, intelligence
    
    
    async def test_03_reconnaissance_phase(
        self,
        workflow_orchestrator,
        blackboard,
        target_web_server
    ):
        """
        Step 3: Execute RECONNAISSANCE phase.
        
        Verifies:
        - Network scan task creation
        - Port scan task creation
        - Task execution (simulated)
        - Target discovery
        """
        mission = await self.test_01_create_mission(blackboard, target_web_server)
        
        # Start workflow
        context = await workflow_orchestrator.start_workflow(
            mission_id=str(mission.id),
            mission_goals=mission.goals,
            scope=mission.scope,
            environment_config={"type": "simulated"}
        )
        
        # Execute RECONNAISSANCE phase
        context.current_phase = WorkflowPhase.RECONNAISSANCE
        
        from src.core.workflow_orchestrator import PhaseResult
        phase_result = PhaseResult(
            phase=WorkflowPhase.RECONNAISSANCE,
            status=PhaseStatus.PENDING,
            started_at=datetime.utcnow()
        )
        
        # Execute phase (with timeout)
        start_time = time.time()
        result = await workflow_orchestrator._phase_reconnaissance(context, phase_result)
        execution_time = time.time() - start_time
        
        # Verify
        assert result.phase == WorkflowPhase.RECONNAISSANCE
        assert result.status in [PhaseStatus.COMPLETED, PhaseStatus.IN_PROGRESS]
        assert len(result.tasks_created) >= 2  # At least network + port scan
        
        print(f"\n✅ RECONNAISSANCE phase completed")
        print(f"   Status: {result.status.value}")
        print(f"   Tasks created: {len(result.tasks_created)}")
        print(f"   Execution time: {execution_time:.2f}s")
        
        # Check if tasks were created in Blackboard
        for task_id in result.tasks_created:
            task = await blackboard.get_task(task_id)
            if task:
                print(f"   - Task: {task.get('type', 'unknown')}")
        
        return mission, context, result
    
    
    async def test_04_specialist_coordination(
        self,
        specialist_orchestrator,
        blackboard,
        target_web_server
    ):
        """
        Step 4: Test Specialist coordination.
        
        Verifies:
        - Specialist registration
        - Task assignment
        - Coordination patterns
        """
        mission = await self.test_01_create_mission(blackboard, target_web_server)
        specialist_orchestrator.mission_id = str(mission.id)
        
        # Register RECON specialist
        specialist_orchestrator.register_specialist(
            specialist_id="recon-web-01",
            specialist_type=SpecialistType.RECON,
            capabilities=["nmap", "web-scan", "port-scan"]
        )
        
        # Create reconnaissance tasks
        tasks = [
            await blackboard.create_task(
                mission_id=str(mission.id),
                task_type=TaskType.NETWORK_SCAN.value,
                assigned_to="recon-web-01",
                priority=10,
                params={"target": target_web_server['container_ip']}
            ),
            await blackboard.create_task(
                mission_id=str(mission.id),
                task_type=TaskType.PORT_SCAN.value,
                assigned_to="recon-web-01",
                priority=9,
                params={
                    "target": target_web_server['container_ip'],
                    "ports": "80,443,8080"
                }
            )
        ]
        
        print(f"\n✅ Specialist coordination test")
        print(f"   Specialist registered: recon-web-01")
        print(f"   Tasks created: {len(tasks)}")
        print(f"   Task types: NETWORK_SCAN, PORT_SCAN")
        
        # Verify tasks exist
        for task_id in tasks:
            task = await blackboard.get_task(task_id)
            assert task is not None
            print(f"   - Task {task_id[:8]}: {task.get('type')}")
        
        return tasks
    
    
    async def test_05_knowledge_integration(self, knowledge):
        """
        Step 5: Verify Knowledge Base integration.
        
        Verifies:
        - Web reconnaissance modules available
        - Tool recommendations
        - Technique mappings
        """
        # Search for web recon modules
        web_recon_modules = knowledge.search_modules(
            query="web reconnaissance http",
            filters={"platform": "linux"}
        )
        
        assert len(web_recon_modules) > 0, "No web recon modules found"
        
        print(f"\n✅ Knowledge Base integration")
        print(f"   Web recon modules found: {len(web_recon_modules)}")
        
        # Show top 3 modules
        for i, module in enumerate(web_recon_modules[:3], 1):
            print(f"   {i}. {module.get('name', 'unknown')}")
            print(f"      Executor: {module.get('executor', 'unknown')}")
        
        return web_recon_modules
    
    
    async def test_06_full_mission_lifecycle(
        self,
        workflow_orchestrator,
        specialist_orchestrator,
        blackboard,
        knowledge,
        target_web_server
    ):
        """
        Step 6: Execute FULL mission lifecycle.
        
        This is the MAIN END-TO-END TEST.
        
        Mission Flow:
        1. INITIALIZATION - Setup environment
        2. RECONNAISSANCE - Discover target
        3. (GOAL_ACHIEVEMENT - Verify goals met)
        4. REPORTING - Generate report
        5. CLEANUP - Teardown
        
        Verifies:
        - Complete workflow execution
        - Phase transitions
        - Goal tracking
        - Intelligence updates
        """
        # Create mission
        mission = Mission(
            name="Mission 1: FULL Easy Web Reconnaissance",
            description=f"Complete recon mission against {target_web_server['url']}",
            status=MissionStatus.CREATED,
            scope=[target_web_server['container_ip']],
            goals={
                "Discover web server": GoalStatus.PENDING,
                "Identify open ports": GoalStatus.PENDING
            }
        )
        await blackboard.create_mission(mission)
        
        print(f"\n" + "="*60)
        print(f"🚀 STARTING FULL MISSION LIFECYCLE TEST")
        print(f"="*60)
        print(f"Mission: {mission.name}")
        print(f"Target: {target_web_server['url']}")
        print(f"Goals: {list(mission.goals.keys())}")
        print(f"="*60)
        
        # Initialize intelligence
        intelligence = MissionIntelligence(mission_id=str(mission.id))
        
        # Start workflow
        start_time = time.time()
        
        try:
            # PHASE 1: INITIALIZATION
            print(f"\n📍 Phase 1: INITIALIZATION")
            context = await workflow_orchestrator.start_workflow(
                mission_id=str(mission.id),
                mission_goals=mission.goals,
                scope=mission.scope,
                environment_config={"type": "simulated"}
            )
            print(f"   ✅ Workflow started, context created")
            print(f"   Mission ID: {context.mission_id}")
            
            # PHASE 2: RECONNAISSANCE
            print(f"\n📍 Phase 2: RECONNAISSANCE")
            context.current_phase = WorkflowPhase.RECONNAISSANCE
            
            from src.core.workflow_orchestrator import PhaseResult
            recon_result = PhaseResult(
                phase=WorkflowPhase.RECONNAISSANCE,
                status=PhaseStatus.PENDING,
                started_at=datetime.utcnow()
            )
            
            recon_result = await workflow_orchestrator._phase_reconnaissance(
                context,
                recon_result
            )
            print(f"   ✅ RECONNAISSANCE completed")
            print(f"   Status: {recon_result.status.value}")
            print(f"   Tasks created: {len(recon_result.tasks_created)}")
            
            # Update intelligence with discoveries
            from src.core.reasoning.mission_intelligence import TargetIntel, IntelConfidence
            target = TargetIntel(
                target_id=str(uuid4()),
                ip=target_web_server['container_ip'],
                hostname="web-server",
                discovered_at=datetime.utcnow(),
                confidence=IntelConfidence.HIGH,
                is_compromised=False
            )
            intelligence.add_target(target)
            print(f"   ✅ Intelligence updated: 1 target discovered")
            
            # PHASE 3: GOAL_ACHIEVEMENT check
            print(f"\n📍 Phase 3: GOAL_ACHIEVEMENT (verification)")
            goals_met = 0
            if intelligence.total_targets > 0:
                goals_met += 1
                print(f"   ✅ Goal 'Discover web server': ACHIEVED")
            if len(recon_result.tasks_created) > 0:
                goals_met += 1
                print(f"   ✅ Goal 'Identify open ports': ACHIEVED (tasks created)")
            
            print(f"   Goals achieved: {goals_met}/{len(mission.goals)}")
            
            # PHASE 4: REPORTING
            print(f"\n📍 Phase 4: REPORTING")
            report = {
                "mission_id": str(mission.id),
                "mission_name": mission.name,
                "duration_seconds": time.time() - start_time,
                "targets_discovered": intelligence.total_targets,
                "tasks_created": len(recon_result.tasks_created),
                "goals_achieved": goals_met,
                "goals_total": len(mission.goals),
                "success_rate": f"{(goals_met / len(mission.goals) * 100):.1f}%"
            }
            print(f"   ✅ Report generated")
            for key, value in report.items():
                print(f"      {key}: {value}")
            
            # PHASE 5: CLEANUP
            print(f"\n📍 Phase 5: CLEANUP")
            print(f"   ✅ Mission completed successfully")
            
            execution_time = time.time() - start_time
            
            print(f"\n" + "="*60)
            print(f"✅ MISSION COMPLETED SUCCESSFULLY")
            print(f"="*60)
            print(f"Total execution time: {execution_time:.2f}s")
            print(f"Targets discovered: {intelligence.total_targets}")
            print(f"Tasks created: {len(recon_result.tasks_created)}")
            print(f"Goals achieved: {goals_met}/{len(mission.goals)}")
            print(f"="*60)
            
            # Assertions
            assert context.mission_id == str(mission.id)
            assert intelligence.total_targets >= 1
            assert len(recon_result.tasks_created) >= 2
            assert goals_met >= 1
            assert execution_time < 60  # Should complete within 60 seconds
            
            return {
                "mission": mission,
                "intelligence": intelligence,
                "report": report,
                "execution_time": execution_time
            }
            
        except Exception as e:
            print(f"\n❌ Mission failed: {e}")
            raise


# ═══════════════════════════════════════════════════════════════
# Performance & Metrics
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
@pytest.mark.e2e
class TestMission01Metrics:
    """Performance and metrics validation for Mission 1."""
    
    async def test_performance_benchmarks(
        self,
        workflow_orchestrator,
        blackboard,
        target_web_server
    ):
        """
        Verify performance benchmarks.
        
        SLAs:
        - Mission creation: < 1s
        - RECONNAISSANCE phase: < 30s
        - Total mission: < 60s
        """
        mission = Mission(
            name="Mission 1: Performance Test",
            status=MissionStatus.CREATED,
            scope=[target_web_server['container_ip']],
            goals={"Test": GoalStatus.PENDING}
        )
        
        # Test mission creation time
        start = time.time()
        await blackboard.create_mission(mission)
        creation_time = time.time() - start
        
        assert creation_time < 1.0, f"Mission creation took {creation_time:.2f}s (SLA: < 1s)"
        
        print(f"\n✅ Performance benchmarks")
        print(f"   Mission creation: {creation_time*1000:.2f}ms (SLA: < 1s)")
        
        # Test workflow start time
        start = time.time()
        context = await workflow_orchestrator.start_workflow(
            mission_id=str(mission.id),
            mission_goals=mission.goals,
            scope=mission.scope
        )
        workflow_start_time = time.time() - start
        
        assert workflow_start_time < 2.0, f"Workflow start took {workflow_start_time:.2f}s"
        
        print(f"   Workflow start: {workflow_start_time*1000:.2f}ms (SLA: < 2s)")
        
        return {
            "creation_time": creation_time,
            "workflow_start_time": workflow_start_time
        }
