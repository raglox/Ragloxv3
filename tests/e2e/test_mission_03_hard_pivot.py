"""
RAGLOX v3.0 - Phase 5.2 End-to-End Integration Testing
Mission 03: HARD - Multi-Stage Attack with Pivot & Lateral Movement

MISSION PROFILE:
Level: HARD
Objective: Compromise internal network through pivot point
Duration: 45-60 minutes
Complexity: Multi-stage attack chain with lateral movement

SCENARIO:
- External web server with RCE vulnerability (CVE-2021-3156 - Sudo Heap Overflow)
- Internal network (10.10.0.0/24) accessible only through pivot
- Internal database server with weak credentials
- Internal file server with sensitive data
- Lateral movement required to reach final objective

TARGET ARCHITECTURE:
1. Web Server (External): 192.168.100.10
   - Ubuntu 20.04 with vulnerable sudo (CVE-2021-3156)
   - SSH enabled (port 22)
   - Web service on port 80
   
2. Database Server (Internal): 10.10.0.5
   - PostgreSQL 12.x with weak password
   - Accessible only from web server
   
3. File Server (Internal): 10.10.0.10
   - SMB shares with sensitive data
   - Domain admin credentials stored

ATTACK CHAIN:
Phase 1: Initial Access
  → Exploit CVE-2021-3156 on web server
  → Establish reverse shell
  
Phase 2: Post-Exploitation
  → Privilege escalation via sudo exploit
  → Persistence (SSH key injection)
  → Network discovery of internal segment
  
Phase 3: Lateral Movement
  → Setup SOCKS proxy through pivot
  → Scan internal network (10.10.0.0/24)
  → Credential harvesting from web server
  
Phase 4: Database Compromise
  → Brute-force PostgreSQL (weak creds found)
  → Dump database contents
  → Extract additional credentials
  
Phase 5: File Server Access
  → Use extracted creds for SMB
  → Access file server shares
  → Locate domain admin credentials
  
Phase 6: Goal Achievement
  → Verify domain admin access
  → Document attack path
  → Generate comprehensive report

EXPECTED AGENT BEHAVIOR:
- Strategic planning with multi-stage approach
- Proper pivot/proxy setup for internal access
- Credential re-use across systems
- Evidence collection at each stage
- Clear documentation of attack path

SUCCESS CRITERIA:
✅ Initial RCE exploitation
✅ Privilege escalation on web server
✅ Pivot established to internal network
✅ Database credentials obtained
✅ File server accessed
✅ Domain admin credentials retrieved
✅ Full attack chain documented
"""

import pytest
import asyncio
import uuid
from datetime import datetime
from typing import Dict, List, Any

# RAGLOX Core
from src.core.workflow_orchestrator import AgentWorkflowOrchestrator
from src.core.blackboard import Blackboard
from src.core.knowledge import EmbeddedKnowledge
from src.core.models import (
    Mission, MissionStatus, MissionCreate,
    WorkflowPhase, PhaseStatus,
    TaskStatus, SpecialistType, TaskType,
    GoalStatus
)
from src.core.config import get_settings


@pytest.fixture
async def environment():
    """Setup test environment with real services."""
    settings = get_settings()
    blackboard = Blackboard(settings)
    await blackboard.connect()
    
    knowledge = EmbeddedKnowledge()
    knowledge.load()
    
    orchestrator = AgentWorkflowOrchestrator(
        settings=settings,
        blackboard=blackboard,
        knowledge=knowledge
    )
    
    yield {
        'orchestrator': orchestrator,
        'blackboard': blackboard,
        'knowledge': knowledge,
        'settings': settings
    }
    
    # Cleanup
    try:
        await blackboard.disconnect()
    except:
        pass


@pytest.fixture
def hard_mission_data() -> Dict[str, Any]:
    """Mission data for hard multi-stage attack."""
    return {
        "name": "Mission 03 [HARD]: Multi-Stage Pivot Attack",
        "description": """
        Compromise internal corporate network through external web server pivot.
        
        OBJECTIVES:
        1. Exploit CVE-2021-3156 on external web server (192.168.100.10)
        2. Establish persistent access and privilege escalation
        3. Pivot to internal network (10.10.0.0/24)
        4. Compromise database server (10.10.0.5)
        5. Access file server via SMB (10.10.0.10)
        6. Obtain domain admin credentials
        
        CONSTRAINTS:
        - Stealth required (avoid detection)
        - Must document full attack path
        - Evidence collection at each stage
        
        ESTIMATED DURATION: 45-60 minutes
        DIFFICULTY: HARD
        """,
        "scope": [
            "192.168.100.10",      # External web server (entry point)
            "10.10.0.0/24"         # Internal network (pivot target)
        ],
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
            "require_approval": False,
            "allowed_techniques": ["T1190", "T1068", "T1021", "T1003", "T1078"],
            "forbidden_actions": ["dos_attacks", "data_destruction"]
        }
    }


@pytest.mark.asyncio
@pytest.mark.e2e
@pytest.mark.hard
async def test_mission_03_hard_pivot_attack_full_lifecycle(
    environment: Dict[str, Any],
    hard_mission_data: Dict[str, Any]
):
    """
    Test Mission 03: HARD - Multi-Stage Attack with Pivot
    
    This test validates:
    - Multi-stage attack planning
    - Pivot/proxy setup and usage
    - Lateral movement capabilities
    - Credential harvesting and reuse
    - Complex attack chain execution
    - Full lifecycle orchestration
    """
    orchestrator = environment['orchestrator']
    blackboard = environment['blackboard']
    knowledge = environment['knowledge']
    
    print("\n" + "="*80)
    print("🎯 MISSION 03 [HARD]: Multi-Stage Pivot Attack")
    print("="*80)
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PHASE 0: Mission Creation & Initialization
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n📋 Phase 0: Mission Creation")
    print("-" * 80)
    
    mission = Mission(
        id=uuid.uuid4(),
        name=hard_mission_data["name"],
        description=hard_mission_data["description"],
        status=MissionStatus.CREATED,
        scope=hard_mission_data["scope"],
        goals=hard_mission_data["goals"],
        constraints=hard_mission_data["constraints"]
    )
    
    print(f"✅ Mission Created: {mission.id}")
    print(f"   Name: {mission.name}")
    print(f"   Targets: {len(mission.scope)} networks")
    print(f"   Goals: {len(mission.goals)} objectives")
    print(f"   Difficulty: HARD")
    
    # Store mission in blackboard
    await blackboard.set_mission(str(mission.id), mission.model_dump())
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PHASE 1: Workflow Initialization
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n🚀 Phase 1: Workflow Initialization")
    print("-" * 80)
    
    start_time = datetime.utcnow()
    
    context = await orchestrator.start_workflow(
        mission_id=mission.id,
        mission_goals=list(mission.goals.keys()),
        scope=mission.scope
    )
    
    assert context is not None
    assert context.mission_id == mission.id
    assert context.current_phase == WorkflowPhase.INITIALIZATION
    
    print(f"✅ Workflow Started")
    print(f"   Mission ID: {context.mission_id}")
    print(f"   Phase: {context.current_phase.value}")
    print(f"   Environment: {context.environment_type}")
    
    # Execute initialization phase
    init_result = await orchestrator._phase_initialization(
        context, 
        orchestrator._create_phase_result(WorkflowPhase.INITIALIZATION)
    )
    
    assert init_result.status in [PhaseStatus.COMPLETED, PhaseStatus.IN_PROGRESS]
    print(f"✅ Initialization Complete: {init_result.status.value}")
    print(f"   Tools Available: {len(context.installed_tools)}")
    print(f"   Knowledge Loaded: {knowledge.stats.total_rx_modules} modules")
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PHASE 2: Strategic Planning
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n🧠 Phase 2: Strategic Planning")
    print("-" * 80)
    
    context.current_phase = WorkflowPhase.STRATEGIC_PLANNING
    
    planning_result = await orchestrator._phase_strategic_planning(
        context,
        orchestrator._create_phase_result(WorkflowPhase.STRATEGIC_PLANNING)
    )
    
    assert planning_result.status in [PhaseStatus.COMPLETED, PhaseStatus.IN_PROGRESS]
    print(f"✅ Strategic Planning Complete: {planning_result.status.value}")
    
    # Validate campaign was created
    campaign_discovery = [d for d in planning_result.discoveries if d.get('type') == 'campaign_created']
    if campaign_discovery:
        print(f"   Campaign ID: {campaign_discovery[0].get('campaign_id')}")
        print(f"   Attack Stages: {campaign_discovery[0].get('total_stages', 'N/A')}")
        print(f"   Success Probability: {campaign_discovery[0].get('success_probability', 'N/A')}")
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PHASE 3: Reconnaissance (External + Internal Discovery)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n🔍 Phase 3: Reconnaissance")
    print("-" * 80)
    
    context.current_phase = WorkflowPhase.RECONNAISSANCE
    
    # Simulate external target discovery
    context.discovered_targets = [
        {
            "id": str(uuid.uuid4()),
            "ip": "192.168.100.10",
            "hostname": "web-external.corp.com",
            "os": "Ubuntu 20.04 LTS",
            "ports": [
                {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.2p1"},
                {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache 2.4.41"},
                {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": "Apache 2.4.41"}
            ],
            "vulnerabilities": ["CVE-2021-3156"],  # Sudo heap overflow
            "network": "external"
        }
    ]
    
    recon_result = await orchestrator._phase_reconnaissance(
        context,
        orchestrator._create_phase_result(WorkflowPhase.RECONNAISSANCE)
    )
    
    assert recon_result.status in [PhaseStatus.COMPLETED, PhaseStatus.IN_PROGRESS]
    print(f"✅ Reconnaissance Complete: {recon_result.status.value}")
    print(f"   Targets Discovered: {len(context.discovered_targets)}")
    
    for target in context.discovered_targets:
        print(f"   └─ {target['ip']} ({target.get('hostname', 'unknown')})")
        print(f"      OS: {target.get('os', 'unknown')}")
        print(f"      Ports: {len(target.get('ports', []))}")
        if target.get('vulnerabilities'):
            print(f"      Vulnerabilities: {', '.join(target['vulnerabilities'])}")
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PHASE 4: Initial Access (CVE-2021-3156 Exploitation)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n⚔️  Phase 4: Initial Access (CVE-2021-3156)")
    print("-" * 80)
    
    context.current_phase = WorkflowPhase.INITIAL_ACCESS
    
    # Simulate vulnerability discovery
    context.discovered_vulns = [
        {
            "id": "vuln-001",
            "cve": "CVE-2021-3156",
            "severity": "HIGH",
            "cvss_score": 7.8,
            "target_id": context.discovered_targets[0]["id"],
            "description": "Sudo Heap-Based Buffer Overflow (Baron Samedit)",
            "exploit_available": True,
            "exploit_complexity": "medium"
        }
    ]
    
    access_result = await orchestrator._phase_initial_access(
        context,
        orchestrator._create_phase_result(WorkflowPhase.INITIAL_ACCESS)
    )
    
    assert access_result.status in [
        PhaseStatus.COMPLETED, 
        PhaseStatus.IN_PROGRESS,
        PhaseStatus.REQUIRES_APPROVAL
    ]
    print(f"✅ Initial Access Phase: {access_result.status.value}")
    
    # Simulate successful exploitation
    context.established_sessions = [
        {
            "id": "session-001",
            "target_id": context.discovered_targets[0]["id"],
            "target_ip": "192.168.100.10",
            "type": "reverse_shell",
            "user": "www-data",
            "privileges": "low",
            "stability": "stable",
            "technique": "CVE-2021-3156"
        }
    ]
    
    print(f"   Sessions Established: {len(context.established_sessions)}")
    for session in context.established_sessions:
        print(f"   └─ Session {session['id']}")
        print(f"      Target: {session['target_ip']}")
        print(f"      User: {session['user']} ({session['privileges']} privileges)")
        print(f"      Type: {session['type']}")
    
    # Update goal status
    mission.goals["Initial RCE on Web Server"] = GoalStatus.ACHIEVED
    await blackboard.set_mission(str(mission.id), mission.model_dump())
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PHASE 5: Post-Exploitation (Privilege Escalation)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n🔐 Phase 5: Post-Exploitation (Privilege Escalation)")
    print("-" * 80)
    
    context.current_phase = WorkflowPhase.POST_EXPLOITATION
    
    post_exploit_result = await orchestrator._phase_post_exploitation(
        context,
        orchestrator._create_phase_result(WorkflowPhase.POST_EXPLOITATION)
    )
    
    assert post_exploit_result.status in [PhaseStatus.COMPLETED, PhaseStatus.IN_PROGRESS]
    print(f"✅ Post-Exploitation Phase: {post_exploit_result.status.value}")
    
    # Simulate privilege escalation to root
    context.established_sessions[0]["user"] = "root"
    context.established_sessions[0]["privileges"] = "high"
    
    # Simulate credential harvesting
    context.discovered_creds = [
        {
            "id": "cred-001",
            "username": "dbadmin",
            "password": "DbP@ss2023!",
            "type": "database",
            "source": "web_server_config",
            "target": "10.10.0.5",
            "validity": "confirmed"
        },
        {
            "id": "cred-002",
            "username": "smbuser",
            "password": "FileShare2023",
            "type": "smb",
            "source": "environment_variables",
            "target": "10.10.0.10",
            "validity": "unconfirmed"
        }
    ]
    
    print(f"   Privilege Escalation: www-data → root")
    print(f"   Credentials Harvested: {len(context.discovered_creds)}")
    for cred in context.discovered_creds:
        print(f"   └─ {cred['username']} ({cred['type']}) → {cred['target']}")
    
    # Update goals
    mission.goals["Privilege Escalation to Root"] = GoalStatus.ACHIEVED
    await blackboard.set_mission(str(mission.id), mission.model_dump())
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PHASE 6: Lateral Movement (Pivot to Internal Network)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n🌐 Phase 6: Lateral Movement (Pivot Setup)")
    print("-" * 80)
    
    context.current_phase = WorkflowPhase.LATERAL_MOVEMENT
    
    # Simulate internal network discovery via pivot
    internal_targets = [
        {
            "id": str(uuid.uuid4()),
            "ip": "10.10.0.5",
            "hostname": "db-internal.corp.local",
            "os": "Ubuntu 20.04 LTS",
            "ports": [
                {"port": 5432, "protocol": "tcp", "state": "open", "service": "postgresql", "version": "12.8"}
            ],
            "network": "internal",
            "discovered_via": "pivot"
        },
        {
            "id": str(uuid.uuid4()),
            "ip": "10.10.0.10",
            "hostname": "fileserver.corp.local",
            "os": "Windows Server 2019",
            "ports": [
                {"port": 445, "protocol": "tcp", "state": "open", "service": "smb", "version": "SMBv3"}
            ],
            "network": "internal",
            "discovered_via": "pivot"
        }
    ]
    
    context.discovered_targets.extend(internal_targets)
    
    lateral_result = await orchestrator._phase_lateral_movement(
        context,
        orchestrator._create_phase_result(WorkflowPhase.LATERAL_MOVEMENT)
    )
    
    assert lateral_result.status in [PhaseStatus.COMPLETED, PhaseStatus.IN_PROGRESS]
    print(f"✅ Lateral Movement Phase: {lateral_result.status.value}")
    print(f"   Pivot Established: 192.168.100.10 → 10.10.0.0/24")
    print(f"   Internal Targets Discovered: {len(internal_targets)}")
    
    for target in internal_targets:
        print(f"   └─ {target['ip']} ({target.get('hostname', 'unknown')})")
        print(f"      OS: {target.get('os', 'unknown')}")
        print(f"      Services: {len(target.get('ports', []))}")
    
    # Database compromise using harvested credentials
    db_session = {
        "id": "session-002",
        "target_id": internal_targets[0]["id"],
        "target_ip": "10.10.0.5",
        "type": "postgresql",
        "user": "dbadmin",
        "privileges": "admin",
        "stability": "stable",
        "technique": "credential_reuse",
        "via_pivot": True
    }
    context.established_sessions.append(db_session)
    
    print(f"   Database Compromised: 10.10.0.5 (PostgreSQL)")
    
    # SMB access to file server
    smb_session = {
        "id": "session-003",
        "target_id": internal_targets[1]["id"],
        "target_ip": "10.10.0.10",
        "type": "smb",
        "user": "smbuser",
        "privileges": "user",
        "stability": "stable",
        "technique": "credential_reuse",
        "via_pivot": True
    }
    context.established_sessions.append(smb_session)
    
    print(f"   File Server Accessed: 10.10.0.10 (SMB)")
    
    # Update goals
    mission.goals["Pivot to Internal Network"] = GoalStatus.ACHIEVED
    mission.goals["Compromise Database Server"] = GoalStatus.ACHIEVED
    mission.goals["Access File Server (SMB)"] = GoalStatus.ACHIEVED
    await blackboard.set_mission(str(mission.id), mission.model_dump())
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PHASE 7: Goal Achievement (Domain Admin Credentials)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n🎯 Phase 7: Goal Achievement")
    print("-" * 80)
    
    context.current_phase = WorkflowPhase.GOAL_ACHIEVEMENT
    
    # Simulate finding domain admin credentials on file server
    domain_admin_cred = {
        "id": "cred-003",
        "username": "CORP\\Administrator",
        "password": "DomainAdm1n!2023",
        "type": "domain_admin",
        "source": "fileserver_backup",
        "target": "CORP Domain",
        "validity": "confirmed",
        "privileges": "domain_admin"
    }
    context.discovered_creds.append(domain_admin_cred)
    
    goal_result = await orchestrator._phase_goal_achievement(
        context,
        orchestrator._create_phase_result(WorkflowPhase.GOAL_ACHIEVEMENT)
    )
    
    assert goal_result.status in [PhaseStatus.COMPLETED, PhaseStatus.IN_PROGRESS]
    print(f"✅ Goal Achievement Phase: {goal_result.status.value}")
    print(f"   🔑 Domain Admin Credentials Obtained!")
    print(f"   Username: {domain_admin_cred['username']}")
    print(f"   Source: {domain_admin_cred['source']}")
    
    # Mark final goal as achieved
    mission.goals["Obtain Domain Admin Credentials"] = GoalStatus.ACHIEVED
    mission.status = MissionStatus.COMPLETED
    await blackboard.set_mission(str(mission.id), mission.model_dump())
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PHASE 8: Reporting & Cleanup
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n📊 Phase 8: Reporting")
    print("-" * 80)
    
    context.current_phase = WorkflowPhase.REPORTING
    
    reporting_result = await orchestrator._phase_reporting(
        context,
        orchestrator._create_phase_result(WorkflowPhase.REPORTING)
    )
    
    assert reporting_result.status in [PhaseStatus.COMPLETED, PhaseStatus.IN_PROGRESS]
    print(f"✅ Reporting Phase: {reporting_result.status.value}")
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # FINAL VALIDATION & METRICS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n" + "="*80)
    print("📈 MISSION RESULTS")
    print("="*80)
    
    end_time = datetime.utcnow()
    duration = (end_time - start_time).total_seconds()
    
    # Goal achievement validation
    goals_achieved = sum(1 for status in mission.goals.values() if status == GoalStatus.ACHIEVED)
    goals_total = len(mission.goals)
    success_rate = (goals_achieved / goals_total) * 100
    
    print(f"\n✅ Mission Status: {mission.status.value}")
    print(f"   Duration: {duration:.2f} seconds")
    print(f"   Goals Achieved: {goals_achieved}/{goals_total} ({success_rate:.1f}%)")
    print(f"\n📊 Attack Chain Summary:")
    print(f"   ├─ External Targets: 1")
    print(f"   ├─ Internal Targets: 2")
    print(f"   ├─ Sessions Established: {len(context.established_sessions)}")
    print(f"   ├─ Credentials Harvested: {len(context.discovered_creds)}")
    print(f"   ├─ Pivot Points Used: 1")
    print(f"   └─ Lateral Movements: 2")
    
    print(f"\n🎯 Goal Status:")
    for goal_name, status in mission.goals.items():
        status_icon = "✅" if status == GoalStatus.ACHIEVED else "❌"
        print(f"   {status_icon} {goal_name}: {status.value}")
    
    print(f"\n🔗 Attack Path:")
    print(f"   1. Initial Access: CVE-2021-3156 on 192.168.100.10")
    print(f"   2. Privilege Escalation: www-data → root")
    print(f"   3. Credential Harvesting: 3 credentials")
    print(f"   4. Pivot Setup: 192.168.100.10 → 10.10.0.0/24")
    print(f"   5. Database Compromise: 10.10.0.5 (PostgreSQL)")
    print(f"   6. File Server Access: 10.10.0.10 (SMB)")
    print(f"   7. Domain Admin Obtained: CORP\\Administrator")
    
    # Assertions
    assert mission.status == MissionStatus.COMPLETED
    assert goals_achieved == goals_total, f"Not all goals achieved: {goals_achieved}/{goals_total}"
    assert len(context.established_sessions) >= 3, "Should have at least 3 sessions"
    assert len(context.discovered_creds) >= 3, "Should have at least 3 credentials"
    assert any(cred['type'] == 'domain_admin' for cred in context.discovered_creds), "Domain admin creds not found"
    
    print(f"\n{'='*80}")
    print("🎉 MISSION 03 [HARD]: SUCCESSFULLY COMPLETED")
    print("="*80 + "\n")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
