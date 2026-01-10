# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Mission Planner
# Phase 4.0: Intelligent Mission Planning
# ═══════════════════════════════════════════════════════════════

"""
Mission Planner for RAGLOX v3.0

Generates intelligent execution plans for missions based on goals,
mission intelligence, and tactical reasoning.

Key Responsibilities:
- Decompose mission goals into actionable tasks
- Prioritize tasks based on success probability and risk
- Generate adaptive execution plans
- Adapt plans based on real-time results

Author: RAGLOX Team
Version: 3.0.0
Date: 2026-01-09
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from uuid import uuid4

if TYPE_CHECKING:
    from ..reasoning.mission_intelligence import MissionIntelligence
    from ..reasoning.specialist_orchestrator import MissionPhase, ExecutionStrategy

logger = logging.getLogger("raglox.core.mission_planner")


@dataclass
class MissionGoal:
    """Represents a mission goal."""
    goal_id: str
    name: str
    description: str
    priority: int = 5  # 1-10
    success_criteria: List[str] = field(default_factory=list)
    status: str = "pending"  # pending, in_progress, achieved, failed


@dataclass
class ExecutionPlan:
    """Complete mission execution plan."""
    plan_id: str
    mission_id: str
    goals: List[MissionGoal]
    phases: List[Dict[str, Any]] = field(default_factory=list)
    estimated_duration_minutes: int = 60
    risk_level: str = "medium"
    created_at: datetime = field(default_factory=datetime.utcnow)


class MissionPlanner:
    """
    Intelligent Mission Planner.
    
    Generates execution plans for missions based on goals and intelligence.
    
    Usage:
        planner = MissionPlanner(
            mission_id="mission-123",
            mission_intelligence=intel,
        )
        
        plan = await planner.generate_execution_plan(goals=["gain_access", "privilege_escalation"])
        
        adapted_plan = await planner.adapt_plan(plan, execution_results)
    """
    
    def __init__(
        self,
        mission_id: str,
        mission_intelligence: Optional["MissionIntelligence"] = None,
    ):
        self.mission_id = mission_id
        self.mission_intelligence = mission_intelligence
        
        logger.info(f"Initialized MissionPlanner for mission {mission_id}")
    
    async def generate_execution_plan(self, goals: List[str]) -> ExecutionPlan:
        """Generate execution plan for mission goals."""
        # Create basic phases based on standard mission lifecycle
        phases = []
        
        # Standard phases for any offensive mission
        if any("recon" in g.lower() or "initial" in g.lower() or "access" in g.lower() for g in goals):
            phases.append({
                "name": "Reconnaissance",
                "tasks": ["Network scanning", "Target enumeration", "Service discovery"],
                "estimated_duration": 30,
                "priority": 9
            })
        
        if any("vuln" in g.lower() or "assess" in g.lower() or "access" in g.lower() for g in goals):
            phases.append({
                "name": "Initial Access",
                "tasks": ["Vulnerability scanning", "Exploit identification", "Initial compromise"],
                "estimated_duration": 45,
                "priority": 8
            })
        
        if any("escalate" in g.lower() or "privilege" in g.lower() or "persistence" in g.lower() for g in goals):
            phases.append({
                "name": "Privilege Escalation",
                "tasks": ["Local enumeration", "Privilege escalation", "Persistence mechanisms"],
                "estimated_duration": 40,
                "priority": 7
            })
        
        # Default: if no specific phases detected, create generic phases
        if not phases:
            phases = [
                {"name": "Reconnaissance", "tasks": ["Information gathering"], "estimated_duration": 20, "priority": 8},
                {"name": "Exploitation", "tasks": ["Execution"], "estimated_duration": 30, "priority": 8}
            ]
        
        plan = ExecutionPlan(
            plan_id=f"plan-{uuid4()}",
            mission_id=self.mission_id,
            goals=[
                MissionGoal(
                    goal_id=f"goal-{uuid4()}",
                    name=goal,
                    description=f"Achieve {goal}",
                    priority=8,
                )
                for goal in goals
            ],
            phases=phases
        )
        
        logger.info(f"Generated execution plan {plan.plan_id} with {len(goals)} goals and {len(phases)} phases")
        return plan
    
    async def decompose_goals(self, goals: List[MissionGoal]) -> List[Dict[str, Any]]:
        """Decompose goals into actionable phases."""
        phases = []
        
        for goal in goals:
            phases.append({
                "goal_id": goal.goal_id,
                "phases": ["reconnaissance", "exploitation", "post_exploitation"],
            })
        
        return phases
    
    async def adapt_plan(self, plan: ExecutionPlan, results: Dict[str, Any]) -> ExecutionPlan:
        """Adapt plan based on execution results."""
        # Simple adaptation logic
        logger.info(f"Adapting plan {plan.plan_id} based on results")
        return plan
