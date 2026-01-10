# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Specialist Orchestrator
# Phase 4.0: Intelligent Specialist Coordination
# ═══════════════════════════════════════════════════════════════

"""
Specialist Orchestrator for RAGLOX v3.0

Coordinates the execution of multiple specialists based on mission intelligence
and tactical reasoning. Implements intelligent task distribution, dependency
management, and parallel execution strategies.

Key Responsibilities:
- Coordinate specialist execution based on mission phase
- Manage task dependencies and prerequisites
- Implement parallel vs sequential execution strategies
- Handle specialist failures and recovery
- Provide real-time coordination insights

Architecture:
┌─────────────────────────────────────────────────────────────┐
│              SpecialistOrchestrator                         │
│                                                             │
│  ┌────────────────┐      ┌──────────────────┐             │
│  │ MissionIntel   │──────│ TacticalReasoning│             │
│  │                │      │                  │             │
│  └────────────────┘      └──────────────────┘             │
│         │                        │                         │
│         ▼                        ▼                         │
│  ┌─────────────────────────────────────────┐              │
│  │       Orchestration Logic                │              │
│  │  - Phase Analysis                        │              │
│  │  - Task Generation                       │              │
│  │  - Dependency Resolution                 │              │
│  │  - Execution Strategy Selection          │              │
│  └─────────────────────────────────────────┘              │
│                     │                                       │
│                     ▼                                       │
│  ┌──────────┬──────────┬──────────┬──────────┐            │
│  │  Recon   │  Vuln    │  Attack  │  Intel   │            │
│  │Specialist│Specialist│Specialist│Specialist│            │
│  └──────────┴──────────┴──────────┴──────────┘            │
└─────────────────────────────────────────────────────────────┘

Author: RAGLOX Team
Version: 3.0.0
Date: 2026-01-09
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING
from uuid import uuid4

if TYPE_CHECKING:
    from ..blackboard import Blackboard
    from ...specialists.base import BaseSpecialist
    from .mission_intelligence import MissionIntelligence
    from .tactical_reasoning import TacticalReasoningEngine

from ..models import TaskType, SpecialistType, TaskStatus

logger = logging.getLogger("raglox.core.specialist_orchestrator")


# ═══════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════

class MissionPhase(Enum):
    """Mission execution phases."""
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    INITIAL_ACCESS = "initial_access"
    POST_EXPLOITATION = "post_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    CLEANUP = "cleanup"
    COMPLETED = "completed"


class CoordinationPattern(Enum):
    """Specialist coordination patterns."""
    SEQUENTIAL = "sequential"          # One specialist at a time
    PARALLEL = "parallel"              # All specialists simultaneously
    PIPELINE = "pipeline"              # Output of one feeds into another
    CONDITIONAL = "conditional"        # Based on results/intelligence
    ADAPTIVE = "adaptive"              # Dynamically adjusted


class ExecutionStrategy(Enum):
    """Task execution strategies."""
    AGGRESSIVE = "aggressive"          # Fast, parallel, high risk
    BALANCED = "balanced"              # Moderate pace and risk
    STEALTHY = "stealthy"             # Slow, sequential, low risk
    OPPORTUNISTIC = "opportunistic"    # Based on discovered opportunities


# ═══════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════

@dataclass
class TaskDependency:
    """Represents a task dependency."""
    task_id: str
    depends_on: List[str]  # List of task IDs that must complete first
    dependency_type: str = "completion"  # completion, success, data
    timeout_seconds: int = 300


@dataclass
class CoordinationTask:
    """
    Enhanced task with orchestration metadata.
    
    Wraps a standard Task with additional orchestration information
    like dependencies, priority, and execution strategy.
    """
    task_id: str
    specialist_type: SpecialistType
    task_type: TaskType
    target_id: Optional[str] = None
    
    # Orchestration metadata
    priority: int = 5  # 1-10, higher = more important
    dependencies: List[str] = field(default_factory=list)
    estimated_duration_seconds: int = 60
    risk_level: str = "medium"  # low, medium, high, critical
    
    # Execution tracking
    status: TaskStatus = TaskStatus.PENDING
    assigned_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    # Context
    mission_id: str = ""
    phase: Optional[MissionPhase] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OrchestrationPlan:
    """
    Complete orchestration plan for a mission phase.
    
    Contains all tasks to execute, their dependencies, and execution strategy.
    """
    plan_id: str
    mission_id: str
    phase: MissionPhase
    
    # Tasks
    tasks: List[CoordinationTask] = field(default_factory=list)
    
    # Execution configuration
    coordination_pattern: CoordinationPattern = CoordinationPattern.ADAPTIVE
    execution_strategy: ExecutionStrategy = ExecutionStrategy.BALANCED
    max_parallel_tasks: int = 5
    
    # Timing
    created_at: datetime = field(default_factory=datetime.utcnow)
    estimated_duration_minutes: int = 10
    
    # Status
    status: str = "pending"  # pending, executing, completed, failed
    progress: float = 0.0  # 0.0 - 1.0
    
    # Results
    completed_tasks: int = 0
    failed_tasks: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OrchestrationResult:
    """
    Result of orchestration execution.
    
    Contains summary of execution, task results, and next recommendations.
    """
    plan_id: str
    mission_id: str
    phase: MissionPhase
    
    # Execution summary
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    execution_time_seconds: float = 0.0
    
    # Task results
    task_results: List[Dict[str, Any]] = field(default_factory=list)
    
    # Intelligence gathered
    new_targets_discovered: int = 0
    new_vulnerabilities_found: int = 0
    new_credentials_obtained: int = 0
    new_sessions_created: int = 0
    
    # Next steps
    recommended_next_phase: Optional[MissionPhase] = None
    recommended_tasks: List[str] = field(default_factory=list)
    
    # Status
    success: bool = False
    completed_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════
# Specialist Orchestrator
# ═══════════════════════════════════════════════════════════════

class SpecialistOrchestrator:
    """
    Intelligent Specialist Coordinator.
    
    Manages the execution of specialists based on mission intelligence,
    tactical reasoning, and dynamic mission state.
    
    Usage:
        orchestrator = SpecialistOrchestrator(
            mission_id="mission-123",
            blackboard=bb,
            specialists={"recon": recon_specialist, "attack": attack_specialist},
            mission_intelligence=intel,
        )
        
        # Generate execution plan
        plan = await orchestrator.generate_execution_plan(
            phase=MissionPhase.RECONNAISSANCE
        )
        
        # Execute plan
        result = await orchestrator.execute_plan(plan)
        
        # Get recommendations
        next_phase = result.recommended_next_phase
    """
    
    def __init__(
        self,
        mission_id: str,
        blackboard: "Blackboard",
        specialists: Dict[SpecialistType, "BaseSpecialist"],
        mission_intelligence: Optional["MissionIntelligence"] = None,
        tactical_engine: Optional["TacticalReasoningEngine"] = None,
    ):
        """
        Initialize Specialist Orchestrator.
        
        Args:
            mission_id: Mission ID
            blackboard: Blackboard instance
            specialists: Dict mapping specialist types to instances
            mission_intelligence: MissionIntelligence (optional)
            tactical_engine: TacticalReasoningEngine (optional)
        """
        self.mission_id = mission_id
        self.blackboard = blackboard
        self.specialists = specialists
        self.mission_intelligence = mission_intelligence
        self.tactical_engine = tactical_engine
        
        # State
        self._current_plan: Optional[OrchestrationPlan] = None
        self._active_tasks: Dict[str, CoordinationTask] = {}
        self._task_dependencies: Dict[str, TaskDependency] = {}
        
        # Statistics
        self._stats = {
            "plans_generated": 0,
            "plans_executed": 0,
            "total_tasks_executed": 0,
            "total_tasks_failed": 0,
        }
        
        logger.info(f"Initialized SpecialistOrchestrator for mission {mission_id} "
                   f"with {len(specialists)} specialists")
    
    # ═══════════════════════════════════════════════════════════════
    # Specialist Management
    # ═══════════════════════════════════════════════════════════════
    
    async def register_specialist(
        self,
        specialist_type: SpecialistType,
        specialist_id: str,
        capabilities: List[str]
    ) -> None:
        """
        Register a specialist dynamically at runtime.
        
        Allows tests and dynamic orchestration to add specialists
        after initialization. Useful for:
        - E2E testing with progressive specialist registration
        - Runtime specialist scaling
        - Dynamic capability addition
        
        Args:
            specialist_type: Type of specialist (recon, vuln, attack, etc.)
            specialist_id: Unique identifier for this specialist instance
            capabilities: List of capabilities this specialist provides
        
        Example:
            await orchestrator.register_specialist(
                specialist_type=SpecialistType.recon,
                specialist_id="recon_001",
                capabilities=["nmap", "masscan", "enum"]
            )
        """
        from ...specialists.base import BaseSpecialist
        
        # Create a mock specialist for testing/dynamic scenarios
        class DynamicSpecialist(BaseSpecialist):
            def __init__(self, spec_type, spec_id, caps):
                self.specialist_type = spec_type
                self.specialist_id = spec_id
                self.capabilities = caps
                self.status = "ready"
            
            async def execute_task(self, task):
                """Execute task (mock implementation for testing)"""
                return {
                    "status": "success",
                    "specialist_id": self.specialist_id,
                    "task_id": task.get("task_id", "unknown"),
                    "specialist_type": self.specialist_type.value
                }
            
            async def on_event(self, event):
                """Handle events (mock implementation for testing)"""
                logger.debug(f"Specialist {self.specialist_id} received event: {event}")
                pass
        
        specialist = DynamicSpecialist(specialist_type, specialist_id, capabilities)
        self.specialists[specialist_type] = specialist
        
        logger.info(f"Registered specialist: {specialist_type.value} "
                   f"(id={specialist_id}, capabilities={capabilities})")
    
    def get_registered_specialists(self) -> Dict[SpecialistType, Any]:
        """
        Get all currently registered specialists.
        
        Returns:
            Dictionary mapping specialist types to instances
        """
        return self.specialists.copy()
    
    def get_specialist_count(self) -> int:
        """
        Get count of registered specialists.
        
        Returns:
            Number of registered specialists
        """
        return len(self.specialists)
    
    # ═══════════════════════════════════════════════════════════════
    # Phase Analysis
    # ═══════════════════════════════════════════════════════════════
    
    async def determine_current_phase(self) -> MissionPhase:
        """
        Determine current mission phase based on intelligence.
        
        Returns:
            Current MissionPhase
        """
        if not self.mission_intelligence:
            # Default to reconnaissance if no intelligence available
            return MissionPhase.RECONNAISSANCE
        
        intel = self.mission_intelligence
        
        # Phase determination logic
        if intel.total_targets == 0:
            return MissionPhase.RECONNAISSANCE
        
        if intel.total_vulnerabilities == 0:
            return MissionPhase.VULNERABILITY_ASSESSMENT
        
        if intel.compromised_targets == 0:
            return MissionPhase.INITIAL_ACCESS
        
        if intel.compromised_targets < intel.total_targets:
            # Still have uncompromised targets
            if intel.privileged_credentials > 0:
                return MissionPhase.LATERAL_MOVEMENT
            else:
                return MissionPhase.POST_EXPLOITATION
        
        # All targets compromised
        return MissionPhase.COMPLETED
    
    async def analyze_phase_requirements(self, phase: MissionPhase) -> Dict[str, Any]:
        """
        Analyze requirements for a specific phase.
        
        Args:
            phase: Mission phase to analyze
            
        Returns:
            Dict with phase analysis
        """
        analysis = {
            "phase": phase.value,
            "required_specialists": [],
            "estimated_duration_minutes": 10,
            "risk_level": "medium",
            "success_criteria": [],
        }
        
        # Phase-specific analysis
        if phase == MissionPhase.RECONNAISSANCE:
            analysis.update({
                "required_specialists": [SpecialistType.RECON],
                "estimated_duration_minutes": 5,
                "risk_level": "low",
                "success_criteria": ["targets_discovered >= 1", "services_enumerated >= 1"],
            })
        
        elif phase == MissionPhase.VULNERABILITY_ASSESSMENT:
            analysis.update({
                "required_specialists": [SpecialistType.RECON],  # Vuln scanning done by recon
                "estimated_duration_minutes": 10,
                "risk_level": "low",
                "success_criteria": ["vulnerabilities_found >= 1"],
            })
        
        elif phase == MissionPhase.INITIAL_ACCESS:
            analysis.update({
                "required_specialists": [SpecialistType.ATTACK],
                "estimated_duration_minutes": 15,
                "risk_level": "high",
                "success_criteria": ["sessions_created >= 1", "targets_compromised >= 1"],
            })
        
        elif phase == MissionPhase.POST_EXPLOITATION:
            analysis.update({
                "required_specialists": [SpecialistType.ATTACK],
                "estimated_duration_minutes": 10,
                "risk_level": "medium",
                "success_criteria": ["credentials_harvested >= 1"],
            })
        
        elif phase == MissionPhase.LATERAL_MOVEMENT:
            analysis.update({
                "required_specialists": [SpecialistType.ATTACK],
                "estimated_duration_minutes": 20,
                "risk_level": "high",
                "success_criteria": ["new_targets_compromised >= 1"],
            })
        
        return analysis
    
    # ═══════════════════════════════════════════════════════════════
    # Plan Generation
    # ═══════════════════════════════════════════════════════════════
    
    async def generate_execution_plan(
        self,
        phase: Optional[MissionPhase] = None,
        execution_strategy: ExecutionStrategy = ExecutionStrategy.BALANCED,
    ) -> OrchestrationPlan:
        """
        Generate execution plan for a mission phase.
        
        Args:
            phase: Mission phase (auto-determined if None)
            execution_strategy: Execution strategy to use
            
        Returns:
            Complete OrchestrationPlan
        """
        if phase is None:
            phase = await self.determine_current_phase()
        
        logger.info(f"Generating execution plan for phase: {phase.value}")
        
        # Analyze phase requirements
        phase_analysis = await self.analyze_phase_requirements(phase)
        
        # Create plan
        plan = OrchestrationPlan(
            plan_id=f"plan-{uuid4()}",
            mission_id=self.mission_id,
            phase=phase,
            execution_strategy=execution_strategy,
            estimated_duration_minutes=phase_analysis["estimated_duration_minutes"],
        )
        
        # Generate tasks based on phase
        tasks = await self._generate_phase_tasks(phase, execution_strategy)
        plan.tasks = tasks
        
        # Determine coordination pattern
        plan.coordination_pattern = await self._select_coordination_pattern(phase, tasks)
        
        # Set max parallel tasks based on strategy
        if execution_strategy == ExecutionStrategy.AGGRESSIVE:
            plan.max_parallel_tasks = 10
        elif execution_strategy == ExecutionStrategy.STEALTHY:
            plan.max_parallel_tasks = 1
        else:
            plan.max_parallel_tasks = 5
        
        self._stats["plans_generated"] += 1
        logger.info(f"Generated plan {plan.plan_id} with {len(tasks)} tasks")
        
        return plan
    
    async def _generate_phase_tasks(
        self,
        phase: MissionPhase,
        strategy: ExecutionStrategy
    ) -> List[CoordinationTask]:
        """
        Generate tasks for a specific phase.
        
        Args:
            phase: Mission phase
            strategy: Execution strategy
            
        Returns:
            List of CoordinationTask objects
        """
        tasks = []
        
        if phase == MissionPhase.RECONNAISSANCE:
            # Network scanning tasks
            tasks.append(CoordinationTask(
                task_id=f"task-{uuid4()}",
                specialist_type=SpecialistType.RECON,
                task_type=TaskType.NETWORK_SCAN,
                priority=10,
                estimated_duration_seconds=60,
                risk_level="low",
                mission_id=self.mission_id,
                phase=phase,
            ))
            
            # Port scanning (depends on network scan)
            network_scan_id = tasks[0].task_id
            tasks.append(CoordinationTask(
                task_id=f"task-{uuid4()}",
                specialist_type=SpecialistType.RECON,
                task_type=TaskType.PORT_SCAN,
                priority=9,
                dependencies=[network_scan_id],
                estimated_duration_seconds=120,
                risk_level="low",
                mission_id=self.mission_id,
                phase=phase,
            ))
        
        elif phase == MissionPhase.VULNERABILITY_ASSESSMENT:
            # Vulnerability scanning
            tasks.append(CoordinationTask(
                task_id=f"task-{uuid4()}",
                specialist_type=SpecialistType.RECON,
                task_type=TaskType.VULN_SCAN,
                priority=10,
                estimated_duration_seconds=300,
                risk_level="low",
                mission_id=self.mission_id,
                phase=phase,
            ))
        
        elif phase == MissionPhase.INITIAL_ACCESS:
            # Exploitation tasks based on discovered vulnerabilities
            if self.mission_intelligence:
                exploitable_vulns = self.mission_intelligence.get_exploitable_vulnerabilities()
                
                for vuln in exploitable_vulns[:5]:  # Limit to top 5
                    tasks.append(CoordinationTask(
                        task_id=f"task-{uuid4()}",
                        specialist_type=SpecialistType.ATTACK,
                        task_type=TaskType.EXPLOIT,
                        target_id=vuln.target_id,
                        priority=8 if vuln.severity == "critical" else 6,
                        estimated_duration_seconds=180,
                        risk_level="high" if vuln.severity == "critical" else "medium",
                        mission_id=self.mission_id,
                        phase=phase,
                        metadata={"vuln_id": vuln.vuln_id},
                    ))
        
        elif phase == MissionPhase.POST_EXPLOITATION:
            # Credential harvesting on compromised targets
            if self.mission_intelligence:
                compromised = self.mission_intelligence.get_compromised_targets()
                
                for target in compromised[:3]:  # Limit to 3
                    tasks.append(CoordinationTask(
                        task_id=f"task-{uuid4()}",
                        specialist_type=SpecialistType.ATTACK,
                        task_type=TaskType.CRED_HARVEST,
                        target_id=target.target_id,
                        priority=7,
                        estimated_duration_seconds=120,
                        risk_level="medium",
                        mission_id=self.mission_id,
                        phase=phase,
                    ))
        
        elif phase == MissionPhase.LATERAL_MOVEMENT:
            # Lateral movement using discovered credentials
            if self.mission_intelligence:
                valid_creds = self.mission_intelligence.get_valid_credentials()
                uncompromised = self.mission_intelligence.get_uncompromised_targets()
                
                for target in uncompromised[:3]:
                    for cred in valid_creds[:2]:
                        tasks.append(CoordinationTask(
                            task_id=f"task-{uuid4()}",
                            specialist_type=SpecialistType.ATTACK,
                            task_type=TaskType.LATERAL,
                            target_id=target.target_id,
                            priority=8,
                            estimated_duration_seconds=150,
                            risk_level="high",
                            mission_id=self.mission_id,
                            phase=phase,
                            metadata={"cred_id": cred.cred_id},
                        ))
        
        return tasks
    
    async def _select_coordination_pattern(
        self,
        phase: MissionPhase,
        tasks: List[CoordinationTask]
    ) -> CoordinationPattern:
        """
        Select appropriate coordination pattern for phase.
        
        Args:
            phase: Mission phase
            tasks: List of tasks
            
        Returns:
            CoordinationPattern
        """
        # Check if tasks have dependencies
        has_dependencies = any(len(t.dependencies) > 0 for t in tasks)
        
        if has_dependencies:
            return CoordinationPattern.PIPELINE
        
        # Phase-specific patterns
        if phase in [MissionPhase.RECONNAISSANCE, MissionPhase.VULNERABILITY_ASSESSMENT]:
            return CoordinationPattern.PARALLEL  # Safe to run in parallel
        
        if phase in [MissionPhase.INITIAL_ACCESS, MissionPhase.LATERAL_MOVEMENT]:
            return CoordinationPattern.CONDITIONAL  # Based on results
        
        return CoordinationPattern.ADAPTIVE  # Default
    
    # ═══════════════════════════════════════════════════════════════
    # Plan Execution
    # ═══════════════════════════════════════════════════════════════
    
    async def execute_plan(self, plan: OrchestrationPlan) -> OrchestrationResult:
        """
        Execute an orchestration plan.
        
        Args:
            plan: OrchestrationPlan to execute
            
        Returns:
            OrchestrationResult with execution summary
        """
        logger.info(f"Executing plan {plan.plan_id} for phase {plan.phase.value}")
        
        start_time = datetime.utcnow()
        self._current_plan = plan
        plan.status = "executing"
        
        # Execute based on coordination pattern
        if plan.coordination_pattern == CoordinationPattern.SEQUENTIAL:
            results = await self._execute_sequential(plan.tasks)
        elif plan.coordination_pattern == CoordinationPattern.PARALLEL:
            results = await self._execute_parallel(plan.tasks, plan.max_parallel_tasks)
        elif plan.coordination_pattern == CoordinationPattern.PIPELINE:
            results = await self._execute_pipeline(plan.tasks)
        else:
            # Adaptive/Conditional
            results = await self._execute_adaptive(plan.tasks, plan.max_parallel_tasks)
        
        # Calculate execution time
        execution_time = (datetime.utcnow() - start_time).total_seconds()
        
        # Build result
        result = OrchestrationResult(
            plan_id=plan.plan_id,
            mission_id=plan.mission_id,
            phase=plan.phase,
            total_tasks=len(plan.tasks),
            completed_tasks=len([r for r in results if r.get("status") == "completed"]),
            failed_tasks=len([r for r in results if r.get("status") == "failed"]),
            execution_time_seconds=execution_time,
            task_results=results,
        )
        
        # Analyze results and recommend next phase
        result.recommended_next_phase = await self._recommend_next_phase(plan.phase, result)
        
        result.success = result.failed_tasks == 0 and result.completed_tasks > 0
        
        plan.status = "completed" if result.success else "failed"
        self._stats["plans_executed"] += 1
        self._stats["total_tasks_executed"] += result.completed_tasks
        self._stats["total_tasks_failed"] += result.failed_tasks
        
        logger.info(f"Plan execution completed: {result.completed_tasks}/{result.total_tasks} tasks succeeded")
        
        return result
    
    async def _execute_sequential(self, tasks: List[CoordinationTask]) -> List[Dict[str, Any]]:
        """Execute tasks sequentially."""
        results = []
        
        for task in sorted(tasks, key=lambda t: t.priority, reverse=True):
            result = await self._execute_single_task(task)
            results.append(result)
            
            # Stop on critical failure
            if result.get("status") == "failed" and task.risk_level == "critical":
                logger.warning(f"Critical task {task.task_id} failed, stopping execution")
                break
        
        return results
    
    async def _execute_parallel(
        self,
        tasks: List[CoordinationTask],
        max_parallel: int
    ) -> List[Dict[str, Any]]:
        """Execute tasks in parallel with concurrency limit."""
        semaphore = asyncio.Semaphore(max_parallel)
        
        async def limited_execute(task: CoordinationTask) -> Dict[str, Any]:
            async with semaphore:
                return await self._execute_single_task(task)
        
        tasks_coros = [limited_execute(task) for task in tasks]
        results = await asyncio.gather(*tasks_coros, return_exceptions=True)
        
        # Handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    "task_id": tasks[i].task_id,
                    "status": "failed",
                    "error": str(result),
                })
            else:
                processed_results.append(result)
        
        return processed_results
    
    async def _execute_pipeline(self, tasks: List[CoordinationTask]) -> List[Dict[str, Any]]:
        """Execute tasks respecting dependencies."""
        # Build dependency graph
        completed = set()
        results = []
        
        # Sort by dependencies (topological sort)
        sorted_tasks = self._topological_sort(tasks)
        
        for task in sorted_tasks:
            # Wait for dependencies
            dependencies_met = all(dep_id in completed for dep_id in task.dependencies)
            
            if not dependencies_met:
                logger.warning(f"Task {task.task_id} dependencies not met, skipping")
                results.append({
                    "task_id": task.task_id,
                    "status": "skipped",
                    "error": "dependencies_not_met",
                })
                continue
            
            # Execute task
            result = await self._execute_single_task(task)
            results.append(result)
            
            if result.get("status") == "completed":
                completed.add(task.task_id)
        
        return results
    
    async def _execute_adaptive(
        self,
        tasks: List[CoordinationTask],
        max_parallel: int
    ) -> List[Dict[str, Any]]:
        """
        Execute tasks adaptively based on results.
        
        Starts with parallel execution, adjusts based on success/failure.
        """
        # Start with parallel for independent tasks
        independent_tasks = [t for t in tasks if not t.dependencies]
        dependent_tasks = [t for t in tasks if t.dependencies]
        
        results = []
        
        # Execute independent tasks in parallel
        if independent_tasks:
            results.extend(await self._execute_parallel(independent_tasks, max_parallel))
        
        # Execute dependent tasks using pipeline
        if dependent_tasks:
            results.extend(await self._execute_pipeline(dependent_tasks))
        
        return results
    
    def _topological_sort(self, tasks: List[CoordinationTask]) -> List[CoordinationTask]:
        """Sort tasks by dependencies (topological sort)."""
        # Simple topological sort
        sorted_tasks = []
        visited = set()
        
        def visit(task: CoordinationTask):
            if task.task_id in visited:
                return
            
            # Visit dependencies first
            for dep_id in task.dependencies:
                dep_task = next((t for t in tasks if t.task_id == dep_id), None)
                if dep_task:
                    visit(dep_task)
            
            visited.add(task.task_id)
            sorted_tasks.append(task)
        
        for task in tasks:
            visit(task)
        
        return sorted_tasks
    
    async def _execute_single_task(self, task: CoordinationTask) -> Dict[str, Any]:
        """
        Execute a single coordination task.
        
        Args:
            task: CoordinationTask to execute
            
        Returns:
            Dict with execution result
        """
        logger.debug(f"Executing task {task.task_id} ({task.task_type.value})")
        
        task.status = TaskStatus.RUNNING
        task.started_at = datetime.utcnow()
        
        try:
            # Get specialist for this task
            specialist = self.specialists.get(task.specialist_type)
            
            if not specialist:
                raise ValueError(f"No specialist available for type {task.specialist_type.value}")
            
            # Create task in Blackboard
            bb_task = await self.blackboard.create_task(
                mission_id=self.mission_id,
                task_type=task.task_type,
                target_id=task.target_id,
                parameters=task.metadata,
            )
            
            # Execute via specialist (simplified - actual execution handled by specialist)
            # In real implementation, specialist would poll for tasks and execute
            
            # Simulate execution time
            await asyncio.sleep(min(task.estimated_duration_seconds / 10, 1.0))
            
            # Mark as completed
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.utcnow()
            
            result = {
                "task_id": task.task_id,
                "status": "completed",
                "duration_seconds": (task.completed_at - task.started_at).total_seconds(),
                "specialist": task.specialist_type.value,
                "task_type": task.task_type.value,
            }
            
            logger.debug(f"Task {task.task_id} completed successfully")
            return result
            
        except Exception as e:
            logger.error(f"Task {task.task_id} failed: {e}", exc_info=True)
            
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.utcnow()
            task.error = str(e)
            
            return {
                "task_id": task.task_id,
                "status": "failed",
                "error": str(e),
                "specialist": task.specialist_type.value,
                "task_type": task.task_type.value,
            }
    
    async def _recommend_next_phase(
        self,
        current_phase: MissionPhase,
        result: OrchestrationResult
    ) -> Optional[MissionPhase]:
        """
        Recommend next mission phase based on execution results.
        
        Args:
            current_phase: Current phase
            result: Execution result
            
        Returns:
            Recommended next phase or None
        """
        # Phase progression logic
        phase_progression = {
            MissionPhase.RECONNAISSANCE: MissionPhase.VULNERABILITY_ASSESSMENT,
            MissionPhase.VULNERABILITY_ASSESSMENT: MissionPhase.INITIAL_ACCESS,
            MissionPhase.INITIAL_ACCESS: MissionPhase.POST_EXPLOITATION,
            MissionPhase.POST_EXPLOITATION: MissionPhase.LATERAL_MOVEMENT,
            MissionPhase.LATERAL_MOVEMENT: MissionPhase.PRIVILEGE_ESCALATION,
            MissionPhase.PRIVILEGE_ESCALATION: MissionPhase.PERSISTENCE,
            MissionPhase.PERSISTENCE: MissionPhase.COMPLETED,
        }
        
        # If current phase succeeded, move to next
        if result.success and result.completed_tasks > 0:
            return phase_progression.get(current_phase)
        
        # If failed, retry current phase or fallback
        if result.failed_tasks > result.completed_tasks:
            return current_phase  # Retry
        
        return None
    
    # ═══════════════════════════════════════════════════════════════
    # Coordination Patterns
    # ═══════════════════════════════════════════════════════════════
    
    async def coordinate_recon_phase(self) -> OrchestrationResult:
        """Coordinate reconnaissance phase."""
        plan = await self.generate_execution_plan(
            phase=MissionPhase.RECONNAISSANCE,
            execution_strategy=ExecutionStrategy.BALANCED,
        )
        return await self.execute_plan(plan)
    
    async def coordinate_exploitation_phase(self) -> OrchestrationResult:
        """Coordinate exploitation phase."""
        plan = await self.generate_execution_plan(
            phase=MissionPhase.INITIAL_ACCESS,
            execution_strategy=ExecutionStrategy.BALANCED,
        )
        return await self.execute_plan(plan)
    
    async def coordinate_privilege_escalation(self) -> OrchestrationResult:
        """Coordinate privilege escalation phase."""
        plan = await self.generate_execution_plan(
            phase=MissionPhase.PRIVILEGE_ESCALATION,
            execution_strategy=ExecutionStrategy.STEALTHY,
        )
        return await self.execute_plan(plan)
    
    # ═══════════════════════════════════════════════════════════════
    # Utility Methods
    # ═══════════════════════════════════════════════════════════════
    
    async def get_orchestration_status(self) -> Dict[str, Any]:
        """Get current orchestration status."""
        return {
            "mission_id": self.mission_id,
            "current_plan": self._current_plan.plan_id if self._current_plan else None,
            "active_tasks": len(self._active_tasks),
            "statistics": self._stats.copy(),
            "available_specialists": list(self.specialists.keys()),
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestration statistics."""
        return self._stats.copy()
