# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Advanced Reasoning Layer
# Tactical reasoning and decision-making for hacker AI
# ═══════════════════════════════════════════════════════════════

"""
Advanced Reasoning Layer

This module implements sophisticated tactical reasoning that mimics
how professional Red Team operators think and make decisions.

Components:
- TacticalReasoningEngine: Multi-phase reasoning for tactical decisions
- MissionIntelligenceBuilder: Comprehensive intelligence briefings
- SpecialistOrchestrator: Coordination between HackerAgent and Specialists
- AttackKillChainMapper: Attack kill chain integration
- MITREAttackMapper: MITRE ATT&CK framework integration

Philosophy:
- Think like an advanced hacker
- Multi-layered reasoning (situational awareness, threat modeling, etc.)
- Defense-aware and evasion-focused
- Learning from past operations
- Contingency planning always

Author: RAGLOX Team
Version: 3.0.0
"""

from .tactical_reasoning import (
    TacticalReasoningEngine,
    TacticalContext,
    TacticalReasoning,
    ReasoningPhase
)

# Phase 3.0: Mission Intelligence System
from .mission_intelligence import (
    MissionIntelligence,
    TargetIntel,
    VulnerabilityIntel,
    CredentialIntel,
    NetworkMap,
    AttackSurfaceAnalysis,
    TacticRecommendation,
    IntelConfidence,
    AttackVectorType,
    DefenseType,
    create_mission_intelligence,
)

from .mission_intelligence_builder import (
    MissionIntelligenceBuilder,
)

# Phase 4.0: Specialist Orchestration
from .specialist_orchestrator import (
    SpecialistOrchestrator,
    CoordinationPattern,
    OrchestrationResult,
    MissionPhase,
    ExecutionStrategy,
    CoordinationTask,
    OrchestrationPlan,
)

# TODO Phase 5.0: Attack Frameworks

__all__ = [
    # Tactical Reasoning
    "TacticalReasoningEngine",
    "TacticalContext",
    "TacticalReasoning",
    "ReasoningPhase",
    
    # Phase 3.0: Mission Intelligence
    "MissionIntelligence",
    "MissionIntelligenceBuilder",
    "TargetIntel",
    "VulnerabilityIntel",
    "CredentialIntel",
    "NetworkMap",
    "AttackSurfaceAnalysis",
    "TacticRecommendation",
    "IntelConfidence",
    "AttackVectorType",
    "DefenseType",
    "create_mission_intelligence",
    
    # Phase 4.0: Specialist Orchestration
    "SpecialistOrchestrator",
    "CoordinationPattern",
    "OrchestrationResult",
    "MissionPhase",
    "ExecutionStrategy",
    "CoordinationTask",
    "OrchestrationPlan",
    
    # TODO Phase 5.0:
    # "AttackKillChainMapper",
    # "KillChainPhase",
    # "TacticalMapping",
    # "MITREAttackMapper",
    # "Tactic",
    # "Technique",
]
