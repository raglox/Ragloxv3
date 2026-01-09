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

from .mission_intelligence import (
    MissionIntelligenceBuilder,
    TargetDossier,
    IntelligenceBrief
)

from .specialist_orchestrator import (
    SpecialistOrchestrator,
    CoordinationPattern,
    OrchestrationResult
)

from .attack_kill_chain import (
    AttackKillChainMapper,
    KillChainPhase,
    TacticalMapping
)

from .mitre_mapper import (
    MITREAttackMapper,
    Tactic,
    Technique
)

__all__ = [
    # Tactical Reasoning
    "TacticalReasoningEngine",
    "TacticalContext",
    "TacticalReasoning",
    "ReasoningPhase",
    
    # Mission Intelligence
    "MissionIntelligenceBuilder",
    "TargetDossier",
    "IntelligenceBrief",
    
    # Orchestration
    "SpecialistOrchestrator",
    "CoordinationPattern",
    "OrchestrationResult",
    
    # Attack Frameworks
    "AttackKillChainMapper",
    "KillChainPhase",
    "TacticalMapping",
    "MITREAttackMapper",
    "Tactic",
    "Technique",
]
