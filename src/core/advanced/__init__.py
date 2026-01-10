# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Advanced Features Module
# Phase 5.0: Advanced Features
# ═══════════════════════════════════════════════════════════════

"""
Advanced Features Module

Provides advanced capabilities for RAGLOX v3.0:
- Advanced Risk Assessment
- Real-time Adaptation
- Intelligent Task Prioritization
- Visualization Dashboard API

Author: RAGLOX Team
Version: 3.0.0
Date: 2026-01-09
"""

from .risk_assessment import (
    AdvancedRiskAssessmentEngine,
    RiskAssessment,
    RiskLevel,
    DefenseLevel,
    DefenseCapability,
    ActionRiskProfile,
    RiskFactor,
    ThreatActor,
)

from .adaptation import (
    RealtimeAdaptationEngine,
    AdaptationDecision,
)

from .prioritization import (
    IntelligentTaskPrioritizer,
    TaskScore,
)

from .visualization import (
    VisualizationDashboardAPI,
)

__all__ = [
    # Risk Assessment
    "AdvancedRiskAssessmentEngine",
    "RiskAssessment",
    "RiskLevel",
    "DefenseLevel",
    "DefenseCapability",
    "ActionRiskProfile",
    "RiskFactor",
    "ThreatActor",
    
    # Adaptation
    "RealtimeAdaptationEngine",
    "AdaptationDecision",
    
    # Prioritization
    "IntelligentTaskPrioritizer",
    "TaskScore",
    
    # Visualization
    "VisualizationDashboardAPI",
]
