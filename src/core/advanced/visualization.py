# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Visualization Dashboard API
# Phase 5.0: Advanced Features
# ═══════════════════════════════════════════════════════════════

"""
Visualization Dashboard API for RAGLOX v3.0

Provides data endpoints for dashboard visualization.

Author: RAGLOX Team
Version: 3.0.0
Date: 2026-01-09
"""

import logging
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..reasoning.mission_intelligence import MissionIntelligence
    from ..reasoning.specialist_orchestrator import SpecialistOrchestrator

logger = logging.getLogger("raglox.core.visualization")


class VisualizationDashboardAPI:
    """
    Visualization Dashboard API.
    
    Provides structured data for dashboard rendering.
    """
    
    def __init__(
        self,
        mission_intelligence: Optional["MissionIntelligence"] = None,
        orchestrator: Optional["SpecialistOrchestrator"] = None,
    ):
        self.mission_intelligence = mission_intelligence
        self.orchestrator = orchestrator
        logger.info("Initialized VisualizationDashboardAPI")
    
    async def get_mission_overview(self) -> Dict[str, Any]:
        """Get mission overview data."""
        if not self.mission_intelligence:
            return {"error": "No mission intelligence available"}
        
        return {
            "mission_id": self.mission_intelligence.mission_id,
            "total_targets": self.mission_intelligence.total_targets,
            "compromised_targets": self.mission_intelligence.compromised_targets,
            "total_vulnerabilities": self.mission_intelligence.total_vulnerabilities,
            "exploitable_vulnerabilities": self.mission_intelligence.exploitable_vulnerabilities,
            "total_credentials": self.mission_intelligence.total_credentials,
            "privileged_credentials": self.mission_intelligence.privileged_credentials,
            "last_updated": self.mission_intelligence.last_updated.isoformat(),
        }
    
    async def get_attack_surface_data(self) -> Dict[str, Any]:
        """Get attack surface visualization data."""
        if not self.mission_intelligence or not self.mission_intelligence.attack_surface:
            return {"error": "No attack surface data available"}
        
        attack_surface = self.mission_intelligence.attack_surface
        
        return {
            "overall_risk_score": attack_surface.overall_risk_score,
            "entry_points_count": len(attack_surface.entry_points),
            "high_value_targets": attack_surface.high_value_targets,
            "low_hanging_fruit": attack_surface.low_hanging_fruit,
            "detected_defenses": len(attack_surface.detected_defenses),
        }
    
    async def get_network_topology_graph(self) -> Dict[str, Any]:
        """Get network topology for graph visualization."""
        if not self.mission_intelligence or not self.mission_intelligence.network_topology:
            return {"nodes": [], "edges": []}
        
        topology = self.mission_intelligence.network_topology
        
        # Build nodes
        nodes = []
        for segment in topology.segments:
            for host in segment.hosts:
                nodes.append({
                    "id": host,
                    "subnet": segment.subnet,
                    "type": "host",
                })
        
        # Build edges (simplified)
        edges = []
        for route in topology.routes:
            edges.append({
                "source": route.get("from_subnet"),
                "target": route.get("to_subnet"),
                "type": "route",
            })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "total_hosts": topology.total_hosts,
                "total_subnets": topology.total_subnets,
            }
        }
    
    async def get_recommendations_list(self) -> List[Dict[str, Any]]:
        """Get tactical recommendations."""
        if not self.mission_intelligence:
            return []
        
        recs = self.mission_intelligence.get_top_recommendations(limit=10)
        
        return [
            {
                "recommendation_id": r.recommendation_id,
                "action": r.action,
                "priority": r.priority,
                "success_probability": r.success_probability,
                "risk_level": r.risk_level,
                "status": r.status,
            }
            for r in recs
        ]
    
    async def get_orchestration_status(self) -> Dict[str, Any]:
        """Get orchestration status."""
        if not self.orchestrator:
            return {"error": "No orchestrator available"}
        
        return await self.orchestrator.get_orchestration_status()
